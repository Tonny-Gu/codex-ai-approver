#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import socket
import subprocess
import sys
import time


HOOKS_DIR = Path(__file__).resolve().parent
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from approver_common import (  # noqa: E402
    DAEMON_REQUEST_MAX_BYTES,
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_PATH,
    DEVELOPER_INSTRUCTIONS,
    ENV_ASSIGN_RE,
    OUTPUT_SCHEMA,
    PERMIT_ENV,
    PERMIT_LEVELS,
    REQUIRED_PERMIT,
    RISK_CATEGORIES,
    SCOPE_ENV,
    ApproverConfig,
    DaemonConfig,
    Decision,
    HookInput,
    ReviewResult,
    build_prompt,
    config_path,
    daemon_aux_path,
    daemon_socket_path,
    default_config,
    ensure_daemon_parent,
    final_decision,
    hook_input_from_payload,
    hook_input_to_payload,
    is_daemon_unavailable,
    load_config,
    merge_config,
    parse_bash_controls,
    parse_hook_input,
    parse_review,
    permit_level_for_word,
    permit_retry_guidance,
    permission_request_output,
    print_json,
    review_result_from_payload,
    review_result_to_payload,
    _string,
)
from approver_server import (  # noqa: E402
    DAEMON_ANCHOR_PROMPT,
    DaemonReviewer,
    handle_daemon_request,
    run_daemon,
)


def review_with_codex(hook_input: HookInput, config: ApproverConfig) -> ReviewResult:
    try:
        from openai_codex import ApprovalMode, Codex, Sandbox
        from openai_codex.types import ReasoningEffort
    except ModuleNotFoundError as exc:
        raise RuntimeError("openai-codex is not installed in this Python environment") from exc

    prompt = build_prompt(hook_input)
    effort = ReasoningEffort(config.reasoning_effort)

    with Codex() as codex:
        thread = codex.thread_start(
            approval_mode=ApprovalMode.deny_all,
            config={"model_reasoning_effort": config.reasoning_effort},
            cwd=hook_input.cwd or None,
            developer_instructions=DEVELOPER_INSTRUCTIONS,
            model=config.model,
            sandbox=Sandbox.read_only,
        )
        result = thread.run(
            prompt,
            effort=effort,
            output_schema=OUTPUT_SCHEMA,
            sandbox=Sandbox.read_only,
        )

    return parse_review(result.final_response or "")


def review_permission_request(hook_input: HookInput, config: ApproverConfig) -> ReviewResult:
    if config.daemon.enabled:
        return review_with_daemon(hook_input, config)
    return review_with_codex(hook_input, config)


def review_with_daemon(hook_input: HookInput, config: ApproverConfig) -> ReviewResult:
    ensure_daemon_running(config)
    payload = {
        "command": "review",
        "hook_input": hook_input_to_payload(hook_input),
    }
    try:
        response = send_daemon_request(config, payload)
    except OSError as exc:
        if not _is_daemon_unavailable(exc):
            raise
        _unlink_stale_daemon_socket(daemon_socket_path(config))
        ensure_daemon_running(config)
        response = send_daemon_request(config, payload)

    if response.get("ok") is not True:
        raise RuntimeError(f"approver daemon failed: {_string(response.get('error'), 'unknown error')}")
    return review_result_from_payload(response.get("review"))


def ensure_daemon_running(config: ApproverConfig) -> None:
    if _daemon_probe(config, timeout=0.25) in ("ready", "busy"):
        return

    socket_path = daemon_socket_path(config)
    ensure_daemon_parent(socket_path, config)
    lock_path = daemon_aux_path(socket_path, ".lock")

    import fcntl

    with lock_path.open("w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        if _daemon_probe(config, timeout=0.25) in ("ready", "busy"):
            return

        _unlink_stale_daemon_socket(socket_path)
        _spawn_daemon(config)

        deadline = time.monotonic() + config.daemon.startup_timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                response = send_daemon_request(config, {"command": "status"}, timeout=0.5)
                if response.get("ok") is True:
                    return
            except Exception as exc:
                last_error = exc
            time.sleep(0.2)

    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(
        f"approver daemon did not become ready within "
        f"{config.daemon.startup_timeout_seconds:g}s{detail}"
    )


def send_daemon_request(
    config: ApproverConfig,
    payload: dict[str, Any],
    timeout: float | None = None,
) -> dict[str, Any]:
    socket_path = daemon_socket_path(config)
    request_timeout = config.daemon.request_timeout_seconds if timeout is None else timeout
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    response = bytearray()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(request_timeout)
        client.connect(str(socket_path))
        client.sendall(data)
        while b"\n" not in response:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > DAEMON_REQUEST_MAX_BYTES:
                raise RuntimeError("approver daemon response is too large")

    if not response:
        raise RuntimeError("approver daemon returned no response")
    decoded = json.loads(response.split(b"\n", 1)[0].decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("approver daemon response must be a JSON object")
    return decoded


def daemon_start_cli() -> int:
    config = load_config()
    ensure_daemon_running(config)
    print_json(send_daemon_request(config, {"command": "status"}, timeout=1))
    return 0


def daemon_status_cli() -> int:
    config = load_config()
    try:
        response = send_daemon_request(config, {"command": "status"}, timeout=1)
    except OSError as exc:
        if not _is_daemon_unavailable(exc):
            raise
        response = {
            "ok": False,
            "status": "not_running",
            "socket_path": str(daemon_socket_path(config)),
        }
        print_json(response)
        return 1
    print_json(response)
    return 0


def daemon_stop_cli() -> int:
    config = load_config()
    try:
        response = send_daemon_request(config, {"command": "stop"}, timeout=1)
    except OSError as exc:
        if not _is_daemon_unavailable(exc):
            raise
        response = {
            "ok": True,
            "status": "not_running",
            "socket_path": str(daemon_socket_path(config)),
        }
    print_json(response)
    return 0


def _daemon_ping(config: ApproverConfig, timeout: float) -> bool:
    return _daemon_probe(config, timeout) == "ready"


def _daemon_probe(config: ApproverConfig, timeout: float) -> str:
    try:
        response = send_daemon_request(config, {"command": "status"}, timeout=timeout)
    except OSError as exc:
        if isinstance(exc, TimeoutError):
            return "busy"
        if _is_daemon_unavailable(exc):
            return "unavailable"
        return "bad"
    except RuntimeError as exc:
        if "returned no response" in str(exc) and daemon_socket_path(config).exists():
            return "busy"
        return "bad"
    except Exception:
        return "bad"
    if response.get("ok") is True:
        return "ready"
    return "bad"


def _spawn_daemon(config: ApproverConfig) -> None:
    socket_path = daemon_socket_path(config)
    log_path = daemon_aux_path(socket_path, ".log")
    command = [sys.executable, str(Path(__file__).resolve()), "--daemon"]
    with log_path.open("ab") as log_file:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
            env=os.environ.copy(),
        )
    daemon_aux_path(socket_path, ".pid").write_text(f"{proc.pid}\n", encoding="utf-8")


def _unlink_stale_daemon_socket(socket_path: Path) -> None:
    if not socket_path.exists():
        return
    if not socket_path.is_socket():
        raise RuntimeError(f"approver daemon socket path exists and is not a socket: {socket_path}")
    socket_path.unlink()


def _is_daemon_unavailable(exc: OSError) -> bool:
    return is_daemon_unavailable(exc)


def run_hook() -> int:
    try:
        config = load_config()
        hook_input = parse_hook_input(sys.stdin.read(), config)
        review = review_permission_request(hook_input, config)
        decision = final_decision(
            review,
            hook_input.permit_level,
            hook_input.scope,
            hook_input.tool_name,
        )
        print_json(permission_request_output(decision.behavior, decision.message))
    except Exception as exc:
        return _handle_error(exc)
    return 0


def _handle_error(exc: Exception) -> int:
    reason = (
        f"Codex AI Approver hook failed: {exc}. This is a hook setup/runtime failure, "
        "not a safety denial. Do not retry the same tool call unchanged; ask the user "
        "to fix the hook setup, dependency, Codex authentication, or config."
    )
    try:
        print_json(permission_request_output("deny", reason))
        return 0
    except Exception:
        print(reason, file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return run_hook()

    command = argv[0]
    if command == "--daemon":
        return run_daemon()
    if command == "--daemon-start":
        return daemon_start_cli()
    if command == "--daemon-status":
        return daemon_status_cli()
    if command == "--daemon-stop":
        return daemon_stop_cli()

    print(f"unknown option: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
