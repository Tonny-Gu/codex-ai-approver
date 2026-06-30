#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import time
import xmlrpc.client


DAEMON_HOST = "localhost"
DAEMON_LOG_PATH = Path("~/codex-ai-approver.log")
DAEMON_STARTUP_TIMEOUT_SECONDS = 30
HOOKS_DIR = Path(__file__).resolve().parent
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from approver_common import (  # noqa: E402
    ApproverConfig,
    HookInput,
    ReviewResult,
    final_decision,
    is_daemon_unavailable,
    load_config,
    parse_hook_input,
    permission_request_output,
    print_json,
)
from approver_server import run_daemon  # noqa: E402


def review_with_daemon(hook_input: HookInput, config: ApproverConfig) -> ReviewResult:
    ensure_daemon_running(config)
    try:
        response = daemon_proxy(config).review(hook_input.__dict__)
    except OSError as exc:
        if not is_daemon_unavailable(exc):
            raise
        ensure_daemon_running(config)
        response = daemon_proxy(config).review(hook_input.__dict__)

    return ReviewResult(**response)


def ensure_daemon_running(config: ApproverConfig) -> None:
    try:
        if daemon_proxy(config).status().get("ok") is True:
            return
    except Exception:
        pass

    _spawn_daemon()

    deadline = time.monotonic() + DAEMON_STARTUP_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = daemon_proxy(config).status()
            if response.get("ok") is True:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.2)

    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(
        f"approver daemon did not become ready within "
        f"{DAEMON_STARTUP_TIMEOUT_SECONDS:g}s{detail}"
    )


def daemon_proxy(config: ApproverConfig) -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(
        f"http://{DAEMON_HOST}:{config.daemon_port}/",
        allow_none=True,
    )


def _spawn_daemon() -> None:
    command = [sys.executable, str(Path(__file__).resolve()), "--daemon"]
    with DAEMON_LOG_PATH.expanduser().open("a", encoding="utf-8") as log:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
        )


def daemon_stop_cli() -> int:
    config = load_config()
    try:
        response = daemon_proxy(config).stop()
    except OSError as exc:
        if not is_daemon_unavailable(exc):
            raise
        response = {"ok": True, "status": "not_running"}
    print_json(response)
    return 0


def run_hook() -> int:
    try:
        config = load_config()
        hook_input = parse_hook_input(sys.stdin.read(), config)
        review = review_with_daemon(hook_input, config)
        decision = final_decision(
            review,
            hook_input.permit_categories,
            hook_input.justification,
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
    if command == "--daemon-stop":
        return daemon_stop_cli()

    print(f"unknown option: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
