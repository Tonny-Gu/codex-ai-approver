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

from guardian_common import (  # noqa: E402
    DAEMON_API_VERSION,
    GuardianAssessment,
    GuardianConfig,
    PermissionRequestInput,
    config_fingerprint,
    is_daemon_unavailable,
    load_config,
    parse_guardian_assessment_mapping,
    parse_permission_request_input,
    permission_request_error_output,
    permission_request_output,
    print_json,
)
from guardian_server import run_daemon  # noqa: E402


def assess_with_daemon(
    hook_input: PermissionRequestInput,
    config: GuardianConfig,
) -> GuardianAssessment:
    ensure_daemon_running(config)
    try:
        response = daemon_proxy(config).assess(hook_input.__dict__)
    except OSError as exc:
        if not is_daemon_unavailable(exc):
            raise
        ensure_daemon_running(config)
        response = daemon_proxy(config).assess(hook_input.__dict__)

    return parse_guardian_assessment_mapping(response, hook_input.request_id)


def ensure_daemon_running(config: GuardianConfig) -> None:
    expected_fingerprint = config_fingerprint(config)
    try:
        status = daemon_proxy(config).status()
        if (
            status.get("ok") is True
            and status.get("running") is True
            and status.get("api_version") == DAEMON_API_VERSION
            and status.get("config_fingerprint") == expected_fingerprint
        ):
            return
        daemon_proxy(config).stop()
        _wait_for_daemon_stop(config)
    except Exception:
        pass

    _spawn_daemon()

    deadline = time.monotonic() + DAEMON_STARTUP_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = daemon_proxy(config).status()
            if (
                response.get("ok") is True
                and response.get("running") is True
                and response.get("api_version") == DAEMON_API_VERSION
                and response.get("config_fingerprint") == expected_fingerprint
            ):
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.2)

    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(
        f"guardian daemon did not become ready within "
        f"{DAEMON_STARTUP_TIMEOUT_SECONDS:g}s{detail}"
    )


def daemon_proxy(config: GuardianConfig) -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(
        f"http://{DAEMON_HOST}:{config.daemon_port}/",
        allow_none=True,
    )


def _spawn_daemon() -> None:
    command = [sys.executable, str(Path(__file__).resolve()), "--daemon"]
    log_path = DAEMON_LOG_PATH.expanduser()
    log_path.touch(mode=0o600, exist_ok=True)
    log_path.chmod(0o600)
    with log_path.open("a", encoding="utf-8") as log:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
        )


def _wait_for_daemon_stop(config: GuardianConfig) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            daemon_proxy(config).status()
        except Exception:
            return
        time.sleep(0.05)


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


def daemon_status_cli() -> int:
    config = load_config()
    try:
        response = daemon_proxy(config).status()
    except OSError as exc:
        if not is_daemon_unavailable(exc):
            raise
        response = {"ok": True, "running": False, "api_version": None}
    print_json(response)
    return 0


def run_hook() -> int:
    try:
        config = load_config()
        hook_input = parse_permission_request_input(sys.stdin.read())
        assessment = assess_with_daemon(hook_input, config)
        print_json(permission_request_output(hook_input, assessment))
    except Exception as exc:
        return _handle_error(exc)
    return 0


def _handle_error(exc: Exception) -> int:
    reason = (
        f"Codex AI Approver guardian hook failed: {exc}. This is a hook "
        "setup/runtime failure, not a guardian safety assessment. Do not retry "
        "the same tool call unchanged; ask the user to fix the hook setup, "
        "dependency, Codex authentication, or config."
    )
    try:
        print_json(permission_request_error_output(reason))
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
    if command == "--daemon-status":
        return daemon_status_cli()

    print(f"unknown option: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
