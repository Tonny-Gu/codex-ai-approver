from __future__ import annotations

import sys
import traceback

from .cache import read_cached_decision, write_cached_decision
from .config import load_config
from .hook_io import (
    parse_hook_input,
    permission_request_output,
    print_json,
)
from .llm import LlmDecision, decide_with_codex


def run_hook(event_name: str) -> int:
    try:
        stdin_data = sys.stdin.read()
        config = load_config()
        hook_input = parse_hook_input(stdin_data, event_name)

        cached = read_cached_decision(hook_input, config.cache_ttl_sec)
        if cached is not None:
            decision = LlmDecision(cached.decision, cached.reason)
        else:
            decision = decide_with_codex(hook_input, config)
            write_cached_decision(hook_input, decision.decision, decision.reason)

        if event_name == "PermissionRequest":
            print_json(permission_request_output(decision.decision, decision.reason))
            return 0

        raise ValueError(f"unsupported hook event: {event_name}")
    except Exception as exc:
        return _handle_error(event_name, exc)


def _handle_error(event_name: str, exc: Exception) -> int:
    try:
        config = load_config()
    except Exception:
        config = None

    reason = f"Codex AI Approver failed: {exc}"
    if config is not None and config.debug:
        reason = f"{reason}\n{traceback.format_exc()}"

    if config is not None and config.on_error == "allow":
        return 0

    if event_name == "PermissionRequest":
        print_json(permission_request_output("deny", reason))
    else:
        print(reason, file=sys.stderr)
        return 1
    return 0
