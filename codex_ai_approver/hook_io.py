from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json


@dataclass(frozen=True)
class HookInput:
    event_name: str
    session_id: str
    turn_id: str
    cwd: str
    model: str
    permission_mode: str
    tool_name: str
    tool_input: dict[str, Any]
    transcript_path: str | None = None
    tool_use_id: str | None = None


def parse_hook_input(stdin_data: str, expected_event: str) -> HookInput:
    raw = json.loads(stdin_data)
    if not isinstance(raw, dict):
        raise ValueError("hook input must be a JSON object")

    tool_input = raw.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("hook input field tool_input must be an object")

    return HookInput(
        event_name=_string(raw.get("hook_event_name"), expected_event),
        session_id=_string(raw.get("session_id"), "unknown"),
        turn_id=_string(raw.get("turn_id"), "unknown"),
        cwd=_string(raw.get("cwd"), ""),
        model=_string(raw.get("model"), ""),
        permission_mode=_string(raw.get("permission_mode"), ""),
        tool_name=_string(raw.get("tool_name"), ""),
        tool_input=tool_input,
        transcript_path=_optional_string(raw.get("transcript_path")),
        tool_use_id=_optional_string(raw.get("tool_use_id")),
    )


def extract_target(hook_input: HookInput) -> str:
    tool = hook_input.tool_name
    payload = hook_input.tool_input
    if tool == "Bash":
        return _string(payload.get("command"), "")
    if tool in {"apply_patch", "Edit", "Write"}:
        return _string(payload.get("command"), "") or json.dumps(payload, sort_keys=True)
    return json.dumps(payload, sort_keys=True)


def permission_request_output(decision: str, reason: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": decision,
            },
        },
    }
    if decision == "deny":
        body["hookSpecificOutput"]["decision"]["message"] = reason
    return body


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":")))


def _string(value: Any, default: str) -> str:
    if isinstance(value, str):
        return value
    return default


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None
