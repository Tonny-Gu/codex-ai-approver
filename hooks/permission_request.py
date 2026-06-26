#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import os
import sys
import traceback


DEFAULT_CONFIG_PATH = "~/.codex-ai-approver.json"
DEFAULT_MODEL = "gpt-5.5"
DEFAULT_REASONING_EFFORT = "medium"

OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "decision": {"type": "string", "enum": ["allow", "deny"]},
        "reason": {"type": "string"},
    },
    "required": ["decision", "reason"],
}


@dataclass(frozen=True)
class ApproverConfig:
    model: str = DEFAULT_MODEL
    reasoning_effort: str = DEFAULT_REASONING_EFFORT
    debug: bool = False


@dataclass(frozen=True)
class HookInput:
    cwd: str
    tool_name: str
    tool_input: dict[str, Any]


@dataclass(frozen=True)
class LlmDecision:
    decision: str
    reason: str


def config_path() -> Path:
    raw = os.environ.get("CODEX_AI_APPROVER_CONFIG", DEFAULT_CONFIG_PATH)
    return Path(raw).expanduser()


def load_config(path: Path | None = None) -> ApproverConfig:
    path = path or config_path()
    payload: dict[str, Any] = {}
    if path.is_file():
        payload = _load_json(path)

    model = _as_str(payload.get("model"), DEFAULT_MODEL)
    reasoning_effort = _as_str(
        payload.get("reasoning_effort", payload.get("model_reasoning_effort")),
        DEFAULT_REASONING_EFFORT,
    )

    return ApproverConfig(
        model=model,
        reasoning_effort=reasoning_effort,
        debug=_as_bool(payload.get("debug"), False),
    )


def parse_hook_input(stdin_data: str) -> HookInput:
    raw = json.loads(stdin_data)
    if not isinstance(raw, dict):
        raise ValueError("hook input must be a JSON object")

    tool_input = raw.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("hook input field tool_input must be an object")

    return HookInput(
        cwd=_string(raw.get("cwd"), ""),
        tool_name=_string(raw.get("tool_name"), ""),
        tool_input=tool_input,
    )


def extract_target(hook_input: HookInput) -> str:
    tool = hook_input.tool_name
    payload = hook_input.tool_input
    if tool == "Bash":
        return _string(payload.get("command"), "")
    if tool in {"apply_patch", "Edit", "Write"}:
        return _string(payload.get("command"), "") or json.dumps(payload, sort_keys=True)
    return json.dumps(payload, sort_keys=True)


def build_prompt(hook_input: HookInput) -> str:
    target = extract_target(hook_input)
    tool_input_json = json.dumps(hook_input.tool_input, indent=2, sort_keys=True)

    return f"""You are deciding whether Codex should be permitted to run one proposed tool call.

Decision policy:
- Allow only clearly scoped, low-risk, reversible, or read-only actions.
- Deny destructive commands, broad deletes, forced git history changes, privilege escalation, secret access, persistence changes, and unclear blast radius.
- Deny network, package installation, remote execution, service control, permission changes, and writes outside the working directory unless the input makes safety and necessity explicit.
- If uncertain, deny.
- Judge this exact command only. Do not propose alternatives.

Working directory: {hook_input.cwd or "unknown"}
Tool: {hook_input.tool_name}
Target: {target}

Tool input JSON:
{tool_input_json}
"""


def decide_with_codex(hook_input: HookInput, config: ApproverConfig) -> LlmDecision:
    try:
        from openai_codex import ApprovalMode, Codex, Sandbox
        from openai_codex.types import ReasoningEffort
    except ModuleNotFoundError as exc:
        raise RuntimeError("openai-codex is not installed in this Python environment") from exc

    prompt = build_prompt(hook_input)
    effort = ReasoningEffort(config.reasoning_effort)
    developer_instructions = (
        "Classify one permission request. Do not inspect files or run tools."
    )

    with Codex() as codex:
        thread = codex.thread_start(
            approval_mode=ApprovalMode.deny_all,
            config={"model_reasoning_effort": config.reasoning_effort},
            cwd=hook_input.cwd or None,
            developer_instructions=developer_instructions,
            model=config.model,
            sandbox=Sandbox.read_only,
        )
        result = thread.run(
            prompt,
            effort=effort,
            output_schema=OUTPUT_SCHEMA,
            sandbox=Sandbox.read_only,
        )

    return parse_decision(result.final_response or "")


def parse_decision(text: str) -> LlmDecision:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("LLM response must be a JSON object")
    decision = payload.get("decision")
    reason = payload.get("reason")
    if decision not in {"allow", "deny"}:
        raise ValueError(f"invalid LLM decision: {decision!r}")
    if not isinstance(reason, str) or not reason.strip():
        reason = "Codex AI Approver returned no reason."
    return LlmDecision(decision=decision, reason=reason.strip())


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


def run_hook() -> int:
    try:
        config = load_config()
        hook_input = parse_hook_input(sys.stdin.read())
        decision = decide_with_codex(hook_input, config)
        print_json(permission_request_output(decision.decision, decision.reason))
    except Exception as exc:
        return _handle_error(exc)
    return 0


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":")))


def _handle_error(exc: Exception) -> int:
    try:
        config = load_config()
    except Exception:
        config = None

    reason = f"Codex AI Approver failed: {exc}"
    if config is not None and config.debug:
        reason = f"{reason}\n{traceback.format_exc()}"

    print_json(permission_request_output("deny", reason))
    return 0


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _string(value: Any, default: str) -> str:
    if isinstance(value, str):
        return value
    return default


def _as_str(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "enable", "enabled"}:
            return True
        if lowered in {"0", "false", "no", "off", "disable", "disabled"}:
            return False
    return default


if __name__ == "__main__":
    raise SystemExit(run_hook())
