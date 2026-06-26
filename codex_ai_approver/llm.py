from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import re

from .config import ApproverConfig
from .hook_io import HookInput
from .prompt import build_prompt


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
class LlmDecision:
    decision: str
    reason: str


def decide_with_codex(hook_input: HookInput, config: ApproverConfig) -> LlmDecision:
    try:
        from openai_codex import ApprovalMode, Codex, Sandbox
        from openai_codex.types import ReasoningEffort
    except ModuleNotFoundError as exc:
        raise RuntimeError("openai-codex is not installed in this Python environment") from exc

    prompt = build_prompt(hook_input)
    effort = ReasoningEffort(config.reasoning_effort)
    developer_instructions = (
        "You are a command approval classifier. Do not inspect files, do not run "
        "tools, and do not continue beyond the requested JSON decision."
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
    payload = _parse_json_object(text)
    decision = payload.get("decision")
    reason = payload.get("reason")
    if decision not in {"allow", "deny"}:
        raise ValueError(f"invalid LLM decision: {decision!r}")
    if not isinstance(reason, str) or not reason.strip():
        reason = "Codex AI Approver returned no reason."
    return LlmDecision(decision=decision, reason=reason.strip())


def _parse_json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("LLM response must be a JSON object")
    return value
