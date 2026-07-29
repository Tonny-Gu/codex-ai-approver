from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import os
import uuid


DEFAULT_CONFIG_PATH = "~/.codex-ai-approver.json"
POLICY_TEMPLATE_PATH = Path(__file__).with_name("guardian_policy.md")
GUARDIAN_ASSESSMENT_PREFIX = "CODEX_AI_APPROVER_GUARDIAN_ASSESSMENT "

RISK_LEVELS = ("low", "medium", "high", "critical")
USER_AUTHORIZATION_LEVELS = ("unknown", "low", "medium", "high")
OUTCOMES = ("allow", "deny")

DEFAULT_OUTCOME_POLICY = """- Assign `risk_level` and `user_authorization` before deciding.
- `risk_level = "low"` -> allow.
- `risk_level = "medium"` -> allow only when `user_authorization` is at least
  `medium` and the action remains proportionate and bounded; otherwise deny.
- `risk_level = "high"` -> `user_authorization = "high"` is necessary but not
  sufficient. Allow only when the action is exact, narrowly scoped, and has no
  absolute deny rule; otherwise deny.
- `risk_level = "critical"` -> deny.
- For a critical denial, state in `decision_rationale` that the agent must not
  perform the action and that the user should carry it out manually if they
  still want it.
- These rules are applied by the guardian. Application code must not replace
  the guardian's judgment with numeric level comparison."""

DEFAULT_CONFIG: dict[str, Any] = {
    "model": "gpt-5.6-sol",
    "reasoning_effort": "medium",
    "daemon_port": 47678,
    "batch_wait_seconds": 0.1,
    "outcome_policy": DEFAULT_OUTCOME_POLICY,
}

ASSESSMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "request_id": {"type": "string"},
        "risk_level": {"type": "string", "enum": list(RISK_LEVELS)},
        "user_authorization": {
            "type": "string",
            "enum": list(USER_AUTHORIZATION_LEVELS),
        },
        "outcome": {"type": "string", "enum": list(OUTCOMES)},
        "decision_rationale": {"type": "string"},
        "classification_rationale": {"type": "string"},
    },
    "required": [
        "request_id",
        "risk_level",
        "user_authorization",
        "outcome",
        "decision_rationale",
        "classification_rationale",
    ],
}

OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "assessments": {
            "type": "array",
            "items": ASSESSMENT_SCHEMA,
            "minItems": 1,
        }
    },
    "required": ["assessments"],
}


@dataclass(frozen=True)
class GuardianConfig:
    model: str
    reasoning_effort: str
    outcome_policy: str
    daemon_port: int = 47678
    batch_wait_seconds: float = 0.1


@dataclass(frozen=True)
class PermissionRequestInput:
    request_id: str
    session_id: str
    turn_id: str
    agent_id: str | None
    agent_type: str | None
    transcript_path: str | None
    cwd: str
    tool_name: str
    tool_input: dict[str, Any]

    @property
    def guardian_key(self) -> tuple[str, str]:
        return (self.session_id, self.agent_id or "root")


@dataclass(frozen=True)
class GuardianAssessment:
    risk_level: str
    user_authorization: str
    outcome: str
    decision_rationale: str
    classification_rationale: str


def config_path() -> Path:
    raw = os.environ.get("CODEX_AI_APPROVER_CONFIG", DEFAULT_CONFIG_PATH)
    return Path(raw).expanduser()


def load_config(path: Path | None = None) -> GuardianConfig:
    path = path or config_path()
    payload = default_config()
    if path.is_file():
        merge_config(payload, _load_json(path))

    return GuardianConfig(
        model=_as_nonempty_str(payload.get("model"), "model"),
        reasoning_effort=_as_nonempty_str(
            payload.get("reasoning_effort"),
            "reasoning_effort",
        ),
        outcome_policy=_as_nonempty_str(
            payload.get("outcome_policy"),
            "outcome_policy",
        ),
        daemon_port=_as_port(payload.get("daemon_port"), "daemon_port"),
        batch_wait_seconds=_as_wait_seconds(
            payload.get("batch_wait_seconds"),
            "batch_wait_seconds",
        ),
    )


def config_fingerprint(config: GuardianConfig) -> str:
    payload = {
        "model": config.model,
        "reasoning_effort": config.reasoning_effort,
        "outcome_policy": config.outcome_policy,
        "daemon_port": config.daemon_port,
        "batch_wait_seconds": config.batch_wait_seconds,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def guardian_policy_prompt(config: GuardianConfig) -> str:
    template = POLICY_TEMPLATE_PATH.read_text(encoding="utf-8")
    return template.replace("{{ outcome_policy }}", config.outcome_policy.strip())


def parse_permission_request_input(stdin_data: str) -> PermissionRequestInput:
    raw = json.loads(stdin_data)
    if not isinstance(raw, dict):
        raise ValueError("hook input must be a JSON object")

    tool_input = raw.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("hook input field tool_input must be an object")

    session_id = _string(raw.get("session_id"))
    turn_id = _string(raw.get("turn_id"))
    tool_name = _string(raw.get("tool_name"))
    if not session_id:
        raise ValueError("hook input field session_id must be a non-empty string")
    if not turn_id:
        raise ValueError("hook input field turn_id must be a non-empty string")
    if not tool_name:
        raise ValueError("hook input field tool_name must be a non-empty string")

    return PermissionRequestInput(
        request_id=uuid.uuid4().hex,
        session_id=session_id,
        turn_id=turn_id,
        agent_id=_optional_string(raw.get("agent_id")),
        agent_type=_optional_string(raw.get("agent_type")),
        transcript_path=_optional_string(raw.get("transcript_path")),
        cwd=_string(raw.get("cwd")),
        tool_name=tool_name,
        tool_input=deepcopy(tool_input),
    )


def parse_guardian_assessments(
    text: str,
    expected_request_ids: list[str],
) -> dict[str, GuardianAssessment]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("guardian response must be a JSON object")
    raw_assessments = payload.get("assessments")
    if not isinstance(raw_assessments, list):
        raise ValueError("guardian response assessments must be an array")

    expected = set(expected_request_ids)
    parsed: dict[str, GuardianAssessment] = {}
    for raw in raw_assessments:
        if not isinstance(raw, dict):
            raise ValueError("each guardian assessment must be an object")
        request_id = _string(raw.get("request_id"))
        if request_id not in expected:
            raise ValueError(f"unexpected guardian request_id: {request_id!r}")
        if request_id in parsed:
            raise ValueError(f"duplicate guardian request_id: {request_id!r}")

        risk_level = _enum_value(raw.get("risk_level"), RISK_LEVELS, "risk_level")
        user_authorization = _enum_value(
            raw.get("user_authorization"),
            USER_AUTHORIZATION_LEVELS,
            "user_authorization",
        )
        outcome = _enum_value(raw.get("outcome"), OUTCOMES, "outcome")
        decision_rationale = _as_nonempty_str(
            raw.get("decision_rationale"),
            "decision_rationale",
        )
        classification_rationale = _as_nonempty_str(
            raw.get("classification_rationale"),
            "classification_rationale",
        )
        parsed[request_id] = GuardianAssessment(
            risk_level=risk_level,
            user_authorization=user_authorization,
            outcome=outcome,
            decision_rationale=decision_rationale,
            classification_rationale=classification_rationale,
        )

    missing = expected - set(parsed)
    if missing:
        raise ValueError(
            "guardian response omitted request_ids: " + ", ".join(sorted(missing))
        )
    if len(parsed) != len(expected_request_ids):
        raise ValueError("guardian returned an unexpected number of assessments")
    return parsed


def parse_guardian_assessment_mapping(
    payload: Any,
    request_id: str,
) -> GuardianAssessment:
    if not isinstance(payload, dict):
        raise ValueError("guardian daemon response must be an object")
    item = dict(payload)
    item["request_id"] = request_id
    parsed = parse_guardian_assessments(
        json.dumps({"assessments": [item]}, ensure_ascii=False),
        [request_id],
    )
    return parsed[request_id]


def action_fingerprint(hook_input: PermissionRequestInput) -> str:
    return canonical_action_fingerprint(
        hook_input.tool_name,
        hook_input.tool_input,
    )


def canonical_action_fingerprint(tool_name: str, tool_input: Any) -> str:
    payload = {
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return sha256(encoded).hexdigest()[:24]


def guardian_assessment_record(
    hook_input: PermissionRequestInput,
    assessment: GuardianAssessment,
) -> dict[str, Any]:
    return {
        "kind": "guardian_assessment",
        "turn_id": hook_input.turn_id,
        "tool": hook_input.tool_name,
        "action_fingerprint": action_fingerprint(hook_input),
        "risk_level": assessment.risk_level,
        "user_authorization": assessment.user_authorization,
        "outcome": assessment.outcome,
        "decision_rationale": assessment.decision_rationale,
        "classification_rationale": assessment.classification_rationale,
    }


def guardian_assessment_system_message(
    hook_input: PermissionRequestInput,
    assessment: GuardianAssessment,
) -> str:
    payload = json.dumps(
        guardian_assessment_record(hook_input, assessment),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return f"{GUARDIAN_ASSESSMENT_PREFIX}{payload}"


def permission_request_output(
    hook_input: PermissionRequestInput,
    assessment: GuardianAssessment,
) -> dict[str, Any]:
    decision: dict[str, Any] = {"behavior": assessment.outcome}
    if assessment.outcome == "deny":
        decision["message"] = assessment_message(assessment)

    return {
        "systemMessage": guardian_assessment_system_message(
            hook_input,
            assessment,
        ),
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": decision,
        },
    }


def permission_request_error_output(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": reason,
            },
        },
    }


def assessment_message(assessment: GuardianAssessment) -> str:
    return (
        f"{assessment.decision_rationale.strip()} "
        f"{assessment.classification_rationale.strip()}"
    ).strip()


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def is_daemon_unavailable(exc: OSError) -> bool:
    return isinstance(exc, (ConnectionRefusedError, PermissionError))


def default_config() -> dict[str, Any]:
    return deepcopy(DEFAULT_CONFIG)


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> None:
    allowed = {
        "model",
        "reasoning_effort",
        "daemon_port",
        "batch_wait_seconds",
        "outcome_policy",
    }
    unknown = sorted(set(override) - allowed)
    if unknown:
        raise ValueError(f"unknown config fields: {', '.join(unknown)}")
    for key in allowed:
        if key in override:
            base[key] = override[key]


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _enum_value(value: Any, allowed: tuple[str, ...], name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(allowed)}")
    return value


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_nonempty_str(value: Any, name: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ValueError(f"{name} must be a non-empty string")


def _as_port(value: Any, name: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535:
        return value
    raise ValueError(f"{name} must be an integer from 1 to 65535")


def _as_wait_seconds(value: Any, name: str) -> float:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= float(value) <= 5
    ):
        return float(value)
    raise ValueError(f"{name} must be a number from 0 to 5")
