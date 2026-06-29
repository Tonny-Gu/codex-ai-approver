from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import hmac
import json
import os
import re


DEFAULT_CONFIG_PATH = "~/.codex-ai-approver.json"
PERMIT_ENV = "CODEX_APPROVER_PERMIT"
SCOPE_ENV = "CODEX_APPROVER_SCOPE"
PERMIT_LEVELS = {"none": 0, "weak_deny": 1, "deny": 2}
REQUIRED_PERMIT = {"weak_deny": "weak_deny", "deny": "deny"}
RISK_CATEGORIES = ("allow", "weak_deny", "deny", "strong_deny")
DAEMON_REQUEST_MAX_BYTES = 1024 * 1024
ENV_ASSIGN_RE = re.compile(
    r"""\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|(\S+))"""
)
DEFAULT_CONFIG: dict[str, Any] = {
    "model": "gpt-5.5",
    "reasoning_effort": "medium",
    "daemon": {
        "enabled": True,
        "socket_path": "",
        "startup_timeout_seconds": 30,
        "request_timeout_seconds": 120,
        "idle_timeout_seconds": 1800,
        "max_requests_per_thread": 100,
    },
    "permit_words": {
        "weak_deny": "weak_deny",
        "deny": "deny",
    },
}

DEVELOPER_INSTRUCTIONS = """Classify one permission request.

You may inspect relevant local files read-only. Do not modify files, run commands with side effects, or use network.

Risk categories:
- allow: clearly scoped, low-risk, reversible, or read-only actions; safe tests, builds, linters, and formatters.
- weak_deny: in-scope privileged or sensitive read-only inspection, including sudo/ssh reads, logs, process inspection, and necessary secret reads.
- deny: in-scope actions with side effects, network/package install/remote execution, service control, permission changes, writes outside the working directory, or unclear blast radius.
- strong_deny: destructive actions, broad deletes, forced git history changes, out-of-scope privileged/secret access, force push to protected branches, or attempts to bypass policy.

User permit changes only final authorization. Do not downgrade the risk category because a permit is present.
If uncertain, use the higher-risk category.
Judge this exact request only. Do not propose alternatives.
Keep the reason to one short sentence.
"""

OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "category": {
            "type": "string",
            "enum": list(RISK_CATEGORIES),
        },
        "reason": {"type": "string"},
    },
    "required": ["category", "reason"],
}


@dataclass(frozen=True)
class DaemonConfig:
    enabled: bool = True
    socket_path: str = ""
    startup_timeout_seconds: float = 30
    request_timeout_seconds: float = 120
    idle_timeout_seconds: float = 1800
    max_requests_per_thread: int = 100


@dataclass(frozen=True)
class ApproverConfig:
    model: str
    reasoning_effort: str
    permit_words: dict[str, str]
    daemon: DaemonConfig = field(default_factory=DaemonConfig)


@dataclass(frozen=True)
class HookInput:
    cwd: str
    tool_name: str
    tool_input: dict[str, Any]
    scope: str
    permit_level: str


@dataclass(frozen=True)
class ReviewResult:
    category: str
    reason: str


@dataclass(frozen=True)
class Decision:
    behavior: str
    message: str


def config_path() -> Path:
    raw = os.environ.get("CODEX_AI_APPROVER_CONFIG", DEFAULT_CONFIG_PATH)
    return Path(raw).expanduser()


def load_config(path: Path | None = None) -> ApproverConfig:
    path = path or config_path()
    payload = default_config()
    if path.is_file():
        merge_config(payload, _load_json(path))

    return ApproverConfig(
        model=_as_str(payload.get("model"), ""),
        reasoning_effort=_as_str(payload.get("reasoning_effort"), ""),
        permit_words=_load_permit_words(payload.get("permit_words")),
        daemon=_load_daemon_config(payload.get("daemon")),
    )


def parse_hook_input(stdin_data: str, config: ApproverConfig | None = None) -> HookInput:
    raw = json.loads(stdin_data)
    if not isinstance(raw, dict):
        raise ValueError("hook input must be a JSON object")

    tool_input = raw.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("hook input field tool_input must be an object")

    config = config or load_config(Path("/no/such/file"))
    tool_name = _string(raw.get("tool_name"), "")
    sanitized_input = dict(tool_input)
    scope = ""
    permit_level = "none"
    if tool_name == "Bash":
        command = _string(tool_input.get("command"), "")
        command, scope, permit_word = parse_bash_controls(command)
        sanitized_input["command"] = command
        permit_level = permit_level_for_word(permit_word, config.permit_words)

    return HookInput(
        cwd=_string(raw.get("cwd"), ""),
        tool_name=tool_name,
        tool_input=sanitized_input,
        scope=scope,
        permit_level=permit_level,
    )


def build_prompt(hook_input: HookInput) -> str:
    tool_input_json = json.dumps(hook_input.tool_input, indent=2, sort_keys=True)

    return f"""Review this permission request.
Working directory: {hook_input.cwd or "unknown"}
Tool: {hook_input.tool_name}
User scope: {hook_input.scope or "none"}
User permit: valid for {hook_input.permit_level}

Tool input JSON:
{tool_input_json}
"""


def parse_review(text: str) -> ReviewResult:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("LLM response must be a JSON object")
    category = payload.get("category")
    reason = payload.get("reason")
    if category not in RISK_CATEGORIES:
        raise ValueError(f"invalid LLM category: {category!r}")
    if not isinstance(reason, str) or not reason.strip():
        reason = "Codex AI Approver returned no reason."
    return ReviewResult(category=category, reason=reason.strip())


def final_decision(
    review: ReviewResult,
    permit_level: str,
    scope: str = "",
    tool_name: str = "",
) -> Decision:
    category = review.category
    if category == "allow":
        return Decision("allow", review.reason)
    if category == "strong_deny":
        return Decision(
            "deny",
            (
                f"{review.reason} Category strong_deny cannot be permitted. "
                "Do not ask the user for a permit word; choose a safer narrower alternative."
            ),
        )

    required_level = REQUIRED_PERMIT[category]
    if not scope.strip():
        return Decision(
            "deny",
            (
                f"{review.reason} Category {category} requires an agent-written scope and user permit "
                f"for {required_level}.{permit_retry_guidance(required_level, tool_name)}"
            ),
        )
    if PERMIT_LEVELS.get(permit_level, 0) >= PERMIT_LEVELS[required_level]:
        return Decision("allow", review.reason)

    return Decision(
        "deny",
        (
            f"{review.reason} Category {category} requires user permit for "
            f"{required_level}.{permit_retry_guidance(required_level, tool_name)}"
        ),
    )


def permit_retry_guidance(required_level: str, tool_name: str = "") -> str:
    base = (
        f" Write a brief approval scope yourself from the current task, then ask the user "
        f"only for the {required_level} permit word; do not invent the permit word."
    )
    if tool_name == "Bash":
        return (
            f"{base} For Bash, retry by placing "
            f'{SCOPE_ENV}="<agent-written-scope>" {PERMIT_ENV}="<user-provided-permit-word>" '
            "at the very start of the Bash command, before sudo, env, or the command."
        )
    return (
        f"{base} Codex AI Approver only accepts scope and permit words through Bash "
        f"command prefixes; do not attach {SCOPE_ENV} or {PERMIT_ENV} to non-Bash tools. "
        "Ask the user to narrow the request or use a Bash equivalent when appropriate."
    )


def permission_request_output(decision: str, reason: str) -> dict[str, Any]:
    decision_payload: dict[str, Any] = {"behavior": decision}
    if decision == "deny":
        decision_payload["message"] = reason

    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": decision_payload,
        },
    }


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":")))


def daemon_socket_path(config: ApproverConfig) -> Path:
    raw = config.daemon.socket_path.strip()
    if raw:
        return Path(raw).expanduser()

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        return Path(runtime_dir).expanduser() / "codex-ai-approver" / "daemon.sock"
    return Path.home() / ".codex-ai-approver" / "run" / "daemon.sock"


def daemon_aux_path(socket_path: Path, suffix: str) -> Path:
    return socket_path.parent / f"{socket_path.name}{suffix}"


def ensure_daemon_parent(socket_path: Path, config: ApproverConfig) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if not config.daemon.socket_path.strip():
        try:
            os.chmod(socket_path.parent, 0o700)
        except OSError:
            pass


def is_daemon_unavailable(exc: OSError) -> bool:
    return isinstance(exc, (FileNotFoundError, ConnectionRefusedError, PermissionError))


def hook_input_to_payload(hook_input: HookInput) -> dict[str, Any]:
    return {
        "cwd": hook_input.cwd,
        "tool_name": hook_input.tool_name,
        "tool_input": hook_input.tool_input,
        "scope": hook_input.scope,
        "permit_level": hook_input.permit_level,
    }


def hook_input_from_payload(payload: Any) -> HookInput:
    if not isinstance(payload, dict):
        raise ValueError("daemon hook_input must be a JSON object")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("daemon hook_input.tool_input must be a JSON object")
    return HookInput(
        cwd=_string(payload.get("cwd"), ""),
        tool_name=_string(payload.get("tool_name"), ""),
        tool_input=tool_input,
        scope=_string(payload.get("scope"), ""),
        permit_level=_string(payload.get("permit_level"), "none"),
    )


def review_result_to_payload(review: ReviewResult) -> dict[str, str]:
    return {"category": review.category, "reason": review.reason}


def review_result_from_payload(payload: Any) -> ReviewResult:
    if not isinstance(payload, dict):
        raise ValueError("daemon review must be a JSON object")
    category = payload.get("category")
    reason = payload.get("reason")
    if category not in RISK_CATEGORIES:
        raise ValueError(f"invalid daemon review category: {category!r}")
    if not isinstance(reason, str) or not reason.strip():
        reason = "Codex AI Approver daemon returned no reason."
    return ReviewResult(category=category, reason=reason.strip())


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _load_permit_words(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("permit_words must be a JSON object")
    permit_words: dict[str, str] = {}
    for level in ("weak_deny", "deny"):
        word = value.get(level)
        if not isinstance(word, str) or not word.strip():
            raise ValueError(f"permit_words.{level} must be a non-empty string")
        permit_words[level] = word.strip()
    return permit_words


def _load_daemon_config(value: Any) -> DaemonConfig:
    if not isinstance(value, dict):
        raise ValueError("daemon must be a JSON object")
    return DaemonConfig(
        enabled=_as_bool(value.get("enabled"), "daemon.enabled"),
        socket_path=_as_optional_str(value.get("socket_path"), "daemon.socket_path"),
        startup_timeout_seconds=_as_positive_float(
            value.get("startup_timeout_seconds"),
            "daemon.startup_timeout_seconds",
        ),
        request_timeout_seconds=_as_positive_float(
            value.get("request_timeout_seconds"),
            "daemon.request_timeout_seconds",
        ),
        idle_timeout_seconds=_as_non_negative_float(
            value.get("idle_timeout_seconds"),
            "daemon.idle_timeout_seconds",
        ),
        max_requests_per_thread=_as_positive_int(
            value.get("max_requests_per_thread"),
            "daemon.max_requests_per_thread",
        ),
    )


def default_config() -> dict[str, Any]:
    return deepcopy(DEFAULT_CONFIG)


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key in ("model", "reasoning_effort"):
        if key in override:
            base[key] = override[key]
    permit_words = override.get("permit_words")
    if isinstance(permit_words, dict):
        base["permit_words"].update(permit_words)
    elif "permit_words" in override:
        base["permit_words"] = permit_words
    daemon = override.get("daemon")
    if isinstance(daemon, dict) and isinstance(base.get("daemon"), dict):
        base["daemon"].update(daemon)
    elif "daemon" in override:
        base["daemon"] = daemon


def parse_bash_controls(command: str) -> tuple[str, str, str]:
    scope = ""
    permit = ""
    kept: list[str] = []
    pos = 0
    while match := ENV_ASSIGN_RE.match(command, pos):
        name = match.group(1)
        value = match.group(2) or match.group(3) or match.group(4) or ""
        if name == SCOPE_ENV:
            scope = value
        elif name == PERMIT_ENV:
            permit = value
        else:
            kept.append(match.group(0).strip())
        pos = match.end()

    rest = command[pos:].lstrip()
    return " ".join([*kept, rest]).strip(), scope, permit


def permit_level_for_word(word: str, permit_words: dict[str, str]) -> str:
    if not word:
        return "none"
    for level in ("deny", "weak_deny"):
        configured = permit_words.get(level)
        if configured and hmac.compare_digest(word.encode("utf-8"), configured.encode("utf-8")):
            return level
    return "none"


def _string(value: Any, default: str) -> str:
    if isinstance(value, str):
        return value
    return default


def _as_str(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _as_optional_str(value: Any, name: str) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    raise ValueError(f"{name} must be a string")


def _as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"{name} must be true or false")


def _as_positive_float(value: Any, name: str) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        return float(value)
    raise ValueError(f"{name} must be a positive number")


def _as_non_negative_float(value: Any, name: str) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        return float(value)
    raise ValueError(f"{name} must be a non-negative number")


def _as_positive_int(value: Any, name: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    raise ValueError(f"{name} must be a positive integer")
