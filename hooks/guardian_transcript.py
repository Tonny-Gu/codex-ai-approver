from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
import json

from guardian_common import GUARDIAN_ASSESSMENT_PREFIX
from guardian_common import canonical_action_fingerprint


MAX_TEXT_CHARS = 16_000

CONTEXTUAL_USER_PREFIXES = (
    "<environment_context>",
    "<environments_instructions>",
    "<permissions instructions>",
    "<collaboration_mode>",
    "<multi_agent_mode>",
    "<apps_instructions>",
    "<plugins_instructions>",
    "<skills_instructions>",
    "<tools>",
    "<personality_spec>",
    "<context_window>",
    "<context_window_guidance>",
    "<rollout_budget>",
    "<token_budget>",
    "<user_instructions>",
    "<additional_context>",
    "<user_shell_command>",
    "<turn_aborted>",
    "<subagent_notification>",
    "<internal_model_context>",
    "<recommended_plugins>",
    "<hook_prompt",
    "# agents.md instructions",
)


@dataclass(frozen=True)
class TranscriptSnapshot:
    window_key: str
    compacted: bool
    entries: tuple[dict[str, Any], ...]
    source_size: int
    current_user_turn: int = 0

    def render(self) -> str:
        return json.dumps(
            list(self.entries),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )


class _TranscriptBuilder:
    def __init__(self) -> None:
        self.window_key = "initial"
        self.compacted = False
        self.prefix_entries: list[dict[str, Any]] = []
        self.orphan_entries: list[dict[str, Any]] = []
        self.turns: list[list[dict[str, Any]]] = []
        self.calls: dict[str, dict[str, Any]] = {}

    def compact(self, payload: dict[str, Any], ordinal: int) -> None:
        window_id = payload.get("window_id")
        window_number = payload.get("window_number")
        if isinstance(window_id, str) and window_id:
            self.window_key = window_id
        elif isinstance(window_number, int):
            self.window_key = f"window-{window_number}"
        else:
            self.window_key = f"legacy-window-{ordinal}"
        self.compacted = True
        self.prefix_entries = [
            {
                "kind": "compacted_summary",
                "authorization_cap": "medium",
                "authorization_grants_reset": True,
                "user_turn": 0,
                "text": _bounded_text(payload.get("message", "")),
            }
        ]
        self.orphan_entries = []
        self.turns = []
        self.calls = {}

    def add_user_message(self, text: str) -> None:
        user_turn = len(self.turns) + 1
        self.turns.append(
            [
                {
                    "kind": "user_message",
                    "authorization_source": "direct",
                    "user_turn": user_turn,
                    "text": _bounded_text(text),
                }
            ]
        )

    def add_entry(self, entry: dict[str, Any]) -> None:
        entry.setdefault("user_turn", len(self.turns))
        if self.turns:
            self.turns[-1].append(entry)
        else:
            self.orphan_entries.append(entry)

    def add_tool_call(self, payload: dict[str, Any]) -> None:
        kind = payload.get("type")
        call_id = _call_id(payload)
        if kind == "function_call":
            tool = _string(payload.get("name")) or "unknown"
            tool_input = _decode_json_or_text(payload.get("arguments"))
        elif kind == "custom_tool_call":
            tool = _string(payload.get("name")) or "unknown"
            tool_input = _decode_json_or_text(payload.get("input"))
        elif kind == "local_shell_call":
            tool = "shell"
            tool_input = _bounded_value(payload.get("action"))
        elif kind == "web_search_call":
            tool = "web_search"
            tool_input = _bounded_value(payload.get("action"))
        else:
            return

        entry = {
            "kind": "tool_use",
            "call_id": call_id,
            "tool": tool,
            "input": tool_input,
            "action_fingerprint": canonical_action_fingerprint(tool, tool_input),
            "approval": "not_recorded",
            "approval_source": "not_recorded",
            "execution_status": "requested",
        }
        self.add_entry(entry)
        if call_id:
            self.calls[call_id] = entry

    def add_tool_output(self, payload: dict[str, Any]) -> None:
        call_id = _call_id(payload)
        entry = self.calls.get(call_id)
        if entry is None:
            self.add_entry(
                {
                    "kind": "tool_result",
                    "call_id": call_id,
                    "execution_status": "returned",
                    "output_omitted": True,
                }
            )
            return
        if entry.get("approval") == "deny":
            entry["execution_status"] = "not_run"
        else:
            if entry.get("approval") == "not_recorded":
                entry["approval"] = "allowed_or_not_required"
                entry["approval_source"] = "execution_observed"
            entry["execution_status"] = "returned"

    def add_guardian_assessment(self, record: dict[str, Any]) -> None:
        record = _bounded_value(record)
        if not isinstance(record, dict):
            return
        if record.get("user_authorization") == "unknown":
            record["user_authorization"] = "none"
            record["authorization_migrated_from"] = "unknown"
        record["authorization_source"] = "previous_guardian_assessment"
        record["authorization_cap"] = "medium"
        tool_entry = self._matching_tool_entry(record)
        outcome = record.get("outcome")
        if tool_entry is not None and outcome in {"allow", "deny"}:
            tool_entry["approval"] = outcome
            tool_entry["approval_source"] = "guardian"
            if outcome == "deny":
                tool_entry["execution_status"] = "not_run"
        self.add_entry(record)

    def set_exec_status(self, payload: dict[str, Any]) -> None:
        call_id = _call_id(payload)
        entry = self.calls.get(call_id)
        if entry is None:
            return
        exit_code = payload.get("exit_code")
        entry["approval"] = "allowed_or_not_required"
        entry["execution_status"] = "succeeded" if exit_code == 0 else "failed"
        if isinstance(exit_code, int):
            entry["exit_code"] = exit_code

    def rollback(self, num_turns: int) -> None:
        if num_turns <= 0:
            return
        del self.turns[max(0, len(self.turns) - num_turns) :]
        self.calls = {}
        for entry in [*self.orphan_entries, *(item for turn in self.turns for item in turn)]:
            if entry.get("kind") == "tool_use" and entry.get("call_id"):
                self.calls[str(entry["call_id"])] = entry

    def _matching_tool_entry(
        self,
        record: dict[str, Any],
    ) -> dict[str, Any] | None:
        entries = [
            *self.orphan_entries,
            *(item for turn in self.turns for item in turn),
        ]
        fingerprint = record.get("action_fingerprint")
        if isinstance(fingerprint, str):
            for entry in reversed(entries):
                if (
                    entry.get("kind") == "tool_use"
                    and entry.get("approval_source") != "guardian"
                    and entry.get("action_fingerprint") == fingerprint
                ):
                    return entry
        tool = _normalized_tool(record.get("tool"))
        if tool:
            for entry in reversed(entries):
                if (
                    entry.get("kind") == "tool_use"
                    and entry.get("approval_source") != "guardian"
                    and _normalized_tool(entry.get("tool")) == tool
                ):
                    return entry
        for entry in reversed(entries):
            if (
                entry.get("kind") == "tool_use"
                and entry.get("approval_source") != "guardian"
            ):
                return entry
        return None

    def snapshot(self, source_size: int) -> TranscriptSnapshot:
        entries = [
            *self.prefix_entries,
            *self.orphan_entries,
            *(entry for turn in self.turns for entry in turn),
        ]
        return TranscriptSnapshot(
            window_key=self.window_key,
            compacted=self.compacted,
            entries=tuple(entries),
            source_size=source_size,
            current_user_turn=len(self.turns),
        )


def derive_transcript_snapshot(transcript_path: str | None) -> TranscriptSnapshot:
    if not transcript_path:
        return TranscriptSnapshot(
            window_key="unavailable",
            compacted=False,
            entries=(
                {
                    "kind": "transcript_unavailable",
                    "authorization_source": "none",
                },
            ),
            source_size=0,
            current_user_turn=0,
        )

    path = Path(transcript_path)
    builder = _TranscriptBuilder()
    ordinal = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            ordinal += 1
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                # A concurrently appended final line may be incomplete.
                continue
            if not isinstance(item, dict):
                continue
            _consume_rollout_item(builder, item, ordinal)
        source_size = handle.tell()
    return builder.snapshot(source_size)


def _consume_rollout_item(
    builder: _TranscriptBuilder,
    item: dict[str, Any],
    ordinal: int,
) -> None:
    item_type = item.get("type")
    payload = item.get("payload")
    if not isinstance(payload, dict):
        return

    if item_type == "compacted":
        builder.compact(payload, ordinal)
        return
    if item_type == "response_item":
        _consume_response_item(builder, payload)
        return
    if item_type != "event_msg":
        return

    event_type = payload.get("type")
    if event_type == "thread_rolled_back":
        num_turns = payload.get("num_turns")
        if isinstance(num_turns, int):
            builder.rollback(num_turns)
    elif event_type == "hook_completed":
        _consume_hook_completed(builder, payload)
    elif event_type == "exec_command_end":
        builder.set_exec_status(payload)


def _consume_response_item(
    builder: _TranscriptBuilder,
    payload: dict[str, Any],
) -> None:
    item_type = payload.get("type")
    if item_type == "message" and payload.get("role") == "user":
        content = payload.get("content")
        if not isinstance(content, list) or _is_contextual_user_content(content):
            return
        text = _content_text(content)
        if text.strip():
            builder.add_user_message(text)
        return
    if item_type in {
        "function_call",
        "custom_tool_call",
        "local_shell_call",
        "web_search_call",
    }:
        builder.add_tool_call(payload)
        return
    if item_type in {"function_call_output", "custom_tool_call_output"}:
        builder.add_tool_output(payload)


def _consume_hook_completed(
    builder: _TranscriptBuilder,
    payload: dict[str, Any],
) -> None:
    run = payload.get("run")
    if not isinstance(run, dict) or run.get("event_name") != "permission_request":
        return
    entries = run.get("entries")
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        text = entry.get("text")
        if not isinstance(text, str) or not text.startswith(GUARDIAN_ASSESSMENT_PREFIX):
            continue
        try:
            record = json.loads(text[len(GUARDIAN_ASSESSMENT_PREFIX) :])
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            builder.add_guardian_assessment(record)


def _is_contextual_user_content(content: list[Any]) -> bool:
    for item in content:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        normalized = text.lstrip().lower()
        if any(normalized.startswith(prefix) for prefix in CONTEXTUAL_USER_PREFIXES):
            return True
    return False


def _content_text(content: list[Any]) -> str:
    values: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type in {"input_text", "output_text"} and isinstance(item.get("text"), str):
            values.append(item["text"])
        elif item_type == "input_image":
            values.append(_opaque_media_marker("image", item.get("image_url")))
        elif item_type == "input_audio":
            values.append(_opaque_media_marker("audio", item.get("audio_url")))
    return "\n".join(values)


def _opaque_media_marker(kind: str, value: Any) -> str:
    raw = value if isinstance(value, str) else ""
    digest = sha256(raw.encode()).hexdigest()[:16]
    return f"<{kind} omitted sha256={digest}>"


def _decode_json_or_text(value: Any) -> Any:
    if not isinstance(value, str):
        return _bounded_value(value)
    try:
        return _bounded_value(json.loads(value))
    except json.JSONDecodeError:
        return _bounded_text(value)


def _bounded_value(value: Any) -> Any:
    if isinstance(value, str):
        return _bounded_text(value)
    if isinstance(value, list):
        return [_bounded_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _bounded_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _bounded_text(str(value))


def _bounded_text(value: Any) -> str:
    text = value if isinstance(value, str) else str(value)
    if len(text) <= MAX_TEXT_CHARS:
        return text
    digest = sha256(text.encode()).hexdigest()
    keep = (MAX_TEXT_CHARS - 160) // 2
    marker = (
        f"\n<guardian_truncated chars={len(text)} sha256={digest} "
        f"omitted={len(text) - (2 * keep)} />\n"
    )
    return f"{text[:keep]}{marker}{text[-keep:]}"


def _call_id(payload: dict[str, Any]) -> str:
    for key in ("call_id", "id", "tool_use_id"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    return ""


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _normalized_tool(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.lower()
    aliases = {
        "bash": "shell",
        "exec_command": "shell",
        "functions.exec_command": "shell",
    }
    return aliases.get(normalized, normalized)
