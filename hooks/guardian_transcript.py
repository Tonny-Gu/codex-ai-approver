from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json


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
                "text": payload.get("message", ""),
            }
        ]
        self.orphan_entries = []
        self.turns = []

    def add_user_message(self, text: str) -> None:
        user_turn = len(self.turns) + 1
        self.turns.append(
            [
                {
                    "kind": "user_message",
                    "authorization_source": "direct",
                    "user_turn": user_turn,
                    "text": text,
                }
            ]
        )

    def add_entry(self, entry: dict[str, Any]) -> None:
        entry.setdefault("user_turn", len(self.turns))
        if self.turns:
            self.turns[-1].append(entry)
        else:
            self.orphan_entries.append(entry)

    def add_hook_message(self, text: str) -> None:
        self.add_entry(
            {
                "kind": "hook_message",
                "text": text,
            }
        )

    def rollback(self, num_turns: int) -> None:
        if num_turns <= 0:
            return
        del self.turns[max(0, len(self.turns) - num_turns) :]

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


def _consume_response_item(
    builder: _TranscriptBuilder,
    payload: dict[str, Any],
) -> None:
    item_type = payload.get("type")
    if item_type == "message" and payload.get("role") == "user":
        content = payload.get("content")
        if not isinstance(content, list):
            return
        text = "\n".join(
            item["text"]
            for item in content
            if isinstance(item, dict)
            and isinstance(item.get("text"), str)
        )
        if text.strip():
            builder.add_user_message(text)


def _consume_hook_completed(
    builder: _TranscriptBuilder,
    payload: dict[str, Any],
) -> None:
    run = payload.get("run")
    if not isinstance(run, dict):
        return
    entries = run.get("entries")
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        text = entry.get("text")
        if isinstance(text, str) and text.strip():
            builder.add_hook_message(text)
