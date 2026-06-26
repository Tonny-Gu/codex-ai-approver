from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import time

from .hook_io import HookInput, extract_target


@dataclass(frozen=True)
class CachedDecision:
    decision: str
    reason: str
    created_at: float


def cache_dir() -> Path:
    plugin_data = os.environ.get("PLUGIN_DATA")
    if plugin_data:
        return Path(plugin_data) / "cache"
    return Path.home() / ".codex-ai-approver" / "cache"


def cache_key(hook_input: HookInput) -> str:
    material = {
        "session_id": hook_input.session_id,
        "turn_id": hook_input.turn_id,
        "cwd": hook_input.cwd,
        "tool_name": hook_input.tool_name,
        "target": extract_target(hook_input),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_cached_decision(hook_input: HookInput, ttl_sec: int) -> CachedDecision | None:
    path = cache_dir() / f"{cache_key(hook_input)}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    created_at = payload.get("created_at")
    if not isinstance(created_at, (int, float)):
        return None
    if ttl_sec > 0 and time.time() - float(created_at) > ttl_sec:
        return None
    decision = payload.get("decision")
    reason = payload.get("reason")
    if decision not in {"allow", "deny"} or not isinstance(reason, str):
        return None
    return CachedDecision(decision=decision, reason=reason, created_at=float(created_at))


def write_cached_decision(hook_input: HookInput, decision: str, reason: str) -> None:
    item = CachedDecision(decision=decision, reason=reason, created_at=time.time())
    root = cache_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{cache_key(hook_input)}.json"
    path.write_text(json.dumps(asdict(item), indent=2) + "\n", encoding="utf-8")
