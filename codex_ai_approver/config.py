from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import os

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised only without PyYAML.
    yaml = None


DEFAULT_CONFIG_PATH = "~/.codex-ai-approver.yaml"
DEFAULT_MODEL = "gpt-5.5"
DEFAULT_REASONING_EFFORT = "medium"
VALID_DECISIONS = {"allow", "deny"}
VALID_ERROR_POLICIES = {"deny", "allow"}


@dataclass(frozen=True)
class ApproverConfig:
    model: str = DEFAULT_MODEL
    reasoning_effort: str = DEFAULT_REASONING_EFFORT
    on_error: str = "deny"
    cache_ttl_sec: int = 300
    debug: bool = False


def config_path() -> Path:
    raw = os.environ.get("CODEX_AI_APPROVER_CONFIG", DEFAULT_CONFIG_PATH)
    return Path(raw).expanduser()


def load_config(path: Path | None = None) -> ApproverConfig:
    path = path or config_path()
    payload: dict[str, Any] = {}
    if path.is_file():
        payload = _load_yaml(path)

    model = _as_str(payload.get("model"), DEFAULT_MODEL)
    reasoning_effort = _as_str(
        payload.get("reasoning_effort", payload.get("model_reasoning_effort")),
        DEFAULT_REASONING_EFFORT,
    )
    on_error = _as_str(payload.get("on_error"), "deny").lower()
    if on_error not in VALID_ERROR_POLICIES:
        on_error = "deny"

    return ApproverConfig(
        model=model,
        reasoning_effort=reasoning_effort,
        on_error=on_error,
        cache_ttl_sec=_as_int(payload.get("cache_ttl_sec"), 300),
        debug=_as_bool(payload.get("debug"), False),
    )


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to read ~/.codex-ai-approver.yaml")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def _as_str(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _as_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return default
        return parsed if parsed >= 0 else default
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
