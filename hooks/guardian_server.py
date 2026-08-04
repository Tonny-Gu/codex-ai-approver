from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from socketserver import ThreadingMixIn
from threading import Event, Lock
from typing import Any
from xmlrpc.server import SimpleXMLRPCServer
import json
import logging
import sys
import time

from guardian_common import (
    OUTPUT_SCHEMA,
    GuardianAssessment,
    GuardianConfig,
    PermissionRequestInput,
    config_fingerprint,
    guardian_policy_prompt,
    load_config,
    parse_guardian_assessments,
)
from guardian_transcript import TranscriptSnapshot, derive_transcript_snapshot


LOGGER = logging.getLogger("codex_ai_approver.guardian")


class ThreadingXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    daemon_threads = True


@dataclass
class _GuardianThreadState:
    thread: Any
    lock: Lock = field(default_factory=Lock)
    has_temporary_request_turn: bool = False


@dataclass
class _PendingAssessment:
    hook_input: PermissionRequestInput
    snapshot: TranscriptSnapshot
    event: Event = field(default_factory=Event)
    assessment: GuardianAssessment | None = None
    error: Exception | None = None


class GuardianDaemon:
    def __init__(self, config: GuardianConfig) -> None:
        self.config = config
        self._codex: Any = None
        self._effort: Any = None
        self._approval_mode: Any = None
        self._sandbox: Any = None
        self._rollback_response: Any = None
        self._threads: dict[tuple[str, str], _GuardianThreadState] = {}
        self._threads_lock = Lock()
        self._batches: dict[
            tuple[str, str, str],
            list[_PendingAssessment],
        ] = {}
        self._batches_lock = Lock()

    def start(self) -> None:
        try:
            from openai_codex import ApprovalMode, Codex, Sandbox
            from openai_codex.generated.v2_all import ThreadRollbackResponse
            from openai_codex.types import ReasoningEffort
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "openai-codex is not installed in this Python environment"
            ) from exc

        self._approval_mode = ApprovalMode
        self._sandbox = Sandbox
        self._rollback_response = ThreadRollbackResponse
        self._effort = ReasoningEffort(self.config.reasoning_effort)
        self._codex = Codex()

    def assess(self, hook_input: PermissionRequestInput) -> GuardianAssessment:
        snapshot = derive_transcript_snapshot(hook_input.transcript_path)
        pending = _PendingAssessment(hook_input=hook_input, snapshot=snapshot)
        batch_key = (*hook_input.guardian_key, snapshot.window_key)

        with self._batches_lock:
            batch = self._batches.get(batch_key)
            if batch is None:
                batch = []
                self._batches[batch_key] = batch
                leader = True
            else:
                leader = False
            batch.append(pending)

        if leader:
            time.sleep(self.config.batch_wait_seconds)
            with self._batches_lock:
                ready = self._batches.pop(batch_key)
            self._complete_batch(ready)
        else:
            pending.event.wait()

        if pending.error is not None:
            raise pending.error
        if pending.assessment is None:
            raise RuntimeError("guardian batch completed without an assessment")
        return pending.assessment

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "config_fingerprint": config_fingerprint(self.config),
        }

    def close(self) -> None:
        if self._codex is not None:
            self._codex.close()
        self._codex = None
        self._threads = {}

    def _complete_batch(self, batch: list[_PendingAssessment]) -> None:
        try:
            assessments = self._assess_batch(batch)
            for pending in batch:
                pending.assessment = assessments[pending.hook_input.request_id]
        except Exception as exc:
            for pending in batch:
                pending.error = exc
        finally:
            for pending in batch:
                pending.event.set()

    def _assess_batch(
        self,
        batch: list[_PendingAssessment],
    ) -> dict[str, GuardianAssessment]:
        first = batch[0]
        state = self._thread_state(first.hook_input.guardian_key)
        # Concurrent requests may observe slightly different append positions in
        # the same rollout. The largest snapshot is the latest deterministic view.
        snapshot = max(batch, key=lambda pending: pending.snapshot.source_size).snapshot
        guardian_key = first.hook_input.guardian_key

        with state.lock:
            if state.has_temporary_request_turn:
                try:
                    self._rollback_temporary_request(state)
                except Exception:
                    self._discard_thread(guardian_key)
                    raise

            try:
                started_at = time.monotonic()
                result = state.thread.run(
                    build_guardian_prompt(
                        snapshot,
                        [pending.hook_input for pending in batch],
                    ),
                    cwd=first.hook_input.cwd or None,
                    effort=self._effort,
                    output_schema=OUTPUT_SCHEMA,
                    sandbox=self._sandbox.read_only,
                )
                duration_ms = round(
                    (time.monotonic() - started_at) * 1000,
                    3,
                )
                state.has_temporary_request_turn = True
            except Exception:
                self._discard_thread(guardian_key)
                raise

            try:
                assessments = parse_guardian_assessments(
                    result.final_response or "",
                    [pending.hook_input.request_id for pending in batch],
                )
            except Exception as exc:
                log_turn_token_usage(
                    result,
                    state.thread,
                    batch,
                    assessments=None,
                    config=self.config,
                    duration_ms=duration_ms,
                    assessment_error=exc,
                )
                raise

            log_turn_token_usage(
                result,
                state.thread,
                batch,
                assessments=assessments,
                config=self.config,
                duration_ms=duration_ms,
            )
            return assessments

    def _thread_state(self, key: tuple[str, str]) -> _GuardianThreadState:
        with self._threads_lock:
            state = self._threads.get(key)
            if state is not None:
                return state
            if self._codex is None:
                raise RuntimeError("guardian Codex client is not initialized")
            thread = self._codex.thread_start(
                approval_mode=self._approval_mode.deny_all,
                config={"model_reasoning_effort": self.config.reasoning_effort},
                developer_instructions=guardian_policy_prompt(self.config),
                model=self.config.model,
                sandbox=self._sandbox.read_only,
            )
            state = _GuardianThreadState(thread=thread)
            self._threads[key] = state
            return state

    def _rollback_temporary_request(self, state: _GuardianThreadState) -> None:
        try:
            state.thread._client.request(
                "thread/rollback",
                {"threadId": state.thread.id, "numTurns": 1},
                response_model=self._rollback_response,
            )
        except Exception:
            state.has_temporary_request_turn = False
            raise
        state.has_temporary_request_turn = False

    def _discard_thread(self, key: tuple[str, str]) -> None:
        with self._threads_lock:
            self._threads.pop(key, None)


def log_turn_token_usage(
    result: Any,
    thread: Any,
    batch: list[_PendingAssessment],
    assessments: dict[str, GuardianAssessment] | None = None,
    *,
    config: GuardianConfig | None = None,
    duration_ms: float | None = None,
    assessment_error: Exception | None = None,
) -> None:
    usage = getattr(result, "usage", None)
    last_usage = getattr(usage, "last", None)
    token_usage = (
        {
            "total_tokens": getattr(last_usage, "total_tokens", None),
            "input_tokens": getattr(last_usage, "input_tokens", None),
            "cached_input_tokens": getattr(
                last_usage,
                "cached_input_tokens",
                None,
            ),
            "output_tokens": getattr(last_usage, "output_tokens", None),
            "reasoning_output_tokens": getattr(
                last_usage,
                "reasoning_output_tokens",
                None,
            ),
        }
        if last_usage is not None
        else None
    )
    first_input = batch[0].hook_input
    requests = []
    for pending in batch:
        hook_input = pending.hook_input
        assessment = (
            assessments.get(hook_input.request_id)
            if assessments is not None
            else None
        )
        requests.append(
            {
                "request_id": hook_input.request_id,
                "source_turn_id": hook_input.turn_id,
                "cwd": hook_input.cwd,
                "tool": hook_input.tool_name,
                "command": _tool_command(hook_input.tool_input),
                "tool_input": hook_input.tool_input,
                "assessment": (
                    {
                        "outcome": assessment.outcome,
                        "risk_level": assessment.risk_level,
                        "user_authorization": assessment.user_authorization,
                        "decision_rationale": assessment.decision_rationale,
                        "classification_rationale": (
                            assessment.classification_rationale
                        ),
                    }
                    if assessment is not None
                    else None
                ),
            }
        )

    assessment_status = "success"
    if assessment_error is not None:
        assessment_status = "error"
    elif assessments is None:
        assessment_status = "unavailable"

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "guardian_turn_token_usage",
        "session_id": first_input.session_id,
        "agent_id": first_input.agent_id or "root",
        "source_turn_ids": sorted(
            {pending.hook_input.turn_id for pending in batch}
        ),
        "guardian_thread_id": getattr(thread, "id", None),
        "guardian_turn_id": getattr(result, "id", None),
        "guardian_model": config.model if config is not None else None,
        "reasoning_effort": (
            config.reasoning_effort if config is not None else None
        ),
        "config_fingerprint": (
            config_fingerprint(config) if config is not None else None
        ),
        "batch_size": len(batch),
        "duration_ms": duration_ms,
        "assessment_status": assessment_status,
        "assessment_error": (
            {
                "type": type(assessment_error).__name__,
                "message": str(assessment_error),
            }
            if assessment_error is not None
            else None
        ),
        "requests": requests,
        "token_usage": token_usage,
    }
    LOGGER.info(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def _tool_command(tool_input: dict[str, Any]) -> Any:
    for field in ("command", "cmd"):
        if field in tool_input:
            return tool_input[field]
    return None


def configure_logging() -> None:
    if LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


def build_guardian_prompt(
    snapshot: TranscriptSnapshot,
    requests: list[PermissionRequestInput],
) -> str:
    request_payload = [
        {
            "request_id": request.request_id,
            "turn_id": request.turn_id,
            "current_user_turn": snapshot.current_user_turn,
            "cwd": request.cwd or "unknown",
            "tool": request.tool_name,
            "tool_input": request.tool_input,
        }
        for request in requests
    ]
    compact_note = (
        "This context window begins with compacted context. All prior "
        "positive authorization grants ended at compaction; task-level "
        "authorization inferred only from retained user messages is capped "
        "at medium."
        if snapshot.compacted
        else "This is the initial, uncompacted context window."
    )
    return f"""Assess all planned actions in this batch independently.

The transcript below was deterministically derived from the Codex rollout.
Assistant prose and reasoning were excluded. {compact_note}

>>> DETERMINISTIC TRANSCRIPT START
{snapshot.render()}
>>> DETERMINISTIC TRANSCRIPT END

>>> PLANNED ACTIONS START
{json.dumps(request_payload, indent=2, sort_keys=True, ensure_ascii=False)}
>>> PLANNED ACTIONS END

Return exactly one assessment for every request_id.
"""


def run_daemon() -> int:
    configure_logging()
    config = load_config()
    guardian = GuardianDaemon(config)
    server: ThreadingXMLRPCServer | None = None
    stop_requested = Event()
    try:
        guardian.start()
        server = ThreadingXMLRPCServer(
            ("localhost", config.daemon_port),
            allow_none=True,
            logRequests=False,
        )

        def assess(payload: Any) -> dict[str, str]:
            return guardian.assess(PermissionRequestInput(**payload)).__dict__

        def stop() -> dict[str, bool]:
            stop_requested.set()
            return {"ok": True}

        server.register_function(guardian.status, "status")
        server.register_function(assess, "assess")
        server.register_function(stop, "stop")
        server.timeout = 0.2

        while not stop_requested.is_set():
            server.handle_request()
    finally:
        guardian.close()
        if server is not None:
            server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run_daemon())
    except Exception as exc:
        print(f"Codex AI Approver guardian daemon failed: {exc}", file=sys.stderr)
        raise
