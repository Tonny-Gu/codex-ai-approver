from __future__ import annotations

from dataclasses import dataclass, field
from socketserver import ThreadingMixIn
from threading import Event, Lock
from typing import Any
from xmlrpc.server import SimpleXMLRPCServer
import json
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
    error: BaseException | None = None


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
        except BaseException as exc:
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
                state.has_temporary_request_turn = True
            except Exception:
                self._discard_thread(guardian_key)
                raise

            return parse_guardian_assessments(
                result.final_response or "",
                [pending.hook_input.request_id for pending in batch],
            )

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


def build_guardian_prompt(
    snapshot: TranscriptSnapshot,
    requests: list[PermissionRequestInput],
) -> str:
    request_payload = [
        {
            "request_id": request.request_id,
            "turn_id": request.turn_id,
            "cwd": request.cwd or "unknown",
            "tool": request.tool_name,
            "tool_input": request.tool_input,
        }
        for request in requests
    ]
    compact_note = (
        "This context window begins with a compacted summary. Authorization "
        "inferred only from that summary is capped at medium."
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
