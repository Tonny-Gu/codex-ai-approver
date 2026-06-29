from __future__ import annotations

from typing import Any
import sys
from xmlrpc.server import SimpleXMLRPCServer

from approver_common import (
    DEVELOPER_INSTRUCTIONS,
    OUTPUT_SCHEMA,
    ApproverConfig,
    HookInput,
    ReviewResult,
    build_prompt,
    load_config,
    parse_review,
)


DAEMON_ANCHOR_PROMPT = "You will classify permission requests using the developer instructions. Reply exactly OK."


class DaemonReviewer:
    def __init__(self, config: ApproverConfig) -> None:
        self.config = config
        self._codex: Any = None
        self._thread: Any = None
        self._effort: Any = None
        self._approval_mode: Any = None
        self._sandbox: Any = None
        self._rollback_response: Any = None

    def start(self) -> None:
        try:
            from openai_codex import ApprovalMode, Codex, Sandbox
            from openai_codex.generated.v2_all import ThreadRollbackResponse
            from openai_codex.types import ReasoningEffort
        except ModuleNotFoundError as exc:
            raise RuntimeError("openai-codex is not installed in this Python environment") from exc

        self._approval_mode = ApprovalMode
        self._sandbox = Sandbox
        self._rollback_response = ThreadRollbackResponse
        self._effort = ReasoningEffort(self.config.reasoning_effort)
        self._codex = Codex()
        self._start_thread()

    def review(self, hook_input: HookInput) -> ReviewResult:
        if self._thread is None:
            self._start_thread()

        try:
            result = self._thread.run(
                build_prompt(hook_input),
                cwd=hook_input.cwd or None,
                effort=self._effort,
                output_schema=OUTPUT_SCHEMA,
                sandbox=self._sandbox.read_only,
            )
        except Exception:
            self._thread = None
            raise

        try:
            review = parse_review(result.final_response or "")
        finally:
            try:
                self._rollback_one_turn()
            except Exception as exc:
                self._thread = None
                print(f"Codex AI Approver daemon rollback failed: {exc}", file=sys.stderr, flush=True)

        return review

    def status(self) -> dict[str, Any]:
        return {"ok": True}

    def close(self) -> None:
        if self._codex is not None:
            self._codex.close()
        self._codex = None
        self._thread = None

    def _start_thread(self) -> None:
        if self._codex is None:
            raise RuntimeError("approver daemon Codex client is not initialized")
        self._thread = self._codex.thread_start(
            approval_mode=self._approval_mode.deny_all,
            config={"model_reasoning_effort": self.config.reasoning_effort},
            developer_instructions=DEVELOPER_INSTRUCTIONS,
            model=self.config.model,
            sandbox=self._sandbox.read_only,
        )
        self._thread.run(
            DAEMON_ANCHOR_PROMPT,
            effort=self._effort,
            sandbox=self._sandbox.read_only,
        )

    def _rollback_one_turn(self) -> None:
        if self._thread is None:
            return
        self._thread._client.request(
            "thread/rollback",
            {"threadId": self._thread.id, "numTurns": 1},
            response_model=self._rollback_response,
        )


def run_daemon() -> int:
    config = load_config()
    reviewer = DaemonReviewer(config)
    try:
        reviewer.start()
        server = SimpleXMLRPCServer(
            ("localhost", config.daemon_port),
            allow_none=True,
            logRequests=False,
        )

        def review(payload: Any) -> dict[str, str]:
            return reviewer.review(HookInput(**payload)).__dict__

        server.register_function(reviewer.status, "status")
        server.register_function(review, "review")
        server.serve_forever()
    finally:
        reviewer.close()
    return 0
