from __future__ import annotations

from typing import Any
import json
import os
import socket
import sys

from approver_common import (
    DAEMON_REQUEST_MAX_BYTES,
    DEVELOPER_INSTRUCTIONS,
    OUTPUT_SCHEMA,
    ApproverConfig,
    HookInput,
    ReviewResult,
    build_prompt,
    daemon_aux_path,
    daemon_socket_path,
    ensure_daemon_parent,
    hook_input_from_payload,
    load_config,
    parse_review,
    review_result_to_payload,
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
        self._requests_on_thread = 0
        self._total_requests = 0

    @property
    def total_requests(self) -> int:
        return self._total_requests

    @property
    def requests_on_thread(self) -> int:
        return self._requests_on_thread

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
        if self._requests_on_thread >= self.config.daemon.max_requests_per_thread:
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
            self._requests_on_thread = 0
            raise

        rollback_failed = False
        try:
            review = parse_review(result.final_response or "")
        finally:
            try:
                self._rollback_one_turn()
            except Exception as exc:
                self._thread = None
                self._requests_on_thread = 0
                rollback_failed = True
                print(f"Codex AI Approver daemon rollback failed: {exc}", file=sys.stderr, flush=True)

        if not rollback_failed:
            self._requests_on_thread += 1
        self._total_requests += 1
        return review

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "pid": os.getpid(),
            "thread_ready": self._thread is not None,
            "requests_on_thread": self._requests_on_thread,
            "total_requests": self._total_requests,
        }

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
        self._requests_on_thread = 0

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
    socket_path = daemon_socket_path(config)
    ensure_daemon_parent(socket_path, config)
    if socket_path.exists():
        raise RuntimeError(f"approver daemon socket already exists: {socket_path}")

    reviewer = DaemonReviewer(config)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stop_requested = False
    try:
        reviewer.start()
        server.bind(str(socket_path))
        try:
            os.chmod(socket_path, 0o600)
        except OSError:
            pass
        server.listen(16)
        _write_daemon_pid(socket_path)
        if config.daemon.idle_timeout_seconds > 0:
            server.settimeout(config.daemon.idle_timeout_seconds)

        while not stop_requested:
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                break
            with conn:
                stop_requested = _handle_daemon_connection(conn, reviewer)
    finally:
        reviewer.close()
        server.close()
        _remove_daemon_files(socket_path)
    return 0


def handle_daemon_request(payload: Any, reviewer: DaemonReviewer) -> tuple[dict[str, Any], bool]:
    if not isinstance(payload, dict):
        raise ValueError("daemon request must be a JSON object")

    command = payload.get("command")
    if command == "status":
        return reviewer.status(), False
    if command == "stop":
        return {"ok": True}, True
    if command == "review":
        review = reviewer.review(hook_input_from_payload(payload.get("hook_input")))
        return {"ok": True, "review": review_result_to_payload(review)}, False
    raise ValueError(f"unknown daemon command: {command!r}")


def _handle_daemon_connection(conn: socket.socket, reviewer: DaemonReviewer) -> bool:
    stop_requested = False
    try:
        conn.settimeout(5)
        payload = _read_daemon_payload(conn)
        response, stop_requested = handle_daemon_request(payload, reviewer)
    except Exception as exc:
        response = {"ok": False, "error": str(exc)}
    try:
        conn.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
    except OSError as exc:
        print(f"Codex AI Approver daemon response write failed: {exc}", file=sys.stderr, flush=True)
    return stop_requested


def _read_daemon_payload(conn: socket.socket) -> Any:
    data = bytearray()
    while b"\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > DAEMON_REQUEST_MAX_BYTES:
            raise ValueError("daemon request is too large")
    if not data:
        raise ValueError("daemon request is empty")
    return json.loads(data.split(b"\n", 1)[0].decode("utf-8"))


def _remove_daemon_files(socket_path) -> None:
    for path in (socket_path, daemon_aux_path(socket_path, ".pid")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _write_daemon_pid(socket_path) -> None:
    daemon_aux_path(socket_path, ".pid").write_text(f"{os.getpid()}\n", encoding="utf-8")
