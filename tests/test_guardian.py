from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import io
import json
import re
import sys
import tempfile
import threading
import time
import unittest


HOOKS_DIR = Path(__file__).resolve().parents[1] / "hooks"
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import guardian_common as common  # noqa: E402
import guardian_server as server  # noqa: E402
import guardian_transcript as transcript  # noqa: E402
import permission_request as hook  # noqa: E402


def assessment(outcome: str = "allow") -> common.GuardianAssessment:
    return common.GuardianAssessment(
        risk_level="low" if outcome == "allow" else "critical",
        user_authorization="medium",
        outcome=outcome,
        decision_rationale=(
            "The bounded action is allowed."
            if outcome == "allow"
            else "The agent must not perform this action; the user should carry it out manually."
        ),
        classification_rationale=(
            "The action is low risk and directly authorized in substance."
            if outcome == "allow"
            else "The action is critical risk and current authorization is only medium."
        ),
    )


def permission_input(
    request_id: str = "request-1",
    transcript_path: str | None = None,
    tool_name: str = "Bash",
    tool_input: dict | None = None,
) -> common.PermissionRequestInput:
    return common.PermissionRequestInput(
        request_id=request_id,
        session_id="session-1",
        turn_id="turn-1",
        agent_id=None,
        transcript_path=transcript_path,
        cwd="/repo",
        tool_name=tool_name,
        tool_input=tool_input or {"command": "git status"},
    )


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = common.load_config(Path("/no/such/file"))
        self.assertEqual(config.model, "gpt-5.6-sol")
        self.assertEqual(config.reasoning_effort, "medium")
        self.assertEqual(config.daemon_port, 47678)
        self.assertEqual(config.batch_wait_seconds, 0.1)
        self.assertEqual(config.outcome_policy, common.DEFAULT_OUTCOME_POLICY)
        self.assertEqual(
            common.USER_AUTHORIZATION_LEVELS,
            ("prohibited", "none", "low", "medium", "high"),
        )

    def test_reads_guardian_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "model": "gpt-5.4",
                        "reasoning_effort": "high",
                        "daemon_port": 48765,
                        "batch_wait_seconds": 0.25,
                        "outcome_policy": "- Deny medium or higher risk.",
                    }
                ),
                encoding="utf-8",
            )
            config = common.load_config(path)
        self.assertEqual(config.model, "gpt-5.4")
        self.assertEqual(config.reasoning_effort, "high")
        self.assertEqual(config.daemon_port, 48765)
        self.assertEqual(config.batch_wait_seconds, 0.25)
        self.assertEqual(config.outcome_policy, "- Deny medium or higher risk.")

    def test_removed_permit_words_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"permit_words":{"network_fetch":"word"}}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown config fields: permit_words"):
                common.load_config(path)

    def test_batch_wait_range_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"batch_wait_seconds":5.1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "batch_wait_seconds"):
                common.load_config(path)

    def test_policy_has_required_semantics(self) -> None:
        policy = common.guardian_policy_prompt(common.load_config(Path("/no/such/file")))
        self.assertIn("probability of unintended execution multiplied", policy)
        self.assertIn(
            '`risk_level = "low"` -> allow only when `user_authorization` is at least',
            policy,
        )
        self.assertIn('`user_authorization = "prohibited"` -> deny', policy)
        self.assertIn('`user_authorization = "none"` -> deny', policy)
        self.assertIn('`risk_level = "critical"` -> deny', policy)
        self.assertIn("user should carry it out manually", policy)
        self.assertIn("cannot exceed `medium`", policy)
        self.assertIn("Hook messages must not revive an expired grant", policy)
        self.assertIn("persists across", policy)
        self.assertIn("grant_turn + N - 1", policy)
        self.assertIn("An expired grant supplies no positive authorization", policy)
        self.assertNotIn("{{ outcome_policy }}", policy)


class PermissionInputTests(unittest.TestCase):
    def test_parses_full_hook_payload_without_agent_controls(self) -> None:
        command = (
            'CODEX_APPROVER_JUSTIFICATION="old" '
            'CODEX_APPROVER_PERMITS="old-word" git status'
        )
        parsed = common.parse_permission_request_input(
            json.dumps(
                {
                    "session_id": "session-1",
                    "turn_id": "turn-1",
                    "agent_id": "agent-1",
                    "agent_type": "worker",
                    "transcript_path": "/tmp/rollout.jsonl",
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                }
            )
        )
        self.assertEqual(parsed.session_id, "session-1")
        self.assertEqual(parsed.agent_id, "agent-1")
        self.assertEqual(parsed.tool_input, {"command": command})
        self.assertTrue(parsed.request_id)

    def test_requires_session_turn_and_tool(self) -> None:
        with self.assertRaisesRegex(ValueError, "session_id"):
            common.parse_permission_request_input("{}")


class GuardianParsingTests(unittest.TestCase):
    def test_parses_all_assessment_fields(self) -> None:
        parsed = common.parse_guardian_assessments(
            json.dumps(
                {
                    "assessments": [
                        {
                            "request_id": "r1",
                            "risk_level": "high",
                            "user_authorization": "high",
                            "outcome": "allow",
                            "decision_rationale": "The exact bounded action is allowed.",
                            "classification_rationale": "The exact action is directly authorized but has serious impact.",
                        }
                    ]
                }
            ),
            ["r1"],
        )
        self.assertEqual(parsed["r1"].risk_level, "high")
        self.assertEqual(parsed["r1"].user_authorization, "high")

    def test_rejects_missing_batch_member(self) -> None:
        with self.assertRaisesRegex(ValueError, "omitted request_ids"):
            common.parse_guardian_assessments('{"assessments":[]}', ["r1"])

    def test_output_schema_requires_two_rationales(self) -> None:
        required = common.ASSESSMENT_SCHEMA["required"]
        self.assertIn("decision_rationale", required)
        self.assertIn("classification_rationale", required)
        self.assertEqual(
            common.ASSESSMENT_SCHEMA["properties"]["user_authorization"]["enum"],
            ["prohibited", "none", "low", "medium", "high"],
        )


class TranscriptTests(unittest.TestCase):
    def write_rollout(self, items: list[dict]) -> str:
        tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        with tmp:
            for item in items:
                tmp.write(json.dumps(item) + "\n")
        self.addCleanup(Path(tmp.name).unlink, missing_ok=True)
        return tmp.name

    def response_item(self, payload: dict) -> dict:
        return {"type": "response_item", "payload": payload}

    def test_retains_user_and_all_permission_hook_messages(self) -> None:
        guardian_message = common.guardian_assessment_system_message(
            permission_input(),
            assessment(),
        )
        path = self.write_rollout(
            [
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Inspect the repo."}],
                    }
                ),
                self.response_item(
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "I will run a command."}],
                    }
                ),
                self.response_item(
                    {
                        "type": "function_call",
                        "call_id": "call-1",
                        "name": "exec_command",
                        "arguments": '{"cmd":"ignored historical tool"}',
                    }
                ),
                self.response_item(
                    {
                        "type": "function_call_output",
                        "call_id": "call-1",
                        "output": "large output intentionally ignored",
                    }
                ),
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "hook_completed",
                        "run": {
                            "event_name": "permission_request",
                            "entries": [
                                {
                                    "kind": "warning",
                                    "text": guardian_message,
                                },
                                {"kind": "warning", "text": "Other hook context."},
                            ],
                        },
                    },
                },
            ]
        )

        snapshot = transcript.derive_transcript_snapshot(path)
        rendered = snapshot.render()
        self.assertEqual(snapshot.current_user_turn, 1)
        self.assertTrue(all(entry["user_turn"] == 1 for entry in snapshot.entries))
        self.assertIn("Inspect the repo.", rendered)
        self.assertNotIn("I will run a command.", rendered)
        self.assertNotIn("ignored historical tool", rendered)
        self.assertNotIn("large output intentionally ignored", rendered)
        hook_messages = [
            entry for entry in snapshot.entries if entry.get("kind") == "hook_message"
        ]
        self.assertEqual(len(hook_messages), 2)
        self.assertIn("Tool: Bash", hook_messages[0]["text"])
        self.assertIn('"command": "git status"', hook_messages[0]["text"])
        self.assertIn("Outcome: allow", hook_messages[0]["text"])
        self.assertEqual(hook_messages[1]["text"], "Other hook context.")

    def test_compaction_uses_retained_user_messages_then_new_evidence(self) -> None:
        path = self.write_rollout(
            [
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Old exact authorization."}],
                    }
                ),
                {
                    "type": "compacted",
                    "payload": {
                        "message": "",
                        "window_number": 3,
                        "replacement_history": [
                            {
                                "type": "message",
                                "role": "user",
                                "content": [
                                    {
                                        "type": "input_text",
                                        "text": "Old exact authorization.",
                                    }
                                ],
                            },
                            {
                                "type": "message",
                                "role": "assistant",
                                "content": [
                                    {
                                        "type": "output_text",
                                        "text": "Ignored assistant context.",
                                    }
                                ],
                            },
                            {
                                "type": "compaction",
                                "encrypted_content": "ignored encrypted summary",
                            },
                        ],
                    },
                },
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "New direct authorization."}],
                    }
                ),
            ]
        )
        snapshot = transcript.derive_transcript_snapshot(path)
        self.assertTrue(snapshot.compacted)
        self.assertEqual(snapshot.window_key, "window-3")
        self.assertEqual(snapshot.current_user_turn, 1)
        rendered = snapshot.render()
        self.assertIn("Old exact authorization.", rendered)
        self.assertIn("New direct authorization.", rendered)
        self.assertNotIn("Ignored assistant context.", rendered)
        self.assertNotIn("ignored encrypted summary", rendered)
        self.assertIn('"kind": "compacted_user_messages"', rendered)
        self.assertIn('"authorization_cap": "medium"', rendered)
        self.assertIn('"authorization_grants_reset": true', rendered)
        self.assertIn('"user_turn": 0', rendered)
        self.assertIn('"user_turn": 1', rendered)

    def test_user_turn_ordinals_support_bounded_authorization(self) -> None:
        path = self.write_rollout(
            [
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "Allow deployment for two user turns.",
                            }
                        ],
                    }
                ),
                self.response_item(
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "Working."}],
                    }
                ),
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "hook_completed",
                        "run": {
                            "event_name": "permission_request",
                            "entries": [{"text": "Prior hook context."}],
                        },
                    },
                },
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Continue."}],
                    }
                ),
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Next task."}],
                    }
                ),
            ]
        )
        snapshot = transcript.derive_transcript_snapshot(path)
        self.assertEqual(snapshot.current_user_turn, 3)
        user_turns = [
            entry["user_turn"]
            for entry in snapshot.entries
            if entry.get("kind") == "user_message"
        ]
        self.assertEqual(user_turns, [1, 2, 3])
        hook_message = next(
            entry for entry in snapshot.entries if entry.get("kind") == "hook_message"
        )
        self.assertEqual(hook_message["user_turn"], 1)

    def test_hook_messages_are_retained_without_prefix_or_parsing(self) -> None:
        path = self.write_rollout(
            [
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Inspect."}],
                    }
                ),
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "hook_completed",
                        "run": {
                            "event_name": "permission_request",
                            "entries": [
                                {"kind": "warning", "text": "Plain hook note."},
                                {"text": '{"arbitrary":"JSON remains text"}'},
                                {"text": ""},
                                {"text": 123},
                            ],
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "hook_completed",
                        "run": {
                            "event_name": "post_tool_use",
                            "entries": [{"text": "Other lifecycle hook context."}],
                        },
                    },
                },
            ]
        )
        snapshot = transcript.derive_transcript_snapshot(path)
        hook_messages = [
            entry for entry in snapshot.entries if entry.get("kind") == "hook_message"
        ]
        self.assertEqual(
            [entry["text"] for entry in hook_messages],
            [
                "Plain hook note.",
                '{"arbitrary":"JSON remains text"}',
                "Other lifecycle hook context.",
            ],
        )

    def test_all_role_user_messages_are_retained(self) -> None:
        path = self.write_rollout(
            [
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "<environment_context>not a user instruction",
                            }
                        ],
                    }
                ),
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Real user request"}],
                    }
                ),
            ]
        )
        rendered = transcript.derive_transcript_snapshot(path).render()
        self.assertIn("not a user instruction", rendered)
        self.assertIn("Real user request", rendered)

    def test_thread_rollback_removes_rolled_back_user_turns(self) -> None:
        path = self.write_rollout(
            [
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Keep this turn"}],
                    }
                ),
                self.response_item(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Remove this turn"}],
                    }
                ),
                {
                    "type": "event_msg",
                    "payload": {"type": "thread_rolled_back", "num_turns": 1},
                },
            ]
        )
        snapshot = transcript.derive_transcript_snapshot(path)
        rendered = snapshot.render()
        self.assertEqual(snapshot.current_user_turn, 1)
        self.assertIn("Keep this turn", rendered)
        self.assertNotIn("Remove this turn", rendered)


class GuardianDaemonTests(unittest.TestCase):
    def config(self, batch_wait_seconds: float = 0.01) -> common.GuardianConfig:
        return common.GuardianConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            outcome_policy=common.DEFAULT_OUTCOME_POLICY,
            daemon_port=47678,
            batch_wait_seconds=batch_wait_seconds,
        )

    def test_concurrent_requests_are_batched(self) -> None:
        guardian = server.GuardianDaemon(self.config(0.05))
        calls: list[list[server._PendingAssessment]] = []

        def fake_assess_batch(batch):
            calls.append(batch)
            return {
                pending.hook_input.request_id: assessment()
                for pending in batch
            }

        guardian._assess_batch = fake_assess_batch  # type: ignore[method-assign]
        barrier = threading.Barrier(3)
        results: list[common.GuardianAssessment] = []

        def invoke(request_id: str) -> None:
            barrier.wait()
            results.append(guardian.assess(permission_input(request_id)))

        threads = [
            threading.Thread(target=invoke, args=("r1",)),
            threading.Thread(target=invoke, args=("r2",)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)

        self.assertEqual(len(results), 2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0]), 2)

    def test_previous_temporary_request_is_rolled_back(self) -> None:
        class FakeClient:
            def __init__(self):
                self.calls = []

            def request(self, method, payload, response_model):
                self.calls.append((method, payload, response_model))
                return object()

        class FakeThread:
            def __init__(self):
                self.id = "guardian-thread"
                self._client = FakeClient()
                self.prompts = []

            def run(self, prompt, **kwargs):
                self.prompts.append(prompt)
                ids = re.findall(r'"request_id": "([^"]+)"', prompt)
                return SimpleNamespace(
                    id=f"guardian-turn-{len(self.prompts)}",
                    final_response=json.dumps(
                        {
                            "assessments": [
                                {
                                    "request_id": request_id,
                                    **assessment().__dict__,
                                }
                                for request_id in ids
                            ]
                        }
                    ),
                    usage=SimpleNamespace(
                        last=SimpleNamespace(
                            total_tokens=125,
                            input_tokens=100,
                            cached_input_tokens=80,
                            output_tokens=25,
                            reasoning_output_tokens=10,
                        )
                    ),
                )

        class FakeCodex:
            def __init__(self):
                self.thread = FakeThread()
                self.starts = 0

            def thread_start(self, **kwargs):
                self.starts += 1
                return self.thread

        guardian = server.GuardianDaemon(self.config())
        fake_codex = FakeCodex()
        guardian._codex = fake_codex
        guardian._effort = "medium"
        guardian._approval_mode = SimpleNamespace(deny_all="deny_all")
        guardian._sandbox = SimpleNamespace(read_only="read_only")
        guardian._rollback_response = object
        snapshot = transcript.TranscriptSnapshot(
            window_key="initial",
            compacted=False,
            entries=({"kind": "user_message", "text": "Run git status"},),
            source_size=1,
        )

        first = server._PendingAssessment(permission_input("r1"), snapshot)
        second = server._PendingAssessment(permission_input("r2"), snapshot)
        with self.assertLogs(server.LOGGER, level="INFO") as captured:
            guardian._assess_batch([first])
            guardian._assess_batch([second])

        self.assertEqual(fake_codex.starts, 1)
        self.assertEqual(len(fake_codex.thread._client.calls), 1)
        method, payload, _ = fake_codex.thread._client.calls[0]
        self.assertEqual(method, "thread/rollback")
        self.assertEqual(payload["numTurns"], 1)
        self.assertEqual(len(fake_codex.thread.prompts), 2)
        usage_logs = [json.loads(record.getMessage()) for record in captured.records]
        self.assertEqual(
            [record["guardian_turn_id"] for record in usage_logs],
            ["guardian-turn-1", "guardian-turn-2"],
        )
        self.assertTrue(
            all(
                record["event"] == "guardian_turn_token_usage"
                for record in usage_logs
            )
        )
        self.assertTrue(
            all(
                record["token_usage"]["total_tokens"] == 125
                for record in usage_logs
            )
        )
        self.assertTrue(
            all(
                record["token_usage"]["cached_input_tokens"] == 80
                for record in usage_logs
            )
        )
        self.assertTrue(
            all(record["assessment_status"] == "success" for record in usage_logs)
        )
        self.assertTrue(
            all(record["guardian_model"] == "gpt-5.5" for record in usage_logs)
        )
        self.assertTrue(
            all(record["reasoning_effort"] == "medium" for record in usage_logs)
        )
        first_request = usage_logs[0]["requests"][0]
        self.assertEqual(first_request["request_id"], "r1")
        self.assertEqual(first_request["source_turn_id"], "turn-1")
        self.assertEqual(first_request["tool"], "Bash")
        self.assertEqual(first_request["command"], "git status")
        self.assertEqual(first_request["tool_input"], {"command": "git status"})
        self.assertEqual(first_request["assessment"], assessment().__dict__)
        self.assertGreaterEqual(usage_logs[0]["duration_ms"], 0)

    def test_logs_turn_when_sdk_usage_is_unavailable(self) -> None:
        snapshot = transcript.TranscriptSnapshot(
            window_key="initial",
            compacted=False,
            entries=(),
            source_size=0,
        )
        pending = server._PendingAssessment(permission_input(), snapshot)

        with self.assertLogs(server.LOGGER, level="INFO") as captured:
            server.log_turn_token_usage(
                SimpleNamespace(id="guardian-turn-1"),
                SimpleNamespace(id="guardian-thread-1"),
                [pending],
                assessments={"request-1": assessment()},
            )

        payload = json.loads(captured.records[0].getMessage())
        self.assertEqual(payload["event"], "guardian_turn_token_usage")
        self.assertEqual(payload["guardian_turn_id"], "guardian-turn-1")
        self.assertIsNone(payload["token_usage"])
        self.assertEqual(payload["assessment_status"], "success")

    def test_logs_each_batched_request_with_its_own_assessment(self) -> None:
        snapshot = transcript.TranscriptSnapshot(
            window_key="initial",
            compacted=False,
            entries=(),
            source_size=0,
        )
        bash = server._PendingAssessment(
            permission_input(
                "bash-request",
                tool_input={"command": "git status", "timeout": 10},
            ),
            snapshot,
        )
        patch = server._PendingAssessment(
            permission_input(
                "patch-request",
                tool_name="apply_patch",
                tool_input={"patch": "*** Begin Patch"},
            ),
            snapshot,
        )

        with self.assertLogs(server.LOGGER, level="INFO") as captured:
            server.log_turn_token_usage(
                SimpleNamespace(id="guardian-turn-1"),
                SimpleNamespace(id="guardian-thread-1"),
                [bash, patch],
                assessments={
                    "bash-request": assessment(),
                    "patch-request": assessment("deny"),
                },
            )

        payload = json.loads(captured.records[0].getMessage())
        self.assertEqual(payload["batch_size"], 2)
        self.assertEqual(
            payload["source_turn_ids"],
            ["turn-1"],
        )
        self.assertEqual(
            [
                (item["request_id"], item["tool"], item["command"])
                for item in payload["requests"]
            ],
            [
                ("bash-request", "Bash", "git status"),
                ("patch-request", "apply_patch", None),
            ],
        )
        self.assertEqual(
            payload["requests"][0]["assessment"]["outcome"],
            "allow",
        )
        self.assertEqual(
            payload["requests"][1]["assessment"]["outcome"],
            "deny",
        )
        self.assertIn(
            "must not perform",
            payload["requests"][1]["assessment"]["decision_rationale"],
        )

    def test_logs_assessment_parse_errors_with_request_context(self) -> None:
        snapshot = transcript.TranscriptSnapshot(
            window_key="initial",
            compacted=False,
            entries=(),
            source_size=0,
        )
        pending = server._PendingAssessment(permission_input(), snapshot)

        with self.assertLogs(server.LOGGER, level="INFO") as captured:
            server.log_turn_token_usage(
                SimpleNamespace(id="guardian-turn-1"),
                SimpleNamespace(id="guardian-thread-1"),
                [pending],
                assessment_error=ValueError("invalid assessment"),
            )

        payload = json.loads(captured.records[0].getMessage())
        self.assertEqual(payload["assessment_status"], "error")
        self.assertEqual(payload["assessment_error"]["type"], "ValueError")
        self.assertEqual(
            payload["assessment_error"]["message"],
            "invalid assessment",
        )
        self.assertIsNone(payload["requests"][0]["assessment"])

    def test_prompt_marks_compacted_authorization_cap(self) -> None:
        snapshot = transcript.TranscriptSnapshot(
            window_key="window-2",
            compacted=True,
            entries=(
                {
                    "kind": "compacted_user_messages",
                    "authorization_cap": "medium",
                    "messages": ["Continue the task."],
                },
            ),
            source_size=1,
            current_user_turn=2,
        )
        prompt = server.build_guardian_prompt(snapshot, [permission_input()])
        self.assertIn("capped at medium", prompt)
        self.assertIn("positive authorization grants ended", prompt)
        self.assertIn('"current_user_turn": 2', prompt)
        self.assertIn("Continue the task.", prompt)


class HookTests(unittest.TestCase):
    def config(self) -> common.GuardianConfig:
        return common.GuardianConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            outcome_policy=common.DEFAULT_OUTCOME_POLICY,
        )

    def test_assess_with_daemon_uses_guardian_rpc(self) -> None:
        class FakeProxy:
            def assess(self, payload):
                self.payload = payload
                return assessment().__dict__

        proxy = FakeProxy()
        with mock.patch.object(hook, "ensure_daemon_running"), mock.patch.object(
            hook,
            "daemon_proxy",
            return_value=proxy,
        ):
            result = hook.assess_with_daemon(permission_input(), self.config())
        self.assertEqual(result, assessment())
        self.assertEqual(proxy.payload["tool_input"], {"command": "git status"})

    def test_allow_and_deny_emit_self_contained_messages(self) -> None:
        allowed = common.permission_request_output(permission_input(), assessment())
        denied = common.permission_request_output(
            permission_input(),
            assessment("deny"),
        )
        self.assertIn("Tool: Bash", allowed["systemMessage"])
        self.assertIn('"command": "git status"', allowed["systemMessage"])
        self.assertIn("Outcome: allow", allowed["systemMessage"])
        self.assertIn("Outcome: deny", denied["systemMessage"])
        self.assertIn(
            "Authorization assessed at the time: medium",
            allowed["systemMessage"],
        )
        self.assertNotIn(
            "message",
            allowed["hookSpecificOutput"]["decision"],
        )
        self.assertIn(
            "user should carry it out manually",
            denied["hookSpecificOutput"]["decision"]["message"],
        )

    def test_run_hook_outputs_guardian_allow(self) -> None:
        stdin = io.StringIO(
            json.dumps(
                {
                    "session_id": "session-1",
                    "turn_id": "turn-1",
                    "transcript_path": None,
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                }
            )
        )
        stdout = io.StringIO()
        with mock.patch("sys.stdin", stdin), mock.patch(
            "sys.stdout",
            stdout,
        ), mock.patch.object(
            hook,
            "load_config",
            return_value=self.config(),
        ), mock.patch.object(
            hook,
            "assess_with_daemon",
            return_value=assessment(),
        ):
            code = hook.run_hook()

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload["hookSpecificOutput"]["decision"]["behavior"],
            "allow",
        )
        self.assertIn("systemMessage", payload)

    def test_run_hook_denies_on_guardian_runtime_error(self) -> None:
        stdout = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("{}")), mock.patch(
            "sys.stdout",
            stdout,
        ):
            code = hook.run_hook()
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        decision = payload["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "deny")
        self.assertIn("guardian hook failed", decision["message"])
        self.assertIn("not a guardian safety assessment", decision["message"])


if __name__ == "__main__":
    unittest.main()
