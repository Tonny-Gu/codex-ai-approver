from __future__ import annotations

from pathlib import Path
from unittest import mock
import importlib.util
import io
import json
import sys
import tempfile
import unittest


def load_hook_module():
    path = Path(__file__).resolve().parents[1] / "hooks" / "permission_request.py"
    spec = importlib.util.spec_from_file_location("permission_request_hook", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load hook module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


hook = load_hook_module()


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = hook.load_config(Path("/no/such/file"))
        self.assertEqual(config.model, "gpt-5.5")
        self.assertEqual(config.reasoning_effort, "medium")
        self.assertEqual(config.permit_words, {"weak_deny": "weak_deny", "deny": "deny"})
        self.assertTrue(config.daemon.enabled)
        self.assertEqual(config.daemon.socket_path, "")
        self.assertEqual(config.daemon.startup_timeout_seconds, 30)
        self.assertEqual(config.daemon.request_timeout_seconds, 120)
        self.assertEqual(config.daemon.idle_timeout_seconds, 1800)
        self.assertEqual(config.daemon.max_requests_per_thread, 100)

    def test_reads_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                (
                    '{"model":"gpt-5.4","reasoning_effort":"high",'
                    '"permit_words":{"weak_deny":"weak","deny":"higher"}}\n'
                ),
                encoding="utf-8",
            )
            config = hook.load_config(path)
        self.assertEqual(config.model, "gpt-5.4")
        self.assertEqual(config.reasoning_effort, "high")
        self.assertEqual(config.permit_words, {"weak_deny": "weak", "deny": "higher"})

    def test_partial_permit_words_override_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"permit_words":{"weak_deny":"custom"}}\n', encoding="utf-8")
            config = hook.load_config(path)
        self.assertEqual(config.permit_words, {"weak_deny": "custom", "deny": "deny"})

    def test_reads_daemon_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "approver.sock"
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "daemon": {
                            "enabled": False,
                            "socket_path": str(socket_path),
                            "startup_timeout_seconds": 3,
                            "request_timeout_seconds": 4,
                            "idle_timeout_seconds": 5,
                            "max_requests_per_thread": 6,
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = hook.load_config(path)
        self.assertFalse(config.daemon.enabled)
        self.assertEqual(config.daemon.socket_path, str(socket_path))
        self.assertEqual(config.daemon.startup_timeout_seconds, 3)
        self.assertEqual(config.daemon.request_timeout_seconds, 4)
        self.assertEqual(config.daemon.idle_timeout_seconds, 5)
        self.assertEqual(config.daemon.max_requests_per_thread, 6)


class HookInputTests(unittest.TestCase):
    def test_parses_hook_input(self) -> None:
        config = hook.ApproverConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            permit_words={"weak_deny": "secret-token", "deny": "deny"},
        )
        hook_input = hook.parse_hook_input(
            json.dumps(
                {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": (
                            'FOO=bar CODEX_APPROVER_SCOPE="inspect logs" '
                            "CODEX_APPROVER_PERMIT=secret-token git status"
                        )
                    },
                }
            ),
            config,
        )
        self.assertEqual(hook_input.cwd, "/repo")
        self.assertEqual(hook_input.tool_name, "Bash")
        self.assertEqual(hook_input.tool_input, {"command": "FOO=bar git status"})
        self.assertEqual(hook_input.scope, "inspect logs")
        self.assertEqual(hook_input.permit_level, "weak_deny")
        self.assertNotIn("secret-token", hook.build_prompt(hook_input))

    def test_uses_default_permit_words(self) -> None:
        hook_input = hook.parse_hook_input(
            json.dumps(
                {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": (
                            'CODEX_APPROVER_SCOPE="inspect logs" '
                            "CODEX_APPROVER_PERMIT=weak_deny git status"
                        )
                    },
                }
            )
        )
        self.assertEqual(hook_input.permit_level, "weak_deny")


class LlmParsingTests(unittest.TestCase):
    def test_parse_json_review(self) -> None:
        review = hook.parse_review('{"category":"deny","reason":"too broad"}')
        self.assertEqual(review, hook.ReviewResult("deny", "too broad"))

    def test_reviewer_prompt_requires_short_reason(self) -> None:
        self.assertIn("Keep the reason to one short sentence.", hook.DEVELOPER_INSTRUCTIONS)


class DaemonTests(unittest.TestCase):
    def config(self, enabled: bool = True) -> hook.ApproverConfig:
        return hook.ApproverConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            permit_words={"weak_deny": "weak_deny", "deny": "deny"},
            daemon=hook.DaemonConfig(enabled=enabled),
        )

    def test_review_permission_request_uses_direct_codex_when_daemon_disabled(self) -> None:
        hook_input = hook.HookInput("/repo", "Bash", {"command": "git status"}, "", "none")
        with mock.patch.object(
            hook,
            "review_with_codex",
            return_value=hook.ReviewResult("allow", "read-only"),
        ) as review_with_codex:
            review = hook.review_permission_request(hook_input, self.config(enabled=False))
        self.assertEqual(review, hook.ReviewResult("allow", "read-only"))
        review_with_codex.assert_called_once()

    def test_review_with_daemon_uses_socket_protocol(self) -> None:
        hook_input = hook.HookInput("/repo", "Bash", {"command": "git status"}, "", "none")
        with mock.patch.object(hook, "ensure_daemon_running") as ensure, mock.patch.object(
            hook,
            "send_daemon_request",
            return_value={"ok": True, "review": {"category": "allow", "reason": "read-only"}},
        ) as send:
            review = hook.review_with_daemon(hook_input, self.config())
        self.assertEqual(review, hook.ReviewResult("allow", "read-only"))
        ensure.assert_called_once()
        self.assertEqual(send.call_args.args[1]["command"], "review")
        self.assertEqual(send.call_args.args[1]["hook_input"]["tool_input"], {"command": "git status"})

    def test_handle_daemon_review_request(self) -> None:
        class FakeReviewer:
            def status(self):
                return {"ok": True, "thread_ready": True}

            def review(self, hook_input):
                self.hook_input = hook_input
                return hook.ReviewResult("allow", "read-only")

        reviewer = FakeReviewer()
        response, stop = hook.handle_daemon_request(
            {
                "command": "review",
                "hook_input": {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                    "scope": "",
                    "permit_level": "none",
                },
            },
            reviewer,
        )
        self.assertFalse(stop)
        self.assertEqual(response, {"ok": True, "review": {"category": "allow", "reason": "read-only"}})
        self.assertEqual(reviewer.hook_input.cwd, "/repo")

    def test_handle_daemon_stop_request(self) -> None:
        response, stop = hook.handle_daemon_request({"command": "stop"}, mock.Mock())
        self.assertTrue(stop)
        self.assertEqual(response, {"ok": True})

    def test_daemon_probe_treats_status_timeout_as_busy(self) -> None:
        with mock.patch.object(hook, "send_daemon_request", side_effect=TimeoutError("timed out")):
            self.assertEqual(hook._daemon_probe(self.config(), timeout=0.01), "busy")


class FinalDecisionTests(unittest.TestCase):
    def test_weak_deny_requires_permit(self) -> None:
        review = hook.ReviewResult("weak_deny", "needs privileged read")
        decision = hook.final_decision(review, "none", "inspect logs", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("ask the user only for the weak_deny permit word", decision.message)
        self.assertIn("Write a brief approval scope yourself", decision.message)
        self.assertIn("CODEX_APPROVER_SCOPE", decision.message)
        self.assertIn("CODEX_APPROVER_PERMIT", decision.message)
        self.assertIn("very start of the Bash command", decision.message)
        self.assertIn("before sudo", decision.message)
        self.assertEqual(hook.final_decision(review, "weak_deny", "inspect logs").behavior, "allow")
        self.assertEqual(hook.final_decision(review, "deny", "inspect logs").behavior, "allow")

    def test_permit_requires_scope(self) -> None:
        review = hook.ReviewResult("weak_deny", "needs privileged read")
        decision = hook.final_decision(review, "weak_deny", "", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("requires an agent-written scope", decision.message)
        self.assertIn("ask the user only for the weak_deny permit word", decision.message)
        self.assertIn("do not invent the permit word", decision.message)

    def test_non_bash_permit_denial_explains_supported_channel(self) -> None:
        review = hook.ReviewResult("deny", "writes outside workspace")
        decision = hook.final_decision(review, "none", "", "apply_patch")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("only accepts scope and permit words through Bash", decision.message)
        self.assertIn("do not attach CODEX_APPROVER_SCOPE", decision.message)
        self.assertIn("narrow the request", decision.message)

    def test_strong_deny_cannot_be_permitted(self) -> None:
        review = hook.ReviewResult("strong_deny", "destructive")
        decision = hook.final_decision(review, "deny", "cleanup")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("cannot be permitted", decision.message)
        self.assertIn("Do not ask the user for a permit word", decision.message)


class HookMainTests(unittest.TestCase):
    def test_permission_request_outputs_allow(self) -> None:
        stdin = io.StringIO(
            json.dumps(
                {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                }
            )
        )
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text("{}\n", encoding="utf-8")
            with mock.patch("sys.stdin", stdin), mock.patch("sys.stdout", stdout), mock.patch.dict(
                "os.environ",
                {"CODEX_AI_APPROVER_CONFIG": str(config_path)},
            ), mock.patch.object(
                hook,
                "review_permission_request",
                return_value=hook.ReviewResult("allow", "read-only"),
            ):
                code = hook.run_hook()

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        decision = payload["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "allow")

    def test_permission_request_outputs_deny_on_error(self) -> None:
        stdout = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("{}")), mock.patch("sys.stdout", stdout), mock.patch.object(
            hook,
            "review_permission_request",
            side_effect=RuntimeError("boom"),
        ):
            code = hook.run_hook()

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        decision = payload["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "deny")
        self.assertIn("Codex AI Approver hook failed", decision["message"])
        self.assertIn("setup/runtime failure", decision["message"])
        self.assertIn("not a safety denial", decision["message"])
        self.assertIn("Do not retry the same tool call unchanged", decision["message"])
        self.assertIn("boom", decision["message"])


if __name__ == "__main__":
    unittest.main()
