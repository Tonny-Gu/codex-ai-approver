from __future__ import annotations

from pathlib import Path
from unittest import mock
import io
import json
import sys
import tempfile
import threading
import unittest
from xmlrpc.server import SimpleXMLRPCServer


HOOKS_DIR = Path(__file__).resolve().parents[1] / "hooks"
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import approver_common as common  # noqa: E402
import permission_request as hook  # noqa: E402


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = common.load_config(Path("/no/such/file"))
        self.assertEqual(config.model, "gpt-5.5")
        self.assertEqual(config.reasoning_effort, "medium")
        self.assertEqual(config.permit_words, {"weak_deny": "weak_deny", "deny": "deny"})
        self.assertEqual(config.daemon_port, 47678)

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
            config = common.load_config(path)
        self.assertEqual(config.model, "gpt-5.4")
        self.assertEqual(config.reasoning_effort, "high")
        self.assertEqual(config.permit_words, {"weak_deny": "weak", "deny": "higher"})

    def test_partial_permit_words_override_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"permit_words":{"weak_deny":"custom"}}\n', encoding="utf-8")
            config = common.load_config(path)
        self.assertEqual(config.permit_words, {"weak_deny": "custom", "deny": "deny"})

    def test_reads_daemon_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "daemon_port": 48765,
                    }
                ),
                encoding="utf-8",
            )
            config = common.load_config(path)
        self.assertEqual(config.daemon_port, 48765)


class HookInputTests(unittest.TestCase):
    def test_parses_hook_input(self) -> None:
        config = common.ApproverConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            permit_words={"weak_deny": "secret-token", "deny": "deny"},
        )
        hook_input = common.parse_hook_input(
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
        self.assertNotIn("secret-token", common.build_prompt(hook_input))

    def test_uses_default_permit_words(self) -> None:
        hook_input = common.parse_hook_input(
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
        review = common.parse_review('{"category":"deny","reason":"too broad"}')
        self.assertEqual(review, common.ReviewResult("deny", "too broad"))

    def test_reviewer_prompt_requires_short_reason(self) -> None:
        self.assertIn("Keep the reason to one short sentence.", common.DEVELOPER_INSTRUCTIONS)


class DaemonTests(unittest.TestCase):
    def config(self, daemon_port: int = 47678) -> common.ApproverConfig:
        return common.ApproverConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            permit_words={"weak_deny": "weak_deny", "deny": "deny"},
            daemon_port=daemon_port,
        )

    def test_review_with_daemon_uses_rpc_protocol(self) -> None:
        class FakeProxy:
            def review(self, payload):
                self.payload = payload
                return {"category": "allow", "reason": "read-only"}

        hook_input = common.HookInput("/repo", "Bash", {"command": "git status"}, "", "none")
        proxy = FakeProxy()
        with mock.patch.object(hook, "ensure_daemon_running") as ensure, mock.patch.object(
            hook,
            "daemon_proxy",
            return_value=proxy,
        ):
            review = hook.review_with_daemon(hook_input, self.config())
        self.assertEqual(review, common.ReviewResult("allow", "read-only"))
        ensure.assert_called_once()
        self.assertEqual(proxy.payload["tool_input"], {"command": "git status"})

    def test_review_with_daemon_uses_xmlrpc_over_tcp(self) -> None:
        try:
            server = SimpleXMLRPCServer(
                ("localhost", 0),
                allow_none=True,
                logRequests=False,
            )
        except PermissionError as exc:
            self.skipTest(f"TCP bind is unavailable: {exc}")
        server.register_function(lambda: {"ok": True}, "status")
        server.register_function(lambda payload: {"category": "allow", "reason": "read-only"}, "review")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = self.config(daemon_port=server.server_address[1])
            review = hook.review_with_daemon(
                common.HookInput("/repo", "Bash", {"command": "git status"}, "", "none"),
                config,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(review, common.ReviewResult("allow", "read-only"))
        self.assertFalse(thread.is_alive())


class FinalDecisionTests(unittest.TestCase):
    def test_weak_deny_requires_permit(self) -> None:
        review = common.ReviewResult("weak_deny", "needs privileged read")
        decision = common.final_decision(review, "none", "inspect logs", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("ask the user only for the weak_deny permit word", decision.message)
        self.assertIn("Write a brief approval scope yourself", decision.message)
        self.assertIn("CODEX_APPROVER_SCOPE", decision.message)
        self.assertIn("CODEX_APPROVER_PERMIT", decision.message)
        self.assertIn("very start of the Bash command", decision.message)
        self.assertIn("before sudo", decision.message)
        self.assertEqual(common.final_decision(review, "weak_deny", "inspect logs").behavior, "allow")
        self.assertEqual(common.final_decision(review, "deny", "inspect logs").behavior, "allow")

    def test_permit_requires_scope(self) -> None:
        review = common.ReviewResult("weak_deny", "needs privileged read")
        decision = common.final_decision(review, "weak_deny", "", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("requires an agent-written scope", decision.message)
        self.assertIn("ask the user only for the weak_deny permit word", decision.message)
        self.assertIn("do not invent the permit word", decision.message)

    def test_non_bash_permit_denial_explains_supported_channel(self) -> None:
        review = common.ReviewResult("deny", "writes outside workspace")
        decision = common.final_decision(review, "none", "", "apply_patch")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("only accepts scope and permit words through Bash", decision.message)
        self.assertIn("do not attach CODEX_APPROVER_SCOPE", decision.message)
        self.assertIn("narrow the request", decision.message)

    def test_strong_deny_cannot_be_permitted(self) -> None:
        review = common.ReviewResult("strong_deny", "destructive")
        decision = common.final_decision(review, "deny", "cleanup")
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
                "review_with_daemon",
                return_value=common.ReviewResult("allow", "read-only"),
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
            "review_with_daemon",
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
