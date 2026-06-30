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
        self.assertEqual(
            config.permit_words,
            {category: category for category in common.PERMITTABLE_CATEGORIES},
        )
        self.assertEqual(config.daemon_port, 47678)

    def test_reads_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                (
                    '{"model":"gpt-5.4","reasoning_effort":"high",'
                    '"permit_words":{"package_install":"pkg","remote_execution":"remote"}}\n'
                ),
                encoding="utf-8",
            )
            config = common.load_config(path)
        self.assertEqual(config.model, "gpt-5.4")
        self.assertEqual(config.reasoning_effort, "high")
        self.assertEqual(config.permit_words, {"package_install": "pkg", "remote_execution": "remote"})

    def test_permit_words_replace_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"permit_words":{"service_control":"custom"}}\n', encoding="utf-8")
            config = common.load_config(path)
        self.assertEqual(config.permit_words, {"service_control": "custom"})

    def test_unknown_permit_word_category_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"permit_words":{"unknown":"word"}}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown permit_words categories"):
                common.load_config(path)

    def test_duplicate_permit_words_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                '{"permit_words":{"package_install":"same","network_fetch":"same"}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicates permit word"):
                common.load_config(path)

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
        permit_words = {category: category for category in common.PERMITTABLE_CATEGORIES}
        permit_words["privileged_read"] = "priv-token"
        permit_words["log_read"] = "log-token"
        config = common.ApproverConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            permit_words=permit_words,
        )
        hook_input = common.parse_hook_input(
            json.dumps(
                {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": (
                            'FOO=bar CODEX_APPROVER_JUSTIFICATION="inspect app logs to debug startup failure" '
                            'CODEX_APPROVER_PERMITS="priv-token log-token" git status'
                        )
                    },
                }
            ),
            config,
        )
        self.assertEqual(hook_input.cwd, "/repo")
        self.assertEqual(hook_input.tool_name, "Bash")
        self.assertEqual(hook_input.tool_input, {"command": "FOO=bar git status"})
        self.assertEqual(hook_input.justification, "inspect app logs to debug startup failure")
        self.assertEqual(hook_input.permit_categories, ["privileged_read", "log_read"])
        prompt = common.build_prompt(hook_input)
        self.assertNotIn("priv-token", prompt)
        self.assertNotIn("log-token", prompt)
        self.assertNotIn("User permit", prompt)
        self.assertNotIn("privileged_read", prompt)
        self.assertIn("Agent justification", prompt)

    def test_uses_default_permit_words(self) -> None:
        hook_input = common.parse_hook_input(
            json.dumps(
                {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": (
                            'CODEX_APPROVER_JUSTIFICATION="inspect logs" '
                            'CODEX_APPROVER_PERMITS="privileged_read log_read" git status'
                        )
                    },
                }
            )
        )
        self.assertEqual(hook_input.permit_categories, ["privileged_read", "log_read"])


class LlmParsingTests(unittest.TestCase):
    def test_parse_json_review(self) -> None:
        review = common.parse_review(
            '{"categories":["package_install","network_fetch"],"reason":"fetches packages"}'
        )
        self.assertEqual(
            review,
            common.ReviewResult(["package_install", "network_fetch"], "fetches packages"),
        )

    def test_parse_review_deduplicates_categories(self) -> None:
        review = common.parse_review(
            '{"categories":["package_install","package_install"],"reason":"fetches packages"}'
        )
        self.assertEqual(review.categories, ["package_install"])

    def test_output_schema_omits_unsupported_unique_items(self) -> None:
        categories_schema = common.OUTPUT_SCHEMA["properties"]["categories"]
        self.assertNotIn("uniqueItems", categories_schema)

    def test_reviewer_prompt_requires_short_reason(self) -> None:
        self.assertIn("Keep the reason to one short sentence.", common.DEVELOPER_INSTRUCTIONS)
        self.assertIn("necessary and proportional", common.DEVELOPER_INSTRUCTIONS)
        self.assertNotIn("User permit", common.DEVELOPER_INSTRUCTIONS)
        self.assertNotIn("permit is present", common.DEVELOPER_INSTRUCTIONS)


class DaemonTests(unittest.TestCase):
    def config(self, daemon_port: int = 47678) -> common.ApproverConfig:
        return common.ApproverConfig(
            model="gpt-5.5",
            reasoning_effort="medium",
            permit_words={category: category for category in common.PERMITTABLE_CATEGORIES},
            daemon_port=daemon_port,
        )

    def test_review_with_daemon_uses_rpc_protocol(self) -> None:
        class FakeProxy:
            def review(self, payload):
                self.payload = payload
                return {"categories": ["allow"], "reason": "read-only"}

        hook_input = common.HookInput("/repo", "Bash", {"command": "git status"}, "", [])
        proxy = FakeProxy()
        with mock.patch.object(hook, "ensure_daemon_running") as ensure, mock.patch.object(
            hook,
            "daemon_proxy",
            return_value=proxy,
        ):
            review = hook.review_with_daemon(hook_input, self.config())
        self.assertEqual(review, common.ReviewResult(["allow"], "read-only"))
        ensure.assert_called_once()
        self.assertEqual(proxy.payload["tool_input"], {"command": "git status"})

    def test_review_with_daemon_uses_xmlrpc_over_tcp(self) -> None:
        stop_requested = False

        def stop():
            nonlocal stop_requested
            stop_requested = True
            return {"ok": True}

        try:
            server = SimpleXMLRPCServer(
                ("localhost", 0),
                allow_none=True,
                logRequests=False,
            )
        except PermissionError as exc:
            self.skipTest(f"TCP bind is unavailable: {exc}")
        server.register_function(lambda: {"ok": True}, "status")
        server.register_function(lambda payload: {"categories": ["allow"], "reason": "read-only"}, "review")
        server.register_function(stop, "stop")

        def serve():
            while not stop_requested:
                server.handle_request()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            config = self.config(daemon_port=server.server_address[1])
            review = hook.review_with_daemon(
                common.HookInput("/repo", "Bash", {"command": "git status"}, "", []),
                config,
            )
            stop_response = hook.daemon_proxy(config).stop()
        finally:
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(review, common.ReviewResult(["allow"], "read-only"))
        self.assertEqual(stop_response, {"ok": True})
        self.assertFalse(thread.is_alive())

    def test_daemon_stop_cli_calls_stop(self) -> None:
        class FakeProxy:
            def stop(self):
                self.called = True
                return {"ok": True}

        proxy = FakeProxy()
        stdout = io.StringIO()
        with mock.patch.object(hook, "load_config", return_value=self.config()), mock.patch.object(
            hook,
            "daemon_proxy",
            return_value=proxy,
        ), mock.patch("sys.stdout", stdout):
            code = hook.daemon_stop_cli()

        self.assertEqual(code, 0)
        self.assertTrue(proxy.called)
        self.assertEqual(json.loads(stdout.getvalue()), {"ok": True})

    def test_spawn_daemon_appends_to_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "codex-ai-approver.log"
            with mock.patch.object(hook, "DAEMON_LOG_PATH", log_path), mock.patch.object(
                hook.subprocess,
                "Popen",
            ) as popen:
                hook._spawn_daemon()

            self.assertTrue(log_path.exists())

        popen.assert_called_once()
        kwargs = popen.call_args.kwargs
        self.assertEqual(kwargs["stdout"].name, str(log_path))
        self.assertEqual(kwargs["stdout"].mode, "a")
        self.assertEqual(kwargs["stderr"], hook.subprocess.STDOUT)


class FinalDecisionTests(unittest.TestCase):
    def test_category_requires_permit(self) -> None:
        review = common.ReviewResult(["privileged_read"], "needs privileged read")
        decision = common.final_decision(review, [], "inspect logs", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("privileged_read", decision.message)
        self.assertIn("Write a brief justification yourself", decision.message)
        self.assertIn("necessary and proportional", decision.message)
        self.assertIn("CODEX_APPROVER_JUSTIFICATION", decision.message)
        self.assertIn("CODEX_APPROVER_PERMITS", decision.message)
        self.assertIn("very start of the Bash command", decision.message)
        self.assertIn("before sudo", decision.message)
        self.assertEqual(
            common.final_decision(review, ["privileged_read"], "inspect logs").behavior,
            "allow",
        )

    def test_all_categories_must_be_permitted(self) -> None:
        review = common.ReviewResult(
            ["package_install", "network_fetch"],
            "installs packages from the network",
        )
        decision = common.final_decision(review, ["package_install"], "install test dependency", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("network_fetch", decision.message)
        self.assertEqual(
            common.final_decision(
                review,
                ["package_install", "network_fetch"],
                "install test dependency",
            ).behavior,
            "allow",
        )

    def test_permit_requires_justification(self) -> None:
        review = common.ReviewResult(["privileged_read"], "needs privileged read")
        decision = common.final_decision(review, ["privileged_read"], "", "Bash")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("require an agent-written justification", decision.message)
        self.assertIn("privileged_read", decision.message)
        self.assertIn("do not invent permit words", decision.message)

    def test_non_bash_permit_denial_explains_supported_channel(self) -> None:
        review = common.ReviewResult(["write_outside_workspace"], "writes outside workspace")
        decision = common.final_decision(review, [], "", "apply_patch")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("only accepts justification and permit words through Bash", decision.message)
        self.assertIn("do not attach CODEX_APPROVER_JUSTIFICATION", decision.message)
        self.assertIn("CODEX_APPROVER_PERMITS", decision.message)
        self.assertIn("narrow the request", decision.message)

    def test_blocked_categories_cannot_be_permitted(self) -> None:
        review = common.ReviewResult(["destructive_action"], "destructive")
        decision = common.final_decision(review, ["package_install"], "cleanup")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("cannot be permitted", decision.message)
        self.assertIn("Do not ask the user for permit words", decision.message)


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
                return_value=common.ReviewResult(["allow"], "read-only"),
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
