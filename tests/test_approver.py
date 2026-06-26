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


class HookInputTests(unittest.TestCase):
    def test_parses_hook_input(self) -> None:
        config = hook.ApproverConfig(permit_words={"weak_deny": "secret-token"})
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


class LlmParsingTests(unittest.TestCase):
    def test_parse_json_review(self) -> None:
        review = hook.parse_review('{"category":"deny","reason":"too broad"}')
        self.assertEqual(review, hook.ReviewResult("deny", "too broad"))


class FinalDecisionTests(unittest.TestCase):
    def test_weak_deny_requires_permit(self) -> None:
        review = hook.ReviewResult("weak_deny", "needs privileged read")
        self.assertEqual(hook.final_decision(review, "none").behavior, "deny")
        self.assertEqual(hook.final_decision(review, "weak_deny").behavior, "allow")
        self.assertEqual(hook.final_decision(review, "deny").behavior, "allow")

    def test_strong_deny_cannot_be_permitted(self) -> None:
        review = hook.ReviewResult("strong_deny", "destructive")
        decision = hook.final_decision(review, "deny")
        self.assertEqual(decision.behavior, "deny")
        self.assertIn("cannot be permitted", decision.message)


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
                "review_with_codex",
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
            "review_with_codex",
            side_effect=RuntimeError("boom"),
        ):
            code = hook.run_hook()

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        decision = payload["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "deny")
        self.assertIn("boom", decision["message"])


if __name__ == "__main__":
    unittest.main()
