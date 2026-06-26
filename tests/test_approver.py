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
                '{"model":"gpt-5.4","reasoning_effort":"high"}\n',
                encoding="utf-8",
            )
            config = hook.load_config(path)
        self.assertEqual(config.model, "gpt-5.4")
        self.assertEqual(config.reasoning_effort, "high")


class HookInputTests(unittest.TestCase):
    def test_parses_hook_input(self) -> None:
        hook_input = hook.parse_hook_input(
            json.dumps(
                {
                    "cwd": "/repo",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                }
            )
        )
        self.assertEqual(hook_input.cwd, "/repo")
        self.assertEqual(hook_input.tool_name, "Bash")
        self.assertEqual(hook_input.tool_input, {"command": "git status"})


class LlmParsingTests(unittest.TestCase):
    def test_parse_json_decision(self) -> None:
        decision = hook.parse_decision('{"decision":"deny","reason":"too broad"}')
        self.assertEqual(decision, hook.LlmDecision("deny", "too broad"))


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
                "decide_with_codex",
                return_value=hook.LlmDecision("allow", "read-only"),
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
            "decide_with_codex",
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
