from __future__ import annotations

from pathlib import Path
from unittest import mock
import io
import json
import tempfile
import unittest

from codex_ai_approver.config import load_config
from codex_ai_approver.hook_io import parse_hook_input, extract_target
from codex_ai_approver.hook_main import run_hook
from codex_ai_approver.llm import LlmDecision, parse_decision


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = load_config(Path("/no/such/file"))
        self.assertEqual(config.model, "gpt-5.5")
        self.assertEqual(config.reasoning_effort, "medium")

    def test_reads_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            path.write_text("model: gpt-5.4\nreasoning_effort: high\n", encoding="utf-8")
            config = load_config(path)
        self.assertEqual(config.model, "gpt-5.4")
        self.assertEqual(config.reasoning_effort, "high")


class HookInputTests(unittest.TestCase):
    def test_extracts_bash_command(self) -> None:
        hook_input = parse_hook_input(
            json.dumps(
                {
                    "hook_event_name": "PermissionRequest",
                    "session_id": "s",
                    "turn_id": "t",
                    "cwd": "/repo",
                    "model": "gpt",
                    "permission_mode": "default",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                }
            ),
            "PermissionRequest",
        )
        self.assertEqual(extract_target(hook_input), "git status")

    def test_extracts_non_bash_payload(self) -> None:
        hook_input = parse_hook_input(
            json.dumps(
                {
                    "hook_event_name": "PermissionRequest",
                    "session_id": "s",
                    "turn_id": "t",
                    "cwd": "/repo",
                    "model": "gpt",
                    "permission_mode": "default",
                    "tool_name": "apply_patch",
                    "tool_input": {"command": "*** Begin Patch\n*** End Patch\n"},
                }
            ),
            "PermissionRequest",
        )
        self.assertEqual(extract_target(hook_input), "*** Begin Patch\n*** End Patch\n")


class LlmParsingTests(unittest.TestCase):
    def test_parse_json_decision(self) -> None:
        decision = parse_decision('{"decision":"deny","reason":"too broad"}')
        self.assertEqual(decision, LlmDecision("deny", "too broad"))


class HookMainTests(unittest.TestCase):
    def test_permission_request_outputs_allow(self) -> None:
        stdin = io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PermissionRequest",
                    "session_id": "s",
                    "turn_id": "t",
                    "cwd": "/repo",
                    "model": "gpt",
                    "permission_mode": "default",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                }
            )
        )
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text("cache_ttl_sec: 0\n", encoding="utf-8")
            with mock.patch("sys.stdin", stdin), mock.patch("sys.stdout", stdout), mock.patch.dict(
                "os.environ",
                {"CODEX_AI_APPROVER_CONFIG": str(config_path), "PLUGIN_DATA": tmp},
            ), mock.patch(
                "codex_ai_approver.hook_main.decide_with_codex",
                return_value=LlmDecision("allow", "read-only"),
            ):
                code = run_hook("PermissionRequest")

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        decision = payload["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "allow")


if __name__ == "__main__":
    unittest.main()
