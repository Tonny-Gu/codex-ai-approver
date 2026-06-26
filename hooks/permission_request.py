#!/usr/bin/env python3
from pathlib import Path
import os
import sys


def _add_plugin_root() -> None:
    plugin_root = os.environ.get("PLUGIN_ROOT")
    if plugin_root:
        root = Path(plugin_root)
    else:
        root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))


def main() -> int:
    _add_plugin_root()
    from codex_ai_approver.hook_main import run_hook

    return run_hook("PermissionRequest")


if __name__ == "__main__":
    raise SystemExit(main())
