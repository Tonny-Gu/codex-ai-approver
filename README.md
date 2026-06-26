# Codex AI Approver

Codex plugin that uses a Codex model to answer command approval requests from a single-file lifecycle hook.

The plugin reads `~/.codex-ai-approver.json`. If the file is missing, defaults are:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium"
}
```

Optional keys:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium",
  "on_error": "deny",
  "debug": false
}
```

The plugin only registers `PermissionRequest` and answers Codex approval prompts with `allow` or `deny`. The matcher is `*`, so it can review every supported permission request hook payload Codex sends to plugins, including Bash, patch, and MCP tool approvals. It does not intercept normal sandbox-allowed actions or product-layer prompts that do not go through `PermissionRequest`.

Install dependency in the Python environment used by hooks:

```bash
python3 -m pip install openai-codex
```

The hook uses existing Codex authentication from the local Codex SDK runtime.
