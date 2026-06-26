# Codex AI Approver

Codex plugin that uses a Codex model to answer command approval requests from a single-file lifecycle hook.

## Install from GitHub marketplace

Add this repository as a Codex plugin marketplace, list available plugins, then install the plugin:

```bash
codex plugin marketplace add owner/codex-ai-approver --ref main
codex plugin list --available
codex plugin add codex-ai-approver@<marketplace-name>
```

Replace `owner` with the GitHub owner for the repository. If you are unsure what marketplace name Codex assigned, run:

```bash
codex plugin marketplace list
```

This marketplace declares the name `codex-ai-approver`, so the install command is usually:

```bash
codex plugin add codex-ai-approver@codex-ai-approver
```

After installing, start a new Codex thread or restart Codex. Because this plugin registers a command hook, open `/hooks` and trust the new hook if Codex asks for review.

The plugin reads `~/.codex-ai-approver.json`. If the file is missing, defaults are:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium",
  "permit_words": {
    "weak_deny": "weak_deny",
    "deny": "deny"
  }
}
```

Optional keys:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium",
  "permit_words": {
    "weak_deny": "word-for-weak-risk",
    "deny": "word-for-higher-risk"
  }
}
```

The plugin only registers `PermissionRequest` and answers Codex approval prompts with `allow` or `deny`. The matcher is `*`, so it can review every supported permission request hook payload Codex sends to plugins, including Bash, patch, and MCP tool approvals. It does not intercept normal sandbox-allowed actions or product-layer prompts that do not go through `PermissionRequest`.

For Bash approvals, a command can pass user context with prefix variables:

```bash
CODEX_APPROVER_SCOPE="inspect service logs" CODEX_APPROVER_PERMIT="weak_deny" sudo journalctl -u app
```

The permit word is verified locally and stripped before the command is sent to the model. The model classifies risk as `allow`, `weak_deny`, `deny`, or `strong_deny`; the hook then applies the permit level. `strong_deny` cannot be permitted.

Install dependency in the Python environment used by hooks:

```bash
python3 -m pip install openai-codex
```

The hook uses existing Codex authentication from the local Codex SDK runtime.
