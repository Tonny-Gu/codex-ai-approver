# Codex AI Approver

Codex AI Approver is a Codex plugin that installs a `PermissionRequest` lifecycle hook. When Codex asks for permission to run a tool, this hook asks a separate Codex model to classify the request, then returns `allow` or `deny` to the approval flow.

The hook is designed to make approval prompts more consistent. It does not bypass Codex sandboxing, product approval policy, hook trust, or user permissions.

## Install

Install the Python dependency in the environment that Codex uses for hooks:

```bash
python3 -m pip install openai-codex
```

Add this GitHub repository as a Codex plugin marketplace and install the plugin:

```bash
codex plugin marketplace add Tonny-Gu/codex-ai-approver --ref main
codex plugin list --available
codex plugin add codex-ai-approver@codex-ai-approver
```

After installing, start a new Codex thread or restart Codex. Because this plugin registers a command hook, open `/hooks` and trust the new hook if Codex asks for review.

If you need to inspect configured marketplace names:

```bash
codex plugin marketplace list
```

## What the Hook Reviews

The plugin registers only the `PermissionRequest` hook. Its matcher is `*`, so it can review every supported permission request payload Codex sends to plugins, including:

- `Bash`
- `apply_patch`
- MCP tools

It does not intercept actions that Codex can already run without a permission request, and it does not handle product-layer prompts that do not go through `PermissionRequest`.

## Compared With Codex Auto-Review

Codex also has a built-in [Auto-review](https://developers.openai.com/codex/concepts/sandboxing/auto-review) feature. Auto-review replaces manual approval at the sandbox boundary with a separate reviewer agent. It applies when approvals are interactive, such as `approval_policy = "on-request"` or a granular approval policy that still surfaces the relevant prompt category. It does not apply when `approval_policy = "never"` because there is no approval prompt to review.

This plugin is different: it is a plugin-bundled `PermissionRequest` hook. In the current open-source Codex implementation, `PermissionRequest` hooks run in the approval path before guardian/Auto-review or the user approval UI. If a matching hook returns `allow` or `deny`, that hook decision takes top precedence. If no matching hook returns a decision, Codex falls back to the normal Auto-review or user approval path.

The main motivation is context control. Codex Auto-review gives its reviewer a compact transcript plus the exact approval request. That transcript can include user messages, assistant updates, relevant tool calls, and tool outputs. Codex AI Approver intentionally sends a smaller payload to its reviewer model: working directory, tool name, sanitized tool input, explicit user scope, and validated permit level. That usually means less contextual leakage and a smaller approval prompt, at the cost of less broad conversation awareness.

Key differences:

- **Layer:** Auto-review is a built-in Codex sandbox-boundary reviewer; this project is a plugin lifecycle hook.
- **Context:** Auto-review sees a compact retained transcript and tool evidence; this hook sees only the current permission request plus explicit scope/permit metadata.
- **Precedence:** When `PermissionRequest` hook evaluation is enabled, a hook decision is handled before Auto-review or user approval.
- **Policy shape:** Auto-review follows Codex's reviewer policy and supports policy customization through Codex configuration; this hook uses four local risk categories and optional local permit words.
- **User override:** Auto-review has its own denial override flow in Codex; this hook uses Bash prefix variables for scoped permit words.
- **Failure mode:** Auto-review timeouts and denials are handled by Codex; this hook fails closed by returning a deny message that tells the agent the hook setup/runtime failed.
- **Coverage:** Auto-review focuses on approval requests that cross the active sandbox or policy boundary. This hook sees supported `PermissionRequest` hook payloads from the plugin system.

Normal Auto-review should not make this hook ineffective, because hook decisions are evaluated first. There are still important limits:

- If hooks are disabled, untrusted, not installed, or not matched, Codex falls back to Auto-review or user approval.
- If this hook exits without a decision, Codex falls back to Auto-review or user approval.
- In strict Auto-review paths, Codex disables `PermissionRequest` hook evaluation and routes the request through the guardian reviewer directly.

For this plugin to be the primary approver, keep hooks enabled and trusted, and do not rely on strict Auto-review for the same approval path. The relevant upstream implementation is in Codex's [`PermissionRequest` hook event](https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/permission_request.rs) and approval [`orchestrator`](https://github.com/openai/codex/blob/main/codex-rs/core/src/tools/orchestrator.rs).

## Risk Categories

The reviewer model returns one of four categories:

- `allow`: clearly scoped, low-risk, reversible, or read-only actions.
- `weak_deny`: sensitive but in-scope read-only inspection, such as privileged logs, process inspection, or necessary secret reads.
- `deny`: in-scope actions with side effects, network access, package installs, service control, permission changes, writes outside the workspace, or unclear blast radius.
- `strong_deny`: destructive, out-of-scope, bypass-oriented, or too dangerous to permit.

Final authorization is stricter than classification:

- `allow` is allowed.
- `weak_deny` requires a scope and a valid `weak_deny` or `deny` permit word.
- `deny` requires a scope and a valid `deny` permit word.
- `strong_deny` is always denied and cannot be permitted.

## Bash Scope and Permit Words

For Bash approvals, an agent can pass user-provided context with prefix environment variables:

```bash
CODEX_APPROVER_SCOPE="inspect service logs" CODEX_APPROVER_PERMIT="weak_deny" sudo journalctl -u app
```

The variables must be placed at the very start of the Bash command, before `sudo`, `env`, or the actual command. The hook parses these prefixes, verifies the permit word locally, and removes the permit word from the prompt sent to the reviewer model.

The permit word is not something the agent should invent. If the hook denies a request because scope or permit is missing, the agent should write a brief scope from the current task, ask the user only for the required permit word, then retry the Bash command with the prefix variables.

## Non-Bash Requests

Scope and permit words can only be passed through Bash command prefixes. For `apply_patch` and MCP tool approvals, the agent should not try to attach `CODEX_APPROVER_SCOPE` or `CODEX_APPROVER_PERMIT` to the tool call.

If a non-Bash request is denied, the expected next step is to narrow the request, use a safer alternative, or use a Bash equivalent when that is appropriate.

## Configuration

The hook reads `~/.codex-ai-approver.json`. If the file is missing, these defaults are used:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium",
  "daemon_port": 47678,
  "permit_words": {
    "weak_deny": "weak_deny",
    "deny": "deny"
  }
}
```

Example custom config:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium",
  "daemon_port": 47678,
  "permit_words": {
    "weak_deny": "word-for-weak-risk",
    "deny": "word-for-higher-risk"
  }
}
```

You can override the config path by setting this in the environment where Codex launches hooks:

```bash
CODEX_AI_APPROVER_CONFIG=/path/to/config.json
```

## Long-Lived Daemon

By default, the hook starts a detached local daemon and sends each permission payload over XML-RPC on `localhost:47678`. The daemon keeps one Codex client and one warmed reviewer thread alive, runs each classification turn, then calls `thread/rollback` so the request history does not grow.

Stop the daemon manually with `python3 hooks/permission_request.py --daemon-stop`.

## Failure Behavior

If the hook itself fails, it denies the permission request and tells the agent that this is a hook setup/runtime failure, not a safety denial. Typical causes include:

- `openai-codex` is not installed in the hook Python environment.
- Codex authentication is unavailable to the local SDK runtime.
- The config file is invalid JSON or has invalid `permit_words`.
- The configured model or reasoning effort is invalid.
- The local approver daemon cannot start, respond, or return a valid review.
- The reviewer response cannot be parsed.

In these cases, the agent should not retry the same tool call unchanged. Fix the hook setup, dependency, authentication, or config first.

## Development

Run tests with:

```bash
python -m unittest tests/test_approver.py
```
