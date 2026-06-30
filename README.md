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

The main motivation is context control. Codex Auto-review gives its reviewer a compact transcript plus the exact approval request. That transcript can include user messages, assistant updates, relevant tool calls, and tool outputs. Codex AI Approver intentionally sends a smaller prompt to its reviewer model: working directory, tool name, sanitized tool input, and the agent's justification for the request. The reviewer prompt does not include the permit word or permit level. That usually means less contextual leakage and a smaller approval prompt, at the cost of less broad conversation awareness.

Key differences:

- **Layer:** Auto-review is a built-in Codex sandbox-boundary reviewer; this project is a plugin lifecycle hook.
- **Context:** Auto-review sees a compact retained transcript and tool evidence; this hook's reviewer prompt sees only the current permission request plus the agent's justification.
- **Precedence:** When `PermissionRequest` hook evaluation is enabled, a hook decision is handled before Auto-review or user approval.
- **Policy shape:** Auto-review follows Codex's reviewer policy and supports policy customization through Codex configuration; this hook uses fixed local risk categories and optional local permit words for each permittable category.
- **User override:** Auto-review has its own denial override flow in Codex; this hook uses Bash prefix variables for agent-written justifications and user-provided permit words.
- **Failure mode:** Auto-review timeouts and denials are handled by Codex; this hook fails closed by returning a deny message that tells the agent the hook setup/runtime failed.
- **Coverage:** Auto-review focuses on approval requests that cross the active sandbox or policy boundary. This hook sees supported `PermissionRequest` hook payloads from the plugin system.

Normal Auto-review should not make this hook ineffective, because hook decisions are evaluated first. There are still important limits:

- If hooks are disabled, untrusted, not installed, or not matched, Codex falls back to Auto-review or user approval.
- If this hook exits without a decision, Codex falls back to Auto-review or user approval.
- In strict Auto-review paths, Codex disables `PermissionRequest` hook evaluation and routes the request through the guardian reviewer directly.

For this plugin to be the primary approver, keep hooks enabled and trusted, and do not rely on strict Auto-review for the same approval path. The relevant upstream implementation is in Codex's [`PermissionRequest` hook event](https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/permission_request.rs) and approval [`orchestrator`](https://github.com/openai/codex/blob/main/codex-rs/core/src/tools/orchestrator.rs).

## Risk Categories

The reviewer model returns every category that applies. `allow` is used only when no other category applies.

No-permit category:

- `allow`: clearly justified actions that are low-risk, scoped, reversible, and have no privileged access, secret exposure, external side effects, or persistent production impact. Includes safe local tests, builds, linters, formatters, ordinary workspace edits requested by the user, and local git staging/commits that do not discard work, rewrite history, or affect remotes.

Permittable categories:

- `privileged_read`: sudo/admin/root read-only access.
- `log_read`: log inspection.
- `process_inspection`: process, port, performance, or system-state inspection.
- `secret_read`: secret, token, credential, or environment-variable reads.
- `personal_data_access`: personal or private user data such as email, calendar, contacts, browser data, local documents, or history.
- `network_fetch`: outbound read-only network access or data fetches.
- `external_side_effect`: external writes such as sending messages, posting comments, creating tickets, submitting forms, or calling webhooks.
- `package_install`: package manager installs, upgrades, or dependency fetches.
- `dependency_or_supply_chain_change`: dependency, lockfile, package source, toolchain, base image, or CI action changes.
- `remote_execution`: SSH or other remote command execution.
- `service_control`: service, daemon, container, VM, or cluster control.
- `production_change`: production deploy, feature flag, environment config, scaling, cache, CDN, or infrastructure behavior change.
- `permission_change`: chmod/chown/ACL/capability/IAM/access-control changes.
- `auth_or_credential_change`: login, logout, token creation, key rotation, credential revocation, SSH/GPG/keychain/OAuth changes.
- `persistent_data_write`: database, cache, queue, object storage, search index, or other persistent state mutation.
- `write_outside_workspace`: writes outside the current working directory.
- `scheduled_or_persistent_execution`: cron, systemd timer, launch agent, startup hook, scheduled CI, background worker, or persistent job creation.
- `resource_intensive`: load tests, long-running jobs, high CPU/GPU/memory/disk/network usage, or large batch operations.
- `publication_or_release`: release or publication of packages, images, repositories, artifacts, announcements, or public content.

Non-permittable categories:

- `destructive_action`: irreversible or broad destructive deletes, overwrites, data loss, or cleanup affecting user data, production data, shared resources, or unclear targets.
- `git_worktree_discard`: discarding uncommitted changes without explicit user intent.
- `git_history_rewrite`: forced history changes such as reset, rebase rewrites, filter-branch, reflog-sensitive operations, or deleting refs.
- `protected_branch_force_push`: force push to protected, shared, release, main, or unclear branches.
- `policy_bypass`: attempts to bypass approval, sandboxing, authentication, monitoring, or safety policy.
- `unjustified_access`: privileged, remote, secret, personal-data, side-effecting, or broad access without concrete necessary and proportional justification.
- `unclear_blast_radius`: request has an unclear, ambiguous, or overly broad blast radius.
- `data_exfiltration`: sending secrets, credentials, private code, personal data, logs, dumps, or proprietary data to external destinations without explicit necessity and authorization.
- `unreviewed_untrusted_code_execution`: executing untrusted downloaded, pasted, generated, or third-party code without review and justification, especially with elevated privileges or network access.
- `identity_or_access_grant_to_third_party`: granting third parties access, sharing private resources publicly, inviting users, adding deploy keys, or authorizing OAuth apps without explicit authorization.
- `financial_or_legal_commitment`: purchases, trades, billing changes, legal filings, contract acceptance, or other binding commitments.
- `unauthorized_publication`: public release or publication of packages, images, repositories, artifacts, announcements, or confidential information without explicit authorization.

Final authorization is stricter than classification:

- `allow` is allowed.
- Every permittable category returned by the reviewer requires an agent-written justification and a matching user-provided permit word.
- If the reviewer returns more than one permittable category, every category must be permitted.
- Non-permittable categories are always denied and cannot be permitted.

## Bash Justification and Permit Words

For Bash approvals, an agent can pass user-provided context with prefix environment variables:

```bash
CODEX_APPROVER_JUSTIFICATION="Need to install project test dependencies; package install and network fetch only." CODEX_APPROVER_PERMITS="package_install network_fetch" pip install -r requirements.txt
```

The variables must be placed at the very start of the Bash command, before `sudo`, `env`, or the actual command. The hook parses these prefixes, verifies the permit words locally, and excludes both the permit words and matched permit categories from the prompt sent to the reviewer model.

The justification is written by the agent and should explain why this exact request is necessary and proportional to the current task, including the intended boundary. Permit words are not something the agent should invent. If the hook denies a request because justification or permits are missing, the agent should write the justification itself, ask the user only for the required permit words, then retry the Bash command with the prefix variables.

## Non-Bash Requests

Justification and permit words can only be passed through Bash command prefixes. For `apply_patch` and MCP tool approvals, the agent should not try to attach `CODEX_APPROVER_JUSTIFICATION` or `CODEX_APPROVER_PERMITS` to the tool call.

If a non-Bash request is denied, the expected next step is to narrow the request, use a safer alternative, or use a Bash equivalent when that is appropriate.

## Configuration

The hook reads `~/.codex-ai-approver.json`. If the file is missing, these defaults are used:

```json
{
  "model": "gpt-5.5",
  "reasoning_effort": "medium",
  "daemon_port": 47678,
  "permit_words": {
    "privileged_read": "privileged_read",
    "log_read": "log_read",
    "process_inspection": "process_inspection",
    "secret_read": "secret_read",
    "personal_data_access": "personal_data_access",
    "network_fetch": "network_fetch",
    "external_side_effect": "external_side_effect",
    "package_install": "package_install",
    "dependency_or_supply_chain_change": "dependency_or_supply_chain_change",
    "remote_execution": "remote_execution",
    "service_control": "service_control",
    "production_change": "production_change",
    "permission_change": "permission_change",
    "auth_or_credential_change": "auth_or_credential_change",
    "persistent_data_write": "persistent_data_write",
    "write_outside_workspace": "write_outside_workspace",
    "scheduled_or_persistent_execution": "scheduled_or_persistent_execution",
    "resource_intensive": "resource_intensive",
    "publication_or_release": "publication_or_release"
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
    "package_install": "word-for-package-installs",
    "network_fetch": "word-for-network-fetch",
    "remote_execution": "word-for-remote-execution",
    "service_control": "word-for-service-control",
    "production_change": "word-for-production-change"
  }
}
```

If `permit_words` is present in the config file, it replaces the default permit-word set. Only listed categories can be permitted. Permit word keys must be one of the fixed permittable categories; unknown category names and duplicate permit words are rejected.

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
