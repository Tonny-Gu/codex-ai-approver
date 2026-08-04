# Codex AI Approver

Codex AI Approver is a Codex plugin that installs a `PermissionRequest`
lifecycle hook. When Codex asks for permission to run a tool, the hook sends a
deterministically filtered session transcript and the exact planned action to a
separate Codex guardian, then returns the guardian's `allow` or `deny` outcome.

The plugin does not bypass Codex sandboxing, product approval policy, hook
trust, or user permissions.

## Install

Install the Python dependency in the environment that Codex uses for hooks:

```bash
python3 -m pip install openai-codex
```

Add this repository as a Codex plugin marketplace and install the plugin:

```bash
codex plugin marketplace add Tonny-Gu/codex-ai-approver --ref main
codex plugin list --available
codex plugin add codex-ai-approver@codex-ai-approver
```

Start a new Codex thread or restart Codex. Because this plugin registers a
command hook, open `/hooks` and trust it if Codex asks for review.

## What the Hook Covers

The plugin registers a `PermissionRequest` hook with matcher `*`. It can assess
supported Bash, `apply_patch`, MCP, and other permission requests sent through
that lifecycle event.

It does not intercept actions Codex can already run without a permission
request, and it does not handle product prompts that do not pass through
`PermissionRequest`.

Hook decisions run before built-in guardian/Auto-review or the user approval UI.
An `allow` or `deny` returned by this plugin therefore resolves the matching
permission request before those fallback paths.

## Guardian Evidence

The `PermissionRequest` payload provides `session_id`, `turn_id`,
`transcript_path`, the tool name, and the exact tool input. The plugin derives
guardian evidence directly from the Codex rollout JSONL on every assessment.
Correctness does not depend on a daemon-held authorization ledger.

The deterministic transcript retains:

- Messages recorded by the rollout with role `user`.
- A deterministic `user_turn` ordinal for each such message in the current
  context window.
- Text messages emitted by lifecycle hooks. This hook's own message is
  self-contained and includes the exact action and complete assessment.
- User messages retained by Codex at the start of a compacted context window.

It excludes assistant prose, reasoning, and standalone historical tool records.
Retained text is passed to the guardian unchanged.

Positive authorization persists across user turns by default, but only within
the current context window and until a later user message narrows or revokes
it. A user can instead limit authorization to the current user turn or to a
stated number of user turns. The granting turn counts as the first turn unless
the user explicitly specifies a different start.

After context compaction, pre-compaction user messages and hook messages are no
longer direct evidence. All prior positive grants end. User messages retained
in the compacted context may independently support the current task in
substance at no more than `medium`, but they cannot preserve an expired,
revoked, or turn-bounded grant.
`high` authorization requires a direct user message in the current context
window.

An expired grant produces no affirmative authorization. Hook messages cannot
extend it. A still-active user prohibition is classified separately and
remains effective until the user explicitly lifts it.

The pending action is always supplied separately and in full.

## Guardian Assessment

The guardian returns one structured assessment per planned action:

```json
{
  "risk_level": "medium",
  "user_authorization": "medium",
  "outcome": "allow",
  "decision_rationale": "The bounded action is allowed under the configured outcome policy.",
  "classification_rationale": "The user authorized the effect but not the exact implementation, and the reversible side effect makes the risk medium."
}
```

Risk levels are:

- `low`
- `medium`
- `high`
- `critical`

User authorization levels are:

- `prohibited`
- `none`
- `low`
- `medium`
- `high`

`prohibited` means the action conflicts with an applicable user prohibition or
revocation. `none` means there is no reliable affirmative authorization,
including when a bounded grant has expired. `low`, `medium`, and `high` are
increasing degrees of affirmative authorization.

Risk includes both the likely intended effect and execution uncertainty. The
guardian evaluates execution risk as the probability of unintended execution
multiplied by the severity of the resulting harm. Command length alone is not a
reason to raise risk.

Both allow and deny outcomes include two rationales. The decision rationale
explains the outcome; the classification rationale explains both
`risk_level` and `user_authorization`.

Guardian assessments are emitted as self-contained, transcript-visible hook
messages containing the exact tool input, classifications, outcome, and
rationales. Later assessments retain hook messages as bounded text without
parsing a private record format. A previous guardian decision is model evidence
rather than a user statement and can never independently establish `high`
authorization.

## Default Outcome Policy

When `outcome_policy` is not configured, the guardian uses:

- `prohibited` authorization: deny regardless of risk.
- `none` authorization: deny.
- `low` risk: authorization must be at least `low`.
- `medium` risk: authorization must be at least `medium`, and the guardian must
  still find the action bounded and proportionate.
- `high` risk: authorization must be `high`, but that is only a necessary
  condition; the guardian may still deny.
- `critical` risk: deny. The decision rationale tells the agent not to perform
  the action and that the user should carry it out manually if still desired.

Application code validates and relays the assessment. It does not compare risk
and authorization levels to override the guardian.

## Configuration

The hook reads `~/.codex-ai-approver.json`. Missing fields use these defaults:

```json
{
  "model": "gpt-5.6-sol",
  "reasoning_effort": "medium",
  "daemon_port": 47678,
  "batch_wait_seconds": 0.1
}
```

`outcome_policy` is an optional non-empty Markdown prompt. When omitted, the
default policy above is inserted into the trusted guardian policy template.

Example:

```json
{
  "model": "gpt-5.6-sol",
  "reasoning_effort": "high",
  "daemon_port": 47678,
  "batch_wait_seconds": 0.1,
  "outcome_policy": "- Low risk may be allowed.\n- Medium or higher risk must be denied."
}
```

Override the config path in the environment where Codex launches hooks:

```bash
CODEX_AI_APPROVER_CONFIG=/path/to/config.json
```

Changing effective config causes the hook to replace a daemon that was started
with a different config fingerprint.

## Context and Concurrent Requests

The daemon keeps one guardian thread for each `(session_id, agent_id)` pair.
Each assessment turn contains:

```text
[guardian policy]
[complete deterministic transcript for the current context window]
[one or more planned actions]
```

Before the next assessment, the daemon rolls back the previous temporary
assessment turn. The next transcript therefore replaces rather than appends to
the guardian's semantic context, while its unchanged token prefix remains
eligible for prompt-cache reuse.

The daemon waits `batch_wait_seconds` before starting an assessment. Permission
requests arriving concurrently for the same session, agent, and context window
are combined into one guardian request and receive independent assessments.

After every guardian turn, the daemon appends a structured
`guardian_turn_token_usage` JSON record to `~/codex-ai-approver.log`. The record
includes the source turn IDs, batch size, guardian thread and turn IDs, model,
reasoning effort, request duration, and the SDK-reported input, cached input,
output, reasoning output, and total token usage for the response. Each item in
`requests` records the request ID, source turn, working directory, tool, an
extracted `command`/`cmd` value when present, the exact tool input, and the
guardian outcome, risk, authorization, decision rationale, and classification
rationale. A response-schema failure is logged with `assessment_status =
"error"` and an `assessment_error` before the hook fails closed. `token_usage`
is `null` if the installed SDK does not report usage for that turn.

The log file is set to mode `0600` because exact tool inputs and commands may
contain sensitive values.

Stop the daemon manually with:

```bash
python3 hooks/permission_request.py --daemon-stop
```

## Failure Behavior

The hook fails closed. Setup, authentication, config, transcript parsing, daemon
startup, timeout, or schema failures return `deny` and are identified as
guardian runtime failures rather than safety assessments.

## Development

Run tests with:

```bash
python -m unittest tests/test_guardian.py
```
