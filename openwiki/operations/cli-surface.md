---
type: Reference
title: The command surface
description: How the commands are grouped, which ones need a repository or a config, and what keeps the agent-facing contract honest.
tags: [cli, commands, exit-codes, agents]
sources:
  - id: openwiki-source-c38906bbfa9e9c69417b11b5
    resource: repo://src/cli.rs
  - id: openwiki-source-2a737474d86fc75cc9d9694f
    resource: repo://src/config.rs
  - id: openwiki-source-3d3d1fb96f9025804ec5bdb3
    resource: repo://src/context.rs
  - id: openwiki-source-9616e50e881946cd4b6ba8dd
    resource: repo://src/hooks.rs
  - id: openwiki-source-b3e43d1879144ee611465d1e
    resource: repo://tests/agents_md.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# The command surface

## How it is grouped

- **Bootstrap and inspection** — `init`, `status`, `report`, `tools`, and
  `enable`/`disable` for individual controls.
- **Verification** — `verify`, optionally narrowed to named controls and optionally
  `--strict`.
- **Remediation** — `harden`, which is dry-run unless you apply.
- **Hook entry points** — `hook pre-commit`, `hook commit-msg`, `hook pre-push`.
- **Per-subsystem groups** — `deps`, `receipt`, `provenance`, `signers`, `signing`,
  `sbom`, `scan`, `sast`, `vex`, plus the optional-service commands.

The hook subcommands exist so the installed shell shims can **delegate all policy to
the binary** rather than implementing any of it themselves. That is why the shims are
three lines and why policy is testable — see
[git hooks](../commit-integrity/git-hooks.md).

## What each command needs

**Two commands never discover a repository at all** — the tool inventory and the
agent-key guidance — so they work anywhere.

**`status` and `report` work without a config**, resolving each control's state from
the registry default. That is deliberate: they are the two commands you run to find
out what a repository looks like before deciding to configure it.

**`verify`, `harden`, `sbom`, `scan` and `sast` require a config** and exit with a
**usage error** without one, telling you to run `init` first.

Read the exit code carefully: `2` means sscsb could not run, `1` means a gate failed.
The full contract is in
[the verdict contract](../control-model/registry-and-outcomes.md#verdicts-become-exit-codes).

## Invalid input is rejected, not absorbed

**Enabling or disabling an unregistered control is rejected before the config file is
touched**, with every valid id listed. Failing before the write is the right order —
a rejected command should leave nothing behind.

## The agent-facing contract is test-pinned

sscsb ships a machine-facing document so an agent can drive it without reading source,
and that document is **pinned to the binary by tests**:

- every documented subcommand exists;
- no subcommand is invented;
- the exit-code table matches reality;
- the verdict table uses the binary's own symbols, including the one rendered in
  lowercase;
- every documented invocation **actually parses**.

That last one has teeth. An early version of the invocation guard read its list of
shapes from a hard-coded array gated on the document containing them — which is
vacuous. It now reads the shapes **out of the document** and parses each.

**The shipped agent skill is not pinned by those tests.** Only the document is
guarded. If you rely on the skill, treat it as prose that can drift.

## Source map

| Concern | Location |
|---|---|
| Command definitions | `src/cli.rs` |
| Dispatch and exit codes | `src/cli.rs`, `src/main.rs` |
| Config requirement | `src/context.rs`, `require_config` |
| Doc guards | `tests/agents_md.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test agents_md
```
