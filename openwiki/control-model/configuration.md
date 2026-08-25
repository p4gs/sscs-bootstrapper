---
type: Architecture Guide
title: Configuration and the off-means-off contract
description: How .sscsb/config.toml is generated and read, what happens to absent, wrong-typed and unknown keys, and the limits of disabling a control.
tags: [configuration, controls, toml, defaults]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Configuration and the off-means-off contract

`sscsb` reads one file: `.sscsb/config.toml`. This page covers where it comes from,
how a control reads it, what happens when it is wrong, and — the part with real
edges — exactly how much "off" turns off.

## The file is generated, not maintained

`default_config_toml` builds the whole file from the control registry: a `[general]`
table, then one `[controls.<id>]` section per registered control containing
`enabled` plus that control's declared options, verbatim.

That matters more than it sounds. Because the file is derived from `CONTROLS`,
its keys cannot drift from the controls they configure, and the type of every option
is taken from the same registry literal that generates it — no option's type is
declared twice. It is why `max_key_age_days` is checked as an integer and
`allowed_backends` as an array of strings without a second declaration anywhere.

`[general]` holds three settings: `protected_branches` (defaults to `main` and
`master`, matched by exact string equality with no glob support), `fail_open`
(defaults to `false`, described in source as a deliberate, visible weakening), and
`github_repo`.

## How a control reads its own switch

Through exactly one helper, `Config::control_enabled_or_default`, which falls back
to **the registry's declared default** rather than to a literal.

This is enforced rather than encouraged. A source-scanning test forbids any call
site outside `config.rs` from writing `control_enabled(...)` followed by
`.unwrap_or(true)` or `.unwrap_or(false)`. A fallback derived from the registry —
`unwrap_or(def.default_enabled)` — is explicitly permitted.

The rule exists because of a real defect: the registry declared the SAST control on
by default while the pre-commit hook read it with a hard-coded `false` fallback. A
config with no explicit `[controls.sast] enabled` line therefore reported the control
**ON** in `status` and `verify` while the commit gate skipped every commit. The
literal and the registry disagreed, and the user believed the half that was lying.

A companion test goes further: where a call site does write a literal fallback for an
*option* (not the enabled flag), that literal must equal the registry's declared
default. And a third requires every key written into the generated config to be
reachable through a `control_opt_*` accessor in production code, on the stated
grounds that an inert key is worse than a missing one — it answers "is this on?"
with a value that means nothing. Five genuinely dead keys were deleted because of it.

## Absent, wrong-typed, and unknown

These are three different things and sscsb treats them differently on purpose.

**Absent is always legal.** `init` never overwrites an existing config, so every
config written by an older version is missing whatever has been added since. A
missing key resolves to the registry default. This repository's own config
demonstrates it: eight of the 44 controls have no section at all and run at their
declared defaults, and the file loads without a single complaint.

**Wrong-typed is a hard error.** A known key holding the wrong TOML type aborts the
command with exit 2, naming the file, the count of invalid values, and every message
— all of them at once rather than one per run. The error quotes the offending value
back at you, so `found string ("false")` is distinguishable from
`found boolean (false)`. That specific example is the defect the check was written
for: `enabled = "false"` is a string, reading it as a boolean yielded nothing, the
caller fell back to the registry default of `true`, and a user who thought they had
switched secret scanning off was still running it.

An array-typed option containing a non-string element is an error for the same
reason: the accessors filter non-strings out, so `["a", 1]` would silently become a
one-element list.

**Unknown is a warning, and the command proceeds.** An unrecognised top-level
section, an unrecognised `[general]` key, a `[controls.<id>]` whose id is not in the
registry, or a key inside a known control that is not one of its declared options —
each produces a warning on **stderr** and the config still loads. So a misspelled
control name configures nothing, says so, and the command can still exit 0.

That is a deliberate trade: an unknown control id is as likely to be forward
compatibility with a newer sscsb as it is a typo. But it means **anything capturing
only stdout never sees the warning**, and the warning is printed inside config
loading, so it appears on every command and every hook invocation.

## What "off" actually turns off

Disabling a control does three things:

- `verify` returns `disabled` and stops **before gathering any evidence** — no tool
  spawned, no file read.
- `init` skips that control's artifacts, logging `skip … (control … disabled)`.
- The hooks check the flag before running their arm, and `scan --grype` refuses and
  tells you to enable the control first.

And two things it does **not** do, both worth knowing before you rely on it:

**Disabling never removes artifacts already on disk.** `install_all` only writes;
there is no delete path. A disabled `codeql` control leaves `.github/workflows/codeql.yml`
exactly where it was, and GitHub keeps running it. Turning the control off changes
what sscsb verifies and installs, not what your forge does. Removing the workflow is
a separate, manual act. See [repository state](repository-state.md).

**With no config at all, the hooks allow everything.** All three git hooks return
success immediately when `.sscsb/config.toml` is absent — the pre-commit hook prints
`no config — run \`sscsb init\` (allowing commit)`. So an unconfigured repository is
fail-open at the hook layer, which sits oddly beside `fail_open` defaulting to
`false` *within* a configured run. The two are different questions: `fail_open`
governs what happens when a scanner cannot run, not what happens when sscsb has not
been set up.

## Writing the config

`set_control_enabled` is the only writer, and it is careful in three ways: it
rejects an unregistered control id **before touching the file**, listing every valid
id; it edits through `toml_edit` so comments and layout survive; and it writes only
the `enabled` key.

That last point has a consequence users hit. Enabling a default-off control on an
existing repository does **not** backfill that control's options, so there may be no
option key in the file to edit. This is why, for instance, the endpoint-exposure
control's guidance prints its whole TOML block rather than naming a key that is not
there.

## Source map

| Concern | Location |
|---|---|
| Generation from the registry | `src/config.rs`, `default_config_toml` |
| Enabled resolution | `src/config.rs`, `control_enabled_or_default` |
| Validation and warnings | `src/config.rs`, `inspect` |
| The only writer | `src/config.rs`, `set_control_enabled` |
| Anti-drift source scans | `src/controls.rs` tests |
| Disabled short-circuit | `src/controls.rs`, `verify_control` |
| Artifact skipping | `src/workflows.rs`, `install_all` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib config::
```

The tests worth reading first are the one asserting a wrong-typed `enabled` is an
error rather than a silent fallback, the one asserting unknown sections and keys warn
but still load, and the one asserting this repository's own config produces neither
an error nor a warning.
