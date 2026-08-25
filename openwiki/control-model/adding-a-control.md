---
type: How-To Guide
title: Adding a control
description: The files a new control must touch, the tests that enforce each requirement, and the gaps the contract does not cover.
tags: [controls, extension, testing, contribution]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Adding a control

The most useful thing to know before you start: **no prose document describes this
contract.** It exists only as tests. Nothing in `README.md`, `AGENTS.md`, `docs/`
or a contributing guide explains how to add a control, so every requirement below is
read off the test suite, and every claim here cites the test that enforces it.

That is worth stating rather than papering over, because it tells you where the real
specification lives: if you want to know whether something is required, the answer is
whether a test fails without it.

## The files

| # | File | What changes | Enforced by |
|---|---|---|---|
| 1 | `src/controls.rs` | A `ControlDef` in `CONTROLS` | ids unique, phase in `1..=5`, summary non-empty |
| 2 | `src/controls.rs` | A dispatch arm in `verify_control` | three tests, two crates |
| 3 | `templates/compliance/map.json` | An entry keyed by the id | phase agreement, no orphans |
| 4 | `src/tools.rs` | A `ToolSpec`, if the control names a tool | every referenced tool exists |
| 5 | `.github/actions/setup-sscsb-tools/action.yml` | A pin, if the tool is new | pin parity with `tools.rs` |
| 6 | A phase module | The verifier itself | verdict names the control, always says something |
| 7 | `src/workflows.rs` | An `Artifact`, if the control ships files | every artifact's control is registered |
| 8 | `templates/…` | The template file | six template tests, below |

**Nothing needs to be added to `src/config.rs`.** The config file is generated from
the registry, and a test asserts the new section and each of its declared options
appear with the registry's values. See [configuration](configuration.md).

## What the tests would catch

Read this as the real specification.

- **Duplicate or malformed id, phase out of range, empty summary.** The registry
  test.
- **Forgot the dispatch arm.** Three separate tests, across two crates, all assert
  no registered control ever reaches the `no verifier wired for … — this is a bug`
  fallback. The fallback exists and returns `Fail`; the tests exist so it is never
  reached in a shipped binary.
- **Forgot the compliance entry, or gave it a phase that disagrees with the
  registry.** The map test. A companion catches the reverse — a map entry for a
  control that no longer exists.
- **Named a tool with no `ToolSpec`.** The tool-registry test.
- **Added an option key nothing reads.** A source scan requires every generated
  config key to be reachable through a `control_opt_*` accessor. Five genuinely inert
  keys were deleted because of it.
- **Wrote a fallback literal that disagrees with the config the user was handed.**
  A second source scan compares call-site literals against the registry defaults.
- **Wrote `control_enabled("x").unwrap_or(false)`.** Banned outright outside
  `config.rs` — this is the defect that made a control read ON in `status` while its
  commit gate skipped every commit.
- **Verifier ignores its own toggle.** A test disables every control in turn and
  requires `disabled` with exactly the one canonical message.

## If your control ships a workflow

Six more tests fire, and they are the ones most likely to surprise you.

1. **The template must pass sscsb's own extended actions audit** with no non-`Info`
   findings. An unpinned action reference or a missing `permissions:` block fails
   the build. The tool audits what it ships, which is the only honest posture for a
   tool that audits other people's workflows.
2. **It must embed the pinned Harden-Runner SHA**, exactly. This catches both a new
   workflow that forgets egress monitoring and a Harden-Runner bump applied to some
   templates but not all.
3. **Rendering must leave no placeholders** — a typo'd `{{…}}` would ship literally
   into a user's repository.
4. **No absolute user home paths.** Catches an author's local path pasted into a
   shipped file.
5. **The template must satisfy the same shape check its own verifier applies.**
   This is the subtle one: it prevents writing a check strict enough to fail every
   real repository the moment `init` writes the file.
6. **Every default-on template control must `Pass` on a freshly bootstrapped
   repository.** A false `FAIL` here lands on every user.

A control routed to the template verifier with no artifacts registered hits a
`Fail` arm that says so.

## Gaps in the contract

These are real, and knowing them is part of using the contract well.

**Documenting a new control is not required.** The guard on `AGENTS.md` control ids
is one-directional: it fails on a *cited* id that does not exist, never on an
existing control that is undocumented. The subcommand guards check **both**
directions. So a new control can ship entirely undocumented and the build stays
green.

**Registry ordering is unconstrained**, and it is load-bearing for the generated
config's phase banners. See [phases](phases.md).

**Default on/off is only spot-checked** against a hand-written list of ids; a new
control's default is otherwise unconstrained.

**Your control will not appear in existing repositories' configs.** `init` keeps an
existing `.sscsb/config.toml`, so an already-bootstrapped repository silently gains
the control at its registry default with no line in the file. This repository
demonstrates it: eight of the 44 controls have no section at all.

## Before you open the pull request

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo llvm-cov --ignore-filename-regex '(main\.rs|cli\.rs)' \
  --fail-under-lines 95 --fail-under-functions 94
```

The `GIT_CONFIG_*` isolation is **mandatory and not enforced by the harness**.
Without it the host's git identity leaks into the fixtures and you get mass failures
that look like regressions and are not. See
[building and testing](../development/building-and-testing.md), which also covers the
coverage gate's rationale.
