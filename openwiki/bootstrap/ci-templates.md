---
type: Architecture Guide
title: CI templates
description: How shipped workflow templates are registered, rendered and installed, and the six invariants that keep sscsb from shipping a workflow it would fail you for.
tags: [templates, workflows, artifacts, self-audit, rendering]
sources:
  - id: openwiki-source-fa874b115e6a9b7eedb58401
    resource: repo://src/workflows.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# CI templates

Most controls deliver their value as a **file**: a workflow, a config, a policy, a
worksheet. This is the machinery that registers, renders and installs them — and the
tests that stop sscsb shipping something it would flag in your repository.

## The registry

Every template is **embedded into the binary at compile time**. There is no runtime
template lookup, no template directory to lose, and no way for a shipped template to
be missing.

Each artifact names the control that owns it, and **that lookup is the assertion**:
an artifact pointing at a control id that does not exist fails the build rather than
panicking in a user's repository.

## Installation

Three outcomes per artifact, each logged:

- **skip** — the owning control is disabled;
- **keep** — the file already exists (and the log says to delete it to regenerate);
- **write** — it did not exist.

**Installation never overwrites.** That is the same promise
[initialization](initialization.md) makes, and the reason a template upgrade is a
manual act.

## Rendering happens once

Templates substitute the repository slug, the default branch and the project name at
**write time**.

Two consequences worth carrying:

- The slug falls back to a **literal placeholder** when neither configuration nor an
  origin remote supplies one, and that placeholder is then baked into the installed
  file permanently.
- The default branch has its own silent fallback — see
  [repository context](../runtime/repository-context.md).

Because installation never re-renders a kept file, both are permanent for that
repository unless you delete and re-run.

## The six invariants

These are the tests that make "the tool that audits you is the tool that generated
your workflows" true rather than aspirational.

**Every shipped workflow passes sscsb's own extended audit** with nothing above
informational. An unpinned action or a missing permissions block in a template fails
the build. See [workflow auditing](../github/workflow-auditing.md).

**Every shipped workflow embeds the pinned runner-hardening step by exact digest.**
This catches two different mistakes at once: a new workflow that forgets it, and a
version bump applied to some templates but not all.

**No rendered artifact retains an unsubstituted placeholder.** A typo'd placeholder in
a branch filter would ship a workflow that silently never triggers.

**No template contains an absolute user home path** — the same rule the shipped
ruleset applies to user code, applied to sscsb's own files.

**Every template satisfies the same shape check its own verifier applies.** This is
the subtle one: it prevents writing a check strict enough to fail every real
repository the moment the file is installed.

**Every enabled template control passes on a freshly bootstrapped repository**, with a
floor on how many were checked so the test cannot quietly go vacuous. A false failure
here would land on every user.

## What a template control can assert

Shape only, and the shape is chosen from the destination path. The full contract lives
in [CI hardening](../github/ci-hardening.md#the-shape-machinery), because that page
also owns the control that short-circuits past it.

The short version: a workflow must parse, declare a job, and have no job that runs
nothing; other formats get progressively weaker structural claims; and prose files get
the honest "present and non-empty, and that is all I am asserting".

## Source map

| Concern | Location |
|---|---|
| Artifact registry | `src/workflows.rs`, `ARTIFACTS` |
| Installation | `src/workflows.rs`, `install_all` |
| Rendering | `src/workflows.rs`, `render` |
| The six invariants | `src/workflows.rs` tests |
| Templates | `templates/` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib workflows::
```
