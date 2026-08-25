---
type: Architecture Guide
title: Bootstrapping a repository
description: What sscsb init does end to end, the three classes of file it manages, and why there is no upgrade path except deletion.
tags: [init, bootstrap, idempotence, gitignore]
sources:
  - id: openwiki-source-9616e50e881946cd4b6ba8dd
    resource: repo://src/hooks.rs
  - id: openwiki-source-95352b0faaf38cc22d6f51b3
    resource: repo://src/init.rs
  - id: openwiki-source-fa874b115e6a9b7eedb58401
    resource: repo://src/workflows.rs
  - id: openwiki-source-b3e43d1879144ee611465d1e
    resource: repo://tests/agents_md.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# Bootstrapping a repository

`sscsb init` is the entry point. It writes configuration, installs hooks, seeds
policy files, and lays down the artifacts of every enabled control.

It is safe to re-run, and the precise form of that promise is the useful part:
**not** "nothing is overwritten", but **"nothing you are meant to edit is
overwritten"**. See [repository state](../control-model/repository-state.md) for the
per-path contract; this page covers the run itself.

## The run, in order

1. **Discover the repository** through git. Outside one, this fails loudly.
2. **Write the config** if absent, generated from the control registry — or keep and
   log the existing one.
3. **Reload the context** so the rest of the run sees the config just written.
4. **Install the three hook shims** and point git's hooks path at them, plus record
   the allowed-signers path as an absolute path.
5. **Seed the policy files** if absent.
6. **Regenerate the allowed-signers file** from signer policy.
7. **Ensure generated output is git-ignored.**
8. **Install every enabled control's artifacts.**
9. **Print next steps** — add a signing identity, baseline dependencies, then verify
   and report.

## The three classes

**Kept if present** — config, the policy files, and every registered artifact. The
measurable form: a second run writes **strictly fewer** files than the first. Not
zero, because the next class exists, and the source says so rather than claiming
zero.

**Regenerated every run** — the three hook shims and the derived allowed-signers
file. Edits to those are discarded by design: the shims are generated delegation
stubs, and the signers file is a projection of policy.

**Extended, never rewritten** — the ignore file.

## The ignore step, in detail

This is the most carefully built part of the run, because it edits a file the user
owns.

**Git decides, not sscsb.** A `check-ignore` probe asks git whether the generated
output path is already ignored. Already ignored means do nothing; not ignored means
append; **anything else is a hard error** rather than a guess. So a rule spelled a
different way, or one living in a global excludes file, correctly counts.

**The probe uses a neutral placeholder name**, not a real artifact name. Probing a
specific filename would let a narrow pre-existing rule answer "covered" — and leave
receipts and VEX documents exposed.

**Appending never glues onto an unterminated final line.** Without that, a file saved
without a trailing newline would have its last rule silently absorbed into sscsb's
comment.

The motivating defect is worth keeping: the tool directory holds **both** policy that
belongs in history **and** generated output that does not. Nothing enforced that
boundary, so committing a regenerated SBOM buried real policy diffs in review noise.

One limit stated plainly: **adding an ignore rule cannot untrack anything.** A
repository that has already committed generated output keeps tracking it.

## Upgrading: there is no path but deletion

`sscsb init` **takes no flags**. No force, no dry-run. The only way to pick up a newer
template is to **delete the file and re-run**, and the run log tells you so per file.

The consequence is worth stating directly: **after upgrading the binary, every
already-installed artifact stays at its old version.** Nothing compares installed
files against newer templates, and nothing tells you a newer one exists. Only the four
always-regenerated files pick up binary changes automatically.

That is a deliberate trade — never clobbering an edited file — but it means template
upgrades are a manual, per-file decision.

## Source map

| Concern | Location |
|---|---|
| The run | `src/init.rs`, `bootstrap` |
| Ignore handling | `src/init.rs`, `ensure_out_ignored` |
| Hook installation | `src/hooks.rs`, `install_hooks` |
| Artifact installation | `src/workflows.rs`, `install_all` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test integration bootstrap
```
