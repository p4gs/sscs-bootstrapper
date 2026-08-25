---
type: Architecture Guide
title: Process execution and the tool exit-code contract
description: How sscsb invokes external tools, why a killed scanner must not read as a clean one, and the argument-injection guard on git.
tags: [exec, exit-codes, git, security, orchestration]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Process execution and the tool exit-code contract

`sscsb` does not scan anything itself. It orchestrates other people's tools, reads
what they return, and turns that into a verdict. This module is the whole boundary,
and it is the canonical home for two contracts that several other pages depend on:

- **what a tool's exit status means** — because every tool means something different
  by it;
- **why an argument array is not enough** to make a `git` invocation safe.

Pages for the individual scanners cross-reference this one rather than restating it.

## One door, argument arrays only

Every invocation goes through this module, using **argument arrays and never shell
interpolation**, so detection, degrade messaging and argument construction stay
auditable in one place.

Two `git` wrappers exist for different jobs: one **bails on a non-zero exit**, and one
returns the full output without bailing, for callers legitimately probing whether a
reference exists.

## A killed scanner is not a clean one

This is the invariant with the sharpest failure mode.

A killed process **has no exit code at all**. Representing that as a numeric sentinel
and then comparing numerically ranks *"we do not know how this ended"* **below every
real failure code** — and that is exactly how a killed scanner reads as a clean one.

So `success` is defined as *the exit code is exactly zero*, not as a numeric
comparison. It is signal-aware by construction.

Worse than the ranking, and the reason this is not theoretical: **a signal-killed
scanner still has its pre-death stdout captured.** A scanner that printed an empty
result set and was then killed by an out-of-memory kill or a timeout has produced
output that parses perfectly. Without the check, it reports a clean scan.

## The exit-code table

There is no single convention here, which is the point.

| Tool class | Contract |
|---|---|
| **SAST engine (default)** | Exits **0 even with findings**. Must be parsed, not gated on. |
| **SAST engine (alternate)** | 0 clean, 1 findings — **and anything else, including no exit code, is a failed scan.** |
| **Secret scanner A** | A sentinel code means "results found"; anything else is an error. |
| **Secret scanner B** | sscsb **chooses** the findings code and passes it to the tool. |
| **Vulnerability scanner A** | Exits **0 on findings**; gating happens on parsed JSON. |
| **Vulnerability scanner B** | 0 clean, 1 findings, a third code meaning **no packages found to scan** — a note, not a failure. |
| **SBOM matcher** | Exit code deliberately ignored; it exits non-zero on its own severity threshold. |
| **Endpoint scanner** | **Findings do not change the exit code**; a distinct code means scan error. |

Three of these exit zero regardless of what they found. Those are precisely the ones
where a `$?` gate would be a silent pass-through — a control that passes through every
compromise it detects.

**When matching on the raw status is safe:** wherever zero is the only clean arm and a
catch-all bails, because a killed child's sentinel falls into the catch-all. The one
place that needed the explicit exit-code accessor is the engine where **two different
codes are both clean** — there, a numeric comparison put "killed" below both of them.

## When stdout is content, not a message

The ordinary output type decodes stdout **lossily**: every invalid UTF-8 sequence
becomes a replacement character. For a tool's diagnostics that is harmless.

For a file's **content** it is destructive and silent — the bytes change, the length
changes, and nothing reports it. So a raw-bytes variant exists, and the one production
consumer is [staged-file materialisation](../commit-integrity/git-hooks.md): routing a
staged image or archive through the lossy path would mean the scanners read different
bytes than the ones being committed.

## Argument arrays stop the shell, not git

The security section, and worth reading carefully.

Passing arguments as an array means no shell parses them. It does **not** mean `git`
will not read one as an **option**. `git show`, `git log` and `git rev-list` all
inherit git's diff options, so a value that starts with a dash is an option.

Two primitives were reproduced against a real git:

- **An option that suppresses output.** The command exits 0 and prints nothing, so a
  caller comparing digests computes the hash of the empty string. Supply a receipt
  whose digest is that hash and it verifies — a **universal forgery**.
- **An option that redirects output to a file.** The diff is written to a path of the
  attacker's choosing, and stdout is empty, so the digest comparison *also* sees the
  empty string. Verification has become an arbitrary file write.

### Why `--` would have been worse than the bug

This is the part that matters, because `--` is the reflex fix.

`--` does stop git parsing the value as an option. But it does not mean "a revision
follows" — it means **"everything after this is a pathspec."** So the value stops
being read as a commit at all, the command exits **0 with empty output**, and the
caller hashes the empty string.

Before the fix, the forgery required a specific option-shaped value. With `--`,
**every** value would produce the hash of the empty string, so any receipt at all
would verify — at exit 0, with no error anywhere. It converts a targeted forgery into
an unconditional one.

`--end-of-options` is the correct primitive: it stops option parsing while keeping the
next argument a revision.

### Two defences, chosen by call shape

- **`--end-of-options`** where the revision is the **last** argument.
- **A shape guard** — a bare lowercase hex object name of plausible length — where
  trailing flags must follow the revision and `--end-of-options` would swallow them.

Values built with a fixed non-option prefix are **safe by construction** and need
neither.

### Guarded versus deliberately unguarded

A value read out of **a file someone else supplied** is guarded, because that file is
the thing under suspicion. A value typed on **the operator's own command line** is
deliberately not, because an option-shaped argument from someone who already has a
shell is self-inflicted — and legitimate callers pass real options there.

That asymmetry is a decision about trust boundaries, not an inconsistency.

## Source map

| Concern | Location |
|---|---|
| Invocation surfaces | `src/exec.rs` |
| Exit-code semantics | `src/exec.rs`, `CmdOutput`, `success`, `termination` |
| Raw-bytes path | `src/exec.rs`, `RawOutput` |
| Object-name guard | `src/exec.rs`, `is_object_name` |
| Per-tool exit codes | `src/hooks.rs`, `src/scan.rs`, `src/sast.rs`, `src/bumblebee.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib exec::
```

One test kills a child and asserts all four properties at once — no exit code, not
successful, a readable termination description, **and stdout still captured**.
