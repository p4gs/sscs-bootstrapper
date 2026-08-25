---
type: Architecture Guide
title: AI provenance trailers and the commit gates
description: What an AI-assisted commit must declare, the review gates that follow from it, and what a pre-push hook can honestly prove.
tags: [ai-provenance, trailers, commit-msg, review, dependencies]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# AI provenance trailers and the commit gates

When AI writes code, the question that matters later is not "was AI involved" but
"who checked it". These gates make the first question answerable and force the second
to be answered before the work lands.

They run in the `commit-msg` hook, and in the pre-push gate for merges. The engine
underneath is [git hooks](git-hooks.md).

## Declaring is voluntary; declaring badly is not

**With no `AI-Assisted` trailer, there are no requirements at all.** The gate polices
only what you declare. That is a deliberate stance: sscsb cannot detect AI
involvement, so it does not pretend to, and a tool that guessed would be both wrong
and easy to route around.

Declare `AI-Assisted: true` and three things become mandatory: a **tool**, a
**model**, and a **role** drawn from a fixed set — draft, review, test, refactor.
Anything other than `true` or `false` in that field is a problem, not a default.

Trailer parsing is looser than git's own rules: it scans **every line** of the
message rather than a trailing block, and on a repeated key the last occurrence wins.
Practically, that means the declaration counts wherever it appears in the body, and a
prose line like `Note: see the RFC` becomes a trailer named `Note`.

## The review gates that follow

Declaring AI assistance triggers two conditional requirements:

- **Touching a dependency manifest** requires an explicit dependency-review trailer.
- **Touching a shell script** requires a command-review trailer.

Both are the same idea: the two file classes where AI-generated content has the
sharpest blast radius are the ones a human has to sign off on by name.

> This gate had a real bypass, now fixed: it enumerated staged files without
> NUL-delimiting, so a manifest under a directory with a non-ASCII character was
> C-quoted by git, stopped looking like a manifest, and walked through. The hardened
> enumeration lived in the same file the whole time. See
> [git hooks](git-hooks.md#scanning-what-is-actually-being-committed).

## Package trust runs regardless

Beside the AI gates, and easy to conflate with them, is the package-trust arm. **It
runs on every commit whether or not AI assistance is declared**, blocking any new
unapproved dependency.

Two behaviours are worth knowing:

**Typosquat annotations are suppressed in two cases, and suppression never lets a
package through.** The annotation is dropped when the dependency's source is not
resolved by name against a public registry — a path or git dependency one edit from a
popular name fetches nothing from that registry, so the warning would be noise — and
separately when the check is switched off. In both cases the underlying block still
happens. The annotation is commentary on a decision already made.

**An unreadable baseline blocks the commit** unless fail-open is set. The reasoning
is precise: deleting the baseline already fails closed, so corrupting it must too, or
that asymmetry *is* the bypass.

See [manifests and package trust](../dependencies/manifests-and-package-trust.md).

## Review evidence on merges

The last gate is the most carefully reasoned, and the source is unusually honest
about its own limits.

It fires on a **merge commit to a protected branch** where AI involvement is declared
— either in the merge message, or anywhere in the merged range. The range scan
**fails closed**: a range it cannot read is treated as AI-involved, because a gate
that cannot see must not assume innocence.

Then the honesty: **a pre-push hook reads a commit message. It cannot prove a review
happened.** The forge's required-review rule is what does that. What this gate can do
deterministically is refuse a *vacuous* attestation, and it refuses four:

1. No named reviewer — an evidence URL alone names nobody.
2. A reviewer whose identity cannot be extracted.
3. A reviewer absent from policy, or present but not classified `human`. An agent
   cannot vouch for its own review.
4. A reviewer who authored commits in the merged range. Self-review.

### The subtlety in check 4

Git's `A..B` range always includes `B`. Without excluding the merge commit itself
from the authors of the merged range, the human performing the merge counts as an
author of the work being reviewed — and **every legitimate agent-authors,
human-merges push would be refused as self-review.** That exclusion was found by
adversarial review with a working reproduction before it shipped.

The intended flow — an agent writes the branch, a human reviews and merges — passes,
because the merged-range authors are the agent, not the human.

### One asymmetry, deliberately

Signature-principal matching is **exact**; reviewer matching is
**case-insensitive**. Both sides of the first comparison were generated by sscsb from
the same file. The second compares a **human-typed trailer** against policy. Different
provenance, different strictness.

## The pull-request template

The `pr-template` control installs a template asking whether AI generated the code,
the tests, the dependencies or the documentation — the pull-request-level counterpart
to these commit trailers.

Its verifier checks **content, not just presence**: a template that exists but has
lost the AI-provenance questions fails. Installing the file is not the point; asking
the questions is.

## Source map

| Concern | Location |
|---|---|
| Trailer parsing | `src/hooks.rs`, `parse_trailers` |
| Trailer validation | `src/hooks.rs`, `validate_ai_trailers` |
| Dependency and shell gates | `src/hooks.rs`, `hook_commit_msg` |
| Package-trust arm | `src/hooks.rs`, typosquat annotation and baseline handling |
| Review evidence | `src/hooks.rs`, `review_evidence_problems` |
| Merged-range authors | `src/hooks.rs`, `range_author_emails` |
| PR template control | `src/workflows.rs`, `verify_pr_template` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test integration commit_msg_gates
```
