---
type: Architecture Guide
title: Branch protection, read and write
description: The verifier and its write-side counterpart, why some gaps fail the control and others only report, and what harden refuses to do.
tags: [branch-protection, rulesets, harden, github, solo-maintainer]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Branch protection, read and write

One control id, two halves: a **read-only verifier** that reports what your forge
actually enforces, and `sscsb harden`, its **write-side counterpart** that can bring a
ruleset up to that standard. They are on one page because they share a definition of
"protected" and because reading one without the other gives a misleading picture.

## Reading

The verifier queries the **rules** API rather than the classic protection endpoint,
because that one covers classic protection *and* rulesets — so a repository using
either is answered correctly.

### Three ways to degrade before asking anything

No forge CLI; no repository slug from either configuration or the origin remote; or
**no configured protected branches at all**. The last is worth stating: having nothing
to verify is not the same as being protected, and a control that passed on an empty
list would be reporting on nothing.

### The counter that prevents fiction

The verifier tracks **how many branches the API actually answered for**. A branch that
could not be queried proves nothing about its protection.

If **none** were answered, the control reports that **nothing was verified** — it does
not report on the rules it failed to read. That distinction is the whole difference
between "your branch is unprotected" and "I could not find out", and they are not
interchangeable.

### Rules, and the two tiers of parameter

Four rule types are required, and their absence fails the control: pull requests,
non-fast-forward, signed commits, and required status checks. A deletion rule is
reported when present but is **not** treated as a gap.

Beyond rule existence, the granular parameters split into two tiers, and this is the
most opinionated decision on the page:

- **Solo-safe settings fail the control.** Dismissing stale reviews on push, and
  requiring branches to be up to date, are safe for a single maintainer — the first is
  a no-op when no approvals are required — so a gap there is a real finding.
- **Second-reviewer settings are reported but never fail it.** Requiring an approval,
  code-owner review, or last-push approval would **lock a solo owner out of merging
  their own work**. sscsb reports them, and never silently fails on them.

That is a deliberate stance rather than a limitation: a security tool that makes a solo
maintainer unable to merge gets disabled, and a disabled tool protects nothing.

## Writing

`sscsb harden` is the counterpart, and its safety model is worth reading before you
run it.

**Dry-run by default.** Nothing is written unless you pass an apply flag. Reads still
happen in both modes, so the plan you see is computed from your real ruleset.

**It will not create a ruleset.** A branch with none is skipped with a message. The
tool tightens what exists; it does not decide your protection model for you.

**It will not silently no-op.** A rule that is *absent* has its fields recorded as
**skipped**, never as changes — so a write that would have done nothing can never read
as success.

**It will not clobber the rest of your ruleset.** Applying preserves every other rule
and field, and creates a parameters object when a rule is present but bare, so that
setting it is a real change rather than a quiet failure.

**It will not double-apply.** A single ruleset matching several of your configured
branches is planned and written **at most once**.

**It will not enable the second-reviewer settings unless you ask.** They are off unless
you pass the flag, for the lockout reason above.

And the warning about that lockout is shown in **both** modes — because requiring a
second reviewer is precisely the mode that can lock a solo owner out, and seeing the
warning only after applying it would be too late.

## The two halves agree

The verifier's remediation messages name the exact `harden` invocation that fixes each
gap, including which flag the second-reviewer tier needs. The
[Scorecard mapping](scorecard.md) routes the same finding to the same control with the
same split. Three places state this tiering and they agree.

## Source map

| Concern | Location |
|---|---|
| The verifier | `src/audit.rs`, `verify_branch_protection` |
| Rule matrix and granular tiers | `src/audit.rs` |
| Plan computation | `src/harden.rs`, `plan_branch_protection` |
| Applying | `src/harden.rs`, `apply_to_ruleset`, `put_ruleset` |
| Plan rendering and warnings | `src/harden.rs`, `render_plan` |
| Command surface | `src/cli.rs`, `cmd_harden` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib harden::
```

The network calls are deliberately thin and excluded from coverage; the planning,
merging and rendering functions above them are unit-tested.
