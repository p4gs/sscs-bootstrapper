---
type: Architecture Guide
title: Scorecard integration
description: Reading live Scorecard findings, routing each to the control that owns it, and why open findings are informational rather than failing.
tags: [scorecard, openssf, findings, remediation]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Scorecard integration

Most tools that integrate OpenSSF Scorecard install its workflow and call it done.
This control does something more useful: it **reads the live findings** the repository
publishes to code scanning and maps each one to the sscsb control that addresses it,
with an honest remediation status.

That turns the question from *"is the workflow installed?"* into *"what does Scorecard
actually see, and what can sscsb do about each thing it sees?"*

## The remediation taxonomy

Each mapped finding carries one of four classes, and the distinctions are the point:

- **sscsb-fixable** — there is a control, and running it closes the finding.
- **solo-capped** — the finding cannot be closed by a single maintainer without
  locking themselves out. See [branch protection](branch-protection.md).
- **justified exception** — sscsb's behaviour is deliberate and the residual finding is
  the cost. The dependency-pinning finding is here: sscsb pins **every** action except
  the one trusted builder that must stay tag-pinned by its own trust model.
- **owner action** — nothing sscsb can perform, such as registering for a badge.

A tool that reported all four as "failing" would be lying about three of them.

## Unmapped findings surface

A Scorecard rule sscsb does not recognise is reported as **unmapped**, not dropped.
That is the forward-compatibility seam: when upstream adds a check, it shows up in your
output as something to look at rather than vanishing into a mapping table that does not
know about it yet.

## The verdict rule

Five outcomes, and two of them exist because of specific defects.

**A missing workflow fails.** That is a real, checked finding — the file either exists
or it does not.

**Every way of failing to read the live findings degrades.** No forge CLI, no
repository slug, or an API that returned nothing. The reasoning: an installed workflow
proves only that a file exists, while whether Scorecard actually **scores** this
repository — and what it sees — is the substantive half of the control.

Before that fix, with the CLI absent the live half could not run at all and the whole
verdict collapsed to passing on the strength of a workflow file existing, while every
other CLI-dependent control in the same run correctly reported degraded.

**Open findings are informational, not passing.** This is the more interesting call.
sscsb deliberately does **not** re-gate on another scanner's rubric — each finding routes
to the sscsb control that owns it, and *that* control fails on its own evidence. But
reporting `PASS` while printing open findings manufactures assurance. Informational is
the honest verdict: context, not a gate.

**No open findings passes.**

### The corollary worth carrying

An informational verdict contributes nothing to the exit code, **even under
`--strict`**. That is the whole point of not double-counting another scanner's rubric,
but it means a strict CI gate will not catch a Scorecard regression on its own. The
routed control is what gates. See
[the verdict contract](../control-model/registry-and-outcomes.md).

## Source map

| Concern | Location |
|---|---|
| Finding-to-control map | `src/scorecard.rs`, `CHECK_MAP` |
| Remediation classes | `src/scorecard.rs`, `Remediable` |
| Formatting and unmapped handling | `src/scorecard.rs`, `format_finding` |
| The verdict | `src/scorecard.rs`, `verify_scorecard_control` |
| Live query | `src/scorecard.rs`, `fetch_findings` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib scorecard::
```

The cross-repository QA record shows both fixes as observed transitions rather than
claims: fourteen controls moved from passing to degraded once "could not check" stopped
reading as fine, and five moved from passing to informational.
