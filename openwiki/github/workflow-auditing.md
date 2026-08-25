---
type: Architecture Guide
title: Workflow auditing
description: How sscsb audits GitHub Actions workflows for pinning and least privilege, and the calibration behind each threshold.
tags: [actions, workflows, pinning, permissions, audit]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Workflow auditing

Two controls share one code path: a basic audit that always runs, and an extended one
that adds six further checks. Together they answer "can something get into this
repository's CI, and how much could it do once there?"

The same auditor runs against sscsb's **own shipped templates** in its test suite, so
the tool that audits you is the tool that generated your workflows.

## Two things it refuses to assume

**Every YAML document in a file is audited.** A document separator used to end the
audit: only the first document was examined, so any jobs, actions or permissions
below the separator were reported clean **without being looked at**. Whether the forge
itself runs a second document is beside the point — sscsb must not call a file clean on
the strength of the half it read.

**Local composite actions are audited too.** A local action can pull in an unpinned
third-party action, and the workflow-level audit never looked inside it.

An unparseable workflow or action becomes an **error finding** rather than aborting the
run, so one broken file cannot hide the state of the others.

## Pinning

Every third-party action must be pinned to a full commit digest. Local and container
references are handled separately.

There is exactly **one exemption**, for the trusted SLSA builder, which must stay
tag-pinned because its verifier derives the builder identity from the reference. Two
details make that exemption safe:

- **It ends at the repository boundary**, rather than being a prefix test. A prefix
  would also match a *different* repository under the same owner, which would inherit a
  licence written for exactly one builder.
- **It is surfaced as informational, not as silence.** The deliberate exception is
  visible in the output rather than invisible, which is the difference between a
  documented exception and a hole.

## Least privilege, calibrated

Permissions are checked in four shapes rather than by matching one string.

**Full write access spelled out.** Enumerating write on five or more of the token's
scopes is treated as the same thing as asking for everything. The threshold is
**calibrated above the most privileged workflow sscsb itself ships** — which needs
four — rather than at the edge of one. A threshold low enough to catch a single write
scope would flag every release workflow in existence, which is noise rather than least
privilege.

**Workflow control plus publishing.** Holding the scope that reaches *other* workflow
runs alongside any publishing scope is flagged, because one compromised step can then
**poison the build and ship the result**. Neither half can do that alone. This is the
shape behind several real cache-poisoning compromises.

**Placement.** A top-level write grant is reported differently depending on whether
current jobs override it: a **live** grant names the jobs inheriting it, while a
**latent** one is informational — currently overridden by every job, but still the
default for the next job someone adds. A tool that conflates those two is the reason
people stop reading its output.

**Absence.** No permissions block anywhere, with at least one job not setting its own,
is an error.

## Behaviour, not publisher

Checkout detection asks what an action *does*, not who publishes it. Matching one
publisher's literal string asked the question of one publisher and **silently exempted
all the others** — anyone could ship an equivalent action under a different name and
escape the check.

The match strips conventional decoration from the action name and requires the stem to
*be* checkout. An action whose name merely contains the word is not one.

## What changes the verdict

**Only error-severity findings.** Warnings and informational findings are printed
under a passing verdict, which is what keeps the exemption above readable and the
placement distinction useful.

## Source map

| Concern | Location |
|---|---|
| Audit entry points | `src/audit.rs`, `audit_workflow`, `audit_repo` |
| Pinning | `src/audit.rs`, `check_uses_ref` |
| The tag-pin exemption | `src/audit.rs`, `is_tag_pin_exception` |
| Permissions | `src/audit.rs`, `audit_permissions`, `audit_top_level_write_reach` |
| Checkout detection | `src/audit.rs`, `is_checkout_action` |
| Local actions | `src/audit.rs`, `audit_local_actions` |
| The controls | `src/audit.rs`, `verify_actions_control` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib audit::
```

One test asserts every shipped template passes this audit with nothing above
informational — so a template that would fail your repository fails the build first.
