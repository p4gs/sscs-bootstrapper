---
type: Architecture Guide
title: CI hardening controls
description: Runner hardening checked per job, the one control whose verdict is a constant, and the shape machinery every template control shares.
tags: [harden-runner, ci, templates, verification, shapes]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# CI hardening controls

Three controls that harden the CI environment itself rather than the code in it:
runner hardening, a hosted repository-hardening service, and just-in-time secret
approval.

This page also owns the **shape machinery** every template control shares, because it
is the substrate several other pages cross-reference.

## Runner hardening, per job

The verdict comes from a dedicated function that the generic template verifier
short-circuits to — **not** from the YAML helpers that live in the auditing module.
Worth knowing if you go looking for it.

Its predecessor searched each file's **raw text** for the action's name. Three
different repositories passed while unprotected:

**A commented-out reference matched.** Which is exactly what a developer leaves behind
when they remove the step.

**One hardened job vouched for every other job in the same file.** Hardening protects
the job whose step list it heads, not the file it happens to appear in. So the question
is only answerable **per job**, off the parsed document.

**An existing-but-empty workflow directory examined nothing and reported passing** —
with no messages at all.

A fourth was found later: a job carrying both a delegation key *and* its own steps was
skipped outright, so adding one line removed a job from the check entirely.

### What counts

**Presence is precise:** the job's **first** step must be the hardening action. Not any
step.

**A job that only delegates** to a reusable workflow is exempt, because no hardening
step can be added there — hardening is the callee's responsibility. The exemption is
not silent: the callee is named in the report.

### Fail versus degrade

This is the distinction most likely to be got wrong, so it is worth being exact.

An **unreadable**, **unparseable** or **job-less** workflow **fails** the control. Its
messages say "unverified, not confirmed" — but the outcome is failure, because those
share the same counter as a genuinely unhardened job.

**Degraded is reserved for the two nothing-to-look-at cases**: no workflow directory at
all, and a directory holding zero workflow files. The second reports that zero jobs
were examined, so coverage is unverified rather than confirmed — never passing.

### No egress-policy config key

There is deliberately no configuration key for the runner's egress mode. The only
value such a key would offer enforces against an allowlist **sscsb cannot synthesise**,
and a generated blocking policy without one breaks the first checkout step in every
workflow. Offering that from a generated config file would be a trap, so egress policy
stays a per-repository decision made in the workflow file.

The key once existed, read by nothing, and was removed rather than left advertising
configurability that does not exist.

## The control whose verdict is a constant

One of these three has a **hard-coded informational verdict**, written as a literal in
the dispatch table. It is the only control in the registry whose verdict reads no file,
no tool and no remote.

The reason is honest rather than lazy: the thing it names is a **hosted web service**,
not an action. sscsb cannot invoke it and does not pretend to. What it would have fixed,
sscsb already enforces locally; it is useful for repositories you adopt rather than
bootstrap.

One consequence to carry: an informational verdict contributes nothing to the exit
code, **even under `--strict`**. See
[the verdict contract](../control-model/registry-and-outcomes.md).

## The shape machinery

Every template control shares this, and it is the answer to "what can sscsb honestly
say about a file it installed?"

**It checks content, not existence.** Installation never overwrites, so the file
sitting at a destination may be a gutted stub, or something else entirely that happens
to share the name.

Shape is chosen from the **destination path**:

| Shape | Claim asserted |
|---|---|
| Workflow | parses, declares at least one job, and **no job runs nothing** |
| Other YAML | first document is a non-empty mapping |
| JSON | parses to a non-empty object |
| TOML | non-empty table |
| Opaque | present and non-empty, **and the verdict says that is all** |

Two nuances:

- **Emptiness is the floor for every kind.** A file trimmed to nothing enforces
  nothing.
- **A JSON parse failure is "unprovable", not "broken."** The comment stripper handles
  only the subset sscsb's own template uses, so a failure is **sscsb's limitation**
  rather than proof the file is broken. Unprovable degrades; broken fails.

For prose and worksheet files, the opaque verdict states its own limit in the output:
present and non-empty, with no machine-checkable structure, because the substance is a
human judgement sscsb does not assert. See
[project declarations](../governance/project-declarations.md).

## Source map

| Concern | Location |
|---|---|
| Runner-hardening verdict | `src/workflows.rs`, `verify_harden_runner` |
| Per-job YAML helpers | `src/audit.rs`, `harden_runner_status` |
| Generic template verifier | `src/workflows.rs`, `verify_template_control` |
| Shape selection and checks | `src/workflows.rs`, `shape_of`, `check_shape` |
| The constant-verdict control | `src/controls.rs`, dispatch table |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib harden_runner
```

Seven tests map one-to-one onto the failure modes above, including a fixture that drops
a non-workflow file into the workflow directory to prove it is not counted.
