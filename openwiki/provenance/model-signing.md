---
type: Architecture Guide
title: Model signing
description: Signing ML model artifacts, and the distinction between a scan that found nothing and one that stopped looking.
tags: [model-signing, sigstore, ml, scanning, budgets]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Model signing

If a repository ships machine-learning model files, those files are build outputs with
no provenance unless someone gives them some. This control wires up keyless signing for
them.

It is **off by default**, and applies only when models are actually present — so a
repository without them is reported as **not applicable** rather than as a false pass
or a false fail.

## Found nothing versus stopped looking

The most interesting thing here is a distinction most scanners collapse.

Detecting whether a repository ships models means walking the tree, and walking is
bounded — otherwise `sscsb verify` could stall on a large or pathological directory
structure. There are **two independent bounds**:

- one on **directories traversed**, so a match-free tree cannot stall verification;
- one on **matches collected**, since a handful is enough to prove the control applies.

Each sets its own flag, and the flags mean different things.

**A completed scan that found no models is not applicable.** A scan that **stopped
early** and found none so far is `DEGRADED` — unknown, not not-applicable. Saying
not-applicable off an abandoned search would hide a repository that *does* ship models
behind a verdict that reads like a clean bill of health.

The same honesty applies to counting: a **capped** match count is rendered as a floor
rather than a bare number, so it cannot imply the whole tree was tallied.

## Two scanning decisions

**Symlinks are never followed.** A symlinked directory could form a cycle or point
outside the repository entirely — the exact thing the traversal bound promises against.

**Recognised extensions are a closed list** that deliberately excludes generic
container formats, to avoid false positives. That is a real coverage boundary worth
knowing: a repository shipping weights in an excluded format reads as not applicable.

## Why an installed workflow is not a pass

When models *are* present, an installed signing workflow is necessary but not
sufficient.

**A workflow file is a YAML file, not a signature.** Whether these models are signed
and verifiable is only answerable with the signing tool the control declares, so
without it the honest verdict is *not checked* rather than passing.

There is a second, practical reason: `sscsb status` already reports the tool as
missing in that situation, and a `PASS` here made the two commands contradict each
other in the same session.

Even the passing case is scoped: it means the tooling is available for local signing
and verification. **Nothing in the control executes a verification**, and the verdict
says so rather than implying it.

## What the shipped workflow does

It signs the model path with a pinned signing tool, using the CI runner's ambient
OIDC credentials so signing is non-interactive — without that, the tool falls through
to a browser flow that hangs on a runner.

It then verifies its own signature, deriving the **expected identity from the actual
reference** rather than hard-coding one, because the certificate's subject embeds a
tag reference on a release run and a branch reference on a manual run. Hard-coding
either would fail verification on the other.

Absence is a clean no-op rather than a failure: no model at the configured path exits
successfully, and the verify and upload steps are skipped when nothing was produced.
That is the **opposite** of the [release templates](release-attestations.md) posture,
where nothing-to-do is an error — deliberately, because this control is conditional on
models existing at all.

The signature is uploaded as a workflow artifact. It is **not** attached to the release
and **not** written to the attestation store.

## Source map

| Concern | Location |
|---|---|
| The verifier and its verdicts | `src/openssf.rs`, `verify_model_signing` |
| Bounded tree scan | `src/openssf.rs`, `scan_model_files` |
| Extension list and budgets | `src/openssf.rs` |
| Registry entry and tool pin | `src/controls.rs`, `src/tools.rs` |
| Workflow | `templates/workflows/sign-models.yml` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib model_s
```

One test builds a directory chain deep enough to exhaust the traversal bound with a
real model beyond it, so visit order is forced: the scan reports empty **and**
incomplete, and the same tree with the real bound finds the model.
