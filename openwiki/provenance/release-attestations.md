---
type: Architecture Guide
title: Release attestations
description: The five release controls, what each kind of evidence proves, and the one pair that genuinely cannot coexist.
tags: [release, attestation, slsa, cosign, immutability]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Release attestations

Five controls put provenance evidence *on* a release. None of them has any Rust
implementation: each installs one workflow template, and its verdict is a check on the
installed file's **content**, not merely its existence — because an install never
overwrites, so the file at a destination may be a gutted stub that happens to share
the name.

The [verify side](artifact-signing.md) covers checking that evidence later.

| Control | Ships | Default |
|---|---|---|
| `sigstore-signing` | keyless signature bundles beside each asset | on |
| `slsa-provenance` | isolated-builder provenance attached to the release | on |
| `github-attestations` | build provenance in the forge's attestation store | on |
| `sbom-attestation` | an SBOM bound to the artifact digest, in the same store | on |
| `release-immutability` | a draft-then-publish release workflow | off |

## The either/or

**The generator path and the immutable path are alternatives, not companions.**

The SLSA generator attaches provenance to the release **after** it is published. An
immutable release forbids post-publication asset writes. So enabling both means one of
them must fail.

The same effect, for a different reason, applies to standalone signing: its final step
uploads assets after publication. The immutable workflow absorbs the signing instead,
doing it **before** the publish flip.

The two attestation-store controls are a softer case — **redundant rather than
fatal**. They write only to the forge's store, never to release assets, so they do not
break immutability. But each **rebuilds the artifact independently**, and therefore
attests a *different digest* than the one actually shipped. The evidence is real; it
is just about different bytes.

**Nothing in the tool enforces any of this.** sscsb will happily install the immutable
release workflow alongside the generator workflow, with no warning. Choosing is
currently yours.

## What each kind of evidence proves

**A keyless signature bundle** binds the signed bytes to the **OIDC identity of the
workflow that signed them** — repository, reference, workflow path — using a
short-lived certificate, with the signing event recorded in a public transparency log.
It travels *with* the release asset, so it can be verified offline. It says nothing
about how the artifact was built.

**Isolated-builder provenance** is produced in a job your build cannot reach and
signed by the builder's own control plane. That isolation is exactly what makes it a
higher build level than a build step politely describing itself. It carries the builder
identity, the source, and the artifact digests.

This is also why the generator is **the one action deliberately tag-pinned** rather
than digest-pinned, against the rule applied everywhere else: the verifier derives the
builder identity from the reference, and a digest reference fails by design. sscsb
encodes that as a single named exception scoped to that exact repository, so a
similarly-named one does not inherit the licence. See
[workflow auditing](../github/workflow-auditing.md).

**Forge attestation-store evidence** needs no bundle file and no extra tooling to
verify — which is precisely why it is compatible with an immutable release. The
evidence travels with the repository rather than the assets.

Two things it does not do, both stated in the templates rather than glossed:

- It claims **lower build levels** than the isolated-builder path, and says so instead
  of implying equivalence.
- Availability differs by plan and repository visibility, so on some repositories the
  honest configuration is to disable the control.

## Verifying, precisely

Two details are easy to get wrong and will silently give you nothing:

**Pin both the repository and the signing workflow.** Verifying that *something*
attested an artifact is close to worthless; verifying that **this repository's release
workflow** did is the control.

**Name the predicate type when verifying an SBOM attestation.** The verification
command defaults to the build-provenance predicate, so an SBOM attestation is simply
invisible without it — you get a confident "no attestation found" for evidence that
exists.

## Properties worth copying

Every one of these templates refuses to proceed when there is **nothing to do**. An
empty artifact set, a missing SBOM, an empty signature set — each is an error, because
"there was nothing to sign" must never be indistinguishable from "everything was
signed".

**Per-file signing failures fail the job explicitly.** Without that, a loop's
last-iteration exit status lets a failure on any one file pass — a defect found by
adversarial review before it shipped.

**Every asset write happens while the release is still a draft**, making the final
publish the only immutable transition. Re-running against an already-published tag
exits cleanly rather than failing at the upload step.

All five templates open with a hardened runner step, check out without persisting
credentials, and pin every action by digest — with the one documented exception above.
They pass sscsb's own audit, which is asserted by test.

## Source map

| Concern | Location |
|---|---|
| The five control registrations | `src/controls.rs` |
| Artifact installation | `src/workflows.rs`, `install_all` |
| Content verification | `src/workflows.rs`, `verify_template_control` |
| Templates | `templates/workflows/release-sign.yml`, `release-slsa.yml`, `release-attest.yml`, `release-attest-sbom.yml`, `release.yml` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib workflows::
```

Note that sscsb's **own** release pipeline is a different thing from these templates,
even where filenames coincide — see
[release pipeline](../development/release-pipeline.md).
