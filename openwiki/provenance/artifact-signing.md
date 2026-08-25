---
type: Architecture Guide
title: Artifact signing and verification
description: The verify side of provenance — why the builder identity is mandatory, what the deploy gate refuses, and what a passing verdict does not mean.
tags: [provenance, cosign, slsa, verification, deploy-gate]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Artifact signing and verification

This page owns the **verify** side: checking that an artifact you are about to deploy
was built by the builder you expect, from the source you expect, and signed by the
identity you expect. The **install** side — which workflow puts each kind of evidence
there in the first place — is
[release attestations](release-attestations.md).

## The builder identity is the whole control

`sscsb provenance verify-artifact` **requires** a builder identity. It is not
optional, and there is no default.

The reason is precise. Pinning only the source repository makes the verdict *"some
builder the verifier trusts produced this, for this source"* — not *"the builder our
release pipeline actually uses"*. Anyone who can get **any** trusted builder to run in
that repository clears the gate.

A default is refused deliberately too: a default that is wrong for a repository either
narrows the gate silently, or gets copied without thought. Both are the same failure
with extra steps.

**The pin is resolved before the verifier tool is even looked for.** That ordering is a
claim about what kind of thing a missing pin is: an unset trust anchor is a *policy
gap*, and should be reported as one whether or not the tool happens to be installed
today.

### Where the identity comes from

Read it **once, from a build you already trust**, using `sscsb provenance inspect` —
never from the file you are currently verifying, which is the untrusted input. That
bootstrap step is the whole trust decision; everything after it is mechanical.

The source **tag** stays optional, because branch builds and pre-tag builds are
legitimate. But an unpinned tag is **spelled out in the verdict**, so you can see that
any reference of the repository satisfies the check rather than discovering it later.

### It is tested against real material

The pin is proven against **genuine externally-signed release artifacts**, not
fixtures: the same untampered artifact and provenance pair passes against its real
builder and **fails against a different trusted builder**. Without the pin, that exact
invocation passed — which is the finding, demonstrated rather than asserted.

## Signature verification

Verifying a signature requires **both** an identity and an issuer as mandatory
parameters. There is no any-identity mode, because a signature checked against no
particular signer establishes only that someone signed something.

## The deploy gate

The shipped `deploy-gate.yml` is one verify job and one publish job, with the publish
job depending on the verify job. That dependency is the entire gate.

Four properties are worth copying into any gate you write yourself:

**Nothing-to-verify is a failure.** An empty set of signatures or provenance files is
an error — *refusing to certify unsigned artifacts* — because an unmatched glob
silently becoming a literal string is not a verification result.

**The tag reaches the shell through the environment**, never through template
interpolation. That is sscsb applying to its own template the script-injection rule
its extended audit flags in your workflows.

**The identity check is an anchored regular expression** over the repository prefix
with escaped separators, so it cannot match a look-alike host or a repository whose
name merely *starts* with yours. This is the one place shipped verification
deliberately differs from the exact-identity command: one repository, many workflows.

**Per-file failures accumulate.** The result is collected across the loop rather than
taken from the last iteration, so one failing artifact cannot be masked by a later
success.

## Two things a passing verdict does not mean

Both are worth knowing before you trust the control's green.

**An unpinned builder identity does not weaken the verdict.** The control degrades
only when a tool is missing; an unset pin merely adds a message. So
`verify provenance-verify` can report `PASS` on a repository where every actual
verification will refuse to run for want of a pin. Read the messages, not just the
verdict.

**The `witness` control's verdict is tool presence only.** A `PASS` there means the
binary is installed — nothing about whether any build step was wrapped or anything
attested. It is off by default and ships no template.

## Source map

| Concern | Location |
|---|---|
| Artifact verification | `src/provenance.rs`, `verify_artifact` |
| Attestation inspection | `src/provenance.rs`, `inspect_dsse` |
| Signature wrappers | `src/provenance.rs`, `cosign_sign_blob`, `cosign_verify_blob` |
| The control | `src/provenance.rs`, `verify_provenance_control` |
| The witness control | `src/provenance.rs`, `verify_witness_control` |
| Deploy gate | `templates/workflows/deploy-gate.yml` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib provenance::
```

The integration suite additionally downloads real signed release material and drives
the four cases above; it needs network access and the real verifier on `PATH`.
