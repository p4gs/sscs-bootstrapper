---
type: Architecture Guide
title: AI provenance receipts
description: What a receipt binds a commit to, what it deliberately does not prove, and the untrusted-input boundary around a file someone hands you.
tags: [ai-provenance, receipts, in-toto, untrusted-input, signing]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# AI provenance receipts

A receipt turns an AI-involvement claim from an honour-system commit trailer into a
verifiable attestation. `sscsb receipt create` writes one; `sscsb receipt verify`
checks it.

The control is **off by default**, and the most useful thing to understand is the
precise boundary of what a receipt proves.

## What a receipt binds

An in-toto statement whose subject is **one commit**, carrying:

- the commit's object name and a **digest of its patch**;
- the declared AI **tool**, **model** and **role**;
- the tool version that generated it, and a timestamp.

The AI declaration comes from the commit message's trailers — the same ones
[the trailer gates](../commit-integrity/ai-provenance-trailers.md) validate. An absent
declaration is recorded as **undeclared**, not as false, so a receipt distinguishes a
commit that said nothing from one that denied assistance.

## What it does not prove

**The patch digest says nothing about the AI declaration.** It proves the commit's
*content* is the one the receipt was made from. The declaration lives in the commit
message, which the digest does not cover.

That was once the whole verification, and it left the actual purpose unchecked: a
receipt claiming one AI tool while the commit's trailer said another **verified
happily**, because the patch bytes were untouched. Dropping a tool field entirely was
the most useful forgery of all — it launders AI-assisted work into apparently
unassisted work. A signed receipt also verified identically to an unsigned one, because
nothing read the signature.

Verification now re-reads the trailers and compares them **field by field**, naming
each divergence with both sides.

The second limit is worth stating plainly: a receipt proves the record is intact, not
that the claim is **true**. A commit message that lies produces a receipt that
verifies.

## The untrusted-input boundary

A receipt is **a file someone hands you**. It is the artifact under suspicion, so every
value read out of it is untrusted — and exactly one of them reaches `git`: the commit
name.

It is rejected unless it is a bare lowercase hex object name, **before** it can reach
git's argument parser. Without that guard, two payloads work:

- an option that **suppresses output**, so the digest comparison sees the hash of the
  empty string — supply a receipt whose digest is that hash and it verifies, for any
  commit, which is a universal forgery;
- an option that **redirects output to a file**, which makes verification an arbitrary
  file write *and* produces the same empty-string digest.

The regression test asserts both are refused **and** that a bystander file on disk is
byte-identical afterwards: verifying a forged receipt must never write to a file.

The guard is narrow rather than blunt. Genuine receipts made from revision expressions
still verify; option-shaped, too-short and uppercase names are refused. The full
reasoning — including why the obvious `--` fix would have been strictly worse — is in
[process execution](../runtime/process-execution.md#argument-arrays-stop-the-shell-not-git).

One more sharp edge in the same family: resolving a commit name additionally requires
a **full-length** object name, because git **echoes an unrecognised option back at
exit zero**. A fixed-width slice of that five-character answer once aborted the
process outright.

## Signatures

Three states, and the middle one is the interesting choice:

- **No bundle** — reported plainly, not an error. An unsigned receipt is
  distinguishable from an unverifiable one.
- **A bundle with no identity to check it against** — an **error**, not a warning. A
  signature nobody checks is not evidence.
- **A verified signature** — the verdict **names the identity and issuer** it was
  checked against, so an operator can see which identity the receipt was accepted for
  rather than just that something passed.

## Source map

| Concern | Location |
|---|---|
| Creation | `src/provenance.rs`, `create_receipt` |
| Claim extraction and comparison | `src/provenance.rs`, `AiClaim` |
| Verification | `src/provenance.rs`, `verify_receipt` |
| Signature handling | `src/provenance.rs`, `verify_receipt_signature` |
| The control | `src/provenance.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib receipt
```

The test to read first enumerates five one-field forgeries with the patch left
untouched, and asserts each is caught.
