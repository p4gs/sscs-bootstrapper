---
type: Architecture Guide
title: Signer policy and the client-side gate
description: The three signer classes, how allowed_signers is derived, and the half of the AI-cannot-sign invariant that runs on your machine.
tags: [signing, policy, ssh, protected-branches]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Signer policy and the client-side gate

This page owns the **client-side half** of the signing model: who is allowed to sign,
how that policy becomes something git can verify against, and the pre-push gate that
enforces it locally.

It is only half. The enforcement that actually holds against a determined actor is
[the server-side policy gate](server-side-policy-gate.md), and the reason why is at
the [bottom of this page](#why-this-half-cannot-be-the-enforcement-point). Read both
or you will have the wrong model of the guarantee.

## Three classes

`.sscsb/policy/signers.toml` lists signing identities, each classified **`human`**,
**`ci`**, or **`ai`**. That class is the only thing that decides authorisation on a
protected branch.

Two fields exist to describe a signer and are explicitly barred from changing any
outcome: `backend` (which hardware or service holds the key) and `attestation_file`.
Both are descriptive. Neither can elevate a class. A signer's `expires` date is
reported by `verify` but is not enforced by the emitted file.

## Two uniqueness rules, one of them non-obvious

A duplicate **principal** is a hard parse error. So is duplicate **key material** —
and that second rule is the interesting one, because it closes a real bypass.

Git resolves the signer name that a gate matches on to the **first** line in
`allowed_signers` whose key verifies the signature. Register one key twice, once as
`human` and once as `ai`, and the agent's signature resolves to the human's
principal. With the agent-signing control off it is worse still: only the human twin
is ever emitted, so the bypass does not even depend on ordering.

Key material is therefore compared as **key type plus base64 body, ignoring the
trailing comment**, so the same key under two different comments is still caught. An
unrecognised class is an error rather than a silent default.

## The invariant, in two separate mechanisms

"An AI cannot sign a commit on a protected branch" is true, but it is delivered by
two mechanisms with different strengths, and conflating them produces a wrong mental
model.

**Mechanism 1 — conditional.** Whether an `ai`-class key is written into
`allowed_signers` at all depends on the `agent-signing` control, which is **off by
default**. With it off, an AI key can never produce a verifiable signature anywhere,
because the material git needs is simply absent. With it **on**, the key *is* emitted
— deliberately — so an agent's commit verifies as a genuine agent signature on a
feature branch.

**Mechanism 2 — absolute.** The protected-branch gate rejects a signature on the
signer's **class**, never on presence in `allowed_signers`. It resolves the principal
git reports back to the policy file and refuses anything not classified `human`. This
holds whichever way mechanism 1 is set, and no configuration key changes it.

So: mechanism 1 governs **verifiability**, and is switchable. Mechanism 2 governs
**authorisation on a protected branch**, and is not.

> Some older prose in this repository states mechanism 1 without its condition,
> claiming an `ai` key is "never" emitted. That is the default, not the contract.

`allowed_signers` is regenerated from `signers.toml` on every protected-branch push,
so editing it directly accomplishes nothing.

## The pre-push gate, and what it refuses

Roughly in order:

1. **An empty signer policy refuses the push.** Not a warning, not a pass — there is
   nobody to authorise anything.
2. `allowed_signers` is regenerated from the working tree.
3. Commits in the range are enumerated with **no count cap**. A cap would leave
   commits beyond it unverified, so an unsigned commit deep in a large push could
   reach the branch behind a passing check.
4. Each commit's signature status, principal, key and parents are read in one call.
5. A good signature must resolve to a policy entry whose class is `human`, and
   — under the default setting — whose entry declares a hardware-backed key.
6. **An unrecognised signature status is refused by name**, not defaulted to allowed.

### The argument-injection guard

Both revisions arrive on stdin from git's pre-push protocol, and both are validated
as bare object names before reaching git.

The reason is specific and worth stating: `git rev-list` inherits diff options
including `--output=<file>`. A revision shaped like an option would write a file and
return an **empty** commit list — and an empty list means no unsigned commits were
found, so the push sails through. The same class of defect is catalogued in
[process execution](../runtime/process-execution.md).

## Why this half cannot be the enforcement point

Two independent reasons, both stated in the source:

**The policy it reads is under the pushing actor's control.** This gate loads
`signers.toml` from the working tree and regenerates `allowed_signers` from it,
immediately before verifying against it. Anyone able to push can edit that file
first. Reclassify an `ai` key as `human`, and the local gate happily agrees.

**In cloud and mobile sessions there is no local hook at all.** Nothing on the client
side runs.

Which is exactly why the enforcement lives on the server:
[the server-side policy gate](server-side-policy-gate.md) reads the trusted policy
from the base revision instead, so a push cannot supply the policy that authorises
it. The local gate is a fast, useful, honest check that catches mistakes. It is not
the thing that stops an adversary, and this wiki does not claim otherwise.

## Authoring policy

`sscsb signers add` validates the class, requires at least one key or fingerprint,
checks the backend against the known list and the expiry as a date, then **parses the
whole prospective file with the real parser before writing it** — so the duplicate
rules above apply to additions too — and regenerates `allowed_signers`. It also tells
you when your new `ai` signer is not yet emitted because the control is off.

## Source map

| Concern | Location |
|---|---|
| `Signer`, `SignerClass`, the template | `src/hooks.rs` |
| Parsing and uniqueness | `src/hooks.rs`, `parse_signers` |
| Emission | `src/hooks.rs`, `regenerate_allowed_signers` |
| The gate | `src/hooks.rs`, `check_signing_for_range` |
| Posture reporting | `src/hooks.rs`, `verify_signing_control` |
| Policy authoring | `src/signers.rs`, `add_signer` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test integration signing
```

The end-to-end proof approves one key as `human`, pushes successfully, reclassifies
that **same key** as `ai`, and asserts the push of a newly signed commit is blocked.
