# Agent signing

> Optional, **off by default**. Enable with `sscsb enable agent-signing`.

This control lets an AI coding agent produce **verifiable, cryptographically signed
commits under its own distinct identity** — without ever letting that signature stand
in for a human's on a protected branch.

It exists because two things are both true:

1. An agent's work should be *attributable*. When a human, a CI bot, and an AI all
   commit to the same repo, a signature that says "this came from the agent" is real
   provenance — non-repudiable, tamper-evident, and useful in review.
2. An agent must **never** be able to sign *as a human* or land unreviewed on
   `main`/`master`. That is the whole point of [`signing.md`](signing.md).

The reconciliation is a single idea: **an `ai`-class signature is verifiable as an
agent signature, and is rejected on protected branches — and those two facts are
independent.** The protected-branch gate keys on the signer's `class` (from
`signers.toml`), not on whether the key appears in `allowed_signers`. So enabling
agent-signing emits the agent key into `allowed_signers` (making feature-branch agent
commits verify `%G?=G`) while the human-only gate is untouched.

## What a signature does and does not mean

A touchless agent signing key attests exactly one thing: *this process had access to
this key.* It does **not** attest intent, correctness, or human approval. So in this
system a signature is **provenance, never authorization**. The trust boundary — the
place a human is accountable — is **code review at merge**, enforced by
`branch-protection` and the human-signed-merge rule, not by any per-commit signature.

## The two properties of a hardware-backed key (only one is automatable)

Hardware backing (TPM, Secure Enclave, FIDO2 security key, HSM, cloud KMS) gives a
signing key two separable properties:

| Property | What it means | Automatable? |
|----------|---------------|--------------|
| **Non-exfiltratability + attribution** | The private key cannot be copied off the device; a signature proves *that key* signed | **Yes** — this is what an agent wants |
| **Presence / user-verification** | Every signature requires a human touch or PIN | **No** — a touch defeats a headless agent |

An agent wants the first and must avoid the second. This is why a **Secure Enclave**
or a **FIDO2 key with `verify-required`** is the *wrong* choice for a headless agent
(they bind a human touch), and why an **empty-passphrase TPM key** or a **GitHub App**
server-side key is the *right* one (non-exfiltratable, touchless).

## Backend matrix

`backend` on a signer is descriptive. It **never** changes the protected-branch gate
(ISC-A6) — it documents where the key lives and drives the setup guidance from
`sscsb agent-key setup --backend <b>`.

| Backend | Where the key lives | Touchless? | sscsb tier | Notes |
|---------|--------------------|-----------|-----------|-------|
| `github-app` | Inside GitHub; never on any box | n/a (server-side) | **first-class** | Best fit for **Claude Code cloud / mobile**. Commits made via the App's installation token are signed server-side and show the **Verified** badge. `sscsb signers check --github-app <login>` confirms it. The agent literally cannot sign as a human. |
| `tpm` | Linux TPM 2.0, non-exportable | yes (empty-passphrase) | **docs-tier** | `ssh-tpm-agent` (Foxboron). `TPM2_Certify` can prove non-exportability, but no git tooling surfaces it, so v1 tracks attestation as an artifact only. Linux only. |
| `fido2` | Hardware security key (`ed25519-sk`) | only if **not** `verify-required` | docs-tier | A resident, non-verify-required key can sign headlessly. `ssh-keygen -O write-attestation` proves hardware residence at keygen (verify out-of-band against the FIDO MDS). |
| `kms` | Cloud KMS (AWS/GCP/Azure) | yes | **documented pattern only** | ssh-agent shims (`go-kms-signer`, `iam-ssh-agent`) are lightly maintained and untestable in CI; sscsb does not orchestrate them. Non-exfiltratable, audited, rotatable. |
| `piv` | YubiKey PIV slot, `--touch-policy never` | yes | docs-tier | Non-exportable via PKCS#11; `never` touch policy makes it headless-viable. |
| `software` | A file on disk | yes | (last resort) | Exfiltratable — attribution only, no hardware guarantee. Honestly labelled `hw:software`. |

**Deliberately not supported in v1:** `gitsign` for *commit* signing (no GitHub
Verified badge, online Fulcio+Rekor dependency, incompatible with the `allowed_signers`
model — Sigstore keyless remains for *artifacts* in `provenance.rs`); native Windows
`nCryptAgent`; macOS Secure Enclave for headless agents (presence-bound); full FIDO-MDS
chain verification and `TPM2_Certify` attestation (no maintained Rust verifier; format
drift). See the plan's *Out of Scope* for the reasoning.

## Making this work under a Claude Max subscription (cloud / mobile)

When you drive **Claude Code cloud** from the iPhone app, there is no box you control:
the agent runs in an Anthropic-managed ephemeral sandbox, and signing keys are kept
out of it by design. Two consequences:

- **The client-side pre-push hook never runs.** Nothing local can gate the push.
- **You cannot place a TPM/YubiKey in that sandbox.**

The answer is **GitHub App server-side signing** plus the **server-side policy gate**:

1. The agent commits through a **GitHub App** installation token (Contents: write on
   the target repo only). GitHub signs server-side → **Verified** badge, key never on
   a box. Register the App's committer as a `class = "ai"` signer.
2. Enable `agent-signing` and install its workflow. On every push, GitHub runs
   `sscsb signers verify-policy --base <before> --head <sha>`, which reads the trusted
   signer policy **from the parent commit** and rejects any push that changes
   `.sscsb/policy/**` unless a human trusted *before* the push signed it.

That server-side gate is the only thing that holds when no local hook runs, and it is
what stops an agent (or anyone) promoting an `ai` key to `human` and using it in the
same push.

## Setup

```sh
sscsb enable agent-signing
sscsb agent-key setup --backend github-app   # or: tpm
# ... provision the key per the printed guidance, then:
sscsb signers add --principal agent@ci.example.com --class ai \
  --backend github-app --hardware-backed \
  --ssh-key "ssh-ed25519 AAAA... agent@ci.example.com"
sscsb verify agent-signing
sscsb signers check                          # label recent commits human/ci/agent/unsigned
sscsb signers check --github-app agent[bot]  # verify server-side signing
```

## Key rotation and attestation

- `expires` (a `YYYY-MM-DD` date) is reported by `sscsb verify agent-signing`; a key
  past its date **fails** the control, and a validity window longer than
  `max_key_age_days` (default 90) **degrades** it. Rotate agent keys often.
- `attestation_file` points at an out-of-band hardware-residence proof (e.g.
  `ssh-keygen -O write-attestation`). If present, sscsb records its path and sha256 and
  reports `hardware=attested`; if absent, `hardware=declared`. In v1 this is
  **artifact tracking, not chain verification** — and it can **never** elevate a
  signer's class or flip a gate outcome.

## What this is not

- It is **not** a way to let an agent merge to a protected branch. It cannot.
- It is **not** authorization. A signature says *who ran*, not *whether it was right*.
- It does **not** replace human review. Accountability lives at the merge boundary.
