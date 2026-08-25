---
type: Architecture Guide
title: The server-side policy gate
description: The enforcement that survives an attacker-controlled working tree, and the agent-signing control that installs it.
tags: [signing, ci, policy, agent-signing, self-promotion]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# The server-side policy gate

This is the half of the signing model that actually holds.

[Signer policy](signer-policy.md) describes the client-side gate, which reads policy
from the working tree that the pushing actor controls, and which does not run at all
in cloud or mobile sessions. Neither limitation is a bug in that gate; they are
inherent to running on the client. This gate is the answer to both.

## The threat it closes

An actor with push access edits `.sscsb/policy/signers.toml`, reclassifying an `ai`
key as `human`, and uses that key in the **same push**. Every local check reads the
edited file and agrees.

The property this gate buys, stated in the source: *a push can never promote an `ai`
or `ci` key to `human` and use it in the same push.*

## How it gets that property

By refusing to read anything the push supplied.

- The trusted signer set is built from the policy blob **at the base revision** —
  straight out of committed history, not from the pushed tree.
- Verification is forced against that set by overriding the allowed-signers path for
  that one git invocation. The pushed tree's copy is never consulted.
- The trusted content is generated with **agent keys excluded unconditionally**. Even
  with the `agent-signing` control enabled, an AI key cannot authorise a policy
  change. That is a hard-coded exclusion, not a configurable one.

The gate then inspects only the commits in the pushed range that touch the policy
directory, and rejects each one that is:

- signed by someone in the trusted set whose class is not `human`;
- signed by someone **not in the trusted set at all** — the self-promotion guard,
  which is the arm that catches the attack above;
- carrying any signature status other than a good one.

Everything else in the push is none of this gate's business.

## The first push

A new branch or a new repository has no trusted parent policy to check against. The
gate does **not** silently pass in that case. It reports a problem saying so
explicitly: the change is not verifiable against a prior state, and branch protection
is what has to cover the initial commit.

The exemption that makes this usable lives in the CLI rather than the library, and it
is narrow on purpose: the command exits 0 **only when that is the single problem
reported**. Any second problem alongside it still fails. So "this is a first push" can
excuse the absence of a parent policy, and nothing else.

## The workflow

The gate ships as a workflow template that runs on pushes to the default branch and
on every pull request. Two of its properties matter:

- **It checks out full history**, because the parent policy has to be readable.
- **It runs without persisted credentials.**

One thing to fix in your own copy: **the shipped template installs sscsb unpinned**,
and its own comment tells you to pin a version. Left as shipped, the gate's behaviour
depends on whatever version resolves at run time — an odd property for a control whose
entire job is refusing to trust what a push supplies. Pin it.

## The `agent-signing` control

This control owns whether the whole agent-signing model is switched on. It is off by
default, and this page owns it because its verdict is fundamentally *is the
server-side gate in place and correctly configured?*

Its verdicts are informative about the design's priorities:

- **A signer policy that cannot be parsed is a hard `Fail`.** The policy gating agent
  identities must itself be well-formed; there is no lenient reading.
- **A missing server-side workflow is a `Degraded`**, naming that as the reason. The
  control refuses to pass while the thing that enforces it is absent.
- **No `ai` signer configured is `Degraded`**, not a failure — an incomplete setup
  rather than a violation.

Its options are `allowed_backends`, `max_key_age_days` and
`require_agent_signatures`.

**Key expiry is evaluated only for `ai`-class signers.** An expired key fails; a
validity window longer than the configured maximum degrades. That asymmetry is
deliberate — an expired key is a violation, an over-long window is a policy smell.

**Attestation checking is presence and digest only.** It verifies that a declared
attestation file exists and hashes as expected. It explicitly does **not** verify a
hardware attestation certificate chain, and the source says so rather than implying a
stronger guarantee. Treat it as bookkeeping, not proof of hardware.

## The GitHub-App path

For cloud and mobile sessions, where there is no local key and no local hook, commits
are signed by a forge App identity instead. `sscsb signers check --github-app` reads
the forge's own verification verdict and confirms the committer matches, exiting
non-zero if any commit in the range fails either test. When the `gh` CLI is absent it
degrades with a message rather than passing silently.

`sscsb agent-key setup --backend <backend>` prints guidance only. It never touches a
key or a remote service. Note that `--backend` is a **flag**, not a positional
argument.

## Source map

| Concern | Location |
|---|---|
| The gate | `src/signers.rs`, `verify_policy_changes` |
| Trusted-base construction | `src/signers.rs`, `signers_at_ref` |
| First-push exemption | `src/cli.rs`, `cmd_signers` |
| The control | `src/signers.rs`, `verify_agent_signing_control` |
| GitHub-App verification | `src/signers.rs`, `verify_github_app_commits` |
| The workflow | `templates/workflows/agent-signing-verify.yml` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib signers::
```

The three tests worth reading are the ones that accept a human trusted before the
push, reject a CI-signed policy change with "only a HUMAN", and reject a
stranger-signed one as not verifiably human-signed against the pre-push trusted
policy.
