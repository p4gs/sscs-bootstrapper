---
type: Architecture Guide
title: The five signing environments
description: Where a commit can come from, who signs in each case, and how sscsb handles the environments it cannot probe.
tags: [signing, environments, attestation, identity]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# The five signing environments

A commit can be authored from a laptop, by a coding agent on that laptop, by an agent
in a cloud container, through the forge's web editor, or in a hosted dev environment.
Each has a different signer, different capabilities, and — importantly — a different
amount of ground truth sscsb can actually read.

This page owns that model. [Signer policy](signer-policy.md) owns who is allowed to
sign; this page owns getting each environment configured so the right identity signs
in the first place.

## The rules the model exists to keep

Four, from the source:

1. **The agent never signs as the human.**
2. **The agent's key is never registered on the human's forge account.** Its commits
   therefore show as *unverified* on the forge — and **that is the designed state.**
   An unverified agent commit is correct; an *unsigned* commit is the failure.
3. Verified-as-human always traces back to a genuine human action.
4. Merges to protected branches come from the human-local lane.

Point 2 is the one people try to "fix". Registering the agent key on the human's
account would make the badge green and destroy the distinction the whole model
exists to draw.

## The shape of the work

Each lane runs the same four steps: **probe** what is true now, **converge** what can
be set programmatically, **guide** what cannot with numbered steps, then **verify**.

A guided step is not just an instruction — it carries *why it matters* and *how to
confirm it later*, because a step nobody can check is a step nobody did.

Two configuration keys once existed here as generalisation seams for other agents and
backends. Nothing read them, and they were **removed rather than left advertising
configurability that does not exist**. That is the honest treatment of a seam that is
not yet real, and the same reasoning appears in
[configuration](../control-model/configuration.md).

## What can and cannot be probed

| Lane | Probe reads | Best reachable state |
|---|---|---|
| Human local | git global config, key files, alias | Configured |
| Agent on that machine | the harness settings file's git-config block | Configured |
| Cloud agent | repository-level settings for an attribution block | Configured |
| Forge web editor | one account fact via the forge CLI | **Partial only** |
| Hosted dev environment | nothing — no read API exists | **Pending only** |

**Two lanes can never report as fully configured.** The web editor exposes only one
readable fact, and the hosted-dev-environment lane has no read API at all, so its
probe is a constant. That is not a gap in the implementation; it is the shape of what
those platforms expose.

This is precisely why the attestation store exists — and why an unreachable `Pass`
verdict on the overall control was a symptom worth chasing rather than a dead branch
worth deleting.

Machine-level git settings are read at **global** scope deliberately, so an agent
session's own per-command git environment cannot leak into what the probe reports.

## The laptop footgun

The human-local lane requires a `git sign` alias, and the reason is specific: **inside
an agent session, a bare `git commit` signs as the agent.** The agent's harness sets
git configuration for its own identity, and that configuration outranks the human's
global settings.

The alias forces the human key through explicit per-command overrides, which outrank
the environment. Without it, a human committing from inside an agent session
unknowingly produces agent-signed commits.

## Identity blur

The agent lane reports **`IDENTITY BLUR`** when the agent's signing key or email
equals the human's. That exact string is matched by both verifying surfaces, so it is
load-bearing text rather than a message.

Converging the agent lane **refuses outright, writing nothing**, if the requested
agent email equals the human's — the refusal message says that would forge the
human's identity onto AI commits. It is the one place in this codebase where setup
declines to do what it was asked.

The settings merge that configures the agent is the highest blast-radius write in the
tool and is layered accordingly: it preserves every unrelated key, **clears stale
numbered git-config entries before writing** so that shrinking a set cannot orphan a
half-pair, backs the file up first, and reads it back afterwards to confirm the
identity survived.

## Attestations, for what cannot be probed

Where no API exists, the operator confirms something themselves and sscsb records the
date. Three properties keep that honest:

**Freshness is 180 days, counted backwards.** The function that evaluates it is
deliberately separate from the one that evaluates key expiry, and the source explains
why at the subtraction: an expiry date is a deadline in the future, an attestation
records an action in the past, and the two count in opposite directions. Conflating
them is exactly the defect that once made a confirmation made *yesterday* read as
stale.

**A future-dated attestation does not count.** A confirmation records something
already done, so a date ahead of today is a typo or a forgery — not a deadline far
away.

**An attestation may fill a gap a probe cannot reach; it may never overrule one it
can.** Where the forge itself reports the underlying protection disabled, the
attestation is refused. You cannot confirm your way past a fact the tool can read.

Confirming under `--dry-run` records nothing, and says so.

## The two verifying surfaces

`sscsb signing verify` is a report card per lane. `sscsb verify signing-model` is the
control.

Both check **identity blur first, from any lane, attested or not**, so no confirmation
can shadow it. Blur is a violation of the model; everything else is either satisfied
or pending. That is why a lapsed attestation drops a lane to pending rather than
failing it — missing evidence is not a breach, and the distinction matters for a
control people have to live with.

## Honest limits

The implementation is specific, not general: one agent harness, one hardware backend's
socket path, one hard-coded agent key filename. Generalising is real work in the paths
and environment types, not a config key — which is exactly why those two seam keys were
deleted rather than left in place.

## Source map

| Concern | Location |
|---|---|
| The model and its rules | `src/signing_setup.rs` module doc |
| Environments and probes | `src/signing_setup.rs`, `probe_*` |
| Convergence | `src/signing_setup.rs`, `converge_*` |
| Settings merge | `src/signing_setup.rs`, `merge_git_config_env` |
| Attestation store | `src/signing_setup.rs`, `record_lane_attestation`, staleness |
| Probe-versus-attestation rule | `src/signing_setup.rs`, `probe_contradiction` |
| The control | `src/signing_setup.rs`, `verify_signing_model_control` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test integration signing_
```
