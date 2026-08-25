---
type: Quickstart
title: sscsb
description: A policy engine for software supply chain security — what it is, how to drive it, and where to read about any part of it.
tags: [quickstart, overview, routing]
sources:
  - id: openwiki-source-c38906bbfa9e9c69417b11b5
    resource: repo://src/cli.rs
  - id: openwiki-source-2a737474d86fc75cc9d9694f
    resource: repo://src/config.rs
  - id: openwiki-source-6d5d5a727c380c95e2fe604e
    resource: repo://src/controls.rs
  - id: openwiki-source-930affe7a5ad90d840c90761
    resource: repo://src/exec.rs
  - id: openwiki-source-95352b0faaf38cc22d6f51b3
    resource: repo://src/init.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# sscsb

`sscsb` hardens a git repository's software supply chain. It is a **policy engine over
other people's tools**: it decides which controls apply, invokes scanners and signers,
parses what comes back, and turns that into a verdict you can gate on.

**Forty-four controls, banded into five phases.** The control registry is the single
source of truth — the generated config, the compliance map, `sscsb status` and
`sscsb report` are all derived from it rather than maintained beside it.

## The loop

```sh
sscsb init            # bootstrap: config, hooks, policy, CI templates
sscsb status          # what is on, what tools are present
sscsb deps baseline   # approve the dependencies you already have
sscsb verify          # run every enabled control
sscsb report          # map controls onto compliance frameworks
```

`init`'s own closing output names the baseline step, and it is easy to skip: without
it, the first commit that touches a manifest is blocked by a gate you have not seeded.

## Read the exit code, then read the verdicts

**Exit 0 means nothing that ran failed — not that everything was verified.** A
degraded control contributes to the exit code only under `--strict`.

| Code | Meaning |
|---|---|
| 0 | No control failed |
| 1 | A gate failed (or a control degraded, under `--strict`) |
| 2 | sscsb could not run — not a finding about your repository |

Start at [the verdict contract](control-model/registry-and-outcomes.md). It is the one
page everything else assumes, and the distinction it draws — **`DEGRADED` is not
`PASS`** — is the one most consumers get wrong.

## Where to read about what

**Understanding the model**
[Verdicts and the registry](control-model/registry-and-outcomes.md) ·
[Phases](control-model/phases.md) ·
[Configuration](control-model/configuration.md) ·
[What lands on disk](control-model/repository-state.md) ·
[Adding a control](control-model/adding-a-control.md) ·
[Compliance mapping](control-model/compliance-mapping.md)

**Commits and identity**
[Git hooks](commit-integrity/git-hooks.md) ·
[Signer policy](commit-integrity/signer-policy.md) ·
[The server-side gate](commit-integrity/server-side-policy-gate.md) ·
[Signing environments](commit-integrity/signing-environments.md) ·
[AI provenance trailers](commit-integrity/ai-provenance-trailers.md) ·
[gittuf ref policy](commit-integrity/gittuf-ref-policy.md)

**Dependencies**
[Manifests and package trust](dependencies/manifests-and-package-trust.md) ·
[Vulnerability scanning](dependencies/vulnerability-scanning.md) ·
[SBOM generation](dependencies/sbom-generation.md) ·
[OpenVEX](dependencies/openvex.md) ·
[Endpoint exposure](dependencies/endpoint-exposure.md)

**Code scanning**
[Static analysis](code-scanning/sast.md) ·
[Deep scanning and fuzzing](code-scanning/codeql-and-fuzzing.md)

**Provenance**
[Artifact signing](provenance/artifact-signing.md) ·
[Release attestations](provenance/release-attestations.md) ·
[AI receipts](provenance/ai-receipts.md) ·
[Model signing](provenance/model-signing.md)

**Forge posture**
[Workflow auditing](github/workflow-auditing.md) ·
[Branch protection](github/branch-protection.md) ·
[CI hardening](github/ci-hardening.md) ·
[Federated credentials](github/federated-credentials.md) ·
[Scorecard](github/scorecard.md)

**Governance**
[Project declarations](governance/project-declarations.md) ·
[External services](governance/external-services.md)

**How it works underneath**
[Process execution and exit codes](runtime/process-execution.md) ·
[Repository context](runtime/repository-context.md) ·
[Tools and degradation](runtime/external-tools-and-degradation.md)

**Bootstrap and operations**
[Initialization](bootstrap/initialization.md) ·
[CI templates](bootstrap/ci-templates.md) ·
[Command surface](operations/cli-surface.md) ·
[Network and credentials](operations/network-and-credentials.md)

**Working on sscsb**
[Building and testing](development/building-and-testing.md) ·
[Release pipeline](development/release-pipeline.md) ·
[CI and tool pins](development/ci-and-tool-pins.md)

## Task routing

| I want to… | Go to |
|---|---|
| Understand what a verdict means | [Verdicts](control-model/registry-and-outcomes.md) |
| Know what `init` will write or overwrite | [Repository state](control-model/repository-state.md) |
| Work out why a control is degraded | [Tools and degradation](runtime/external-tools-and-degradation.md) |
| Stop an AI signing a protected-branch commit | [Signer policy](commit-integrity/signer-policy.md) + [the server-side gate](commit-integrity/server-side-policy-gate.md) |
| Waive a vulnerability | [OpenVEX](dependencies/openvex.md) |
| Understand a scanner's exit code | [Process execution](runtime/process-execution.md) |
| Add a control | [Adding a control](control-model/adding-a-control.md) |
| Know what leaves my machine | [Network and credentials](operations/network-and-credentials.md) |
| Run the tests correctly | [Building and testing](development/building-and-testing.md) |

## One habit worth forming

Several pages record where the source is **honest about its own limits** — a passing
verdict that means "the machinery is installed" rather than "the policy verified", a
control whose verdict is a constant, a check that asserts a file is non-empty and says
so.

Those are the places to read before relying on a green result. They are marked, not
hidden, and that is deliberate.
