---
type: Architecture Guide
title: CI and tool pins
description: The three-job pipeline, and the duplicated tool versions a parity test keeps honest.
tags: [ci, pins, versions, parity]
sources:
  - id: openwiki-source-164e2da859b5277df81c7d94
    resource: repo://.github/workflows/ci.yml
  - id: openwiki-source-dc449d951131c1f542891d71
    resource: repo://tests/tool_pin_parity.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# CI and tool pins

## The pipeline

Three jobs — **lint**, **test**, and **coverage** — each installing the orchestrated
tool set through a shared composite action so all three see the same versions.

Beyond those, the repository runs its own controls against itself: secret scanning,
SAST, vulnerability scanning, SBOM generation and the rest. sscsb is its own most
demanding user, which is what keeps the shipped templates honest — see
[CI templates](../bootstrap/ci-templates.md).

## The duplicated pins

Tool versions are declared **twice**:

- in the Rust **tool registry**, which is the single place sscsb pins versions and the
  source of every install hint it prints;
- as **environment variables in the CI action**, which is what CI actually installs.

Two copies of the same facts in two languages is exactly the shape that drifts. A
**parity test** makes the registry **normative** and the CI action a derived copy.

The failure it prevents is specific and quiet: **CI would test against one version
while the tool's own degrade message told users to install another, and both would
look correct in isolation.** Nothing would be visibly broken; the two would simply be
describing different worlds.

## The deliberate omission

**Four tools are intentionally absent from the CI action**, and the parity test pins
that absence too.

The reason: their absence is what keeps the **degrade branches** exercised in CI. If
every tool were installed, the "tool missing" paths — a large share of what
[degradation](../runtime/external-tools-and-degradation.md) does — would never run
outside a developer's laptop.

So adding one of those four to the CI action **silently deletes a coverage path**.
That is the kind of change that looks like an improvement and is not, which is why the
test states it explicitly rather than leaving it to a comment.

## Source map

| Concern | Location |
|---|---|
| Pipeline | `.github/workflows/ci.yml` |
| Tool installation | `.github/actions/setup-sscsb-tools/action.yml` |
| Version registry | `src/tools.rs` |
| Parity test | `tests/tool_pin_parity.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test tool_pin_parity
```
