---
type: Architecture Guide
title: The five-phase model
description: How sscsb bands its 44 controls into five phases, where phases are enforced, and where they are only conventional.
tags: [controls, phases, status, configuration]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# The five-phase model

Phases are the product's user-facing vocabulary. Every control declares one, the
generated config is banded by them, and `sscsb status` and `sscsb report` group
their output by them. They answer "where in the supply chain does this control sit?"

They are deliberately **not** the axis this wiki is organised around, because
several phases mix independently owned subsystems. The map at the end of this page
connects the two.

## The five bands

| Phase | Theme | Controls | Default on | Default off |
|---|---|---:|---:|---:|
| 1 | Local source integrity | 11 | 8 | 3 |
| 2 | Dependencies and vulnerabilities | 8 | 5 | 3 |
| 3 | Provenance, signing, federation | 10 | 7 | 3 |
| 4 | SAST and CI hardening | 7 | 4 | 3 |
| 5 | Observability and governance | 8 | 5 | 3 |

Forty-four controls, twenty-nine on by default. The shape is intentional: the
default-on set is what a small team can adopt without standing up infrastructure,
and each phase keeps a few advanced controls off until someone asks for them.

## What actually enforces a phase

`ControlDef.phase` is a plain `u8`. There is no newtype, no constructor and **no
runtime validation anywhere**. Nothing in production code checks it.

What holds the model together is tests:

- One asserts control ids are unique, that every `phase` is in `1..=5`, and that
  every summary is non-empty.
- Another asserts every phase holds at least three controls, so a phase cannot
  quietly empty out.
- A third asserts the shipped compliance map's phase for each control equals the
  registry's, so the map cannot drift from the registry it describes.

The consequences of an out-of-range phase are therefore silent omission rather than
a loud failure. Both `sscsb status` and `sscsb report` iterate `1..=5`, so a
control declaring phase 6 would never be printed by either, and the generated
config's title lookup has explicit arms for phases 1 through 4 with a catch-all
that maps everything else to the Phase 5 title — so it would be filed under Phase 5.
Two tests are the only thing standing between the registry and that behaviour.

## Registry order is load-bearing

The generated `.sscsb/config.toml` emits a phase banner whenever a control's phase
**differs from the previous control's**, not when a phase is first seen. That makes
the order of the `CONTROLS` array part of the contract: inserting a phase-2 control
between two phase-3 controls would emit the phase-2 banner twice and the phase-3
banner twice.

Nothing asserts that `CONTROLS` is sorted by phase. The existing config test checks
that every control's section and options are present, not their order or grouping.
This is a genuine gap rather than a subtlety, and it is worth knowing before you
add a control — see [adding a control](adding-a-control.md).

A smaller wrinkle in the same area: the five phase **titles** written into the
generated config live in `src/config.rs` and are worded differently from the section
comments in the registry. Phases 1 and 5 agree; 2, 3 and 4 do not. The generated
config is the only place a phase title appears at runtime, so that file's wording is
the one users actually see.

## Phases at runtime

`sscsb status` is the phase view, and it is unusually permissive about what it needs:

- **It does not require a config.** It runs in any git repository, printing
  `MISSING — run \`sscsb init\`` and resolving each control's enabled state from the
  registry default.
- **It probes tools live.** For each tool a control declares, it reports `ok` or
  `missing` via `tools::is_available`, which is stricter than a PATH lookup: the
  binary must be found *and* answer its version probe. A present-but-unspawnable or
  silent binary reports missing, which is what stops a decoy file named after a tool
  satisfying a control. See
  [external tools and degradation](../runtime/external-tools-and-degradation.md).
- **Hook integrity is printed once**, above the phase listing, rather than repeated
  per control.

`sscsb report` groups by phase too, and adds framework mappings — see
[compliance mapping](compliance-mapping.md).

Both print bare `Phase 1`…`Phase 5` headers with no titles, so the titled version
exists only in the generated config.

## Phases mapped onto this wiki

The wiki is organised by what a control does at runtime and which subsystem owns it,
because several phases mix owners. This table is the bridge.

| Phase | Where its material lives here |
|---|---|
| 1 — Local source integrity | [commit-integrity/](../commit-integrity/git-hooks.md) for hooks, signer policy, trailers and the server-side gate; [gittuf ref policy](../commit-integrity/gittuf-ref-policy.md) |
| 2 — Dependencies and vulnerabilities | [dependencies/](../dependencies/manifests-and-package-trust.md) for package trust, scanning, SBOM, VEX and endpoint exposure |
| 3 — Provenance, signing, federation | [provenance/](../provenance/artifact-signing.md) for signing, release attestations and receipts; [github/federated-credentials.md](../github/federated-credentials.md) for Octo STS |
| 4 — SAST and CI hardening | [code-scanning/](../code-scanning/sast.md) for SAST, CodeQL and fuzzing; [github/ci-hardening.md](../github/ci-hardening.md) for Harden-Runner and friends |
| 5 — Observability and governance | [governance/](../governance/project-declarations.md) for declarations and external services |

## Source map

| Concern | Location |
|---|---|
| `ControlDef.phase`, the registry bands | `src/controls.rs` |
| `phase_controls` accessor | `src/controls.rs` |
| Phase banners and titles in generated config | `src/config.rs`, `default_config_toml` |
| Phase grouping in `status` | `src/cli.rs`, `cmd_status` |
| Phase grouping in `report` | `src/compliance.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib registry_ids_unique_and_phases_valid every_phase_has_controls
```
