---
type: Architecture Guide
title: Endpoint exposure
description: The one control that asks about the developer's machine rather than the repository, and the four ways an empty scan is not a clean one.
tags: [bumblebee, endpoint, machine, profiles, catalog]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Endpoint exposure

Every other dependency control asks about **the repository**. This one asks about
**the machine the work happens on**: is anything installed here — an editor extension,
a browser extension, an agent skill, a locally configured tool server — that appears in
a catalog of known-compromised releases?

Nothing else in the registry looks at that, which is why it exists and why it is
default-off.

## The gating trap it avoids

**Findings do not change the underlying tool's exit code.** A scan that matches a
compromised package exits exactly like a clean one.

So gating on exit status would produce a control that **passes through every compromise
it detects** — the same trap the SAST engine documents, catalogued with the rest in
[the exit-code contract](../runtime/process-execution.md).

## Four ways an empty run is not a clean one

This is the most carefully reasoned part of the control, and the invariant is that
**passing requires criteria, subjects, and completion together**.

**No criteria.** A catalog containing only wildcard version entries is refused
**before the scan runs**, because the shipped matcher requires **exact** version
matches — so such a catalog is a gate that never fires. Measured: an empty catalog
scanned hundreds of thousands of files and reported zero findings at exit zero.

**No subjects.** If nothing was inventoried at all, there was nothing to match.

**No subjects of the right class.** See profiles, below.

**No completion.** A scan that timed out, or that never emitted a summary, has not
finished — and a summary record alone is not proof.

## Endpoint classes, and what is deliberately excluded

The four classes that define "the endpoint" are the ones nothing else covers: tool
server configs, editor extensions, browser extensions, and agent skills.

General package inventories are **deliberately excluded**, because those are already
covered from the repository side by package trust, vulnerability scanning and SBOM
generation. Including them would let a large package inventory satisfy this control
without any of the surfaces it was written for being examined.

## Profiles

Two are reachable from configuration: one scoped to the repository, one covering the
machine's standard locations.

A third, broader profile is **deliberately unreachable from configuration** because it
walks the whole home directory — a decision for a developer at a shell prompt, not
something a repository bootstrapper turns on from a config file it generated.

And an **unrecognised profile name narrows rather than widens**. Configuration can
never increase the blast radius, even by typo.

### The asymmetric verdict

The same "reached none of the endpoint classes" condition yields different verdicts
under different profiles, and the reasoning is worth keeping:

- Under the **repository-scoped** profile it is **degraded** — that profile cannot
  reach those roots by construction, so this is a control pointed at the wrong surface.
  The fix is one config key, and `--strict` should catch it.
- Under the **machine-wide** profile it is **informational** — there is nothing to fix.
  This machine genuinely has none of those roots, and the run honestly verified
  installed packages only.

Reaching even one class passes, naming the classes covered.

## A catalog is required to pass

No catalog configured is **informational**, not passing. An inventory with nothing to
match against is useful context, but it is not a passing security control and must not
be dressed up as one.

sscsb ships **no catalog**. A stale threat feed that reports clean is worse than no feed.

## Dropped subjects weaken the verdict

A subject the scan could not read — a malformed config, an unreadable file — turns an
otherwise clean verdict **degraded** rather than invalidating it. The incident behind
that: a malformed tool-server config was dropped from the scan and the control reported
passing.

Problems are itemised up to a limit and then counted, and informational diagnostics are
counted rather than reprinted.

## Source map

| Concern | Location |
|---|---|
| Tool contract and invariants | `src/bumblebee.rs` module doc |
| Catalog counting | `src/bumblebee.rs`, `count_catalog_entries` |
| Profiles | `src/bumblebee.rs`, profile resolution |
| Endpoint classes | `src/bumblebee.rs`, `ENDPOINT_ROOT_KINDS` |
| Verdict | `src/bumblebee.rs`, `evaluate_scan` |
| Diagnostics | `src/bumblebee.rs`, `parse_diagnostics` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib bumblebee::
```

The policy functions deliberately spawn no subprocess and touch no `PATH`, so they are
exercised directly rather than through a fake tool — see
[building and testing](../development/building-and-testing.md) for why that matters.
