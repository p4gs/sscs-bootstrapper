---
type: Architecture Guide
title: OpenVEX suppression
description: The full lifecycle of a VEX waiver — written by one module, consumed by another — and why a bare product name deliberately reaches across ecosystems.
tags: [vex, openvex, suppression, waivers]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# OpenVEX suppression

A vulnerability scanner reports what is *present*. VEX records what is *exploitable*.
This page follows a waiver across the seam: `sscsb vex create` writes it,
`sscsb scan --vex` consumes it, and the two are in different modules with different
requirements.

That asymmetry is the most important thing here — **the verifier checks fewer
conditions than the consumer**, so a document can verify as fine and suppress
nothing.

## Writing a statement

`sscsb vex create` takes a vulnerability, a product, a status and an optional
justification, and writes a single-statement OpenVEX document into the generated
output directory.

Two constraints at write time:

- **The status set is closed** to four values: not affected, affected, fixed, and
  under investigation.
- **A `not_affected` status requires a justification.** That is the OpenVEX
  specification's rule, and sscsb enforces it rather than emitting an unjustified
  waiver.

The author is derived from the repository's origin, and the document is stamped with
a timestamp.

## Consuming one

Only **two of the four statuses suppress anything**: not affected, and fixed.
Affected and under-investigation are read and skipped — they are statements *about* a
vulnerability, not waivers of it.

Then four conditions gate every suppression:

1. The document must be valid JSON carrying an OpenVEX context, or it is a hard
   error.
2. The status must be one of the two suppressing values.
3. The vulnerability must be named.
4. **The product list must be non-empty.**

That fourth one is worth dwelling on. A statement naming no products suppresses
nothing, and says so in the notes. The reasoning: a product-free assertion would mean
"this vulnerability affects nothing anywhere" — a document-wide wildcard nobody
intended to write.

## Matching, and the bare-name decision

Product matching requires **ecosystem agreement only when both sides declare one**.
An exact id match wins first; otherwise both sides are parsed as package URLs and
compared.

When either side declares no ecosystem — a bare product id, or a finding with no
ecosystem such as a secret or misconfiguration — matching **falls back to name
granularity**. A bare `openssl` waiver will therefore suppress an `openssl` finding in
every ecosystem.

This is deliberate, and the argument is worth repeating because it looks like a hole:
a bare id is a namespace-free assertion with **no ecosystem to cross**. Requiring one
would turn every bare-name statement into a silent no-op — which is precisely the
failure this module exists to prevent. A waiver that suppresses nothing and says
nothing is worse than one that reaches too far.

The compensating control is **visibility, not prevention**. Each suppression row
names the ecosystem of the finding it removed, so a bare-name waiver reaching three
ecosystems prints as **three distinct rows**, not one repeated line. The reach is
readable rather than hidden.

The gate that does bite: a waiver that *does* declare an ecosystem cannot cross into
another. A cargo-scoped waiver will not suppress an operating-system package of the
same name for the same vulnerability.

## Why ecosystem normalisation is load-bearing

Three vocabularies disagree systematically:

- a package URL names the **registry**;
- one advisory database names the registry its own way;
- one scanner names the **manifest it read the dependency out of**.

So a single registry answers to many labels: a Python dependency arrives as `pip`,
`poetry`, `pipenv` or `uv` depending on which lockfile was read. Without aliasing,
the canonical `pkg:pypi/...` form — the one the documentation recommends — matched
**no Python finding that scanner can produce**. A waiver that suppressed nothing, and
said nothing about it.

One invariant keeps aliasing safe: **it only ever loosens a gate**, so every entry
must be a genuine one-registry-many-labels identity, never a mapping between two
different registries. A waiver for one registry must still not reach another's package
of the same name.

Every run reports how many findings were suppressed out of how many — **including
when the count is zero**, which is how you notice a waiver that is not doing what you
thought.

## The control, and what it does not check

The `openvex` control reports `Info` rather than `Pass` when no VEX documents exist.
It used to be an unconditional `Pass` that examined nothing — the one control in the
registry that could not fail — and a control that cannot fail is not evidence of
anything.

Per document, it checks two things: the OpenVEX context, and a non-empty statement
list.

**Those are necessary conditions for suppression, not sufficient ones.** The consumer
requires four. So a document created with an under-investigation status, or one
hand-edited to an empty product list, **verifies as passing while suppressing
nothing**. If you are relying on a waiver, confirm it in the scan's own suppression
count rather than in this control's verdict.

## Source map

| Concern | Location |
|---|---|
| Writing statements | `src/observability.rs`, `vex_create` |
| The control | `src/observability.rs`, `verify_openvex_control` |
| Consumption and matching | `src/scan.rs`, `apply_vex` |
| Product matching | `src/scan.rs`, `vex_product_matches` |
| Ecosystem aliasing | `src/scan.rs`, `normalize_ecosystem` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib vex
```

The test worth reading first asserts that a bare-name waiver removes findings in
three different ecosystems **and** that all three printed rows are distinct.
