---
type: Architecture Guide
title: Project declarations
description: The machine-readable security declaration sscsb validates structurally, and two worksheets it deliberately says almost nothing about.
tags: [security-insights, openssf, badge, baseline, governance]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Project declarations

Three controls install files that **declare** things about a project rather than
enforce anything: a machine-readable security-metadata document, and two worksheets
for external assessment programmes.

The interesting engineering is in how carefully sscsb limits what it claims about each.

## The security declaration

This one gets real validation, but scoped: sscsb performs the **structural sanity
check**, while full schema conformance belongs to the upstream validator — and the
verdict says so rather than implying it did more.

### Reading it safely

Two bounds exist because a declaration is untrusted input like any other file.

**A byte ceiling**, because this is a metadata file rather than a data file. Oversized
or non-UTF-8 fails.

**An alias-expansion budget**, counted on the parser's **event stream** so a document
that expands enormously is refused *before* the loader materialises it. This is not
theoretical: a small file of nested aliases drove verification past several gigabytes
of memory. Counting on the stream is what makes refusal possible at all — by the time
the loader has built the graph, the damage is done.

### What it checks

Structural problems are **accumulated and reported together** rather than one per run:
the schema version, the required sections, and any field whose *name* marks it as a
URL.

One deliberate looseness: a schema version **inside a known major** is accepted, so a
point release upstream does not turn a good file red.

### The placeholder verdict

A file that clears every structural check but still contains **placeholder text** is
reported as **informational**, not passing, with messages naming what to replace.

And a subtle consequence handled explicitly: placeholder text sitting *inside* a URL
field is routed to the placeholder branch rather than the malformed-value branch —
otherwise bootstrapping would install a starter file that its own verifier fails.

Note that informational contributes nothing to the exit code, so a freshly bootstrapped
repository whose declaration is still all placeholders exits zero **even under
`--strict`**. See [the verdict contract](../control-model/registry-and-outcomes.md).

## The two worksheets

Both ship markdown, and markdown is verified as **opaque**. The verdict states its own
limit in the output: present and non-empty, with no machine-checkable structure,
because **its substance is a human judgement sscsb does not assert**.

The only floor is emptiness. A worksheet gutted to a single line still verifies as
sound — an intentional, **labelled** weakness rather than an oversight.

That is the right call for this kind of artifact. Inventing a structure to check would
mean asserting something about a document whose value is entirely in whether a person
filled it in thoughtfully, and a tool that graded that would be grading itself.

Both worksheets are candid about what they cannot do. One notes that sscsb cannot
register a badge on your behalf, because that needs your own forge authorisation. The
other notes that the higher maturity levels and the governance families include human
attestations sscsb cannot auto-satisfy, and points at `sscsb report` for the live view.

See [compliance mapping](../control-model/compliance-mapping.md), which owns that
report — including two registry summaries that overstate what these controls do.

## Source map

| Concern | Location |
|---|---|
| Declaration verifier | `src/openssf.rs`, `verify_security_insights` |
| Read bounds and alias budget | `src/openssf.rs` |
| URL-shaped field walk | `src/openssf.rs` |
| Worksheet verification | `src/workflows.rs`, `verify_template_control` |
| Templates | `templates/configs/security-insights.yml`, `best-practices-badge.md`, `osps-baseline.md` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib openssf::
```

One test refuses an alias bomb in under five seconds; a companion asserts ordinary
anchor reuse still passes, so the budget cannot become a false positive.
