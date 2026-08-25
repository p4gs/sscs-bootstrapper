---
type: Architecture Guide
title: Manifests and package trust
description: Which manifests are read, why a dependency's source decides what may be asked about it, and how the approved-package baseline gates new dependencies.
tags: [dependencies, manifests, typosquat, baseline, renovate]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Manifests and package trust

This is the control that decides whether a dependency entering your build is one
somebody meant to add. It reads manifests, classifies each dependency by **where it
comes from**, checks new ones against an approved baseline, and looks for names that
shadow popular packages.

The single most important idea here is that **the source, not the name, is the trust
unit**.

## What counts as a manifest

Six filenames across five ecosystems, matched **by basename anywhere in the tree**:
`Cargo.toml`, `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod` and
`Gemfile`.

The search universe is **git's index**, not the filesystem. That single choice buys
two things: vendored directories like `node_modules/`, `target/` and `.venv/` are
excluded without an ignore list, and a **staged-new** manifest counts before it has
ever been committed — which is what makes the commit gate possible.

## Source is the trust unit

A dependency is classified `Registry`, `Git`, `Path`, `Alias`, `Url`, `Index` or
other. Only **registry** and **npm alias** sources are resolvable by name against a
public registry — an alias genuinely does install a real registry package.

That guard runs **first and unconditionally**, before any configurable check. The
ordering is deliberate and documented: switching the registry check on must never be
able to reintroduce the confusion.

The confusion is not hypothetical. Resolving path dependencies by name once produced
both errors at once:

- an in-repo crate reported as **"exists on registry"** — a validation that never
  happened, on nothing but a name collision with an unrelated public crate;
- an ordinary sibling-repo path dependency reported as a **likely slopsquatting
  target**, failing the build.

Rather than stay silent about names it declines to resolve, the check emits a note
saying *why* the name was not the thing that resolves the code.

A dependency's trust key combines **name plus source**, so repointing an approved
name at a git URL is a **new** trust unit needing fresh approval. Cargo's `patch` and
`replace` tables are exactly this attack shape — they keep a trusted name and swap the
code behind it — and are classified so they can never read as a plain registry
dependency.

## Parsing, and where it refuses to guess

Each ecosystem's declaration sites are read structurally rather than by pattern where
possible. Two decisions are worth knowing:

**A `pyproject.toml` that announces itself** — through a build system, project,
dependency-groups or tool table — is parsed as TOML and **never line-scanned**. Its
declaration sites include the standard, the Poetry, the PDM, the uv and the Hatch
layouts.

**Go's `// indirect` comment is deliberately not a filter.** Treating it as one would
mean appending eight characters hides a dependency from the gate. The cost is real —
a `go get` pulling new transitive modules now needs them approved — and it is the
honest answer rather than the convenient one.

Only the structured formats can fail to parse; the line-scanned ones cannot, by
construction rather than by omission. An **empty file is a real answer**, not a
failure.

## The baseline, and failing closed

New dependencies are diffed **staged against HEAD** and checked against
`.sscsb/policy/packages.toml`.

The fail-closed rule is asymmetric on purpose: an **unparseable staged** manifest
fails the gate, while an unparseable manifest **at HEAD** does not. History cannot be
fixed, and failing on it would wedge the repository.

The same reasoning covers the baseline file itself. An unreadable baseline blocks,
because deleting it already blocks — and an asymmetry there *is* the bypass. See
[AI provenance trailers](../commit-integrity/ai-provenance-trailers.md), which owns
the commit-gate side.

`deps baseline` is worth calling out as **partial success**: clean packages *are*
written, suspect ones are skipped and named, and it exits 1. Reading that 1 as
"nothing happened" and re-running is a mistake.

## When the registry cannot answer

A lookup that cannot be completed — DNS failure, proxy, outage, offline laptop — is
reported as a **problem**, not a note.

That is the fix for a real hole: the two callers used to disagree, one filing an
inconclusive result as a note and printing `clean` at exit 0. Every hallucinated name
in the manifest reported clean, with the reason buried in a line nobody's CI reads.
One function now decides what a registry outcome means, so the callers cannot drift
again.

`--offline` is the deliberate way to decline the question. The typosquat check still
runs.

## Typosquat heuristics

Distance is **Damerau**-Levenshtein, so an adjacent transposition counts as one edit
— plain Levenshtein scores `tokoi` against `tokio` as two and would miss it. Hyphen,
underscore and case confusion are normalised away.

Two refinements keep it usable:

- **Digit families are exempt** under tight conditions, so `sha1` and `sha3` are not
  squats of `sha2`, while `boto` against `boto3` still is.
- **Membership in the popular list does double duty**: it protects a name *and*
  asserts that name is real. That is why near-identical genuine packages must both be
  listed, or one would be flagged as a squat of the other.

The heuristic runs in three places — check, approval, and the commit gate — which is
why switching it off has to reach all three.

## Renovate

The `renovate` control's entire surface is one config template at the repository
root: digest pinning for actions, OSV vulnerability alerts, weekly lockfile
maintenance, and a concurrency limit.

Its verifier is **shape-only**. It checks the file is present, readable, and a
non-empty JSON object — so a file gutted down to `{"a": 1}` verifies as passing.
Nothing asserts that digest pinning is still configured or that lockfile maintenance
is still enabled. Only the *shipped template* is content-asserted, and only in a unit
test.

Read a passing `renovate` verdict as "a config file is installed", not "your update
policy is intact". The same shape-only contract applies to every template control —
see [CI templates](../bootstrap/ci-templates.md).

## Source map

| Concern | Location |
|---|---|
| Manifest recognition and discovery | `src/deps.rs` |
| Source classification | `src/deps.rs`, `DepSource`, `is_registry_resolvable` |
| Per-ecosystem parsing | `src/deps.rs` |
| Baseline and new-dependency diff | `src/deps.rs`, `new_unapproved_deps` |
| Registry probing | `src/deps.rs`, `registry_problem` |
| Typosquat heuristics | `src/deps.rs` |
| Renovate template and verifier | `templates/configs/renovate.json5`, `src/workflows.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib deps::
```
