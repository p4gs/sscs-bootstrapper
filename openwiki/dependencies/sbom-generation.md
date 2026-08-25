---
type: Architecture Guide
title: SBOM generation
description: Producing a software bill of materials, validating it is what it claims to be, and one gap in the matcher's output handling.
tags: [sbom, cyclonedx, spdx, grype, syft]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# SBOM generation

`sscsb sbom` produces a software bill of materials for the repository. A second,
default-off control matches that SBOM against a vulnerability database.

## Format is a closed set

Two formats are supported. **An unsupported format is an error raised before the
generator is invoked** — not a silent fallback to the default, which would produce a
document in a format you did not ask for and did not notice.

Precedence is the command-line override, then configuration, then the default.

## The output path is a convention other controls rely on

The path is derived from the chosen format, and it is **the path other parts of the
system read**: the SBOM attestation control defaults to it when binding an SBOM to an
artifact digest. See [release attestations](../provenance/release-attestations.md).

It lands under the generated-output directory, which
[init arranges to be git-ignored](../control-model/repository-state.md) — the SBOM is
regenerated output, not policy.

## Validation after generation

The document is checked against a **format-specific marker** after it is written. A
file that is not the SBOM it claims to be is an error rather than something discovered
later by whatever consumes it.

That is a shape check, not a schema validation, and the page should not imply more.

## The matcher, and one real gap

The vulnerability matcher's **exit code is deliberately ignored**, because it exits
non-zero when findings exceed its own severity threshold — which is a finding count,
not a tool failure. Its output is parsed regardless. That is the same reasoning as the
rest of the [exit-code contract](../runtime/process-execution.md).

**But its output has no report-shape guard.** An empty object, a bare array, or an
unrelated JSON document all read as **zero matches, with no error and no note**. Only
non-JSON fails.

This is worth flagging plainly because it is precisely the defect that *was* fixed for
the two vulnerability scanners, where a wrong-shaped document is now an error rather
than a clean scan. The SBOM-first path has not had the same treatment. If you rely on
this control, do not read "0 matches" as proof of anything without checking the tool
actually ran.

The matcher also **never affects the exit code**. Gating is done solely on the
[vulnerability scanners' report](vulnerability-scanning.md); the matcher's findings are
printed as additional context.

## The controls

Both verify **tool presence only** — a version when the tool is available, a degrade
message when it is not. Neither verdict says anything about the contents of the SBOM
or the quality of the match.

## Source map

| Concern | Location |
|---|---|
| Generation and format selection | `src/sbom.rs` |
| Post-generation validation | `src/sbom.rs`, `validate_sbom` |
| Matcher invocation and parsing | `src/sbom.rs`, `grype_scan` |
| Command wiring | `src/cli.rs`, `cmd_sbom`, `cmd_scan` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib sbom::
```

One test asserts the matcher errors loudly rather than reporting a false clean when
the SBOM it was pointed at does not exist.
