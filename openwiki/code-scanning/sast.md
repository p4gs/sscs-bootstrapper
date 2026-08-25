---
type: Architecture Guide
title: Static analysis
description: How SAST runs, why its severity gate is fail-closed by construction, and what a scan reports about files it could not read.
tags: [sast, opengrep, semgrep, severity, staged-scan]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Static analysis

`sscsb sast` scans the repository with a configurable engine. A second control names a
faster pre-commit-oriented scanner.

**The commit-time path is off by default.** So despite living next to the hooks, the
default runtime is the standalone subcommand plus a CI workflow — which is why this
page sits in code scanning rather than in commit integrity.

## The runner and the verifier cannot disagree

One list of supported engines is consulted by **both**.

That is a fix, not a nicety. The verifier used to detect the configured engine by
falling back to a generic tool lookup for any name it did not recognise — and the tool
registry holds every tool sscsb orchestrates. So configuring an engine that is a real,
installed tool but not a SAST engine made `sscsb verify` report **passing**, printing
that tool's version as its evidence, while `sscsb sast` refused to run at all.

An engine outside the list now **fails** the control with **no version line**, naming
the valid choices.

## The scanner does not scan its own rules

A rule file contains the pattern text it matches, so scanning the ruleset produces
findings about the rules themselves. The rules directory is excluded, and the same
exclusion is written into the CI template for the same reason.

## The severity gate is fail-closed by construction

The list enumerates the **advisory** severities — the ones that do *not* block. Any
label absent from it blocks, including a severity that could not be read at all.

That direction matters. A gate written the other way round — enumerating what blocks —
waved through the **two strictest severities**, both of which the engines accept and
echo verbatim. Enumerating the permissive set means an unfamiliar label is treated as
serious rather than ignored.

Relatedly, a finding whose severity could not be read is recorded as **unrated** rather
than defaulted to a warning level. A schema change upstream would otherwise silently
downgrade every finding.

**An engine that exits zero but reports errors** above informational level is treated
as a failed scan, because the scan itself did not work — regardless of how few findings
it managed to emit.

## Coverage the scan does not have

Files the engine could not read are tracked **separately** from findings, because
dropping them is how a scan of a file nobody read reports clean.

The two paths report them differently, and both are deliberate:

- **At commit time**, an unreadable staged file is a **hard error that short-circuits
  before findings are computed**. The gate covers what is being committed or it does
  not run.
- **In a whole-tree scan**, the unscanned list is printed **before** any finding count,
  because a bare "0 findings" line would say otherwise.

Diagnostic text is truncated and stripped of control characters, because a parse error
quotes the bytes that failed to parse — and those bytes can be binary.

## Staged scanning is shared

The commit-time path uses the **same** staged-file materialisation as the secret
scanners: fail-closed on an unreadable blob, NUL-delimited path enumeration, and raw
bytes rather than lossy decoding. See [git hooks](../commit-integrity/git-hooks.md).

## The companion control is detection-only

The second control here is worth being blunt about: **nothing in the codebase ever
executes its binary.** Its entire implementation is tool detection, so its verdict is
"the tool is installed" and enabling it **changes no scan**.

The registry summary describes an intent that is not yet wired. Knowing that is the
difference between relying on it and not.

## Source map

| Concern | Location |
|---|---|
| Engine list and selection | `src/sast.rs` |
| Rules resolution and self-exclusion | `src/sast.rs` |
| Severity gate | `src/sast.rs`, `blocks` |
| Parsing and diagnostics | `src/sast.rs` |
| Staged scan | `src/sast.rs`, `scan_staged` |
| The controls | `src/sast.rs`, `verify_sast_control`, `verify_sighthound_control` |
| CI template | `templates/workflows/sast-opengrep.yml` |
| Shipped ruleset | `templates/rules/sscsb-default.yaml` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib sast::
```
