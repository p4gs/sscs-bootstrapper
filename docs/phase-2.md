# Phase 2 — Know your dependencies

You cannot secure what you cannot enumerate. Phase 2 answers three questions
continuously: *what is in this project*, *what is known to be wrong with it*, and —
the question the AI era added — *is this package even real?*

| Control | What it does | Backing tool | Default |
|---------|--------------|--------------|---------|
| `sbom` | CycloneDX (default) or SPDX SBOM | Syft | on |
| `vuln-scan` | Vulnerabilities, secrets, misconfigurations | Trivy + OSV-Scanner V2 | on |
| `scorecard` | Scores the repository's own security posture | Scorecard (CI) | on |
| `renovate` | Dependency updates, digest-pinned, lockfile maintenance | Renovate | on |
| `package-trust` | Existence checks, typosquat heuristics, human approval | (native) | on |
| `grype` | SBOM-first vulnerability scanning | Grype | off |
| `socket-firewall` | Malicious-package blocking at install time | Socket | off |

## SBOM

```sh
sscsb sbom                          # CycloneDX JSON → .sscsb/out/sbom.cdx.json
sscsb sbom --format spdx-json
```

Syft does the work. `sscsb` picks the format, runs it against the repository,
validates that the output is actually a well-formed BOM of the requested flavor,
and writes it where the rest of the pipeline expects to find it — the scanner, the
attestation step in [phase 3](phase-3.md), Dependency-Track and GUAC in
[phase 5](phase-5.md).

An unsupported `--format` is an error, not a silent fallback to the default.

## Vulnerability scanning

```sh
sscsb scan                          # Trivy + OSV-Scanner
sscsb scan --grype                  # also Grype, against a fresh SBOM
sscsb scan --vex path/to/vex.json   # suppress with OpenVEX
```

Two scanners, because they disagree usefully. **Trivy** is broad: OS packages,
language dependencies, secrets, and IaC misconfigurations in one pass.
**OSV-Scanner V2** is lockfile-exact and maps to the OSV database, which is the
one upstream ecosystems actually publish into.

One detail that matters more than it should: **Trivy exits 0 even when it finds
critical vulnerabilities.** Its exit code tells you whether Trivy ran, not whether
your project is clean. A CI job that trusts Trivy's exit status is a CI job that
never fails. `sscsb` parses the JSON and gates on the findings — the exit code is
used only to detect that the tool itself broke. (OSV-Scanner differs again: `0`
clean, `1` findings, `128` no packages found. These are not interchangeable, and
treating them as such is how scanners get quietly disarmed.)

Findings are gated against a configurable threshold:

```toml
[controls.vuln-scan]
enabled = true
fail_on = "high"      # critical | high | medium | low
```

## Package trust — the AI-era control

A model will confidently tell you to install a package that does not exist. If an
attacker has *registered* that hallucinated name — "slopsquatting" — the
suggestion becomes an install becomes an execution. And a package named `tokoi` is
one keystroke from `tokio`, which is the oldest trick in the registry.

`sscsb deps` addresses all three:

```sh
sscsb deps baseline           # approve everything currently in your manifests
sscsb deps check              # existence + typosquat, against the live registries
sscsb deps check --offline    # skip network lookups; heuristics still run
sscsb deps approve npm:left-pad
sscsb deps list
```

**Existence.** Every package is checked against its own public registry —
crates.io, npm, PyPI, the Go module proxy, RubyGems. A package that is *not found*
is reported as a likely hallucination or slopsquatting target, and must not be
approved without verification. This is a network call; `--offline` skips it, and an
inconclusive lookup is reported as inconclusive rather than assumed fine.

**Typosquat proximity.** A new package name within one edit of a popular package
in the same ecosystem is flagged, with the name it shadows. The distance is
**Damerau**-Levenshtein, not plain Levenshtein — because the single most common
typosquat shape is an adjacent transposition (`tokoi` for `tokio`, `reqeusts` for
`requests`), which plain Levenshtein scores as distance *2* and would wave straight
through. Hyphen/underscore confusion (`serde-json` for `serde_json`) is caught
separately.

**Human approval.** New packages introduced by a **staged** manifest change are
compared against the previous revision and against your approved baseline. Anything
new and unapproved blocks the commit — and if the commit is AI-assisted, it needs
the `AI-Dependency-Review: approved` trailer *as well*. Approval is an explicit,
recorded human act.

This is why the first thing to do after `sscsb init` is `sscsb deps baseline`:
without it, your existing dependencies look brand new and the first commit is
blocked. That is the control working, and it is also mildly annoying, which is why
it is step 2 of the printed next-steps.

## Scorecard and Renovate

Both are CI-side and installed by `sscsb init` as SHA-pinned workflows.

**Scorecard** grades the repository itself — branch protection, pinned
dependencies, dangerous workflow patterns, signing, and so on. It is the outside
view of everything the other phases do from the inside.

**Renovate** ships with `config:recommended`, plus:

- `helpers:pinGitHubActionDigestsToSemver` — updates keep actions pinned to
  **digests**, with the human-readable version in a trailing comment. Renovate
  bumping you from a pinned SHA to a floating tag would quietly undo
  [phase 1](phase-1.md)'s Actions audit; this is the setting that prevents it.
- `security:openssf-scorecard` — surfaces each dependency's Scorecard rating in the
  PR, so an update to a package with a collapsing posture is visible at review
  time.
- `osvVulnerabilityAlerts` — vulnerability-driven updates from OSV.
- `lockFileMaintenance` — keeps the lockfile fresh, which is what makes
  lockfile-exact scanning meaningful.

## The optional two

**Grype** (`sscsb enable grype`) scans the SBOM rather than the source tree. If
your workflow is SBOM-first — you build a BOM, then reason about it — Grype fits
that shape better than Trivy. For most people it duplicates coverage Trivy already
provides, which is why it is off by default rather than absent.

**Socket** (`sscsb enable socket-firewall`) blocks malicious packages at install
time, catching install-scripts, obfuscated payloads, and telemetry exfiltration
that a CVE database will never list because they were never disclosed — they were
just published. It needs a Socket account, so it is off by default; when enabled
and unconfigured, the control reports `DEGRADED` and tells you what is missing.
