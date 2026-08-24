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
| `bumblebee` | Known-compromised packages, MCP servers, extensions and agent skills present on the endpoint | Bumblebee | off |
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

A `fail_on` that is not one of those four is a configuration error, not a
default. It used to rank below `low` — which meant `fail_on = "error"` gated on
*everything*, a misconfigured threshold wearing the appearance of a strict one.

**A severity we could not determine is not a low severity.** Advisory databases
disagree about where they put a rating: GHSA states a label (`MODERATE`, which
is this scale's `medium`), while RUSTSEC and PYSEC records carry no label at all
and state a CVSS vector instead — in the OSV `severity` array, or under
`affected[].database_specific.cvss`. `sscsb` reads all of them and scores v3
vectors, because a finding that reads `unknown` cannot be gated on, and reading
one field only left 13 of 25 findings in a real `osv-scanner` run unrateable.
What is still genuinely unrated after that breaches **every** threshold and is
reported with its count. The way to stand one down is a VEX statement, which
says so out loud:

```sh
sscsb vex create --vuln RUSTSEC-2024-0375 --product pkg:cargo/atty \
  --status not_affected --justification vulnerable_code_not_present
```

### Suppression is allowed. Silence is not.

The scanners take configuration out of the repository without being asked:
Trivy reads `trivy.yaml` and `.trivyignore` from the directory it scans,
OSV-Scanner reads `osv-scanner.toml` from the tree. Committing the file is the
whole install step. On one fixture a `trivy.yaml` of `severity: [CRITICAL]`
took a scan from 3 findings to 1, and a single `[[IgnoredVulns]]` entry took
OSV-Scanner from 8 to 6 — and the report said nothing at all.

`sscsb` does not override these files. They are legitimate, and this repo's own
`.trivyignore` is the example: two container rules that cannot model an
OSS-Fuzz build image, waived with per-ID rationale in the file. Overriding a
deliberate waiver would break real decisions and push people into disabling
scanning altogether, which is worse than the waiver. What was wrong was never
that suppression exists — it was that it was invisible.

So `sscsb` inherits the waiver and states it, the way it already states VEX
suppressions:

```text
note: scanner config: trivy.yaml is present and trivy loads it automatically, and it
      NARROWS this scan: severity=[CRITICAL] (only these severities are reported at all)
note: scanner config: .trivyignore is present with 1 entr(ies): CVE-2021-25900
suppressed: CVE-2021-25900 (smallvec) — trivy ignored via .trivyignore: reviewed 2026-08
suppressed: RUSTSEC-2021-0003 and 2 aliases — osv-scanner filtered out: not reachable here
```

Two layers, because one is not enough. The `suppressed:` rows come from the
scanners themselves — Trivy's `--show-suppressed`, OSV-Scanner's stderr (which
is the only place it says so; its JSON never mentions a filtered vulnerability,
even under `--all-vulns`). The `note:` lines come from reading the config files
directly, which is the *only* signal for `trivy.yaml` narrowing: findings
excluded by a `severity` allowlist or a `skip-dirs` entry are filtered before
they are findings, and Trivy reports nothing about them even when asked to show
suppressions. `sscsb verify` prints the same inventory. It does not change the
verdict — a documented waiver is a decision, not a failure — so if you want a
gate on it, `verify --strict` plus a review of that inventory is the place.

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

## Endpoint exposure — the machine, not the repository

Every other control in this phase asks a question about the *repository*. **Bumblebee**
(`sscsb enable bumblebee`) asks one about the *machine the work happens on*: is anything
installed here that appears in a catalog of known-compromised releases?

That is a different surface, and it is the one the 2024-2026 worm campaigns actually
landed on. Bumblebee inventories npm, PyPI, Go, RubyGems and Composer packages — and,
more to the point, **MCP server configs, editor extensions, browser extensions, agent
skills, and Homebrew receipts**. Nothing else in `sscsb` looks at those.

```sh
sscsb enable bumblebee
# .sscsb/config.toml
#   [controls.bumblebee]
#   profile = "baseline"     # user-global roots (default) | "project" to scope to this repo
#   catalog = ""             # path to a JSON exposure catalog, or a directory of them
sscsb verify bumblebee
```

It reads only static files — no `npm ls`, no `pip show`, no source-file reads — and the
binary is Go with a zero-dependency `go.mod`.

**Things worth knowing before you trust the output:**

- **Findings do not change bumblebee's exit code.** A scan that matches a compromised
  package exits `0`, exactly like a clean one. `sscsb` parses the NDJSON record stream
  rather than the exit status; a control that gated on `$?` would pass through every
  compromise it found.
- **A scan that cannot be shown to have finished is a `FAIL`, not a pass.** "Zero
  findings" and "the scan died early" produce the same empty result, so `sscsb` requires
  bumblebee's end-of-run `scan_summary` record before it will report clean.
- **Catalogs use `schema_version` `"0.1.0"`, and wildcards do not work.** Upstream's
  README documents `"0.2.0"` and `versions: ["*"]`; the shipped v0.1.2 binary rejects the
  former outright and silently matches nothing on the latter. Matching is exact
  `(ecosystem, name, version)`. A catalog written from the README is a gate that never
  fires — so `sscsb` refuses to count a wildcard-only entry as criteria and fails the
  control rather than reporting a clean scan that checked nothing.
- **What the scan could NOT read is only ever said on stderr.** stdout carries findings
  and the summary; `record_type=diagnostic` rows go to stderr, and a config bumblebee
  cannot parse appears there at `warn` while the run still exits `0` with a `complete`
  summary. `sscsb` reads that stream on every run — not just failed ones — so a clean
  scan that dropped a subject reports `DEGRADED` naming the file it could not read,
  rather than `PASS`. `--strict` gates on it.
- **`profile = "project"` scopes the scan to the repository**, which for most repos means
  none of the MCP / extension / agent-skill roots are reached, and for a Rust repo means
  nothing is inventoried at all. If a scan inventories zero artifacts the control `FAIL`s
  rather than calling the endpoint clean. The default is `baseline` for that reason.
- **"It inventoried something" is not the same as "it inventoried the endpoint."** The
  artifact count is one aggregate number, and a machine whose only populated root is the
  Homebrew Cellar can clear it with thousands of receipts while no MCP config, editor or
  browser extension, or agent skill was ever opened — the four classes this control
  exists for. `sscsb` reads the summary's `roots[].kind` list, reports which of those
  classes a clean run actually covered, and refuses to call a run that reached none of
  them a `PASS`: `DEGRADED` under `profile = "project"` (fixable — point it at
  `baseline`), `INFO` under `baseline` (this endpoint simply has none of those roots, so
  the run verified installed packages only).

`sscsb` ships **no** catalog. A stale threat feed that reports clean is worse than no
feed, so the catalog is yours to point at — upstream publishes them under `threat_intel/`.
With no catalog configured the control reports `INFO` and says so, because an inventory
with nothing to match against is context, not a passing security control.

Off by default: it needs a catalog you may not have, which is the same reason
Dependency-Track and GUAC are off. Note also that bumblebee has **no Cargo/Rust
ecosystem** — for a Rust repository the value is the endpoint surface, not the lockfile.

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
