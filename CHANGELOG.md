# Changelog

All notable changes to `sscsb` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) and is pre-1.0 — the
CLI surface and `.sscsb/config.toml` schema may still change between minor
versions.

## [Unreleased]

### Fixed

- **A severity we could not determine ranked below `low`, so real advisories
  could not breach the gate.** `severity_rank` ended in `.unwrap_or(0)`: every
  string that was not one of `low|medium|high|critical` ranked *beneath the
  weakest severity*, and therefore could not breach any threshold. Three
  consequences, all measured against live tools:
  - `parse_osv` read severity only from `/database_specific/severity`, a field
    RUSTSEC and PYSEC records do not carry — 13 of 25 findings in an
    `osv-scanner 2.4.0` run landed as `unknown` and could not breach
    `fail_on = "high"`. Severity is now recovered from the fields those records
    *do* populate: the OSV `severity` array's CVSS vectors (scored with the
    CVSS v3.0/v3.1 base-score formula) and `affected[].database_specific.cvss`.
    Where a record states a rating more than one way, the highest wins.
  - GHSA's `MODERATE` ranked 0 because it is not the literal string `medium`.
    The two vocabularies are now bridged.
  - What remains genuinely unrated breaches *every* threshold rather than
    passing as `low`, and is reported as a note with its count. The way to
    waive one is a VEX statement — visibly, like every other suppression.
  A CVSS v4.0 vector is left undetermined rather than guessed at; scoring it
  needs the v4 macro-vector tables, and inventing a band is how a gate starts
  lying.
- **A typo'd `fail_on` silently became the strictest setting.** `fail_on =
  "error"` ranked 0, i.e. `low`, i.e. everything breaches — a broken gate that
  looks like a working one. A `fail_on` that is not a severity is now an error
  naming the valid values. Case and stray whitespace (`"HIGH "`) are still
  accepted as the threshold their author meant.
- **Five controls reported `PASS` for checks that never ran.** `sscsb`'s value
  rests on a green `verify --strict` meaning the named controls actually work,
  and `--strict` only escalates `DEGRADED` — so a false `PASS` sailed straight
  through CI. Each of these now reports `DEGRADED`, with the reason:
  - `branch-protection` passed when the GitHub rules API answered for **no**
    configured branch (e.g. a slug that does not exist): the failing-query arm
    pushed a message and `continue`d without touching the verdict.
  - `scorecard` passed when `gh` was absent, when no repo slug could be
    resolved, and when the code-scanning query failed — while every other
    gh-dependent control in the same run correctly degraded.
  - `package-trust` reported an unparseable `.sscsb/policy/packages.toml` as
    `approved baseline present (0 package(s))` and passed.
  - `dependency-track` passed on a non-empty `url` string plus `DTRACK_API_KEY`
    merely being *set*; `verify` now probes `GET /api/version` (5s bound, key in
    the header) so an unreachable server or a rejected key degrades instead of
    passing and then failing at upload time.
  - `model-signing` and `gittuf` passed with the declared tool absent, while
    `sscsb status` said `…:missing` in the same session. An installed workflow is
    not a signature, and a `refs/gittuf/*` ref is a name anyone can create with
    `git update-ref`.
- **The new-package commit gate failed OPEN on a corrupt policy file.** Deleting
  `.sscsb/policy/packages.toml` already failed closed (every dependency reads as
  unapproved), but corrupting it printed "package-trust check skipped" and
  returned `0` — one appended line switched the gate off. It now fails closed,
  with `fail_open = true` as the single explicit opt-out, matching the
  secret-scan and SAST arms of the same hook.

### Changed

- `scorecard` reports `INFO` rather than `PASS` when the live scan returns open
  Scorecard findings. sscsb does not re-gate on another scanner's rubric — each
  finding is routed to the sscsb control that owns it — but printing open
  findings under a `PASS` verdict manufactured assurance.

## [0.2.0] — 2026-08-24

The distribution release: `sscsb` becomes installable by someone who is not its
author, and drivable by an AI agent that has never seen it.

### Added

- **Homebrew install.** `brew install p4gs/p4gs/sscsb`. The release now builds
  real binaries for `aarch64-apple-darwin`, `x86_64-apple-darwin`, and
  `x86_64-unknown-linux-gnu`; v0.1.0 shipped a single Linux target.
- **`AGENTS.md`** — the machine-facing contract: every subcommand, the exit-code
  semantics (`0` pass / `1` gate failed / `2` tool error), the five verdicts and
  why `DEGRADED` is not `PASS`, the config model, and the AI-cannot-sign
  invariant. Pinned to the binary by `tests/agents_md.rs`, so a renamed
  subcommand breaks the build rather than silently misleading an agent.
- **Claude Code skill** at `.claude/skills/sscsb/SKILL.md`, routing
  supply-chain-security asks to the right subcommand.
- **`sscsb signing`** (`status` / `setup` / `verify`) — the multi-environment
  commit-signing model. Verifies and converges the *developer's environment*,
  where signing actually breaks, rather than only the repository's policy.
- **Five OpenSSF controls**: OSPS Baseline, Security Insights, Model Signing,
  gittuf, and the Best-Practices Badge.
- **`bumblebee`** — endpoint exposure scanning, as a phase-2 control.
- **Threat & Control Model** diagram and table in the README.

### Changed

- Release pipeline builds a full platform matrix and refuses to publish an
  incomplete set — a partial platform set is a failed release, not a small one,
  because a formula pinned to a missing asset installs nothing. Checksums are
  computed centrally so every digest comes from one implementation.
- The 1Password SSH key is registered as an approved human signer.
- Control count: 37 → 44.

### Fixed

- **VEX suppression was too broad.** A `not_affected` statement suppressed
  matching findings regardless of which product or ecosystem it was scoped to,
  so a suppression written for one component could silently hide a real finding
  in another.
- **AI-merge review gating checked for the wrong thing.** The hook validated
  that a review-evidence trailer *key was present* rather than that the evidence
  it named was real, which a well-formed but empty trailer satisfied.

### Documentation

- The hermetic test invocation is documented, because the suite builds real git
  repos and verifies real signatures — the host's git identity leaking in
  produces mass failures that look exactly like regressions and are not:

  ```sh
  GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
  ```

## [0.1.0] — 2026-07-21

Initial release. Five phases, 37 controls, orchestrating TruffleHog, Gitleaks,
Syft, Trivy, OSV-Scanner, Cosign, slsa-verifier, OpenGrep, Scorecard, Octo STS,
Harden-Runner, Dependency-Track, and GUAC behind one policy engine.

- Phase 1 — commit integrity: secret scanning at pre-commit and pre-push,
  human-only signing on protected branches, branch-protection verification,
  Actions auditing, AI-provenance commit trailers.
- Phase 2 — dependencies: CycloneDX SBOMs, vulnerability scanning, Scorecard,
  Renovate with digest pinning, package-trust and typosquat heuristics.
- Phase 3 — provenance: keyless signing, SBOM and provenance attestations bound
  to artifact digests, SLSA Build L3, short-lived credentials, Harden-Runner.
- Phase 4 — code analysis: OpenGrep SAST, CodeQL, extended workflow auditing.
- Phase 5 — continuous posture: Dependency-Track, GUAC, OpenVEX, and a
  machine-readable control → SLSA/SSDF/CRA map behind `sscsb report`.

[0.2.0]: https://github.com/p4gs/sscs-bootstrapper/releases/tag/v0.2.0
[0.1.0]: https://github.com/p4gs/sscs-bootstrapper/releases/tag/v0.1.0
