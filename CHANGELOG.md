# Changelog

All notable changes to `sscsb` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) and is pre-1.0 — the
CLI surface and `.sscsb/config.toml` schema may still change between minor
versions.

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
