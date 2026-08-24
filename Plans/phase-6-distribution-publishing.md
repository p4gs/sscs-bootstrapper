# Phase 6 — Distribution & Publishing

## Context

sscsb today hardens the repo, dependencies, CI, and GitHub-Release artifacts (phases 1–5, 34 controls) but stops at the registry door: nothing covers *publishing* to crates.io, npm, PyPI, Homebrew, Chocolatey, or WinGet, and nothing addresses the farthest-left link — the maintainer's publishing account and its credentials. That's the Shai-Hulud/chalk-debug attack class: phish a maintainer, steal a long-lived token, publish malware under a trusted name. Owner directive: cover distribution across those ecosystems, pushing as far left as possible (phishing-resistant MFA on publishing accounts, short-lived and/or IP-allowlisted API keys, trusted publishing). Owner chose: **full build in one increment**, **registry probes in `verify` by default** (with air-gapped opt-out).

2026 registry reality this plan is built against (web-verified this session):

- **npm**: classic tokens permanently revoked 2025-11-19; granular tokens support CIDR IP-allowlists and have a 90-day max expiry for write; Trusted Publishing (OIDC) GA; `npm publish --provenance`; `npm profile get` exposes `tfa.mode`.
- **crates.io**: Trusted Publishing GA July 2025 (`rust-lang/crates-io-auth-action`, 30-min exchanged tokens); scoped tokens with expiry; identity = GitHub account, so GitHub MFA is the left edge. No artifact-level provenance yet.
- **PyPI**: Trusted Publishers mature; 2FA mandatory for all uploaders; PEP 740 attestations auto-generated under trusted publishing, queryable via the integrity API. `uv`/`pip`/twine are clients; `bun` publishes to the npm registry — clients fold into their registry target.
- **Homebrew**: PR-based (core) or self-owned tap (a git repo — existing sscsb controls apply to it); formula `sha256` pins artifacts fed by our already-signed GitHub Releases.
- **Chocolatey**: push API key is long-lived; community repo has no real 2FA (open upstream issue) — an honest ecosystem gap to report, not paper over. Checksums in install scripts are required and locally checkable.
- **WinGet**: publish = PR to microsoft/winget-pkgs (GitHub identity again); manifest `InstallerSha256`; Authenticode is the trust anchor.
- **Compliance anchor**: CISA/OpenSSF *Principles for Package Repository Security* (4 maturity levels; phishing-resistant MFA at upper levels) — cited in map notes; SLSA/SSDF/CRA carry the formal mappings.

## Architecture

**New module `src/distribution.rs`** owns everything: a `PublishTarget` enum (what this repo *publishes* — distinct from `deps::Ecosystem`, which is what it *consumes*), file-based detection, the six phase-6 verifiers, the `distribution.toml` policy parser, the `sscsb dist` subcommand impls, and a **separate `DIST_ARTIFACTS` template table with a detection-gated installer** (publish templates must NOT go into `workflows::ARTIFACTS` — `install_all` gates only on control-enabled, and installing `publish-npm.yml` into a repo with no `package.json` violates the per-target no-op rule). `init::bootstrap` calls `distribution::install_templates(ctx, cfg)` after `workflows::install_all` (src/init.rs:63); init is idempotent so re-running picks up new targets.

Detection (file-based, no network):

| Target | Trigger |
|---|---|
| CratesIo | `Cargo.toml` with `[package]` (pure `[workspace]` excluded) |
| Npm | `package.json` without `"private": true` (bun folds in) |
| PyPi | `pyproject.toml` with `[project]` (uv/pip fold in) |
| Homebrew | `Formula/*.rb` / `Casks/*.rb` / repo named `homebrew-*` |
| Chocolatey | tracked `*.nuspec` |
| WinGet | winget manifest YAML set (`*.installer.yaml` + locale) |

`[targets]` in distribution.toml can override each to `on`/`off` (default `auto`).

## The six controls (all phase 6, all default-on, all skip cleanly when target undetected)

Every check **verifies with tool evidence, degrades explicitly naming why, or reports a self-attestation AS an attestation** — attestations document, they never upgrade an outcome (the signers.rs ISC-A6 invariant, reused verbatim via `pub` `evaluate_expiry` at src/signers.rs:45-63 and `evaluate_attestation` at :79-96).

1. **`publish-targets`** — inventory. Runs detection, reports every target + triggering manifest. Outcome `Info`; FS errors → `Degraded`.
2. **`trusted-publishing`** (`tools: ["gh"]`, opt `environment = "release"`) — for each OIDC-capable detected target (crates.io/npm/PyPI): matching publish template installed (missing → `Fail`, "run `sscsb init`"); workflow has `id-token: write`, references the pinned TP action, and references **no** long-lived registry token secret (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, `PYPI_API_TOKEN`, `TWINE_PASSWORD` → `Fail` with TP remediation). Then `gh api repos/{slug}/environments/release` for environment-protection rules — gh/auth/slug absent → `Degraded` never `Fail` (the verify_branch_protection precedent, src/audit.rs:534-551).
3. **`maintainer-mfa`** (`tools: ["gh","npm"]`, opt `max_attestation_age_days = "180"`) — the far-left control:
   - crates.io/WinGet/homebrew targets → GitHub identity: `gh api user` → `two_factor_authentication` true → Pass; `null` → Degraded naming `gh auth refresh -s read:user`; gh absent → degrade_message.
   - npm → `npm profile get --json` → `tfa.mode`: `auth-and-writes` → Pass; weaker → **Fail**; npm missing/unauthenticated → Degraded.
   - PyPI → structural Pass (registry-mandated 2FA, labeled as a registry-enforced fact).
   - Chocolatey → `Info` honest gap (no 2FA exists upstream; unfixable by the maintainer, must not permanently fail `--strict`).
   - *Phishing-resistant* (WebAuthn-only) claims are not exposed by any registry API → `[[account]]` attestation with `attested` date; fresh → documented; **expired → Fail** (stale claim is actionable, same as expired agent keys).
4. **`publish-tokens`** (opt `max_token_age_days = "90"` — npm's granular-write maximum) — committed credential files (`.npmrc` `_authToken`, `.pypirc` password, tracked credential TOML) → hard `Fail`; publish/release workflows using long-lived token secrets where an OIDC path exists → `Fail`. Declared-token attestations (`[[token]]`: choco push key, deliberate npm granular token) carry `scoped`/`cidr_allowlist`/`issued`/`expires`/`stored_in`; expiry evaluated via `evaluate_expiry`; expired → Fail, over-window → called out.
5. **`publish-provenance`** (opt `probe_registry = "true"`) — anonymous `ureq` probes (the registry_exists pattern, src/deps.rs:742-761) of the **live registry** for the latest published version: npm attestations endpoint and PyPI integrity API → provenance present → Pass / absent → `Fail` ("publish via trusted publishing / `--provenance`") / never-published → skip. crates.io → `Info` (no artifact provenance exists in the ecosystem yet; TP is the max). Homebrew → local `sha256`-pin check (artifacts are our signed GitHub Releases — phase 3 covers those, untouched). Network error → `Degraded` naming the endpoint; `probe_registry=false` → `Info` "local checks only".
6. **`dist-manifests`** — local checksum integrity: formula `sha256` per URL, nuspec + `chocolateyinstall.ps1` `$checksum`, winget `InstallerSha256`; missing for a detected target → `Fail`. `[signing]` Authenticode attestation (not locally verifiable on macOS/Linux) with optional cert expiry.

34 → 40 controls; phase 6 has 6 (≥3 floor at controls.rs:477 satisfied).

## Templates (3 new; brew/choco/winget get docs guidance instead — a choco workflow template would launder the long-lived-key anti-pattern)

`templates/workflows/publish-crates.yml` (crates-io-auth-action OIDC exchange → `cargo publish`), `publish-npm.yml` (setup-node → `npm publish --provenance --access public`, no token), `publish-pypi.yml` (build sdist+wheel → `pypa/gh-action-pypi-publish`, PEP 740 auto-attested). All: release-published trigger + workflow_dispatch, `permissions: {id-token: write, contents: read}`, `environment: release`, harden-runner (pinned `bf7454d0…`) first step of every job, all actions SHA-pinned w/ version comments, values through `env:` never `${{ }}` in run bodies, explicit failure on empty input ("nothing to publish" ≠ success). A mirrored ∀-test module in distribution.rs runs `audit::audit_workflow` + harden-runner + placeholder + no-baked-identity checks over `DIST_ARTIFACTS` (duplicating workflows.rs:324-374 style, not modifying it).

## `distribution.toml` (new policy file, `.sscsb/policy/`, all-commented template like signers.toml)

Sections: `[targets]` (auto/on/off per target) · `[[account]]` (target, identity, `mfa = webauthn-only|webauthn|totp|none`, `attested` date, optional `attestation_file`) · `[[token]]` (target, purpose, scoped, cidr_allowlist, issued, expires, stored_in) · `[signing]` (authenticode + expiry). Parse errors are a hard Fail (signers.rs:119-130 precedent). Installed `write_if_absent` from init.rs.

## `sscsb dist` subcommand (NOT a publish wrapper)

`dist status` (detected targets + posture summary) and `dist check` (runs phase-6 verifiers incl. probes — break-glass preflight before an emergency manual publish). A `sscsb publish` wrapper was considered and **rejected**: git hooks can't intercept `npm publish` (hooks.rs:20 — git events only) so a wrapper is advisory theater; the doctrine of this phase moves publishing INTO CI via OIDC; and real publish flows (OTP, workspace ordering) are a support tarpit.

## File-touch list

New: `src/distribution.rs` · `templates/workflows/publish-{crates,npm,pypi}.yml` · `docs/phase-6.md`.

Modified (additive): `src/controls.rs` (6 defs + 6 dispatch arms; **:470** `1..=5`→`1..=6`; **:477** same; default-ON list :501-507) · `src/config.rs` (**:163-169** explicit `5 =>`/`6 =>` arms, fallback → `"Phase ? — uncategorized"` + new test that no control renders the fallback — fixes the latent mislabel bug) · `src/cli.rs` (**:364** loop; `Dist` subcommand) · `src/compliance.rs` (**:30** loop) · `src/init.rs` (distribution.toml + install_templates after :63) · `src/lib.rs` (module) · `src/tools.rs` (ONE new ToolSpec: `npm`, pin resolved at implementation time; cargo/uv/choco/winget not needed — verifiers are file/ureq-based; gh already registered) · `templates/compliance/map.json` (6 entries, phase 6, SSDF PS.3/PS.1/PO.3 + CRA Annex I (2)(d)/(2)(f) + SLSA where honest; PRSP cited in notes — no fifth framework column) · `tests/tool_orchestration.rs` (both exhaustive lists :775-810, :914-949) · `tests/integration.rs` (init-file list :89-113 + distribution.toml; NEW negative assertion: publish workflows NOT installed in a target-less repo) · `README.md` (34/5 → 40/6 + phase table row) · `docs/example-walkthrough.md` (counts + new init/verify lines re-captured from the real binary — the D-16/D-17 doc-drift class; never hand-edit).

## Verification

- Pure-fn fixtures: `detect_targets` matrix (workspace-only Cargo.toml, private package.json, build-system-only pyproject…), `tfa.mode` parser (null/auth-only/auth-and-writes), registry-payload classifiers (embedded npm-attestation + PyPI-integrity JSON), manifest checksum parsers, policy parsing with pinned `today`.
- Hermetic degrade paths: gh/npm absent → exact degrade_message, never Fail/panic; unauthenticated → Degraded naming the scope.
- Integration: existing dynamic ∀-tests (every-control-dispatches, every-control-enable+verify) cover the six for free once registered; add repo-with-package.json → init installs publish-npm.yml → trusted-publishing shape checks pass; delete template → Fail; target-less repo → skips.
- Live: probe URL construction unit-tested; network exercised via `dist check` integration tests that skip cleanly offline; `probe_registry=false` asserted hermetically.
- Gates: `cargo fmt --check` / `clippy --all-targets -- -D warnings` / full `cargo test` (with `GIT_CONFIG_GLOBAL=/dev/null` locally — signing-hermeticity gotcha) / coverage ≥95/95 via existing CI gate. Dogfood: `sscsb init` + `verify` on this repo (detects CratesIo target → installs publish-crates.yml — real dogfood of the new phase). Ship per house rules: commit (agent-signed), push, watch CI green.

## Build order

1. Skeleton slice: distribution.rs + detection + `publish-targets`/`trusted-publishing`(shape-only)/`dist-manifests` + all five 1..=5 breakage fixes + map entries + test lists → full suite green.
2. Templates + init wiring + mirrored ∀-tests.
3. distribution.toml parsing + `publish-tokens` + attestation reporting.
4. `maintainer-mfa` (npm ToolSpec, gh/npm probes, account attestations).
5. `publish-provenance` probes + environment-protection check.
6. `sscsb dist`, docs/phase-6.md, README/walkthrough re-capture.

## Risks

- npm trusted-publisher *configuration* isn't anonymously queryable — the published-artifact provenance probe is the observable proxy (documented in control messages).
- `gh api user` MFA field needs `read:user`; handle `null` → Degraded with remediation, never assume.
- Verify latency: two probe classes added; 10s ureq timeouts + `probe_registry=false` opt-out; owner accepted network-in-verify default.
- Monorepo multi-package publishing: v1 detects root + one level; documented limitation.
- Chocolatey `Info`-not-Degraded for the ecosystem 2FA gap is a judgment call (unfixable-by-maintainer shouldn't permanently fail `--strict`); flagged here for review.
