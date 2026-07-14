---
task: Extend sscsb with hardware-backed / remote-signer commit signing for AI agents
slug: sscsb-agent-signing
project: sscs-bootstrapper
kind: ISA-plan
effort: E4
phase: complete
status: built-and-verified
created: 2026-07-13
council_pressure_tested: true
---

# ISA-Plan — Agent-Signed Commits for `sscsb`

## Context

Across this session we established, with source-verified research, how an AI coding agent can produce *cryptographically signed* commits using non-exportable hardware/remote keys, and how that must work under a Claude Max subscription driving Claude Code **cloud** environments from the iPhone app. This plan captures that whole thread as a buildable extension to `sscsb` (Rust CLI, branch `feat/sscsb-rust-cli`).

The tension this resolves: sscsb's advertised axiom is **"an AI can draft anything; it cannot sign"** — the `ai` signer class is structurally excluded from `allowed_signers` (`src/hooks.rs:184-196`, `docs/signing.md`). The new capability is **"AI agents produce verifiable signed commits under a distinct identity."** These are reconcilable because the *protected-branch* guarantee is enforced by the `class != Human` check (`src/hooks.rs:788`) **independently** of `allowed_signers`. So we can make agent signatures verifiable *as agent signatures* without weakening the human-only rule — but only if we also close a pre-existing hole the council surfaced.

**Council pressure-test (3 agents: Architect, Security Red-Team, Pragmatist) already run.** Their critical findings drove the scope and the anti-criteria below. Two forks were confirmed by the owner: **lean core + docs** (no unmaintained shims), and **ship the server-side CI gate in v1** (because in cloud/mobile the client-side pre-push hook never runs).

## Vision

`sscsb` becomes the tool that lets a solo dev say: *my agent signs its own commits, verifiably, as itself — and that signature can never masquerade as mine, on any branch, on any machine, including the ones I drive from my phone.* Running `sscsb verify agent-signing` reads back exactly which commits were human-signed, agent-signed, or unsigned, and the server-side check makes the policy true even when no local hook ran.

## Out of Scope

- Implementing any cryptography, key hosting, or a signing service — sscsb **orchestrates** named tools, never reimplements them.
- First-class orchestration of cloud-KMS ssh-agent shims (`go-kms-signer`, `iam-ssh-agent`) — lightly maintained, uncheckable release discipline, untestable in CI. Documented pattern only.
- `gitsign` for *commit* signing — no GitHub "Verified" badge, online Fulcio+Rekor dependency, verification model incompatible with the `allowed_signers` architecture. (Sigstore keyless already lives in `provenance.rs` for *artifacts*; it stays there.)
- TPM `TPM2_Certify` attestation and full FIDO-MDS chain verification — no git tooling surfaces the former; the latter has no maintained Rust verifier and permanent MDS-format-drift maintenance cost.
- Native Windows (`nCryptAgent`) — sscsb targets macOS/Linux/WSL; Windows is a footnote.
- macOS Secure Enclave for headless agents — presence-bound; not headless-viable. Documented as rejected.
- Per-commit human co-signing of agent work — accountability lives at the **review/merge boundary** (existing `branch-protection` control), not in per-commit signatures.

## Principles

- **Split the axiom, don't break it.** "AI signs nothing" = two invariants: *protected branches are human-only* AND *agents never use human identities*. Preserve both; make agent signatures verifiable in between.
- **A signature is provenance, never authorization.** A touchless agent key attests "this process had key access," not intent or correctness. The trust boundary is human review at merge.
- **Fail closed; never weaken a control.** New behavior ships default-OFF so today's byte-for-byte behavior is unchanged until explicitly enabled.
- **Honest degrade over fake assurance.** If sscsb didn't *observe* hardware-backedness, it reports `declared, not attested` — never `PASS`.
- **Orchestrate what's pinnable and testable; document the rest.**

## Constraints

- Rust, single crate, existing module layout. Config stays schemaless-per-control via `control_opt_bool/str` (`src/config.rs:42-48`).
- Every orchestrated tool pinned to a concrete version in `src/tools.rs` (never "latest"); every Action SHA-pinned; templates pass sscsb's own `actions-audit`.
- Cross-platform macOS/Linux/WSL with explicit `degrade_message` (`src/tools.rs:211-230`) where a backend is unavailable.
- Feature branch only; PR delivery; AI commit trailers; unsigned agent commits on a non-protected branch. 95%/94% coverage gates (lines/functions) per the repo's CI.
- The server-side gate MUST read signer policy from the **parent commit** (`<ref>^:.sscsb/policy/signers.toml`), never the pushed working tree.

## Goal

Add a default-off **`agent-signing`** control and an evolved signer model so that (1) `ai`-class commits are verifiable as agent-signed on non-protected branches, (2) the human-only protected-branch gate remains provably intact, (3) a SHA-pinned server-side workflow re-verifies signer policy from the parent commit (covering cloud/mobile and self-promotion), and (4) `sscsb verify`/`report` distinguishes human/ci/agent/unsigned per commit — all CI-testable with software keys, with real hardware backends documented and honestly degraded.

## Criteria

Positive:
- [x] ISC-1: `Signer` gains `backend: Option<String>` (tpm|fido2|kms|github-app|piv|software), `attestation_file: Option<String>`, `expires: Option<String>`; parsing round-trips (unit test).
- [x] ISC-2: With `agent-signing` **disabled** (default), `allowed_signers_content` output is byte-identical to today (regression test asserts ai keys still excluded).
- [x] ISC-3: With `agent-signing` **enabled**, an `ai`-class SSH key is emitted so an agent commit verifies `%G?=G` on a feature branch (fixture test with a software ed25519 key classed `ai`).
- [x] ISC-4: New `verify_agent_signing_control` reports, per configured signer: class, backend, expiry status, attestation state (`attested` vs `declared`); FAILs on policy collisions.
- [x] ISC-5: `sscsb verify`/`report` (or a `--signatures` view) labels each commit in a range as human / ci / agent / unsigned.
- [x] ISC-6: New CLI: `sscsb signers list|add|check` and `sscsb agent-key setup --backend github-app|tpm` (mutation logic in a new `src/signers.rs`; parsing/gate stay in `hooks.rs`).
- [x] ISC-7: GitHub-App verification: a check (reusing the `gh api` pattern in `src/audit.rs::verify_branch_protection`) confirms commits on a branch have `verification.verified==true` and committer == the configured app; DEGRADES without `gh`/network.
- [x] ISC-8: One SHA-pinned template `templates/workflows/agent-signing-verify.yml` (Artifact bound to the control) re-checks signer policy from the parent commit; installed/verified via existing `verify_template_control`; passes sscsb's own `actions-audit`.
- [x] ISC-9: `attestation_file` present → `sscsb` records its path + sha256 and reports `hardware_backed: attested (artifact present)`; absent → `declared, not attested`. (Artifact tracking only; no MDS chain verification in v1.)
- [x] ISC-10: `docs/agent-signing.md` (threat model + backend matrix) added; `docs/signing.md` 3-class table and `docs/phase-1.md` updated to the new posture.
- [x] ISC-11: `agent-signing` registered in `CONTROLS` (phase 1, default_enabled:false, tools `["ssh-tpm-agent"]`) with options `require_agent_signatures=false`, `allowed_backends`, `max_key_age_days=90`; wired in `verify_control`; registry tests updated.
- [x] ISC-12: `cargo build --release`, `clippy -D warnings`, `fmt --check`, tests pass; coverage ≥95% lines / ≥94% functions.

Anti (from the red-team — each testable):
- [x] ISC-A1 (S1): A commit that modifies `.sscsb/policy/**` and is signed only by an ai/ci key MUST be rejected by the **server-side** check reading policy from the parent commit. Test: push a commit promoting an ai key to `human` → CI workflow rejects even though the local hook would pass.
- [x] ISC-A2 (S2): The signer loader MUST reject duplicate `principal` across classes. Test: two entries same principal → parse error.
- [x] ISC-A3 (S2): GPG fingerprint match MUST be full-length exact equality, not `ends_with`. Test: `key_id="…DEADBEEF"`, `fp="BEEF"` must NOT match (fixes `src/hooks.rs:781`).
- [x] ISC-A4 (S2): An `ai`-class signature MUST NOT satisfy the protected-branch human+hardware gate under any input. Test: agent-signed commit pushed to `main` → blocked (invariant regression, must hold with the control both on and off).
- [x] ISC-A5 (S3/S4): No protected-branch acceptance path may let an agent signature substitute for the human `Reviewed-by`/`Review-evidence` merge gate (`src/hooks.rs:822-840`). Test: merge commit with AI history + agent signature but no review evidence → blocked.
- [x] ISC-A6 (S5): `attestation_file` MUST never auto-elevate a signer's class or the `hardware_backed` decision used by the gate. Test: presence of an attestation file does not change protected-branch outcome for an ai key.

## Test Strategy

| isc | type | check | tool |
|-----|------|-------|------|
| 1,2,3,A2,A3 | rust unit | parse/generate assertions on `signers.toml` + `allowed_signers` | cargo test |
| 4,5,9,11 | rust unit | `VerifyResult` messages + registry invariants | cargo test |
| 3,A4,A5,A6 | rust integration | software ed25519 keys classed human/ci/ai in tempdir repos (reuse fixture pattern `src/hooks.rs:1780+`, `controls.rs::bootstrapped_ctx`); drive `check_signing_for_range` | cargo test |
| 7 | rust + `gh` | fixture/live: committer + `verification.verified` via `gh api`; DEGRADE path when absent | cargo test + manual |
| 8,A1 | yaml + shell | template installs, passes `actions-audit`; A1 = the workflow's own logic tested against a crafted promoting-commit | cargo test + workflow dry-run |
| 12 | bash | full gate | cargo/clippy/fmt/llvm-cov |

**Untestable-in-CI (honest):** TPM, YubiKey PIV, real KMS. Verification for those = check git-config wiring + agent-socket presence + (if hardware present) one local test-signature roundtrip, else `DEGRADED`. Never emit `PASS` for hardware-backedness sscsb didn't observe.

## Features

| name | satisfies | depends_on | parallelizable |
|------|-----------|------------|----------------|
| F1 signer-model evolution (`hooks.rs`: schema, exact-match, dup-principal reject, gated allowed_signers) | 1,2,3,A2,A3 | — | no (core) |
| F2 `agent-signing` control + verify + per-class report | 4,5,11,A4,A6 | F1 | partial |
| F3 CLI `signers`/`agent-key` (`src/signers.rs`) | 6 | F1 | yes |
| F4 GitHub-App verification (reuse `audit.rs` gh pattern) | 7 | — | yes |
| F5 server-side verify template + parent-commit policy logic | 8,A1,A5 | F1 | partial |
| F6 attestation artifact tracking | 9,A6 | F1 | yes |
| F7 docs (`agent-signing.md`, `signing.md`, `phase-1.md`) | 10 | F1-F6 | yes (agent) |
| F8 tools.rs `ssh-tpm-agent` ToolSpec (detect/degrade only; docs-tier backend) | 11 | — | yes |

## Decisions

- D-1: **New `agent-signing` control, not options on `commit-signing`.** Keeps the human gate's code path untouched and makes the whole capability one toggle; default-off preserves byte-identical behavior (ISC-2).
- D-2: **Single `allowed_signers` file, class-gated emission.** git supports one `gpg.ssh.allowedSignersFile`; ai keys are written *only when the control is enabled*. The human gate never trusts class from this file — it re-checks `SignerClass` from `signers.toml` (`hooks.rs:788`), so co-residence is safe **iff** ISC-A2/A3/A4 hold. (Red-team wanted a separate namespace; the class re-check makes one file safe and simpler, but the anti-criteria are mandatory, not optional.)
- D-3: **Ship the server-side CI gate in v1** (owner-confirmed). It reads policy from `<ref>^` — the only guardrail against self-promotion (S1) and the only thing that works in cloud/mobile where local hooks don't run.
- D-4: **Lean core + docs** (owner-confirmed). First-class: signer model, GitHub-App check (nothing to install — best fit for the Claude-Max cloud/mobile audience: Verified badge, key never on a box), one CI template. Docs-tier: TPM (`ssh-tpm-agent`), YubiKey PIV. Rejected: KMS shims in code, gitsign-for-commits, TPM attestation, nCryptAgent, Secure-Enclave-headless.
- D-5: **Attestation = artifact tracking, not verification, in v1.** Record path + sha256; report `attested (artifact present)` vs `declared`. Full FIDO-MDS verification deferred (no maintained Rust verifier; format-drift tax) — `ssh-keygen -O write-attestation` + FIDO MDS is the documented out-of-band procedure.
- D-6: **`hardware_backed` self-assertion is preserved but no longer auto-upgraded.** Attestation never elevates class/gate outcome (ISC-A6) — prevents "attestation theater" turning a self-lie into a machine-blessed lie.

## Changelog

- conjectured: making ai keys verifiable would weaken the human-only protected-branch rule. refuted by: reading `check_signing_for_range` — the `class != Human` reject at `hooks.rs:788` is independent of `allowed_signers`. learned: the two invariants are separable. criterion now: ISC-A4 asserts the separation holds with the control on and off.
- conjectured: the client-side pre-push hook is a sufficient gate for agent keys. refuted by: red-team S1 — `signers_path` resolves to the working tree (`hooks.rs:127`), which the agent can edit, and cloud/mobile runs no local hook at all. learned: policy must be enforced server-side from the parent commit. criterion now: ISC-A1 + F5.

## Verification

Built on branch `feat/sscsb-rust-cli`. All gates green locally (2026-07-13):

- **Gate (ISC-12):** `cargo build --release --locked` → `sscsb 0.1.0`; `cargo fmt --check` exit 0; `cargo clippy --all-targets -- -D warnings` exit 0; full suite **all green** (280 lib unit + integration suites, 0 failures, after warming the Trivy cache the way CI does); `cargo llvm-cov --ignore-filename-regex '(main|cli).rs' --fail-under-lines 95 --fail-under-functions 94` → **95.68% lines / 94.57% functions**, exit 0.

- **ISC-1 / ISC-2 / A2:** `hooks::tests::parse_signers_round_trips_backend_attestation_and_expiry_fields`, `allowed_signers_is_byte_identical_with_agents_off_and_emits_ai_only_when_on`, `parse_signers_rejects_a_duplicate_principal_across_classes` — all pass.
- **A3 (exact fingerprint):** matcher changed `key_id.ends_with(fp)` → `key_id.eq_ignore_ascii_case(fp)` in `src/hooks.rs`; existing signing tests still pass.
- **ISC-3 / A4 / A5 / A6 (real signatures):** `hooks::tests::agent_signature_verifies_on_a_feature_branch_but_is_blocked_on_a_protected_branch` (%G?=G on feature, blocked on main), `..._even_with_agent_signing_disabled`, `an_attestation_file_never_elevates_an_agent_key_on_a_protected_branch`, `ai_merge_without_review_evidence_is_blocked_even_with_agent_signing_enabled` — all pass. Live: agent commit `%G? = G by agent@ci.example.com`; push to `main` → `PUSH BLOCKED: signed by agent@ci.example.com (class Ai) — protected branch main requires a HUMAN signer`, exit 1.
- **ISC-4 / ISC-9 / ISC-11:** `signers::tests::verify_agent_signing_{passes_for_a_well_formed_agent_signer, degrades_without_an_agent_signer, fails_on_disallowed_and_unknown_backends, fails_on_expired_key_and_missing_attestation, reports_attested_when_the_artifact_exists, fails_on_an_invalid_policy_and_when_hooks_absent}`. Live: `sscsb verify agent-signing` → DEGRADED on a 170-day expiry window (> 90d) with `hardware=declared` and `agent-signing-verify.yml installed`.
- **ISC-5 / ISC-6:** `signers::tests::classify_range_labels_recent_commits`, `add_signer_appends_validates_and_regenerates_allowed_signers`, `add_signer_warns_when_agent_signing_is_disabled`, `describe_signers_lists_configured_entries_and_handles_empty`, `agent_key_setup_guidance_covers_first_class_docs_tier_and_unknown`. Live: `sscsb signers check` → `3d830f7652 agent  signed by agent@ci.example.com`; `sscsb agent-key setup --backend github-app` prints the Verified-badge guidance.
- **ISC-7:** `signers::tests::parse_github_commit_reads_verification_and_matches_committer`, `verify_github_app_commits_reports_verified_and_mismatched_via_stubbed_gh`, `..._degrades_without_a_configured_repo`.
- **ISC-8:** `workflows::tests::every_workflow_template_passes_own_audit` + `every_workflow_template_embeds_harden_runner` now include `agent-signing-verify.yml` (registered Artifact) — pass.
- **ISC-10:** `docs/agent-signing.md` added; `docs/signing.md` + `docs/phase-1.md` updated.
- **A1 (self-promotion / server-side gate):** `signers::tests::verify_policy_changes_accepts_human_and_rejects_ci_and_untrusted` (real signed commits: human-trusted-before-push edit accepted; ci-signed policy edit rejected `only a HUMAN`; stranger-signed edit rejected `not verifiably human-signed`, verified against the *trusted base* allowed_signers, not the pushed tree) + `..._notes_first_push_without_a_trusted_parent`. Live: `sscsb signers verify-policy --base 0..0 --head HEAD` prints the first-push note and exits 0.

Environmental note: two `scan.rs` Trivy tests intermittently segfault on a cold/contended local Trivy DB (Go `unexpected fault address`); they pass once the DB cache is warmed (as CI does via the setup action's pre-warm step). `scan.rs` was not modified by this work.

## Files to touch

- `src/hooks.rs` — signer schema, exact fingerprint match, dup-principal reject, config-gated `allowed_signers` generation, `SIGNERS_TEMPLATE` comment rewrite; new `verify_agent_signing_control`.
- `src/controls.rs` — `agent-signing` `ControlDef` + `verify_control` dispatch arm; registry tests.
- `src/signers.rs` **(new)** — `signers`/`agent-key` mutation logic.
- `src/cli.rs` — subcommand wiring.
- `src/audit.rs` — reuse `gh api` verification pattern for the GitHub-App check.
- `src/workflows.rs` + `templates/workflows/agent-signing-verify.yml` **(new)** — Artifact registration + parent-commit policy logic.
- `src/tools.rs` — `ssh-tpm-agent` ToolSpec (docs-tier).
- `docs/agent-signing.md` **(new)**, `docs/signing.md`, `docs/phase-1.md`.
- `ISA.md` (project) — reconcile these ISCs into the project system-of-record before EXECUTE.

## How to verify end-to-end

1. `cargo test` — unit + integration (software-key fixtures cover class enforcement, collision/expiry rejection, gated allowed_signers, invariant regressions A1-A6).
2. `sscsb init` in a throwaway repo → `sscsb enable agent-signing` → add a software ai-key → commit as agent on a feature branch → `sscsb verify agent-signing` shows `agent`-signed; push same commit to `main` → **blocked**.
3. Install the CI template → craft a commit promoting an ai key to `human` → workflow dry-run **rejects** (reads parent-commit policy).
4. `sscsb verify commit-signing` unchanged; `actions-audit` passes on the new template.
5. Full gate: `cargo build --release && cargo clippy --all-targets -- -D warnings && cargo fmt --check && cargo llvm-cov --fail-under-lines 95 --fail-under-functions 94`.
6. Manual (needs hardware/accounts, honest degrade otherwise): GitHub-App signed commit shows Verified via `gh api`; `ssh-tpm-agent` socket roundtrip on a Linux TPM box.
