# Plan: Hardware-backed / remote-signer commit signing for AI agents (sscsb)

## Resolving the central tension
Split the old axiom into its two real invariants:
1. **Protected branches are human-only.** Already enforced independently of allowed_signers — `check_signing_for_range` (hooks.rs:788) rejects any matched signer with `class != Human` even on a "G" signature. Making ai keys verifiable does NOT weaken this.
2. **Agents never use human identities.** New parse-time validation (fail-closed): reject a policy with duplicate principals across signers or the same `ssh_public_key` appearing under two classes; the gate must also fail if a signature matches >1 signer (today `iter().find()` silently takes the first — a human-principal ai entry could shadow).

New posture: "AI signs *as an agent*, never as a human, and an agent signature never satisfies protected-branch policy." Verifiability upgrade: `allowed_signers_content` emits ai-class keys **only when the new `agent-signing` control is enabled** (one file — git supports a single `gpg.ssh.allowedSignersFile`, set absolute at hooks.rs:69). With it disabled, behavior is byte-identical to today (never-weaken: default off).

## 1. Signer model changes (src/hooks.rs)
- `Signer` gains: `backend: Option<String>` ("fido2"|"tpm"|"kms"|"github-app"|"software"), `attestation_file: Option<String>` (repo-relative path to `ssh-keygen -O write-attestation` blob + challenge), `expires: Option<String>` (ISO date; expired ai signers excluded from allowed_signers and gate → fail-closed).
- `allowed_signers_content(signers, include_ai: bool)`; `regenerate_allowed_signers` reads the `agent-signing` enabled flag from config (thread `&Config` through, callers at hooks.rs:760 and init).
- `parse_signers`: add duplicate-principal / cross-class key-reuse rejection; ai entries with `hardware_backed=true` but no `backend` get a verify warning.
- `check_signing_for_range`: keep human-only protected logic untouched. Improve the "G but class!=Human" message to say agent-signed commits belong on feature branches behind PR review. New optional gate (option `require_agent_signatures`, default false): on **non-protected** branches, a commit whose trailers declare `AI-Assisted: true` must be signed by a matching ai-class signer (status G + class==Ai + not expired). Runs in pre-push for all branches, not just protected ones (extend `pre_push` dispatch).

## 2. Controls (src/controls.rs)
New `ControlDef` (Phase 1, after `ai-receipts`):
```
id: "agent-signing", phase: 1, name: "Agent commit signing",
summary: "AI agents sign with distinct hardware/remote-backed keys; verifiable, never valid on protected branches",
default_enabled: false, tools: &["ssh-tpm-agent"],
default_options: &[("require_agent_signatures","false"), ("allowed_backends","\"tpm,fido2,kms,github-app\""), ("max_key_age_days","90")]
```
Dispatch arm → `crate::hooks::verify_agent_signing_control(ctx, cfg)`: reports ai signer count, per-signer backend/expiry/attestation presence, whether keys are emitted to allowed_signers, FAILs on principal/key collisions, Degraded on software-backend ai keys when policy expects hardware. Update `verify_signing_control` (hooks.rs:1018-1035) to note agent-signing status; add `agent-signing` to the default-off list in `optional_service_controls_default_off...` test.

## 3. Attestation scope
- **In scope:** FIDO2 attestation *artifact tracking* — `signers check` verifies attestation_file + challenge exist, records sha256, and reports `hardware_backed: attested (artifacts on file)` vs `asserted`. Structural only.
- **Deferred (non-goal for this iteration):** cryptographic FIDO MDS chain verification (CBOR parsing + metadata service — reimplementation territory, violates orchestrate-don't-reimplement) and TPM2_Certify verification (no git tooling surfaces it). Both documented as manual out-of-band procedures in docs.

## 4. Backend tiers
- **First-class (orchestrated):** (a) Linux TPM via `ssh-tpm-agent` — add pinned ToolSpec in tools.rs; `sscsb agent-key setup --backend tpm` detects agent, guides key creation, emits git-config lines, appends signer entry, regenerates allowed_signers. (b) GitHub App server-side signing — nothing local to run; ships as workflow template + docs (the merge-boundary pattern).
- **Docs-only:** AWS/GCP KMS ssh-agent shims (lightly maintained upstream — don't pin), Windows nCryptAgent/PCP, YubiKey PIV touch-policy=never, sigstore gitsign (no Verified badge; note SIGSTORE_ID_TOKEN + private Fulcio).
- **Explicitly rejected in docs:** macOS Secure Enclave for headless agents (presence-bound); signing inside cloud sandboxes (keys stay out by design).

## 5. CLI surface (src/cli.rs + new src/signers.rs)
`sscsb signers list|add|check` (check = policy lint: collisions, expiry, attestation, orphaned keys) and `sscsb agent-key setup --backend <tpm|github-app> [--principal]`. Signer file mutation logic lives in new `src/signers.rs`; parsing/gate stay in hooks.rs to minimize churn.

## 6. Templates (src/workflows.rs + templates/)
One new Artifact: `templates/workflows/merge-boundary-sign.yml` — human-review-gated workflow that merges approved PRs via the GitHub API under a GitHub App identity (server-side Verified signature; key never on any box), using `{{repo_slug}}`/`{{default_branch}}`, SHA-pinned, Harden-Runner step, passing sscsb's own actions audit. Verified generically via `verify_template_control`.

## 7. Docs
- New `docs/agent-signing.md`: threat model, backend decision matrix, per-backend setup, "why agents can't sign to main," attestation procedures.
- Update `docs/signing.md` (3-class table: ai class is now verifiable-but-never-privileged), `docs/phase-1.md`, SIGNERS_TEMPLATE comment block (hooks.rs:110-125 — currently says "they never sign").

## 8. Tests (no hardware needed — ssh signing is backend-agnostic)
Reuse the real-key fixtures pattern (hooks.rs:1780+ generates ed25519 keys and signs commits): software keys registered as `class = "ai"` stand in for TPM keys. Cases: ai key emitted to allowed_signers iff control enabled; ai-signed commit on protected branch still blocked (regression for invariant 1); ai-signed commit on feature branch passes; `require_agent_signatures` blocks unsigned AI-Assisted commits and human-key-signed AI commits; duplicate principal / shared key rejected at parse; expired ai signer excluded + gate fails; verify_agent_signing_control outcomes; existing controls.rs registry tests extended.

## 9. File touch list
src/hooks.rs (schema, allowed_signers, gate, verifiers, tests) · src/controls.rs (ControlDef + dispatch) · src/signers.rs (new) · src/cli.rs · src/tools.rs (ssh-tpm-agent) · src/workflows.rs + templates/workflows/merge-boundary-sign.yml · src/config.rs (only if regenerate needs Config plumbing) · docs/agent-signing.md, docs/signing.md, docs/phase-1.md.

## 10. Non-goals
Implementing any signing/crypto; running or hosting agent keys; FIDO MDS / TPM cryptographic attestation verification; gitsign/KMS-shim orchestration (docs only); Secure Enclave headless; per-commit human co-signing (accountability stays at the review/merge boundary per branch-protection control); weakening any existing default.
