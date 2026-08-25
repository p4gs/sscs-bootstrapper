//! The control registry: every SSCS control sscsb knows about, its phase,
//! secure default, required external tools, and default config options.
//! `.sscsb/config.toml` is generated FROM this table, so config keys and
//! controls can never drift apart.

use crate::config::Config;
use crate::context::Ctx;

#[derive(Debug, Clone, Copy)]
pub struct ControlDef {
    pub id: &'static str,
    pub phase: u8,
    pub name: &'static str,
    pub summary: &'static str,
    /// Secure-by-default: on unless the control needs external services,
    /// accounts, or explicitly-optional tooling.
    pub default_enabled: bool,
    /// External tool ids (see `tools::TOOLS`) this control orchestrates.
    pub tools: &'static [&'static str],
    /// Extra per-control options emitted into the generated config
    /// (key, literal TOML value).
    pub default_options: &'static [(&'static str, &'static str)],
}

pub const CONTROLS: &[ControlDef] = &[
    // ───────────────────────── Phase 1 — Local source integrity ─────────────
    ControlDef {
        id: "secrets",
        phase: 1,
        name: "Secret scanning hooks",
        summary: "TruffleHog + Gitleaks block secrets at pre-commit and pre-push",
        default_enabled: true,
        tools: &["trufflehog", "gitleaks"],
        default_options: &[
            ("trufflehog", "true"),
            ("gitleaks", "true"),
            ("pre_push_range_scan", "true"),
        ],
    },
    ControlDef {
        id: "commit-signing",
        phase: 1,
        name: "CommitSigningGuard",
        summary: "Hardware-backed, human-only signing enforced on protected branches at pre-push",
        default_enabled: true,
        tools: &[],
        default_options: &[
            ("require_hardware_backed", "true"),
            ("require_review_evidence_for_ai_merges", "true"),
        ],
    },
    ControlDef {
        id: "agent-signing",
        phase: 1,
        name: "AI agent commit signing",
        summary: "Verifiable AI-agent signatures (distinct identity, never valid on protected branches); off by default",
        default_enabled: false,
        tools: &["ssh-tpm-agent"],
        default_options: &[
            ("require_agent_signatures", "false"),
            ("allowed_backends", "[\"github-app\", \"tpm\", \"fido2\", \"kms\", \"piv\", \"software\"]"),
            ("max_key_age_days", "90"),
        ],
    },
    ControlDef {
        id: "signing-model",
        phase: 1,
        name: "Five-environment signing model",
        summary: "Machine-wide signing posture: human enclave lane, distinct agent identity, cloud/web/Codespaces guidance",
        default_enabled: true,
        tools: &[],
        // No options. `agent = "claude-code"` and `human_backend = "secretive"`
        // used to be emitted here as "generalization seams" and were read by
        // nothing: `Environment::ALL` has one hard-coded AI variant and
        // `SigningPaths` hard-codes Secretive's container path, so a user who set
        // `human_backend = "1password"` still got Secretive probes and no
        // indication their setting was ignored. Honouring them means implementing
        // multi-backend and multi-agent support — a feature, not a default — and
        // until that exists an inert key is worse than no key, because it reads as
        // a control the user has set.
        default_options: &[],
    },
    ControlDef {
        id: "branch-protection",
        phase: 1,
        name: "Branch protection verification",
        summary: "Verify GitHub protected-branch rules (PRs, no force-push, signatures, checks)",
        default_enabled: true,
        tools: &["gh"],
        default_options: &[],
    },
    ControlDef {
        id: "actions-audit",
        phase: 1,
        name: "Actions pinning & permissions audit",
        summary: "Flag mutable action refs and missing/over-broad workflow permissions",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "gittuf",
        phase: 1,
        name: "gittuf ref protection",
        summary: "Signed, forge-independent policy over who may change which git refs, verified in CI; off by default (advanced)",
        default_enabled: false,
        tools: &["gittuf"],
        default_options: &[],
    },
    ControlDef {
        id: "ai-trailers",
        phase: 1,
        name: "AI commit trailers",
        summary: "Validate AI-Assisted / AI-Tool / AI-Model / AI-Role commit trailers",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "ai-dep-gate",
        phase: 1,
        name: "AI dependency & command gate",
        summary: "Extra gating when AI-assisted commits add dependencies or shell commands",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "pr-template",
        phase: 1,
        name: "AI-provenance PR template",
        summary: "PR template asking whether AI generated code/tests/dependencies/docs",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "ai-receipts",
        phase: 1,
        name: "AI provenance receipts",
        summary: "Optional cryptographic receipts linking commits to AI tool/model/role",
        default_enabled: false,
        tools: &["cosign"],
        default_options: &[
            ("sign_with_cosign", "false"),
            // Empty means "no signature policy configured". A receipt that IS
            // signed but has no identity to check the signature against fails
            // verification rather than passing quietly — see
            // `provenance::verify_receipt_signature`.
            ("cosign_identity", "\"\""),
            (
                "cosign_issuer",
                "\"https://token.actions.githubusercontent.com\"",
            ),
        ],
    },
    // ───────────────────────── Phase 2 — Dependencies & vulnerabilities ─────
    ControlDef {
        id: "sbom",
        phase: 2,
        name: "SBOM generation",
        summary: "Syft SBOM in CycloneDX (default) or SPDX JSON",
        default_enabled: true,
        tools: &["syft"],
        default_options: &[("format", "\"cyclonedx-json\"")],
    },
    ControlDef {
        id: "vuln-scan",
        phase: 2,
        name: "Vulnerability scanning",
        summary: "Trivy (vuln+secret+misconfig) and OSV-Scanner V2 (lockfile-exact)",
        default_enabled: true,
        tools: &["trivy", "osv-scanner"],
        default_options: &[("fail_on", "\"high\"")],
    },
    ControlDef {
        id: "scorecard",
        phase: 2,
        name: "OpenSSF Scorecard",
        summary: "Scorecard workflow scoring repository security posture",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "renovate",
        phase: 2,
        name: "Renovate onboarding",
        summary: "Automated dependency updates with digest pinning + lockfile maintenance",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "package-trust",
        phase: 2,
        name: "Package trust gate",
        summary: "Existence validation, human approval for new packages, typosquat heuristics, lockfile-exact installs",
        default_enabled: true,
        tools: &[],
        default_options: &[("registry_check", "true"), ("typosquat_check", "true")],
    },
    ControlDef {
        id: "bumblebee",
        phase: 2,
        name: "Bumblebee endpoint exposure scan",
        summary: "Inventory installed packages, MCP servers, editor/browser extensions and agent skills; match against known-compromise catalogs",
        default_enabled: false,
        tools: &["bumblebee"],
        // `baseline`, not `project`: the artifact classes this control exists to
        // find (MCP configs, editor/browser extensions, agent skills, Homebrew
        // receipts) live under user-global roots. `project` pins the scan to the
        // repository, where none of them are — and for a Rust repo it inventories
        // nothing at all, since bumblebee has no cargo ecosystem.
        default_options: &[("profile", "\"baseline\""), ("catalog", "\"\"")],
    },
    ControlDef {
        id: "grype",
        phase: 2,
        name: "Grype (optional)",
        summary: "SBOM-first vulnerability scanning where Syft+Grype is preferred",
        default_enabled: false,
        tools: &["grype"],
        default_options: &[],
    },
    ControlDef {
        id: "socket-firewall",
        phase: 2,
        name: "Socket Firewall (optional)",
        summary: "Malicious-package detection/blocking at install time",
        default_enabled: false,
        tools: &[],
        default_options: &[],
    },
    // ───────────────────────── Phase 3 — Provenance, signing, federation ────
    ControlDef {
        id: "sigstore-signing",
        phase: 3,
        name: "Sigstore keyless signing",
        summary: "Cosign keyless signing + SBOM/provenance attestations bound to digests",
        default_enabled: true,
        tools: &["cosign"],
        default_options: &[],
    },
    ControlDef {
        id: "slsa-provenance",
        phase: 3,
        name: "SLSA Build L3 provenance",
        summary: "slsa-github-generator reusable workflow (tag-pinned per its trust model)",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "github-attestations",
        phase: 3,
        name: "GitHub artifact attestations",
        summary: "GitHub-native build provenance (attest-build-provenance) — additive to Cosign/SLSA, verified with `gh attestation verify`",
        default_enabled: true,
        tools: &["gh"],
        default_options: &[],
    },
    ControlDef {
        id: "sbom-attestation",
        phase: 3,
        name: "GitHub SBOM attestation",
        summary: "GitHub-native SBOM attestation bound to the artifact digest (actions/attest, sbom-path) — additive, verified with `gh attestation verify`",
        default_enabled: true,
        tools: &["gh"],
        default_options: &[],
    },
    ControlDef {
        id: "model-signing",
        phase: 3,
        name: "OpenSSF Model Signing",
        summary: "Sign & verify ML model artifacts with Sigstore keyless signing; applies when models are present (off by default)",
        default_enabled: false,
        tools: &["model-signing"],
        default_options: &[],
    },
    ControlDef {
        id: "provenance-verify",
        phase: 3,
        name: "Provenance verification gates",
        summary: "slsa-verifier + cosign verification required before promote/deploy/publish",
        default_enabled: true,
        tools: &["slsa-verifier", "cosign"],
        // The builder whose provenance this repo trusts, e.g.
        // "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/\
        // generator_generic_slsa3.yml@refs/tags/v2.0.0". Empty means unset, and
        // `sscsb provenance verify` refuses to run unpinned — see
        // `provenance::verify_artifact`.
        default_options: &[("builder_id", "\"\"")],
    },
    ControlDef {
        id: "release-immutability",
        phase: 3,
        name: "Immutable releases (draft-then-publish)",
        summary: "Draft-then-publish release.yml so assets attach before publish — compatible with GitHub release immutability (Settings -> Releases); opt-in, supersedes the modular release-sign/slsa flow",
        default_enabled: false,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "octo-sts",
        phase: 3,
        name: "Octo STS federation",
        summary: "Short-lived repo-scoped GitHub credentials replacing long-lived PATs",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "harden-runner",
        phase: 3,
        name: "Harden-Runner",
        summary: "StepSecurity Harden-Runner egress/tamper monitoring in every workflow",
        default_enabled: true,
        tools: &[],
        // No options. `egress_policy = "audit"` was emitted here and read by
        // nothing: every workflow template hard-codes `egress-policy: audit`, and
        // `render` substitutes only repo_slug/default_branch/project. The value
        // this key appeared to offer is `block`, which harden-runner enforces
        // against an `allowed-endpoints` allowlist that sscsb cannot synthesise —
        // a generated `block` with no allowlist breaks the first `actions/checkout`
        // in every workflow. Offering that from a config key is a trap, so egress
        // policy stays a per-repo decision made in the workflow file.
        default_options: &[],
    },
    ControlDef {
        id: "witness",
        phase: 3,
        name: "Witness (optional)",
        summary: "Richer in-toto attestation capture and policy around build steps",
        default_enabled: false,
        tools: &["witness"],
        default_options: &[],
    },
    // ───────────────────────── Phase 4 — SAST & CI hardening ────────────────
    ControlDef {
        id: "sast",
        phase: 4,
        name: "SAST (OpenGrep default)",
        summary: "OpenGrep rule-driven SAST in pre-commit and CI; Semgrep selectable",
        default_enabled: true,
        tools: &["opengrep", "semgrep"],
        default_options: &[
            ("engine", "\"opengrep\""),
            ("pre_commit", "false"),
            ("rules", "\".sscsb/rules\""),
        ],
    },
    ControlDef {
        id: "sighthound",
        phase: 4,
        name: "Sighthound (optional)",
        summary: "Ultra-fast local pre-commit SAST layer",
        default_enabled: false,
        tools: &["sighthound"],
        default_options: &[],
    },
    ControlDef {
        id: "codeql",
        phase: 4,
        name: "CodeQL",
        summary: "Deep interprocedural analysis on PRs and default branch",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "fuzzing",
        phase: 4,
        name: "ClusterFuzzLite fuzzing",
        summary: "Continuous fuzzing on PRs (cargo-fuzz + ClusterFuzzLite) — the OpenSSF-Scorecard Rust fuzzing probe; opt-in (needs project fuzz targets)",
        default_enabled: false,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "workflow-audit-extended",
        phase: 4,
        name: "Extended workflow audit",
        summary: "pull_request_target misuse, credential persistence, secret echo, risky actions",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "secure-repo",
        phase: 4,
        name: "StepSecurity secure-repo",
        summary: "Onboarding accelerator via app.stepsecurity.io (web service, not an action)",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "wait-for-secrets",
        phase: 4,
        name: "wait-for-secrets (optional)",
        summary: "Human-in-the-loop secret injection for high-sensitivity workflows",
        default_enabled: false,
        tools: &[],
        default_options: &[],
    },
    // ───────────────────────── Phase 5 — Observability & governance ─────────
    ControlDef {
        id: "dependency-track",
        phase: 5,
        name: "Dependency-Track",
        summary: "Continuous SBOM management platform (self-hosted); sscsb uploads BOMs",
        default_enabled: false,
        tools: &[],
        default_options: &[("url", "\"\""), ("project_name", "\"\"")],
    },
    ControlDef {
        id: "guac",
        phase: 5,
        name: "GUAC ingestion",
        summary: "Supply-chain knowledge graph over SBOMs, attestations, and VEX",
        default_enabled: false,
        tools: &["guacone"],
        default_options: &[],
    },
    ControlDef {
        id: "openvex",
        phase: 5,
        name: "OpenVEX",
        summary: "Generate and ingest VEX for exploitability-aware triage",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "oras",
        phase: 5,
        name: "ORAS OCI storage (optional)",
        summary: "Push SBOMs/attestations to an OCI registry as reference artifacts",
        default_enabled: false,
        tools: &["oras"],
        default_options: &[],
    },
    ControlDef {
        id: "security-insights",
        phase: 5,
        name: "OpenSSF Security Insights",
        summary: "Machine-readable security-insights.yml declaring the project's security practices and reporting channels",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "best-practices-badge",
        phase: 5,
        name: "OpenSSF Best Practices Badge helper",
        summary: "Worksheet pre-filling the passing-badge criteria from installed controls (lifts Scorecard's CII check)",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "osps-baseline",
        phase: 5,
        name: "OSPS Baseline assessment",
        summary: "Maps enabled controls to OpenSSF Project Security Baseline families and adds an OSPS column to `sscsb report`",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
    ControlDef {
        id: "compliance-map",
        phase: 5,
        name: "Compliance map & report",
        summary: "Machine-readable control → SLSA/SSDF/CRA/OSPS/Badge map behind `sscsb report`",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
];

pub fn control(id: &str) -> Option<&'static ControlDef> {
    CONTROLS.iter().find(|c| c.id == id)
}

/// Reject any id that is not a real control, before the caller acts on ANY of
/// them.
///
/// An id nobody recognises is a usage error — exit `2` per `AGENTS.md` — and
/// never a verdict about the repository. `sscsb verify not-a-real-control` used
/// to filter the registry down to nothing, run zero controls, print
/// `verify: 0 failed, 0 degraded` and exit `0`, so a typo in a CI invocation
/// was indistinguishable from a genuine clean run: the tool reported success
/// for a check that never existed. That is the exact false assurance this
/// project exists to eliminate, and it defeated the advice `AGENTS.md` gives
/// agents — read the exit code rather than scraping stdout — because the exit
/// code was the part that lied.
///
/// All-or-nothing on purpose. `sscsb verify secrets not-a-real-control` must
/// not verify `secrets`, report success and leave the typo unmentioned; a
/// partially-understood invocation is not a partially-valid one.
///
/// `enable`/`disable` already rejected unknown ids exactly this way. Both
/// routes share this function so the two can never drift into disagreeing
/// about what a control id is.
pub fn reject_unknown_controls(ids: &[&str]) -> anyhow::Result<()> {
    let unknown: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| control(id).is_none())
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = unknown.iter().map(|id| format!("`{id}`")).collect();
    let valid: Vec<&str> = CONTROLS.iter().map(|c| c.id).collect();
    anyhow::bail!(
        "unknown control{} {}. Valid controls: {}",
        if unknown.len() == 1 { "" } else { "s" },
        named.join(", "),
        valid.join(", ")
    );
}

pub fn phase_controls(phase: u8) -> impl Iterator<Item = &'static ControlDef> {
    CONTROLS.iter().filter(move |c| c.phase == phase)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Degraded,
    Disabled,
    /// Verified as far as locally verifiable; remainder is informational.
    Info,
}

impl Outcome {
    /// The weaker of two outcomes. A control is only as strong as its weakest
    /// piece of evidence, so a shared prerequisite that could not be verified
    /// (hook integrity, say) must drag the control's own verdict down rather
    /// than being reported alongside a cheerful PASS.
    ///
    /// `Disabled` is never folded — a disabled control short-circuits before
    /// any evidence is gathered — so it sits at the strong end by convention.
    pub fn weakest(self, other: Outcome) -> Outcome {
        fn rank(o: &Outcome) -> u8 {
            match o {
                Outcome::Fail => 0,
                Outcome::Degraded => 1,
                Outcome::Info => 2,
                Outcome::Pass => 3,
                Outcome::Disabled => 4,
            }
        }
        if rank(&other) < rank(&self) {
            other
        } else {
            self
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            Outcome::Pass => "PASS",
            Outcome::Fail => "FAIL",
            Outcome::Degraded => "DEGRADED",
            Outcome::Disabled => "disabled",
            Outcome::Info => "INFO",
        }
    }
}

#[derive(Debug)]
pub struct VerifyResult {
    pub control: &'static str,
    pub outcome: Outcome,
    pub messages: Vec<String>,
}

impl VerifyResult {
    pub fn new(control: &'static str, outcome: Outcome, messages: Vec<String>) -> Self {
        VerifyResult {
            control,
            outcome,
            messages,
        }
    }
}

/// Verify one control. Central dispatch so `sscsb verify` and `sscsb report`
/// share behavior; per-control logic lives in the phase modules.
pub fn verify_control(ctx: &Ctx, cfg: &Config, def: &'static ControlDef) -> VerifyResult {
    if !cfg.control_enabled_or_default(def.id) {
        return VerifyResult::new(
            def.id,
            Outcome::Disabled,
            vec!["disabled in .sscsb/config.toml".into()],
        );
    }
    match def.id {
        "secrets" => crate::hooks::verify_secrets_control(ctx, cfg),
        "commit-signing" => crate::hooks::verify_signing_control(ctx, cfg),
        "agent-signing" => crate::signers::verify_agent_signing_control(ctx, cfg),
        "signing-model" => crate::signing_setup::verify_signing_model_control(ctx, cfg),
        "branch-protection" => crate::audit::verify_branch_protection(ctx, cfg),
        "actions-audit" => crate::audit::verify_actions_control(ctx, false),
        "gittuf" => crate::openssf::verify_gittuf(ctx),
        "model-signing" => crate::openssf::verify_model_signing(ctx),
        "security-insights" => crate::openssf::verify_security_insights(ctx),
        "best-practices-badge" | "osps-baseline" => {
            crate::workflows::verify_template_control(ctx, def.id)
        }
        "workflow-audit-extended" => crate::audit::verify_actions_control(ctx, true),
        "ai-trailers" | "ai-dep-gate" => crate::hooks::verify_hook_installed(ctx, def.id),
        "pr-template" => crate::workflows::verify_pr_template(ctx),
        "ai-receipts" => crate::provenance::verify_receipts_control(ctx, cfg),
        "sbom" => crate::sbom::verify_sbom_control(ctx),
        "vuln-scan" => crate::scan::verify_scan_control(ctx),
        "grype" => crate::sbom::verify_grype_control(ctx),
        "bumblebee" => crate::bumblebee::verify_bumblebee_control(ctx, cfg),
        "package-trust" => crate::deps::verify_package_trust(ctx, cfg),
        "scorecard" => crate::scorecard::verify_scorecard_control(ctx, cfg),
        "renovate"
        | "codeql"
        | "fuzzing"
        | "sigstore-signing"
        | "slsa-provenance"
        | "github-attestations"
        | "sbom-attestation"
        | "release-immutability"
        | "octo-sts"
        | "harden-runner" => crate::workflows::verify_template_control(ctx, def.id),
        "provenance-verify" => crate::provenance::verify_provenance_control(ctx),
        "sast" => crate::sast::verify_sast_control(ctx, cfg),
        "sighthound" => crate::sast::verify_sighthound_control(ctx),
        "socket-firewall" => crate::deps::verify_socket_control(ctx),
        "witness" => crate::provenance::verify_witness_control(ctx),
        "secure-repo" => VerifyResult::new(
            def.id,
            Outcome::Info,
            vec![
                "StepSecurity secure-repo is a web service (app.stepsecurity.io), not an action; \
                 run it against this repo to auto-generate hardening PRs. See docs/phase-4.md."
                    .into(),
            ],
        ),
        "wait-for-secrets" => crate::workflows::verify_template_control(ctx, def.id),
        "dependency-track" => crate::observability::verify_dtrack_control(ctx, cfg),
        "guac" => crate::observability::verify_guac_control(ctx),
        "openvex" => crate::observability::verify_openvex_control(ctx),
        "oras" => crate::observability::verify_oras_control(ctx),
        "compliance-map" => crate::compliance::verify_compliance_control(ctx),
        other => VerifyResult::new(
            def.id,
            Outcome::Fail,
            vec![format!("no verifier wired for `{other}` — this is a bug")],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `.rs` file under `src/`, whitespace-collapsed so a rustfmt line
    /// break cannot hide a call from a source scan.
    ///
    /// Source scanning is the only way to assert a *negative* about the code —
    /// "no second copy of this default exists anywhere" — and that negative is
    /// the whole anti-recurrence property here. Nothing weaker catches a default
    /// re-typed into a call site three modules away.
    fn collapsed_sources() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source is readable");
            // Production code only. A key whose only "reader" is an assertion in
            // its own test module is still a key that does nothing at runtime,
            // and every module in this crate puts its `#[cfg(test)]` block last.
            let production = match text.find("#[cfg(test)]") {
                Some(i) => &text[..i],
                None => &text[..],
            };
            let collapsed = production.split_whitespace().collect::<Vec<_>>().join(" ");
            out.push((
                path.file_name().unwrap().to_string_lossy().to_string(),
                collapsed,
            ));
        }
        assert!(
            out.len() > 10,
            "source scan found almost nothing — wrong dir?"
        );
        out
    }

    /// M27. The registry declared `sast` enabled by default while the pre-commit
    /// hook read the same control's enabled state with a hard-coded `false`
    /// fallback, so a config with no explicit `[controls.sast] enabled` key
    /// reported the control ON in `status` and `verify` while the commit gate
    /// silently skipped every commit. Every such literal was a second copy of the
    /// registry that could disagree with it; `Config::control_enabled_or_default`
    /// reads the registry, so no call site needs one. Ban them, and the class
    /// cannot come back.
    ///
    /// (This comment deliberately describes the banned shape instead of quoting
    /// it — a verbatim example here would trip the scanner on its own source.)
    ///
    /// A fallback derived FROM the registry (`unwrap_or(def.default_enabled)`) is
    /// fine and is not what this matches.
    #[test]
    fn no_call_site_hard_codes_a_controls_enabled_default() {
        let pattern = regex_lite_enabled_literal();
        for (file, text) in collapsed_sources() {
            if file == "config.rs" {
                continue; // where the single registry-backed fallback lives
            }
            assert!(
                !pattern(&text),
                "{file} hard-codes an enabled-state default next to `control_enabled(` — \
                 use `Config::control_enabled_or_default` so the registry stays the only \
                 source of that value"
            );
        }
    }

    /// Hand-rolled scan for an enabled-state call followed by a boolean literal
    /// fallback, so the test needs no regex dependency.
    ///
    /// The needles are BUILT rather than written out: a literal copy of the
    /// pattern in this file would make the scanner match its own source and fail
    /// on `controls.rs` forever, which would mean exempting the registry module
    /// from its own rule.
    fn regex_lite_enabled_literal() -> impl Fn(&str) -> bool {
        let call = format!("control_{}(", "enabled");
        let fallbacks = [
            format!("unwrap_or({})", true),
            format!("unwrap_or({})", false),
        ];
        move |text: &str| {
            let mut rest = text;
            while let Some(i) = rest.find(&call) {
                let after = &rest[i + call.len()..];
                if let Some(close) = after.find(')') {
                    let tail = after[close + 1..].trim_start();
                    let tail = tail.strip_prefix('.').map(str::trim_start).unwrap_or(tail);
                    if fallbacks.iter().any(|f| tail.starts_with(f.as_str())) {
                        return true;
                    }
                }
                rest = &rest[i + call.len()..];
            }
            false
        }
    }

    /// The same drift class one level down: a per-control OPTION whose code
    /// fallback disagrees with the value `sscsb init` writes for it. Checked by
    /// comparing the literal at the call site against the registry rather than
    /// banning it, because an option's fallback has nowhere else to live.
    ///
    /// `[controls.sast] pre_commit = false` is deliberately false in BOTH places
    /// and must stay that way — this asserts agreement, not a direction.
    #[test]
    fn every_hard_coded_option_default_agrees_with_the_registry() {
        let mut checked = 0;
        for (file, text) in collapsed_sources() {
            for c in CONTROLS {
                for (key, declared) in c.default_options {
                    for (accessor, unwrap_form) in [
                        ("control_opt_bool", "unwrap_or("),
                        ("control_opt_str", "unwrap_or_else(|| \""),
                    ] {
                        let call = format!("{accessor}(\"{}\", \"{key}\")", c.id);
                        let Some(i) = text.find(&call) else { continue };
                        let tail = text[i + call.len()..].trim_start();
                        let Some(tail) = tail.strip_prefix('.') else {
                            continue;
                        };
                        let tail = tail.trim_start();
                        let Some(rest) = tail.strip_prefix(unwrap_form) else {
                            continue;
                        };
                        let literal: String = match accessor {
                            "control_opt_bool" => {
                                rest.chars().take_while(|ch| *ch != ')').collect()
                            }
                            _ => rest.chars().take_while(|ch| *ch != '"').collect(),
                        };
                        let expected = declared.trim_matches('"');
                        assert_eq!(
                            literal.trim(),
                            expected,
                            "{file}: fallback for [controls.{}] {key} disagrees with the \
                             registry, so the control behaves differently depending on \
                             whether the config key happens to be present",
                            c.id
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(
            checked >= 8,
            "expected to check several option fallbacks, found {checked} — the scan \
             stopped matching real call sites"
        );
    }

    /// M21. `.sscsb/config.toml` is generated from `default_options`, so every
    /// key in that table becomes a line in the user's config that looks like a
    /// control they have set. Four of them were read by nothing at all —
    /// `signing-model.agent`, `signing-model.human_backend`,
    /// `package-trust.typosquat_check`, `harden-runner.egress_policy` — and a
    /// fifth, `package-trust.registry_check`, changed only the sentence `sscsb
    /// verify` printed while the check itself ran regardless.
    ///
    /// An inert key is worse than a missing one: it answers "is this on?" with a
    /// value that means nothing. So every key must be reachable through a
    /// `Config::control_opt_*` accessor in production code, or not be emitted.
    #[test]
    fn every_generated_config_key_has_a_reader() {
        let accessor = format!("control_{}_", "opt");
        let sources = collapsed_sources();
        let mut orphans = Vec::new();
        for c in CONTROLS {
            for (key, _) in c.default_options {
                // The id may be a literal or a module `CONTROL` const, so match on
                // the key argument and require an accessor call immediately
                // before it: `control_opt_str(CONTROL, "catalog")`,
                // `control_opt_bool("secrets", "gitleaks")`.
                let needle = format!("\"{key}\")");
                let read = sources.iter().any(|(file, text)| {
                    file != "controls.rs"
                        && text.match_indices(&needle).any(|(i, _)| {
                            let window = &text[i.saturating_sub(80)..i];
                            window.contains(&accessor)
                        })
                });
                if !read {
                    orphans.push(format!("[controls.{}] {key}", c.id));
                }
            }
        }
        assert!(
            orphans.is_empty(),
            "these keys are written into every generated config and read by nothing — \
             wire them to behaviour or stop emitting them: {}",
            orphans.join(", ")
        );
    }

    #[test]
    fn registry_ids_unique_and_phases_valid() {
        let mut seen = std::collections::HashSet::new();
        for c in CONTROLS {
            assert!(seen.insert(c.id), "duplicate control id {}", c.id);
            assert!((1..=5).contains(&c.phase), "{} has invalid phase", c.id);
            assert!(!c.summary.is_empty());
        }
    }

    #[test]
    fn every_phase_has_controls() {
        for phase in 1..=5u8 {
            assert!(
                phase_controls(phase).count() >= 3,
                "phase {phase} suspiciously sparse"
            );
        }
    }

    #[test]
    fn all_referenced_tools_exist_in_tool_registry() {
        for c in CONTROLS {
            for t in c.tools {
                assert!(
                    crate::tools::spec(t).is_some(),
                    "control {} references unknown tool {}",
                    c.id,
                    t
                );
            }
        }
    }

    #[test]
    fn optional_service_controls_default_off_core_controls_default_on() {
        for id in [
            "secrets",
            "commit-signing",
            "signing-model",
            "sbom",
            "vuln-scan",
            "compliance-map",
        ] {
            assert!(control(id).unwrap().default_enabled, "{id} must default on");
        }
        for id in [
            "grype",
            "socket-firewall",
            "witness",
            "sighthound",
            "wait-for-secrets",
            "dependency-track",
            "guac",
            "oras",
            "ai-receipts",
            "agent-signing",
        ] {
            assert!(
                !control(id).unwrap().default_enabled,
                "{id} must default off"
            );
        }
    }

    /// A fully bootstrapped throwaway repo (hooks installed, config written),
    /// so every control's real verifier — not just the dispatch table shape —
    /// gets exercised through `verify_control`.
    fn bootstrapped_ctx() -> (tempfile::TempDir, Ctx, Config) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let cfg = Config::load(root).unwrap().unwrap();
        (dir, ctx, cfg)
    }

    #[test]
    fn every_registered_control_dispatches_to_a_real_wired_verifier() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        for def in CONTROLS {
            let result = verify_control(&ctx, &cfg, def);
            assert_eq!(result.control, def.id);
            assert!(
                !result.messages.is_empty(),
                "control {} produced no message",
                def.id
            );
            assert!(
                !result
                    .messages
                    .iter()
                    .any(|m| m.contains("no verifier wired")),
                "control {} has no verifier wired — dispatch table is stale",
                def.id
            );
        }
    }

    #[test]
    fn disabling_a_control_in_config_short_circuits_before_dispatch() {
        let (_d, ctx, _cfg) = bootstrapped_ctx();
        for def in CONTROLS {
            crate::config::set_control_enabled(&ctx.config_path(), def.id, false).unwrap();
        }
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        for def in CONTROLS {
            let result = verify_control(&ctx, cfg, def);
            assert_eq!(
                result.outcome,
                Outcome::Disabled,
                "{} should have short-circuited before its verifier ran",
                def.id
            );
            assert_eq!(
                result.messages,
                vec!["disabled in .sscsb/config.toml".to_string()]
            );
        }
    }
}
