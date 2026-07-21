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
        default_options: &[("sign_with_cosign", "false")],
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
        id: "provenance-verify",
        phase: 3,
        name: "Provenance verification gates",
        summary: "slsa-verifier + cosign verification required before promote/deploy/publish",
        default_enabled: true,
        tools: &["slsa-verifier", "cosign"],
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
        default_options: &[("egress_policy", "\"audit\"")],
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
        id: "compliance-map",
        phase: 5,
        name: "Compliance map & report",
        summary: "Machine-readable control → SLSA/SSDF/CRA/Badge map behind `sscsb report`",
        default_enabled: true,
        tools: &[],
        default_options: &[],
    },
];

pub fn control(id: &str) -> Option<&'static ControlDef> {
    CONTROLS.iter().find(|c| c.id == id)
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
    if !cfg.control_enabled(def.id).unwrap_or(def.default_enabled) {
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
        "branch-protection" => crate::audit::verify_branch_protection(ctx, cfg),
        "actions-audit" => crate::audit::verify_actions_control(ctx, false),
        "workflow-audit-extended" => crate::audit::verify_actions_control(ctx, true),
        "ai-trailers" | "ai-dep-gate" => crate::hooks::verify_hook_installed(ctx, def.id),
        "pr-template" => crate::workflows::verify_pr_template(ctx),
        "ai-receipts" => crate::provenance::verify_receipts_control(ctx, cfg),
        "sbom" => crate::sbom::verify_sbom_control(ctx),
        "vuln-scan" => crate::scan::verify_scan_control(ctx),
        "grype" => crate::sbom::verify_grype_control(ctx),
        "package-trust" => crate::deps::verify_package_trust(ctx, cfg),
        "scorecard"
        | "renovate"
        | "codeql"
        | "sigstore-signing"
        | "slsa-provenance"
        | "github-attestations"
        | "sbom-attestation"
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
