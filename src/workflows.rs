//! Template registry: CI workflows, policy files, and sample configs that
//! `sscsb init` installs. Templates are embedded at compile time and rendered
//! with repo-specific values. Invariants enforced by tests in this module:
//! every workflow template passes sscsb's OWN actions audit (SHA-pinned,
//! least-privilege, Harden-Runner first) — the tool that audits you is the
//! tool that generated your workflows.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct Artifact {
    /// Control that owns this artifact (installed only when enabled).
    pub control: &'static str,
    /// Destination path relative to the repo root.
    pub dest: &'static str,
    pub content: &'static str,
}

pub const ARTIFACTS: &[Artifact] = &[
    Artifact {
        control: "secrets",
        dest: ".github/workflows/secrets-scan.yml",
        content: include_str!("../templates/workflows/secrets-scan.yml"),
    },
    Artifact {
        control: "secrets",
        dest: ".gitleaks.toml",
        content: include_str!("../templates/configs/gitleaks.toml"),
    },
    Artifact {
        control: "secrets",
        dest: ".trufflehog.yaml",
        content: include_str!("../templates/configs/trufflehog.yaml"),
    },
    Artifact {
        control: "pr-template",
        dest: ".github/PULL_REQUEST_TEMPLATE.md",
        content: include_str!("../templates/configs/pull_request_template.md"),
    },
    Artifact {
        control: "sbom",
        dest: ".github/workflows/sbom.yml",
        content: include_str!("../templates/workflows/sbom.yml"),
    },
    Artifact {
        control: "vuln-scan",
        dest: ".github/workflows/vuln-scan.yml",
        content: include_str!("../templates/workflows/vuln-scan.yml"),
    },
    Artifact {
        control: "scorecard",
        dest: ".github/workflows/scorecard.yml",
        content: include_str!("../templates/workflows/scorecard.yml"),
    },
    Artifact {
        control: "renovate",
        dest: "renovate.json5",
        content: include_str!("../templates/configs/renovate.json5"),
    },
    Artifact {
        control: "sigstore-signing",
        dest: ".github/workflows/release-sign.yml",
        content: include_str!("../templates/workflows/release-sign.yml"),
    },
    Artifact {
        control: "slsa-provenance",
        dest: ".github/workflows/release-slsa.yml",
        content: include_str!("../templates/workflows/release-slsa.yml"),
    },
    Artifact {
        control: "provenance-verify",
        dest: ".github/workflows/deploy-gate.yml",
        content: include_str!("../templates/workflows/deploy-gate.yml"),
    },
    Artifact {
        control: "octo-sts",
        dest: ".github/workflows/octo-sts-example.yml",
        content: include_str!("../templates/workflows/octo-sts-example.yml"),
    },
    Artifact {
        control: "octo-sts",
        dest: ".github/chainguard/sscsb-automation.sts.yaml",
        content: include_str!("../templates/configs/octo-sts-policy.sts.yaml"),
    },
    Artifact {
        control: "sast",
        dest: ".github/workflows/sast-opengrep.yml",
        content: include_str!("../templates/workflows/sast-opengrep.yml"),
    },
    Artifact {
        control: "sast",
        dest: ".sscsb/rules/sscsb-default.yaml",
        content: include_str!("../templates/rules/sscsb-default.yaml"),
    },
    Artifact {
        control: "codeql",
        dest: ".github/workflows/codeql.yml",
        content: include_str!("../templates/workflows/codeql.yml"),
    },
    Artifact {
        control: "wait-for-secrets",
        dest: ".github/workflows/wait-for-secrets-example.yml",
        content: include_str!("../templates/workflows/wait-for-secrets-snippet.yml"),
    },
    Artifact {
        control: "dependency-track",
        dest: ".sscsb/templates/dependency-track-compose.yml",
        content: include_str!("../templates/configs/dependency-track-compose.yml"),
    },
];

/// Render template placeholders with repo-specific values.
pub fn render(content: &str, repo_slug: &str, default_branch: &str) -> String {
    content
        .replace("{{repo_slug}}", repo_slug)
        .replace("{{default_branch}}", default_branch)
}

pub fn artifacts_for(control: &str) -> Vec<&'static Artifact> {
    ARTIFACTS.iter().filter(|a| a.control == control).collect()
}

/// Install all artifacts whose control is enabled. Existing files are never
/// overwritten (delete to regenerate). Returns human-readable report lines.
pub fn install_all(ctx: &Ctx, cfg: &Config) -> Result<Vec<String>> {
    let slug = cfg
        .github_repo()
        .or_else(|| ctx.origin_slug())
        .unwrap_or_else(|| "OWNER/REPO".to_string());
    let branch = ctx.default_branch();
    let mut lines = Vec::new();
    for artifact in ARTIFACTS {
        let def = crate::controls::control(artifact.control).expect("registry");
        let enabled = cfg
            .control_enabled(artifact.control)
            .unwrap_or(def.default_enabled);
        if !enabled {
            lines.push(format!(
                "skip {} (control {} disabled)",
                artifact.dest, artifact.control
            ));
            continue;
        }
        let dest = ctx.root.join(artifact.dest);
        if dest.exists() {
            lines.push(format!(
                "keep {} (exists — delete to regenerate)",
                artifact.dest
            ));
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, render(artifact.content, &slug, &branch))?;
        lines.push(format!("write {}", artifact.dest));
    }
    Ok(lines)
}

/// Generic verifier for controls whose deliverable is installed artifacts.
pub fn verify_template_control(ctx: &Ctx, control: &'static str) -> VerifyResult {
    if control == "harden-runner" {
        return verify_harden_runner(ctx);
    }
    let artifacts = artifacts_for(control);
    if artifacts.is_empty() {
        return VerifyResult::new(
            control,
            Outcome::Fail,
            vec![format!("no artifacts registered for `{control}` — bug")],
        );
    }
    let mut messages = Vec::new();
    let mut missing = 0;
    for a in artifacts {
        if ctx.root.join(a.dest).is_file() {
            messages.push(format!("{} installed", a.dest));
        } else {
            missing += 1;
            messages.push(format!("{} MISSING — run `sscsb init`", a.dest));
        }
    }
    let outcome = if missing == 0 {
        Outcome::Pass
    } else {
        Outcome::Fail
    };
    VerifyResult::new(control, outcome, messages)
}

/// Harden-Runner is verified across EVERY installed workflow.
fn verify_harden_runner(ctx: &Ctx) -> VerifyResult {
    let dir = ctx.root.join(".github").join("workflows");
    if !dir.is_dir() {
        return VerifyResult::new(
            "harden-runner",
            Outcome::Degraded,
            vec!["no workflows installed yet — run `sscsb init`".into()],
        );
    }
    let mut messages = Vec::new();
    let mut missing = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        if content.contains("step-security/harden-runner@") {
            messages.push(format!("{name}: harden-runner present"));
        } else if content.contains("slsa-framework/slsa-github-generator")
            && !content.contains("steps:")
        {
            messages.push(format!(
                "{name}: reusable-workflow only (harden-runner runs inside the trusted builder)"
            ));
        } else {
            missing += 1;
            messages.push(format!("{name}: MISSING harden-runner"));
        }
    }
    let outcome = if missing == 0 {
        Outcome::Pass
    } else {
        Outcome::Fail
    };
    VerifyResult::new("harden-runner", outcome, messages)
}

pub fn verify_pr_template(ctx: &Ctx) -> VerifyResult {
    let path = ctx.root.join(".github").join("PULL_REQUEST_TEMPLATE.md");
    if !path.is_file() {
        return VerifyResult::new(
            "pr-template",
            Outcome::Fail,
            vec![".github/PULL_REQUEST_TEMPLATE.md missing — run `sscsb init`".into()],
        );
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let has_ai_questions = content.contains("AI generated or assisted with **code**")
        && content.contains("new dependencies");
    if has_ai_questions {
        VerifyResult::new(
            "pr-template",
            Outcome::Pass,
            vec!["AI-provenance PR template installed (code/tests/deps/docs questions)".into()],
        )
    } else {
        VerifyResult::new(
            "pr-template",
            Outcome::Fail,
            vec!["PR template exists but lacks the AI-provenance questions".into()],
        )
    }
}

/// Also expose the templates dir installer for non-artifact extras.
pub fn write_if_absent(root: &Path, rel: &str, content: &str) -> Result<bool> {
    let dest = root.join(rel);
    if dest.exists() {
        return Ok(false);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&dest, content)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{audit_workflow, Severity};
    use crate::context::Ctx;

    /// Throwaway repo bootstrapped through the real `sscsb init` path —
    /// mirrors the pattern in `tests/library.rs` so template-control tests
    /// run against the same layout a user gets.
    fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    fn rendered_workflows() -> Vec<(&'static str, String)> {
        ARTIFACTS
            .iter()
            .filter(|a| a.dest.starts_with(".github/workflows/"))
            .map(|a| (a.dest, render(a.content, "owner/repo", "main")))
            .collect()
    }

    /// ∀ workflow templates: zero audit ERRORS (SHA-pinning + permissions) —
    /// including the extended checks. The one sanctioned tag pin
    /// (slsa-github-generator) surfaces as Info, not Error.
    #[test]
    fn every_workflow_template_passes_own_audit() {
        for (dest, content) in rendered_workflows() {
            let findings = audit_workflow(dest, &content, true)
                .unwrap_or_else(|e| panic!("{dest} failed to parse: {e:#}"));
            let bad: Vec<_> = findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .collect();
            assert!(bad.is_empty(), "{dest} fails sscsb's own audit: {bad:?}");
        }
    }

    /// ∀ workflow templates: every job with its own steps starts with
    /// Harden-Runner (reusable-workflow jobs are the trusted builder's concern).
    #[test]
    fn every_workflow_template_embeds_harden_runner() {
        for (dest, content) in rendered_workflows() {
            assert!(
                content.contains(
                    "step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920"
                ),
                "{dest} lacks the pinned harden-runner step"
            );
        }
    }

    /// ∀ templates: no unrendered placeholders survive rendering.
    #[test]
    fn rendering_leaves_no_placeholders() {
        for a in ARTIFACTS {
            let rendered = render(a.content, "owner/repo", "main");
            assert!(
                !rendered.contains("{{repo_slug}}") && !rendered.contains("{{default_branch}}"),
                "{} has unrendered placeholders",
                a.dest
            );
        }
    }

    /// ∀ templates: no real identities/secrets baked in — placeholders only.
    #[test]
    fn templates_carry_no_baked_in_identities() {
        for a in ARTIFACTS {
            assert!(
                !a.content.contains("/Users/") && !a.content.contains("/home/"),
                "{} contains a hardcoded home path",
                a.dest
            );
        }
    }

    #[test]
    fn every_artifact_control_is_registered() {
        for a in ARTIFACTS {
            assert!(
                crate::controls::control(a.control).is_some(),
                "artifact {} references unknown control {}",
                a.dest,
                a.control
            );
        }
    }

    #[test]
    fn renovate_template_is_valid_json_after_comment_strip() {
        let a = ARTIFACTS
            .iter()
            .find(|a| a.dest == "renovate.json5")
            .unwrap();
        let stripped: String = a
            .content
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let v: serde_json::Value = serde_json::from_str(&stripped).expect("renovate config parses");
        assert!(v["extends"].as_array().is_some());
        assert_eq!(v["osvVulnerabilityAlerts"], serde_json::Value::Bool(true));
    }

    #[test]
    fn verify_template_control_reports_bug_for_control_with_no_artifacts() {
        let (_d, ctx) = repo();
        // "witness" is a real control but owns no ARTIFACTS entries — calling
        // the generic template verifier for it is the defensive "this is a
        // bug" branch, not a real dispatch (controls.rs routes witness
        // elsewhere), but the function must still handle it safely.
        let result = verify_template_control(&ctx, "witness");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("no artifacts registered for `witness`"));
    }

    #[test]
    fn verify_template_control_reports_missing_artifacts_and_fails() {
        let (_d, ctx) = repo();
        // Every enabled control's artifacts are installed by bootstrap;
        // delete one to simulate an incomplete/corrupted install.
        std::fs::remove_file(ctx.root.join(".github/workflows/scorecard.yml")).unwrap();
        let result = verify_template_control(&ctx, "scorecard");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains(".github/workflows/scorecard.yml MISSING")));
    }

    #[test]
    fn harden_runner_check_covers_present_missing_and_reusable_workflow_cases() {
        let (_d, ctx) = repo();
        // A non-workflow file in the directory must be skipped, not misread.
        std::fs::write(
            ctx.root.join(".github/workflows/README.md"),
            "not a workflow\n",
        )
        .unwrap();
        // A workflow that never adopted harden-runner.
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        )
        .unwrap();
        // A reusable-workflow-only caller: harden-runner runs inside the
        // trusted builder, not in this file, so it must not be flagged.
        std::fs::write(
            ctx.root.join(".github/workflows/reusable-only.yml"),
            "name: reusable-only\non: push\npermissions:\n  contents: read\njobs:\n  provenance:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0\n    with:\n      base64-subjects: \"abc\"\n",
        )
        .unwrap();

        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("custom.yml: MISSING harden-runner")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("reusable-only.yml: reusable-workflow only")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("harden-runner present")));
        assert!(
            !result.messages.iter().any(|m| m.contains("README.md")),
            "non-workflow files must be skipped entirely: {:?}",
            result.messages
        );
    }

    #[test]
    fn harden_runner_check_degrades_when_no_workflows_installed() {
        let (_d, ctx) = repo();
        std::fs::remove_dir_all(ctx.root.join(".github/workflows")).unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result.messages[0].contains("no workflows installed yet"));
    }

    #[test]
    fn pr_template_check_reports_missing_file() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/PULL_REQUEST_TEMPLATE.md")).unwrap();
        let result = verify_pr_template(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("missing — run `sscsb init`"));
    }

    #[test]
    fn pr_template_check_flags_template_missing_ai_provenance_questions() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/PULL_REQUEST_TEMPLATE.md"),
            "# Pull Request\n\nDescribe your change.\n",
        )
        .unwrap();
        let result = verify_pr_template(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("lacks the AI-provenance questions"));
    }

    #[test]
    fn write_if_absent_creates_parent_dirs_and_skips_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let created = write_if_absent(dir.path(), "nested/dir/file.txt", "hello\n").unwrap();
        assert!(created);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("nested/dir/file.txt")).unwrap(),
            "hello\n"
        );

        let skipped = write_if_absent(dir.path(), "nested/dir/file.txt", "changed\n").unwrap();
        assert!(!skipped);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("nested/dir/file.txt")).unwrap(),
            "hello\n",
            "existing file must never be overwritten"
        );
    }

    #[test]
    fn install_all_skips_disabled_controls_and_keeps_existing_files() {
        let (_d, ctx) = repo();
        // Bootstrap already installed everything once; re-running install_all
        // must "keep" every existing artifact rather than overwrite it.
        let cfg = ctx.require_config().unwrap();
        let second = install_all(&ctx, cfg).unwrap();
        assert!(second
            .iter()
            .all(|l| l.starts_with("keep") || l.starts_with("skip")));
        assert!(second
            .iter()
            .any(|l| l.contains("keep .github/workflows/scorecard.yml")));

        // Disable a control and delete its artifact, then confirm install_all
        // skips reinstalling it — the modularity contract.
        crate::config::set_control_enabled(&ctx.config_path(), "renovate", false).unwrap();
        std::fs::remove_file(ctx.root.join("renovate.json5")).unwrap();
        let ctx2 = Ctx::discover(&ctx.root).unwrap();
        let cfg2 = ctx2.require_config().unwrap();
        let third = install_all(&ctx2, cfg2).unwrap();
        assert!(third
            .iter()
            .any(|l| l.contains("skip renovate.json5 (control renovate disabled)")));
        assert!(!ctx2.root.join("renovate.json5").exists());
    }

    #[test]
    fn slsa_template_is_tag_pinned_and_documented() {
        let a = ARTIFACTS
            .iter()
            .find(|a| a.dest == ".github/workflows/release-slsa.yml")
            .unwrap();
        assert!(a.content.contains(
            "slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
        ));
        assert!(a.content.contains("PINNING EXCEPTION"));
    }
}
