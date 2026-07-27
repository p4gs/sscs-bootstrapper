//! Verifiers for the OpenSSF controls layered on top of the core registry:
//! Security Insights (`security-insights.yml`), OpenSSF Model Signing
//! (`sign-models.yml`), and gittuf (`gittuf-verify.yml`). Each follows sscsb's
//! scan-for / implement pattern — `sscsb init` installs the artifact, these
//! functions report the real, on-disk state (and, for model-signing, whether the
//! control even applies to this repo). The Best-Practices-Badge worksheet is a
//! plain generated artifact and uses the generic template verifier.

use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use std::path::Path;

// ─────────────────────────── Security Insights ──────────────────────────────

/// `security-insights.yml` must exist, parse as YAML, carry a `header` with a
/// `schema-version`, and describe the `project` or `repository`. Full schema
/// conformance is si-tooling's job (`si validate`); sscsb does the structural
/// sanity check and says where deeper validation lives.
pub fn verify_security_insights(ctx: &Ctx) -> VerifyResult {
    let path = ctx.root.join("security-insights.yml");
    if !path.is_file() {
        return VerifyResult::new(
            "security-insights",
            Outcome::Fail,
            vec!["security-insights.yml missing — run `sscsb init`".into()],
        );
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec![format!("security-insights.yml unreadable: {e}")],
            )
        }
    };
    let docs = match yaml_rust2::YamlLoader::load_from_str(&content) {
        Ok(d) => d,
        Err(e) => {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec![format!("security-insights.yml is not valid YAML: {e}")],
            )
        }
    };
    let doc = match docs.first() {
        Some(d) => d,
        None => {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec!["security-insights.yml is empty".into()],
            )
        }
    };
    // Structural checks mirroring the v2-required fields `si validate` enforces
    // (not the full CUE evaluation — that's si-tooling's job).
    let mut problems: Vec<String> = Vec::new();
    if doc["header"]["schema-version"].is_badvalue() {
        problems.push("MISSING header.schema-version".into());
    }
    let has_project = !doc["project"].is_badvalue();
    let has_repository = !doc["repository"].is_badvalue();
    if !has_project && !has_repository {
        problems.push("MISSING project or repository block".into());
    }
    if has_project
        && doc["project"]["administrators"]
            .as_vec()
            .is_none_or(|v| v.is_empty())
    {
        problems.push("project.administrators must list at least one contact".into());
    }
    if has_repository {
        if doc["repository"]["core-team"]
            .as_vec()
            .is_none_or(|v| v.is_empty())
        {
            problems.push("repository.core-team must list at least one contact".into());
        }
        // license must be a {expression, url} object, never a bare URL string.
        if doc["repository"]["license"].as_str().is_some()
            || doc["repository"]["license"]["expression"].is_badvalue()
        {
            problems.push("repository.license must be an object with `expression` + `url`".into());
        }
    }
    if !problems.is_empty() {
        return VerifyResult::new("security-insights", Outcome::Fail, problems);
    }

    // Structurally valid. If generator placeholders remain, it's an unfinished
    // starter — report Info (not a false Pass) so `sscsb verify` stays honest.
    if content.contains("REPLACE-ME") || content.contains("TODO:") {
        return VerifyResult::new(
            "security-insights",
            Outcome::Info,
            vec![
                "structurally valid starter installed".into(),
                "replace the REPLACE-ME/TODO placeholders, then run `si validate`".into(),
            ],
        );
    }
    VerifyResult::new(
        "security-insights",
        Outcome::Pass,
        vec!["structurally valid — run `si validate` for full schema conformance".into()],
    )
}

// ─────────────────────────── Model Signing ──────────────────────────────────

/// File extensions that unambiguously indicate an ML model artifact. Deliberately
/// excludes generic containers (`.bin`, `.pkl`) to avoid false positives.
const MODEL_EXTS: &[&str] = &[
    "safetensors",
    "onnx",
    "gguf",
    "ggml",
    "tflite",
    "h5",
    "ckpt",
    "pt",
    "pth",
    "npz",
];

/// Bounded recursive scan for model files under `root`, skipping VCS/build dirs.
/// Capped so a large repo can't stall `verify`.
fn find_model_files(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    // Bound on DIRECTORIES traversed (not just matches) so a match-free tree
    // can't stall verify, independent of the 50-match cap below.
    let mut dirs_visited = 0usize;
    while let Some(dir) = stack.pop() {
        if found.len() >= 50 || dirs_visited >= 4000 {
            break;
        }
        dirs_visited += 1;
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            // Never follow symlinks: a symlinked directory could form a cycle or
            // point outside the repo (e.g. `models -> ~/models`, `link -> /`),
            // which would let `sscsb verify` escape the repo and stall — the exact
            // thing the cap above promises against. file_type() does not traverse
            // the link, so is_symlink() is true for a symlink to a directory.
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if matches!(
                    name.as_str(),
                    ".git" | "target" | "node_modules" | ".venv" | "venv" | "dist"
                ) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if MODEL_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
                        if let Ok(rel) = path.strip_prefix(root) {
                            found.push(rel.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }
    found.sort();
    found
}

/// Model signing applies only when the repo ships models. If it does, the
/// signing workflow must be installed; if it doesn't, the control is honestly
/// reported as N/A (Info) rather than a false pass or fail.
pub fn verify_model_signing(ctx: &Ctx) -> VerifyResult {
    let workflow_ok = ctx.root.join(".github/workflows/sign-models.yml").is_file();
    let models = find_model_files(&ctx.root);
    if models.is_empty() {
        let installed = if workflow_ok {
            "sign-models.yml installed (ready if models are added)"
        } else {
            "sign-models.yml not installed — run `sscsb init`"
        };
        return VerifyResult::new(
            "model-signing",
            Outcome::Info,
            vec![
                "no ML model files detected (*.safetensors/*.onnx/*.gguf/*.pt …) — N/A for this repo"
                    .into(),
                installed.into(),
            ],
        );
    }
    let mut messages = vec![format!(
        "{} model file(s) detected (e.g. {})",
        models.len(),
        models[0]
    )];
    if workflow_ok {
        messages.push(".github/workflows/sign-models.yml installed".into());
        VerifyResult::new("model-signing", Outcome::Pass, messages)
    } else {
        messages.push(".github/workflows/sign-models.yml MISSING — run `sscsb init`".into());
        VerifyResult::new("model-signing", Outcome::Fail, messages)
    }
}

// ─────────────────────────── gittuf ─────────────────────────────────────────

/// gittuf policy lives in `refs/gittuf/*`, not the working tree. Detect it via
/// git rather than a directory probe (robust to worktrees). Absent git or refs
/// → not initialized.
fn gittuf_policy_present(root: &Path) -> bool {
    crate::exec::git_raw(&["show-ref"], root)
        .map(|o| o.stdout.contains("refs/gittuf/"))
        .unwrap_or(false)
}

/// The verify workflow must be installed; gittuf policy is an advanced,
/// locally-initialized step, so its absence is Info (guidance), not Fail.
pub fn verify_gittuf(ctx: &Ctx) -> VerifyResult {
    let workflow_ok = ctx
        .root
        .join(".github/workflows/gittuf-verify.yml")
        .is_file();
    if !workflow_ok {
        return VerifyResult::new(
            "gittuf",
            Outcome::Fail,
            vec![".github/workflows/gittuf-verify.yml MISSING — run `sscsb init`".into()],
        );
    }
    if gittuf_policy_present(&ctx.root) {
        VerifyResult::new(
            "gittuf",
            Outcome::Pass,
            vec![
                "gittuf policy (refs/gittuf/*) present".into(),
                "gittuf-verify.yml installed".into(),
            ],
        )
    } else {
        VerifyResult::new(
            "gittuf",
            Outcome::Info,
            vec![
                "gittuf-verify.yml installed; no gittuf policy yet".into(),
                "initialize locally: `gittuf trust init` + policy, then push refs/gittuf/* — https://github.com/gittuf/gittuf".into(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Ctx;

    fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    #[test]
    fn security_insights_starter_is_info_filled_is_pass_missing_is_fail() {
        let (_d, ctx) = repo();
        // Bootstrap installs a structurally-VALID starter that still carries
        // REPLACE-ME placeholders → Info (not a false Pass).
        let starter = verify_security_insights(&ctx);
        assert_eq!(starter.outcome, Outcome::Info, "{:?}", starter.messages);
        assert!(starter.messages.iter().any(|m| m.contains("placeholder")));
        // Placeholders replaced + valid structure → Pass.
        let filled = "header:\n  schema-version: \"2.0.0\"\n  url: \"https://example.com/si.yml\"\nproject:\n  name: \"acme/widget\"\n  administrators:\n    - name: \"Real Maintainer\"\n      primary: true\n  repositories:\n    - name: \"acme/widget\"\n      comment: \"primary\"\n      url: \"https://github.com/acme/widget\"\n  vulnerability-reporting:\n    reports-accepted: true\n    bug-bounty-available: false\n";
        std::fs::write(ctx.root.join("security-insights.yml"), filled).unwrap();
        assert_eq!(verify_security_insights(&ctx).outcome, Outcome::Pass);
        // Missing → Fail with the init hint.
        std::fs::remove_file(ctx.root.join("security-insights.yml")).unwrap();
        let missing = verify_security_insights(&ctx);
        assert_eq!(missing.outcome, Outcome::Fail);
        assert!(missing.messages[0].contains("missing"));
    }

    #[test]
    fn security_insights_rejects_missing_required_fields_and_string_license() {
        let (_d, ctx) = repo();
        let p = ctx.root.join("security-insights.yml");
        // project present but no administrators → Fail.
        std::fs::write(
            &p,
            "header:\n  schema-version: \"2.0.0\"\n  url: \"x\"\nproject:\n  name: \"x\"\n",
        )
        .unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("administrators")));
        // repository with a bare-string license → Fail (must be an object).
        std::fs::write(&p, "header:\n  schema-version: \"2.0.0\"\n  url: \"x\"\nrepository:\n  core-team:\n    - name: \"m\"\n      primary: true\n  license: \"https://x/LICENSE\"\n").unwrap();
        let r2 = verify_security_insights(&ctx);
        assert_eq!(r2.outcome, Outcome::Fail);
        assert!(r2.messages.iter().any(|m| m.contains("license")));
    }

    #[test]
    fn security_insights_fails_on_invalid_yaml_and_on_missing_keys() {
        let (_d, ctx) = repo();
        let path = ctx.root.join("security-insights.yml");
        std::fs::write(&path, "header: [this is: not: valid").unwrap();
        assert_eq!(verify_security_insights(&ctx).outcome, Outcome::Fail);
        // Valid YAML but missing the required structure.
        std::fs::write(&path, "something: else\n").unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("schema-version")));
    }

    #[test]
    fn model_signing_is_info_without_models_and_pass_with_a_model() {
        let (_d, ctx) = repo();
        // Fresh repo has no models → Info, N/A, workflow present.
        let na = verify_model_signing(&ctx);
        assert_eq!(na.outcome, Outcome::Info);
        assert!(na.messages.iter().any(|m| m.contains("N/A")));
        // model-signing is default-OFF, so bootstrap did NOT install the
        // workflow. Enable the scenario by hand: add a model + install the
        // workflow → Pass.
        std::fs::write(ctx.root.join("model.safetensors"), b"\x00\x01").unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/sign-models.yml"),
            "name: Sign ML Models\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        let ok = verify_model_signing(&ctx);
        assert_eq!(ok.outcome, Outcome::Pass, "{:?}", ok.messages);
        assert!(ok.messages[0].contains("model.safetensors"));
        // Remove the workflow → Fail (models present, no signing).
        std::fs::remove_file(ctx.root.join(".github/workflows/sign-models.yml")).unwrap();
        assert_eq!(verify_model_signing(&ctx).outcome, Outcome::Fail);
    }

    #[test]
    fn model_scan_skips_git_and_build_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join(".git/x.onnx"), b"x").unwrap();
        std::fs::write(root.join("target/y.pt"), b"y").unwrap();
        std::fs::write(root.join("real.gguf"), b"z").unwrap();
        let found = find_model_files(root);
        assert_eq!(found, vec!["real.gguf".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn model_scan_never_follows_symlinks() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        // A real model living OUTSIDE the scanned repo.
        std::fs::write(outside.path().join("external.onnx"), b"x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("in-repo.safetensors"), b"y").unwrap();
        // A symlinked directory pointing outside the repo, and a self-cycle.
        symlink(outside.path(), root.join("models")).unwrap();
        symlink(root, root.join("loop")).unwrap();
        // A symlinked model file.
        symlink(
            outside.path().join("external.onnx"),
            root.join("linked.onnx"),
        )
        .unwrap();
        let found = find_model_files(root);
        // Only the real in-repo file — the scan neither follows the dir symlink
        // (escaping the repo), the cycle (stalling), nor the file symlink.
        assert_eq!(found, vec!["in-repo.safetensors".to_string()]);
    }

    #[test]
    fn gittuf_is_info_when_installed_without_policy_and_fail_when_missing() {
        let (_d, ctx) = repo();
        // Bootstrap does not enable gittuf (default-off), so the workflow is
        // absent → Fail. Install it, then re-check → Info (no policy yet).
        assert_eq!(verify_gittuf(&ctx).outcome, Outcome::Fail);
        std::fs::write(
            ctx.root.join(".github/workflows/gittuf-verify.yml"),
            "name: gittuf verify\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        let info = verify_gittuf(&ctx);
        assert_eq!(info.outcome, Outcome::Info, "{:?}", info.messages);
        assert!(info.messages.iter().any(|m| m.contains("no gittuf policy")));
        assert!(!gittuf_policy_present(&ctx.root));
    }

    #[test]
    fn gittuf_passes_once_a_policy_ref_exists() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/gittuf-verify.yml"),
            "name: gittuf verify\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        // Simulate an initialized gittuf policy by creating a refs/gittuf ref.
        let head = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root)
            .or_else(|_| {
                // Ensure at least one commit exists to point the ref at.
                std::fs::write(ctx.root.join("f.txt"), "x").unwrap();
                crate::exec::git(&["add", "-A"], &ctx.root).unwrap();
                crate::exec::git(&["commit", "-m", "c", "--no-verify"], &ctx.root).unwrap();
                crate::exec::git(&["rev-parse", "HEAD"], &ctx.root)
            })
            .unwrap();
        crate::exec::git(
            &["update-ref", "refs/gittuf/reference-state-log", &head],
            &ctx.root,
        )
        .unwrap();
        assert!(gittuf_policy_present(&ctx.root));
        let pass = verify_gittuf(&ctx);
        assert_eq!(pass.outcome, Outcome::Pass, "{:?}", pass.messages);
        assert!(pass.messages.iter().any(|m| m.contains("refs/gittuf/*")));
    }

    #[test]
    fn security_insights_reports_empty_file() {
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join("security-insights.yml"), "").unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("empty")));
    }

    #[test]
    fn model_signing_info_notes_when_workflow_is_already_installed() {
        let (_d, ctx) = repo();
        // No models, but the workflow is present → Info that says it's ready.
        std::fs::write(
            ctx.root.join(".github/workflows/sign-models.yml"),
            "name: Sign ML Models\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        let r = verify_model_signing(&ctx);
        assert_eq!(r.outcome, Outcome::Info);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("ready if models are added")));
    }
}
