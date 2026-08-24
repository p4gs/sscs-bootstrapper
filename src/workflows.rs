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
use yaml_rust2::YamlLoader;

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
        control: "agent-signing",
        dest: ".github/workflows/agent-signing-verify.yml",
        content: include_str!("../templates/workflows/agent-signing-verify.yml"),
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
        control: "github-attestations",
        dest: ".github/workflows/release-attest.yml",
        content: include_str!("../templates/workflows/release-attest.yml"),
    },
    Artifact {
        control: "sbom-attestation",
        dest: ".github/workflows/release-attest-sbom.yml",
        content: include_str!("../templates/workflows/release-attest-sbom.yml"),
    },
    Artifact {
        control: "provenance-verify",
        dest: ".github/workflows/deploy-gate.yml",
        content: include_str!("../templates/workflows/deploy-gate.yml"),
    },
    Artifact {
        control: "release-immutability",
        dest: ".github/workflows/release.yml",
        content: include_str!("../templates/workflows/release.yml"),
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
        control: "fuzzing",
        dest: ".github/workflows/cflite-pr.yml",
        content: include_str!("../templates/workflows/cflite-pr.yml"),
    },
    // The ClusterFuzzLite scaffold the workflow needs: a hardened, Trivy-clean
    // build container + build script + the documented `.trivyignore` waiver, so
    // enabling `fuzzing` on any repo yields a Scorecard-detectable, scanner-clean
    // fuzzing setup — not a workflow that references a Dockerfile you must invent.
    // The `fuzz/` cargo-fuzz targets stay yours to write (project-specific).
    Artifact {
        control: "fuzzing",
        dest: ".clusterfuzzlite/Dockerfile",
        content: include_str!("../templates/clusterfuzzlite/Dockerfile"),
    },
    Artifact {
        control: "fuzzing",
        dest: ".clusterfuzzlite/build.sh",
        content: include_str!("../templates/clusterfuzzlite/build.sh"),
    },
    Artifact {
        control: "fuzzing",
        dest: ".trivyignore",
        content: include_str!("../templates/trivyignore"),
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
    // ── OpenSSF controls ────────────────────────────────────────────────────
    Artifact {
        control: "security-insights",
        dest: "security-insights.yml",
        content: include_str!("../templates/configs/security-insights.yml"),
    },
    Artifact {
        control: "best-practices-badge",
        dest: ".sscsb/best-practices-badge.md",
        content: include_str!("../templates/configs/best-practices-badge.md"),
    },
    Artifact {
        control: "osps-baseline",
        dest: ".sscsb/osps-baseline.md",
        content: include_str!("../templates/configs/osps-baseline.md"),
    },
    Artifact {
        control: "model-signing",
        dest: ".github/workflows/sign-models.yml",
        content: include_str!("../templates/workflows/sign-models.yml"),
    },
    Artifact {
        control: "gittuf",
        dest: ".github/workflows/gittuf-verify.yml",
        content: include_str!("../templates/workflows/gittuf-verify.yml"),
    },
];

/// Render template placeholders with repo-specific values.
pub fn render(content: &str, repo_slug: &str, default_branch: &str) -> String {
    // `{{project}}` = the repo name (slug tail) — used by the ClusterFuzzLite
    // scaffold for the OSS-Fuzz `$SRC/<project>` build path.
    let project = repo_slug.rsplit('/').next().unwrap_or(repo_slug);
    content
        .replace("{{repo_slug}}", repo_slug)
        .replace("{{default_branch}}", default_branch)
        .replace("{{project}}", project)
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

// ───────────────────────── artifact shape checks ────────────────────────────

/// What sscsb can honestly assert about an installed artifact BEYOND the fact
/// that a file exists at the path.
///
/// Existence is not function. `install_all` never overwrites, so a pre-existing
/// file at a destination is kept and then reported — and a file gutted to
/// `# gutted` is still a file. Each artifact kind therefore gets the strongest
/// structural claim sscsb can make from the bytes alone, and no stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// GitHub Actions workflow: must parse as YAML and declare at least one
    /// job that actually runs something.
    Workflow,
    /// Any other YAML document: must parse into a non-empty mapping.
    Yaml,
    /// JSON / JSON5 config: sscsb parses the comment-stripped JSON subset.
    Json,
    /// TOML config: must parse into a non-empty table.
    Toml,
    /// Prose, shell, Dockerfile, ignore-lists. There is no machine-checkable
    /// structure here that sscsb could assert without inventing one — the
    /// substance of a filled-in worksheet is a human judgement. sscsb proves
    /// only that the file is present and not empty, and says so.
    Opaque,
}

fn shape_of(dest: &str) -> Shape {
    let is_yamlish = dest.ends_with(".yml") || dest.ends_with(".yaml");
    if is_yamlish && dest.starts_with(".github/workflows/") {
        Shape::Workflow
    } else if is_yamlish {
        Shape::Yaml
    } else if dest.ends_with(".json") || dest.ends_with(".json5") {
        Shape::Json
    } else if dest.ends_with(".toml") {
        Shape::Toml
    } else {
        Shape::Opaque
    }
}

/// The verdict on one installed artifact's contents.
enum ShapeVerdict {
    /// Structurally sound as far as this artifact kind can be checked.
    Sound(String),
    /// Present and non-empty, but sscsb's parser cannot confirm it — reported
    /// honestly rather than claimed as verified.
    Unprovable(String),
    /// Provably not a working artifact: empty, unparseable, or inert.
    Broken(String),
}

/// Strip whole-line `//` comments so a JSON5 config can be handed to a strict
/// JSON parser. Deliberately conservative: it does not attempt to be a JSON5
/// implementation, and anything it cannot parse is reported as UNPROVABLE, not
/// as broken.
fn strip_line_comments(content: &str) -> String {
    content
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn check_workflow(dest: &str, content: &str) -> ShapeVerdict {
    let docs = match YamlLoader::load_from_str(content) {
        Ok(d) => d,
        Err(err) => {
            return ShapeVerdict::Broken(format!(
                "{dest} is NOT valid YAML ({err}) — GitHub Actions cannot run it"
            ))
        }
    };
    let Some(doc) = docs.first() else {
        return ShapeVerdict::Broken(format!(
            "{dest} contains no YAML document — a gutted or comment-only workflow runs NOTHING"
        ));
    };
    let Some(jobs) = doc["jobs"].as_hash().filter(|j| !j.is_empty()) else {
        return ShapeVerdict::Broken(format!(
            "{dest} declares no `jobs:` — the workflow runs NOTHING"
        ));
    };
    // A job with neither `steps:` nor `uses:` is not a runnable job; GitHub
    // rejects it and, until it does, the control it is supposed to enforce is
    // not being enforced.
    let inert: Vec<String> = jobs
        .iter()
        .filter(|(_, job)| {
            let has_steps = job["steps"].as_vec().is_some_and(|s| !s.is_empty());
            let has_uses = job["uses"].as_str().is_some_and(|u| !u.trim().is_empty());
            !(has_steps || has_uses)
        })
        .map(|(id, _)| id.as_str().unwrap_or("<non-string job id>").to_string())
        .collect();
    if !inert.is_empty() {
        return ShapeVerdict::Broken(format!(
            "{dest}: job(s) {} declare neither `steps:` nor `uses:` — they run NOTHING",
            inert.join(", ")
        ));
    }
    ShapeVerdict::Sound(format!("{dest} installed ({} job(s))", jobs.len()))
}

fn check_yaml(dest: &str, content: &str) -> ShapeVerdict {
    match YamlLoader::load_from_str(content) {
        Err(err) => ShapeVerdict::Broken(format!("{dest} is NOT valid YAML ({err})")),
        Ok(docs) => match docs.first().and_then(|d| d.as_hash()) {
            Some(h) if !h.is_empty() => {
                ShapeVerdict::Sound(format!("{dest} installed ({} key(s))", h.len()))
            }
            _ => ShapeVerdict::Broken(format!(
                "{dest} holds no YAML mapping — an empty or comment-only config configures NOTHING"
            )),
        },
    }
}

fn check_json(dest: &str, content: &str) -> ShapeVerdict {
    let stripped = strip_line_comments(content);
    if stripped.trim().is_empty() {
        return ShapeVerdict::Broken(format!(
            "{dest} is empty once comments are stripped — it configures NOTHING"
        ));
    }
    match serde_json::from_str::<serde_json::Value>(&stripped) {
        Ok(serde_json::Value::Object(map)) if !map.is_empty() => {
            ShapeVerdict::Sound(format!("{dest} installed ({} key(s))", map.len()))
        }
        Ok(serde_json::Value::Object(_)) => {
            ShapeVerdict::Broken(format!("{dest} is an empty object — it configures NOTHING"))
        }
        Ok(_) => ShapeVerdict::Broken(format!("{dest} is not a JSON object")),
        // JSON5 is a superset (trailing commas, unquoted keys, single quotes);
        // sscsb's stripper only handles the subset its own template uses, so a
        // parse failure here is sscsb's limitation, NOT proof the file is
        // broken. Say that instead of failing a legitimate hand-written config.
        Err(err) => ShapeVerdict::Unprovable(format!(
            "{dest} present and non-empty, but sscsb could not parse it as comment-stripped JSON \
             ({err}) — JSON5 features beyond that subset are outside what it can check"
        )),
    }
}

fn check_toml(dest: &str, content: &str) -> ShapeVerdict {
    match content.parse::<toml::Value>() {
        Err(err) => ShapeVerdict::Broken(format!("{dest} is NOT valid TOML ({err})")),
        Ok(toml::Value::Table(t)) if !t.is_empty() => {
            ShapeVerdict::Sound(format!("{dest} installed ({} key(s))", t.len()))
        }
        Ok(_) => ShapeVerdict::Broken(format!(
            "{dest} holds no TOML table — an empty or comment-only config configures NOTHING"
        )),
    }
}

/// Assert whatever this artifact kind permits. The floor, applied to every
/// kind, is that a zero-byte or whitespace-only artifact is never sound.
fn check_shape(dest: &str, content: &str) -> ShapeVerdict {
    if content.trim().is_empty() {
        return ShapeVerdict::Broken(format!("{dest} is EMPTY — it enforces nothing"));
    }
    match shape_of(dest) {
        Shape::Workflow => check_workflow(dest, content),
        Shape::Yaml => check_yaml(dest, content),
        Shape::Json => check_json(dest, content),
        Shape::Toml => check_toml(dest, content),
        // Deliberately weak, and labelled as such. See `Shape::Opaque`.
        Shape::Opaque => ShapeVerdict::Sound(format!(
            "{dest} installed (present and non-empty; no machine-checkable structure — its \
             substance is a human judgement sscsb does not assert)"
        )),
    }
}

/// Generic verifier for controls whose deliverable is installed artifacts.
///
/// Checks the artifact's CONTENT, not just its inode: `install_all` never
/// overwrites, so the file sitting at a destination may be a gutted stub or
/// something else entirely that happens to share the name.
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
    let mut broken = 0;
    let mut unprovable = 0;
    for a in artifacts {
        let path = ctx.root.join(a.dest);
        if !path.is_file() {
            broken += 1;
            messages.push(format!("{} MISSING — run `sscsb init`", a.dest));
            continue;
        }
        // A non-UTF-8 blob at a template destination is not the artifact.
        let Ok(content) = std::fs::read_to_string(&path) else {
            broken += 1;
            messages.push(format!(
                "{} is unreadable as text — this is not the installed artifact",
                a.dest
            ));
            continue;
        };
        match check_shape(a.dest, &content) {
            ShapeVerdict::Sound(m) => messages.push(m),
            ShapeVerdict::Unprovable(m) => {
                unprovable += 1;
                messages.push(m);
            }
            ShapeVerdict::Broken(m) => {
                broken += 1;
                messages.push(format!(
                    "{m} — run `sscsb init` after deleting it to regenerate"
                ));
            }
        }
    }
    let outcome = if broken > 0 {
        Outcome::Fail
    } else if unprovable > 0 {
        Outcome::Degraded
    } else {
        Outcome::Pass
    };
    VerifyResult::new(control, outcome, messages)
}

/// Harden-Runner is verified across EVERY installed workflow, one JOB at a time.
///
/// The predecessor asked `content.contains("step-security/harden-runner@")` of
/// each file's raw text, which answered a different question than the one the
/// control claims. Three ways that passed a repo that was not protected:
/// a `#`-commented-out reference still matched; one hardened job vouched for
/// every OTHER job in the same file; and an existing-but-empty
/// `.github/workflows/` directory examined nothing and reported Pass. The check
/// now parses each workflow and asks [`crate::audit::harden_runner_status`] the
/// per-job question, and anything it could not read, parse, or find jobs in is
/// reported as unverified rather than silently counted either way.
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
    let mut missing = 0usize;
    let mut workflows = 0usize;
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
        workflows += 1;
        let Ok(content) = std::fs::read_to_string(&path) else {
            missing += 1;
            messages.push(format!(
                "{name}: unreadable as text — harden-runner could not be verified"
            ));
            continue;
        };
        let jobs = match crate::audit::harden_runner_status(&content) {
            Ok(jobs) => jobs,
            Err(err) => {
                missing += 1;
                messages.push(format!(
                    "{name}: could not be parsed ({err:#}) — harden-runner is unverified, \
                     not confirmed"
                ));
                continue;
            }
        };
        if jobs.is_empty() {
            missing += 1;
            messages.push(format!(
                "{name}: declares no jobs — nothing runs here and nothing was verified"
            ));
            continue;
        }
        for (job, status) in jobs {
            match status {
                crate::audit::HardenRunner::Present => {
                    messages.push(format!("{name}: harden-runner present in job `{job}`"))
                }
                // Kept deliberately: a job that only calls a reusable workflow
                // has no step list to head, so hardening belongs to the callee
                // (for slsa-github-generator, the trusted builder does it).
                crate::audit::HardenRunner::Reusable(calls) => messages.push(format!(
                    "{name}: reusable-workflow only — job `{job}` calls `{calls}`, where \
                     harden-runner is the called workflow's concern"
                )),
                crate::audit::HardenRunner::Absent => {
                    missing += 1;
                    messages.push(format!(
                        "{name}: MISSING harden-runner in job `{job}` — that job's egress and \
                         file tampering are unmonitored"
                    ));
                }
            }
        }
    }
    if workflows == 0 {
        messages.push(
            ".github/workflows/ holds no workflow files — zero jobs were examined, so \
             harden-runner coverage is unverified, not confirmed"
                .into(),
        );
        return VerifyResult::new("harden-runner", Outcome::Degraded, messages);
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

    // ─────────────────── artifact shape checks (H1) ────────────────────────

    /// ∀ registered artifacts: the template sscsb SHIPS satisfies the
    /// structural check sscsb APPLIES. This is the guard against the fix's own
    /// worst failure mode — a check strict enough to fail every real repo the
    /// moment `sscsb init` writes the file.
    #[test]
    fn every_artifact_template_satisfies_its_own_shape_check() {
        for a in ARTIFACTS {
            let rendered = render(a.content, "owner/repo", "main");
            match check_shape(a.dest, &rendered) {
                ShapeVerdict::Sound(_) => {}
                ShapeVerdict::Unprovable(m) => {
                    panic!("shipped template {} is not verifiable: {m}", a.dest)
                }
                ShapeVerdict::Broken(m) => panic!("shipped template {} is broken: {m}", a.dest),
            }
        }
    }

    /// Every control routed through `verify_template_control` must be green on
    /// a freshly bootstrapped repo. A false FAIL here lands on every user.
    #[test]
    fn every_template_control_passes_on_a_freshly_bootstrapped_repo() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        let mut checked = 0;
        for a in ARTIFACTS {
            let def = crate::controls::control(a.control).expect("registry");
            if !cfg
                .control_enabled(a.control)
                .unwrap_or(def.default_enabled)
            {
                continue;
            }
            if a.control == "harden-runner" {
                continue;
            }
            let result = verify_template_control(&ctx, def.id);
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "control `{}` regressed on a clean install: {:?}",
                def.id,
                result.messages
            );
            checked += 1;
        }
        assert!(checked > 10, "expected to cover the template controls");
    }

    /// H1: gutting a workflow to a single comment left the control PASSing,
    /// because the verifier only asked whether a file existed at the path.
    #[test]
    fn a_gutted_workflow_fails_its_template_control() {
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(".github/workflows/codeql.yml"), "# gutted\n").unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(
            result.outcome,
            Outcome::Fail,
            "a workflow that runs nothing must not verify: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("contains no YAML document")),
            "{:?}",
            result.messages
        );
    }

    /// The floor that applies to every artifact kind, checked on the one kind
    /// that has no structure beyond it: a prose worksheet.
    #[test]
    fn a_zero_byte_artifact_fails_its_template_control() {
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(".sscsb/osps-baseline.md"), "").unwrap();
        let result = verify_template_control(&ctx, "osps-baseline");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.messages[0].contains("is EMPTY"));

        // Whitespace-only is the same emptiness wearing a disguise.
        std::fs::write(ctx.root.join(".sscsb/osps-baseline.md"), "  \n\n\t\n").unwrap();
        assert_eq!(
            verify_template_control(&ctx, "osps-baseline").outcome,
            Outcome::Fail
        );
    }

    /// A workflow can parse, declare jobs, and still run nothing.
    #[test]
    fn a_workflow_whose_jobs_run_nothing_fails() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            "name: codeql\non: push\njobs:\n  analyze:\n    runs-on: ubuntu-latest\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("declare neither `steps:` nor `uses:`")));

        // ...and an empty `jobs:` mapping.
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            "name: codeql\non: push\njobs:\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("declares no `jobs:`")));
    }

    #[test]
    fn an_unparseable_workflow_fails_its_template_control() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            "name: codeql\n  bad: [unclosed\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.messages[0].contains("NOT valid YAML"));
    }

    /// A non-UTF-8 blob at a template destination is not the artifact.
    #[test]
    fn a_binary_blob_at_an_artifact_path_fails() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            [0xff_u8, 0xfe, 0x00, 0x01],
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("unreadable as text"));
    }

    /// Non-workflow YAML (octo-sts trust policy) gets the mapping check.
    #[test]
    fn a_gutted_yaml_config_fails_its_template_control() {
        let (_d, ctx) = repo();
        let dest = ctx
            .root
            .join(".github/chainguard/sscsb-automation.sts.yaml");
        std::fs::write(&dest, "# gutted\n").unwrap();
        let result = verify_template_control(&ctx, "octo-sts");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("holds no YAML mapping")));

        std::fs::write(&dest, "- just\n- a\n- list\n").unwrap();
        assert_eq!(
            verify_template_control(&ctx, "octo-sts").outcome,
            Outcome::Fail
        );
    }

    #[test]
    fn a_gutted_json_config_fails_its_template_control() {
        let (_d, ctx) = repo();
        let dest = ctx.root.join("renovate.json5");
        std::fs::write(&dest, "// gutted\n").unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.messages[0].contains("empty once comments are stripped"));

        std::fs::write(&dest, "{}\n").unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("empty object"));

        std::fs::write(&dest, "[1, 2]\n").unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("not a JSON object"));
    }

    /// JSON5 is a superset of JSON. A file sscsb's stripper cannot parse is
    /// sscsb's limitation, not proof the config is broken — so it degrades
    /// (which `verify --strict` still refuses) instead of failing a
    /// legitimate hand-written renovate config.
    #[test]
    fn json5_beyond_the_parseable_subset_degrades_rather_than_failing() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join("renovate.json5"),
            "{\n  extends: ['config:recommended'],\n}\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(result.messages[0].contains("could not parse it as comment-stripped JSON"));
    }

    #[test]
    fn shape_of_routes_each_artifact_kind() {
        assert_eq!(
            shape_of(".github/workflows/codeql.yml"),
            Shape::Workflow,
            "workflows are the strongest-checked kind"
        );
        assert_eq!(shape_of("security-insights.yml"), Shape::Yaml);
        assert_eq!(
            shape_of(".github/chainguard/sscsb-automation.sts.yaml"),
            Shape::Yaml
        );
        assert_eq!(shape_of("renovate.json5"), Shape::Json);
        assert_eq!(shape_of("deps.json"), Shape::Json);
        assert_eq!(shape_of(".gitleaks.toml"), Shape::Toml);
        assert_eq!(shape_of(".sscsb/osps-baseline.md"), Shape::Opaque);
        assert_eq!(shape_of(".clusterfuzzlite/Dockerfile"), Shape::Opaque);
        assert_eq!(shape_of(".trivyignore"), Shape::Opaque);
    }

    #[test]
    fn toml_configs_are_checked_for_a_non_empty_table() {
        match check_shape(".gitleaks.toml", "[extend]\nuseDefault = true\n") {
            ShapeVerdict::Sound(m) => assert!(m.contains("1 key(s)")),
            other => panic!("expected sound: {}", verdict_text(&other)),
        }
        match check_shape(".gitleaks.toml", "# only a comment\n") {
            ShapeVerdict::Broken(m) => assert!(m.contains("holds no TOML table")),
            other => panic!("expected broken: {}", verdict_text(&other)),
        }
        match check_shape(".gitleaks.toml", "not = [valid toml\n") {
            ShapeVerdict::Broken(m) => assert!(m.contains("NOT valid TOML")),
            other => panic!("expected broken: {}", verdict_text(&other)),
        }
    }

    /// An opaque artifact that survives the emptiness floor is reported as
    /// checked-for-presence-only, never as verified.
    #[test]
    fn opaque_artifacts_report_the_limit_of_what_was_checked() {
        match check_shape(".sscsb/osps-baseline.md", "# filled in by a human\n") {
            ShapeVerdict::Sound(m) => {
                assert!(m.contains("no machine-checkable structure"), "{m}");
                assert!(m.contains("human judgement"), "{m}");
            }
            other => panic!("expected sound: {}", verdict_text(&other)),
        }
    }

    fn verdict_text(v: &ShapeVerdict) -> &str {
        match v {
            ShapeVerdict::Sound(m) | ShapeVerdict::Unprovable(m) | ShapeVerdict::Broken(m) => m,
        }
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

    /// M1: the check was a substring search over the file's TEXT, so a
    /// commented-out reference — the exact thing a developer leaves behind when
    /// they rip harden-runner out — satisfied it.
    #[test]
    fn a_commented_out_harden_runner_reference_does_not_satisfy_the_control() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\non: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
             runs-on: ubuntu-latest\n    steps:\n      \
             # - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n      \
             - run: echo hi\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(
            result.outcome,
            Outcome::Fail,
            "a comment monitors no egress: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("custom.yml: MISSING harden-runner")),
            "{:?}",
            result.messages
        );
    }

    /// M1: harden-runner protects the JOB it starts, not the file it appears
    /// in. One hardened job used to vouch for every other job in the workflow.
    #[test]
    fn harden_runner_is_checked_per_job_not_per_file() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\non: push\npermissions:\n  contents: read\njobs:\n  \
             hardened:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n        \
             with:\n          egress-policy: audit\n      - run: echo hi\n  \
             unhardened:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl evil.example\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(
            result.outcome,
            Outcome::Fail,
            "the second job runs unmonitored: {:?}",
            result.messages
        );
        assert!(
            result.messages.iter().any(
                |m| m.contains("custom.yml: MISSING harden-runner") && m.contains("unhardened")
            ),
            "the unprotected job must be named: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("custom.yml: harden-runner present") && m.contains("hardened")),
            "{:?}",
            result.messages
        );
    }

    /// M1: an existing-but-empty workflow directory verified NOTHING, and
    /// reported that as a pass with no messages at all.
    #[test]
    fn harden_runner_degrades_when_the_workflow_directory_holds_no_workflows() {
        let (_d, ctx) = repo();
        let dir = ctx.root.join(".github/workflows");
        for entry in std::fs::read_dir(&dir).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        // A non-workflow file in the directory is not a workflow either.
        std::fs::write(dir.join("README.md"), "not a workflow\n").unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(
            result.outcome,
            Outcome::Degraded,
            "zero workflows examined is not a pass: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("no workflow files")),
            "{:?}",
            result.messages
        );
    }

    /// A workflow sscsb cannot parse, or one that declares no jobs, proves
    /// nothing about harden-runner — and must not be reported as protected.
    #[test]
    fn harden_runner_reports_workflows_it_could_not_check() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/broken.yml"),
            "name: broken\n  bad: [unclosed\n",
        )
        .unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/jobless.yml"),
            "name: jobless\non: push\npermissions:\n  contents: read\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("broken.yml") && m.contains("could not be parsed")),
            "{:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("jobless.yml") && m.contains("declares no jobs")),
            "{:?}",
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
