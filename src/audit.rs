//! GitHub Actions workflow auditing.
//!
//! Basic audit (Phase 1 `actions-audit`): SHA pinning + least-privilege
//! permissions. Extended audit (Phase 4 `workflow-audit-extended`):
//! pull_request_target misuse, credential persistence, secret exposure in
//! logs, risky third-party actions (with StepSecurity maintained-action
//! substitutions), lockfile-exact installs, and Harden-Runner presence.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use anyhow::{Context as _, Result};
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub file: String,
    pub message: String,
}

impl Finding {
    fn new(severity: Severity, file: &str, message: String) -> Self {
        Finding {
            severity,
            file: file.to_string(),
            message,
        }
    }
}

/// Known-risky third-party actions with maintained, drop-in StepSecurity
/// replacements. Kept deliberately small and defensible.
pub const RISKY_ACTION_SUBSTITUTIONS: &[(&str, &str)] = &[
    // Compromised March 2025 (CVE-2025-30066): secrets dumped from runner memory.
    ("tj-actions/changed-files", "step-security/changed-files"),
    ("tj-actions/branch-names", "step-security/branch-names"),
    // Frequently flagged for over-privileged token use; maintained fork exists.
    (
        "dawidd6/action-download-artifact",
        "step-security/action-download-artifact",
    ),
];

/// The one sanctioned non-SHA pin: slsa-github-generator MUST be referenced by
/// semver tag for slsa-verifier to validate the trusted builder ref
/// (upstream README, slsa-verifier issue #12).
const TAG_PIN_EXCEPTION_PREFIX: &str = "slsa-framework/slsa-github-generator";

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_semver_tag(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Audit one workflow document.
pub fn audit_workflow(file: &str, content: &str, extended: bool) -> Result<Vec<Finding>> {
    let docs =
        YamlLoader::load_from_str(content).with_context(|| format!("parsing YAML in {file}"))?;
    let Some(doc) = docs.first() else {
        return Ok(vec![Finding::new(
            Severity::Warn,
            file,
            "empty workflow file".into(),
        )]);
    };
    let mut findings = Vec::new();

    audit_permissions(file, doc, &mut findings);
    audit_uses_refs(file, doc, &mut findings);

    if extended {
        audit_pull_request_target(file, doc, content, &mut findings);
        audit_checkout_credentials(file, doc, &mut findings);
        audit_secret_exposure(file, doc, &mut findings);
        audit_risky_actions(file, doc, &mut findings);
        audit_lockfile_exact(file, doc, &mut findings);
        audit_harden_runner(file, doc, &mut findings);
    }
    Ok(findings)
}

fn jobs(doc: &Yaml) -> Vec<(&str, &Yaml)> {
    let mut out = Vec::new();
    if let Some(jobs) = doc["jobs"].as_hash() {
        for (k, v) in jobs {
            if let Some(name) = k.as_str() {
                out.push((name, v));
            }
        }
    }
    out
}

fn steps(job: &Yaml) -> Vec<&Yaml> {
    job["steps"]
        .as_vec()
        .map(|v| v.iter().collect())
        .unwrap_or_default()
}

/// Every `uses:` in the workflow — both step-level actions and job-level
/// reusable workflows.
fn all_uses(doc: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    for (_, job) in jobs(doc) {
        if let Some(u) = job["uses"].as_str() {
            out.push(u.to_string());
        }
        for step in steps(job) {
            if let Some(u) = step["uses"].as_str() {
                out.push(u.to_string());
            }
        }
    }
    out
}

fn audit_uses_refs(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for uses in all_uses(doc) {
        check_uses_ref(file, &uses, findings);
    }
}

/// Pin-check a single `uses:` reference. Local (`./`) actions are resolved and
/// audited separately (see [`audit_repo`]); `docker://` images are expected to
/// be digest-pinned elsewhere.
fn check_uses_ref(file: &str, uses: &str, findings: &mut Vec<Finding>) {
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return;
    }
    let Some((action, r)) = uses.rsplit_once('@') else {
        findings.push(Finding::new(
            Severity::Error,
            file,
            format!("`{uses}` has no ref — pin to a full commit SHA"),
        ));
        return;
    };
    if is_full_sha(r) {
        return;
    }
    if action.starts_with(TAG_PIN_EXCEPTION_PREFIX) && is_semver_tag(r) {
        findings.push(Finding::new(
            Severity::Info,
            file,
            format!(
                "`{uses}` is tag-pinned by design: slsa-github-generator must be referenced \
                 by @vX.Y.Z for slsa-verifier to verify the trusted builder"
            ),
        ));
        return;
    }
    findings.push(Finding::new(
        Severity::Error,
        file,
        format!("`{uses}` uses mutable ref `@{r}` — pin to a full 40-char commit SHA"),
    ));
}

/// Every `uses:` inside a local composite action's `runs.steps`.
fn composite_action_uses(doc: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(steps) = doc["runs"]["steps"].as_vec() {
        for step in steps {
            if let Some(u) = step["uses"].as_str() {
                out.push(u.to_string());
            }
        }
    }
    out
}

/// Audit a local composite action definition (`.github/actions/<x>/action.yml`).
/// These are `uses: ./...`-referenced from workflows and were previously a blind
/// spot: a local action can pull in an unpinned third-party action, and the
/// workflow-level audit never looked inside it.
pub fn audit_action_file(file: &str, content: &str) -> Result<Vec<Finding>> {
    let docs =
        YamlLoader::load_from_str(content).with_context(|| format!("parsing YAML in {file}"))?;
    let Some(doc) = docs.first() else {
        return Ok(vec![Finding::new(
            Severity::Warn,
            file,
            "empty action file".into(),
        )]);
    };
    let mut findings = Vec::new();
    for uses in composite_action_uses(doc) {
        check_uses_ref(file, &uses, &mut findings);
    }
    Ok(findings)
}

fn permissions_is_write_all(perms: &Yaml) -> bool {
    perms.as_str() == Some("write-all")
}

fn audit_permissions(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    let top = &doc["permissions"];
    let top_present = !top.is_badvalue();
    if top_present && permissions_is_write_all(top) {
        findings.push(Finding::new(
            Severity::Error,
            file,
            "top-level `permissions: write-all` — grant specific least-privilege scopes".into(),
        ));
    }
    let mut all_jobs_scoped = true;
    for (name, job) in jobs(doc) {
        let jp = &job["permissions"];
        if jp.is_badvalue() {
            all_jobs_scoped = false;
        } else if permissions_is_write_all(jp) {
            findings.push(Finding::new(
                Severity::Error,
                file,
                format!("job `{name}` uses `permissions: write-all`"),
            ));
        }
    }
    if !top_present && !all_jobs_scoped {
        findings.push(Finding::new(
            Severity::Error,
            file,
            "no `permissions:` block at workflow or job level — the default GITHUB_TOKEN grant \
             is too broad; add an explicit least-privilege block"
                .into(),
        ));
    }
}

fn audit_pull_request_target(file: &str, doc: &Yaml, raw: &str, findings: &mut Vec<Finding>) {
    let triggers = &doc["on"];
    let has_prt = match triggers {
        Yaml::String(s) => s == "pull_request_target",
        Yaml::Array(a) => a.iter().any(|v| v.as_str() == Some("pull_request_target")),
        Yaml::Hash(h) => h.keys().any(|k| k.as_str() == Some("pull_request_target")),
        _ => false,
    };
    if !has_prt {
        return;
    }
    let checks_out_pr_head = raw.contains("github.event.pull_request.head");
    if checks_out_pr_head {
        findings.push(Finding::new(
            Severity::Error,
            file,
            "`pull_request_target` combined with checkout of the PR head — untrusted code runs \
             with a privileged token (classic pwn-request); use `pull_request` or split the \
             privileged half into a separate workflow"
                .into(),
        ));
    } else {
        findings.push(Finding::new(
            Severity::Warn,
            file,
            "`pull_request_target` trigger — runs with a privileged token in the base repo \
             context; ensure it never executes PR-controlled code"
                .into(),
        ));
    }
}

fn audit_checkout_credentials(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for (name, job) in jobs(doc) {
        for step in steps(job) {
            let Some(uses) = step["uses"].as_str() else {
                continue;
            };
            if !uses.starts_with("actions/checkout@") {
                continue;
            }
            let persist = &step["with"]["persist-credentials"];
            let disabled = persist.as_bool() == Some(false) || persist.as_str() == Some("false");
            if !disabled {
                findings.push(Finding::new(
                    Severity::Warn,
                    file,
                    format!(
                        "job `{name}`: actions/checkout without `persist-credentials: false` — \
                         the GITHUB_TOKEN stays on disk for later steps to exfiltrate"
                    ),
                ));
            }
        }
    }
}

fn audit_secret_exposure(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for (name, job) in jobs(doc) {
        for step in steps(job) {
            let Some(run) = step["run"].as_str() else {
                continue;
            };
            let uses_secret = run.contains("${{ secrets.") || run.contains("${{secrets.");
            let dumps = run.contains("echo")
                || run.contains("printenv")
                || run.contains("env |")
                || run.contains("set -x");
            if uses_secret && dumps {
                findings.push(Finding::new(
                    Severity::Warn,
                    file,
                    format!(
                        "job `{name}`: a `run:` step both references `secrets.*` and echoes/dumps \
                         environment — check for secret exposure in logs"
                    ),
                ));
            }
        }
    }
}

fn audit_risky_actions(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for uses in all_uses(doc) {
        let action = uses.split('@').next().unwrap_or(&uses);
        for (risky, replacement) in RISKY_ACTION_SUBSTITUTIONS {
            if action == *risky {
                findings.push(Finding::new(
                    Severity::Warn,
                    file,
                    format!(
                        "`{action}` has a maintained StepSecurity replacement: `{replacement}` — \
                         prefer the maintained fork (see docs/phase-4.md)"
                    ),
                ));
            }
        }
    }
}

fn audit_lockfile_exact(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    const PATTERNS: &[(&str, &str)] = &[
        (
            "npm install",
            "use `npm ci` for lockfile-exact installs in CI",
        ),
        (
            "yarn install",
            "add `--frozen-lockfile` (or use `yarn install --immutable`)",
        ),
        ("pnpm install", "add `--frozen-lockfile`"),
        ("cargo install ", "add `--locked` so Cargo.lock is honored"),
    ];
    for (name, job) in jobs(doc) {
        for step in steps(job) {
            let Some(run) = step["run"].as_str() else {
                continue;
            };
            for (pat, advice) in PATTERNS {
                let lockfile_exact = run.contains("--frozen-lockfile")
                    || run.contains("--immutable")
                    || run.contains("--locked")
                    || (pat.starts_with("npm") && run.contains("npm ci"));
                if run.contains(pat) && !lockfile_exact {
                    findings.push(Finding::new(
                        Severity::Warn,
                        file,
                        format!("job `{name}`: `{pat}` is not lockfile-exact — {advice}"),
                    ));
                }
            }
        }
    }
}

fn audit_harden_runner(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for (name, job) in jobs(doc) {
        // Reusable-workflow jobs have no steps of their own.
        if job["uses"].as_str().is_some() {
            continue;
        }
        let first_uses = steps(job)
            .first()
            .and_then(|s| s["uses"].as_str())
            .unwrap_or("");
        if !first_uses.starts_with("step-security/harden-runner@") {
            findings.push(Finding::new(
                Severity::Warn,
                file,
                format!(
                    "job `{name}` does not start with step-security/harden-runner — runner \
                     egress/tamper monitoring is absent for this job"
                ),
            ));
        }
    }
}

/// Audit all workflows in the repo.
pub fn audit_repo(ctx: &Ctx, extended: bool) -> Result<Vec<Finding>> {
    let dir = ctx.root.join(".github").join("workflows");
    let mut findings = Vec::new();
    if !dir.is_dir() {
        return Ok(findings);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yml" || e == "yaml")
        })
        .collect();
    entries.sort();
    for path in entries {
        let rel = format!(
            ".github/workflows/{}",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        let content = std::fs::read_to_string(&path)?;
        match audit_workflow(&rel, &content, extended) {
            Ok(f) => findings.extend(f),
            Err(err) => findings.push(Finding::new(
                Severity::Error,
                &rel,
                format!("unparseable workflow: {err:#}"),
            )),
        }
    }
    // Also audit local composite actions the workflows `uses: ./...`. Their
    // internal `uses:` refs must be pinned just like a workflow's.
    findings.extend(audit_local_actions(ctx)?);
    Ok(findings)
}

/// Audit every `.github/actions/<name>/action.yml` (or `.yaml`) in the repo.
fn audit_local_actions(ctx: &Ctx) -> Result<Vec<Finding>> {
    let actions_dir = ctx.root.join(".github").join("actions");
    let mut findings = Vec::new();
    if !actions_dir.is_dir() {
        return Ok(findings);
    }
    let mut dirs: Vec<_> = std::fs::read_dir(&actions_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for d in dirs {
        for fname in ["action.yml", "action.yaml"] {
            let path = d.join(fname);
            if !path.is_file() {
                continue;
            }
            let rel = format!(
                ".github/actions/{}/{fname}",
                d.file_name().unwrap_or_default().to_string_lossy()
            );
            let content = std::fs::read_to_string(&path)?;
            match audit_action_file(&rel, &content) {
                Ok(f) => findings.extend(f),
                Err(err) => findings.push(Finding::new(
                    Severity::Error,
                    &rel,
                    format!("unparseable action: {err:#}"),
                )),
            }
        }
    }
    Ok(findings)
}

pub fn verify_actions_control(ctx: &Ctx, extended: bool) -> VerifyResult {
    let id: &'static str = if extended {
        "workflow-audit-extended"
    } else {
        "actions-audit"
    };
    match audit_repo(ctx, extended) {
        Err(err) => VerifyResult::new(id, Outcome::Fail, vec![format!("audit failed: {err:#}")]),
        Ok(findings) => {
            if findings.is_empty() {
                let dir = ctx.root.join(".github").join("workflows");
                let msg = if dir.is_dir() {
                    "all workflows pass (SHA-pinned, least-privilege)".to_string()
                } else {
                    "no .github/workflows directory — nothing to audit yet".to_string()
                };
                return VerifyResult::new(id, Outcome::Pass, vec![msg]);
            }
            let errors = findings
                .iter()
                .filter(|f| f.severity == Severity::Error)
                .count();
            let outcome = if errors > 0 {
                Outcome::Fail
            } else {
                Outcome::Pass
            };
            let messages = findings
                .iter()
                .map(|f| {
                    format!(
                        "[{}] {}: {}",
                        match f.severity {
                            Severity::Error => "ERROR",
                            Severity::Warn => "warn",
                            Severity::Info => "info",
                        },
                        f.file,
                        f.message
                    )
                })
                .collect();
            VerifyResult::new(id, outcome, messages)
        }
    }
}

/// Verify GitHub branch protection through the rules API (covers classic
/// protection AND rulesets).
pub fn verify_branch_protection(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "branch-protection";
    if crate::exec::find_in_path("gh").is_none() {
        return VerifyResult::new(
            id,
            Outcome::Degraded,
            vec![crate::tools::degrade_message("gh", ctx.platform)],
        );
    }
    let Some(slug) = cfg.github_repo().or_else(|| ctx.origin_slug()) else {
        return VerifyResult::new(
            id,
            Outcome::Degraded,
            vec![
                "no GitHub repo configured (general.github_repo) and no origin remote — \
                 cannot verify branch protection"
                    .into(),
            ],
        );
    };
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    for branch in cfg.protected_branches() {
        let api = format!("repos/{slug}/rules/branches/{branch}");
        let out = match exec::run("gh", &["api", &api], Some(&ctx.root)) {
            Ok(o) => o,
            Err(err) => {
                return VerifyResult::new(
                    id,
                    Outcome::Degraded,
                    vec![format!("gh failed: {err:#}")],
                )
            }
        };
        if !out.success() {
            messages.push(format!(
                "{branch}: could not query rules API ({}) — branch may not exist on the remote",
                out.stderr.lines().next().unwrap_or("error")
            ));
            continue;
        }
        let rules: Vec<serde_json::Value> = serde_json::from_str(&out.stdout).unwrap_or_default();
        let active: Vec<&str> = rules
            .iter()
            .filter_map(|r| r.get("type").and_then(|t| t.as_str()))
            .collect();
        let mut gaps = Vec::new();
        for (rule, label, remediation) in [
            (
                "pull_request",
                "required pull requests",
                "add a ruleset requiring PRs before merging",
            ),
            (
                "non_fast_forward",
                "force-push blocking",
                "enable 'Block force pushes'",
            ),
            (
                "required_signatures",
                "required signed commits",
                "enable 'Require signed commits'",
            ),
            (
                "required_status_checks",
                "required status checks",
                "require your CI checks before merge",
            ),
        ] {
            if active.contains(&rule) {
                messages.push(format!("{branch}: {label} ✓"));
            } else {
                gaps.push(format!("{branch}: MISSING {label} — {remediation}"));
            }
        }
        if active.contains(&"deletion") {
            messages.push(format!("{branch}: deletion protection ✓"));
        }
        if !gaps.is_empty() {
            outcome = Outcome::Fail;
            messages.extend(gaps);
        }
    }
    VerifyResult::new(id, outcome, messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Ctx;

    /// Throwaway repo bootstrapped through the real `sscsb init` path —
    /// mirrors the pattern in `tests/library.rs` so audit-control tests run
    /// against the same layout a user gets.
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

    /// Serializes tests that temporarily prepend a fake `gh` onto PATH.
    /// Nothing else in this crate's test suite shells out to `gh`, so a
    /// prepend-only mutation (never removing existing PATH entries) cannot
    /// affect any other test's tool resolution — this lock only protects our
    /// own PATH-touching tests from racing each other.
    static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that prepends `dir` onto PATH and restores the original
    /// value on drop (including on panic, so a failing assertion never
    /// leaves the test process with a mutated PATH).
    struct PathPrepend {
        original: Option<std::ffi::OsString>,
    }

    impl PathPrepend {
        fn new(dir: &std::path::Path) -> Self {
            let original = std::env::var_os("PATH");
            let mut joined = std::ffi::OsString::from(dir.as_os_str());
            if let Some(orig) = &original {
                joined.push(":");
                joined.push(orig);
            }
            std::env::set_var("PATH", joined);
            PathPrepend { original }
        }
    }

    impl Drop for PathPrepend {
        fn drop(&mut self) {
            match self.original.take() {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    /// Writes a fake, executable `gh` POSIX shim into a fresh temp dir that
    /// understands exactly `gh api repos/*/rules/branches/<branch>` and
    /// returns deterministic, scripted responses keyed on the branch name —
    /// so the branch-protection matrix logic can be exercised without any
    /// real network call.
    fn fake_gh(script: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    const PINNED_OK: &str = r#"
name: ok
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920
        with:
          egress-policy: audit
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
        with:
          persist-credentials: false
      - run: cargo build --locked
"#;

    #[test]
    fn clean_pinned_workflow_passes_basic_and_extended() {
        assert!(audit_workflow("ok.yml", PINNED_OK, false)
            .unwrap()
            .is_empty());
        assert!(audit_workflow("ok.yml", PINNED_OK, true)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn mutable_ref_flagged() {
        let wf = "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::Error && x.message.contains("mutable ref")));
    }

    #[test]
    fn slsa_generator_tag_pin_is_sanctioned() {
        let wf = "on: push\npermissions: {}\njobs:\n  p:\n    permissions:\n      id-token: write\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(f.iter().all(|x| x.severity != Severity::Error), "{f:?}");
        assert!(f.iter().any(|x| x.message.contains("tag-pinned by design")));
    }

    #[test]
    fn missing_permissions_and_write_all_flagged() {
        let wf =
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(f
            .iter()
            .any(|x| x.message.contains("no `permissions:` block")));

        let wf = "on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(f.iter().any(|x| x.message.contains("write-all")));
    }

    #[test]
    fn pwn_request_pattern_is_error() {
        let wf = r#"
on: pull_request_target
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: make test
"#;
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::Error && x.message.contains("pwn-request")));
    }

    #[test]
    fn extended_checks_fire() {
        let wf = r#"
on: push
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - uses: tj-actions/changed-files@aa08304bd477b800d468db44fe10f6c61f7f7b11
      - run: |
          echo "${{ secrets.MY_TOKEN }}" > token.txt
          npm install
"#;
        let f = audit_workflow("w.yml", wf, true).unwrap();
        let msgs: Vec<&str> = f.iter().map(|x| x.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("persist-credentials")));
        assert!(msgs
            .iter()
            .any(|m| m.contains("step-security/changed-files")));
        assert!(msgs.iter().any(|m| m.contains("secret exposure")));
        assert!(msgs.iter().any(|m| m.contains("npm ci")));
        assert!(msgs.iter().any(|m| m.contains("harden-runner")));
    }

    #[test]
    fn empty_workflow_yaml_is_flagged_as_empty_not_parsed() {
        let f = audit_workflow("empty.yml", "", false).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].message.contains("empty workflow file"));
    }

    #[test]
    fn workflow_with_no_jobs_key_has_nothing_to_walk() {
        // No `jobs:` at all — jobs()/all_uses() must degrade to empty rather
        // than treat the document as malformed. Top-level permissions are
        // present so the missing-permissions rule stays out of the way.
        let wf = "on: push\npermissions:\n  contents: read\n";
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(f.is_empty(), "no jobs means nothing to audit: {f:?}");
    }

    #[test]
    fn workflow_with_empty_jobs_map_has_nothing_to_walk() {
        // `jobs:` present but empty — the hash branch of jobs() is entered
        // and the loop runs zero iterations.
        let wf = "on: push\npermissions:\n  contents: read\njobs: {}\n";
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(f.is_empty(), "empty jobs map yields no findings: {f:?}");
    }

    #[test]
    fn local_and_docker_uses_refs_are_skipped_not_flagged() {
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/local\n      - uses: docker://alpine:3.19\n      - run: echo hi\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(
            f.is_empty(),
            "local composite actions and docker refs are out of scope: {f:?}"
        );
    }

    #[test]
    fn uses_without_at_ref_is_flagged_with_no_ref_message() {
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::Error && x.message.contains("has no ref")));
    }

    #[test]
    fn job_level_write_all_permissions_flagged() {
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    permissions: write-all\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(f
            .iter()
            .any(|x| x.message.contains("job `b` uses `permissions: write-all`")));
    }

    #[test]
    fn pull_request_target_trigger_detected_in_array_and_map_forms() {
        let array_wf = "on: [push, pull_request_target]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        let f = audit_workflow("array.yml", array_wf, true).unwrap();
        assert!(f.iter().any(|x| x.severity == Severity::Warn
            && x.message.contains("privileged token in the base repo")));

        let map_wf = "on:\n  pull_request_target:\n    types: [opened]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        let f = audit_workflow("map.yml", map_wf, true).unwrap();
        assert!(f.iter().any(|x| x.severity == Severity::Warn
            && x.message.contains("privileged token in the base repo")));
    }

    #[test]
    fn audit_repo_surfaces_filesystem_errors_not_just_yaml_errors() {
        let (_d, ctx) = repo();
        // A directory masquerading as a workflow file: read_to_string must
        // fail, and that failure must propagate out of audit_repo rather
        // than being silently swallowed.
        std::fs::create_dir(ctx.root.join(".github/workflows/not-a-file.yml")).unwrap();
        let result = verify_actions_control(&ctx, false);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages.iter().any(|m| m.contains("audit failed")));
    }

    #[test]
    fn verify_actions_control_passes_cleanly_on_freshly_bootstrapped_templates() {
        let (_d, ctx) = repo();
        // release-slsa.yml carries the one sanctioned tag-pin exception,
        // which surfaces as an Info finding even under the basic (non-
        // extended) audit — remove it so this exercises the true
        // zero-findings "all workflows pass" branch.
        std::fs::remove_file(ctx.root.join(".github/workflows/release-slsa.yml")).unwrap();
        let result = verify_actions_control(&ctx, false);
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result.messages[0].contains("all workflows pass"));
    }

    #[test]
    fn branch_protection_degrades_when_no_repo_is_configured() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result.messages[0].contains("no GitHub repo configured"));
    }

    /// End-to-end matrix: one branch with every rule present (all ✓ +
    /// deletion protection), one branch with gaps (mixed ✓/MISSING → Fail),
    /// and one branch whose rules-API query itself fails (404-shaped) — all
    /// driven through a scripted `gh` stub so the assertions are
    /// deterministic and don't depend on live GitHub state.
    #[test]
    fn branch_protection_full_matrix_via_stubbed_gh() {
        let _guard = PATH_LOCK.lock().unwrap();
        let script = r#"#!/bin/sh
case "$2" in
    */rules/branches/full)
        echo '[{"type":"pull_request"},{"type":"non_fast_forward"},{"type":"required_signatures"},{"type":"required_status_checks"},{"type":"deletion"}]'
        exit 0
        ;;
    */rules/branches/gaps)
        echo '[{"type":"deletion"}]'
        exit 0
        ;;
    */rules/branches/missing)
        echo "HTTP 404: Not Found" 1>&2
        exit 1
        ;;
    *)
        echo '[]'
        exit 0
        ;;
esac
"#;
        let gh_dir = fake_gh(script);
        let _path = PathPrepend::new(gh_dir.path());

        let (_d, ctx) = repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace(
                "protected_branches = [\"main\", \"master\"]",
                "protected_branches = [\"full\", \"gaps\", \"missing\"]",
            )
            .replace(
                "# github_repo = \"owner/repo\"  # set to enable GitHub API checks",
                "github_repo = \"acme/demo\"",
            );
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);

        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("full: required pull requests ✓")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("full: force-push blocking ✓")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("full: required signed commits ✓")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("full: required status checks ✓")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("full: deletion protection ✓")));

        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("gaps: MISSING required pull requests")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("gaps: MISSING force-push blocking")));

        assert!(result.messages.iter().any(|m| m.contains("missing")
            && m.contains("could not query rules API")
            && m.contains("branch may not exist on the remote")));
    }

    #[test]
    fn sha_and_semver_helpers() {
        assert!(is_full_sha("9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"));
        assert!(!is_full_sha("v4"));
        assert!(!is_full_sha("9c091bb"));
        assert!(is_semver_tag("v2.1.0"));
        assert!(!is_semver_tag("v2.1"));
        assert!(!is_semver_tag("2.1.0"));
    }
}
