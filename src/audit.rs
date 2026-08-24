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
const TAG_PIN_EXCEPTION_REPO: &str = "slsa-framework/slsa-github-generator";

/// Does this action path belong to the one repository the tag-pin exception
/// names?
///
/// A `starts_with` prefix test does not answer that question: it also matches
/// `slsa-framework/slsa-github-generator-anything`, a DIFFERENT repository
/// under the same owner, which would have inherited a licence to use mutable
/// refs from a rule written for exactly one builder. The exception ends at the
/// repository boundary — the path is either the repo itself or a `/`-separated
/// path inside it.
fn is_tag_pin_exception(action: &str) -> bool {
    action == TAG_PIN_EXCEPTION_REPO
        || action
            .strip_prefix(TAG_PIN_EXCEPTION_REPO)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Does this `uses:` reference an actions/checkout-shaped action?
///
/// The credential-persistence hazard belongs to the BEHAVIOUR, not to the
/// `actions` org: a fork (`myorg/checkout`) or a re-publish
/// (`myorg/checkout-action`, `myorg/action-checkout`) leaves the same
/// GITHUB_TOKEN in `.git/config` for every later step to read. Matching the
/// literal string `actions/checkout@` asked the question of one publisher and
/// silently exempted all the others.
///
/// Deliberately narrow: the repository name, minus a conventional
/// `action-`/`-action` decoration, must BE `checkout`. An action whose name
/// merely contains the word is not one.
fn is_checkout_action(uses: &str) -> bool {
    let action = uses.split('@').next().unwrap_or(uses);
    let Some(repo) = action.split('/').nth(1) else {
        return false;
    };
    let lower = repo.to_ascii_lowercase();
    let stem = lower.strip_prefix("action-").unwrap_or(&lower);
    let stem = stem.strip_suffix("-action").unwrap_or(stem);
    stem == "checkout"
}

/// A YAML document that holds nothing — what a trailing `---` separator
/// produces. It is not a second workflow and owes no findings.
fn is_blank_doc(doc: &Yaml) -> bool {
    matches!(doc, Yaml::Null | Yaml::BadValue)
}

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

/// Prefix each finding raised by one document of a multi-document file with
/// which document it came from — otherwise the operator gets a finding they
/// cannot locate in the file.
fn locate(findings: &mut [Finding], index: usize, total: usize) {
    if total < 2 {
        return;
    }
    for f in findings.iter_mut() {
        f.message = format!("document {}: {}", index + 1, f.message);
    }
}

/// Audit one workflow file — EVERY YAML document in it.
///
/// A `---` separator used to end the audit: only `docs.first()` was ever
/// examined, so any jobs, actions or permissions living below the separator
/// were reported as clean without being looked at. Whether GitHub itself runs
/// a second document is beside the point — sscsb must not call a file clean on
/// the strength of the half it read.
pub fn audit_workflow(file: &str, content: &str, extended: bool) -> Result<Vec<Finding>> {
    let docs =
        YamlLoader::load_from_str(content).with_context(|| format!("parsing YAML in {file}"))?;
    let live: Vec<&Yaml> = docs.iter().filter(|d| !is_blank_doc(d)).collect();
    if live.is_empty() {
        return Ok(vec![Finding::new(
            Severity::Warn,
            file,
            "empty workflow file".into(),
        )]);
    }
    let mut findings = Vec::new();
    if live.len() > 1 {
        findings.push(Finding::new(
            Severity::Warn,
            file,
            format!(
                "file holds {} YAML documents — a GitHub Actions workflow file is a single \
                 document, so at least one of these is not the workflow anyone thinks is \
                 running; all of them were audited rather than assumed inert",
                live.len()
            ),
        ));
    }
    for (i, doc) in live.iter().enumerate() {
        let mut of_doc = Vec::new();
        audit_permissions(file, doc, &mut of_doc);
        audit_uses_refs(file, doc, &mut of_doc);

        if extended {
            audit_pull_request_target(file, doc, content, &mut of_doc);
            audit_checkout_credentials(file, doc, &mut of_doc);
            audit_secret_exposure(file, doc, &mut of_doc);
            audit_risky_actions(file, doc, &mut of_doc);
            audit_lockfile_exact(file, doc, &mut of_doc);
            audit_harden_runner(file, doc, &mut of_doc);
        }
        locate(&mut of_doc, i, live.len());
        findings.extend(of_doc);
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
    if is_tag_pin_exception(action) && is_semver_tag(r) {
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
    let live: Vec<&Yaml> = docs.iter().filter(|d| !is_blank_doc(d)).collect();
    if live.is_empty() {
        return Ok(vec![Finding::new(
            Severity::Warn,
            file,
            "empty action file".into(),
        )]);
    }
    let mut findings = Vec::new();
    // Same reasoning as `audit_workflow`: a `---` is not the end of the file.
    for (i, doc) in live.iter().enumerate() {
        let mut of_doc = Vec::new();
        for uses in composite_action_uses(doc) {
            check_uses_ref(file, &uses, &mut of_doc);
        }
        locate(&mut of_doc, i, live.len());
        findings.extend(of_doc);
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
            if !is_checkout_action(uses) {
                continue;
            }
            let action = uses.split('@').next().unwrap_or(uses);
            let persist = &step["with"]["persist-credentials"];
            let disabled = persist.as_bool() == Some(false) || persist.as_str() == Some("false");
            if !disabled {
                findings.push(Finding::new(
                    Severity::Warn,
                    file,
                    format!(
                        "job `{name}`: `{action}` checks out code without \
                         `persist-credentials: false` — the GITHUB_TOKEN stays on disk for later \
                         steps to exfiltrate"
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

/// Whether ONE job runs under Harden-Runner.
///
/// Harden-Runner protects the job whose step list it heads — not the file it
/// happens to appear in, and never a `#`-commented mention of itself. The
/// question is therefore only answerable per job, off the parsed document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardenRunner {
    /// The job's first step is `step-security/harden-runner@…`.
    Present,
    /// The job delegates to a reusable workflow and has no steps of its own,
    /// so no harden-runner step can be added here — hardening is the called
    /// workflow's responsibility. Carries the `uses:` target.
    Reusable(String),
    /// The job runs its own steps without starting them under harden-runner.
    Absent,
}

fn harden_runner_of(job: &Yaml) -> HardenRunner {
    // A reusable-workflow job has no steps of its own to harden.
    if let Some(uses) = job["uses"].as_str() {
        if steps(job).is_empty() {
            return HardenRunner::Reusable(uses.to_string());
        }
    }
    let first_uses = steps(job)
        .first()
        .and_then(|s| s["uses"].as_str())
        .unwrap_or("");
    if first_uses.starts_with("step-security/harden-runner@") {
        HardenRunner::Present
    } else {
        HardenRunner::Absent
    }
}

/// Per-job Harden-Runner status for one parsed workflow document.
fn harden_runner_jobs(doc: &Yaml) -> Vec<(String, HardenRunner)> {
    jobs(doc)
        .into_iter()
        .map(|(name, job)| (name.to_string(), harden_runner_of(job)))
        .collect()
}

/// Per-job Harden-Runner status for a workflow file's raw text, across EVERY
/// YAML document in it. Parsing is the point: a substring search over the text
/// matches commented-out references and cannot tell one job from another.
///
/// An empty result means the file declares no jobs at all — which proves
/// nothing about harden-runner, and callers must not read it as a pass.
pub fn harden_runner_status(content: &str) -> Result<Vec<(String, HardenRunner)>> {
    let docs = YamlLoader::load_from_str(content).context("parsing workflow YAML")?;
    Ok(docs.iter().flat_map(harden_runner_jobs).collect())
}

fn audit_harden_runner(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for (name, status) in harden_runner_jobs(doc) {
        if status == HardenRunner::Absent {
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
    let branches = cfg.protected_branches();
    if branches.is_empty() {
        return VerifyResult::new(
            id,
            Outcome::Degraded,
            vec![
                "no protected branches configured (general.protected_branches) — \
                 there is nothing to verify, which is not the same as being protected"
                    .into(),
            ],
        );
    }
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    // How many branches the rules API actually answered for. A branch that
    // could not be queried proves nothing about its protection, so if NOT ONE
    // was answered the control verified nothing at all — see the Degraded
    // return below.
    let mut answered = 0usize;
    for branch in &branches {
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
        answered += 1;
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

        // OpenSSF Scorecard "Branch-Protection" alignment: the rule-type checks
        // above only prove a rule EXISTS; Scorecard scores the granular
        // parameters. Surface each so `sscsb verify` mirrors what Scorecard sees.
        // Two tiers: knobs a SOLO maintainer can safely set, and knobs that
        // structurally require a SECOND reviewer (a solo owner cannot
        // self-approve without deadlocking their own merges — enabling those
        // would lock the owner out, so we report, never silently fail, on them).
        let rule_params = |ty: &str| -> Option<&serde_json::Value> {
            rules
                .iter()
                .find(|r| r.get("type").and_then(|t| t.as_str()) == Some(ty))
                .and_then(|r| r.get("parameters"))
        };
        if let Some(p) = rule_params("pull_request") {
            let flag = |k: &str| p.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
            let approvals = p
                .get("required_approving_review_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            // Solo-safe: dismissing stale approvals is a no-op when 0 approvals
            // are required, so it never blocks a solo owner — `harden` sets it.
            if flag("dismiss_stale_reviews_on_push") {
                messages.push(format!("{branch}: Scorecard — stale-review dismissal ✓"));
            } else {
                messages.push(format!(
                    "{branch}: Scorecard gap — stale-review dismissal off \
                     (solo-safe; fix: `sscsb harden branch-protection --apply`)"
                ));
            }

            // Second-reviewer tier — solo-capped.
            for (ok, label) in [
                (approvals >= 1, "≥1 required approving review"),
                (flag("require_code_owner_review"), "code-owner review"),
                (flag("require_last_push_approval"), "last-push approval"),
            ] {
                if ok {
                    messages.push(format!("{branch}: Scorecard — {label} ✓"));
                } else {
                    messages.push(format!(
                        "{branch}: Scorecard gap — {label} off (needs a 2nd reviewer; a \
                         solo maintainer cannot self-approve — opt in with \
                         `sscsb harden branch-protection --require-reviews` once you have one)"
                    ));
                }
            }
        }
        if let Some(p) = rule_params("required_status_checks") {
            if p.get("strict_required_status_checks_policy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                messages.push(format!(
                    "{branch}: Scorecard — branch-up-to-date (strict) ✓"
                ));
            } else {
                messages.push(format!(
                    "{branch}: Scorecard gap — status checks not strict \
                     (solo-safe; fix: `sscsb harden branch-protection --apply`)"
                ));
            }
        }

        if !gaps.is_empty() {
            outcome = Outcome::Fail;
            messages.extend(gaps);
        }
    }
    // Not one protected branch could be read: every rule check above was
    // skipped, so nothing was verified. "I could not check" is DEGRADED, never
    // PASS — a green branch-protection line here would be pure fiction.
    if answered == 0 {
        messages.push(format!(
            "NOTHING VERIFIED: the rules API answered for 0 of {} configured protected \
             branch(es) — branch protection is unverified, not confirmed",
            branches.len()
        ));
        return VerifyResult::new(id, Outcome::Degraded, messages);
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
    // Shared across modules (audit/harden/scorecard) so PATH-touching gh-stub
    // tests never run concurrently and race on $PATH.
    use crate::testutil::PATH_LOCK;

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

    /// Regression (C4): when the rules API answers for NOT ONE configured
    /// branch, every rule check inside the loop was skipped — nothing about
    /// branch protection was read. The failing-query arm pushed a message and
    /// `continue`d without touching `outcome`, so the optimistic initial
    /// `Outcome::Pass` survived and `sscsb verify --strict branch-protection`
    /// exited 0 against a repo slug that does not even exist. "I could not
    /// check" must report DEGRADED.
    #[test]
    fn branch_protection_degrades_when_not_one_branch_could_be_queried() {
        let _guard = PATH_LOCK.lock().unwrap();
        let gh_dir = fake_gh("#!/bin/sh\necho 'gh: Not Found (HTTP 404)' 1>&2\nexit 1\n");
        let _path = PathPrepend::new(gh_dir.path());

        let (_d, ctx) = crate::testutil::repo_with_gh_repo("acme/does-not-exist", "main");
        let cfg = ctx.require_config().unwrap();
        let result = verify_branch_protection(&ctx, cfg);

        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("could not query rules API")),
            "the per-branch failure must still be reported: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("NOTHING VERIFIED")
                    && m.contains("0 of 1 configured protected branch")),
            "the verdict must say nothing was verified: {:?}",
            result.messages
        );
    }

    /// An empty `protected_branches` list means the loop body never runs, which
    /// is likewise "nothing verified" rather than "all clear".
    #[test]
    fn branch_protection_degrades_when_no_protected_branches_are_configured() {
        let _guard = PATH_LOCK.lock().unwrap();
        // `gh` must resolve for the check under test to be reached at all.
        let gh_dir = fake_gh("#!/bin/sh\necho '[]'\nexit 0\n");
        let _path = PathPrepend::new(gh_dir.path());

        let (_d, ctx) = crate::testutil::repo_with_gh_repo("acme/demo", "main");
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("protected_branches = [\"main\"]", "protected_branches = []");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(result.messages[0].contains("no protected branches configured"));
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
    fn branch_protection_reports_scorecard_granular_fields() {
        let _guard = PATH_LOCK.lock().unwrap();
        // "aligned": every Scorecard knob set. "gaps2": all off.
        let script = r#"#!/bin/sh
case "$2" in
    */rules/branches/aligned)
        echo '[{"type":"pull_request","parameters":{"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true,"require_last_push_approval":true,"required_approving_review_count":1}},{"type":"non_fast_forward"},{"type":"required_signatures"},{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true}}]'
        exit 0
        ;;
    */rules/branches/gaps2)
        echo '[{"type":"pull_request","parameters":{"dismiss_stale_reviews_on_push":false,"require_code_owner_review":false,"require_last_push_approval":false,"required_approving_review_count":0}},{"type":"non_fast_forward"},{"type":"required_signatures"},{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false}}]'
        exit 0
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
                "protected_branches = [\"aligned\", \"gaps2\"]",
            )
            .replace(
                "# github_repo = \"owner/repo\"  # set to enable GitHub API checks",
                "github_repo = \"acme/demo\"",
            );
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        let m = |s: &str| result.messages.iter().any(|x| x.contains(s));

        // aligned branch: all Scorecard ✓
        assert!(m("aligned: Scorecard — stale-review dismissal ✓"));
        assert!(m("aligned: Scorecard — ≥1 required approving review ✓"));
        assert!(m("aligned: Scorecard — code-owner review ✓"));
        assert!(m("aligned: Scorecard — last-push approval ✓"));
        assert!(m("aligned: Scorecard — branch-up-to-date (strict) ✓"));

        // gaps2 branch: the solo-safe gap + the solo-capped tier both surfaced
        assert!(m("gaps2: Scorecard gap — stale-review dismissal off"));
        assert!(m("gaps2: Scorecard gap — ≥1 required approving review off"));
        assert!(m("gaps2: Scorecard gap — code-owner review off"));
        assert!(m("gaps2: Scorecard gap — last-push approval off"));
        assert!(m("gaps2: Scorecard gap — status checks not strict"));
        assert!(result
            .messages
            .iter()
            .any(|x| x.contains("cannot self-approve")));
    }

    /// M13(a): the tag-pin exception was a `starts_with` PREFIX test, so any
    /// repository whose path merely begins with the sanctioned one inherited
    /// permission to use a mutable ref. The exception belongs to exactly one
    /// repository.
    #[test]
    fn tag_pin_exception_does_not_extend_to_lookalike_repositories() {
        for lookalike in [
            "slsa-framework/slsa-github-generator-evil/.github/workflows/generator_generic_slsa3.yml",
            "slsa-framework/slsa-github-generator2",
        ] {
            let wf = format!(
                "on: push\npermissions: {{}}\njobs:\n  p:\n    permissions:\n      \
                 id-token: write\n    uses: {lookalike}@v2.1.0\n"
            );
            let f = audit_workflow("w.yml", &wf, false).unwrap();
            assert!(
                f.iter()
                    .any(|x| x.severity == Severity::Error && x.message.contains("mutable ref")),
                "`{lookalike}` is a different repository and must not inherit the tag-pin \
                 exception: {f:?}"
            );
        }

        // The genuine repository, and its reusable workflows, keep it.
        for genuine in [
            "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
            "slsa-framework/slsa-github-generator",
        ] {
            let wf = format!(
                "on: push\npermissions: {{}}\njobs:\n  p:\n    permissions:\n      \
                 id-token: write\n    uses: {genuine}@v2.1.0\n"
            );
            let f = audit_workflow("w.yml", &wf, false).unwrap();
            assert!(
                f.iter().all(|x| x.severity != Severity::Error),
                "the sanctioned exception must survive: {f:?}"
            );
            assert!(f.iter().any(|x| x.message.contains("tag-pinned by design")));
        }
    }

    /// M13(b): the credential-persistence check matched the literal string
    /// `actions/checkout@`, so a fork or re-publish of the same action — which
    /// leaves the same GITHUB_TOKEN on disk — was never asked the question.
    #[test]
    fn checkout_credential_check_covers_forks_and_republished_actions() {
        for fork in [
            "myorg/checkout",
            "myorg/checkout-action",
            "MyOrg/Checkout",
            "myorg/action-checkout",
        ] {
            let wf = format!(
                "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
                 runs-on: ubuntu-latest\n    steps:\n      \
                 - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n      \
                 - uses: {fork}@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
            );
            let f = audit_workflow("w.yml", &wf, true).unwrap();
            assert!(
                f.iter()
                    .any(|x| x.message.contains("persist-credentials") && x.message.contains(fork)),
                "`{fork}` checks out code with the same token exposure: {f:?}"
            );
        }

        // Setting it still silences the check, whoever publishes the action.
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
                  runs-on: ubuntu-latest\n    steps:\n      \
                  - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n      \
                  - uses: myorg/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n        \
                  with:\n          persist-credentials: false\n";
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(f.is_empty(), "no finding is owed here: {f:?}");

        // And an action that merely mentions checkout in a longer name is not
        // a checkout — this rule must not invent findings.
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
                  runs-on: ubuntu-latest\n    steps:\n      \
                  - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n      \
                  - uses: myorg/checkout-secrets-to-disk@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n";
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(f.is_empty(), "not a checkout action: {f:?}");
    }

    /// M13(c): only `docs.first()` was ever audited, so everything after a
    /// `---` separator was reported as clean without being looked at.
    #[test]
    fn every_yaml_document_in_a_workflow_file_is_audited() {
        let wf = format!("{PINNED_OK}---\non: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n");
        let f = audit_workflow("w.yml", &wf, false).unwrap();
        assert!(
            f.iter().any(|x| x.severity == Severity::Error
                && x.message.contains("mutable ref")
                && x.message.contains("document 2")),
            "the second document must be audited and located: {f:?}"
        );
        assert!(
            f.iter()
                .any(|x| x.severity == Severity::Warn && x.message.contains("2 YAML documents")),
            "the reader must be told the file is multi-document: {f:?}"
        );

        // A trailing separator is an empty document, not a hidden workflow.
        let f = audit_workflow("w.yml", &format!("{PINNED_OK}---\n"), true).unwrap();
        assert!(f.is_empty(), "a trailing `---` owes no finding: {f:?}");

        // A file that is nothing BUT a separator declares no workflow at all —
        // it used to audit an empty document and report the file as clean.
        let f = audit_workflow("w.yml", "---\n", false).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("empty workflow file"));
    }

    /// Composite action definitions hide the same way.
    #[test]
    fn every_yaml_document_in_a_composite_action_is_audited() {
        let action = "name: setup\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n---\nname: shadow\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n";
        let f = audit_action_file("a.yml", action).unwrap();
        assert!(
            f.iter().any(|x| x.severity == Severity::Error
                && x.message.contains("mutable ref")
                && x.message.contains("document 2")),
            "{f:?}"
        );
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
