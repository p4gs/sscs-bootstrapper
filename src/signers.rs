//! Agent-signing: the (default-off) `agent-signing` control, signer-policy
//! description and mutation (`sscsb signers ...`), per-commit signature
//! classification, and backend setup guidance (`sscsb agent-key setup`).
//!
//! Load-bearing invariant, enforced here and in [`crate::hooks`]: an `ai`-class
//! signature is verifiable as an AGENT signature (so an agent's work is
//! attributable and non-repudiable on a feature branch) but is NEVER valid on a
//! protected branch. That gate lives in `hooks::check_signing_for_range` and
//! keys on `class`; nothing in this module can loosen it. `backend` and
//! `attestation_file` are descriptive only — they never elevate a signer's
//! class or change a gate outcome (ISC-A6).

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::hooks::{self, Signer, SignerClass};
use anyhow::{Context as _, Result};
use chrono::NaiveDate;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::Path;

const CONTROL: &str = "agent-signing";
const KNOWN_BACKENDS: &[&str] = &["tpm", "fido2", "kms", "github-app", "piv", "software"];

// ───────────────────────────── expiry evaluation ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiryState {
    /// No `expires` set on the signer.
    Unset,
    /// Parsed and still in the future, within the rotation window.
    Valid { days_left: i64 },
    /// Parsed but already in the past — the key must be rotated.
    Expired { days_ago: i64 },
    /// Valid, but the window exceeds `max_key_age_days` — rotate sooner.
    WindowTooLong { days_left: i64, max: i64 },
    /// `expires` present but not a `YYYY-MM-DD` date.
    Unparseable,
}

/// Pure expiry evaluation so tests can pin "today" rather than depend on the
/// wall clock. `max_age_days <= 0` disables the window-too-long check.
pub fn evaluate_expiry(expires: Option<&str>, today: NaiveDate, max_age_days: i64) -> ExpiryState {
    let Some(raw) = expires else {
        return ExpiryState::Unset;
    };
    let Ok(date) = NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d") else {
        return ExpiryState::Unparseable;
    };
    let days = (date - today).num_days();
    if days < 0 {
        ExpiryState::Expired { days_ago: -days }
    } else if max_age_days > 0 && days > max_age_days {
        ExpiryState::WindowTooLong {
            days_left: days,
            max: max_age_days,
        }
    } else {
        ExpiryState::Valid { days_left: days }
    }
}

// ─────────────────────────── attestation evaluation ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationState {
    /// No `attestation_file` — the hardware claim is self-declared only.
    Declared,
    /// Artifact present; sscsb records its sha256 (it does NOT verify a FIDO
    /// MDS chain in v1 — presence + hash only, see D-5).
    Attested { sha256: String },
    /// `attestation_file` set but the file is absent — a misconfiguration.
    Missing { path: String },
}

/// Resolve a signer's attestation artifact relative to the repo root.
pub fn evaluate_attestation(
    root: &Path,
    attestation_file: Option<&str>,
) -> Result<AttestationState> {
    let Some(rel) = attestation_file else {
        return Ok(AttestationState::Declared);
    };
    let path = root.join(rel);
    if !path.is_file() {
        return Ok(AttestationState::Missing {
            path: rel.to_string(),
        });
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(AttestationState::Attested {
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

fn class_label(class: &SignerClass) -> &'static str {
    match class {
        SignerClass::Human => "human",
        SignerClass::Ci => "ci",
        SignerClass::Ai => "agent",
    }
}

// ───────────────────────────── verify control ───────────────────────────────

/// Verify the `agent-signing` control. Reports every configured signer's class,
/// backend, expiry, and attestation state, and FAILs on policy collisions
/// (unknown/disallowed backend, expired or malformed key, missing attestation).
pub fn verify_agent_signing_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    if !hooks::hooks_installed(ctx) {
        return VerifyResult::new(
            CONTROL,
            Outcome::Fail,
            vec!["hooks not installed — run `sscsb init`".into()],
        );
    }
    // A parse error (bad class, duplicate principal, non-table) is a hard fail:
    // the policy that gates agent identities must itself be well-formed.
    let signers = match hooks::load_signers(&hooks::signers_path(ctx)) {
        Ok(s) => s,
        Err(err) => {
            return VerifyResult::new(
                CONTROL,
                Outcome::Fail,
                vec![format!("signers policy invalid: {err:#}")],
            )
        }
    };

    let allowed_backends = cfg
        .control_opt_str_list(CONTROL, "allowed_backends")
        .unwrap_or_else(|| KNOWN_BACKENDS.iter().map(|s| s.to_string()).collect());
    let max_age = cfg
        .control_opt_int(CONTROL, "max_key_age_days")
        .unwrap_or(90);
    let require_sigs = cfg
        .control_opt_bool(CONTROL, "require_agent_signatures")
        .unwrap_or(false);
    let today = chrono::Utc::now().date_naive();

    let mut messages = vec![
        format!("allowed backends: {}", allowed_backends.join(", ")),
        format!("policy: agent signatures required = {require_sigs}"),
        format!("policy: rotate agent keys within {max_age} day(s)"),
    ];
    let mut outcome = Outcome::Pass;
    let fail = |m: String, out: &mut Outcome, msgs: &mut Vec<String>| {
        *out = Outcome::Fail;
        msgs.push(m);
    };

    let agents: Vec<&Signer> = signers
        .iter()
        .filter(|s| s.class == SignerClass::Ai)
        .collect();
    if agents.is_empty() {
        messages.push(
            "agent-signing enabled but no `class = \"ai\"` signer configured — add one with \
             `sscsb signers add` (see docs/agent-signing.md)"
                .into(),
        );
        // Nothing to attest yet — this is an incomplete setup, not a hard fail.
        return VerifyResult::new(CONTROL, Outcome::Degraded, messages);
    }

    for s in &signers {
        let mut line = format!("{} [{}]", s.principal, class_label(&s.class));
        // Backend must be recognized AND in the allowed list (agents only).
        if let Some(backend) = &s.backend {
            let _ = write!(line, " backend={backend}");
            if !KNOWN_BACKENDS.contains(&backend.as_str()) {
                fail(
                    format!(
                        "{}: unknown backend `{backend}` — must be one of {}",
                        s.principal,
                        KNOWN_BACKENDS.join("|")
                    ),
                    &mut outcome,
                    &mut messages,
                );
            } else if s.class == SignerClass::Ai && !allowed_backends.iter().any(|b| b == backend) {
                fail(
                    format!(
                        "{}: backend `{backend}` is not in this repo's allowed_backends ({})",
                        s.principal,
                        allowed_backends.join(", ")
                    ),
                    &mut outcome,
                    &mut messages,
                );
            }
        } else if s.class == SignerClass::Ai {
            let _ = write!(line, " backend=unspecified");
        }

        // Expiry — only meaningful for agent keys, which are the rotating ones.
        if s.class == SignerClass::Ai {
            match evaluate_expiry(s.expires.as_deref(), today, max_age) {
                ExpiryState::Unset => {
                    let _ = write!(line, " expiry=unset");
                }
                ExpiryState::Valid { days_left } => {
                    let _ = write!(line, " expiry=ok({days_left}d left)");
                }
                ExpiryState::WindowTooLong { days_left, max } => {
                    let _ = write!(line, " expiry={days_left}d(> {max}d window)");
                    if outcome == Outcome::Pass {
                        outcome = Outcome::Degraded;
                    }
                }
                ExpiryState::Expired { days_ago } => {
                    let _ = write!(line, " expiry=EXPIRED({days_ago}d ago)");
                    fail(
                        format!(
                            "{}: signing key EXPIRED {days_ago} day(s) ago — rotate it",
                            s.principal
                        ),
                        &mut outcome,
                        &mut messages,
                    );
                }
                ExpiryState::Unparseable => {
                    let _ = write!(line, " expiry=INVALID");
                    fail(
                        format!("{}: `expires` is not a YYYY-MM-DD date", s.principal),
                        &mut outcome,
                        &mut messages,
                    );
                }
            }
        }

        // Attestation state (agents; humans/ci may carry one too, harmlessly).
        match evaluate_attestation(&ctx.root, s.attestation_file.as_deref()) {
            Ok(AttestationState::Declared) => {
                if s.hardware_backed {
                    let _ = write!(line, " hardware=declared");
                }
            }
            Ok(AttestationState::Attested { sha256 }) => {
                let _ = write!(
                    line,
                    " hardware=attested(sha256:{})",
                    &sha256[..sha256.len().min(12)]
                );
            }
            Ok(AttestationState::Missing { path }) => {
                let _ = write!(line, " hardware=ATTESTATION-MISSING");
                fail(
                    format!("{}: attestation_file `{path}` does not exist", s.principal),
                    &mut outcome,
                    &mut messages,
                );
            }
            Err(err) => fail(
                format!("{}: reading attestation failed: {err:#}", s.principal),
                &mut outcome,
                &mut messages,
            ),
        }
        messages.push(line);
    }

    // The server-side gate (F5) is the only thing that holds in cloud/mobile;
    // if the control is on but its workflow isn't installed, that is a real gap.
    for a in crate::workflows::artifacts_for(CONTROL) {
        if ctx.root.join(a.dest).is_file() {
            messages.push(format!("{} installed", a.dest));
        } else {
            messages.push(format!(
                "{} MISSING — the server-side policy gate is not installed; run `sscsb init`",
                a.dest
            ));
            if outcome == Outcome::Pass {
                outcome = Outcome::Degraded;
            }
        }
    }

    VerifyResult::new(CONTROL, outcome, messages)
}

// ─────────────────────────── signer description ─────────────────────────────

/// Human-readable one line per configured signer, for `sscsb signers list`.
pub fn describe_signers(ctx: &Ctx) -> Result<Vec<String>> {
    let signers = hooks::load_signers(&hooks::signers_path(ctx))?;
    if signers.is_empty() {
        return Ok(vec![
            "no signers configured — add one with `sscsb signers add` (see docs/signing.md)".into(),
        ]);
    }
    let today = chrono::Utc::now().date_naive();
    let mut out = Vec::new();
    for s in &signers {
        let backend = s.backend.as_deref().unwrap_or("-");
        let attest = match evaluate_attestation(&ctx.root, s.attestation_file.as_deref())? {
            AttestationState::Declared if s.hardware_backed => "hw:declared",
            AttestationState::Declared => "hw:software",
            AttestationState::Attested { .. } => "hw:attested",
            AttestationState::Missing { .. } => "hw:attestation-missing",
        };
        let expiry = match evaluate_expiry(s.expires.as_deref(), today, 0) {
            ExpiryState::Unset => "expiry:-".to_string(),
            ExpiryState::Valid { days_left } => format!("expiry:{days_left}d"),
            ExpiryState::Expired { days_ago } => format!("expiry:EXPIRED-{days_ago}d"),
            ExpiryState::WindowTooLong { days_left, .. } => format!("expiry:{days_left}d"),
            ExpiryState::Unparseable => "expiry:INVALID".to_string(),
        };
        out.push(format!(
            "{:<32} class:{:<6} backend:{:<11} {attest} {expiry}",
            s.principal,
            class_label(&s.class),
            backend
        ));
    }
    Ok(out)
}

// ───────────────────────────── signer mutation ──────────────────────────────

/// A new signer to append to `.sscsb/policy/signers.toml`.
#[derive(Debug, Clone)]
pub struct NewSigner {
    pub principal: String,
    pub class: String,
    pub ssh_public_key: Option<String>,
    pub gpg_fingerprint: Option<String>,
    pub backend: Option<String>,
    pub hardware_backed: bool,
    pub expires: Option<String>,
}

/// Render a `[[signer]]` TOML block. Kept separate so it can be unit-tested and
/// so `add_signer` can validate the whole-file parse before writing.
fn render_signer_block(spec: &NewSigner) -> String {
    let mut b = String::from("\n[[signer]]\n");
    let _ = writeln!(b, "principal = \"{}\"", spec.principal);
    let _ = writeln!(b, "class = \"{}\"", spec.class);
    if let Some(backend) = &spec.backend {
        let _ = writeln!(b, "backend = \"{backend}\"");
    }
    let _ = writeln!(b, "hardware_backed = {}", spec.hardware_backed);
    if let Some(key) = &spec.ssh_public_key {
        let _ = writeln!(b, "ssh_public_key = \"{}\"", key.trim());
    }
    if let Some(fp) = &spec.gpg_fingerprint {
        let _ = writeln!(b, "gpg_fingerprint = \"{fp}\"");
    }
    if let Some(exp) = &spec.expires {
        let _ = writeln!(b, "expires = \"{exp}\"");
    }
    b
}

/// Append a signer to policy, validating the RESULTING file parses (which
/// enforces class validity, duplicate-principal rejection, etc.) before it is
/// written, then regenerate allowed_signers. Returns a status line.
pub fn add_signer(ctx: &Ctx, cfg: &Config, spec: &NewSigner) -> Result<String> {
    if !matches!(spec.class.as_str(), "human" | "ci" | "ai") {
        anyhow::bail!("class must be human|ci|ai (got `{}`)", spec.class);
    }
    if spec.ssh_public_key.is_none() && spec.gpg_fingerprint.is_none() {
        anyhow::bail!("a signer needs an ssh_public_key or a gpg_fingerprint");
    }
    if let Some(backend) = &spec.backend {
        anyhow::ensure!(
            KNOWN_BACKENDS.contains(&backend.as_str()),
            "unknown backend `{backend}` — one of {}",
            KNOWN_BACKENDS.join("|")
        );
    }
    if let Some(exp) = &spec.expires {
        anyhow::ensure!(
            NaiveDate::parse_from_str(exp.trim(), "%Y-%m-%d").is_ok(),
            "`expires` must be a YYYY-MM-DD date (got `{exp}`)"
        );
    }

    let path = hooks::signers_path(ctx);
    let existing = if path.is_file() {
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
    } else {
        String::new()
    };
    let candidate = format!("{existing}{}", render_signer_block(spec));
    // The single source of truth for validity is the real parser — this catches
    // duplicate principals (ISC-A2) and any structural error before we commit
    // the change to disk.
    hooks::parse_signers(&candidate).context("adding this signer would make the policy invalid")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &candidate).with_context(|| format!("writing {}", path.display()))?;
    hooks::regenerate_allowed_signers(ctx, hooks::agent_signing_enabled(cfg))?;

    let mut note = format!("added signer `{}` (class {})", spec.principal, spec.class);
    if spec.class == "ai" && !hooks::agent_signing_enabled(cfg) {
        note.push_str(
            " — NOTE: the `agent-signing` control is disabled, so this key is NOT yet emitted \
             into allowed_signers; enable it with `sscsb enable agent-signing`",
        );
    }
    Ok(note)
}

// ─────────────────────────── commit classification ──────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitClass {
    pub sha: String,
    pub label: String,
    pub detail: String,
}

/// Label one commit's signature against the signer policy. Shares its matching
/// rule with `hooks::check_signing_for_range`: exact principal, or exact
/// (case-insensitive) gpg fingerprint.
fn classify(status: &str, principal: &str, key_id: &str, signers: &[Signer]) -> (String, String) {
    match status {
        "G" => {
            let matched = signers.iter().find(|s| {
                s.principal == principal
                    || s.gpg_fingerprint
                        .as_deref()
                        .is_some_and(|fp| !fp.is_empty() && key_id.eq_ignore_ascii_case(fp))
            });
            match matched {
                Some(s) => (
                    class_label(&s.class).to_string(),
                    format!("signed by {}", s.principal),
                ),
                None => (
                    "unknown-signer".into(),
                    format!("good signature from `{principal}` not in policy"),
                ),
            }
        }
        "N" => ("unsigned".into(), "no signature".into()),
        "U" | "E" => (
            "unverified".into(),
            format!("signature not validated against policy (status {status})"),
        ),
        "B" => ("bad".into(), "BAD signature".into()),
        other => ("unknown".into(), format!("unexpected status `{other}`")),
    }
}

/// Classify each commit in `range` (default: the last 20 commits) as human /
/// ci / agent / unsigned. Regenerates allowed_signers first so verification
/// reflects current policy (including agent keys when the control is enabled).
pub fn classify_range(ctx: &Ctx, cfg: &Config, range: Option<&str>) -> Result<Vec<CommitClass>> {
    hooks::regenerate_allowed_signers(ctx, hooks::agent_signing_enabled(cfg))?;
    let signers = hooks::load_signers(&hooks::signers_path(ctx))?;

    let mut args = vec!["log", "--format=%H%x00%G?%x00%GS%x00%GK"];
    match range {
        Some(r) => args.push(r),
        None => args.extend_from_slice(&["-n", "20"]),
    }
    let out = exec::git(&args, &ctx.root)?;
    let mut classes = Vec::new();
    for line in out.lines().filter(|l| !l.is_empty()) {
        let mut parts = line.splitn(4, '\0');
        let sha = parts.next().unwrap_or("").to_string();
        let status = parts.next().unwrap_or("");
        let principal = parts.next().unwrap_or("");
        let key_id = parts.next().unwrap_or("");
        if sha.is_empty() {
            continue;
        }
        let (label, detail) = classify(status, principal, key_id, &signers);
        classes.push(CommitClass {
            sha: sha[..sha.len().min(10)].to_string(),
            label,
            detail,
        });
    }
    Ok(classes)
}

// ─────────────────────────── GitHub-App verification ────────────────────────

/// Per-commit GitHub-side signature status, read from the commits API. This is
/// how a Claude Code *cloud* / mobile agent's server-side-signed commits are
/// checked: the key never touches a box, and GitHub reports the 'Verified'
/// state plus the committer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubAppCommit {
    pub sha: String,
    pub verified: bool,
    pub reason: String,
    pub committer: String,
    pub committer_matches: bool,
}

/// Interpret one commits-API JSON blob against the expected committer login.
/// Pure so it can be tested without a network call.
pub fn parse_github_commit(json: &serde_json::Value, expected_committer: &str) -> GithubAppCommit {
    let sha = json
        .get("sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let verification = json.get("commit").and_then(|c| c.get("verification"));
    let verified = verification
        .and_then(|v| v.get("verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reason = verification
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    // Prefer the resolved GitHub login of the committer; fall back to the raw
    // git committer email in the commit object.
    let committer = json
        .get("committer")
        .and_then(|c| c.get("login"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            json.get("commit")
                .and_then(|c| c.get("committer"))
                .and_then(|c| c.get("email"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
        .to_string();
    let committer_matches = committer.eq_ignore_ascii_case(expected_committer);
    GithubAppCommit {
        sha: sha[..sha.len().min(10)].to_string(),
        verified,
        reason,
        committer,
        committer_matches,
    }
}

/// Verify, via `gh api`, that recent commits in `range` are GitHub-'Verified'
/// and committed by `expected_committer`. Degrades (returns an explanatory
/// error) when `gh` is absent or no repo slug is resolvable — never a silent
/// pass.
pub fn verify_github_app_commits(
    ctx: &Ctx,
    cfg: &Config,
    expected_committer: &str,
    range: Option<&str>,
) -> Result<Vec<GithubAppCommit>> {
    if exec::find_in_path("gh").is_none() {
        anyhow::bail!("{}", crate::tools::degrade_message("gh", ctx.platform));
    }
    let slug = cfg
        .github_repo()
        .or_else(|| ctx.origin_slug())
        .context("no GitHub repo configured (general.github_repo) and no origin remote")?;

    let mut log_args = vec!["log", "--format=%H"];
    match range {
        Some(r) => log_args.push(r),
        None => log_args.extend_from_slice(&["-n", "20"]),
    }
    let shas = exec::git(&log_args, &ctx.root)?;
    let mut out = Vec::new();
    for sha in shas.lines().filter(|l| !l.is_empty()) {
        let api = format!("repos/{slug}/commits/{sha}");
        let resp = exec::run("gh", &["api", &api], Some(&ctx.root))?;
        if !resp.success() {
            anyhow::bail!(
                "gh api {api} failed: {}",
                resp.stderr.lines().next().unwrap_or("error")
            );
        }
        let json: serde_json::Value = serde_json::from_str(&resp.stdout)
            .with_context(|| format!("parsing gh api response for {sha}"))?;
        out.push(parse_github_commit(&json, expected_committer));
    }
    Ok(out)
}

// ───────────────────── server-side policy-change gate ───────────────────────

/// Load the signer policy AS OF a git ref (e.g. the trusted pre-push tip),
/// reading the blob straight out of history rather than the working tree.
fn signers_at_ref(ctx: &Ctx, git_ref: &str) -> Result<Vec<Signer>> {
    let spec = format!("{git_ref}:.sscsb/policy/signers.toml");
    let out = exec::run("git", &["show", &spec], Some(&ctx.root))?;
    if !out.success() {
        // Absent at that ref (e.g. policy introduced in this push) — no trusted
        // signers to check against; caller decides how to treat that.
        return Ok(Vec::new());
    }
    hooks::parse_signers(&out.stdout)
}

fn is_zero_sha(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c == '0')
}

/// Server-side gate: reject any commit in `base..head` that MODIFIES the signer
/// policy (`.sscsb/policy/**`) unless that commit is signed by a HUMAN who was
/// already trusted in the policy AS OF `base`. This is the guardrail the
/// client-side hook cannot provide: the trusted signer set is read from the
/// parent (`base`) history and the signature is verified against THAT set, so a
/// push can never promote an ai/ci key to human and use it in the same push
/// (red-team S1 / ISC-A1). Returns a list of problems (empty = clean).
pub fn verify_policy_changes(ctx: &Ctx, base: &str, head: &str) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    if base.is_empty() || is_zero_sha(base) {
        // First push / brand-new branch: there is no trusted parent policy to
        // check against. Say so loudly — GitHub branch protection guards the
        // initial state — rather than silently pass as if verified.
        problems.push(
            "no trusted parent policy (first push / new branch) — policy changes here are NOT \
             verifiable against a prior state; rely on branch protection for the initial commit"
                .into(),
        );
        return Ok(problems);
    }

    // The trusted signer set, as of the pre-push tip.
    let trusted = signers_at_ref(ctx, base)?;
    let trusted_allowed = hooks::allowed_signers_content_with_agents(&trusted, false);
    let allowed_file = tempfile::NamedTempFile::new()?;
    std::fs::write(allowed_file.path(), &trusted_allowed)?;
    let allowed_path = allowed_file.path().display().to_string();

    // Commits in this push that touch the policy directory.
    let range = format!("{base}..{head}");
    let log = exec::run(
        "git",
        &["log", "--format=%H", &range, "--", ".sscsb/policy"],
        Some(&ctx.root),
    )?;
    if !log.success() {
        anyhow::bail!("git log {range} failed: {}", log.stderr.trim());
    }

    for sha in log.stdout.lines().filter(|l| !l.is_empty()) {
        // Verify the signature against the TRUSTED allowed_signers, never the
        // pushed tree's copy — `-c` overrides config for this invocation only.
        let raw = exec::run(
            "git",
            &[
                "-c",
                &format!("gpg.ssh.allowedSignersFile={allowed_path}"),
                "log",
                "-1",
                "--format=%G?%x00%GS",
                sha,
            ],
            Some(&ctx.root),
        )?;
        let short = &sha[..sha.len().min(10)];
        let mut parts = raw.stdout.trim_end_matches('\n').splitn(2, '\0');
        let status = parts.next().unwrap_or("");
        let principal = parts.next().unwrap_or("");
        match status {
            "G" => {
                let signer = trusted.iter().find(|s| s.principal == principal);
                match signer {
                    Some(s) if s.class == SignerClass::Human => { /* trusted human — allowed */ }
                    Some(s) => problems.push(format!(
                        "{short}: modifies .sscsb/policy signed by `{principal}` (class {:?}) — \
                         only a HUMAN trusted before this push may change signer policy",
                        s.class
                    )),
                    None => problems.push(format!(
                        "{short}: modifies .sscsb/policy signed by `{principal}`, who was not a \
                         trusted signer before this push — refusing (self-promotion guard)"
                    )),
                }
            }
            _ => problems.push(format!(
                "{short}: modifies .sscsb/policy but is not verifiably human-signed against the \
                 pre-push trusted policy (status {status}) — refusing"
            )),
        }
    }
    Ok(problems)
}

// ─────────────────────────── agent-key setup guidance ───────────────────────

/// Backend-specific, copy-pasteable setup guidance for `sscsb agent-key setup`.
/// This prints instructions; it never touches a key or a remote service.
pub fn agent_key_setup_guidance(backend: &str) -> Result<Vec<String>> {
    let lines: Vec<String> = match backend {
        "github-app" => vec![
            "GitHub App server-side signing (recommended for Claude Code cloud / mobile):".into(),
            "  • The signing key lives in GitHub, never on any box you or the agent control.".into(),
            "  • Commits made via the App's installation token are signed server-side and show".into(),
            "    the GitHub 'Verified' badge — the agent literally cannot sign as a human.".into(),
            "  1. Create a GitHub App (Settings → Developer settings → GitHub Apps).".into(),
            "  2. Grant it 'Contents: write' on the target repo(s) only.".into(),
            "  3. Have the agent commit through the App's installation token (e.g. the".into(),
            "     create-commit REST API), NOT a local `git commit`.".into(),
            "  4. Record the App's committer identity as a `class = \"ai\"` signer here so".into(),
            "     `sscsb verify agent-signing` and the CI gate recognize it:".into(),
            "       sscsb signers add --principal <app>[bot]@users.noreply.github.com \\".into(),
            "         --class ai --backend github-app --hardware-backed".into(),
            "  5. Verify with: sscsb verify agent-signing".into(),
        ],
        "tpm" => vec![
            "TPM-backed ssh signing (Linux only, touchless via ssh-tpm-agent):".into(),
            "  • The private key is generated inside the TPM and is non-exportable.".into(),
            "  • An empty-passphrase TPM key signs without a human touch — right for a".into(),
            "    headless agent (a Secure Enclave / FIDO touch-required key is NOT).".into(),
            "  1. Install ssh-tpm-agent (Foxboron) — pinned 0.9.0; see `sscsb tools`.".into(),
            "  2. Create a TPM-resident key:  ssh-tpm-keygen -t ecdsa".into(),
            "  3. Run the agent:  ssh-tpm-agent &  and export SSH_AUTH_SOCK to its socket.".into(),
            "  4. git config gpg.format ssh; git config user.signingkey <the .pub>".into(),
            "  5. Register it as an agent signer (never a human principal):".into(),
            "       sscsb signers add --principal agent@ci.example.com \\".into(),
            "         --class ai --backend tpm --hardware-backed \\".into(),
            "         --ssh-key \"$(cat ~/.ssh/id_ecdsa_tpm.pub)\"".into(),
            "  6. Optionally attach a hardware attestation artifact; see docs/agent-signing.md.".into(),
        ],
        other if KNOWN_BACKENDS.contains(&other) => vec![
            format!("Backend `{other}` is documented but not first-class in v1."),
            "  See docs/agent-signing.md for the full backend matrix (fido2 / kms / piv / software)".into(),
            "  and the honest trade-offs. Register the resulting key with `sscsb signers add".into(),
            format!("  --class ai --backend {other} ...` once configured."),
        ],
        other => anyhow::bail!(
            "unknown backend `{other}` — one of {}",
            KNOWN_BACKENDS.join("|")
        ),
    };
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    // ─────────────────── real-signature policy-gate fixtures ────────────────

    /// Generate an ed25519 key at `dir/name`, returning its public key line.
    fn keygen(dir: &Path, name: &str, comment: &str) -> String {
        let path = dir.join(name);
        let out = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen failed");
        std::fs::read_to_string(path.with_extension("pub"))
            .unwrap()
            .trim()
            .to_string()
    }

    fn git(ctx: &Ctx, args: &[&str]) {
        let out = crate::exec::run("git", args, Some(&ctx.root)).unwrap();
        assert!(out.success(), "git {args:?} failed: {}", out.stderr);
    }

    /// Bootstrapped repo with `gpg.format ssh`; returns (dir, ctx, keydir).
    fn repo() -> (tempfile::TempDir, tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let keydir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "Dev"], root).unwrap();
        crate::exec::git(&["config", "user.email", "dev@example.com"], root).unwrap();
        crate::exec::git(&["config", "gpg.format", "ssh"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, keydir, ctx)
    }

    fn write_policy(ctx: &Ctx, body: &str) {
        std::fs::write(hooks::signers_path(ctx), body).unwrap();
    }

    fn sign_with(ctx: &Ctx, keypath: &Path) {
        git(
            ctx,
            &["config", "user.signingkey", keypath.to_str().unwrap()],
        );
    }

    /// Bootstrapped repo with the agent-signing control ENABLED, returned with
    /// a fresh Ctx so the enabled state is loaded.
    fn agent_enabled_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "Dev"], root).unwrap();
        crate::exec::git(&["config", "user.email", "dev@example.com"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx0 = Ctx::discover(root).unwrap();
        crate::config::set_control_enabled(&ctx0.config_path(), "agent-signing", true).unwrap();
        // Enabling the control means its server-side workflow should be present;
        // install it so the happy path isn't shadowed by a "workflow missing".
        let ctx0 = Ctx::discover(root).unwrap();
        let cfg = ctx0.require_config().unwrap();
        crate::workflows::install_all(&ctx0, cfg).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    fn set_policy(ctx: &Ctx, body: &str) {
        std::fs::write(hooks::signers_path(ctx), body).unwrap();
    }

    #[test]
    fn verify_agent_signing_passes_for_a_well_formed_agent_signer() {
        let (_d, ctx) = agent_enabled_repo();
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"github-app\"\nhardware_backed = true\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        );
        let cfg = ctx.require_config().unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("agent-signing-verify.yml installed")));
    }

    #[test]
    fn verify_agent_signing_degrades_without_an_agent_signer() {
        let (_d, ctx) = agent_enabled_repo();
        // Default bootstrap signers.toml has no ai signer.
        let cfg = ctx.require_config().unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded);
        assert!(r.messages.iter().any(|m| m.contains("no `class = \"ai\"`")));
    }

    #[test]
    fn verify_agent_signing_fails_on_disallowed_and_unknown_backends() {
        let (_d, ctx) = agent_enabled_repo();
        // 'software' backend, but this repo's allowed_backends excludes... it
        // doesn't by default, so restrict allowed_backends first.
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace(
                "allowed_backends = [\"github-app\", \"tpm\", \"fido2\", \"kms\", \"piv\", \"software\"]",
                "allowed_backends = [\"github-app\"]",
            );
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"tpm\"\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        );
        let cfg = ctx.require_config().unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("not in this repo's allowed_backends")));

        // An unknown backend is always a hard fail.
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"quantum\"\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        );
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("unknown backend")));
    }

    #[test]
    fn verify_agent_signing_fails_on_expired_key_and_missing_attestation() {
        let (_d, ctx) = agent_enabled_repo();
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"github-app\"\nexpires = \"2000-01-01\"\nattestation_file = \".sscsb/policy/att/none.bin\"\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        );
        let cfg = ctx.require_config().unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("EXPIRED")));
        assert!(r.messages.iter().any(|m| m.contains("attestation_file")));
    }

    #[test]
    fn verify_agent_signing_reports_attested_when_the_artifact_exists() {
        let (_d, ctx) = agent_enabled_repo();
        std::fs::create_dir_all(ctx.root.join(".sscsb/policy/att")).unwrap();
        std::fs::write(ctx.root.join(".sscsb/policy/att/agent.bin"), b"proof").unwrap();
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"fido2\"\nhardware_backed = true\nattestation_file = \".sscsb/policy/att/agent.bin\"\nexpires = \"2099-01-01\"\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        );
        // 2099 is > max_key_age_days (90) out → WindowTooLong → Degraded.
        let cfg = ctx.require_config().unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert!(r.messages.iter().any(|m| m.contains("hardware=attested")));
        assert!(r.messages.iter().any(|m| m.contains("window")));
    }

    #[test]
    fn verify_agent_signing_fails_on_an_invalid_policy_and_when_hooks_absent() {
        // Invalid policy (duplicate principal) → Fail.
        let (_d, ctx) = agent_enabled_repo();
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"a@x\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 A a@x\"\n\n[[signer]]\nprincipal = \"a@x\"\nclass = \"ai\"\nssh_public_key = \"ssh-ed25519 B a@x\"\n",
        );
        let cfg = ctx.require_config().unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("policy invalid")));

        // Hooks not installed → Fail. Build a repo whose hooks were removed.
        std::fs::remove_dir_all(ctx.root.join(".sscsb/hooks")).unwrap();
        let r = verify_agent_signing_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("hooks not installed")));
    }

    #[test]
    fn describe_signers_lists_configured_entries_and_handles_empty() {
        let (_d, ctx) = agent_enabled_repo();
        // Fresh bootstrap policy is the commented template → no [[signer]] → empty.
        assert!(describe_signers(&ctx)
            .unwrap()
            .iter()
            .any(|l| l.contains("no signers configured")));
        set_policy(
            &ctx,
            "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"tpm\"\nhardware_backed = true\nexpires = \"2099-01-01\"\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        );
        let lines = describe_signers(&ctx).unwrap();
        assert!(lines.iter().any(|l| l.contains("class:agent")
            && l.contains("backend:tpm")
            && l.contains("hw:declared")));
    }

    #[test]
    fn add_signer_appends_validates_and_regenerates_allowed_signers() {
        let (_d, ctx) = agent_enabled_repo();
        let cfg = ctx.require_config().unwrap();
        // A well-formed agent signer is added and (control enabled) emitted.
        let note = add_signer(
            &ctx,
            cfg,
            &NewSigner {
                principal: "agent@ci.example.com".into(),
                class: "ai".into(),
                ssh_public_key: Some("ssh-ed25519 AAAAA agent@ci.example.com".into()),
                gpg_fingerprint: None,
                backend: Some("github-app".into()),
                hardware_backed: true,
                expires: Some("2026-12-31".into()),
            },
        )
        .unwrap();
        assert!(note.contains("added signer"));
        let allowed =
            std::fs::read_to_string(ctx.sscsb_dir().join("policy").join("allowed_signers"))
                .unwrap();
        assert!(
            allowed.contains("agent@ci.example.com"),
            "control enabled → the ai key is emitted"
        );

        // Adding the same principal again must be refused by the parser guard.
        let dup = add_signer(
            &ctx,
            cfg,
            &NewSigner {
                principal: "agent@ci.example.com".into(),
                class: "human".into(),
                ssh_public_key: Some("ssh-ed25519 BBBBB agent@ci.example.com".into()),
                gpg_fingerprint: None,
                backend: None,
                hardware_backed: false,
                expires: None,
            },
        );
        assert!(dup.is_err(), "duplicate principal must be rejected");

        // Bad inputs are rejected before any write.
        assert!(add_signer(
            &ctx,
            cfg,
            &NewSigner {
                principal: "x@y".into(),
                class: "wizard".into(),
                ssh_public_key: Some("ssh-ed25519 C x@y".into()),
                gpg_fingerprint: None,
                backend: None,
                hardware_backed: false,
                expires: None,
            }
        )
        .is_err());
        assert!(add_signer(
            &ctx,
            cfg,
            &NewSigner {
                principal: "z@y".into(),
                class: "ai".into(),
                ssh_public_key: None,
                gpg_fingerprint: None,
                backend: None,
                hardware_backed: false,
                expires: None,
            }
        )
        .is_err());
    }

    #[test]
    fn add_signer_warns_when_agent_signing_is_disabled() {
        // A default (agent-signing OFF) bootstrapped repo.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "Dev"], root).unwrap();
        crate::exec::git(&["config", "user.email", "dev@example.com"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let cfg = ctx.require_config().unwrap();
        let note = add_signer(
            &ctx,
            cfg,
            &NewSigner {
                principal: "agent@ci.example.com".into(),
                class: "ai".into(),
                ssh_public_key: Some("ssh-ed25519 AAAAA agent@ci.example.com".into()),
                gpg_fingerprint: None,
                backend: Some("tpm".into()),
                hardware_backed: true,
                expires: None,
            },
        )
        .unwrap();
        assert!(note.contains("agent-signing` control is disabled"));
        // With the control off, the ai key must NOT be emitted.
        let allowed =
            std::fs::read_to_string(ctx.sscsb_dir().join("policy").join("allowed_signers"))
                .unwrap();
        assert!(!allowed.contains("agent@ci.example.com"));
    }

    #[test]
    fn classify_range_labels_recent_commits() {
        let (_d, _k, ctx) = repo();
        std::fs::write(ctx.root.join("a.txt"), "a\n").unwrap();
        git(&ctx, &["add", "-A"]);
        git(&ctx, &["commit", "-m", "unsigned commit", "--no-verify"]);
        let cfg = ctx.require_config().unwrap();
        let classes = classify_range(&ctx, cfg, None).unwrap();
        assert!(!classes.is_empty());
        assert!(classes.iter().any(|c| c.label == "unsigned"));
    }

    #[test]
    fn verify_policy_changes_notes_first_push_without_a_trusted_parent() {
        let (_d, _k, ctx) = repo();
        let problems = verify_policy_changes(&ctx, &"0".repeat(40), "HEAD").unwrap();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("no trusted parent policy"));
    }

    #[test]
    fn verify_policy_changes_accepts_human_and_rejects_ci_and_untrusted() {
        let (_d, keydir, ctx) = repo();
        let kd = keydir.path();
        let human_pub = keygen(kd, "human", "human@example.com");
        let ci_pub = keygen(kd, "ci", "ci@example.com");
        let _stranger_pub = keygen(kd, "stranger", "stranger@example.com");

        // BASE: a trusted policy with a human and a ci signer.
        write_policy(
            &ctx,
            &format!(
                "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"{human_pub}\"\n\n[[signer]]\nprincipal = \"ci@example.com\"\nclass = \"ci\"\nssh_public_key = \"{ci_pub}\"\n"
            ),
        );
        git(&ctx, &["add", "-A"]);
        // Base commit itself need not be signed; only its policy content matters.
        git(&ctx, &["commit", "-m", "base policy", "--no-verify"]);
        let base = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        // (1) A human trusted-before-the-push edits policy → ACCEPTED.
        sign_with(&ctx, &kd.join("human"));
        write_policy(
            &ctx,
            &format!(
                "# tweaked by the human\n[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"{human_pub}\"\n\n[[signer]]\nprincipal = \"ci@example.com\"\nclass = \"ci\"\nssh_public_key = \"{ci_pub}\"\n"
            ),
        );
        git(&ctx, &["add", "-A"]);
        git(
            &ctx,
            &["commit", "-S", "-m", "human edits policy", "--no-verify"],
        );
        let head_human = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        assert!(
            verify_policy_changes(&ctx, &base, &head_human)
                .unwrap()
                .is_empty(),
            "a human trusted before the push may edit policy"
        );

        // (2) The CI key edits policy → REJECTED (only a human may).
        sign_with(&ctx, &kd.join("ci"));
        std::fs::write(ctx.root.join("nudge.txt"), "x\n").unwrap();
        write_policy(
            &ctx,
            &format!(
                "# tweaked by CI\n[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"{human_pub}\"\n\n[[signer]]\nprincipal = \"ci@example.com\"\nclass = \"ci\"\nssh_public_key = \"{ci_pub}\"\n"
            ),
        );
        git(&ctx, &["add", "-A"]);
        git(
            &ctx,
            &["commit", "-S", "-m", "ci edits policy", "--no-verify"],
        );
        let head_ci = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let ci_problems = verify_policy_changes(&ctx, &base, &head_ci).unwrap();
        assert!(
            ci_problems.iter().any(|p| p.contains("only a HUMAN")),
            "ci-signed policy change must be rejected: {ci_problems:?}"
        );

        // (3) A stranger key (not in the trusted base policy) edits policy →
        // REJECTED (cannot even verify against the trusted signer set).
        sign_with(&ctx, &kd.join("stranger"));
        write_policy(
            &ctx,
            &format!(
                "# tweaked by a stranger\n[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"{human_pub}\"\n"
            ),
        );
        git(&ctx, &["add", "-A"]);
        git(
            &ctx,
            &["commit", "-S", "-m", "stranger edits policy", "--no-verify"],
        );
        let head_stranger = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let s_problems = verify_policy_changes(&ctx, &base, &head_stranger).unwrap();
        assert!(
            s_problems
                .iter()
                .any(|p| p.contains("not verifiably human-signed")),
            "stranger-signed policy change must be rejected: {s_problems:?}"
        );
    }

    #[test]
    fn expiry_evaluation_covers_every_state() {
        let today = ymd(2026, 7, 13);
        assert_eq!(evaluate_expiry(None, today, 90), ExpiryState::Unset);
        assert_eq!(
            evaluate_expiry(Some("2026-08-01"), today, 90),
            ExpiryState::Valid { days_left: 19 }
        );
        assert_eq!(
            evaluate_expiry(Some("2026-07-01"), today, 90),
            ExpiryState::Expired { days_ago: 12 }
        );
        assert_eq!(
            evaluate_expiry(Some("2027-07-13"), today, 90),
            ExpiryState::WindowTooLong {
                days_left: 365,
                max: 90
            }
        );
        assert_eq!(
            evaluate_expiry(Some("not-a-date"), today, 90),
            ExpiryState::Unparseable
        );
        // max_age_days <= 0 disables the window check.
        assert_eq!(
            evaluate_expiry(Some("2099-01-01"), today, 0),
            ExpiryState::Valid {
                days_left: (ymd(2099, 1, 1) - today).num_days()
            }
        );
    }

    #[test]
    fn attestation_state_reflects_presence_and_absence() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(
            evaluate_attestation(root, None).unwrap(),
            AttestationState::Declared
        );
        assert!(matches!(
            evaluate_attestation(root, Some("missing.bin")).unwrap(),
            AttestationState::Missing { .. }
        ));
        std::fs::create_dir_all(root.join("att")).unwrap();
        std::fs::write(root.join("att/a.bin"), b"attestation-bytes").unwrap();
        let expected = hex::encode(Sha256::digest(b"attestation-bytes"));
        match evaluate_attestation(root, Some("att/a.bin")).unwrap() {
            AttestationState::Attested { sha256 } => assert_eq!(sha256, expected),
            other => panic!("expected Attested, got {other:?}"),
        }
    }

    #[test]
    fn classify_labels_each_signature_status() {
        let signers = hooks::parse_signers(
            "[[signer]]\nprincipal = \"h@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAAH h@example.com\"\n\n[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nssh_public_key = \"ssh-ed25519 AAAAA agent@ci.example.com\"\n",
        )
        .unwrap();
        assert_eq!(classify("G", "h@example.com", "", &signers).0, "human");
        assert_eq!(
            classify("G", "agent@ci.example.com", "", &signers).0,
            "agent"
        );
        assert_eq!(
            classify("G", "stranger@x.com", "", &signers).0,
            "unknown-signer"
        );
        assert_eq!(classify("N", "", "", &signers).0, "unsigned");
        assert_eq!(classify("U", "", "", &signers).0, "unverified");
        assert_eq!(classify("B", "", "", &signers).0, "bad");
        assert_eq!(classify("?", "", "", &signers).0, "unknown");
    }

    #[test]
    fn render_signer_block_emits_all_provided_fields() {
        let spec = NewSigner {
            principal: "agent@ci.example.com".into(),
            class: "ai".into(),
            ssh_public_key: Some("ssh-ed25519 AAAAA agent@ci.example.com".into()),
            gpg_fingerprint: None,
            backend: Some("github-app".into()),
            hardware_backed: true,
            expires: Some("2027-01-01".into()),
        };
        let block = render_signer_block(&spec);
        // The rendered block must itself parse back to exactly this signer.
        let parsed = hooks::parse_signers(&block).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].class, SignerClass::Ai);
        assert_eq!(parsed[0].backend.as_deref(), Some("github-app"));
        assert_eq!(parsed[0].expires.as_deref(), Some("2027-01-01"));
        assert!(parsed[0].hardware_backed);
    }

    /// Serializes the PATH-mutating fake-gh test (mirrors audit.rs).
    static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct PathPrepend {
        original: Option<std::ffi::OsString>,
    }
    impl PathPrepend {
        fn new(dir: &Path) -> Self {
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

    #[test]
    fn verify_github_app_commits_reports_verified_and_mismatched_via_stubbed_gh() {
        let _guard = PATH_LOCK.lock().unwrap();
        // A fake gh that returns a Verified commit committed by the app bot.
        let ghdir = tempfile::tempdir().unwrap();
        let ghpath = ghdir.path().join("gh");
        std::fs::write(
            &ghpath,
            "#!/bin/sh\necho '{\"sha\":\"1111111111111111\",\"commit\":{\"verification\":{\"verified\":true,\"reason\":\"valid\"},\"committer\":{\"email\":\"x@x\"}},\"committer\":{\"login\":\"my-app[bot]\"}}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ghpath, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _path = PathPrepend::new(ghdir.path());

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "T"], root).unwrap();
        crate::exec::git(&["config", "user.email", "t@example.com"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        // Give it a repo slug so the API path resolves, and one real commit.
        let cfg_text = std::fs::read_to_string(root.join(".sscsb/config.toml"))
            .unwrap()
            .replace(
                "# github_repo = \"owner/repo\"  # set to enable GitHub API checks",
                "github_repo = \"acme/demo\"",
            );
        std::fs::write(root.join(".sscsb/config.toml"), cfg_text).unwrap();
        std::fs::write(root.join("f.txt"), "x\n").unwrap();
        crate::exec::git(&["add", "f.txt"], root).unwrap();
        crate::exec::git(&["commit", "-m", "c", "--no-verify"], root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let cfg = ctx.require_config().unwrap();

        // Expected committer matches → verified & matching.
        let good = verify_github_app_commits(&ctx, cfg, "my-app[bot]", Some("-n1")).unwrap();
        assert_eq!(good.len(), 1);
        assert!(good[0].verified && good[0].committer_matches);

        // A different expected committer → verified but NOT matching.
        let bad = verify_github_app_commits(&ctx, cfg, "someone-else", Some("-n1")).unwrap();
        assert!(bad[0].verified && !bad[0].committer_matches);
    }

    #[test]
    fn parse_github_commit_reads_verification_and_matches_committer() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"sha":"abcdef1234567890","commit":{"verification":{"verified":true,"reason":"valid"},"committer":{"email":"raw@example.com"}},"committer":{"login":"my-app[bot]"}}"#,
        )
        .unwrap();
        let c = parse_github_commit(&json, "my-app[bot]");
        assert!(c.verified);
        assert_eq!(c.reason, "valid");
        assert_eq!(c.committer, "my-app[bot]");
        assert!(c.committer_matches);
        assert_eq!(c.sha, "abcdef1234"); // truncated to 10

        // Not verified, and committer login absent → falls back to git email
        // and does not match the expected app.
        let json2: serde_json::Value = serde_json::from_str(
            r#"{"sha":"deadbeefcafe","commit":{"verification":{"verified":false,"reason":"unsigned"},"committer":{"email":"human@example.com"}}}"#,
        )
        .unwrap();
        let c2 = parse_github_commit(&json2, "my-app[bot]");
        assert!(!c2.verified);
        assert_eq!(c2.committer, "human@example.com");
        assert!(!c2.committer_matches);
    }

    #[test]
    fn verify_github_app_commits_degrades_without_a_configured_repo() {
        // A bootstrapped repo with no origin remote and no github_repo set:
        // the function must error (degrade), never silently pass.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "T"], root).unwrap();
        crate::exec::git(&["config", "user.email", "t@example.com"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let cfg = ctx.require_config().unwrap();
        // Only exercise the no-slug degrade when gh happens to be installed;
        // otherwise the gh-absent degrade fires first (also correct).
        let err = verify_github_app_commits(&ctx, cfg, "my-app[bot]", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no GitHub repo configured") || msg.contains("gh not found"),
            "must degrade, got: {msg}"
        );
    }

    #[test]
    fn agent_key_setup_guidance_covers_first_class_docs_tier_and_unknown() {
        assert!(agent_key_setup_guidance("github-app")
            .unwrap()
            .iter()
            .any(|l| l.contains("Verified")));
        assert!(agent_key_setup_guidance("tpm")
            .unwrap()
            .iter()
            .any(|l| l.contains("non-exportable")));
        assert!(agent_key_setup_guidance("kms")
            .unwrap()
            .iter()
            .any(|l| l.contains("documented but not first-class")));
        assert!(agent_key_setup_guidance("nonsense").is_err());
    }
}
