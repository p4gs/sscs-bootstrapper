//! Git hook engine. The installed hooks are POSIX shell SHIMS (spec: hooks are
//! shell) that delegate to `sscsb hook <event>` (spec: policy engine and glue
//! are Rust). Shims fail CLOSED when sscsb is missing so enabled controls can
//! never be silently skipped.
//!
//! Events: pre-commit (secret blocking, optional SAST), commit-msg (AI
//! trailers, AI dependency/command gate, new-package approval gate), pre-push
//! (CommitSigningGuard + secret range scan).

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;
use anyhow::{Context as _, Result};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub const HOOK_EVENTS: &[&str] = &["pre-commit", "commit-msg", "pre-push"];

/// Exit code gitleaks is told to use for "leaks found" so we can distinguish
/// findings from operational errors.
const GITLEAKS_FINDINGS_EXIT: i32 = 99;
/// trufflehog --fail exits 183 when results are found.
const TRUFFLEHOG_FINDINGS_EXIT: i32 = 183;

// ─────────────────────────────── Shims ───────────────────────────────────────

/// POSIX shell shim for a hook event. Fail-closed by design: if the sscsb CLI
/// cannot be found, the operation is blocked with an explicit message.
pub fn shim_script(event: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Installed by sscsb (SSCS Bootstrapper). DO NOT EDIT — regenerate with `sscsb init`.\n\
         # This shim only delegates; policy logic lives in the sscsb CLI (Rust).\n\
         if command -v sscsb >/dev/null 2>&1; then\n\
         \x20 exec sscsb hook {event} \"$@\"\n\
         fi\n\
         if [ -n \"${{SSCSB_BIN:-}}\" ] && [ -x \"${{SSCSB_BIN}}\" ]; then\n\
         \x20 exec \"${{SSCSB_BIN}}\" hook {event} \"$@\"\n\
         fi\n\
         echo \"sscsb: CLI not found on PATH — blocking {event} (fail-closed) because\" >&2\n\
         echo \"sscsb: enabled supply-chain controls cannot run without it.\" >&2\n\
         echo \"sscsb: install sscsb (cargo install --path . / release binary) or set SSCSB_BIN.\" >&2\n\
         exit 1\n"
    )
}

/// Install shims into `.sscsb/hooks` and point `core.hooksPath` at them.
pub fn install_hooks(ctx: &Ctx) -> Result<Vec<String>> {
    let hooks_dir = ctx.sscsb_dir().join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let mut written = Vec::new();
    for event in HOOK_EVENTS {
        let path = hooks_dir.join(event);
        std::fs::write(&path, shim_script(event))?;
        make_executable(&path)?;
        written.push(format!(".sscsb/hooks/{event}"));
    }
    exec::git(&["config", "core.hooksPath", ".sscsb/hooks"], &ctx.root)?;
    // Point signature verification at the policy-generated allowed_signers
    // file (absolute path: git resolves relative paths from the cwd, which is
    // unreliable inside hooks).
    let signers = ctx.sscsb_dir().join("policy").join("allowed_signers");
    exec::git(
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            &signers.display().to_string(),
        ],
        &ctx.root,
    )?;
    Ok(written)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    // Git for Windows executes hooks through its own sh; no chmod needed.
    Ok(())
}

// ─────────────────────────────── Signer policy ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerClass {
    Human,
    Ci,
    Ai,
}

#[derive(Debug, Clone)]
pub struct Signer {
    pub principal: String,
    pub class: SignerClass,
    pub ssh_public_key: Option<String>,
    pub gpg_fingerprint: Option<String>,
    pub hardware_backed: bool,
}

pub const SIGNERS_TEMPLATE: &str = r#"# sscsb approved-signers policy.
#
# Humans, CI, and AI agents must NEVER share keys or identities. Only signers
# listed here can push to protected branches, and only `class = "human"`
# signers satisfy the human-only protected-branch signing policy. AI agents
# draft changes; they never sign, so no `class = "ai"` entry should ever carry
# a key that is used for signing — the class exists so an AI-associated
# identity can be explicitly DENIED signing rights.
#
# [[signer]]
# principal = "you@example.com"          # matches allowed_signers principal
# class = "human"                        # human | ci | ai
# hardware_backed = true                 # asserted when the key lives on a YubiKey/secure element
# ssh_public_key = "ssh-ed25519 AAAA... you@example.com"
# # gpg_fingerprint = "ABCD1234..."      # for gpg.format=openpgp signers
"#;

pub fn signers_path(ctx: &Ctx) -> PathBuf {
    ctx.sscsb_dir().join("policy").join("signers.toml")
}

pub fn load_signers(path: &Path) -> Result<Vec<Signer>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    parse_signers(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn parse_signers(text: &str) -> Result<Vec<Signer>> {
    let table: toml::Table = text.parse()?;
    let mut out = Vec::new();
    let Some(items) = table.get("signer").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for (i, item) in items.iter().enumerate() {
        let t = item
            .as_table()
            .with_context(|| format!("signer #{i} is not a table"))?;
        let principal = t
            .get("principal")
            .and_then(|v| v.as_str())
            .with_context(|| format!("signer #{i} missing `principal`"))?
            .to_string();
        let class = match t.get("class").and_then(|v| v.as_str()) {
            Some("human") => SignerClass::Human,
            Some("ci") => SignerClass::Ci,
            Some("ai") => SignerClass::Ai,
            other => {
                anyhow::bail!("signer `{principal}`: class must be human|ci|ai (got {other:?})")
            }
        };
        out.push(Signer {
            principal,
            class,
            ssh_public_key: t
                .get("ssh_public_key")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            gpg_fingerprint: t
                .get("gpg_fingerprint")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            hardware_backed: t
                .get("hardware_backed")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
        });
    }
    Ok(out)
}

/// Build the ssh allowed_signers file content from policy. AI-class signers
/// are NEVER emitted: an AI key can never produce a "good" signature.
pub fn allowed_signers_content(signers: &[Signer]) -> String {
    let mut out =
        String::from("# Generated by sscsb from .sscsb/policy/signers.toml — do not edit.\n");
    for s in signers {
        if s.class == SignerClass::Ai {
            continue;
        }
        if let Some(key) = &s.ssh_public_key {
            let _ = writeln!(out, "{} namespaces=\"git\" {}", s.principal, key.trim());
        }
    }
    out
}

pub fn regenerate_allowed_signers(ctx: &Ctx) -> Result<()> {
    let policy_dir = ctx.sscsb_dir().join("policy");
    std::fs::create_dir_all(&policy_dir)?;
    let signers = load_signers(&signers_path(ctx))?;
    std::fs::write(
        policy_dir.join("allowed_signers"),
        allowed_signers_content(&signers),
    )?;
    Ok(())
}

// ─────────────────────────────── Trailers ───────────────────────────────────

pub const AI_ROLES: &[&str] = &["draft", "review", "test", "refactor"];

/// Extract `Key: value` trailers (AI-*, Reviewed-by, Review-evidence) from a
/// commit message.
pub fn parse_trailers(message: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in message.lines() {
        let line = line.trim_end();
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let is_trailer_key = !key.is_empty()
                && !key.contains(' ')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
            if is_trailer_key {
                out.insert(key.to_string(), value.trim().to_string());
            }
        }
    }
    out
}

/// Validate AI trailer discipline. Returns problems (empty = OK).
pub fn validate_ai_trailers(trailers: &BTreeMap<String, String>) -> Vec<String> {
    let mut problems = Vec::new();
    let assisted = trailers.get("AI-Assisted").map(String::as_str);
    match assisted {
        None => {}
        Some("true") => {
            for key in ["AI-Tool", "AI-Model"] {
                if trailers.get(key).is_none_or(|v| v.is_empty()) {
                    problems.push(format!(
                        "AI-Assisted: true requires a non-empty `{key}:` trailer"
                    ));
                }
            }
            match trailers.get("AI-Role").map(String::as_str) {
                Some(role) if AI_ROLES.contains(&role) => {}
                Some(role) => problems.push(format!(
                    "AI-Role: `{role}` invalid — must be one of {}",
                    AI_ROLES.join("|")
                )),
                None => problems.push(format!(
                    "AI-Assisted: true requires `AI-Role:` (one of {})",
                    AI_ROLES.join("|")
                )),
            }
        }
        Some("false") => {}
        Some(other) => problems.push(format!(
            "AI-Assisted must be `true` or `false` (got `{other}`)"
        )),
    }
    problems
}

// ─────────────────────────────── pre-commit ─────────────────────────────────

/// Staged paths, enumerated NUL-delimited so git never C-quotes a name.
///
/// `--name-only` (without `-z`) renders any path containing a non-ASCII byte,
/// control character, or quote as a C-quoted string (`"caf\303\251.txt"`) when
/// `core.quotePath` is on (the default). Feeding that quoted string back to
/// `git show :<path>` fails to resolve the real object — which, on the old
/// `continue`-on-failure path, silently dropped the file from the secret scan.
/// `-z` emits raw bytes with a NUL terminator and never quotes.
fn staged_paths(ctx: &Ctx) -> Result<Vec<String>> {
    let out = exec::git_raw(
        &[
            "diff",
            "--cached",
            "-z",
            "--name-only",
            "--diff-filter=ACMR",
        ],
        &ctx.root,
    )?;
    if !out.success() {
        anyhow::bail!("git diff --cached failed: {}", out.stderr.trim());
    }
    Ok(out
        .stdout
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Staged paths that are gitlinks (submodules, mode 160000). These have no blob
/// content in the superproject, so a `git show` miss on them is expected — every
/// OTHER `git show` miss is treated as a hard error (fail-closed).
fn staged_submodules(ctx: &Ctx) -> Result<std::collections::HashSet<String>> {
    let out = exec::git_raw(&["ls-files", "--stage", "-z"], &ctx.root)?;
    if !out.success() {
        anyhow::bail!("git ls-files --stage failed: {}", out.stderr.trim());
    }
    let mut subs = std::collections::HashSet::new();
    for entry in out.stdout.split('\0').filter(|s| !s.is_empty()) {
        // `<mode> <object> <stage>\t<path>`
        if let Some((meta, path)) = entry.split_once('\t') {
            if meta.starts_with("160000 ") {
                subs.insert(path.to_string());
            }
        }
    }
    Ok(subs)
}

/// Materialize staged file contents into a temp directory (handles initial
/// commits where HEAD does not exist). A file that is listed as staged but whose
/// blob cannot be read is a hard error — never a silent skip — unless it is a
/// submodule gitlink, which legitimately has no scannable content.
///
/// Shared by the secret scanner and the pre-commit SAST scanner so both get the
/// same fail-closed, quote-safe materialization.
pub fn stage_to_tempdir(ctx: &Ctx) -> Result<(tempfile::TempDir, Vec<String>)> {
    let dir = tempfile::tempdir()?;
    let files = staged_paths(ctx)?;
    let submodules = staged_submodules(ctx)?;
    for file in &files {
        // `--` guards against a path that begins with a dash, and the raw path
        // is passed as a single argument (never shell-interpolated).
        let out = exec::git_raw(&["show", &format!(":{file}")], &ctx.root)?;
        if !out.success() {
            if submodules.contains(file) {
                continue; // gitlink: no blob to scan, correctly skipped
            }
            anyhow::bail!(
                "refusing to commit: staged file `{file}` could not be read for scanning \
                 (git show exit {}: {}) — this must not be skipped silently",
                out.status,
                out.stderr.trim()
            );
        }
        let dest = dir.path().join(file);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, out.stdout.as_bytes())?;
    }
    Ok((dir, files))
}

pub fn hook_pre_commit(ctx: &Ctx) -> Result<i32> {
    let Some(cfg) = ctx.config.as_ref() else {
        eprintln!("sscsb: no config — run `sscsb init` (allowing commit)");
        return Ok(0);
    };
    let mut blocked = false;

    if cfg.control_enabled("secrets").unwrap_or(true) {
        match run_secret_scan_staged(ctx, cfg) {
            Ok(problems) if problems.is_empty() => {
                eprintln!("sscsb: secrets — staged changes clean");
            }
            Ok(problems) => {
                blocked = true;
                eprintln!("sscsb: BLOCKED — secret scanning found problems:");
                for p in &problems {
                    eprintln!("  ✗ {p}");
                }
                eprintln!("sscsb: remove the secret (and rotate it if real), then retry.");
            }
            Err(err) => {
                if cfg.fail_open() {
                    eprintln!("sscsb: WARNING (fail_open=true): {err:#}");
                } else {
                    blocked = true;
                    eprintln!("sscsb: BLOCKED (fail-closed): {err:#}");
                }
            }
        }
    }

    if cfg.control_enabled("sast").unwrap_or(false)
        && cfg.control_opt_bool("sast", "pre_commit").unwrap_or(false)
    {
        match crate::sast::scan_staged(ctx, cfg) {
            Ok(findings) if findings.is_empty() => {
                eprintln!("sscsb: sast — staged changes clean");
            }
            Ok(findings) => {
                blocked = true;
                eprintln!("sscsb: BLOCKED — SAST findings in staged changes:");
                for f in findings.iter().take(20) {
                    eprintln!("  ✗ {f}");
                }
            }
            Err(err) => {
                // SAST pre-commit is opt-in advisory; degrade open with notice.
                eprintln!("sscsb: sast pre-commit unavailable: {err:#}");
            }
        }
    }

    Ok(if blocked { 1 } else { 0 })
}

/// Run TruffleHog + Gitleaks over staged content. Returns findings.
/// Errors when NO enabled scanner could run (caller applies fail-open policy).
fn run_secret_scan_staged(ctx: &Ctx, cfg: &Config) -> Result<Vec<String>> {
    let want_th = cfg
        .control_opt_bool("secrets", "trufflehog")
        .unwrap_or(true);
    let want_gl = cfg.control_opt_bool("secrets", "gitleaks").unwrap_or(true);
    let (dir, files) = stage_to_tempdir(ctx)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut findings = Vec::new();
    let mut ran = 0u32;
    let mut degrade = Vec::new();

    if want_th {
        if tools::is_available("trufflehog") {
            ran += 1;
            let dir_arg = dir.path().display().to_string();
            let out = exec::run(
                "trufflehog",
                &[
                    "filesystem",
                    &dir_arg,
                    "--no-update",
                    "--fail",
                    "--json",
                    "--results=verified,unknown",
                ],
                None,
            )?;
            match out.status {
                0 => {}
                TRUFFLEHOG_FINDINGS_EXIT => {
                    findings.extend(parse_trufflehog_findings(&out.stdout));
                }
                code => anyhow::bail!("trufflehog failed (exit {code}): {}", out.stderr.trim()),
            }
        } else {
            degrade.push(tools::degrade_message("trufflehog", ctx.platform));
        }
    }

    if want_gl {
        if tools::is_available("gitleaks") {
            ran += 1;
            let report = tempfile::NamedTempFile::new()?;
            let report_arg = report.path().display().to_string();
            let dir_arg = dir.path().display().to_string();
            let exit_arg = GITLEAKS_FINDINGS_EXIT.to_string();
            let mut args: Vec<&str> = vec![
                "dir",
                &dir_arg,
                "--no-banner",
                "--redact",
                "--exit-code",
                &exit_arg,
                "--report-format",
                "json",
                "--report-path",
                &report_arg,
            ];
            let repo_gitleaks = ctx.root.join(".gitleaks.toml");
            let cfg_arg = repo_gitleaks.display().to_string();
            if repo_gitleaks.is_file() {
                args.push("--config");
                args.push(&cfg_arg);
            }
            let out = exec::run("gitleaks", &args, None)?;
            match out.status {
                0 => {}
                code if code == GITLEAKS_FINDINGS_EXIT => {
                    let json = std::fs::read_to_string(report.path()).unwrap_or_default();
                    findings.extend(parse_gitleaks_findings(&json));
                }
                code => anyhow::bail!("gitleaks failed (exit {code}): {}", out.stderr.trim()),
            }
        } else {
            degrade.push(tools::degrade_message("gitleaks", ctx.platform));
        }
    }

    if ran == 0 {
        anyhow::bail!(
            "no secret scanner could run: {}",
            if degrade.is_empty() {
                "both scanners disabled in config".to_string()
            } else {
                degrade.join(" | ")
            }
        );
    }
    for d in degrade {
        eprintln!("sscsb: degraded — {d}");
    }
    Ok(findings)
}

pub fn parse_trufflehog_findings(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(det) = v.get("DetectorName").and_then(|d| d.as_str()) {
            let file = v
                .pointer("/SourceMetadata/Data/Filesystem/file")
                .and_then(|f| f.as_str())
                .unwrap_or("<unknown>");
            let file = file.rsplit('/').next().unwrap_or(file);
            let verified = v
                .get("Verified")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            out.push(format!(
                "trufflehog: {det} credential in {file} (verified: {verified})"
            ));
        }
    }
    if out.is_empty() {
        out.push("trufflehog: findings reported (exit 183)".to_string());
    }
    out
}

pub fn parse_gitleaks_findings(stdout: &str) -> Vec<String> {
    let start = stdout.find('[');
    let Some(start) = start else {
        return vec!["gitleaks: leaks reported".to_string()];
    };
    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout[start..]) else {
        return vec!["gitleaks: leaks reported".to_string()];
    };
    items
        .iter()
        .map(|v| {
            format!(
                "gitleaks: {} in {} (line {})",
                v.get("RuleID").and_then(|r| r.as_str()).unwrap_or("rule"),
                v.get("File").and_then(|f| f.as_str()).unwrap_or("<file>"),
                v.get("StartLine")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0),
            )
        })
        .collect()
}

// ─────────────────────────────── commit-msg ─────────────────────────────────

pub fn hook_commit_msg(ctx: &Ctx, msg_file: &Path) -> Result<i32> {
    let Some(cfg) = ctx.config.as_ref() else {
        return Ok(0);
    };
    let message = std::fs::read_to_string(msg_file)
        .with_context(|| format!("reading commit message {}", msg_file.display()))?;
    let trailers = parse_trailers(&message);
    let mut problems: Vec<String> = Vec::new();

    if cfg.control_enabled("ai-trailers").unwrap_or(true) {
        problems.extend(validate_ai_trailers(&trailers));
    }

    let ai_assisted = trailers.get("AI-Assisted").map(String::as_str) == Some("true");

    if ai_assisted && cfg.control_enabled("ai-dep-gate").unwrap_or(true) {
        let staged = exec::git(
            &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            &ctx.root,
        )?;
        let staged: Vec<&str> = staged.lines().collect();
        let manifests: Vec<&&str> = staged
            .iter()
            .filter(|f| crate::deps::is_dependency_manifest(f))
            .collect();
        if !manifests.is_empty()
            && trailers.get("AI-Dependency-Review").map(String::as_str) != Some("approved")
        {
            problems.push(format!(
                "AI-assisted commit modifies dependency manifests ({}) — a human must review \
                 and add trailer `AI-Dependency-Review: approved` (see docs/ai-provenance.md); \
                 run `sscsb deps check` to validate the new packages first",
                manifests.iter().map(|m| **m).collect::<Vec<_>>().join(", ")
            ));
        }
        let shellish: Vec<&&str> = staged
            .iter()
            .filter(|f| f.ends_with(".sh") || f.ends_with(".bash") || f.ends_with(".zsh"))
            .collect();
        if !shellish.is_empty()
            && trailers.get("AI-Command-Review").map(String::as_str) != Some("approved")
        {
            problems.push(format!(
                "AI-assisted commit adds/modifies shell scripts ({}) — a human must review \
                 and add trailer `AI-Command-Review: approved`",
                shellish.iter().map(|m| **m).collect::<Vec<_>>().join(", ")
            ));
        }
    }

    if cfg.control_enabled("package-trust").unwrap_or(true) {
        match crate::deps::new_unapproved_deps(ctx) {
            Ok(new_deps) if !new_deps.is_empty() => {
                for d in &new_deps {
                    problems.push(d.explain());
                    // Enforce the anti-slopsquat heuristic HERE, not only in the
                    // advisory `deps check`: a new package one edit from a popular
                    // name is called out at the gate that actually blocks.
                    if let Some((eco_label, name)) = d.qualified.split_once(':') {
                        if let Some(eco) = crate::deps::Ecosystem::from_label(eco_label) {
                            if let Some(shadowed) = crate::deps::typosquat_suspect(eco, name) {
                                problems.push(format!(
                                    "`{}` is one edit from popular package `{shadowed}` — likely \
                                     typosquat/slopsquat; verify before approving",
                                    d.qualified
                                ));
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(err) => eprintln!("sscsb: package-trust check skipped: {err:#}"),
        }
    }

    if problems.is_empty() {
        Ok(0)
    } else {
        eprintln!("sscsb: BLOCKED — commit message / AI-provenance policy:");
        for p in &problems {
            eprintln!("  ✗ {p}");
        }
        Ok(1)
    }
}

// ─────────────────────────────── pre-push ───────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub struct RefUpdate {
    pub local_ref: String,
    pub local_sha: String,
    pub remote_ref: String,
    pub remote_sha: String,
}

pub fn parse_push_lines(stdin: &str) -> Vec<RefUpdate> {
    stdin
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            Some(RefUpdate {
                local_ref: it.next()?.to_string(),
                local_sha: it.next()?.to_string(),
                remote_ref: it.next()?.to_string(),
                remote_sha: it.next()?.to_string(),
            })
        })
        .collect()
}

pub fn branch_of_ref(r: &str) -> Option<&str> {
    r.strip_prefix("refs/heads/")
}

const ZERO_SHA_PREFIX: &str = "0000000";

pub fn hook_pre_push(ctx: &Ctx, _remote: &str, stdin: &str) -> Result<i32> {
    let Some(cfg) = ctx.config.as_ref() else {
        return Ok(0);
    };
    let updates = parse_push_lines(stdin);
    let protected = cfg.protected_branches();
    let mut problems: Vec<String> = Vec::new();

    for u in &updates {
        if u.local_sha.starts_with(ZERO_SHA_PREFIX) {
            continue; // deletion
        }
        let branch = branch_of_ref(&u.remote_ref).unwrap_or("");
        let is_protected = protected.iter().any(|p| p == branch);

        if is_protected && cfg.control_enabled("commit-signing").unwrap_or(true) {
            problems.extend(check_signing_for_range(ctx, cfg, u, branch)?);
        }

        if cfg.control_enabled("secrets").unwrap_or(true)
            && cfg
                .control_opt_bool("secrets", "pre_push_range_scan")
                .unwrap_or(true)
        {
            match range_secret_scan(ctx, u) {
                Ok(findings) => problems.extend(findings),
                Err(err) => {
                    if cfg.fail_open() {
                        eprintln!("sscsb: WARNING (fail_open=true): {err:#}");
                    } else {
                        problems.push(format!("secret range scan could not run: {err:#}"));
                    }
                }
            }
        }
    }

    if problems.is_empty() {
        eprintln!("sscsb: pre-push checks passed");
        Ok(0)
    } else {
        eprintln!("sscsb: PUSH BLOCKED:");
        for p in &problems {
            eprintln!("  ✗ {p}");
        }
        Ok(1)
    }
}

fn commits_in_range(ctx: &Ctx, u: &RefUpdate) -> Result<Vec<String>> {
    // No count cap: EVERY commit being pushed to a protected branch must be
    // verified. A cap would leave commits beyond it unverified for signing —
    // an unsigned commit deep in a large push could reach the branch. Large
    // pushes are rare; correctness wins over the walk time.
    let range_out = if u.remote_sha.starts_with(ZERO_SHA_PREFIX) {
        // New remote branch: verify commits not already on any remote ref.
        exec::git(&["rev-list", &u.local_sha, "--not", "--remotes"], &ctx.root)?
    } else {
        exec::git(
            &["rev-list", &format!("{}..{}", u.remote_sha, u.local_sha)],
            &ctx.root,
        )?
    };
    Ok(range_out.lines().map(str::to_string).collect())
}

/// CommitSigningGuard core: every commit pushed to a protected branch must
/// carry a good signature from an approved `class = "human"` signer; merges
/// with declared AI involvement need review evidence.
fn check_signing_for_range(
    ctx: &Ctx,
    cfg: &Config,
    u: &RefUpdate,
    branch: &str,
) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let signers = load_signers(&signers_path(ctx))?;
    if signers.is_empty() {
        problems.push(format!(
            "protected branch `{branch}`: no approved signers configured — add your key to \
             .sscsb/policy/signers.toml (see docs/signing.md); refusing unsigned/unapproved push"
        ));
    }
    // Ensure allowed_signers reflects current policy before verification.
    regenerate_allowed_signers(ctx)?;

    for sha in commits_in_range(ctx, u)? {
        let raw = exec::git(
            &["log", "-1", "--format=%G?%x00%GS%x00%GK%x00%P%x00%B", &sha],
            &ctx.root,
        )?;
        let mut parts = raw.splitn(5, '\0');
        let status = parts.next().unwrap_or("");
        let signer_principal = parts.next().unwrap_or("");
        let key_id = parts.next().unwrap_or("");
        let parents = parts.next().unwrap_or("");
        let body = parts.next().unwrap_or("");
        let short = &sha[..sha.len().min(10)];

        match status {
            "G" => {
                let matched = signers.iter().find(|s| {
                    s.principal == signer_principal
                        || s.gpg_fingerprint
                            .as_deref()
                            .is_some_and(|fp| !fp.is_empty() && key_id.ends_with(fp))
                });
                match matched {
                    None => problems.push(format!(
                        "{short}: good signature but signer `{signer_principal}` is not in the \
                         approved-signers policy"
                    )),
                    Some(s) if s.class != SignerClass::Human => problems.push(format!(
                        "{short}: signed by `{}` (class {:?}) — protected branch `{branch}` \
                         requires a HUMAN signer (humans, CI, and AI never share identities)",
                        s.principal, s.class
                    )),
                    Some(s) => {
                        if cfg
                            .control_opt_bool("commit-signing", "require_hardware_backed")
                            .unwrap_or(true)
                            && !s.hardware_backed
                        {
                            problems.push(format!(
                                "{short}: signer `{}` key is not marked hardware_backed=true in \
                                 policy — hardware-backed signing is required on `{branch}`",
                                s.principal
                            ));
                        }
                    }
                }
            }
            "N" => problems.push(format!(
                "{short}: UNSIGNED commit — protected branch `{branch}` requires signed commits \
                 (git config commit.gpgSign true; see docs/signing.md)"
            )),
            "U" | "E" => problems.push(format!(
                "{short}: signature cannot be validated against approved signers \
                 (status {status}) — key missing from .sscsb/policy/signers.toml?"
            )),
            "B" => problems.push(format!("{short}: BAD signature")),
            other => problems.push(format!(
                "{short}: unexpected signature status `{other}` — refusing"
            )),
        }

        // Human-signed merge + review evidence when AI involvement declared.
        let is_merge = parents.split_whitespace().count() > 1;
        if is_merge
            && cfg
                .control_opt_bool("commit-signing", "require_review_evidence_for_ai_merges")
                .unwrap_or(true)
        {
            let trailers = parse_trailers(body);
            let ai_declared = trailers.get("AI-Assisted").map(String::as_str) == Some("true")
                || range_declares_ai(ctx, &sha).unwrap_or(false);
            let has_evidence =
                trailers.contains_key("Reviewed-by") || trailers.contains_key("Review-evidence");
            if ai_declared && !has_evidence {
                problems.push(format!(
                    "{short}: merge with declared AI involvement lacks review evidence — add \
                     `Reviewed-by:` or `Review-evidence:` trailer to the merge commit"
                ));
            }
        }
    }
    Ok(problems)
}

/// Does either parent-side of a merge (first-parent excluded) declare AI assistance?
fn range_declares_ai(ctx: &Ctx, merge_sha: &str) -> Result<bool> {
    let out = exec::git(
        &[
            "log",
            "--format=%B%x00",
            &format!("{merge_sha}^1..{merge_sha}"),
        ],
        &ctx.root,
    )?;
    Ok(out
        .split('\0')
        .any(|body| parse_trailers(body).get("AI-Assisted").map(String::as_str) == Some("true")))
}

/// Secret scan over the outgoing commit range (TruffleHog git mode +
/// Gitleaks log-opts).
fn range_secret_scan(ctx: &Ctx, u: &RefUpdate) -> Result<Vec<String>> {
    let mut findings = Vec::new();
    let mut ran = 0u32;
    let repo_url = format!("file://{}", ctx.root.display());
    let branch = branch_of_ref(&u.local_ref).unwrap_or("HEAD").to_string();

    if tools::is_available("trufflehog") {
        ran += 1;
        let mut args: Vec<String> = vec![
            "git".into(),
            repo_url.clone(),
            "--no-update".into(),
            "--fail".into(),
            "--json".into(),
            "--results=verified,unknown".into(),
            format!("--branch={branch}"),
        ];
        if !u.remote_sha.starts_with(ZERO_SHA_PREFIX) {
            args.push(format!("--since-commit={}", u.remote_sha));
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = exec::run("trufflehog", &arg_refs, Some(&ctx.root))?;
        match out.status {
            0 => {}
            TRUFFLEHOG_FINDINGS_EXIT => findings.extend(parse_trufflehog_findings(&out.stdout)),
            code => anyhow::bail!(
                "trufflehog range scan failed (exit {code}): {}",
                out.stderr.trim()
            ),
        }
    }

    if tools::is_available("gitleaks") {
        ran += 1;
        let report = tempfile::NamedTempFile::new()?;
        let report_arg = report.path().display().to_string();
        let exit_arg = GITLEAKS_FINDINGS_EXIT.to_string();
        let log_opts = if u.remote_sha.starts_with(ZERO_SHA_PREFIX) {
            u.local_sha.clone()
        } else {
            format!("{}..{}", u.remote_sha, u.local_sha)
        };
        let log_opts_arg = format!("--log-opts={log_opts}");
        let root_arg = ctx.root.display().to_string();
        let out = exec::run(
            "gitleaks",
            &[
                "git",
                &root_arg,
                "--no-banner",
                "--redact",
                "--exit-code",
                &exit_arg,
                &log_opts_arg,
                "--report-format",
                "json",
                "--report-path",
                &report_arg,
            ],
            None,
        )?;
        match out.status {
            0 => {}
            code if code == GITLEAKS_FINDINGS_EXIT => {
                let json = std::fs::read_to_string(report.path()).unwrap_or_default();
                findings.extend(parse_gitleaks_findings(&json));
            }
            code => anyhow::bail!(
                "gitleaks range scan failed (exit {code}): {}",
                out.stderr.trim()
            ),
        }
    }

    if ran == 0 {
        anyhow::bail!(
            "no secret scanner available for pre-push range scan ({} / {})",
            tools::degrade_message("trufflehog", ctx.platform),
            tools::degrade_message("gitleaks", ctx.platform)
        );
    }
    Ok(findings)
}

// ─────────────────────────────── verify ─────────────────────────────────────

pub fn hooks_installed(ctx: &Ctx) -> bool {
    let hooks_path = exec::git(&["config", "core.hooksPath"], &ctx.root).unwrap_or_default();
    if hooks_path != ".sscsb/hooks" {
        return false;
    }
    HOOK_EVENTS
        .iter()
        .all(|e| ctx.sscsb_dir().join("hooks").join(e).is_file())
}

pub fn verify_secrets_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    if !hooks_installed(ctx) {
        return VerifyResult::new(
            "secrets",
            Outcome::Fail,
            vec!["hooks not installed — run `sscsb init`".into()],
        );
    }
    messages.push("pre-commit + pre-push hooks installed (core.hooksPath=.sscsb/hooks)".into());
    for (tool, wanted) in [
        (
            "trufflehog",
            cfg.control_opt_bool("secrets", "trufflehog")
                .unwrap_or(true),
        ),
        (
            "gitleaks",
            cfg.control_opt_bool("secrets", "gitleaks").unwrap_or(true),
        ),
    ] {
        if !wanted {
            messages.push(format!("{tool}: disabled in config"));
            continue;
        }
        match tools::detect(tools::spec(tool).expect("registry")) {
            tools::ToolStatus::Found { version, path } => messages.push(format!(
                "{tool}: {} ({path})",
                version.unwrap_or_else(|| "version unknown".into())
            )),
            tools::ToolStatus::Missing => {
                outcome = Outcome::Degraded;
                messages.push(tools::degrade_message(tool, ctx.platform));
            }
        }
    }
    VerifyResult::new("secrets", outcome, messages)
}

pub fn verify_signing_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    if !hooks_installed(ctx) {
        return VerifyResult::new(
            "commit-signing",
            Outcome::Fail,
            vec!["hooks not installed — run `sscsb init`".into()],
        );
    }
    let signers = match load_signers(&signers_path(ctx)) {
        Ok(s) => s,
        Err(err) => {
            return VerifyResult::new(
                "commit-signing",
                Outcome::Fail,
                vec![format!("signers policy invalid: {err:#}")],
            )
        }
    };
    let humans = signers
        .iter()
        .filter(|s| s.class == SignerClass::Human)
        .count();
    if signers.is_empty() {
        outcome = Outcome::Degraded;
        messages.push(
            "no approved signers configured — protected-branch pushes will be blocked until a \
             human signer is added to .sscsb/policy/signers.toml"
                .into(),
        );
    } else {
        messages.push(format!(
            "{} approved signer(s), {} human",
            signers.len(),
            humans
        ));
    }
    for key in ["gpg.format", "user.signingkey", "commit.gpgSign"] {
        let val = exec::git(&["config", key], &ctx.root).unwrap_or_default();
        if val.is_empty() {
            messages.push(format!(
                "git config `{key}` unset — see docs/signing.md for YubiKey ed25519-sk setup"
            ));
        } else {
            messages.push(format!("git config {key} = {val}"));
            if key == "user.signingkey" && !val.contains("-sk") && !val.contains("sk-") {
                messages.push(
                    "signing key does not look hardware-backed (no `-sk`) — spec recommends \
                     YubiKey ed25519-sk; software keys weaken the human-accountability model"
                        .into(),
                );
            }
        }
    }
    if cfg
        .control_opt_bool("commit-signing", "require_hardware_backed")
        .unwrap_or(true)
    {
        messages.push("policy: hardware-backed keys required on protected branches".into());
    }
    let note = ctx.platform.signing_note();
    if !note.is_empty() {
        messages.push(note.to_string());
    }
    VerifyResult::new("commit-signing", outcome, messages)
}

pub fn verify_hook_installed(ctx: &Ctx, control: &'static str) -> VerifyResult {
    if hooks_installed(ctx) {
        VerifyResult::new(
            control,
            Outcome::Pass,
            vec!["enforced by commit-msg hook (installed)".into()],
        )
    } else {
        VerifyResult::new(
            control,
            Outcome::Fail,
            vec!["hooks not installed — run `sscsb init`".into()],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shims_are_posix_and_fail_closed() {
        for event in HOOK_EVENTS {
            let s = shim_script(event);
            assert!(
                s.starts_with("#!/bin/sh\n"),
                "{event} shim must be POSIX sh"
            );
            assert!(s.contains(&format!("sscsb hook {event}")));
            assert!(s.contains("exit 1"), "{event} shim must fail closed");
            assert!(!s.contains("exit 0"), "{event} shim must not fail open");
        }
    }

    #[test]
    fn trailer_parsing_extracts_ai_block() {
        let msg = "feat: add thing\n\nBody text here: not a trailer? it is captured but harmless\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n";
        let t = parse_trailers(msg);
        assert_eq!(t.get("AI-Assisted").map(String::as_str), Some("true"));
        assert_eq!(t.get("AI-Role").map(String::as_str), Some("draft"));
        assert!(validate_ai_trailers(&t).is_empty());
    }

    #[test]
    fn ai_trailers_validation_catches_gaps() {
        let t = parse_trailers("x\n\nAI-Assisted: true\nAI-Tool: Claude Code\n");
        let problems = validate_ai_trailers(&t);
        assert_eq!(problems.len(), 2); // missing AI-Model, missing AI-Role
        let t = parse_trailers("x\n\nAI-Assisted: yes\n");
        assert_eq!(validate_ai_trailers(&t).len(), 1);
        let t = parse_trailers("x\n\nAI-Assisted: true\nAI-Tool: c\nAI-Model: m\nAI-Role: pilot\n");
        assert!(validate_ai_trailers(&t)[0].contains("invalid"));
        let t = parse_trailers("plain commit, no AI trailers\n");
        assert!(validate_ai_trailers(&t).is_empty());
    }

    #[test]
    fn push_line_parsing() {
        let updates = parse_push_lines(
            "refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 2222222222222222222222222222222222222222\n",
        );
        assert_eq!(updates.len(), 1);
        assert_eq!(branch_of_ref(&updates[0].remote_ref), Some("main"));
        assert!(parse_push_lines("garbage\n").is_empty());
    }

    #[test]
    fn trufflehog_json_findings_are_rendered_per_line() {
        // trufflehog emits one JSON object per line; a verified GitHub credential
        // in `secrets.env` must render with detector, filename, and verified flag.
        let stdout = r#"{"DetectorName":"Github","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/secrets.env"}}}}
not-json-noise
{"DetectorName":"AWS","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"config.toml"}}}}"#;
        let findings = parse_trufflehog_findings(stdout);
        assert!(findings
            .iter()
            .any(|f| f.contains("Github") && f.contains("secrets.env") && f.contains("verified: true")));
        assert!(findings
            .iter()
            .any(|f| f.contains("AWS") && f.contains("verified: false")));
        // Non-empty stdout that parses to no detector objects still reports the
        // exit-183 signal rather than silently claiming clean.
        assert_eq!(
            parse_trufflehog_findings("{}\n"),
            vec!["trufflehog: findings reported (exit 183)".to_string()]
        );
    }

    fn tmp_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        crate::exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        crate::exec::git(&["config", "user.name", "t"], dir.path()).unwrap();
        crate::exec::git(&["config", "user.email", "t@e.com"], dir.path()).unwrap();
        crate::init::bootstrap(dir.path()).unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn staged_paths_are_nul_delimited_and_never_quoted() {
        let (_d, ctx) = tmp_repo();
        std::fs::write(ctx.root.join("café.txt"), "x\n").unwrap();
        std::fs::write(ctx.root.join("plain.txt"), "y\n").unwrap();
        crate::exec::git(&["add", "."], &ctx.root).unwrap();
        let paths = staged_paths(&ctx).unwrap();
        // The real, unquoted UTF-8 name is present — not `"caf\303\251.txt"`.
        assert!(paths.iter().any(|p| p == "café.txt"), "{paths:?}");
        assert!(paths.iter().any(|p| p == "plain.txt"));
        assert!(!paths.iter().any(|p| p.contains('\\')));
    }

    #[test]
    fn range_declares_ai_reads_merged_side_history() {
        let (_d, ctx) = tmp_repo();
        let g = |args: &[&str]| crate::exec::git(args, &ctx.root).unwrap();
        std::fs::write(ctx.root.join("base.txt"), "1\n").unwrap();
        g(&["add", "."]);
        g(&["commit", "-m", "base", "--no-verify"]);
        g(&["checkout", "-b", "feature"]);
        std::fs::write(ctx.root.join("f.txt"), "2\n").unwrap();
        g(&["add", "."]);
        g(&[
            "commit",
            "-m",
            "feat: ai work\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft",
            "--no-verify",
        ]);
        g(&["checkout", "main"]);
        g(&["merge", "--no-ff", "--no-verify", "-m", "merge feature", "feature"]);
        let merge_sha = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        assert!(
            range_declares_ai(&ctx, &merge_sha).unwrap(),
            "the merged-in branch declared AI involvement"
        );
    }

    #[test]
    fn signers_policy_parse_and_allowed_signers_generation() {
        let toml = r#"
[[signer]]
principal = "human@example.com"
class = "human"
hardware_backed = true
ssh_public_key = "ssh-ed25519 AAAATESTKEY human@example.com"

[[signer]]
principal = "ci@example.com"
class = "ci"
ssh_public_key = "ssh-ed25519 AAAACIKEY ci@example.com"

[[signer]]
principal = "agent@example.com"
class = "ai"
ssh_public_key = "ssh-ed25519 AAAAAIKEY agent@example.com"
"#;
        let signers = parse_signers(toml).unwrap();
        assert_eq!(signers.len(), 3);
        assert_eq!(signers[0].class, SignerClass::Human);
        assert!(signers[0].hardware_backed);
        let allowed = allowed_signers_content(&signers);
        assert!(allowed.contains("human@example.com"));
        assert!(allowed.contains("ci@example.com"));
        assert!(
            !allowed.contains("agent@example.com"),
            "AI-class signers must never be verification-valid"
        );
    }

    #[test]
    fn signers_policy_rejects_bad_class() {
        let toml = "[[signer]]\nprincipal = \"x@y\"\nclass = \"robot\"\n";
        assert!(parse_signers(toml).is_err());
        assert!(parse_signers("").unwrap().is_empty());
    }

    #[test]
    fn trufflehog_and_gitleaks_finding_parsers() {
        let th = r#"{"DetectorName":"AWS","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/creds.txt"}}}}"#;
        let f = parse_trufflehog_findings(th);
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("AWS"));
        assert!(f[0].contains("creds.txt"));

        let gl = r#"[{"RuleID":"aws-access-key-id","File":"creds.txt","StartLine":3}]"#;
        let f = parse_gitleaks_findings(gl);
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("aws-access-key-id"));
    }

    // ───────────────────── in-process repo fixtures ─────────────────────────
    //
    // The subprocess integration suite (tests/library.rs) proves the same
    // control logic end-to-end but doesn't count toward `cargo llvm-cov --lib`
    // coverage of this file. These fixtures mirror its pattern so hooks.rs's
    // own error branches, degrade paths, and policy edges get exercised at
    // the unit-test boundary too.

    const ZERO: &str = "0000000000000000000000000000000000000000";

    /// A repo bootstrapped through the real `sscsb init` path (hooks
    /// installed, config present).
    fn test_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    /// A plain git repo with no `.sscsb/` at all: `ctx.config` is `None` and
    /// no hooks are installed.
    fn bare_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    /// A repo with a generated `.sscsb/config.toml` but hooks never
    /// installed — the shape `verify_*` sees before `sscsb init` runs the
    /// hook-writing step (or on a config that predates it).
    fn unbootstrapped_repo_with_config() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join(".sscsb")).unwrap();
        std::fs::write(
            dir.path().join(".sscsb/config.toml"),
            crate::config::default_config_toml(None),
        )
        .unwrap();
        let ctx = Ctx::discover(dir.path()).expect("discover");
        (dir, ctx)
    }

    fn write_file(ctx: &Ctx, rel: &str, content: &str) {
        let path = ctx.root.join(rel);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn stage(ctx: &Ctx, rel: &str) {
        let out = exec::git_raw(&["add", rel], &ctx.root).unwrap();
        assert!(out.success());
    }

    fn git_ok(ctx: &Ctx, args: &[&str]) {
        let out = exec::git_raw(args, &ctx.root).unwrap();
        assert!(out.success(), "git {args:?}: {}", out.stderr);
    }

    fn commit_msg(ctx: &Ctx, message: &str) -> i32 {
        let file = ctx.root.join("COMMIT_EDITMSG_TEST");
        std::fs::write(&file, message).unwrap();
        hook_commit_msg(ctx, &file).unwrap()
    }

    // ───────────────────────── install_hooks ─────────────────────────────

    #[test]
    fn install_hooks_writes_executable_shims_and_configures_git() {
        let (_d, ctx) = bare_repo();
        let written = install_hooks(&ctx).unwrap();
        assert_eq!(written.len(), HOOK_EVENTS.len());
        for event in HOOK_EVENTS {
            let path = ctx.sscsb_dir().join("hooks").join(event);
            assert!(path.is_file(), "{event} shim not written");
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(content.starts_with("#!/bin/sh"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o111, 0o111, "{event} shim must be executable");
            }
        }
        let hooks_path = exec::git(&["config", "core.hooksPath"], &ctx.root).unwrap();
        assert_eq!(hooks_path, ".sscsb/hooks");
        let signers_cfg = exec::git(&["config", "gpg.ssh.allowedSignersFile"], &ctx.root).unwrap();
        assert!(signers_cfg.ends_with(".sscsb/policy/allowed_signers"));
        assert!(
            Path::new(&signers_cfg).is_absolute(),
            "git resolves relative hook paths unreliably — allowedSignersFile must be absolute"
        );
    }

    #[test]
    fn hooks_installed_is_false_before_init_and_true_after() {
        let (_d, ctx) = bare_repo();
        assert!(!hooks_installed(&ctx));
        install_hooks(&ctx).unwrap();
        assert!(hooks_installed(&ctx));
    }

    // ───────────────────────── signer policy ──────────────────────────────

    #[test]
    fn load_signers_from_missing_file_is_empty_not_an_error() {
        let (_d, ctx) = bare_repo();
        assert!(load_signers(&signers_path(&ctx)).unwrap().is_empty());
    }

    #[test]
    fn load_signers_parses_an_existing_policy_file() {
        let (_d, ctx) = bare_repo();
        let path = signers_path(&ctx);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAATESTKEY human@example.com\"\n",
        )
        .unwrap();
        let signers = load_signers(&path).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].principal, "human@example.com");
    }

    #[test]
    fn parse_signers_rejects_missing_principal() {
        let err = parse_signers("[[signer]]\nclass = \"human\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("missing `principal`"));
    }

    #[test]
    fn parse_signers_rejects_non_table_entries() {
        let err = parse_signers("signer = [1, 2]\n").unwrap_err();
        assert!(format!("{err:#}").contains("is not a table"));
    }

    #[test]
    fn parse_signers_reads_gpg_fingerprint_and_skips_keyless_signers_in_allowed_signers() {
        let toml = "[[signer]]\nprincipal = \"gpg@example.com\"\nclass = \"human\"\ngpg_fingerprint = \"ABCD1234EF\"\n";
        let signers = parse_signers(toml).unwrap();
        assert_eq!(signers[0].gpg_fingerprint.as_deref(), Some("ABCD1234EF"));
        assert!(signers[0].ssh_public_key.is_none());
        // A signer with no ssh key can never appear in the ssh allowed_signers
        // file — there is nothing to add.
        let allowed = allowed_signers_content(&signers);
        assert!(!allowed.contains("gpg@example.com"));
    }

    #[test]
    fn regenerate_allowed_signers_writes_policy_derived_file() {
        let (_d, ctx) = bare_repo();
        std::fs::create_dir_all(ctx.sscsb_dir().join("policy")).unwrap();
        std::fs::write(
            signers_path(&ctx),
            "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAATESTKEY human@example.com\"\n",
        )
        .unwrap();
        regenerate_allowed_signers(&ctx).unwrap();
        let content =
            std::fs::read_to_string(ctx.sscsb_dir().join("policy").join("allowed_signers"))
                .unwrap();
        assert!(content.contains("human@example.com"));
    }

    // ───────────────────────────── trailers ────────────────────────────────

    #[test]
    fn ai_assisted_false_is_valid_and_needs_no_further_trailers() {
        let t = parse_trailers("x\n\nAI-Assisted: false\n");
        assert!(validate_ai_trailers(&t).is_empty());
    }

    // ─────────────────────────── hook_pre_commit ───────────────────────────

    #[test]
    fn hook_pre_commit_without_config_allows_the_commit() {
        let (_d, ctx) = bare_repo();
        assert_eq!(hook_pre_commit(&ctx).unwrap(), 0);
    }

    #[test]
    fn hook_pre_commit_passes_clean_stage_and_blocks_a_real_secret() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "clean.md", "nothing to see here\n");
        stage(&ctx, "clean.md");
        assert_eq!(hook_pre_commit(&ctx).unwrap(), 0, "clean stage must pass");

        // Runtime-constructed token — never a real credential, and never
        // present in this repository's sources as a single string.
        let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
        write_file(&ctx, "leak.txt", &format!("github_token = \"{token}\"\n"));
        stage(&ctx, "leak.txt");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            1,
            "planted secret must block the commit"
        );
    }

    #[test]
    fn hook_pre_commit_fails_closed_when_both_scanners_are_disabled_in_config() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("trufflehog = true", "trufflehog = false")
            .replace("gitleaks = true", "gitleaks = false");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();

        write_file(&ctx, "a.txt", "a\n");
        stage(&ctx, "a.txt");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            1,
            "no scanner able to run must fail CLOSED by default"
        );
    }

    #[test]
    fn hook_pre_commit_fails_open_when_configured_and_no_scanner_can_run() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("trufflehog = true", "trufflehog = false")
            .replace("gitleaks = true", "gitleaks = false")
            .replace("fail_open = false", "fail_open = true");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();

        write_file(&ctx, "a.txt", "a\n");
        stage(&ctx, "a.txt");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            0,
            "fail_open=true must let the commit through with only a warning"
        );
    }

    #[test]
    fn hook_pre_commit_sast_clean_pass_and_misconfigured_engine_degrades_without_blocking() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("pre_commit = false", "pre_commit = true");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        write_file(&ctx, "clean.md", "hello\n");
        stage(&ctx, "clean.md");
        assert_eq!(hook_pre_commit(&ctx).unwrap(), 0);

        // An unusable SAST engine must degrade (advisory), never block.
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("engine = \"opengrep\"", "engine = \"bogus-engine\"");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        write_file(&ctx, "clean2.md", "hello again\n");
        stage(&ctx, "clean2.md");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            0,
            "an unusable SAST engine must degrade, not block"
        );
    }

    // ────────────────────── trufflehog/gitleaks parsing edges ──────────────

    #[test]
    fn trufflehog_findings_skip_unparseable_lines_and_default_when_nothing_extracted() {
        let mixed = "not json at all\n{\"DetectorName\":\"AWS\",\"Verified\":true,\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"/tmp/x/creds.txt\"}}}}\n";
        let f = parse_trufflehog_findings(mixed);
        assert_eq!(
            f.len(),
            1,
            "the unparseable line must be skipped, not panic"
        );
        assert!(f[0].contains("verified: true"));

        let f = parse_trufflehog_findings("garbage\nmore garbage\n");
        assert_eq!(
            f,
            vec!["trufflehog: findings reported (exit 183)".to_string()]
        );

        // Valid JSON without a DetectorName field is silently skipped.
        let f = parse_trufflehog_findings(r#"{"SomeOtherField":true}"#);
        assert_eq!(
            f,
            vec!["trufflehog: findings reported (exit 183)".to_string()]
        );
    }

    #[test]
    fn gitleaks_findings_default_message_when_output_has_no_json_array() {
        let f = parse_gitleaks_findings("no brackets here at all");
        assert_eq!(f, vec!["gitleaks: leaks reported".to_string()]);

        let f = parse_gitleaks_findings("[ this is not valid json");
        assert_eq!(f, vec!["gitleaks: leaks reported".to_string()]);
    }

    // ─────────────────────────── hook_commit_msg ───────────────────────────

    #[test]
    fn hook_commit_msg_without_config_allows_the_commit() {
        let (_d, ctx) = bare_repo();
        let file = ctx.root.join("MSG");
        std::fs::write(&file, "chore: x\n").unwrap();
        assert_eq!(hook_commit_msg(&ctx, &file).unwrap(), 0);
    }

    #[test]
    fn hook_commit_msg_validates_ai_trailers() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "a.txt", "a\n");
        stage(&ctx, "a.txt");
        assert_eq!(commit_msg(&ctx, "chore: no ai trailers\n"), 0);
        assert_eq!(
            commit_msg(
                &ctx,
                "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n"
            ),
            0
        );
        assert_eq!(commit_msg(&ctx, "feat: x\n\nAI-Assisted: true\n"), 1);
    }

    #[test]
    fn hook_commit_msg_gates_ai_introduced_dependencies_and_shell_scripts() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(&ctx, &["commit", "-m", "chore: baseline", "--no-verify"]);

        let ai =
            "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n";

        write_file(&ctx, "package.json", r#"{"dependencies":{"lodash":"4"}}"#);
        stage(&ctx, "package.json");
        assert_eq!(commit_msg(&ctx, ai), 1, "AI dep change must gate");

        crate::deps::approve_package(&ctx, "npm:lodash").unwrap();
        assert_eq!(commit_msg(&ctx, ai), 1, "review trailer still required");
        assert_eq!(
            commit_msg(&ctx, &format!("{ai}AI-Dependency-Review: approved\n")),
            0
        );

        write_file(&ctx, "run.sh", "#!/bin/sh\necho hi\n");
        stage(&ctx, "run.sh");
        assert_eq!(
            commit_msg(&ctx, &format!("{ai}AI-Dependency-Review: approved\n")),
            1,
            "AI-authored shell script must gate"
        );
        assert_eq!(
            commit_msg(
                &ctx,
                &format!("{ai}AI-Dependency-Review: approved\nAI-Command-Review: approved\n")
            ),
            0
        );
    }

    #[test]
    fn hook_commit_msg_skips_package_trust_check_on_corrupt_policy_without_blocking() {
        let (_d, ctx) = test_repo();
        // Corrupt the approved-packages policy so `unapproved_new_packages`
        // errors; package-trust degrades advisory here, so the commit must
        // still pass rather than being blocked by an unrelated parse bug.
        std::fs::write(
            crate::deps::packages_policy_path(&ctx),
            "not = [valid toml\n",
        )
        .unwrap();
        write_file(&ctx, "a.txt", "a\n");
        stage(&ctx, "a.txt");
        assert_eq!(commit_msg(&ctx, "chore: x\n"), 0);
    }

    // ─────────────────────────── parse_push_lines ──────────────────────────

    #[test]
    fn push_line_parsing_drops_truncated_lines() {
        let updates = parse_push_lines(&format!("refs/heads/main {ZERO} refs/heads/main {ZERO}\n"));
        assert_eq!(updates.len(), 1);
        assert_eq!(branch_of_ref(&updates[0].remote_ref), Some("main"));

        assert!(
            parse_push_lines("garbage\n").is_empty(),
            "missing local_sha"
        );
        assert!(
            parse_push_lines("\n").is_empty(),
            "blank line has no local_ref"
        );
        assert!(
            parse_push_lines("refs/heads/main aaaa\n").is_empty(),
            "missing remote_ref"
        );
        assert!(
            parse_push_lines("refs/heads/main aaaa refs/heads/main\n").is_empty(),
            "missing remote_sha"
        );
    }

    // ─────────────────────────── hook_pre_push ─────────────────────────────

    #[test]
    fn hook_pre_push_without_config_allows_the_push() {
        let (_d, ctx) = bare_repo();
        assert_eq!(hook_pre_push(&ctx, "origin", "").unwrap(), 0);
    }

    #[test]
    fn hook_pre_push_blocks_unsigned_commits_on_protected_branches_only() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(&ctx, &["commit", "-m", "chore: unsigned", "--no-verify"]);
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            hook_pre_push(&ctx, "origin", &stdin).unwrap(),
            1,
            "unsigned commit on a protected branch must be blocked"
        );

        let stdin = format!("refs/heads/feature/x {local} refs/heads/feature/x {ZERO}\n");
        assert_eq!(hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);

        let stdin = format!("(delete) {ZERO} refs/heads/main {ZERO}\n");
        assert_eq!(hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);
    }

    #[test]
    fn pre_push_range_scan_blocks_a_secret_reachable_only_via_history() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(&ctx, &["commit", "-m", "chore: base", "--no-verify"]);

        let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
        write_file(&ctx, "leak.txt", &format!("github_token = \"{token}\"\n"));
        stage(&ctx, "leak.txt");
        git_ok(&ctx, &["commit", "-m", "chore: oops", "--no-verify"]);
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        // Not a protected branch — isolates the range secret scan from the
        // signing guard.
        let stdin = format!("refs/heads/feature/x {local} refs/heads/feature/x {ZERO}\n");
        assert_eq!(
            hook_pre_push(&ctx, "origin", &stdin).unwrap(),
            1,
            "a secret anywhere in the outgoing range must block the push"
        );
    }

    #[test]
    fn commits_in_range_uses_rev_list_between_shas_when_remote_is_known() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "a.txt", "a\n");
        stage(&ctx, "a.txt");
        git_ok(&ctx, &["commit", "-m", "chore: first", "--no-verify"]);
        let first = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        write_file(&ctx, "b.txt", "b\n");
        stage(&ctx, "b.txt");
        git_ok(&ctx, &["commit", "-m", "chore: second", "--no-verify"]);
        let second = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        let update = RefUpdate {
            local_ref: "refs/heads/main".into(),
            local_sha: second.clone(),
            remote_ref: "refs/heads/main".into(),
            remote_sha: first,
        };
        let range = commits_in_range(&ctx, &update).unwrap();
        assert_eq!(range, vec![second], "only the new commit is in range");
    }

    fn signed_test_repo() -> (tempfile::TempDir, Ctx, String) {
        let (dir, ctx) = test_repo();
        let key = dir.path().join("id_test");
        let out = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "sscsb-test@example.com",
                "-f",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success());
        let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        git_ok(&ctx, &["config", "gpg.format", "ssh"]);
        git_ok(&ctx, &["config", "user.signingkey", key.to_str().unwrap()]);
        // Relax the hardware-backed requirement — these are throwaway
        // software keys generated purely to exercise real signature
        // verification, not to assert anything about hardware policy here.
        let cfg_text = std::fs::read_to_string(ctx.config_path()).unwrap().replace(
            "require_hardware_backed = true",
            "require_hardware_backed = false",
        );
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        (dir, ctx, pubkey.trim().to_string())
    }

    #[test]
    fn check_signing_for_range_falls_through_a_non_matching_signer_before_matching() {
        let (_dir, ctx, pubkey) = signed_test_repo();
        // A second, unrelated real key registered first in the policy —
        // forces the matcher in check_signing_for_range to evaluate (and
        // fail) the principal AND gpg_fingerprint fallback for this entry
        // before it reaches the real signer.
        let other_out = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", "unrelated@example.com"])
            .arg("-f")
            .arg(_dir.path().join("id_unrelated"))
            .output()
            .unwrap();
        assert!(other_out.status.success());
        let other_pub = std::fs::read_to_string(_dir.path().join("id_unrelated.pub")).unwrap();
        let other_pub = other_pub.trim();

        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"unrelated@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{other_pub}\"\n\n[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{pubkey}\"\n"
            ),
        )
        .unwrap();

        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(
            &ctx,
            &["commit", "-S", "-m", "chore: signed", "--no-verify"],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        let update = RefUpdate {
            local_ref: "refs/heads/main".into(),
            local_sha: local,
            remote_ref: "refs/heads/main".into(),
            remote_sha: ZERO.into(),
        };
        let cfg = ctx.require_config().unwrap();
        let problems = check_signing_for_range(&ctx, cfg, &update, "main").unwrap();
        assert!(
            problems.is_empty(),
            "the second policy entry must still match by principal: {problems:?}"
        );
    }

    #[test]
    fn pre_push_flags_ai_merge_commits_lacking_review_evidence() {
        let (_dir, ctx, pubkey) = signed_test_repo();
        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{pubkey}\"\n"
            ),
        )
        .unwrap();

        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(&ctx, &["commit", "-S", "-m", "chore: base", "--no-verify"]);
        git_ok(&ctx, &["checkout", "-b", "feature"]);
        write_file(&ctx, "feature.txt", "f\n");
        stage(&ctx, "feature.txt");
        git_ok(
            &ctx,
            &[
                "commit",
                "-S",
                "-m",
                "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft",
                "--no-verify",
            ],
        );
        git_ok(&ctx, &["checkout", "main"]);
        git_ok(
            &ctx,
            &[
                "merge",
                "--no-ff",
                "-S",
                "-m",
                "Merge branch 'feature'",
                "--no-verify",
                "feature",
            ],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            hook_pre_push(&ctx, "origin", &stdin).unwrap(),
            1,
            "merge with AI-declared parent lacking review evidence must block"
        );

        // Redo the same merge, this time with a Reviewed-by trailer on the
        // merge commit itself — must pass.
        git_ok(&ctx, &["reset", "--hard", "HEAD^"]);
        git_ok(
            &ctx,
            &[
                "merge",
                "--no-ff",
                "-S",
                "-m",
                "Merge branch 'feature'\n\nReviewed-by: human@example.com",
                "--no-verify",
                "feature",
            ],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);
    }

    // ────────────────────────── verify_* controls ──────────────────────────

    #[test]
    fn verify_secrets_control_fails_when_hooks_are_not_installed() {
        let (_d, ctx) = unbootstrapped_repo_with_config();
        let cfg = ctx.require_config().unwrap();
        let result = verify_secrets_control(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("hooks not installed"));
    }

    #[test]
    fn verify_secrets_control_reports_a_tool_disabled_in_config() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("trufflehog = true", "trufflehog = false");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        let result = verify_secrets_control(&ctx, cfg);
        assert!(result
            .messages
            .iter()
            .any(|m| m == "trufflehog: disabled in config"));
    }

    #[test]
    fn verify_signing_control_fails_when_hooks_are_not_installed() {
        let (_d, ctx) = unbootstrapped_repo_with_config();
        let cfg = ctx.require_config().unwrap();
        let result = verify_signing_control(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("hooks not installed"));
    }

    #[test]
    fn verify_signing_control_fails_on_an_invalid_signers_policy_file() {
        let (_d, ctx) = test_repo();
        std::fs::write(
            signers_path(&ctx),
            "[[signer]]\nprincipal = \"x\"\nclass = \"robot\"\n",
        )
        .unwrap();
        let cfg = ctx.require_config().unwrap();
        let result = verify_signing_control(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("signers policy invalid"));
    }

    #[test]
    fn verify_signing_control_reports_configured_signers_and_soft_key_warning() {
        let (_dir, ctx, pubkey) = signed_test_repo();
        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nhardware_backed = true\nssh_public_key = \"{pubkey}\"\n"
            ),
        )
        .unwrap();
        let cfg = ctx.require_config().unwrap();
        let result = verify_signing_control(&ctx, cfg);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("1 approved signer(s), 1 human")));
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("does not look hardware-backed")),
            "a software (non -sk) signingkey must warn: {:?}",
            result.messages
        );
    }

    #[test]
    fn verify_signing_control_surfaces_platform_specific_signing_notes() {
        let (_d, ctx) = test_repo();
        let mut ctx = ctx;
        // Exercise the WSL-specific messaging deterministically regardless
        // of the host OS this test suite happens to run on.
        ctx.platform = crate::platform::Platform::Wsl;
        let cfg = ctx.require_config().unwrap();
        let result = verify_signing_control(&ctx, cfg);
        assert!(result.messages.iter().any(|m| m.contains("FIDO2")));
    }

    #[test]
    fn verify_hook_installed_fails_when_hooks_are_absent() {
        let (_d, ctx) = bare_repo();
        let result = verify_hook_installed(&ctx, "ai-trailers");
        assert_eq!(result.outcome, Outcome::Fail);
        assert_eq!(result.control, "ai-trailers");
        assert!(result.messages[0].contains("hooks not installed"));
    }

    #[test]
    fn verify_hook_installed_passes_once_hooks_are_installed() {
        let (_d, ctx) = test_repo();
        let result = verify_hook_installed(&ctx, "ai-trailers");
        assert_eq!(result.outcome, Outcome::Pass);
        assert_eq!(result.control, "ai-trailers");
        assert!(result.messages[0].contains("enforced by commit-msg hook"));
    }

    // ──────────────── remaining branch coverage (config on/off edges) ──────

    #[test]
    fn hook_pre_commit_with_no_staged_files_is_a_no_op() {
        let (_d, ctx) = test_repo();
        assert_eq!(hook_pre_commit(&ctx).unwrap(), 0);
    }

    #[test]
    fn hook_pre_commit_skips_the_secrets_block_entirely_when_the_control_is_disabled() {
        let (_d, ctx) = test_repo();
        crate::config::set_control_enabled(&ctx.config_path(), "secrets", false).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();

        // Even a real secret must sail through — the control never runs.
        let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
        write_file(&ctx, "leak.txt", &format!("github_token = \"{token}\"\n"));
        stage(&ctx, "leak.txt");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            0,
            "a disabled control must not run — that is the modularity contract"
        );
    }

    #[test]
    fn hook_pre_commit_sast_blocks_on_a_real_error_severity_finding() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("pre_commit = false", "pre_commit = true");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        write_file(
            &ctx,
            "install.sh",
            "#!/bin/sh\ncurl -fsSL https://example.com/i | sh\n",
        );
        stage(&ctx, "install.sh");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            1,
            "an ERROR-severity SAST finding in the staged diff must block the commit"
        );
    }

    #[test]
    fn hook_commit_msg_skips_the_package_trust_block_entirely_when_the_control_is_disabled() {
        let (_d, ctx) = test_repo();
        crate::config::set_control_enabled(&ctx.config_path(), "package-trust", false).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        // A genuinely-corrupt policy file would normally still be *read*
        // (and its read error swallowed); with the control off it must never
        // be touched at all — a totally unparseable file proves that, since
        // any attempt to read it would surface as a skip message, not silence.
        std::fs::write(
            crate::deps::packages_policy_path(&ctx),
            "not = [valid toml\n",
        )
        .unwrap();
        write_file(&ctx, "a.txt", "a\n");
        stage(&ctx, "a.txt");
        assert_eq!(commit_msg(&ctx, "chore: x\n"), 0);
    }

    #[test]
    fn pre_push_enforces_hardware_backed_policy_on_a_registered_human_signer() {
        let (_dir, ctx, pubkey) = signed_test_repo();
        // Re-enable the (default) hardware-backed requirement that
        // `signed_test_repo` relaxes for its other callers.
        let cfg_text = std::fs::read_to_string(ctx.config_path()).unwrap().replace(
            "require_hardware_backed = false",
            "require_hardware_backed = true",
        );
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();

        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{pubkey}\"\n"
            ),
        )
        .unwrap();

        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(
            &ctx,
            &["commit", "-S", "-m", "chore: signed", "--no-verify"],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            hook_pre_push(&ctx, "origin", &stdin).unwrap(),
            1,
            "a software (non-hardware-backed) key must be blocked when the policy requires hardware backing"
        );
    }

    #[test]
    fn range_secret_scan_args_use_since_commit_and_log_opts_when_the_remote_ref_already_exists() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(&ctx, &["commit", "-m", "chore: first", "--no-verify"]);
        let first = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        write_file(&ctx, "second.txt", "s\n");
        stage(&ctx, "second.txt");
        git_ok(&ctx, &["commit", "-m", "chore: second", "--no-verify"]);
        let second = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();

        // A non-zero remote_sha means the remote ref already exists — the
        // scan must be scoped with `--since-commit` / `--log-opts` rather
        // than treating this as a brand-new branch.
        let stdin = format!("refs/heads/feature/x {second} refs/heads/feature/x {first}\n");
        assert_eq!(
            hook_pre_push(&ctx, "origin", &stdin).unwrap(),
            0,
            "clean incremental push must pass"
        );
    }
}
