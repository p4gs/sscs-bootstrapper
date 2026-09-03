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
use std::collections::{BTreeMap, BTreeSet};
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
    /// How the key is held: tpm | fido2 | kms | github-app | piv | software.
    /// Informational — it NEVER changes the protected-branch gate outcome; the
    /// gate keys on `class`, not `backend`.
    pub backend: Option<String>,
    /// Path (repo-relative) to an out-of-band hardware-residence attestation
    /// artifact (e.g. `ssh-keygen -O write-attestation`). Its presence lets
    /// sscsb report `attested` instead of `declared`; it is NEVER trusted to
    /// elevate a signer's class (see ISC-A6).
    pub attestation_file: Option<String>,
    /// Optional RFC3339 date after which this key must be rotated. Reported by
    /// `verify`; not enforced in the emitted allowed_signers file.
    pub expires: Option<String>,
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
#
# AI agents may sign ONLY when the `agent-signing` control is enabled, and their
# signatures are ALWAYS rejected on protected branches regardless of any other
# field — humans, CI, and AI never share identities. When agent-signing is on:
#
# [[signer]]
# principal = "agent@ci.example.com"     # a DISTINCT identity, never a human's
# class = "ai"                           # only emitted into allowed_signers when agent-signing is on
# backend = "github-app"                 # tpm | fido2 | kms | github-app | piv | software
# hardware_backed = true                 # self-asserted; see attestation_file to back it up
# # attestation_file = ".sscsb/policy/attestations/agent.bin"  # out-of-band hardware proof
# # expires = "2027-01-01"               # reported by `sscsb verify`; rotate before this
# ssh_public_key = "ssh-ed25519 AAAA... agent@ci.example.com"
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
    // A principal identifies exactly one signer. The same principal appearing
    // twice — especially across classes — is the exact shape that would let an
    // `ai` entry ride in on a `human` principal, so it is a hard parse error
    // (ISC-A2), matched case-insensitively so casing can't smuggle a duplicate.
    //
    // Deduping the PRINCIPAL alone was not sufficient, and the gap was
    // exploitable end to end. Git resolves `%GS` — the principal the
    // protected-branch gate matches on — to the FIRST line in `allowed_signers`
    // whose key verifies the signature. Register ONE key twice, once under a
    // `human` principal and once under an `ai` principal, and an agent's
    // signature resolves to the human and passes the gate. With `agent-signing`
    // off (the default) it is worse: the `ai` line is never emitted at all, so
    // only the human twin exists and the bypass does not even depend on
    // ordering.
    //
    // Key material is an identity too. A key belongs to exactly one signer, or
    // the class gate means nothing.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_keys: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (i, item) in items.iter().enumerate() {
        let t = item
            .as_table()
            .with_context(|| format!("signer #{i} is not a table"))?;
        let principal = t
            .get("principal")
            .and_then(|v| v.as_str())
            .with_context(|| format!("signer #{i} missing `principal`"))?
            .to_string();
        if !seen.insert(principal.to_ascii_lowercase()) {
            anyhow::bail!(
                "signer `{principal}` is listed more than once — each principal must map to a \
                 single signer/class (humans, CI, and AI never share an identity)"
            );
        }
        // Compare the key's TYPE and BASE64 BODY, ignoring the trailing comment:
        // `ssh-ed25519 AAAA… alice@host` and `ssh-ed25519 AAAA… bot@ci` are the
        // same key wearing two names, which is precisely the attack.
        for (field, raw) in [
            (
                "ssh_public_key",
                t.get("ssh_public_key").and_then(|v| v.as_str()),
            ),
            (
                "gpg_fingerprint",
                t.get("gpg_fingerprint").and_then(|v| v.as_str()),
            ),
        ] {
            let Some(raw) = raw else { continue };
            let fingerprint = if field == "ssh_public_key" {
                let mut parts = raw.split_whitespace();
                match (parts.next(), parts.next()) {
                    (Some(kind), Some(body)) => format!("{kind} {body}"),
                    _ => raw.trim().to_string(),
                }
            } else {
                // GPG fingerprints are case- and space-insensitive in practice.
                raw.replace(char::is_whitespace, "").to_ascii_lowercase()
            };
            if let Some(other) = seen_keys.insert(fingerprint, principal.clone()) {
                anyhow::bail!(
                    "signer `{principal}` reuses the {field} already registered to `{other}` — \
                     one key must map to exactly one signer. Sharing key material across \
                     principals defeats the class gate: git resolves a signature to the FIRST \
                     matching principal, so an agent's signature would verify as the human's."
                );
            }
        }
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
            backend: t
                .get("backend")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            attestation_file: t
                .get("attestation_file")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            expires: t
                .get("expires")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }
    Ok(out)
}

/// Build the ssh allowed_signers file content from policy. AI-class signers
/// are NEVER emitted: with agent-signing OFF (the default), an AI key can never
/// produce a "good" signature. This is the historical, agent-unaware behavior —
/// kept byte-identical so enabling nothing changes nothing.
///
/// Every emitted line carries an explicit `namespaces=` grant, and the grant is
/// class-dependent: `git` for all, plus [`crate::local_scan::NAMESPACE`] for
/// `human` signers only — see [`allowed_signers_content_inner`].
pub fn allowed_signers_content(signers: &[Signer]) -> String {
    allowed_signers_content_inner(signers, false)
}

/// Like [`allowed_signers_content`], but emits `ai`-class keys too when
/// `include_agents` is set. Even when an AI key IS emitted (so an agent commit
/// can verify as `%G?=G` on a feature branch), the protected-branch gate in
/// [`check_signing_for_range`] still rejects it on `class`, not on presence in
/// this file — the two invariants are separate (ISC-A4).
pub fn allowed_signers_content_with_agents(signers: &[Signer], include_agents: bool) -> String {
    allowed_signers_content_inner(signers, include_agents)
}

fn allowed_signers_content_inner(signers: &[Signer], include_agents: bool) -> String {
    let mut out =
        String::from("# Generated by sscsb from .sscsb/policy/signers.toml — do not edit.\n");
    for s in signers {
        if s.class == SignerClass::Ai && !include_agents {
            continue;
        }
        if let Some(key) = &s.ssh_public_key {
            // The namespace grant is EXPLICIT for every signer, and it is not
            // the same grant for every class.
            //
            // `git` — what commit signatures are minted in — goes to all three
            // classes: a `ci` key signs release commits, and an emitted `ai`
            // key exists precisely so an agent commit can verify as `%G?=G` on
            // a feature branch (the protected-branch gate still rejects it on
            // class, in `check_signing_for_range`).
            //
            // The local-scan namespace (`crate::local_scan::NAMESPACE`) goes to
            // `human` signers ONLY. A local scan record is a MAINTAINER's
            // attested word about a machine nobody else can inspect; granting
            // it to a `ci` key would let the action lane assert through the
            // weaker lane it already bypasses, and granting it to an `ai` key
            // would contradict this policy's own load-bearing invariant, stated
            // in `crate::signers`: an ai-class signer never signs anything that
            // authorizes. Withholding the namespace makes that structural —
            // `ssh-keygen -Y verify -n sscsb-scan-record` fails against the
            // committed anchor, so the directory refuses the record rather than
            // trusting this file to be read correctly by four programs.
            //
            // Naming the namespaces at all keeps the grant a positive statement
            // rather than the absence of a restriction: dropping `namespaces=`
            // would silently permit every namespace OpenSSH will ever define.
            let namespaces = if s.class == SignerClass::Human {
                format!("git,{}", crate::local_scan::NAMESPACE)
            } else {
                "git".to_string()
            };
            let _ = writeln!(
                out,
                "{} namespaces=\"{}\" {}",
                s.principal,
                namespaces,
                key.trim()
            );
        }
    }
    out
}

/// Regenerate `.sscsb/policy/allowed_signers`. `include_agents` is driven by
/// whether the `agent-signing` control is enabled; with it off, output is the
/// historical human/ci-only file.
pub fn regenerate_allowed_signers(ctx: &Ctx, include_agents: bool) -> Result<()> {
    let policy_dir = ctx.sscsb_dir().join("policy");
    std::fs::create_dir_all(&policy_dir)?;
    let signers = load_signers(&signers_path(ctx))?;
    std::fs::write(
        policy_dir.join("allowed_signers"),
        allowed_signers_content_with_agents(&signers, include_agents),
    )?;
    Ok(())
}

/// Whether the (default-off) `agent-signing` control is enabled.
pub fn agent_signing_enabled(cfg: &Config) -> bool {
    cfg.control_enabled_or_default("agent-signing")
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
///
/// The blob is carried as BYTES end to end. `CmdOutput.stdout` is
/// `from_utf8_lossy`, so routing a staged PNG, zip, or any other non-UTF-8 file
/// through it would rewrite every invalid sequence as U+FFFD before the
/// scanners ever saw it: the scan would read the wrong bytes, and anything
/// downstream reading this directory would too.
pub fn stage_to_tempdir(ctx: &Ctx) -> Result<(tempfile::TempDir, Vec<String>)> {
    let dir = tempfile::tempdir()?;
    let files = staged_paths(ctx)?;
    let submodules = staged_submodules(ctx)?;
    for file in &files {
        // `--` guards against a path that begins with a dash, and the raw path
        // is passed as a single argument (never shell-interpolated).
        let out = exec::git_bytes(&["show", &format!(":{file}")], &ctx.root)?;
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
        std::fs::write(&dest, &out.stdout)?;
    }
    Ok((dir, files))
}

pub fn hook_pre_commit(ctx: &Ctx) -> Result<i32> {
    let Some(cfg) = ctx.config.as_ref() else {
        eprintln!("sscsb: no config — run `sscsb init` (allowing commit)");
        return Ok(0);
    };
    let mut blocked = false;

    if cfg.control_enabled_or_default("secrets") {
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

    if cfg.control_enabled_or_default("sast")
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
                // This arm used to degrade open unconditionally, on the grounds
                // that pre-commit SAST is opt-in and advisory. Being opt-in is
                // the argument AGAINST that: a user who turned this gate on had
                // no way to make it hold — `fail_open = false` did not apply to
                // it, so a missing engine or a mistyped `engine =` name silently
                // removed the gate they asked for. `fail_open` is documented as
                // the single opt-out for every hook ("would let hooks pass when
                // scanners are missing"), and it governs this arm too.
                if cfg.fail_open() {
                    eprintln!(
                        "sscsb: WARNING (fail_open=true): sast pre-commit could not run: {err:#}"
                    );
                } else {
                    blocked = true;
                    eprintln!(
                        "sscsb: BLOCKED (fail-closed): sast pre-commit could not run: {err:#}"
                    );
                    eprintln!(
                        "sscsb: install the engine, fix `[controls.sast] engine`, or disable the \
                         control — `sscsb verify` names which."
                    );
                }
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

/// The name-proximity annotation the commit gate adds ON TOP of
/// [`crate::deps::NewDep::explain`], for a new dependency it is already
/// blocking.
///
/// Extracted from the loop and RETURNED rather than printed because two
/// independent conditions suppress it, and neither was testable while it lived
/// inline behind an `eprintln!`:
///
/// 1. **Correctness, unconditional.** A `path`/`git`/`url` dependency named one
///    edit from `serde` fetches nothing from crates.io, so the heuristic is
///    asking about a name that does not resolve the code. `explain()` has
///    already said the true thing — that its source needs review. No
///    configuration re-enables this; it is not a check the user elected to run.
/// 2. **Policy, configurable.** `typosquat_check = false` switches the heuristic
///    off. The commit gate is the THIRD place it runs, after `deps check` and
///    approval, and a toggle reaching only the advisory two is the exact defect
///    the key was fixed to close: the user turns it off because their dependency
///    is legitimately one edit from a popular name, and it still blocks their
///    commit.
///
/// Suppressing the annotation never lets the PACKAGE through: `explain()` is
/// pushed unconditionally by the caller and still blocks the commit. Only the
/// proximity note is withheld.
fn typosquat_annotation(
    d: &crate::deps::NewDep,
    checks: crate::deps::TrustChecks,
) -> Option<String> {
    if d.source
        .as_ref()
        .is_some_and(|s| !s.is_registry_resolvable())
    {
        return None;
    }
    if !checks.typosquat {
        return None;
    }
    let (eco_label, name) = d.qualified.split_once(':')?;
    let eco = crate::deps::Ecosystem::from_label(eco_label)?;
    let shadowed = crate::deps::typosquat_suspect(eco, name)?;
    Some(format!(
        "`{}` is one edit from popular package `{shadowed}` — likely \
         typosquat/slopsquat; verify before approving",
        d.qualified
    ))
}

pub fn hook_commit_msg(ctx: &Ctx, msg_file: &Path) -> Result<i32> {
    let Some(cfg) = ctx.config.as_ref() else {
        return Ok(0);
    };
    let message = std::fs::read_to_string(msg_file)
        .with_context(|| format!("reading commit message {}", msg_file.display()))?;
    let trailers = parse_trailers(&message);
    let mut problems: Vec<String> = Vec::new();

    if cfg.control_enabled_or_default("ai-trailers") {
        problems.extend(validate_ai_trailers(&trailers));
    }

    let ai_assisted = trailers.get("AI-Assisted").map(String::as_str) == Some("true");

    if ai_assisted && cfg.control_enabled_or_default("ai-dep-gate") {
        // `staged_paths`, not a second `git diff --cached --name-only` parsed by
        // line. `core.quotePath` is on by default, so git C-quotes any path with
        // a non-ASCII byte, a control character, or a quote: `caf\u{e9}/Cargo.toml`
        // arrives as `"caf\\303\\251/Cargo.toml"`, whose basename gains a trailing
        // quote and stops matching `is_dependency_manifest`. A dependency manifest
        // under any such directory therefore walked straight past this gate on an
        // AI-assisted commit — reproduced end to end: the same commit message with
        // `plain/Cargo.toml` staged BLOCKED at exit 1, and with `caf\u{e9}/Cargo.toml`
        // staged exited 0. The hardened NUL-delimited enumeration was already in
        // this file for exactly this reason; this arm simply never adopted it.
        let staged = staged_paths(ctx)?;
        let manifests: Vec<&String> = staged
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
                manifests
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // Same enumeration, same reason: a quoted path also loses its `.sh`
        // suffix to the trailing quote, so the shell-review arm had the identical
        // hole.
        let shellish: Vec<&String> = staged
            .iter()
            .filter(|f| f.ends_with(".sh") || f.ends_with(".bash") || f.ends_with(".zsh"))
            .collect();
        if !shellish.is_empty()
            && trailers.get("AI-Command-Review").map(String::as_str) != Some("approved")
        {
            problems.push(format!(
                "AI-assisted commit adds/modifies shell scripts ({}) — a human must review \
                 and add trailer `AI-Command-Review: approved`",
                shellish
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    if cfg.control_enabled_or_default("package-trust") {
        // The commit gate is the THIRD place the typosquat heuristic runs, after
        // `deps check` and approval. A toggle that reaches only the advisory two
        // is the defect it was written to fix: the user switched the heuristic
        // off because their dependency is legitimately one edit from a popular
        // name, and it still blocks their commit — the config contradicting
        // itself at the one gate that actually stops work.
        //
        // The package itself is NOT let through by this: `d.explain()` above
        // still reports it as a new unapproved dependency and still blocks. Only
        // the name-proximity annotation is suppressed.
        let checks = crate::deps::TrustChecks::from_config(Some(cfg));
        match crate::deps::new_unapproved_deps(ctx) {
            Ok(new_deps) if !new_deps.is_empty() => {
                for d in &new_deps {
                    problems.push(d.explain());
                    problems.extend(typosquat_annotation(d, checks));
                }
            }
            Ok(_) => {}
            // The gate could not evaluate — an unreadable or unparseable
            // `.sscsb/policy/packages.toml` is the common case, and a one-line
            // append to that file must not be a way to switch the new-package
            // gate off. Deleting the baseline already fails CLOSED (every new
            // package reads as unapproved); corrupting it has to fail closed
            // too, or that asymmetry IS the bypass. `fail_open = true` stays
            // the single explicit opt-out — the same shape the secret-scan and
            // SAST arms of these hooks already use.
            Err(err) => {
                if cfg.fail_open() {
                    eprintln!(
                        "sscsb: WARNING (fail_open=true): package-trust check could not run: {err:#}"
                    );
                } else {
                    problems.push(format!(
                        "package-trust check could not run (fail-closed): {err:#}"
                    ));
                }
            }
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

        if is_protected && cfg.control_enabled_or_default("commit-signing") {
            problems.extend(check_signing_for_range(ctx, cfg, u, branch)?);
        }

        if cfg.control_enabled_or_default("secrets")
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
    // These shas arrive on pre-push stdin. `git rev-list` inherits git's diff
    // options — `--output=<file>` included — so an option-shaped sha would
    // write a file instead of listing commits, and this gate would then see an
    // EMPTY commit list and wave the push through. Fail closed on anything that
    // is not a bare object name.
    //
    // `--end-of-options` is not usable here: `--not --remotes` must follow the
    // revision, and `--end-of-options` would swallow them.
    for sha in [&u.local_sha, &u.remote_sha] {
        anyhow::ensure!(
            sha.starts_with(ZERO_SHA_PREFIX) || exec::is_object_name(sha),
            "refusing to run git with {sha:?}, which is not a git object name"
        );
    }
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
    // When agent-signing is enabled, AI keys are emitted too — but the
    // class check below still rejects them on this protected branch.
    regenerate_allowed_signers(ctx, agent_signing_enabled(cfg))?;

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
                            .is_some_and(|fp| !fp.is_empty() && key_id.eq_ignore_ascii_case(fp))
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

        // Human-signed merge + VALIDATED review evidence when AI involvement
        // is declared. An earlier gate passed on the mere presence of a
        // `Reviewed-by`/`Review-evidence` trailer KEY — no value validation,
        // no identity resolution, no reviewer≠author check — while its
        // trigger is a trailer the agent writes about itself. An agent could
        // author the work, author the merge, and vouch for its own review in
        // one commit message.
        let is_merge = parents.split_whitespace().count() > 1;
        if is_merge
            && cfg
                .control_opt_bool("commit-signing", "require_review_evidence_for_ai_merges")
                .unwrap_or(true)
        {
            let trailers = parse_trailers(body);
            // Fail closed: a gate that cannot read the merged range must not
            // assume the range is AI-free.
            let ai_declared = trailers.get("AI-Assisted").map(String::as_str) == Some("true")
                || range_declares_ai(ctx, &sha).unwrap_or(true);
            if ai_declared {
                match range_author_emails(ctx, &sha) {
                    Ok(range_authors) => problems.extend(
                        review_evidence_problems(&trailers, &signers, &range_authors)
                            .into_iter()
                            .map(|p| format!("{short}: {p}")),
                    ),
                    Err(err) => problems.push(format!(
                        "{short}: could not enumerate merged-range authors to validate review \
                         evidence: {err:#}"
                    )),
                }
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

/// Author emails of the work a merge brings in (`merge^1..merge` with the
/// merge commit itself excluded) — the people whose commits the review
/// evidence is vouching for.
///
/// The exclusion is load-bearing: git's `A..B` range always contains `B`
/// itself, so without it the merge commit's own author — the human performing
/// the merge, whose act of reviewing is precisely the intended flow — would
/// be counted as an author of the reviewed work, and every legitimate
/// agent-authors/human-reviews-and-merges push would be refused as
/// self-review. (Caught by adversarial review with an empirical POC before
/// this ever shipped.)
fn range_author_emails(ctx: &Ctx, merge_sha: &str) -> Result<BTreeSet<String>> {
    let out = exec::git(
        &[
            "log",
            "--format=%H %ae",
            &format!("{merge_sha}^1..{merge_sha}"),
        ],
        &ctx.root,
    )?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let (sha, email) = l.trim().split_once(' ')?;
            (sha != merge_sha && !email.is_empty()).then(|| email.to_string())
        })
        .collect())
}

/// Validate the review-evidence trailers on a merge with declared AI
/// involvement. Returns problems (empty = OK).
///
/// What this can and cannot prove, stated honestly: a pre-push hook reads a
/// commit message, so it cannot prove a review *happened* — the forge-side
/// required-review rule is the enforcement for that. What it CAN refuse
/// deterministically is a vacuous attestation: a bare trailer key with no
/// identity, a reviewer nobody approved, an AI-class identity "reviewing" AI
/// work, and an author vouching for their own commits. The human merge author
/// reviewing an agent's branch commits is the intended flow and passes —
/// the merged-range authors are the agent, not the human.
pub fn review_evidence_problems(
    trailers: &BTreeMap<String, String>,
    signers: &[Signer],
    merged_range_author_emails: &BTreeSet<String>,
) -> Vec<String> {
    let mut problems = Vec::new();

    let reviewed_by = trailers
        .get("Reviewed-by")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if reviewed_by.is_empty() {
        problems.push(
            "merge with declared AI involvement lacks a `Reviewed-by: Name <email>` trailer \
             naming a policy-approved human reviewer (a `Review-evidence:` URL alone names \
             no reviewer)"
                .to_string(),
        );
        return problems;
    }

    let Some(email) = trailer_identity_email(reviewed_by) else {
        problems.push(format!(
            "`Reviewed-by: {reviewed_by}` carries no identity — expected `Name <email>` (or a \
             bare email) matching a principal in .sscsb/policy/signers.toml"
        ));
        return problems;
    };

    // Case-insensitive, unlike the primary signature-principal match above:
    // that one compares two strings with the same provenance (git's %GS output
    // is read back from the allowed_signers file this tool generates), so
    // exact equality is guaranteed-consistent there. This one compares a
    // HUMAN-TYPED trailer against policy, where case drift is expected and
    // leniency on ASCII case grants nothing.
    match signers
        .iter()
        .find(|s| s.principal.eq_ignore_ascii_case(&email))
    {
        None => problems.push(format!(
            "reviewer `{email}` is not in the approved-signers policy — review evidence must \
             name a `class = \"human\"` principal from .sscsb/policy/signers.toml"
        )),
        Some(s) if s.class != SignerClass::Human => problems.push(format!(
            "reviewer `{email}` has class {:?} — only a human-class signer can provide review \
             evidence for AI-assisted work (an agent cannot vouch for its own review)",
            s.class
        )),
        Some(_)
            if merged_range_author_emails
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&email)) =>
        {
            problems.push(format!(
                "reviewer `{email}` authored commit(s) in the merged range — review evidence \
                 must come from someone other than the author of the work (agent-authored work \
                 under the agent's own identity may be reviewed by the human merging it)"
            ));
        }
        Some(_) => {}
    }

    if let Some(evidence) = trailers.get("Review-evidence") {
        let evidence = evidence.trim();
        let looks_like_url = evidence.contains("://");
        let looks_like_sha = evidence.len() >= 7 && evidence.chars().all(|c| c.is_ascii_hexdigit());
        if !(looks_like_url || looks_like_sha) {
            problems.push(format!(
                "`Review-evidence: {evidence}` is neither a URL nor a commit sha — point it at \
                 the review artifact (PR URL, review comment, or reviewed commit)"
            ));
        }
    }

    problems
}

/// The email inside `Name <email>`, or the value itself when it is a bare
/// address. `None` when no plausible address is present — a trailer with no
/// identity is exactly the vacuous attestation the gate exists to refuse.
fn trailer_identity_email(value: &str) -> Option<String> {
    let candidate = match (value.find('<'), value.rfind('>')) {
        (Some(open), Some(close)) if close > open => &value[open + 1..close],
        _ => value,
    };
    let candidate = candidate.trim();
    (!candidate.is_empty() && candidate.contains('@') && !candidate.contains(char::is_whitespace))
        .then(|| candidate.to_string())
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

/// What sscsb can actually prove about the installed hook shims.
///
/// Presence is not enforcement. Three files named `pre-commit`, `commit-msg`
/// and `pre-push` can exist, be executable, and be pointed at by
/// `core.hooksPath` while containing nothing but `exit 0` — in which case
/// every control that says "enforced by the hook" is enforcing nothing. The
/// shims are generated by [`shim_script`], so their correct content is known
/// exactly; that is the evidence this check uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookIntegrity {
    /// `Pass` only when every shim is byte-identical to the generated one.
    pub outcome: Outcome,
    pub messages: Vec<String>,
}

impl HookIntegrity {
    /// `Some(result)` when the hooks provably enforce nothing and the calling
    /// verifier must stop; `None` when it should carry on and fold
    /// [`Self::outcome`] into its own.
    pub fn blocking(&self, control: &'static str) -> Option<VerifyResult> {
        (self.outcome == Outcome::Fail)
            .then(|| VerifyResult::new(control, Outcome::Fail, self.messages.clone()))
    }
}

/// A CRLF checkout of a committed shim (`.sscsb/hooks/` is versioned) is the
/// same script; comparing normalised text keeps the identity check about the
/// shim's content rather than about the user's `core.autocrlf` setting.
fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    // Git for Windows runs hooks through its own sh; there is no exec bit to
    // read, so there is nothing to assert here (see `make_executable`).
    true
}

/// Verify that git is pointed at sscsb's hooks AND that each shim still
/// delegates to the policy engine.
///
/// Three outcomes, because there are three genuinely different states:
///
/// * `Pass` — every shim is byte-identical to what `sscsb init` writes, so
///   sscsb knows exactly what runs.
/// * `Degraded` — a shim was edited but still names `sscsb hook <event>`.
///   sscsb cannot prove a hand-edited shell script still reaches that line, so
///   it refuses to call the control verified. `sscsb init` restores it.
/// * `Fail` — `core.hooksPath` is elsewhere, a shim is missing, a shim is not
///   executable (git silently ignores those), or a shim no longer mentions the
///   delegation at all. The control is provably not enforced.
pub fn hook_integrity(ctx: &Ctx) -> HookIntegrity {
    let hooks_path = exec::git(&["config", "core.hooksPath"], &ctx.root).unwrap_or_default();
    if hooks_path != ".sscsb/hooks" {
        let seen = if hooks_path.is_empty() {
            "unset".to_string()
        } else {
            format!("`{hooks_path}`")
        };
        return HookIntegrity {
            outcome: Outcome::Fail,
            messages: vec![format!(
                "core.hooksPath is {seen}, not `.sscsb/hooks` — git is not running sscsb's hooks; \
                 run `sscsb init`"
            )],
        };
    }

    let dir = ctx.sscsb_dir().join("hooks");
    let mut broken = Vec::new();
    let mut drifted = Vec::new();
    for event in HOOK_EVENTS {
        let path = dir.join(event);
        let Ok(found) = std::fs::read_to_string(&path) else {
            broken.push(format!(
                ".sscsb/hooks/{event} is missing or unreadable — nothing enforces this event"
            ));
            continue;
        };
        if !is_executable(&path) {
            broken.push(format!(
                ".sscsb/hooks/{event} is not executable — git silently SKIPS non-executable \
                 hooks, so the control never runs"
            ));
            continue;
        }
        if normalize_newlines(&found) == normalize_newlines(&shim_script(event)) {
            continue;
        }
        if found.contains(&format!("sscsb hook {event}")) {
            drifted.push(format!(
                ".sscsb/hooks/{event} differs from the shim `sscsb init` generates — it still \
                 names `sscsb hook {event}`, but sscsb cannot prove an edited shell script still \
                 reaches it; re-run `sscsb init` to restore the generated shim"
            ));
        } else {
            broken.push(format!(
                ".sscsb/hooks/{event} never invokes `sscsb hook {event}` — the shim has been \
                 replaced by one that enforces NOTHING; re-run `sscsb init`"
            ));
        }
    }

    if !broken.is_empty() {
        broken.extend(drifted);
        return HookIntegrity {
            outcome: Outcome::Fail,
            messages: broken,
        };
    }
    if !drifted.is_empty() {
        return HookIntegrity {
            outcome: Outcome::Degraded,
            messages: drifted,
        };
    }
    HookIntegrity {
        outcome: Outcome::Pass,
        messages: vec![
            "pre-commit + commit-msg + pre-push shims installed, executable, and unmodified \
             (core.hooksPath=.sscsb/hooks)"
                .into(),
        ],
    }
}

pub fn verify_secrets_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = Vec::new();
    let hooks = hook_integrity(ctx);
    if let Some(blocked) = hooks.blocking("secrets") {
        return blocked;
    }
    let mut outcome = Outcome::Pass.weakest(hooks.outcome);
    messages.extend(hooks.messages);
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
    let hooks = hook_integrity(ctx);
    if let Some(blocked) = hooks.blocking("commit-signing") {
        return blocked;
    }
    let mut outcome = Outcome::Pass.weakest(hooks.outcome);
    messages.extend(hooks.messages);
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
    let hooks = hook_integrity(ctx);
    let mut messages = Vec::new();
    if hooks.outcome == Outcome::Pass {
        messages.push("enforced by the commit-msg hook".into());
    }
    messages.extend(hooks.messages);
    VerifyResult::new(control, hooks.outcome, messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `hook_pre_commit` and `hook_pre_push` shell out to whatever scanners are
    // naturally on PATH — trufflehog, gitleaks, opengrep. PATH is
    // process-global and the harness runs the whole crate's tests in ONE
    // multi-threaded process, so these calls must not run while a sibling test
    // is masking or shimming PATH: the scan asks `tools::is_available(x)` and
    // then spawns `x`, and a PATH that changes in between turns a clean run
    // into "failed to spawn `trufflehog`" and a passing assertion into a
    // failing one. Observed intermittently across full-suite runs before these
    // wrappers existed. This is the discipline `sast::tests` already documents
    // for every test that depends on a tool-detection outcome, applied to the
    // hook lane that had been missing it.

    fn pre_commit(ctx: &Ctx) -> i32 {
        crate::sast::tests::serialized(|| hook_pre_commit(ctx).unwrap())
    }

    fn pre_push(ctx: &Ctx, stdin: &str) -> i32 {
        crate::sast::tests::serialized(|| hook_pre_push(ctx, "origin", stdin).unwrap())
    }

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
        assert!(findings.iter().any(|f| f.contains("Github")
            && f.contains("secrets.env")
            && f.contains("verified: true")));
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

    /// CRC-32/IEEE, so the test can build (and then validate) a REAL archive
    /// rather than trust a hand-waved one. Bit-reversed polynomial 0xEDB88320.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A real ZIP archive holding one STORED (uncompressed) entry, assembled
    /// here at runtime — no binary fixture lives in this tree.
    fn zip_with_stored_entry(name: &str, payload: &[u8]) -> Vec<u8> {
        let crc = crc32(payload);
        let size = payload.len() as u32;
        let n = name.len() as u16;
        let mut z = Vec::new();
        // Local file header.
        z.extend(b"PK\x03\x04");
        z.extend(20u16.to_le_bytes()); // version needed
        z.extend(0u16.to_le_bytes()); // flags
        z.extend(0u16.to_le_bytes()); // method: stored
        z.extend(0u16.to_le_bytes()); // mod time
        z.extend(0u16.to_le_bytes()); // mod date
        z.extend(crc.to_le_bytes());
        z.extend(size.to_le_bytes()); // compressed size
        z.extend(size.to_le_bytes()); // uncompressed size
        z.extend(n.to_le_bytes());
        z.extend(0u16.to_le_bytes()); // extra len
        z.extend(name.as_bytes());
        z.extend(payload);
        // Central directory.
        let cd_offset = z.len() as u32;
        z.extend(b"PK\x01\x02");
        z.extend(20u16.to_le_bytes()); // version made by
        z.extend(20u16.to_le_bytes()); // version needed
        z.extend(0u16.to_le_bytes()); // flags
        z.extend(0u16.to_le_bytes()); // method
        z.extend(0u16.to_le_bytes()); // mod time
        z.extend(0u16.to_le_bytes()); // mod date
        z.extend(crc.to_le_bytes());
        z.extend(size.to_le_bytes());
        z.extend(size.to_le_bytes());
        z.extend(n.to_le_bytes());
        z.extend(0u16.to_le_bytes()); // extra len
        z.extend(0u16.to_le_bytes()); // comment len
        z.extend(0u16.to_le_bytes()); // disk number start
        z.extend(0u16.to_le_bytes()); // internal attrs
        z.extend(0u32.to_le_bytes()); // external attrs
        z.extend(0u32.to_le_bytes()); // local header offset
        z.extend(name.as_bytes());
        let cd_size = z.len() as u32 - cd_offset;
        // End of central directory.
        z.extend(b"PK\x05\x06");
        z.extend(0u16.to_le_bytes()); // this disk
        z.extend(0u16.to_le_bytes()); // disk with cd
        z.extend(1u16.to_le_bytes()); // entries this disk
        z.extend(1u16.to_le_bytes()); // entries total
        z.extend(cd_size.to_le_bytes());
        z.extend(cd_offset.to_le_bytes());
        z.extend(0u16.to_le_bytes()); // comment len
        z
    }

    /// M2: `stage_to_tempdir` materialised `git show`'s stdout after it had
    /// been through `String::from_utf8_lossy`, so every staged non-UTF-8 file
    /// was rewritten — each invalid byte becoming U+FFFD (`EF BF BD`), which
    /// changes the content AND the length. The scanners then read the wrong
    /// bytes, and so does anything else that opens this directory. Reported
    /// symptom: a staged, valid zip comes out "zipfile corrupt".
    #[test]
    fn a_staged_binary_file_is_materialised_byte_for_byte() {
        let (_d, ctx) = tmp_repo();

        // Every one of the 256 byte values, behind a real PNG signature: the
        // maximal non-UTF-8 stress, built at runtime.
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend((0u8..=255).rev());
        assert!(
            String::from_utf8(png.clone()).is_err(),
            "fixture must actually be non-UTF-8, or it proves nothing"
        );
        let zip = zip_with_stored_entry("payload.bin", &(0u8..=255).collect::<Vec<u8>>());

        std::fs::write(ctx.root.join("image.png"), &png).unwrap();
        std::fs::write(ctx.root.join("archive.zip"), &zip).unwrap();
        crate::exec::git(&["add", "image.png", "archive.zip"], &ctx.root).unwrap();

        let (dir, files) = stage_to_tempdir(&ctx).unwrap();
        assert_eq!(files.len(), 2, "{files:?}");

        let got_png = std::fs::read(dir.path().join("image.png")).unwrap();
        assert_eq!(
            got_png.len(),
            png.len(),
            "lossy decoding also RESIZES the file: {} bytes staged, {} materialised",
            png.len(),
            got_png.len()
        );
        assert_eq!(got_png, png, "staged PNG must be materialised verbatim");

        let got_zip = std::fs::read(dir.path().join("archive.zip")).unwrap();
        assert_eq!(got_zip, zip, "staged zip must be materialised verbatim");

        // …and the materialised archive is still a VALID zip: read its own
        // stored CRC back and check it against the payload that survived.
        assert_eq!(&got_zip[0..4], b"PK\x03\x04", "local file header signature");
        let stored_crc = u32::from_le_bytes(got_zip[14..18].try_into().unwrap());
        let name_len = u16::from_le_bytes(got_zip[26..28].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(got_zip[22..26].try_into().unwrap()) as usize;
        let start = 30 + name_len;
        let payload = &got_zip[start..start + size];
        assert_eq!(
            crc32(payload),
            stored_crc,
            "materialised zip fails its own CRC — this is the `zipfile corrupt` symptom"
        );
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
        g(&[
            "merge",
            "--no-ff",
            "--no-verify",
            "-m",
            "merge feature",
            "feature",
        ]);
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
    fn hook_integrity_fails_before_init_and_passes_after() {
        let (_d, ctx) = bare_repo();
        let before = hook_integrity(&ctx);
        assert_eq!(before.outcome, Outcome::Fail);
        assert!(
            before.messages[0].contains("core.hooksPath is unset"),
            "{:?}",
            before.messages
        );
        install_hooks(&ctx).unwrap();
        let after = hook_integrity(&ctx);
        assert_eq!(after.outcome, Outcome::Pass, "{:?}", after.messages);
        assert!(after.messages[0].contains("unmodified"));
    }

    /// Replace the installed shims with `exit 0` — the file is still there,
    /// still executable, still pointed at by `core.hooksPath`, and enforces
    /// nothing. Presence-only checking reported this as installed, so every
    /// control that says "enforced by the hook" reported PASS on a repo where
    /// a planted AWS key committed cleanly. (H8)
    #[test]
    fn neutered_shims_fail_integrity_instead_of_passing() {
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        for event in HOOK_EVENTS {
            let path = ctx.sscsb_dir().join("hooks").join(event);
            std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            make_executable(&path).unwrap();
        }
        let state = hook_integrity(&ctx);
        assert_eq!(
            state.outcome,
            Outcome::Fail,
            "a shim that never invokes sscsb enforces nothing: {:?}",
            state.messages
        );
        assert_eq!(state.messages.len(), HOOK_EVENTS.len());
        for event in HOOK_EVENTS {
            assert!(
                state
                    .messages
                    .iter()
                    .any(|m| m.contains(&format!(".sscsb/hooks/{event} never invokes"))),
                "{event} must be named as neutered: {:?}",
                state.messages
            );
        }
    }

    /// A shim a human edited but that still calls the policy engine is NOT
    /// proof of enforcement (the delegation may sit after an early exit) and
    /// NOT proof of breakage either. sscsb refuses to claim either: it
    /// degrades, which `verify --strict` still treats as a failure.
    #[test]
    fn edited_but_delegating_shim_degrades_rather_than_passing() {
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        let path = ctx.sscsb_dir().join("hooks").join("pre-commit");
        let edited = format!(
            "{}\n# locally added trailing note\n",
            shim_script("pre-commit")
        );
        std::fs::write(&path, edited).unwrap();
        let state = hook_integrity(&ctx);
        assert_eq!(state.outcome, Outcome::Degraded, "{:?}", state.messages);
        assert_eq!(state.messages.len(), 1);
        assert!(state.messages[0].contains(".sscsb/hooks/pre-commit differs from the shim"));
    }

    /// A CRLF checkout of a committed shim is the same script — the identity
    /// check must be about content, not about `core.autocrlf`.
    #[test]
    fn crlf_line_endings_do_not_count_as_drift() {
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        let path = ctx.sscsb_dir().join("hooks").join("pre-push");
        let crlf = shim_script("pre-push").replace('\n', "\r\n");
        std::fs::write(&path, crlf).unwrap();
        assert_eq!(hook_integrity(&ctx).outcome, Outcome::Pass);
    }

    #[test]
    fn a_missing_shim_fails_integrity() {
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        std::fs::remove_file(ctx.sscsb_dir().join("hooks").join("commit-msg")).unwrap();
        let state = hook_integrity(&ctx);
        assert_eq!(state.outcome, Outcome::Fail);
        assert!(state.messages[0].contains(".sscsb/hooks/commit-msg is missing or unreadable"));
    }

    /// git SKIPS non-executable hooks with only a hint on stderr, so a shim
    /// that lost its exec bit is exactly as inert as a deleted one.
    #[cfg(unix)]
    #[test]
    fn a_non_executable_shim_fails_integrity() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        let path = ctx.sscsb_dir().join("hooks").join("pre-commit");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let state = hook_integrity(&ctx);
        assert_eq!(state.outcome, Outcome::Fail);
        assert!(state.messages[0].contains("is not executable"));
    }

    /// Pointing `core.hooksPath` somewhere else disables sscsb's hooks wholesale.
    #[test]
    fn a_redirected_hookspath_fails_integrity_and_names_the_path() {
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        exec::git(&["config", "core.hooksPath", ".git/hooks"], &ctx.root).unwrap();
        let state = hook_integrity(&ctx);
        assert_eq!(state.outcome, Outcome::Fail);
        assert!(state.messages[0].contains("core.hooksPath is `.git/hooks`"));
    }

    /// A repo with one neutered shim AND one merely edited shim must report the
    /// hard failure, not average down to a degrade.
    #[test]
    fn broken_and_drifted_shims_together_report_fail_and_list_both() {
        let (_d, ctx) = bare_repo();
        install_hooks(&ctx).unwrap();
        let neutered = ctx.sscsb_dir().join("hooks").join("pre-commit");
        std::fs::write(&neutered, "#!/bin/sh\nexit 0\n").unwrap();
        make_executable(&neutered).unwrap();
        let drifted = ctx.sscsb_dir().join("hooks").join("pre-push");
        std::fs::write(&drifted, format!("{}\n# note\n", shim_script("pre-push"))).unwrap();
        let state = hook_integrity(&ctx);
        assert_eq!(state.outcome, Outcome::Fail);
        assert!(state.messages.iter().any(|m| m.contains("never invokes")));
        assert!(state
            .messages
            .iter()
            .any(|m| m.contains("differs from the shim")));
    }

    /// `blocking` is the guard every hook-gated verifier uses: it must stop the
    /// verifier only on a hard failure, never on drift.
    #[test]
    fn blocking_stops_only_on_fail() {
        let fail = HookIntegrity {
            outcome: Outcome::Fail,
            messages: vec!["boom".into()],
        };
        let blocked = fail.blocking("secrets").expect("fail must block");
        assert_eq!(blocked.outcome, Outcome::Fail);
        assert_eq!(blocked.messages, vec!["boom".to_string()]);
        for ok in [Outcome::Pass, Outcome::Degraded] {
            let state = HookIntegrity {
                outcome: ok,
                messages: vec![],
            };
            assert!(state.blocking("secrets").is_none());
        }
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

    /// One key, two principals, two classes — the shape that defeated the
    /// protected-branch class gate entirely.
    ///
    /// Git resolves `%GS` to the FIRST principal in `allowed_signers` whose key
    /// verifies the signature, so an agent signing with a key also registered
    /// under a `human` principal resolved to the human and passed. With
    /// `agent-signing` off (the default) the `ai` line is never emitted at all,
    /// so only the human twin existed and the bypass did not even depend on
    /// ordering. Reproduced end to end against the real binary before this
    /// guard: the push succeeded and `git log -1 --format='%G? %GS'` printed
    /// `G human@example.com` for a commit authored and committed by the agent.
    #[test]
    fn parse_signers_rejects_one_key_registered_under_two_principals() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISHARED";
        let toml = format!(
            "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\n\
             ssh_public_key = \"{key} human@example.com\"\n\n\
             [[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\n\
             ssh_public_key = \"{key} agent@ci.example.com\"\n"
        );
        let err = parse_signers(&toml)
            .expect_err("one key under two principals must be a hard parse error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reuses the ssh_public_key"),
            "error must name the reuse, got: {msg}"
        );
        assert!(
            msg.contains("human@example.com"),
            "error must name the principal already holding the key, got: {msg}"
        );
    }

    /// The trailing comment is not part of the key. Two entries differing only
    /// there are the same key wearing two names, which is the disguised form of
    /// the same attack.
    #[test]
    fn parse_signers_compares_key_material_not_the_trailing_comment() {
        let body = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDISGUISED";
        let toml = format!(
            "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\n\
             ssh_public_key = \"{body} laptop\"\n\n\
             [[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\n\
             ssh_public_key = \"{body} totally-different-comment\"\n"
        );
        assert!(
            parse_signers(&toml).is_err(),
            "a differing comment must not disguise shared key material"
        );

        // Same guard for GPG, which is case- and whitespace-insensitive.
        let gpg = "[[signer]]\nprincipal = \"a@example.com\"\nclass = \"human\"\n\
                   gpg_fingerprint = \"ABCD 1234 ABCD 1234\"\n\n\
                   [[signer]]\nprincipal = \"b@example.com\"\nclass = \"ai\"\n\
                   gpg_fingerprint = \"abcd1234abcd1234\"\n";
        assert!(
            parse_signers(gpg).is_err(),
            "GPG fingerprints must compare case- and space-insensitively"
        );
    }

    /// The guard must not break the legitimate configuration it protects: a
    /// human and an agent with genuinely distinct keys is the intended setup.
    #[test]
    fn parse_signers_admits_distinct_keys_across_classes() {
        let toml = "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\n\
                    ssh_public_key = \"ssh-ed25519 AAAAHUMANKEY human@example.com\"\n\n\
                    [[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\n\
                    ssh_public_key = \"ssh-ed25519 AAAAAGENTKEY agent@ci.example.com\"\n";
        let signers = parse_signers(toml).expect("distinct keys are the intended configuration");
        assert_eq!(signers.len(), 2);
        assert_eq!(signers[0].class, SignerClass::Human);
        assert_eq!(signers[1].class, SignerClass::Ai);

        // A signer with no key material at all must not collide with another.
        let keyless = "[[signer]]\nprincipal = \"a@example.com\"\nclass = \"human\"\n\n\
                       [[signer]]\nprincipal = \"b@example.com\"\nclass = \"ci\"\n";
        assert_eq!(parse_signers(keyless).unwrap().len(), 2);
    }

    #[test]
    fn parse_signers_round_trips_backend_attestation_and_expiry_fields() {
        let toml = "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"github-app\"\nhardware_backed = true\nattestation_file = \".sscsb/policy/attestations/agent.bin\"\nexpires = \"2027-01-01\"\nssh_public_key = \"ssh-ed25519 AAAAAGENT agent@ci.example.com\"\n";
        let signers = parse_signers(toml).unwrap();
        assert_eq!(signers.len(), 1);
        let s = &signers[0];
        assert_eq!(s.class, SignerClass::Ai);
        assert_eq!(s.backend.as_deref(), Some("github-app"));
        assert!(s.hardware_backed);
        assert_eq!(
            s.attestation_file.as_deref(),
            Some(".sscsb/policy/attestations/agent.bin")
        );
        assert_eq!(s.expires.as_deref(), Some("2027-01-01"));
        // Absent optional fields stay None on a minimal human entry.
        let minimal = parse_signers(
            "[[signer]]\nprincipal = \"h@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAAH h@example.com\"\n",
        )
        .unwrap();
        assert_eq!(minimal[0].backend, None);
        assert_eq!(minimal[0].attestation_file, None);
        assert_eq!(minimal[0].expires, None);
    }

    #[test]
    fn allowed_signers_is_byte_identical_with_agents_off_and_emits_ai_only_when_on() {
        // A human + an ai signer, both with keys.
        let toml = "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAAHUMAN human@example.com\"\n\n[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"github-app\"\nssh_public_key = \"ssh-ed25519 AAAAAGENT agent@ci.example.com\"\n";
        let signers = parse_signers(toml).unwrap();

        // Default (agent-signing OFF) output: ai key NEVER appears, and it is
        // byte-identical to the historical agent-unaware generator.
        let off = allowed_signers_content(&signers);
        assert!(off.contains("human@example.com"));
        assert!(
            !off.contains("agent@ci.example.com"),
            "ai key must not leak into the default allowed_signers file"
        );
        assert_eq!(
            off,
            allowed_signers_content_with_agents(&signers, false),
            "the public helper must equal the explicit include_agents=false form"
        );

        // agent-signing ON: the ai key is emitted so an agent commit can verify
        // as %G?=G — the human line is unchanged.
        let on = allowed_signers_content_with_agents(&signers, true);
        assert!(on.contains("human@example.com"));
        assert!(on.contains("agent@ci.example.com"));
    }

    #[test]
    fn the_scan_record_namespace_is_granted_to_human_signers_only() {
        // The grant in `allowed_signers` is the ONLY thing that decides whether
        // `ssh-keygen -Y verify -n sscsb-scan-record` can succeed against this
        // repository, so it is where the "only a maintainer may assert a local
        // record" rule has to live. A `ci` or `ai` key that carried the
        // namespace would be able to mint a record the directory accepts —
        // directly contradicting `crate::signers`'s stated invariant that an
        // ai-class signer never signs anything that authorizes.
        let toml = "[[signer]]\nprincipal = \"human@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAAHUMAN human@example.com\"\n\n\
                    [[signer]]\nprincipal = \"ci@example.com\"\nclass = \"ci\"\nssh_public_key = \"ssh-ed25519 AAAACI ci@example.com\"\n\n\
                    [[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"github-app\"\nssh_public_key = \"ssh-ed25519 AAAAAGENT agent@ci.example.com\"\n";
        let signers = parse_signers(toml).unwrap();
        // include_agents=true so the ai line is emitted at all — the point is
        // that even when it IS emitted, it does not carry the scan namespace.
        let content = allowed_signers_content_with_agents(&signers, true);
        let line_for = |principal: &str| {
            content
                .lines()
                .find(|l| l.starts_with(principal))
                .unwrap_or_else(|| panic!("no line for {principal}:\n{content}"))
                .to_string()
        };

        let human = line_for("human@example.com");
        assert!(
            human.contains(&format!(
                "namespaces=\"git,{}\"",
                crate::local_scan::NAMESPACE
            )),
            "a human signer gets git AND the scan namespace: {human}"
        );

        for principal in ["ci@example.com", "agent@ci.example.com"] {
            let line = line_for(principal);
            assert!(
                line.contains("namespaces=\"git\""),
                "{principal} keeps the git namespace: {line}"
            );
            assert!(
                !line.contains(crate::local_scan::NAMESPACE),
                "{principal} must NOT be granted the local-scan namespace: {line}"
            );
        }

        // And the parser the directory + the tool both use agrees, rather than
        // this being an assertion about a substring.
        let parsed = crate::local_scan::parse_allowed_signers(&content);
        for a in &parsed {
            let is_human = a.principals.iter().any(|p| p == "human@example.com");
            assert!(a.permits("git"), "every class keeps `git`: {a:?}");
            assert_eq!(
                a.permits(crate::local_scan::NAMESPACE),
                is_human,
                "the scan namespace is human-only: {a:?}"
            );
        }
    }

    #[test]
    fn parse_signers_rejects_a_duplicate_principal_across_classes() {
        // The exact downgrade shape: one principal claimed as both human and ai.
        let toml = "[[signer]]\nprincipal = \"me@example.com\"\nclass = \"human\"\nssh_public_key = \"ssh-ed25519 AAAAH me@example.com\"\n\n[[signer]]\nprincipal = \"ME@example.com\"\nclass = \"ai\"\nssh_public_key = \"ssh-ed25519 AAAAA me@example.com\"\n";
        let err = parse_signers(toml).unwrap_err();
        assert!(
            format!("{err:#}").contains("listed more than once"),
            "duplicate principal (case-insensitive) must be rejected"
        );
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
        regenerate_allowed_signers(&ctx, false).unwrap();
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
        assert_eq!(pre_commit(&ctx), 0);
    }

    #[test]
    fn hook_pre_commit_passes_clean_stage_and_blocks_a_real_secret() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "clean.md", "nothing to see here\n");
        stage(&ctx, "clean.md");
        assert_eq!(pre_commit(&ctx), 0, "clean stage must pass");

        // Runtime-constructed token — never a real credential, and never
        // present in this repository's sources as a single string.
        let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
        write_file(&ctx, "leak.txt", &format!("github_token = \"{token}\"\n"));
        stage(&ctx, "leak.txt");
        assert_eq!(pre_commit(&ctx), 1, "planted secret must block the commit");
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
            pre_commit(&ctx),
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
            pre_commit(&ctx),
            0,
            "fail_open=true must let the commit through with only a warning"
        );
    }

    #[test]
    fn hook_pre_commit_sast_passes_a_clean_stage() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("pre_commit = false", "pre_commit = true");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        write_file(&ctx, "clean.md", "hello\n");
        stage(&ctx, "clean.md");
        assert_eq!(hook_pre_commit(&ctx).unwrap(), 0);
    }

    /// M14: the SAST arm of pre-commit degraded open unconditionally, while the
    /// secret-scan arm beside it respected `general.fail_open`. The gate is
    /// opt-in twice over — `enabled` AND `pre_commit = true` — and that is the
    /// argument for the switch applying, not against it: a user who turned it
    /// on had no way to make it hold. A mistyped engine name or an engine that
    /// is not installed removed the gate silently, and `fail_open = false`,
    /// the setting whose entire documented job is "do not let hooks pass when
    /// scanners are missing", did not reach it.
    #[test]
    fn hook_pre_commit_sast_that_cannot_run_obeys_fail_open() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("pre_commit = false", "pre_commit = true")
            .replace("engine = \"opengrep\"", "engine = \"bogus-engine\"");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        write_file(&ctx, "clean.md", "hello\n");
        stage(&ctx, "clean.md");
        assert_eq!(
            hook_pre_commit(&ctx).unwrap(),
            1,
            "fail_open=false (the default) must block when the SAST gate could not run"
        );

        // …and the one documented opt-out still opts out.
        let cfg_text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("fail_open = false", "fail_open = true");
        std::fs::write(ctx.config_path(), cfg_text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        assert_eq!(
            pre_commit(&ctx),
            0,
            "fail_open=true must let the commit through with only a warning"
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

    /// A dependency manifest under a non-ASCII directory must not walk past the
    /// AI dependency-review gate.
    ///
    /// `core.quotePath` is on by default, so `git diff --cached --name-only`
    /// C-quotes such a path: `café/Cargo.toml` comes back as the literal
    /// `"caf\303\251/Cargo.toml"`, whose basename is `Cargo.toml"` — with a
    /// trailing quote — and therefore fails `is_dependency_manifest`. The gate
    /// simply never saw the manifest. Reproduced end to end against a release
    /// binary before the fix: the identical AI-assisted commit message BLOCKED at
    /// exit 1 for `plain/Cargo.toml` and exited 0 for `café/Cargo.toml`.
    ///
    /// The assertion is discriminating on purpose: it stages BOTH an ASCII and a
    /// non-ASCII manifest and requires both to be named, so a fix that merely
    /// stopped enumerating anything would fail it too.
    #[test]
    fn a_manifest_under_a_non_ascii_path_cannot_evade_the_ai_dependency_gate() {
        let (_d, ctx) = test_repo();
        write_file(&ctx, "README.md", "# x\n");
        stage(&ctx, "README.md");
        git_ok(&ctx, &["commit", "-m", "chore: baseline", "--no-verify"]);

        let ai =
            "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n";

        std::fs::create_dir_all(ctx.root.join("caf\u{e9}")).unwrap();
        write_file(&ctx, "caf\u{e9}/package.json", r#"{"dependencies":{}}"#);
        stage(&ctx, "caf\u{e9}/package.json");

        assert_eq!(
            commit_msg(&ctx, ai),
            1,
            "a manifest under a non-ASCII directory must still gate: git C-quotes \
             the path, which used to strip it of its basename and hide it entirely"
        );
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

    /// Regression (H4): the new-package gate must fail CLOSED when it cannot
    /// evaluate. DELETING `.sscsb/policy/packages.toml` already failed closed
    /// (every dependency reads as unapproved), but CORRUPTING it merely printed
    /// "package-trust check skipped" and returned 0 — so one appended line
    /// turned the gate off. That asymmetry was the bypass.
    #[test]
    fn hook_commit_msg_fails_closed_when_the_package_policy_cannot_be_parsed() {
        let (_d, ctx) = test_repo();
        // Baseline: an unapproved new dependency is blocked while the policy
        // file is intact.
        write_file(&ctx, "Cargo.toml", "[dependencies]\nleftpad-rs = \"1\"\n");
        stage(&ctx, "Cargo.toml");
        assert_eq!(
            commit_msg(&ctx, "chore: add dep\n"),
            1,
            "an unapproved new dependency must block"
        );

        // Corrupt the policy — the gate can no longer evaluate anything.
        std::fs::write(
            crate::deps::packages_policy_path(&ctx),
            "not = [valid toml\n",
        )
        .unwrap();
        assert_eq!(
            commit_msg(&ctx, "chore: add dep\n"),
            1,
            "a policy file that cannot be parsed must not switch the gate off"
        );

        // `fail_open = true` stays the single explicit, documented opt-out.
        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("fail_open = false", "fail_open = true");
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        assert_eq!(
            commit_msg(&ctx, "chore: add dep\n"),
            0,
            "fail_open=true must still let the commit through with a warning"
        );
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
        assert_eq!(pre_push(&ctx, ""), 0);
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
            pre_push(&ctx, &stdin),
            1,
            "unsigned commit on a protected branch must be blocked"
        );

        let stdin = format!("refs/heads/feature/x {local} refs/heads/feature/x {ZERO}\n");
        assert_eq!(pre_push(&ctx, &stdin), 0);

        let stdin = format!("(delete) {ZERO} refs/heads/main {ZERO}\n");
        assert_eq!(pre_push(&ctx, &stdin), 0);
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
            pre_push(&ctx, &stdin),
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
        // Two human signers: the committer, and a distinct reviewer with a
        // key of their own. The reviewer must be policy-approved AND must not
        // have authored the merged range — the committer authored it, so they
        // cannot be the one vouching for its review.
        let reviewer_key = _dir.path().join("id_reviewer");
        let out = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "reviewer@example.com",
                "-f",
            ])
            .arg(&reviewer_key)
            .output()
            .unwrap();
        assert!(out.status.success());
        let reviewer_pub = std::fs::read_to_string(reviewer_key.with_extension("pub")).unwrap();
        let reviewer_pub = reviewer_pub.trim();
        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{pubkey}\"\n\n[[signer]]\nprincipal = \"reviewer@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{reviewer_pub}\"\n"
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
            pre_push(&ctx, &stdin),
            1,
            "merge with AI-declared parent lacking review evidence must block"
        );

        // Redo the same merge, this time naming a policy-approved human
        // reviewer who did not author the merged range — must pass. (The old
        // gate accepted `Reviewed-by: human@example.com` here — an identity in
        // NOBODY's policy — because it only checked that the trailer key
        // existed. That acceptance was the defect.)
        git_ok(&ctx, &["reset", "--hard", "HEAD^"]);
        git_ok(
            &ctx,
            &[
                "merge",
                "--no-ff",
                "-S",
                "-m",
                "Merge branch 'feature'\n\nReviewed-by: reviewer@example.com",
                "--no-verify",
                "feature",
            ],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(pre_push(&ctx, &stdin), 0);

        // Self-review: the committer authored the merged range, so naming
        // themselves as reviewer is refused even though they are a
        // policy-approved human.
        git_ok(&ctx, &["reset", "--hard", "HEAD^"]);
        git_ok(
            &ctx,
            &[
                "merge",
                "--no-ff",
                "-S",
                "-m",
                "Merge branch 'feature'\n\nReviewed-by: sscsb-test@example.com",
                "--no-verify",
                "feature",
            ],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            pre_push(&ctx, &stdin),
            1,
            "an author vouching for their own commits must be refused"
        );

        // The two-keys-one-tap shape: the reviewer authors ONLY the merge
        // commit itself and names themselves in Reviewed-by. Git's `A..B`
        // range includes B, so a naive range-author check would count the
        // merge's own author as an author of the reviewed work and refuse
        // this exact flow — the adversarial-review CRITICAL this stage pins.
        git_ok(&ctx, &["reset", "--hard", "HEAD^"]);
        git_ok(
            &ctx,
            &[
                "-c",
                "user.email=reviewer@example.com",
                "-c",
                "user.name=Reviewer",
                "merge",
                "--no-ff",
                "-S",
                "-m",
                "Merge branch 'feature'\n\nReviewed-by: reviewer@example.com",
                "--no-verify",
                "feature",
            ],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            pre_push(&ctx, &stdin),
            0,
            "the merge commit's own author must not be counted as a range author"
        );
    }

    // ── review_evidence_problems: the validation the old gate never did ─────

    fn human_signer(principal: &str) -> Signer {
        Signer {
            principal: principal.to_string(),
            class: SignerClass::Human,
            ssh_public_key: None,
            gpg_fingerprint: None,
            hardware_backed: false,
            backend: None,
            attestation_file: None,
            expires: None,
        }
    }

    fn trailers_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn authors_of(emails: &[&str]) -> BTreeSet<String> {
        emails.iter().map(|e| e.to_string()).collect()
    }

    #[test]
    fn review_evidence_url_alone_names_no_reviewer_and_is_insufficient() {
        // The old gate passed on this exact shape: a `Review-evidence` KEY
        // with any value and no reviewer identity anywhere.
        let problems = review_evidence_problems(
            &trailers_of(&[("Review-evidence", "https://example.com/pr/1")]),
            &[human_signer("reviewer@example.com")],
            &authors_of(&["agent@ci.example.com"]),
        );
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("names no reviewer"), "{problems:?}");
    }

    #[test]
    fn review_evidence_rejects_a_valueless_or_identityless_reviewed_by() {
        let signers = [human_signer("reviewer@example.com")];
        let authors = authors_of(&["agent@ci.example.com"]);
        let empty =
            review_evidence_problems(&trailers_of(&[("Reviewed-by", "")]), &signers, &authors);
        assert_eq!(empty.len(), 1, "{empty:?}");

        let wordy = review_evidence_problems(
            &trailers_of(&[("Reviewed-by", "looked fine to me")]),
            &signers,
            &authors,
        );
        assert!(wordy[0].contains("carries no identity"), "{wordy:?}");
    }

    #[test]
    fn review_evidence_rejects_a_reviewer_outside_the_policy() {
        let problems = review_evidence_problems(
            &trailers_of(&[("Reviewed-by", "Some One <nobody@example.com>")]),
            &[human_signer("reviewer@example.com")],
            &authors_of(&["agent@ci.example.com"]),
        );
        assert!(
            problems[0].contains("not in the approved-signers policy"),
            "{problems:?}"
        );
    }

    #[test]
    fn review_evidence_rejects_an_ai_class_reviewer() {
        let mut agent = human_signer("agent@ci.example.com");
        agent.class = SignerClass::Ai;
        let problems = review_evidence_problems(
            &trailers_of(&[("Reviewed-by", "Agent <agent@ci.example.com>")]),
            &[agent],
            &authors_of(&["someone-else@example.com"]),
        );
        assert!(
            problems[0].contains("only a human-class signer"),
            "{problems:?}"
        );
    }

    #[test]
    fn review_evidence_rejects_a_range_author_reviewing_their_own_work() {
        let problems = review_evidence_problems(
            &trailers_of(&[("Reviewed-by", "Dev <dev@example.com>")]),
            &[human_signer("dev@example.com")],
            &authors_of(&["dev@example.com", "agent@ci.example.com"]),
        );
        assert!(
            problems[0].contains("authored commit(s) in the merged range"),
            "{problems:?}"
        );
    }

    #[test]
    fn review_evidence_accepts_the_human_merge_author_reviewing_agent_work() {
        // The intended two-keys-one-tap flow: the agent authored the range
        // under its own identity; the human reviews and merges. The human is
        // the MERGE commit's author but not a range author — that must pass.
        let problems = review_evidence_problems(
            &trailers_of(&[
                ("Reviewed-by", "Human <human@example.com>"),
                ("Review-evidence", "https://github.com/o/r/pull/1"),
            ]),
            &[human_signer("human@example.com")],
            &authors_of(&["agent@ci.example.com"]),
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn review_evidence_value_must_be_a_url_or_commit_sha_when_present() {
        let signers = [human_signer("human@example.com")];
        let authors = authors_of(&["agent@ci.example.com"]);
        let bogus = review_evidence_problems(
            &trailers_of(&[
                ("Reviewed-by", "Human <human@example.com>"),
                ("Review-evidence", "I promise I read it"),
            ]),
            &signers,
            &authors,
        );
        assert!(
            bogus[0].contains("neither a URL nor a commit sha"),
            "{bogus:?}"
        );

        let sha = review_evidence_problems(
            &trailers_of(&[
                ("Reviewed-by", "Human <human@example.com>"),
                (
                    "Review-evidence",
                    "0123456789abcdef0123456789abcdef01234567",
                ),
            ]),
            &signers,
            &authors,
        );
        assert!(sha.is_empty(), "{sha:?}");
    }

    #[test]
    fn trailer_identity_email_parses_name_addr_and_bare_forms() {
        assert_eq!(
            trailer_identity_email("Justin Pagano <jp@example.com>").as_deref(),
            Some("jp@example.com")
        );
        assert_eq!(
            trailer_identity_email("jp@example.com").as_deref(),
            Some("jp@example.com")
        );
        assert_eq!(trailer_identity_email("no address here"), None);
        assert_eq!(trailer_identity_email(""), None);
        assert_eq!(trailer_identity_email("<>"), None);
    }

    /// Build a repo with agent-signing enabled and a single `ai`-class signer
    /// whose ed25519 key git is configured to sign with. Returns the agent
    /// principal so callers can assert on it.
    fn agent_signed_repo() -> (tempfile::TempDir, Ctx) {
        let (dir, ctx) = test_repo();
        let key = dir.path().join("id_agent");
        let out = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "agent@ci.example.com",
                "-f",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success());
        let pubkey = std::fs::read_to_string(key.with_extension("pub"))
            .unwrap()
            .trim()
            .to_string();
        git_ok(&ctx, &["config", "gpg.format", "ssh"]);
        git_ok(&ctx, &["config", "user.signingkey", key.to_str().unwrap()]);
        crate::config::set_control_enabled(&ctx.config_path(), "agent-signing", true).unwrap();
        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"tpm\"\nhardware_backed = true\nssh_public_key = \"{pubkey}\"\n"
            ),
        )
        .unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        (dir, ctx)
    }

    #[test]
    fn agent_signature_verifies_on_a_feature_branch_but_is_blocked_on_a_protected_branch() {
        let (_dir, ctx) = agent_signed_repo();
        // With agent-signing enabled, the ai key IS emitted into allowed_signers.
        regenerate_allowed_signers(&ctx, true).unwrap();

        write_file(&ctx, "feature.txt", "f\n");
        stage(&ctx, "feature.txt");
        git_ok(
            &ctx,
            &["commit", "-S", "-m", "feat: agent work", "--no-verify"],
        );

        // ISC-3: the agent commit verifies as a good signature.
        let status = exec::git(&["log", "-1", "--format=%G?", "HEAD"], &ctx.root).unwrap();
        assert_eq!(
            status, "G",
            "agent key must produce a good signature when enabled"
        );
        let principal = exec::git(&["log", "-1", "--format=%GS", "HEAD"], &ctx.root).unwrap();
        assert_eq!(principal, "agent@ci.example.com");

        // ISC-A4: the SAME agent-signed commit pushed to a protected branch is
        // blocked — good signature, wrong class.
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            pre_push(&ctx, &stdin),
            1,
            "agent signature must never satisfy the human-only protected-branch gate"
        );
    }

    #[test]
    fn agent_signature_is_blocked_on_protected_branch_even_with_agent_signing_disabled() {
        // ISC-A4 must hold with the control OFF too: the ai key is then NOT in
        // allowed_signers, so the signature can't validate → still rejected.
        let (_dir, ctx) = agent_signed_repo();
        crate::config::set_control_enabled(&ctx.config_path(), "agent-signing", false).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();

        write_file(&ctx, "feature.txt", "f\n");
        stage(&ctx, "feature.txt");
        git_ok(
            &ctx,
            &["commit", "-S", "-m", "feat: agent work", "--no-verify"],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(pre_push(&ctx, &stdin), 1);
    }

    #[test]
    fn an_attestation_file_never_elevates_an_agent_key_on_a_protected_branch() {
        // ISC-A6: attaching a hardware-attestation artifact must not change the
        // protected-branch outcome for an ai key — it stays blocked.
        let (dir, ctx) = agent_signed_repo();
        let att_dir = ctx.root.join(".sscsb/policy/att");
        std::fs::create_dir_all(&att_dir).unwrap();
        std::fs::write(att_dir.join("agent.bin"), b"a genuine-looking attestation").unwrap();
        // Re-write policy with the attestation_file present.
        let pubkey = std::fs::read_to_string(dir.path().join("id_agent.pub"))
            .unwrap()
            .trim()
            .to_string();
        std::fs::write(
            signers_path(&ctx),
            format!(
                "[[signer]]\nprincipal = \"agent@ci.example.com\"\nclass = \"ai\"\nbackend = \"tpm\"\nhardware_backed = true\nattestation_file = \".sscsb/policy/att/agent.bin\"\nssh_public_key = \"{pubkey}\"\n"
            ),
        )
        .unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();

        write_file(&ctx, "feature.txt", "f\n");
        stage(&ctx, "feature.txt");
        git_ok(
            &ctx,
            &["commit", "-S", "-m", "feat: agent work", "--no-verify"],
        );
        let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        let stdin = format!("refs/heads/main {local} refs/heads/main {ZERO}\n");
        assert_eq!(
            pre_push(&ctx, &stdin),
            1,
            "an attestation artifact must not turn an agent key into a valid protected-branch signer"
        );
    }

    #[test]
    fn ai_merge_without_review_evidence_is_blocked_even_with_agent_signing_enabled() {
        // ISC-A5: with agent-signing ON (ai key in allowed_signers), a merge of
        // AI-declared history still needs the human review-evidence trailer.
        let (_dir, ctx) = agent_signed_repo();
        // Give the human path a real signer too so the merge commit itself can
        // be human-signed; here we reuse the agent key only to sign feature
        // work, and sign the merge with the same key to show the merge-evidence
        // gate fires independently of the signer's class check ordering.
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
            pre_push(&ctx, &stdin),
            1,
            "AI-history merge without review evidence must stay blocked with agent-signing on"
        );
    }

    // ────────────────────────── verify_* controls ──────────────────────────

    #[test]
    fn verify_secrets_control_fails_when_hooks_are_not_installed() {
        let (_d, ctx) = unbootstrapped_repo_with_config();
        let cfg = ctx.require_config().unwrap();
        let result = verify_secrets_control(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("core.hooksPath is unset"));
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
        assert!(result.messages[0].contains("core.hooksPath is unset"));
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
        assert!(result.messages[0].contains("core.hooksPath is unset"));
    }

    #[test]
    fn verify_hook_installed_passes_once_hooks_are_installed() {
        let (_d, ctx) = test_repo();
        let result = verify_hook_installed(&ctx, "ai-trailers");
        assert_eq!(result.outcome, Outcome::Pass);
        assert_eq!(result.control, "ai-trailers");
        assert!(result.messages[0].contains("enforced by the commit-msg hook"));
    }

    // ──────────────── remaining branch coverage (config on/off edges) ──────

    #[test]
    fn hook_pre_commit_with_no_staged_files_is_a_no_op() {
        let (_d, ctx) = test_repo();
        assert_eq!(pre_commit(&ctx), 0);
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
            pre_commit(&ctx),
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
            pre_commit(&ctx),
            1,
            "an ERROR-severity SAST finding in the staged diff must block the commit"
        );
    }

    // ── the commit gate's typosquat annotation: two independent suppressors ──

    fn new_dep(qualified: &str, source: Option<crate::deps::DepSource>) -> crate::deps::NewDep {
        crate::deps::NewDep {
            qualified: qualified.to_string(),
            reason: crate::deps::NewDepReason::NotInBaseline,
            source,
        }
    }

    /// Baseline: with a registry source and the heuristic on, the gate that
    /// actually blocks still names the shadowed package.
    #[test]
    fn the_commit_gate_still_names_a_typosquat_on_a_registry_dependency() {
        let annotation = typosquat_annotation(
            &new_dep("cargo:tokoi", Some(crate::deps::DepSource::Registry)),
            crate::deps::TrustChecks::default(),
        );
        assert!(
            annotation.is_some_and(|a| a.contains("tokio")),
            "the enforcing gate must keep calling out a registry-sourced typosquat"
        );
    }

    /// R1's property at the commit gate, asserted with the config fully
    /// PERMISSIVE: a path dependency's name is not what resolves it, and no
    /// `TrustChecks` value may re-enable resolving it by name.
    #[test]
    fn a_path_dependency_is_never_called_a_typosquat_even_with_every_check_on() {
        let annotation = typosquat_annotation(
            &new_dep(
                "cargo:tokoi",
                Some(crate::deps::DepSource::Path("../outside/tokoi".into())),
            ),
            crate::deps::TrustChecks::default(),
        );
        assert_eq!(
            annotation, None,
            "a public package sharing a path dependency's name is an unrelated \
             package; the source guard is correctness, not policy"
        );
    }

    /// M21's property at the commit gate — the third place the heuristic runs.
    /// A toggle that reaches only `deps check` and approval leaves the config
    /// contradicting itself at the one gate that stops work.
    #[test]
    fn typosquat_check_false_reaches_the_commit_gate_too() {
        let off = crate::deps::TrustChecks {
            registry: true,
            typosquat: false,
        };
        assert_eq!(
            typosquat_annotation(
                &new_dep("cargo:tokoi", Some(crate::deps::DepSource::Registry)),
                off
            ),
            None,
            "the key must switch the heuristic off everywhere it runs, or it is \
             the inert key it was fixed for"
        );
    }

    /// ...and suppressing the ANNOTATION must never let the PACKAGE through.
    /// `explain()` is pushed unconditionally by the caller, so the commit is
    /// still blocked; only the proximity note is withheld.
    #[test]
    fn suppressing_the_annotation_does_not_unblock_the_dependency() {
        let (_d, ctx) = test_repo();
        let cfg_text = std::fs::read_to_string(ctx.config_path()).unwrap();
        assert!(
            cfg_text.contains("typosquat_check = true"),
            "the generated config is expected to carry the key already"
        );
        std::fs::write(
            ctx.config_path(),
            cfg_text.replace("typosquat_check = true", "typosquat_check = false"),
        )
        .unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        write_file(&ctx, "Cargo.toml", "[dependencies]\ntokoi = \"1\"\n");
        stage(&ctx, "Cargo.toml");
        assert_eq!(
            commit_msg(&ctx, "chore: add a dep\n"),
            1,
            "a new unapproved dependency is still blocked with the heuristic off"
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
            pre_push(&ctx, &stdin),
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
            pre_push(&ctx, &stdin),
            0,
            "clean incremental push must pass"
        );
    }
}
