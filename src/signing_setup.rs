//! The five-environment commit-signing model: probe, converge, guide, verify.
//!
//! sscsb doesn't just audit signing — it *implements* it. The model
//! (research-derived, 2026): every environment where commits originate has a
//! named actor and a named signer, the AI agent NEVER signs as the human, the
//! agent's key is NEVER registered on the human's forge account (its commits
//! honestly show "Unverified" there — that is the designed state; an UNSIGNED
//! commit is the failure), and Verified-as-human always traces to a genuine
//! human action (hardware tap locally; authenticated account via the forge's
//! own signer for web/Codespaces).
//!
//! | env id             | actor | signer                              |
//! |--------------------|-------|-------------------------------------|
//! | human-local        | human | OS-keystore/enclave key, tap-gated  |
//! | agent-claude-code  | AI    | agent's own key, distinct identity  |
//! | cloud-claude       | bot   | forge App server-side, or unsigned  |
//! | github-web         | human | forge web-flow key (account anchor) |
//! | codespaces         | human | forge-managed signing (opt-in)      |
//!
//! Everything here is probe → converge (programmatic) → guide (numbered steps
//! for what technically cannot be automated) → verify. v1 implements the
//! macOS + Secretive + Claude Code stack behind generalization seams
//! (`human_backend` / `agent` config options).

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub const CONTROL: &str = "signing-model";

// ───────────────────────────── environments ─────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    HumanLocal,
    AgentClaudeCode,
    CloudClaude,
    GithubWeb,
    Codespaces,
}

impl Environment {
    pub const ALL: [Environment; 5] = [
        Environment::HumanLocal,
        Environment::AgentClaudeCode,
        Environment::CloudClaude,
        Environment::GithubWeb,
        Environment::Codespaces,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Environment::HumanLocal => "human-local",
            Environment::AgentClaudeCode => "agent-claude-code",
            Environment::CloudClaude => "cloud-claude",
            Environment::GithubWeb => "github-web",
            Environment::Codespaces => "codespaces",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Environment::HumanLocal => "Laptop — human (enclave key, tap-gated)",
            Environment::AgentClaudeCode => "Laptop — Claude Code agent (own key, own identity)",
            Environment::CloudClaude => "Claude cloud containers (bot identity)",
            Environment::GithubWeb => "GitHub web / mobile (account-anchored web-flow)",
            Environment::Codespaces => "Codespaces (forge-managed signing, opt-in)",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Environment::ALL.into_iter().find(|e| e.id() == id)
    }
}

/// Where each probe looks. Injectable so tests never touch the real home dir.
#[derive(Debug, Clone)]
pub struct SigningPaths {
    pub home: PathBuf,
    /// The agent harness's user settings (Claude Code: `~/.claude/settings.json`).
    pub agent_settings: PathBuf,
    /// Secretive's agent socket (macOS).
    pub secretive_socket: PathBuf,
    pub secretive_app: PathBuf,
}

impl SigningPaths {
    pub fn from_home(home: &Path) -> Self {
        SigningPaths {
            home: home.to_path_buf(),
            agent_settings: home.join(".claude/settings.json"),
            secretive_socket: home
                .join("Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"),
            secretive_app: PathBuf::from("/Applications/Secretive.app"),
        }
    }

    pub fn real() -> Result<Self> {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| anyhow::anyhow!("HOME is not set — cannot locate user configuration"))?;
        Ok(Self::from_home(&home))
    }
}

// ───────────────────────────── probe results ────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvState {
    /// Every locally-probeable requirement of the model holds.
    Configured,
    /// Some requirements hold; `details` names each gap.
    Partial,
    /// Nothing is locally probeable for this environment yet — the state
    /// lives behind a web UI / attestation and is driven by `signing setup`.
    GuidedPending,
    /// A tool needed to probe is missing/unusable; the reason is named.
    Unknown(String),
}

impl EnvState {
    pub fn symbol(&self) -> &'static str {
        match self {
            EnvState::Configured => "CONFIGURED",
            EnvState::Partial => "PARTIAL",
            EnvState::GuidedPending => "GUIDED",
            EnvState::Unknown(_) => "UNKNOWN",
        }
    }
}

#[derive(Debug)]
pub struct EnvStatus {
    pub env: Environment,
    pub state: EnvState,
    pub details: Vec<String>,
}

// ─────────────────────────── low-level readers ──────────────────────────────

/// One `git config --global` value (None when unset or git unavailable).
fn git_global(key: &str) -> Option<String> {
    // --global scope deliberately: the model configures the MACHINE, and this
    // must read the same value in any repo. GIT_CONFIG_* env (an agent
    // session's identity) does not leak into --global reads.
    let out = std::process::Command::new("git")
        .args(["config", "--global", key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// The `GIT_CONFIG_{COUNT,KEY_n,VALUE_n}` map from an agent-harness settings
/// file's `env` block, if present and well-formed.
fn agent_env_git_config(settings_json: &str) -> Option<std::collections::BTreeMap<String, String>> {
    let v: serde_json::Value = serde_json::from_str(settings_json).ok()?;
    let env = v.get("env")?.as_object()?;
    let count: usize = env.get("GIT_CONFIG_COUNT")?.as_str()?.parse().ok()?;
    let mut map = std::collections::BTreeMap::new();
    for i in 0..count {
        let k = env.get(&format!("GIT_CONFIG_KEY_{i}"))?.as_str()?;
        let val = env.get(&format!("GIT_CONFIG_VALUE_{i}"))?.as_str()?;
        map.insert(k.to_string(), val.to_string());
    }
    Some(map)
}

// ───────────────────────────── per-env probes ───────────────────────────────

/// E1: the human's local signing lane. Fully probeable.
pub fn probe_human_local(paths: &SigningPaths) -> EnvStatus {
    let mut details = Vec::new();
    let mut gaps = 0usize;

    match git_global("gpg.format").as_deref() {
        Some("ssh") => details.push("git global gpg.format = ssh".into()),
        other => {
            gaps += 1;
            details.push(format!(
                "git global gpg.format is {} — `sscsb signing setup human-local` sets ssh",
                other.unwrap_or("unset")
            ));
        }
    }

    match git_global("user.signingkey") {
        Some(key) if Path::new(&key).exists() => {
            details.push(format!("human signing key configured: {key}"));
        }
        Some(key) => {
            gaps += 1;
            details.push(format!("user.signingkey points at missing file: {key}"));
        }
        None => {
            gaps += 1;
            details.push("git global user.signingkey unset".into());
        }
    }

    if git_global("commit.gpgsign").as_deref() == Some("true") {
        details.push("commit.gpgsign = true".into());
    } else {
        gaps += 1;
        details.push("commit.gpgsign not enabled globally".into());
    }

    match git_global("gpg.ssh.allowedsignersfile") {
        Some(f) if Path::new(&f).exists() => {
            details.push(format!("allowed_signers wired: {f}"));
        }
        _ => {
            gaps += 1;
            details.push("gpg.ssh.allowedSignersFile unset or missing".into());
        }
    }

    if git_global("alias.sign").is_some() {
        details.push("`git sign` alias present (env-proof human signing)".into());
    } else {
        gaps += 1;
        details.push(
            "`git sign` alias missing — inside an agent session a bare `git commit` \
             signs as the AGENT; the alias forces the human key via -c overrides"
                .into(),
        );
    }

    // Backend presence is informative, not a gap: other backends are legal.
    if paths.secretive_socket.exists() {
        details.push("Secretive agent socket present (enclave backend available)".into());
    } else if paths.secretive_app.exists() {
        details.push("Secretive.app installed but agent socket absent (launch it once)".into());
    } else {
        details.push(
            "Secretive not detected — enclave backend unavailable; see setup guidance".into(),
        );
    }

    EnvStatus {
        env: Environment::HumanLocal,
        state: if gaps == 0 {
            EnvState::Configured
        } else {
            EnvState::Partial
        },
        details,
    }
}

/// E2: the Claude Code agent's lane. Probeable from the harness settings file.
pub fn probe_agent_claude_code(paths: &SigningPaths) -> EnvStatus {
    let mut details = Vec::new();
    let mut gaps = 0usize;

    let settings = match std::fs::read_to_string(&paths.agent_settings) {
        Ok(s) => s,
        Err(_) => {
            return EnvStatus {
                env: Environment::AgentClaudeCode,
                state: EnvState::Partial,
                details: vec![format!(
                    "agent settings not found at {} — Claude Code not configured on this \
                     machine, or a different agent harness is in use",
                    paths.agent_settings.display()
                )],
            };
        }
    };

    let Some(git_env) = agent_env_git_config(&settings) else {
        return EnvStatus {
            env: Environment::AgentClaudeCode,
            state: EnvState::Partial,
            details: vec![
                "agent settings has no GIT_CONFIG_* env block — agent commits will fall \
                 through to the HUMAN's git identity (identity blur). Run \
                 `sscsb signing setup agent-claude-code`"
                    .into(),
            ],
        };
    };

    let human_key = git_global("user.signingkey").unwrap_or_default();
    let human_email = git_global("user.email").unwrap_or_default();

    match git_env.get("user.signingkey") {
        Some(agent_key) if Path::new(agent_key).exists() => {
            if !human_key.is_empty() && *agent_key == human_key {
                gaps += 1;
                details.push(
                    "IDENTITY BLUR: agent sessions sign with the HUMAN's key — the agent \
                     must have its own key"
                        .into(),
                );
            } else {
                details.push(format!("agent signing key wired: {agent_key}"));
            }
        }
        Some(agent_key) => {
            gaps += 1;
            details.push(format!("agent signing key missing on disk: {agent_key}"));
        }
        None => {
            gaps += 1;
            details.push("agent env sets no user.signingkey".into());
        }
    }

    if git_env.get("commit.gpgsign").map(String::as_str) == Some("true") {
        details.push("agent sessions force commit.gpgsign".into());
    } else {
        gaps += 1;
        details.push("agent env does not force commit.gpgsign=true".into());
    }

    match git_env.get("user.email") {
        Some(email) if !email.is_empty() => {
            if !human_email.is_empty() && *email == human_email {
                gaps += 1;
                details.push("IDENTITY BLUR: agent authors commits with the HUMAN's email".into());
            } else {
                details.push(format!("agent identity: {email} (distinct from human)"));
            }
        }
        _ => {
            gaps += 1;
            details.push("agent env sets no user.email — agent commits author as the human".into());
        }
    }

    EnvStatus {
        env: Environment::AgentClaudeCode,
        state: if gaps == 0 {
            EnvState::Configured
        } else {
            EnvState::Partial
        },
        details,
    }
}

/// E3: Claude cloud containers. Repo-side attribution block is probeable;
/// App installation and signing mode are setup/verify concerns.
pub fn probe_cloud_claude(ctx: &Ctx) -> EnvStatus {
    let mut details = Vec::new();
    let repo_settings = ctx.root.join(".claude/settings.json");
    let mut state = EnvState::GuidedPending;

    if let Ok(s) = std::fs::read_to_string(&repo_settings) {
        if serde_json::from_str::<serde_json::Value>(&s)
            .ok()
            .and_then(|v| v.get("attribution").cloned())
            .is_some()
        {
            details.push(".claude/settings.json attribution block present (syncs to cloud)".into());
            state = EnvState::Configured;
        } else {
            details.push(
                ".claude/settings.json exists but has no attribution block — cloud commits \
                 won't carry the session-provenance trailers"
                    .into(),
            );
            state = EnvState::Partial;
        }
    } else {
        details.push(
            "no repo-level .claude/settings.json — cloud sessions get no attribution config \
             (only repo-level settings sync to cloud containers)"
                .into(),
        );
    }
    details.push(
        "cloud invariant: keys never enter the sandbox; use the forge App identity (never \
         a personal token) and land merges from the human-local lane"
            .into(),
    );

    EnvStatus {
        env: Environment::CloudClaude,
        state,
        details,
    }
}

/// E4: forge web/mobile. The account is the anchor; only MFA state is
/// API-probeable today, and only when `gh` is present and authenticated.
pub fn probe_github_web(ctx: &Ctx) -> EnvStatus {
    let mut details = Vec::new();
    if !crate::tools::is_available("gh") {
        return EnvStatus {
            env: Environment::GithubWeb,
            state: EnvState::Unknown(crate::tools::degrade_message("gh", ctx.platform)),
            details,
        };
    }
    let state = match exec::run("gh", &["api", "user"], Some(&ctx.root)) {
        Ok(out) if out.success() => {
            match serde_json::from_str::<serde_json::Value>(&out.stdout)
                .ok()
                .and_then(|v| v.get("two_factor_authentication").cloned())
            {
                Some(serde_json::Value::Bool(true)) => {
                    details.push(
                        "account MFA enabled (phishing-resistance not API-visible — \
                                  attest via `sscsb signing setup github-web`)"
                            .into(),
                    );
                    EnvState::Partial
                }
                Some(serde_json::Value::Bool(false)) => {
                    details.push(
                        "account MFA DISABLED — the web-flow 'Verified' badge is \
                                  only as strong as this account"
                            .into(),
                    );
                    EnvState::Partial
                }
                _ => {
                    details.push(
                        "MFA state not visible to this token (needs `read:user`; \
                         `gh auth refresh -s read:user`)"
                            .into(),
                    );
                    EnvState::Partial
                }
            }
        }
        _ => EnvState::Unknown("gh present but `gh api user` failed — not authenticated?".into()),
    };
    details.push(
        "vigilant mode + passkey enrollment have no read API — guided steps + dated \
         attestation via `sscsb signing setup github-web`"
            .into(),
    );
    EnvStatus {
        env: Environment::GithubWeb,
        state,
        details,
    }
}

/// E5: Codespaces. The GPG-verification toggle has no read API — guided.
pub fn probe_codespaces(_ctx: &Ctx) -> EnvStatus {
    EnvStatus {
        env: Environment::Codespaces,
        state: EnvState::GuidedPending,
        details: vec![
            "Codespaces GPG verification is a web setting with no read API — enable it for a \
             SELECTED trusted-repo list (never 'all repositories'), never mount private keys \
             into a codespace; record via `sscsb signing setup codespaces`"
                .into(),
        ],
    }
}

pub fn probe_env(ctx: &Ctx, paths: &SigningPaths, env: Environment) -> EnvStatus {
    match env {
        Environment::HumanLocal => probe_human_local(paths),
        Environment::AgentClaudeCode => probe_agent_claude_code(paths),
        Environment::CloudClaude => probe_cloud_claude(ctx),
        Environment::GithubWeb => probe_github_web(ctx),
        Environment::Codespaces => probe_codespaces(ctx),
    }
}

// ─────────────────────── guided-lane attestation policy ─────────────────────

/// `.sscsb/policy/signing-model.toml` — records that the user CONFIRMED a
/// web/App setting that has no read API. Reuses the signers.rs freshness model:
/// a dated confirmation that goes stale (default 180d) and must be re-confirmed.
pub fn signing_model_policy_path(ctx: &Ctx) -> PathBuf {
    ctx.sscsb_dir().join("policy").join("signing-model.toml")
}

pub const SIGNING_MODEL_TEMPLATE: &str = r#"# sscsb signing-model attestations.
#
# These lanes (cloud / web / Codespaces) live behind forge web UIs and App
# installs with NO read API, so sscsb cannot prove them — it records the DATE
# you confirmed each, and `sscsb signing verify` warns when a confirmation goes
# stale (default 180 days). Record with:
#   sscsb signing setup <lane> --confirm
# after you've done that lane's guided steps.

# [github-web]
# vigilant_mode = "YYYY-MM-DD"            # you enabled "Flag unsigned commits as unverified"
# phishing_resistant_mfa = "YYYY-MM-DD"   # you enrolled a passkey / hardware security key

# [codespaces]
# gpg_verification = "YYYY-MM-DD"         # enabled for a SELECTED trusted-repo list (never "all")

# [cloud-claude]
# github_app_installed = "YYYY-MM-DD"     # authorized the Claude GitHub App (not a personal token)
# signing_mode = "app-signed"             # app-signed | unsigned-drafts
"#;

/// Attestation keys expected per guided lane (date-valued unless noted).
fn lane_attestation_keys(env: Environment) -> &'static [&'static str] {
    match env {
        Environment::GithubWeb => &["vigilant_mode", "phishing_resistant_mfa"],
        Environment::Codespaces => &["gpg_verification"],
        Environment::CloudClaude => &["github_app_installed"],
        _ => &[],
    }
}

/// Read `[lane]` → {key: value} from the policy file (absent → empty).
fn read_signing_policy(ctx: &Ctx) -> toml::Table {
    std::fs::read_to_string(signing_model_policy_path(ctx))
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .unwrap_or_default()
}

/// Stamp today's date into every attestation key for `env`, preserving other
/// lanes. Returns the ISO date used.
fn record_lane_attestation(ctx: &Ctx, env: Environment, today: &str) -> Result<()> {
    let path = signing_model_policy_path(ctx);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut doc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .unwrap_or_default();
    let lane = env.id();
    for key in lane_attestation_keys(env) {
        doc[lane][key] = toml_edit::value(today);
    }
    std::fs::write(&path, doc.to_string())?;
    Ok(())
}

// ───────────────────────────── setup engine ─────────────────────────────────

/// A manual step sscsb cannot perform programmatically (a Secure-Enclave key
/// birth in a native app, a forge web toggle with no API). Numbered, with the
/// reason it matters and how to confirm it later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidedStep {
    pub title: String,
    pub why: String,
    pub actions: Vec<String>,
    /// How the user (or a later `sscsb signing verify`) confirms it happened.
    pub confirm: String,
}

/// The outcome of a converge pass: what was changed programmatically, and the
/// numbered manual steps that remain.
#[derive(Debug, Default)]
pub struct SetupReport {
    pub changed: Vec<String>,
    pub already: Vec<String>,
    pub guided: Vec<GuidedStep>,
    /// A blocking refusal (e.g. identity blur) — setup did nothing destructive.
    pub refused: Option<String>,
}

impl SetupReport {
    fn note_changed(&mut self, s: impl Into<String>) {
        self.changed.push(s.into());
    }
    fn note_already(&mut self, s: impl Into<String>) {
        self.already.push(s.into());
    }
    fn guide(&mut self, step: GuidedStep) {
        self.guided.push(step);
    }
}

fn git_set_global(key: &str, value: &str, apply: bool) -> Result<()> {
    if apply {
        let out = exec::run("git", &["config", "--global", key, value], None)?;
        if !out.success() {
            anyhow::bail!("git config --global {key} failed: {}", out.stderr.trim());
        }
    }
    Ok(())
}

/// Pure, testable core of the highest-blast-radius write: merge a
/// `GIT_CONFIG_{COUNT,KEY_n,VALUE_n}` block for `pairs` into an agent-harness
/// settings JSON, preserving every other key and every other env var. Returns
/// `None` when the desired block is already present verbatim (idempotent → no
/// write). Errors only on malformed input.
pub fn merge_git_config_env(existing_json: &str, pairs: &[(&str, &str)]) -> Result<Option<String>> {
    let mut root: serde_json::Value = if existing_json.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(existing_json)
            .map_err(|e| anyhow::anyhow!("agent settings is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        anyhow::bail!("agent settings root is not a JSON object");
    }

    // Idempotency check against the current parsed block.
    if let Some(cur) = agent_env_git_config(existing_json) {
        let want: std::collections::BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // Every desired pair already present with the same value AND the count
        // matches exactly → nothing to do.
        if cur == want {
            return Ok(None);
        }
    }

    let obj = root.as_object_mut().unwrap();
    let env = obj.entry("env").or_insert_with(|| serde_json::json!({}));
    if !env.is_object() {
        anyhow::bail!("agent settings `env` is not a JSON object");
    }
    let env = env.as_object_mut().unwrap();

    // Clear any stale GIT_CONFIG_* keys so a shrink (count 4→3) can't orphan
    // a KEY_3/VALUE_3 pair; preserve every non-GIT_CONFIG env var.
    let stale: Vec<String> = env
        .keys()
        .filter(|k| k.starts_with("GIT_CONFIG_"))
        .cloned()
        .collect();
    for k in stale {
        env.remove(&k);
    }
    env.insert(
        "GIT_CONFIG_COUNT".into(),
        serde_json::Value::String(pairs.len().to_string()),
    );
    for (i, (k, v)) in pairs.iter().enumerate() {
        env.insert(
            format!("GIT_CONFIG_KEY_{i}"),
            serde_json::Value::String((*k).to_string()),
        );
        env.insert(
            format!("GIT_CONFIG_VALUE_{i}"),
            serde_json::Value::String((*v).to_string()),
        );
    }

    let mut out = serde_json::to_string_pretty(&root)?;
    out.push('\n');
    Ok(Some(out))
}

/// E1: converge the human's local signing lane. Programmatic where git config
/// allows; guided for the enclave-key birth and the forge key registration.
pub fn setup_human_local(paths: &SigningPaths, apply: bool) -> Result<SetupReport> {
    let mut r = SetupReport::default();

    // gpg.format = ssh
    if git_global("gpg.format").as_deref() == Some("ssh") {
        r.note_already("git global gpg.format already ssh");
    } else {
        git_set_global("gpg.format", "ssh", apply)?;
        r.note_changed("set git global gpg.format = ssh");
    }

    // commit.gpgsign = true
    if git_global("commit.gpgsign").as_deref() == Some("true") {
        r.note_already("commit.gpgsign already true");
    } else {
        git_set_global("commit.gpgsign", "true", apply)?;
        r.note_changed("set git global commit.gpgsign = true");
    }

    // allowed_signers wiring (path only — content is the human key, added when
    // the key exists / after registration).
    let allowed = paths.home.join(".ssh/allowed_signers");
    if git_global("gpg.ssh.allowedsignersfile").is_some() {
        r.note_already("gpg.ssh.allowedSignersFile already set");
    } else {
        git_set_global(
            "gpg.ssh.allowedSignersFile",
            &allowed.to_string_lossy(),
            apply,
        )?;
        r.note_changed(format!(
            "wired gpg.ssh.allowedSignersFile → {}",
            allowed.display()
        ));
    }

    // The env-proof `git sign` alias (the laptop footgun: inside an agent
    // session a bare `git commit` signs as the AGENT; this forces the human key
    // via -c overrides, which outrank GIT_CONFIG_* env).
    if git_global("alias.sign").is_some() {
        r.note_already("`git sign` alias already present");
    } else if let Some(key) = git_global("user.signingkey") {
        let email = git_global("user.email").unwrap_or_default();
        let name = git_global("user.name").unwrap_or_else(|| "you".into());
        let alias = format!(
            "!git -c user.name='{name}' -c user.email='{email}' \
             -c user.signingkey='{key}' -c commit.gpgsign=true commit"
        );
        git_set_global("alias.sign", &alias, apply)?;
        r.note_changed("created env-proof `git sign` alias (human key via -c overrides)");
    } else {
        // No human key yet → the alias needs the key; defer to after the
        // guided key-creation step below.
        r.guide(GuidedStep {
            title: "Create your human signing key, then re-run setup".into(),
            why: "The `git sign` alias must reference your key; no user.signingkey is set yet."
                .into(),
            actions: vec![
                "Create a Secure-Enclave key in Secretive (see step below), or any SSH key".into(),
                "git config --global user.signingkey <path-to-your-pubkey>".into(),
                "Re-run: sscsb signing setup human-local".into(),
            ],
            confirm: "sscsb signing status → human-local shows the key + alias".into(),
        });
    }

    // Guided: enclave key birth (native app; not scriptable).
    if !paths.secretive_socket.exists() {
        r.guide(GuidedStep {
            title: "Create a hardware-backed signing key in Secretive".into(),
            why: "The strongest human anchor: the private key is generated inside the Secure \
                  Enclave and never leaves it; each signature needs a physical Touch ID tap."
                .into(),
            actions: vec![
                "Install Secretive (https://github.com/maxgoedjen/secretive) if absent".into(),
                "Open Secretive → '+' → name it (e.g. Git-Signing) → keep 'Authentication \
                 required' ON (the tap = your ship-gate)"
                    .into(),
                "Copy its public key; save it to ~/.ssh/git_signing_key.pub".into(),
                "git config --global user.signingkey ~/.ssh/git_signing_key.pub".into(),
            ],
            confirm: "sscsb signing status → human-local shows the Secretive socket present".into(),
        });
    }

    // Guided: register the human pubkey as a GitHub SIGNING key (OAuth scope +
    // API; the scope grant is a browser step).
    r.guide(GuidedStep {
        title: "Register your human key as a GitHub *signing* key".into(),
        why: "So your Enclave-signed commits show 'Verified' as you. (Do NOT register the \
              agent key here — the agent stays Unverified by design.)"
            .into(),
        actions: vec![
            "gh auth refresh -h github.com -s admin:ssh_signing_key   # browser OAuth".into(),
            "gh api user/ssh_signing_keys -f title='Secretive (laptop)' \
             -f key=\"$(cat ~/.ssh/git_signing_key.pub)\""
                .into(),
        ],
        confirm: "gh api user/ssh_signing_keys lists your key; a `git sign` commit then \
                  shows Verified on GitHub"
            .into(),
    });

    Ok(r)
}

/// E2: converge the Claude Code agent's lane. Generates/uses a distinct agent
/// key, merges the identity+signing env into the harness settings (backup +
/// validate + never-clobber), and refuses on identity blur.
pub fn setup_agent_claude_code(
    paths: &SigningPaths,
    agent_name: Option<&str>,
    agent_email: Option<&str>,
    apply: bool,
) -> Result<SetupReport> {
    let mut r = SetupReport::default();

    // Resolve the agent identity: explicit flags win; else keep what's already
    // configured; else we cannot invent it → guide.
    let existing = std::fs::read_to_string(&paths.agent_settings)
        .ok()
        .and_then(|s| agent_env_git_config(&s));
    let name = agent_name
        .map(str::to_string)
        .or_else(|| existing.as_ref().and_then(|m| m.get("user.name").cloned()));
    let email = agent_email
        .map(str::to_string)
        .or_else(|| existing.as_ref().and_then(|m| m.get("user.email").cloned()));
    let (Some(name), Some(email)) = (name, email) else {
        r.guide(GuidedStep {
            title: "Choose the agent's commit identity, then re-run".into(),
            why: "The agent must author as ITSELF, never as you. sscsb won't invent your \
                  identity strings."
                .into(),
            actions: vec![
                "Pick a name + an email that is NOT a verified email on your GitHub account".into(),
                "Re-run: sscsb signing setup agent-claude-code --agent-name '<name>' \
                 --agent-email '<email>'"
                    .into(),
            ],
            confirm: "sscsb signing status → agent-claude-code shows the distinct identity".into(),
        });
        return Ok(r);
    };

    // Identity-blur guard: refuse if the agent email/name matches the human's.
    let human_email = git_global("user.email").unwrap_or_default();
    if !human_email.is_empty() && email == human_email {
        r.refused = Some(format!(
            "REFUSED: agent email '{email}' equals your human git email — that would forge \
             your identity onto AI commits. Choose a distinct --agent-email."
        ));
        return Ok(r);
    }

    // Agent key: generate an ed25519 file-backed key if absent.
    let key_path = paths.home.join(".ssh/jai_agent_signing_key");
    let pub_path = paths.home.join(".ssh/jai_agent_signing_key.pub");
    if key_path.exists() {
        r.note_already(format!("agent key already present: {}", key_path.display()));
    } else if apply {
        std::fs::create_dir_all(paths.home.join(".ssh")).ok();
        let comment = format!("agent-signing <{email}>");
        let out = exec::run(
            "ssh-keygen",
            &[
                "-t",
                "ed25519",
                "-f",
                &key_path.to_string_lossy(),
                "-N",
                "",
                "-C",
                &comment,
                "-q",
            ],
            None,
        )?;
        if !out.success() {
            anyhow::bail!("ssh-keygen failed: {}", out.stderr.trim());
        }
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o600);
        }
        std::fs::set_permissions(&key_path, perms).ok();
        r.note_changed(format!(
            "generated agent ed25519 key → {}",
            key_path.display()
        ));
    } else {
        r.note_changed(format!(
            "[dry-run] would generate agent key → {}",
            key_path.display()
        ));
    }

    // Merge the identity+signing env into the harness settings (backup +
    // validate + never-clobber).
    let desired: Vec<(&str, &str)> = vec![
        ("user.signingkey", key_path.to_str().unwrap_or_default()),
        ("commit.gpgsign", "true"),
        ("user.name", name.as_str()),
        ("user.email", email.as_str()),
    ];
    let existing_json =
        std::fs::read_to_string(&paths.agent_settings).unwrap_or_else(|_| "{}".into());
    match merge_git_config_env(&existing_json, &desired)? {
        None => r.note_already("agent settings already carry the exact signing identity"),
        Some(merged) => {
            // Validate the merge parses back to the intended block before writing.
            let check = agent_env_git_config(&merged)
                .ok_or_else(|| anyhow::anyhow!("internal: merged settings failed re-parse"))?;
            anyhow::ensure!(
                check.get("user.email").map(String::as_str) == Some(email.as_str()),
                "internal: merge did not preserve agent identity"
            );
            if apply {
                if paths.agent_settings.exists() {
                    let backup = paths.agent_settings.with_extension("json.sscsb-backup");
                    std::fs::copy(&paths.agent_settings, &backup)?;
                    r.note_changed(format!("backed up settings → {}", backup.display()));
                }
                if let Some(parent) = paths.agent_settings.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&paths.agent_settings, &merged)?;
                // Read-back validation.
                let after = std::fs::read_to_string(&paths.agent_settings)?;
                anyhow::ensure!(
                    agent_env_git_config(&after)
                        .and_then(|m| m.get("user.email").cloned())
                        .as_deref()
                        == Some(email.as_str()),
                    "settings write did not round-trip the agent identity"
                );
                r.note_changed(format!(
                    "merged agent identity into {} (name='{name}', email='{email}')",
                    paths.agent_settings.display()
                ));
            } else {
                r.note_changed(format!(
                    "[dry-run] would merge agent identity into {}",
                    paths.agent_settings.display()
                ));
            }
        }
    }

    // allowed_signers entry for the agent (its own email, never the human's).
    let allowed = paths.home.join(".ssh/allowed_signers");
    let pubkey = std::fs::read_to_string(&pub_path)
        .ok()
        .map(|s| s.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
    match pubkey {
        Some(pk) => {
            let line = format!("{email} {pk}");
            let already = std::fs::read_to_string(&allowed)
                .map(|c| {
                    c.contains(&email) && c.contains(pk.split_whitespace().nth(1).unwrap_or(""))
                })
                .unwrap_or(false);
            if already {
                r.note_already("allowed_signers already maps the agent identity");
            } else if apply {
                let mut content = std::fs::read_to_string(&allowed).unwrap_or_default();
                if !content.is_empty() && !content.ends_with('\n') {
                    content.push('\n');
                }
                content.push_str(&format!(
                    "# ai agent — signs as ITSELF; never maps to a human address\n{line}\n"
                ));
                std::fs::write(&allowed, content)?;
                r.note_changed(format!("added agent principal to {}", allowed.display()));
            } else {
                r.note_changed("[dry-run] would add agent principal to allowed_signers");
            }
        }
        None => r.guide(GuidedStep {
            title: "Agent public key not readable yet".into(),
            why: "allowed_signers needs the agent pubkey to make its signatures locally \
                  verifiable as the agent."
                .into(),
            actions: vec!["Re-run setup after the agent key is generated".into()],
            confirm: "git log --show-signature shows 'Good signature for <agent-email>'".into(),
        }),
    }

    // Reminder invariant (guided, always): never register the agent key on the
    // human's GitHub account.
    r.guide(GuidedStep {
        title: "Do NOT register the agent key on your GitHub account".into(),
        why: "Registering it would badge AI commits as YOUR verified commits. The agent \
              staying 'Unverified' on GitHub is the correct, honest state."
            .into(),
        actions: vec![
            "Leave the agent key unregistered".into(),
            "(Optional) enable GitHub vigilant mode so genuinely-unsigned commits under your \
             email are flagged"
                .into(),
        ],
        confirm: "gh api user/ssh_signing_keys does NOT list the agent key".into(),
    });

    Ok(r)
}

fn print_setup_report(env: Environment, r: &SetupReport) -> i32 {
    println!("sscsb signing setup — {}\n", env.label());
    if let Some(refusal) = &r.refused {
        println!("  ✗ {refusal}");
        return 1;
    }
    for a in &r.already {
        println!("  · {a}");
    }
    for c in &r.changed {
        println!("  ✓ {c}");
    }
    if !r.guided.is_empty() {
        println!(
            "\n  Manual steps sscsb cannot perform for you (do these, then re-run \
                  `sscsb signing status`):"
        );
        for (i, g) in r.guided.iter().enumerate() {
            println!("\n  {}. {}", i + 1, g.title);
            println!("     why: {}", g.why);
            for act in &g.actions {
                println!("       $ {act}");
            }
            println!("     confirm: {}", g.confirm);
        }
    }
    0
}

// ───────────────────────────── CLI: status ──────────────────────────────────

/// `sscsb signing setup <env>`. Local lanes converge programmatically; the
/// cloud/web/Codespaces lanes are guided (Slice 3/4 add their attestation
/// recording — until then they surface the numbered steps).
#[allow(clippy::too_many_arguments)]
pub fn cmd_signing_setup(
    ctx: &Ctx,
    env_id: &str,
    apply: bool,
    agent_name: Option<&str>,
    agent_email: Option<&str>,
    confirm: bool,
) -> Result<i32> {
    let paths = SigningPaths::real()?;
    let Some(env) = Environment::from_id(env_id) else {
        eprintln!(
            "unknown environment `{env_id}` — one of: {}",
            Environment::ALL
                .iter()
                .map(|e| e.id())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(2);
    };
    let report = match env {
        Environment::HumanLocal => setup_human_local(&paths, apply)?,
        Environment::AgentClaudeCode => {
            setup_agent_claude_code(&paths, agent_name, agent_email, apply)?
        }
        Environment::CloudClaude => setup_cloud_claude(ctx, apply)?,
        Environment::GithubWeb | Environment::Codespaces => guided_lane_report(ctx, env),
    };
    if report.refused.is_some() {
        return Ok(print_setup_report(env, &report));
    }
    let code = print_setup_report(env, &report);
    // --confirm stamps the guided lane's attestations with today's date.
    if confirm && !lane_attestation_keys(env).is_empty() {
        if apply {
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            record_lane_attestation(ctx, env, &today)?;
            println!(
                "\n  ✓ recorded {} attestation(s) for `{}` dated {today}",
                lane_attestation_keys(env).len(),
                env.id(),
            );
        } else {
            println!(
                "\n  [dry-run] --confirm would record today's date for `{}`",
                env.id()
            );
        }
    }
    Ok(code)
}

/// E3 cloud: write the repo-level `.claude/settings.json` attribution block
/// (the one thing that syncs to cloud containers), then guide App auth.
pub fn setup_cloud_claude(ctx: &Ctx, apply: bool) -> Result<SetupReport> {
    let mut r = SetupReport::default();
    let repo_settings = ctx.root.join(".claude/settings.json");
    let existing = std::fs::read_to_string(&repo_settings).unwrap_or_default();
    let has_attr = serde_json::from_str::<serde_json::Value>(&existing)
        .ok()
        .and_then(|v| v.get("attribution").cloned())
        .is_some();
    if has_attr {
        r.note_already(".claude/settings.json already has an attribution block");
    } else if apply {
        let mut root: serde_json::Value = if existing.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&existing)
                .map_err(|e| anyhow::anyhow!("repo .claude/settings.json is not valid JSON: {e}"))?
        };
        root.as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("repo .claude/settings.json root is not an object"))?
            .insert(
                "attribution".into(),
                serde_json::json!({ "sessionUrl": true }),
            );
        if let Some(parent) = repo_settings.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = serde_json::to_string_pretty(&root)?;
        out.push('\n');
        std::fs::write(&repo_settings, out)?;
        r.note_changed(format!(
            "wrote attribution block → {} (syncs the Claude-Session trailer to cloud)",
            repo_settings.display()
        ));
    } else {
        r.note_changed("[dry-run] would write .claude/settings.json attribution block");
    }
    r.guide(GuidedStep {
        title: "Authorize the Claude GitHub App (not a personal token)".into(),
        why: "Cloud containers can't hold keys. The App gives cloud work a DISTINCT bot \
              identity, Verified-as-bot (never as you); a personal token via /web-setup would \
              attribute cloud commits to you."
            .into(),
        actions: vec![
            "At claude.ai/code, authorize the Claude GitHub App for this repo".into(),
            "Choose signing mode: App-signed (Verified-as-bot, no rebase) or unsigned drafts"
                .into(),
            "Protect `main` so cloud work lands via a human-tapped merge".into(),
            "Then: sscsb signing setup cloud-claude --confirm".into(),
        ],
        confirm: "cloud PR commits show the bot identity, never p4gs".into(),
    });
    Ok(r)
}

/// E4/E5 guided lanes: numbered steps for web toggles with no API.
fn guided_lane_report(ctx: &Ctx, env: Environment) -> SetupReport {
    let mut r = SetupReport::default();
    if let Ok(p) = SigningPaths::real() {
        for d in probe_env(ctx, &p, env).details {
            r.note_already(d);
        }
    }
    match env {
        Environment::GithubWeb => {
            r.guide(GuidedStep {
                title: "Harden the account anchor: phishing-resistant MFA".into(),
                why: "Web / mobile commits are signed by GitHub's web-flow key and show \
                      Verified-as-you — their security rests entirely on your account. A \
                      passkey / hardware key is the control."
                    .into(),
                actions: vec![
                    "GitHub → Settings → Password and authentication → add a passkey or \
                     security key (WebAuthn)"
                        .into(),
                ],
                confirm: "your account requires a phishing-resistant factor".into(),
            });
            r.guide(GuidedStep {
                title: "Enable vigilant mode".into(),
                why: "Flags any genuinely-unsigned commit under your email as Unverified — \
                      catches an attacker pushing unsigned commits as you."
                    .into(),
                actions: vec![
                    "GitHub → Settings → SSH and GPG keys → 'Flag unsigned commits as \
                     unverified' → enable"
                        .into(),
                    "Then: sscsb signing setup github-web --confirm".into(),
                ],
                confirm: "sscsb signing verify shows github-web attested".into(),
            });
        }
        Environment::Codespaces => {
            r.guide(GuidedStep {
                title: "Enable Codespaces GPG verification for TRUSTED repos only".into(),
                why: "Lets GitHub sign your codespace commits (Verified-as-you) without any \
                      private key entering the codespace."
                    .into(),
                actions: vec![
                    "GitHub → Settings → Codespaces → GPG verification → enable for a SELECTED \
                     trusted-repo list (never 'all repositories')"
                        .into(),
                    "Never mount your private signing key into a codespace".into(),
                    "Then: sscsb signing setup codespaces --confirm".into(),
                ],
                confirm: "sscsb signing verify shows codespaces attested".into(),
            });
        }
        _ => {}
    }
    r
}

/// `sscsb signing verify` — the report card across all five lanes.
pub fn cmd_signing_verify(ctx: &Ctx) -> Result<i32> {
    let paths = SigningPaths::real()?;
    let policy = read_signing_policy(ctx);
    let today = chrono::Utc::now().date_naive();
    const STALE_DAYS: i64 = 180;

    println!("sscsb signing verify — five-environment commit-signing report card\n");
    let mut worst_fail = false;
    let mut any_pending = false;

    for env in Environment::ALL {
        let st = probe_env(ctx, &paths, env);
        let keys = lane_attestation_keys(env);
        let (verdict, extra): (&str, Vec<String>) = if !keys.is_empty() {
            let lane = policy.get(env.id()).and_then(|v| v.as_table());
            let mut lines = Vec::new();
            let mut fresh = 0usize;
            for k in keys {
                let date = lane.and_then(|t| t.get(*k)).and_then(|v| v.as_str());
                match crate::signers::evaluate_expiry(date, today, STALE_DAYS) {
                    crate::signers::ExpiryState::Unset => lines.push(format!(
                        "{k}: not attested — `sscsb signing setup {} --confirm`",
                        env.id()
                    )),
                    crate::signers::ExpiryState::Expired { days_ago } => lines.push(format!(
                        "{k}: attestation STALE ({days_ago}d old) — re-confirm"
                    )),
                    crate::signers::ExpiryState::Unparseable => lines.push(format!(
                        "{k}: attestation date unparseable (want YYYY-MM-DD)"
                    )),
                    crate::signers::ExpiryState::WindowTooLong { .. } => {
                        lines.push(format!("{k}: attested (date far in the future — check it)"));
                        fresh += 1;
                    }
                    crate::signers::ExpiryState::Valid { days_left } => {
                        lines.push(format!("{k}: attested, fresh ({days_left}d until stale)"));
                        fresh += 1;
                    }
                }
            }
            if fresh == keys.len() {
                ("ATTESTED", lines)
            } else {
                any_pending = true;
                ("PENDING", lines)
            }
        } else {
            match st.state {
                EnvState::Configured => ("PASS", st.details.clone()),
                EnvState::Partial if st.details.iter().any(|d| d.contains("IDENTITY BLUR")) => {
                    worst_fail = true;
                    ("FAIL", st.details.clone())
                }
                _ => {
                    any_pending = true;
                    ("PENDING", st.details.clone())
                }
            }
        };
        println!("[{verdict:9}] {} — {}", env.id(), env.label());
        for line in extra {
            println!("             {line}");
        }
    }

    println!("\nrecent-history classification (best-effort):");
    match classify_recent_commits(ctx) {
        Ok(lines) if !lines.is_empty() => lines.iter().for_each(|l| println!("  {l}")),
        Ok(_) => println!("  (no origin/gh — skipped)"),
        Err(e) => println!("  (skipped: {e})"),
    }

    if any_pending {
        println!(
            "\nsome lanes pending — run the `sscsb signing setup <lane>` steps above, then re-verify."
        );
    }
    Ok(if worst_fail { 1 } else { 0 })
}

/// Best-effort: label recent commits' `verification.reason` against the model.
fn classify_recent_commits(ctx: &Ctx) -> Result<Vec<String>> {
    let slug = ctx
        .config
        .as_ref()
        .and_then(|c| c.github_repo())
        .or_else(|| ctx.origin_slug());
    let Some(slug) = slug else {
        return Ok(vec![]);
    };
    if !crate::tools::is_available("gh") {
        return Ok(vec![]);
    }
    let out = exec::run(
        "gh",
        &[
            "api",
            &format!("repos/{slug}/commits?per_page=8"),
            "--jq",
            r#".[] | "\(.commit.author.email)\t\(.commit.verification.verified)\t\(.commit.verification.reason)""#,
        ],
        Some(&ctx.root),
    )?;
    if !out.success() {
        return Ok(vec![]);
    }
    let mut lines = Vec::new();
    for row in out.stdout.lines().take(8) {
        let cols: Vec<&str> = row.split('\t').collect();
        if cols.len() < 3 {
            continue;
        }
        let (email, verified, reason) = (cols[0], cols[1], cols[2]);
        let label = match (verified, reason) {
            ("true", "valid") => "verified (human key or web-flow — expected for human lanes)",
            (_, "unsigned") => "unsigned — expected only for cloud drafts; a FAILURE elsewhere",
            (_, "unknown_key") => "signed by an unregistered key — expected for the agent lane",
            _ => "other",
        };
        lines.push(format!("{email}: {reason} → {label}"));
    }
    Ok(lines)
}

pub fn cmd_signing_status(ctx: &Ctx) -> Result<i32> {
    let paths = SigningPaths::real()?;
    println!("sscsb signing status — the five-environment commit-signing model");
    println!("(actor → signer per environment; agent NEVER signs as the human)\n");
    for env in Environment::ALL {
        let st = probe_env(ctx, &paths, env);
        println!("[{:10}] {} — {}", st.state.symbol(), env.id(), env.label());
        for d in &st.details {
            println!("             {d}");
        }
    }
    println!(
        "\nnext: `sscsb signing setup <env>` converges an environment (programmatic where \
         possible, numbered guided steps where a UI is technically required)."
    );
    Ok(0)
}

// ─────────────────────────── control verifier ───────────────────────────────

/// `sscsb verify signing-model`: the machine-level signing posture.
///
/// Outcome semantics match the house pattern set by `commit-signing`: an
/// UNCONFIGURED lane degrades loudly (strict mode still gates it) — Fail is
/// reserved for actual VIOLATIONS of the model, of which there is exactly one
/// probeable class today: identity blur, the agent signing/authoring as the
/// human. Absence is a to-do; blur is a breach.
pub fn verify_signing_model_control(ctx: &Ctx, _cfg: &Config) -> VerifyResult {
    let paths = match SigningPaths::real() {
        Ok(p) => p,
        Err(e) => {
            return VerifyResult::new(CONTROL, Outcome::Degraded, vec![format!("{e:#}")]);
        }
    };
    let mut messages = Vec::new();
    let mut violation = false;
    let mut pending = false;

    for env in Environment::ALL {
        let st = probe_env(ctx, &paths, env);
        match &st.state {
            EnvState::Configured => {
                messages.push(format!("{}: configured", env.id()));
            }
            EnvState::Partial => {
                if st.details.iter().any(|d| d.contains("IDENTITY BLUR")) {
                    violation = true;
                    for d in &st.details {
                        messages.push(format!("{}: {d}", env.id()));
                    }
                } else {
                    pending = true;
                    messages.push(format!(
                        "{}: incomplete — run `sscsb signing setup {}`",
                        env.id(),
                        env.id()
                    ));
                }
            }
            EnvState::GuidedPending => {
                pending = true;
                messages.push(format!(
                    "{}: pending guided setup (`sscsb signing setup {}`)",
                    env.id(),
                    env.id()
                ));
            }
            EnvState::Unknown(reason) => {
                pending = true;
                messages.push(format!("{}: {reason}", env.id()));
            }
        }
    }

    let outcome = if violation {
        Outcome::Fail
    } else if pending {
        Outcome::Degraded
    } else {
        Outcome::Pass
    };
    VerifyResult::new(CONTROL, outcome, messages)
}

// ──────────────────────────────── tests ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_home(dir: &Path) -> SigningPaths {
        SigningPaths::from_home(dir)
    }

    #[test]
    fn environment_ids_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for env in Environment::ALL {
            assert!(seen.insert(env.id()), "duplicate env id {}", env.id());
            assert_eq!(Environment::from_id(env.id()), Some(env));
            assert!(!env.label().is_empty());
        }
        assert_eq!(Environment::from_id("nope"), None);
    }

    #[test]
    fn agent_probe_reports_missing_settings_as_partial_with_pointer() {
        let tmp = tempfile::tempdir().unwrap();
        let st = probe_agent_claude_code(&fixture_home(tmp.path()));
        assert_eq!(st.state, EnvState::Partial);
        assert!(st.details[0].contains("agent settings not found"));
    }

    #[test]
    fn agent_probe_flags_settings_without_git_env_as_identity_blur_risk() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(claude.join("settings.json"), r#"{"env":{}}"#).unwrap();
        let st = probe_agent_claude_code(&fixture_home(tmp.path()));
        assert_eq!(st.state, EnvState::Partial);
        assert!(st.details[0].contains("no GIT_CONFIG_* env block"));
    }

    #[test]
    fn agent_probe_configured_when_distinct_key_email_and_gpgsign_present() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let key = tmp.path().join("agent_key");
        std::fs::write(&key, "fake-private-key-material-for-path-probe-only").unwrap();
        let settings = serde_json::json!({
            "env": {
                "GIT_CONFIG_COUNT": "3",
                "GIT_CONFIG_KEY_0": "user.signingkey",
                "GIT_CONFIG_VALUE_0": key.to_string_lossy(),
                "GIT_CONFIG_KEY_1": "commit.gpgsign",
                "GIT_CONFIG_VALUE_1": "true",
                "GIT_CONFIG_KEY_2": "user.email",
                "GIT_CONFIG_VALUE_2": "agent@example.invalid",
            }
        });
        std::fs::write(claude.join("settings.json"), settings.to_string()).unwrap();
        let st = probe_agent_claude_code(&fixture_home(tmp.path()));
        // Human globals on the machine running tests may vary; the probe must
        // never claim blur for a distinct example.invalid identity.
        assert!(
            st.details.iter().all(|d| !d.contains("IDENTITY BLUR")),
            "{:?}",
            st.details
        );
        assert!(st
            .details
            .iter()
            .any(|d| d.contains("agent identity: agent@example.invalid")));
    }

    #[test]
    fn agent_env_git_config_parses_count_gated_pairs_only() {
        let s = serde_json::json!({
            "env": {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "user.email",
                "GIT_CONFIG_VALUE_0": "a@b.c",
                "GIT_CONFIG_KEY_1": "ignored.beyond.count",
                "GIT_CONFIG_VALUE_1": "x",
            }
        })
        .to_string();
        let map = agent_env_git_config(&s).unwrap();
        assert_eq!(map.get("user.email").map(String::as_str), Some("a@b.c"));
        assert!(!map.contains_key("ignored.beyond.count"));
    }

    #[test]
    fn agent_env_git_config_rejects_malformed_blocks() {
        assert!(agent_env_git_config("not json").is_none());
        assert!(agent_env_git_config(
            r#"{"env":{"GIT_CONFIG_COUNT":"2","GIT_CONFIG_KEY_0":"k","GIT_CONFIG_VALUE_0":"v"}}"#
        )
        .is_none());
    }

    #[test]
    fn codespaces_and_missing_repo_settings_report_guided_pending() {
        let tmp = tempfile::tempdir().unwrap();
        // A bare Ctx over a scratch git-less dir is fine for these probes.
        let ctx = Ctx {
            root: tmp.path().to_path_buf(),
            platform: crate::platform::Platform::detect(),
            config: None,
        };
        assert_eq!(probe_codespaces(&ctx).state, EnvState::GuidedPending);
        assert_eq!(probe_cloud_claude(&ctx).state, EnvState::GuidedPending);
    }

    #[test]
    fn merge_git_config_env_preserves_other_keys_and_env_vars() {
        let existing = serde_json::json!({
            "model": "Fable",
            "env": {
                "PAI_DIR": "/x",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "old.key",
                "GIT_CONFIG_VALUE_0": "old",
            }
        })
        .to_string();
        let merged = merge_git_config_env(
            &existing,
            &[("user.email", "a@b.c"), ("commit.gpgsign", "true")],
        )
        .unwrap()
        .expect("changed");
        let v: serde_json::Value = serde_json::from_str(&merged).unwrap();
        // Untouched keys survive.
        assert_eq!(v["model"], "Fable");
        assert_eq!(v["env"]["PAI_DIR"], "/x");
        // Stale GIT_CONFIG_ pair is gone; new block is exact.
        assert_eq!(v["env"]["GIT_CONFIG_COUNT"], "2");
        assert!(v["env"].get("old.key").is_none());
        let parsed = agent_env_git_config(&merged).unwrap();
        assert_eq!(parsed.get("user.email").map(String::as_str), Some("a@b.c"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn merge_git_config_env_is_idempotent() {
        let existing = serde_json::json!({
            "env": {
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "user.email",
                "GIT_CONFIG_VALUE_0": "a@b.c",
                "GIT_CONFIG_KEY_1": "commit.gpgsign",
                "GIT_CONFIG_VALUE_1": "true",
            }
        })
        .to_string();
        // Same pairs (order-independent via the BTreeMap compare) → no write.
        let out = merge_git_config_env(
            &existing,
            &[("commit.gpgsign", "true"), ("user.email", "a@b.c")],
        )
        .unwrap();
        assert!(out.is_none(), "identical desired block must not rewrite");
    }

    #[test]
    fn merge_git_config_env_rejects_malformed_json() {
        assert!(merge_git_config_env("{not json", &[("a", "b")]).is_err());
        assert!(merge_git_config_env(r#"["array root"]"#, &[("a", "b")]).is_err());
    }

    #[test]
    fn merge_git_config_env_seeds_empty_settings() {
        let out = merge_git_config_env("", &[("user.email", "x@y.z")])
            .unwrap()
            .unwrap();
        let parsed = agent_env_git_config(&out).unwrap();
        assert_eq!(parsed.get("user.email").map(String::as_str), Some("x@y.z"));
    }

    #[test]
    fn setup_agent_refuses_identity_blur_and_writes_nothing() {
        // Force a known human email so the guard has something to compare to.
        let tmp = tempfile::tempdir().unwrap();
        let paths = fixture_home(tmp.path());
        // The human email is read from the real machine's git global; to keep
        // this hermetic we assert the guard logic directly on a matching value
        // only when a human email is actually configured.
        if let Some(human) = git_global("user.email") {
            let r = setup_agent_claude_code(
                &paths,
                Some("Blur"),
                Some(&human),
                false, // dry-run — must never write regardless
            )
            .unwrap();
            assert!(r.refused.is_some(), "must refuse agent==human email");
            assert!(r.changed.is_empty());
            assert!(!paths.agent_settings.exists(), "must not create settings");
        }
    }

    #[test]
    fn setup_agent_guides_when_identity_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = fixture_home(tmp.path());
        // No flags, no existing settings → cannot invent identity → guided.
        let r = setup_agent_claude_code(&paths, None, None, false).unwrap();
        assert!(r.refused.is_none());
        assert!(r
            .guided
            .iter()
            .any(|g| g.title.contains("Choose the agent's commit identity")));
        assert!(!paths.agent_settings.exists());
    }

    #[test]
    fn record_and_read_lane_attestation_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        // Minimal git repo so Ctx::discover-style paths resolve; we build Ctx directly.
        let ctx = Ctx {
            root: tmp.path().to_path_buf(),
            platform: crate::platform::Platform::detect(),
            config: None,
        };
        record_lane_attestation(&ctx, Environment::GithubWeb, "2026-07-19").unwrap();
        let policy = read_signing_policy(&ctx);
        let lane = policy.get("github-web").and_then(|v| v.as_table()).unwrap();
        assert_eq!(
            lane.get("vigilant_mode").and_then(|v| v.as_str()),
            Some("2026-07-19")
        );
        assert_eq!(
            lane.get("phishing_resistant_mfa").and_then(|v| v.as_str()),
            Some("2026-07-19")
        );
    }

    #[test]
    fn record_lane_attestation_preserves_other_lanes() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = Ctx {
            root: tmp.path().to_path_buf(),
            platform: crate::platform::Platform::detect(),
            config: None,
        };
        record_lane_attestation(&ctx, Environment::Codespaces, "2026-01-01").unwrap();
        record_lane_attestation(&ctx, Environment::GithubWeb, "2026-07-19").unwrap();
        let policy = read_signing_policy(&ctx);
        // The earlier codespaces stamp must survive the github-web write.
        assert_eq!(
            policy
                .get("codespaces")
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("gpg_verification"))
                .and_then(|v| v.as_str()),
            Some("2026-01-01")
        );
    }

    #[test]
    fn lane_attestation_keys_match_the_template_lanes() {
        // Local lanes carry no attestations; the three guided lanes do.
        assert!(lane_attestation_keys(Environment::HumanLocal).is_empty());
        assert!(lane_attestation_keys(Environment::AgentClaudeCode).is_empty());
        assert!(!lane_attestation_keys(Environment::GithubWeb).is_empty());
        assert!(!lane_attestation_keys(Environment::Codespaces).is_empty());
        assert!(!lane_attestation_keys(Environment::CloudClaude).is_empty());
    }

    #[test]
    fn setup_agent_dry_run_makes_no_filesystem_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = fixture_home(tmp.path());
        let r = setup_agent_claude_code(
            &paths,
            Some("Agent"),
            Some("agent@example.invalid"),
            false, // dry-run
        )
        .unwrap();
        assert!(r.refused.is_none());
        assert!(!paths.agent_settings.exists(), "dry-run wrote settings");
        assert!(
            !paths.home.join(".ssh/jai_agent_signing_key").exists(),
            "dry-run generated a key"
        );
        assert!(r.changed.iter().any(|c| c.contains("[dry-run]")));
    }

    #[test]
    fn cloud_probe_recognizes_attribution_block() {
        let tmp = tempfile::tempdir().unwrap();
        let dot = tmp.path().join(".claude");
        std::fs::create_dir_all(&dot).unwrap();
        std::fs::write(
            dot.join("settings.json"),
            r#"{"attribution":{"sessionUrl":true}}"#,
        )
        .unwrap();
        let ctx = Ctx {
            root: tmp.path().to_path_buf(),
            platform: crate::platform::Platform::detect(),
            config: None,
        };
        let st = probe_cloud_claude(&ctx);
        assert_eq!(st.state, EnvState::Configured);
    }
}
