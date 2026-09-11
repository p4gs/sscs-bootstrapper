//! Phase 6 — distribution & publishing: the registry door, and the maintainer
//! account behind it.
//!
//! Phases 1–5 harden the repository, its dependencies, its CI, and the
//! artifacts a GitHub Release carries. None of that covers the moment the
//! artifact leaves for crates.io, npm, PyPI, Homebrew, Chocolatey, or WinGet —
//! nor the credential that lets it. That gap is the Shai-Hulud / chalk-debug
//! attack class in one sentence: phish a maintainer, steal a long-lived
//! publish token, ship malware under a name people already trust. No commit is
//! involved, so every control in phases 1–5 is looking the other way.
//!
//! The far-left move is to delete the credential. Trusted Publishing (OIDC)
//! is GA on crates.io, npm, and PyPI, and where it is in force there is no
//! token in the repository to steal. Where it is not — Chocolatey's push key,
//! a deliberately-kept npm granular token — the policy file records the
//! compensating facts (scope, CIDR allowlist, expiry) and sscsb evaluates the
//! expiry the same way [`crate::signers`] evaluates an agent key's.
//!
//! Two invariants this module inherits rather than reinvents:
//!
//! - **Undetected target ⇒ silence.** A repo with no `package.json` is not a
//!   repo failing its npm publishing posture. Every verifier here skips a
//!   target it cannot see, and a repo that publishes nothing gets `Info`, not
//!   a wall of red. A false positive costs more than a disclosed miss.
//! - **Attestations document; they never upgrade an outcome.** `[[account]]`
//!   and `[[token]]` entries are self-declared, so a fresh one is *reported*
//!   and an expired one FAILS — the ISC-A6 rule from [`crate::signers`],
//!   reusing that module's [`crate::signers::evaluate_expiry`] and
//!   [`crate::signers::evaluate_attestation`] rather than a second copy.
//!
//! Detection is file-based and offline. The only network in this module is
//! `publish-provenance`'s registry probe, which is on by default (owner
//! decision), bounded by the same 10-second `ureq` timeout
//! [`crate::deps::registry_exists`] uses, and switched off wholesale with
//! `probe_registry = false` for an air-gapped lane.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::signers::{evaluate_expiry, ExpiryState};
use anyhow::{Context as _, Result};
use chrono::NaiveDate;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

// ───────────────────────────── publish targets ──────────────────────────────

/// A registry this repository PUBLISHES to.
///
/// Deliberately distinct from [`crate::deps::Ecosystem`], which is what the
/// repository *consumes*. A Rust project that vendors npm dependencies
/// consumes npm and publishes to crates.io, and conflating the two would point
/// every publishing control at the wrong registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublishTarget {
    CratesIo,
    Npm,
    PyPi,
    Homebrew,
    Chocolatey,
    WinGet,
}

/// Every target, in the order reports render them.
pub const ALL_TARGETS: &[PublishTarget] = &[
    PublishTarget::CratesIo,
    PublishTarget::Npm,
    PublishTarget::PyPi,
    PublishTarget::Homebrew,
    PublishTarget::Chocolatey,
    PublishTarget::WinGet,
];

impl PublishTarget {
    /// The id used in `distribution.toml` and in every message.
    pub fn id(self) -> &'static str {
        match self {
            PublishTarget::CratesIo => "crates-io",
            PublishTarget::Npm => "npm",
            PublishTarget::PyPi => "pypi",
            PublishTarget::Homebrew => "homebrew",
            PublishTarget::Chocolatey => "chocolatey",
            PublishTarget::WinGet => "winget",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        ALL_TARGETS.iter().copied().find(|t| t.id() == id)
    }

    /// Human-readable registry name.
    pub fn registry(self) -> &'static str {
        match self {
            PublishTarget::CratesIo => "crates.io",
            PublishTarget::Npm => "npm",
            PublishTarget::PyPi => "PyPI",
            PublishTarget::Homebrew => "Homebrew",
            PublishTarget::Chocolatey => "Chocolatey",
            PublishTarget::WinGet => "WinGet",
        }
    }

    /// Whether the registry supports Trusted Publishing (OIDC) today. Only
    /// these three get a publish template and a `trusted-publishing` verdict;
    /// Homebrew and WinGet publish by pull request (a GitHub identity, covered
    /// by `maintainer-mfa`), and Chocolatey has no OIDC path at all.
    pub fn oidc_capable(self) -> bool {
        matches!(
            self,
            PublishTarget::CratesIo | PublishTarget::Npm | PublishTarget::PyPi
        )
    }

    /// The publish workflow sscsb installs for this target, if any.
    pub fn template(self) -> Option<&'static str> {
        match self {
            PublishTarget::CratesIo => Some(".github/workflows/publish-crates.yml"),
            PublishTarget::Npm => Some(".github/workflows/publish-npm.yml"),
            PublishTarget::PyPi => Some(".github/workflows/publish-pypi.yml"),
            _ => None,
        }
    }

    /// Secret names that mean "a long-lived registry credential lives in this
    /// repository" for this target. Presence in a publish workflow where an
    /// OIDC path exists is a `publish-tokens` failure.
    pub fn token_secrets(self) -> &'static [&'static str] {
        match self {
            PublishTarget::CratesIo => &["CARGO_REGISTRY_TOKEN", "CRATES_IO_TOKEN"],
            PublishTarget::Npm => &["NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN"],
            PublishTarget::PyPi => &["PYPI_API_TOKEN", "TWINE_PASSWORD", "PYPI_TOKEN"],
            PublishTarget::Chocolatey => &["CHOCO_API_KEY", "CHOCOLATEY_API_KEY"],
            PublishTarget::Homebrew | PublishTarget::WinGet => &[],
        }
    }
}

/// One detected publish target and the file that proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTarget {
    pub target: PublishTarget,
    /// Repo-relative path of the manifest that triggered detection.
    pub manifest: String,
    /// The package name, where the manifest states one — the key the registry
    /// probe needs.
    pub package: Option<String>,
}

/// How `[targets]` in `distribution.toml` may override detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetMode {
    /// Believe the filesystem (the default).
    Auto,
    /// Treat as published regardless of what the filesystem says.
    On,
    /// Never report, whatever the filesystem says.
    Off,
}

// ───────────────────────────────── detection ────────────────────────────────

/// How many directory levels below the repository root detection descends.
///
/// TWO, not one, and the difference is the whole point: the conventional
/// monorepo shapes are `packages/<name>/package.json` and
/// `crates/<name>/Cargo.toml`, which sit two directories down, under a
/// container directory that holds no manifest of its own. Stopping at one
/// level reads those repositories as publishing nothing — a silent miss in
/// exactly the layout most likely to publish several packages at once.
///
/// Deeper nesting is a documented v1 limitation rather than a resolver: a
/// maintainer whose manifests live further down declares the target under
/// `[targets]`, and `sscsb dist status` says what was searched.
const SCAN_DEPTH: usize = 2;

/// Directories detection never descends into — build output and vendored
/// dependencies, where a `package.json` says nothing about what THIS
/// repository publishes.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".sscsb",
];

/// The `manifest` of a target that exists only because `[targets]` says so.
///
/// Not a path, and every consumer has to know that. A tap whose formulae live
/// in another repository is a real publish target with nothing local to read,
/// so a checksum check that treated this string as a filename would report
/// "could not read distribution.toml [targets] override" — a degrade caused
/// entirely by the tool misreading its own sentinel.
pub const OVERRIDE_MANIFEST: &str = "distribution.toml [targets] override";

/// Detect every publish target in `root`, honouring `[targets]` overrides.
///
/// Filesystem errors are not detection failures to swallow: an unreadable tree
/// means the answer is unknown, and the caller degrades rather than reporting
/// "no targets".
pub fn detect_targets(root: &Path, overrides: &Policy) -> Result<Vec<DetectedTarget>> {
    let mut found: Vec<DetectedTarget> = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    for _ in 0..=SCAN_DEPTH {
        let mut next = Vec::new();
        for dir in &dirs {
            let entries = std::fs::read_dir(dir)
                .with_context(|| format!("reading {}", dir.display()))?
                .collect::<std::io::Result<Vec<_>>>()
                .with_context(|| format!("listing {}", dir.display()))?;
            for entry in entries {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if path.is_dir() {
                    if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                        next.push(path);
                    }
                    continue;
                }
                if let Some(d) = classify_manifest(root, &path, &name) {
                    found.push(d);
                }
            }
        }
        dirs = next;
        if dirs.is_empty() {
            break;
        }
    }
    // A `homebrew-*` repository name is a target on its own: a tap whose
    // formulae live anywhere in the tree still publishes through Homebrew.
    if let Some(dir_name) = root.file_name().and_then(|n| n.to_str()) {
        if dir_name.starts_with("homebrew-")
            && !found.iter().any(|d| d.target == PublishTarget::Homebrew)
        {
            found.push(DetectedTarget {
                target: PublishTarget::Homebrew,
                manifest: dir_name.to_string(),
                package: Some(dir_name.trim_start_matches("homebrew-").to_string()),
            });
        }
    }
    found.sort_by(|a, b| (a.target, &a.manifest).cmp(&(b.target, &b.manifest)));
    found.dedup_by(|a, b| a.target == b.target && a.manifest == b.manifest);

    // Apply overrides last, so `off` silences a real detection and `on` adds a
    // target the filesystem cannot show (a formula living in another repo).
    found.retain(|d| overrides.target_mode(d.target) != TargetMode::Off);
    for target in ALL_TARGETS {
        if overrides.target_mode(*target) == TargetMode::On
            && !found.iter().any(|d| d.target == *target)
        {
            found.push(DetectedTarget {
                target: *target,
                manifest: OVERRIDE_MANIFEST.to_string(),
                package: None,
            });
        }
    }
    found.sort_by(|a, b| (a.target, &a.manifest).cmp(&(b.target, &b.manifest)));
    Ok(found)
}

/// Classify one file as a publish-target manifest, or not.
fn classify_manifest(root: &Path, path: &Path, name: &str) -> Option<DetectedTarget> {
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let read = || std::fs::read_to_string(path).ok();
    match name {
        "Cargo.toml" => {
            let text = read()?;
            // A pure `[workspace]` manifest publishes nothing; the member
            // crates one level down carry their own `[package]`.
            cargo_package_name(&text).map(|pkg| DetectedTarget {
                target: PublishTarget::CratesIo,
                manifest: rel,
                package: Some(pkg),
            })
        }
        "package.json" => {
            let text = read()?;
            let v: serde_json::Value = serde_json::from_str(&text).ok()?;
            if v.get("private").and_then(|p| p.as_bool()) == Some(true) {
                return None;
            }
            Some(DetectedTarget {
                target: PublishTarget::Npm,
                manifest: rel,
                package: v.get("name").and_then(|n| n.as_str()).map(str::to_string),
            })
        }
        "pyproject.toml" => {
            let text = read()?;
            // `[project]` is what declares a distributable package. A
            // `pyproject.toml` carrying only `[build-system]` or `[tool.ruff]`
            // configures tooling and publishes nothing.
            pyproject_package_name(&text).map(|pkg| DetectedTarget {
                target: PublishTarget::PyPi,
                manifest: rel,
                package: pkg,
            })
        }
        _ if name.ends_with(".rb")
            && (rel.starts_with("Formula/")
                || rel.starts_with("Casks/")
                || rel.starts_with("Cask/")) =>
        {
            Some(DetectedTarget {
                target: PublishTarget::Homebrew,
                manifest: rel,
                package: Some(name.trim_end_matches(".rb").to_string()),
            })
        }
        _ if name.ends_with(".nuspec") => Some(DetectedTarget {
            target: PublishTarget::Chocolatey,
            manifest: rel,
            package: Some(name.trim_end_matches(".nuspec").to_string()),
        }),
        _ if name.ends_with(".installer.yaml") => {
            let stem = name.trim_end_matches(".installer.yaml");
            Some(DetectedTarget {
                target: PublishTarget::WinGet,
                manifest: rel,
                package: Some(stem.to_string()),
            })
        }
        _ => None,
    }
}

/// `[package] name = "x"` from a Cargo manifest, or `None` when the manifest
/// declares no publishable package.
///
/// Two ways to declare nothing: no `[package]` section at all (a pure
/// `[workspace]` root), and `publish = false` / `publish = []`, which is how
/// Cargo spells "this crate is never uploaded". The second matters in practice
/// — every `cargo-fuzz` harness, every internal helper crate and every example
/// in a workspace carries it, and calling those crates.io publish targets is a
/// false positive that drags a real repository's phase-6 verdict down over a
/// crate that cannot be published even deliberately. Found by dogfooding: this
/// repository's own `fuzz/Cargo.toml` was reported as a second crates.io
/// target.
fn cargo_package_name(text: &str) -> Option<String> {
    let table: toml::Table = text.parse().ok()?;
    let pkg = table.get("package")?.as_table()?;
    match pkg.get("publish") {
        Some(toml::Value::Boolean(false)) => return None,
        // `publish = ["some-registry"]` names the registries a crate MAY go
        // to; an empty list is the same prohibition spelled the other way.
        Some(toml::Value::Array(a)) if a.is_empty() => return None,
        _ => {}
    }
    // A workspace-inherited name (`name.workspace = true`) is a name we cannot
    // resolve here; the target is still real, so report it without a package.
    Some(
        pkg.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string(),
    )
    .filter(|s| !s.is_empty())
    .or(Some(String::new()))
}

/// `[project] name = "x"` from a pyproject, or `None` when there is no
/// `[project]` table (tooling-only config).
fn pyproject_package_name(text: &str) -> Option<Option<String>> {
    let table: toml::Table = text.parse().ok()?;
    let project = table.get("project")?.as_table()?;
    Some(
        project
            .get("name")
            .and_then(|n| n.as_str())
            .map(str::to_string),
    )
}

// ──────────────────────────── distribution.toml ─────────────────────────────

/// A declared publishing account, and its self-asserted MFA posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountClaim {
    pub target: PublishTarget,
    pub identity: String,
    pub mfa: MfaClaim,
    /// `YYYY-MM-DD` the claim was last checked by a human.
    pub attested: Option<String>,
    pub attestation_file: Option<String>,
}

/// What a `[[account]]` entry claims about its MFA. No registry API exposes
/// whether a second factor is phishing-resistant, so the strongest tier is a
/// human claim — reported as a claim, never as a verified fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaClaim {
    /// WebAuthn/passkey only — no TOTP fallback left enabled.
    WebauthnOnly,
    /// WebAuthn enrolled, but a weaker factor is still accepted.
    Webauthn,
    Totp,
    None,
}

impl MfaClaim {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "webauthn-only" => Some(MfaClaim::WebauthnOnly),
            "webauthn" => Some(MfaClaim::Webauthn),
            "totp" => Some(MfaClaim::Totp),
            "none" => Some(MfaClaim::None),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            MfaClaim::WebauthnOnly => "webauthn-only",
            MfaClaim::Webauthn => "webauthn",
            MfaClaim::Totp => "totp",
            MfaClaim::None => "none",
        }
    }

    /// Phishing-resistant per CISA/OpenSSF *Principles for Package Repository
    /// Security*: only a WebAuthn factor with no weaker fallback qualifies.
    fn phishing_resistant(self) -> bool {
        self == MfaClaim::WebauthnOnly
    }
}

/// A publishing credential the maintainer has deliberately kept, with the
/// facts that make keeping it defensible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaim {
    pub target: PublishTarget,
    pub purpose: String,
    /// Scoped to specific packages rather than the whole account.
    pub scoped: bool,
    /// Restricted to a set of source addresses (npm granular tokens support
    /// CIDR allowlists).
    pub cidr_allowlist: bool,
    pub issued: Option<String>,
    pub expires: Option<String>,
    /// Where the secret actually lives (a keystore, a GitHub environment).
    pub stored_in: Option<String>,
}

/// `[signing]` — an Authenticode certificate claim. Not locally verifiable on
/// macOS or Linux, so it is recorded and its expiry evaluated, nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SigningClaim {
    pub authenticode: bool,
    pub subject: Option<String>,
    pub expires: Option<String>,
}

/// The parsed `distribution.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    modes: Vec<(PublishTarget, TargetMode)>,
    pub accounts: Vec<AccountClaim>,
    pub tokens: Vec<TokenClaim>,
    pub signing: SigningClaim,
}

impl Policy {
    pub fn target_mode(&self, target: PublishTarget) -> TargetMode {
        self.modes
            .iter()
            .find(|(t, _)| *t == target)
            .map(|(_, m)| *m)
            .unwrap_or(TargetMode::Auto)
    }

    pub fn account_for(&self, target: PublishTarget) -> Option<&AccountClaim> {
        self.accounts.iter().find(|a| a.target == target)
    }

    pub fn tokens_for(&self, target: PublishTarget) -> Vec<&TokenClaim> {
        self.tokens.iter().filter(|t| t.target == target).collect()
    }
}

pub fn policy_path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.sscsb_dir().join("policy").join("distribution.toml")
}

/// Load `distribution.toml`. An absent file is an empty policy — the file is
/// optional and a repo that never wrote one is not misconfigured. A file that
/// exists and does not parse is an ERROR, never an empty policy: the signers.rs
/// precedent, and for the same reason — silently reading a malformed policy as
/// "nothing declared" turns a typo into a missing control.
pub fn load_policy(path: &Path) -> Result<Policy> {
    if !path.is_file() {
        return Ok(Policy::default());
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_policy(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn parse_policy(text: &str) -> Result<Policy> {
    let table: toml::Table = text.parse()?;
    let mut policy = Policy::default();

    if let Some(targets) = table.get("targets") {
        let targets = targets
            .as_table()
            .context("`[targets]` must be a table of target = \"auto\"|\"on\"|\"off\"")?;
        for (key, value) in targets {
            let target = PublishTarget::from_id(key).with_context(|| {
                format!(
                    "`[targets] {key}` is not a publish target; valid: {}",
                    ALL_TARGETS
                        .iter()
                        .map(|t| t.id())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            let raw = value
                .as_str()
                .with_context(|| format!("`[targets] {key}` must be a string"))?;
            let mode = match raw.trim() {
                "auto" => TargetMode::Auto,
                "on" => TargetMode::On,
                "off" => TargetMode::Off,
                other => {
                    anyhow::bail!("`[targets] {key} = \"{other}\"` is not one of auto | on | off")
                }
            };
            policy.modes.push((target, mode));
        }
    }

    for item in array_of_tables(&table, "account")? {
        let target = claim_target(item, "account")?;
        let identity = item
            .get("identity")
            .and_then(|v| v.as_str())
            .context("`[[account]]` needs an `identity`")?
            .to_string();
        let raw_mfa = item
            .get("mfa")
            .and_then(|v| v.as_str())
            .context("`[[account]]` needs `mfa = webauthn-only | webauthn | totp | none`")?;
        let mfa = MfaClaim::parse(raw_mfa).with_context(|| {
            format!("`[[account]] mfa = \"{raw_mfa}\"` is not one of webauthn-only | webauthn | totp | none")
        })?;
        policy.accounts.push(AccountClaim {
            target,
            identity,
            mfa,
            attested: opt_date(item, "attested", "[[account]]")?,
            attestation_file: item
                .get("attestation_file")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }
    // One account per target: two entries claiming different MFA postures for
    // the same registry is an unresolvable policy, not a pair of facts.
    let mut seen = BTreeSet::new();
    for account in &policy.accounts {
        anyhow::ensure!(
            seen.insert(account.target),
            "two `[[account]]` entries for `{}` — a target has exactly one publishing account \
             posture",
            account.target.id()
        );
    }

    for item in array_of_tables(&table, "token")? {
        let target = claim_target(item, "token")?;
        policy.tokens.push(TokenClaim {
            target,
            purpose: item
                .get("purpose")
                .and_then(|v| v.as_str())
                .context("`[[token]]` needs a `purpose` saying why the token still exists")?
                .to_string(),
            scoped: item
                .get("scoped")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            cidr_allowlist: item
                .get("cidr_allowlist")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            issued: opt_date(item, "issued", "[[token]]")?,
            expires: opt_date(item, "expires", "[[token]]")?,
            stored_in: item
                .get("stored_in")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }

    if let Some(signing) = table.get("signing") {
        let signing = signing.as_table().context("`[signing]` must be a table")?;
        policy.signing = SigningClaim {
            authenticode: signing
                .get("authenticode")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            subject: signing
                .get("subject")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            expires: opt_date(signing, "expires", "[signing]")?,
        };
    }
    Ok(policy)
}

fn array_of_tables<'a>(table: &'a toml::Table, key: &str) -> Result<Vec<&'a toml::Table>> {
    let Some(value) = table.get(key) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .with_context(|| format!("`{key}` must be an array of tables (`[[{key}]]`)"))?;
    array
        .iter()
        .map(|v| {
            v.as_table()
                .with_context(|| format!("every `[[{key}]]` entry must be a table"))
        })
        .collect()
}

fn claim_target(item: &toml::Table, kind: &str) -> Result<PublishTarget> {
    let raw = item
        .get("target")
        .and_then(|v| v.as_str())
        .with_context(|| format!("`[[{kind}]]` needs a `target`"))?;
    PublishTarget::from_id(raw).with_context(|| {
        format!(
            "`[[{kind}]] target = \"{raw}\"` is not a publish target; valid: {}",
            ALL_TARGETS
                .iter()
                .map(|t| t.id())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// A `YYYY-MM-DD` field, rejected at parse time rather than silently treated as
/// "unset" later. A date nobody can read is a claim nobody can check.
fn opt_date(table: &toml::Table, key: &str, kind: &str) -> Result<Option<String>> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    // TOML parses a bare `2026-01-01` into its own date type; accept both that
    // and a quoted string, so the obvious spelling is never a parse error.
    let raw = match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Datetime(d) => d.to_string(),
        other => anyhow::bail!("`{kind} {key}` must be a YYYY-MM-DD date, found {other}"),
    };
    NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
        .with_context(|| format!("`{kind} {key} = \"{raw}\"` is not a YYYY-MM-DD date"))?;
    Ok(Some(raw.trim().to_string()))
}

/// The all-commented policy template `init` installs, in the same shape as
/// `signers.toml`: nothing is in force until a human uncomments a block, so a
/// fresh install cannot accidentally assert a posture nobody checked.
pub const DISTRIBUTION_TEMPLATE: &str = r#"# sscsb distribution & publishing policy (phase 6).
#
# Everything here is OPTIONAL and everything here is a SELF-DECLARED CLAIM.
# sscsb reports claims as claims and evaluates their expiry; a claim never
# upgrades a verdict, and an EXPIRED claim FAILS — a stale assertion about a
# publishing account is exactly as actionable as an expired signing key.
#
# Publish targets are detected from the filesystem (Cargo.toml with [package],
# a non-private package.json, pyproject.toml with [project], Formula/*.rb, a
# *.nuspec, a winget *.installer.yaml). You only need [targets] to correct it.

# [targets]
# crates-io  = "auto"   # auto (believe the filesystem) | on | off
# npm        = "auto"
# pypi       = "auto"
# homebrew   = "auto"   # "on" if your tap's formulae live in another repo
# chocolatey = "auto"
# winget     = "auto"

# ── Publishing accounts ─────────────────────────────────────────────────────
# The far-left link: whoever can log in to the registry can publish under your
# name. No registry API reports whether a second factor is phishing-resistant,
# so `mfa` is a human claim with a date on it. `sscsb verify maintainer-mfa`
# reads what the APIs DO expose (GitHub's two_factor_authentication, npm's
# tfa.mode) and uses this block only for the part they cannot answer.
#
# [[account]]
# target   = "npm"
# identity = "your-npm-username"
# mfa      = "webauthn-only"     # webauthn-only | webauthn | totp | none
# attested = "2026-01-15"        # the day a human last confirmed the above
# # attestation_file = ".sscsb/policy/attestations/npm-mfa.png"

# ── Publishing credentials you have deliberately kept ───────────────────────
# Trusted Publishing (OIDC) removes the credential entirely and is the right
# answer for crates.io, npm and PyPI. Declare a token here only where no OIDC
# path exists (Chocolatey's push key) or where you have decided to keep one
# anyway — and then say what makes it defensible.
#
# [[token]]
# target         = "chocolatey"
# purpose        = "push key — Chocolatey has no OIDC path"
# scoped         = true          # scoped to specific packages, not the account
# cidr_allowlist = false         # restricted to known source addresses
# issued         = "2026-01-01"
# expires        = "2026-04-01"  # npm caps granular WRITE tokens at 90 days
# stored_in      = "1Password / GitHub environment `release`"

# ── Windows code signing ────────────────────────────────────────────────────
# Authenticode is WinGet's and Chocolatey's real trust anchor, and it cannot be
# verified from macOS or Linux. Recorded, with its expiry evaluated.
#
# [signing]
# authenticode = true
# subject      = "CN=Your Org, O=Your Org, C=US"
# expires      = "2027-06-30"
"#;

// ────────────────────────── publish workflow templates ──────────────────────

/// A publish workflow template and the target that gates its installation.
///
/// Deliberately NOT in [`crate::workflows::ARTIFACTS`]. `install_all` gates
/// only on whether a control is enabled, and `trusted-publishing` is on by
/// default — so a publish template registered there would drop
/// `publish-npm.yml` into every repository sscsb ever touched, including the
/// ones with no `package.json`. A workflow that publishes to a registry you do
/// not publish to is not a harmless extra file; it is a `workflow_dispatch`
/// button wired to someone else's namespace. The installer below asks
/// detection first.
#[derive(Debug, Clone, Copy)]
pub struct DistArtifact {
    pub target: PublishTarget,
    pub dest: &'static str,
    pub content: &'static str,
}

pub const DIST_ARTIFACTS: &[DistArtifact] = &[
    DistArtifact {
        target: PublishTarget::CratesIo,
        dest: ".github/workflows/publish-crates.yml",
        content: include_str!("../templates/workflows/publish-crates.yml"),
    },
    DistArtifact {
        target: PublishTarget::Npm,
        dest: ".github/workflows/publish-npm.yml",
        content: include_str!("../templates/workflows/publish-npm.yml"),
    },
    DistArtifact {
        target: PublishTarget::PyPi,
        dest: ".github/workflows/publish-pypi.yml",
        content: include_str!("../templates/workflows/publish-pypi.yml"),
    },
];

pub fn dist_artifact(target: PublishTarget) -> Option<&'static DistArtifact> {
    DIST_ARTIFACTS.iter().find(|a| a.target == target)
}

/// Install the publish template for every DETECTED OIDC-capable target whose
/// `trusted-publishing` control is enabled. Called from `init::bootstrap`
/// after `workflows::install_all`; idempotent, and never overwrites.
pub fn install_templates(ctx: &Ctx, cfg: &Config) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    if !cfg.control_enabled_or_default("trusted-publishing") {
        return Ok(vec![
            "skip publish workflows (control trusted-publishing disabled)".to_string(),
        ]);
    }
    let policy = load_policy(&policy_path(ctx))?;
    let detected = detect_targets(&ctx.root, &policy)?;
    let slug = cfg
        .github_repo()
        .or_else(|| ctx.origin_slug())
        .unwrap_or_else(|| "OWNER/REPO".to_string());
    let branch = ctx.default_branch();
    for artifact in DIST_ARTIFACTS {
        if !detected.iter().any(|d| d.target == artifact.target) {
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
        std::fs::write(
            &dest,
            crate::workflows::render(artifact.content, &slug, &branch),
        )?;
        lines.push(format!(
            "write {} ({} target detected)",
            artifact.dest,
            artifact.target.registry()
        ));
    }
    Ok(lines)
}

// ───────────────────────────── shared helpers ───────────────────────────────

/// Read every publish/release workflow in the repo, as (path, text).
///
/// Publishing does not only happen in the file sscsb installs — a repo that
/// already had a `release.yml` doing `npm publish` is the interesting case, and
/// a check that only looked at our own template would call it clean.
fn workflow_files(root: &Path) -> Vec<(String, String)> {
    let dir = root.join(".github/workflows");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((format!(".github/workflows/{name}"), text));
        }
    }
    out.sort();
    out
}

/// Does this workflow text reference `secrets.<NAME>` for any of `names`?
///
/// Keyed on the `secrets.` prefix so the Trusted-Publishing spelling — a token
/// produced by the OIDC exchange and handed on as `steps.auth.outputs.token`
/// — is not mistaken for a stored credential. Those are the same env var name
/// and opposite security postures.
fn references_token_secret(text: &str, names: &[&str]) -> Vec<String> {
    // Whole comment lines are dropped first. A template that DOCUMENTS the
    // anti-pattern — "no `secrets.NPM_TOKEN`: the OIDC identity is the
    // credential" — is doing the opposite of committing one, and a scanner
    // that cannot tell those apart fails the very workflows it installs. A
    // trailing comment on a live line is deliberately NOT stripped, so
    // `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }} # legacy` still counts.
    let live: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let mut hits = Vec::new();
    for name in names {
        if live.contains(&format!("secrets.{name}")) {
            hits.push((*name).to_string());
        }
    }
    hits
}

/// Is this workflow a publishing workflow at all?
fn publishes_to(text: &str, target: PublishTarget) -> bool {
    let markers: &[&str] = match target {
        PublishTarget::CratesIo => &["cargo publish", "crates-io-auth-action"],
        PublishTarget::Npm => &["npm publish", "npm-publish"],
        PublishTarget::PyPi => &["gh-action-pypi-publish", "twine upload", "python -m twine"],
        PublishTarget::Chocolatey => &["choco push"],
        PublishTarget::Homebrew => &["brew bump-formula-pr"],
        PublishTarget::WinGet => &["wingetcreate", "winget-pkgs"],
    };
    markers.iter().any(|m| text.contains(m))
}

/// Format a `[[account]]`/`[[token]]` expiry state as a report line plus
/// whether it is a failure. Mirrors the agent-key vocabulary deliberately: an
/// operator who has read `sscsb verify agent-signing` already knows what
/// "expired 12 days ago" means.
fn expiry_line(label: &str, state: &ExpiryState) -> (String, bool) {
    match state {
        ExpiryState::Unset => (format!("{label}: no expiry declared"), false),
        ExpiryState::Valid { days_left } => (format!("{label}: valid, {days_left}d left"), false),
        ExpiryState::Expired { days_ago } => (
            format!("{label}: EXPIRED {days_ago}d ago — rotate it and update the policy"),
            true,
        ),
        ExpiryState::WindowTooLong { days_left, max } => (
            format!(
                "{label}: valid but {days_left}d is longer than the {max}d window this control \
                 asks for — shorten it at the next rotation"
            ),
            false,
        ),
        ExpiryState::Unparseable => (
            format!("{label}: expiry is not a YYYY-MM-DD date — unreadable, so unchecked"),
            true,
        ),
    }
}

/// Load the policy, or turn a parse error into the control's `Fail`.
///
/// A malformed policy file is a hard failure for every phase-6 control, the
/// same way a malformed `signers.toml` fails `agent-signing`: the file that
/// declares your publishing posture must itself be well-formed, or nothing
/// downstream means anything.
fn policy_or_fail(ctx: &Ctx, id: &'static str) -> std::result::Result<Policy, VerifyResult> {
    load_policy(&policy_path(ctx)).map_err(|err| {
        VerifyResult::new(
            id,
            Outcome::Fail,
            vec![format!("distribution policy invalid: {err:#}")],
        )
    })
}

/// Detect, or turn an unreadable tree into the control's `Degraded`.
fn detect_or_degrade(
    ctx: &Ctx,
    policy: &Policy,
    id: &'static str,
) -> std::result::Result<Vec<DetectedTarget>, VerifyResult> {
    detect_targets(&ctx.root, policy).map_err(|err| {
        VerifyResult::degraded(
            id,
            "scan-error",
            vec![format!(
                "could not scan the tree for publish targets: {err:#}"
            )],
        )
    })
}

// ───────────────── what may be copied out of a tool's answer ────────────────
//
// `maintainer-mfa` and `trusted-publishing` are the only controls in sscsb that
// ask a CREDENTIAL-HOLDING tool about an ACCOUNT: `gh api user` and
// `npm profile get --json` both answer as the logged-in maintainer, and both
// can put things in stdout or stderr that nobody should republish — a registry
// URL with embedded basic-auth, a token fragment in an error, an email.
//
// That matters more here than in most tools, because a `VerifyResult`'s
// `messages` are not just printed. `machine.rs` serializes them into
// `--format json` AND into the signed local-scan record that gets committed and
// published to the public directory. Anything interpolated into a message is
// therefore an artifact with a signature on it.
//
// So the invariant for this module is narrow and absolute, and
// `no_tool_output_is_ever_echoed_into_a_published_message` enforces it:
//
//   NO byte of a tool's stdout or stderr is ever copied into a message.
//
// Only the specific field a control needs is read (`two_factor_authentication`,
// `tfa.mode`), and any of it that is a free-form string is passed through
// [`safe_label`] first. Failures are reported as a status, never as output —
// see [`tool_failure`]. Spawn errors are exempt and deliberately so: they carry
// our own argv and an OS message, never anything the registry said.

/// Longest external token this module will copy into a published message.
const MAX_ECHOED: usize = 64;

/// Reduce an externally-supplied identifier to something safe to publish.
///
/// A GitHub login or npm username is public and genuinely useful in the
/// message — "GitHub `p4gs` has 2FA enabled" is worth more than "the account
/// does" — but it arrives inside a payload from a credential-holding command,
/// so it is treated as untrusted: a bounded charset, a bounded length, and a
/// visible refusal rather than a silent truncation when it is neither.
fn safe_label(raw: &str) -> String {
    let trimmed = raw.trim();
    let ok = !trimmed.is_empty()
        && trimmed.len() <= MAX_ECHOED
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@/".contains(c));
    if ok {
        trimmed.to_string()
    } else {
        "(unprintable)".to_string()
    }
}

/// Summarise a failed tool invocation WITHOUT echoing a byte of its output.
///
/// The HTTP status is the only thing worth extracting and the only thing that
/// cannot carry a credential: it tells an operator whether to authenticate,
/// grant a scope, or look elsewhere, which is the whole diagnostic value the
/// raw stderr line used to carry. Everything else in that line — a URL with
/// inline basic-auth, a token echoed back by a registry, an email — is exactly
/// what must not reach a signed, published record.
fn tool_failure(stderr: &str) -> String {
    for code in [
        "400", "401", "403", "404", "422", "429", "500", "502", "503",
    ] {
        if stderr.contains(code) {
            return format!("HTTP {code}");
        }
    }
    "a non-zero exit (output withheld — it can carry credentials)".to_string()
}

/// The line every verifier prints when the repository publishes nothing.
fn no_targets(id: &'static str) -> VerifyResult {
    VerifyResult::new(
        id,
        Outcome::Info,
        vec![
            "no publish target detected (no Cargo.toml `[package]`, non-private package.json, \
             pyproject `[project]`, Formula/*.rb, *.nuspec or winget manifest) — this repository \
             publishes to no registry sscsb knows about, so there is nothing to check. Declare \
             one with `[targets]` in .sscsb/policy/distribution.toml if that is wrong"
                .into(),
        ],
    )
}

// ─────────────────────────── 1. publish-targets ─────────────────────────────

/// Inventory. Never fails: knowing what a repository publishes is a fact to
/// report, not a posture to grade — the five controls after this one do the
/// grading, and each is scoped by what this one found.
pub fn verify_publish_targets(ctx: &Ctx, _cfg: &Config) -> VerifyResult {
    let id = "publish-targets";
    let policy = match policy_or_fail(ctx, id) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detected = match detect_or_degrade(ctx, &policy, id) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if detected.is_empty() {
        return no_targets(id);
    }
    let mut messages = vec![format!(
        "{} publish target(s) detected:",
        distinct_targets(&detected).len()
    )];
    for d in &detected {
        let pkg = match d.package.as_deref() {
            Some(p) if !p.is_empty() => format!(" `{p}`"),
            _ => String::new(),
        };
        messages.push(format!("  {}{pkg} ← {}", d.target.registry(), d.manifest));
    }
    let oidc: Vec<&str> = distinct_targets(&detected)
        .into_iter()
        .filter(|t| t.oidc_capable())
        .map(|t| t.registry())
        .collect();
    if !oidc.is_empty() {
        messages.push(format!(
            "{} support Trusted Publishing — `sscsb verify trusted-publishing` grades the \
             workflows",
            oidc.join(", ")
        ));
    }
    VerifyResult::new(id, Outcome::Info, messages)
}

fn distinct_targets(detected: &[DetectedTarget]) -> Vec<PublishTarget> {
    let mut seen: Vec<PublishTarget> = detected.iter().map(|d| d.target).collect();
    seen.sort();
    seen.dedup();
    seen
}

// ────────────────────────── 2. trusted-publishing ───────────────────────────

/// For each detected OIDC-capable target: is the publish workflow installed,
/// does it hold `id-token: write`, does it call the Trusted-Publishing action,
/// and does it avoid a long-lived registry secret? Then — best-effort, through
/// `gh` — does the `release` environment carry protection rules?
///
/// The environment read degrades rather than failing when `gh` is absent,
/// unauthenticated, or the repository has no remote: exactly
/// [`crate::audit::verify_branch_protection`]'s posture, and for the same
/// reason — "I could not look" is never "it is not there".
pub fn verify_trusted_publishing(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "trusted-publishing";
    let policy = match policy_or_fail(ctx, id) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detected = match detect_or_degrade(ctx, &policy, id) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let oidc: Vec<PublishTarget> = distinct_targets(&detected)
        .into_iter()
        .filter(|t| t.oidc_capable())
        .collect();
    let others = distinct_targets(&detected)
        .into_iter()
        .filter(|t| !t.oidc_capable())
        .collect::<Vec<_>>();
    if oidc.is_empty() {
        if detected.is_empty() {
            return no_targets(id);
        }
        return VerifyResult::new(
            id,
            Outcome::Info,
            vec![format!(
                "detected target(s) {} have no Trusted Publishing path: Homebrew and WinGet \
                 publish by pull request (a GitHub identity — see `maintainer-mfa`) and \
                 Chocolatey has no OIDC support at all",
                others
                    .iter()
                    .map(|t| t.registry())
                    .collect::<Vec<_>>()
                    .join(", ")
            )],
        );
    }

    let workflows = workflow_files(&ctx.root);
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    for target in &oidc {
        let Some(artifact) = dist_artifact(*target) else {
            continue;
        };
        // Any workflow that publishes to this target counts — our template, or
        // the repo's own release.yml. Grading only our own file would let a
        // hand-rolled token publish pass unexamined.
        let publishing: Vec<&(String, String)> = workflows
            .iter()
            .filter(|(_, text)| publishes_to(text, *target))
            .collect();
        if publishing.is_empty() {
            outcome = outcome.weakest(Outcome::Fail);
            messages.push(format!(
                "{}: no workflow publishes to it — run `sscsb init` to install {}, then \
                 configure the trusted publisher on {}",
                target.registry(),
                artifact.dest,
                target.registry()
            ));
            continue;
        }
        for (path, text) in publishing {
            let secrets = references_token_secret(text, target.token_secrets());
            if !secrets.is_empty() {
                outcome = outcome.weakest(Outcome::Fail);
                messages.push(format!(
                    "{path}: publishes to {} using the long-lived secret(s) {} — {} supports \
                     Trusted Publishing, so delete the secret and let the workflow's OIDC \
                     identity be the credential (see {})",
                    target.registry(),
                    secrets.join(", "),
                    target.registry(),
                    artifact.dest
                ));
                continue;
            }
            let has_id_token = text.contains("id-token: write");
            if !has_id_token {
                outcome = outcome.weakest(Outcome::Fail);
                messages.push(format!(
                    "{path}: publishes to {} with no `id-token: write` permission — without it \
                     no OIDC token can be minted and Trusted Publishing cannot be what is \
                     authenticating this publish",
                    target.registry()
                ));
                continue;
            }
            messages.push(format!(
                "{path}: {} via OIDC — `id-token: write`, no long-lived registry secret ✓",
                target.registry()
            ));
        }
    }

    // The environment gate. An OIDC identity with no protection rules in front
    // of it means anyone who can dispatch the workflow can publish.
    let environment = cfg
        .control_opt_str("trusted-publishing", "environment")
        .unwrap_or_else(|| "release".to_string());
    let mut degraded_reason: Option<&'static str> = None;
    match read_environment(ctx, cfg, &environment) {
        EnvironmentRead::Unavailable(reason, why) => {
            messages.push(format!("{environment} environment: {why}"));
            outcome = outcome.weakest(Outcome::Degraded);
            degraded_reason = Some(reason);
        }
        EnvironmentRead::Missing => {
            messages.push(format!(
                "no `{environment}` environment on the remote — the publish workflows name it, \
                 so create it and add required reviewers plus a branch restriction; until then \
                 anyone who can dispatch the workflow can publish"
            ));
            outcome = outcome.weakest(Outcome::Fail);
        }
        EnvironmentRead::Unprotected => {
            messages.push(format!(
                "`{environment}` environment exists but carries no protection rules — add \
                 required reviewers, a wait timer, or a deployment-branch restriction, or the \
                 environment is a label rather than a gate"
            ));
            outcome = outcome.weakest(Outcome::Fail);
        }
        EnvironmentRead::Protected(rules) => {
            messages.push(format!("`{environment}` environment protected: {rules} ✓"));
        }
    }
    // The only way this control degrades is an environment read that could not
    // be performed, and that read says which of the four reasons it was.
    match degraded_reason {
        Some(reason) if outcome == Outcome::Degraded => {
            VerifyResult::degraded(id, reason, messages)
        }
        _ => VerifyResult::new(id, outcome, messages),
    }
}

enum EnvironmentRead {
    /// Could not look — tool, auth or remote missing. Carries the reason in
    /// [`crate::controls::DEGRADED_REASONS`] vocabulary alongside the prose, so
    /// a machine consumer can tell "the tool was absent" (committed evidence
    /// may still stand) from "the tool ran and was refused" without parsing an
    /// English sentence.
    Unavailable(&'static str, String),
    Missing,
    Unprotected,
    Protected(String),
}

fn read_environment(ctx: &Ctx, cfg: &Config, environment: &str) -> EnvironmentRead {
    if exec::find_in_path("gh").is_none() {
        return EnvironmentRead::Unavailable(
            "tool-missing",
            format!(
                "not read — {}",
                crate::tools::degrade_message("gh", ctx.platform)
            ),
        );
    }
    let Some(slug) = cfg.github_repo().or_else(|| ctx.origin_slug()) else {
        return EnvironmentRead::Unavailable(
            "no-remote",
            "not read — no GitHub repo configured (general.github_repo) and no origin remote"
                .into(),
        );
    };
    let api = format!("repos/{slug}/environments/{environment}");
    let out = match exec::run("gh", &["api", &api], Some(&ctx.root)) {
        Ok(o) => o,
        Err(err) => {
            return EnvironmentRead::Unavailable(
                "scan-error",
                format!("not read — gh failed: {err:#}"),
            )
        }
    };
    if !out.success() {
        let status = tool_failure(&out.stderr);
        // GitHub answers 404 both for "no such environment" and for "your
        // token cannot see environments". Those are opposite verdicts, so the
        // ambiguous case must degrade rather than assert the environment is
        // missing — a false Fail here would tell a maintainer to create an
        // environment that already exists.
        if status == "HTTP 404" {
            return EnvironmentRead::Unavailable(
                "no-access",
                format!(
                    "not read — GitHub answered {status} for `{api}`, which means EITHER no \
                     such environment OR a token that cannot read environments (needs repo \
                     admin). Unverified, not confirmed absent"
                ),
            );
        }
        return EnvironmentRead::Unavailable(
            "scan-error",
            format!("not read — GitHub answered {status} for `{api}`"),
        );
    }
    let env: serde_json::Value = match serde_json::from_str(&out.stdout) {
        Ok(v) => v,
        Err(_) => {
            return EnvironmentRead::Unavailable(
                "scan-error",
                format!("not read — `{api}` did not return JSON"),
            )
        }
    };
    classify_environment(&env)
}

/// Pure classifier over the environments API payload, so the protection logic
/// is testable without a network or a token.
fn classify_environment(env: &serde_json::Value) -> EnvironmentRead {
    if env.get("name").and_then(|n| n.as_str()).is_none() {
        return EnvironmentRead::Missing;
    }
    let rules = env
        .get("protection_rules")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let mut described = Vec::new();
    for rule in &rules {
        match rule.get("type").and_then(|t| t.as_str()) {
            Some("required_reviewers") => {
                let n = rule
                    .get("reviewers")
                    .and_then(|r| r.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                described.push(format!("{n} required reviewer(s)"));
            }
            Some("wait_timer") => {
                let m = rule.get("wait_timer").and_then(|w| w.as_u64()).unwrap_or(0);
                described.push(format!("{m}-minute wait timer"));
            }
            Some("branch_policy") => described.push("deployment-branch policy".to_string()),
            // A rule type GitHub adds after this code was written is still
            // worth naming, but it arrives in a payload and ends up in a
            // published record, so it goes through the same bound as any
            // other external string.
            Some(other) => described.push(safe_label(other)),
            None => {}
        }
    }
    // A branch policy can also be declared outside `protection_rules`.
    if env
        .get("deployment_branch_policy")
        .is_some_and(|p| !p.is_null())
        && !described.iter().any(|d| d.contains("branch"))
    {
        described.push("deployment-branch policy".to_string());
    }
    if described.is_empty() {
        EnvironmentRead::Unprotected
    } else {
        EnvironmentRead::Protected(described.join(", "))
    }
}

// ──────────────────────────── 3. maintainer-mfa ─────────────────────────────

/// The far-left control: the human account that can publish.
///
/// Each target resolves to the identity that actually gates publishing —
/// GitHub for crates.io/Homebrew/WinGet, the npm account for npm, and PyPI's
/// own mandatory 2FA — and sscsb asks the API that can answer. What no API
/// exposes is whether the second factor is phishing-resistant, so that part is
/// a dated `[[account]]` claim: fresh ones are reported, expired ones FAIL.
pub fn verify_maintainer_mfa(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "maintainer-mfa";
    let policy = match policy_or_fail(ctx, id) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detected = match detect_or_degrade(ctx, &policy, id) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if detected.is_empty() {
        return no_targets(id);
    }
    let max_age = cfg
        .control_opt_int(id, "max_attestation_age_days")
        .unwrap_or(180);
    let today = chrono::Utc::now().date_naive();
    let targets = distinct_targets(&detected);

    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    let mut degraded_reason: Option<&'static str> = None;
    let mut github_needed = false;

    for target in &targets {
        match target {
            PublishTarget::CratesIo | PublishTarget::Homebrew | PublishTarget::WinGet => {
                github_needed = true;
            }
            PublishTarget::Npm => {
                let (o, reason, lines) = npm_tfa(ctx);
                outcome = outcome.weakest(o);
                degraded_reason = degraded_reason.or(reason);
                messages.extend(lines);
            }
            PublishTarget::PyPi => messages.push(
                "PyPI: 2FA is MANDATORY for every uploader — enforced by the registry, not by \
                 this repository, so it is a fact rather than a check that could fail"
                    .to_string(),
            ),
            PublishTarget::Chocolatey => messages.push(
                "Chocolatey: the community repository offers no account 2FA (upstream gap, \
                 unfixable by a maintainer) — the push key in `[[token]]` is the only control \
                 available here. Reported, deliberately NOT a failure: `--strict` must not be \
                 permanently red for something nobody can fix"
                    .to_string(),
            ),
        }
    }

    if github_needed {
        let gh_targets: Vec<&str> = targets
            .iter()
            .filter(|t| {
                matches!(
                    t,
                    PublishTarget::CratesIo | PublishTarget::Homebrew | PublishTarget::WinGet
                )
            })
            .map(|t| t.registry())
            .collect();
        let (o, reason, lines) = github_two_factor(ctx, cfg, &gh_targets.join(", "));
        outcome = outcome.weakest(o);
        degraded_reason = degraded_reason.or(reason);
        messages.extend(lines);
    }

    // The phishing-resistance claim, which no API above could have answered.
    for target in &targets {
        let Some(account) = policy.account_for(*target) else {
            messages.push(format!(
                "{}: no `[[account]]` claim — whether the second factor is phishing-resistant \
                 (WebAuthn with no weaker fallback) is not exposed by any registry API, so \
                 sscsb cannot tell. Declare it in .sscsb/policy/distribution.toml",
                target.registry()
            ));
            continue;
        };
        // Deliberately NOT `evaluate_expiry`. That function answers "how long
        // until this key stops being valid", counting FORWARD from today to a
        // future date. `attested` is the opposite direction: the day a human
        // last confirmed the claim, counting BACKWARD, where a larger number is
        // worse. Feeding one to the other would type-check and grade the wrong
        // way round — an ancient claim would read as long-expired and a claim
        // dated tomorrow as comfortably valid. `evaluate_expiry` is still the
        // evaluator for `[[token]] expires` and `[signing] expires`, which are
        // genuine expiries; this is a freshness window, and it is spelled out
        // rather than reused.
        //
        // The parse cannot fail: `opt_date` rejected anything that is not
        // `YYYY-MM-DD` when the policy was loaded, so a malformed date is
        // already a hard Fail on every phase-6 control.
        let stale = account.attested.as_deref().and_then(|raw| {
            NaiveDate::parse_from_str(raw, "%Y-%m-%d")
                .ok()
                .map(|d| (today - d).num_days())
        });
        let mfa = account.mfa;
        let resistance = if mfa.phishing_resistant() {
            "phishing-resistant"
        } else {
            "NOT phishing-resistant"
        };
        match stale {
            Some(days) if max_age > 0 && days > max_age => {
                outcome = outcome.weakest(Outcome::Fail);
                messages.push(format!(
                    "{} account `{}`: claims `{}` ({resistance}) but the claim was last \
                     confirmed {days}d ago, past the {max_age}d window — re-check the account \
                     and update `attested`. A stale claim about a publishing account is exactly \
                     as actionable as an expired signing key",
                    target.registry(),
                    account.identity,
                    mfa.label()
                ));
            }
            Some(days) => {
                if !mfa.phishing_resistant() {
                    outcome = outcome.weakest(Outcome::Info);
                }
                messages.push(format!(
                    "{} account `{}`: claims `{}` ({resistance}), confirmed {days}d ago — a \
                     self-declared claim, documented, never a substitute for the API reads above",
                    target.registry(),
                    account.identity,
                    mfa.label()
                ));
            }
            None => {
                outcome = outcome.weakest(Outcome::Info);
                messages.push(format!(
                    "{} account `{}`: claims `{}` with no `attested` date — an undated claim \
                     cannot go stale, which is exactly why it also cannot be trusted; add the \
                     day you last checked, as YYYY-MM-DD",
                    target.registry(),
                    account.identity,
                    mfa.label()
                ));
            }
        }
        if let Some(rel) = account.attestation_file.as_deref() {
            match crate::signers::evaluate_attestation(&ctx.root, Some(rel)) {
                Ok(crate::signers::AttestationState::Attested { sha256 }) => {
                    messages.push(format!("  attestation {rel} sha256:{}", &sha256[..16]));
                }
                Ok(crate::signers::AttestationState::Missing { path }) => {
                    outcome = outcome.weakest(Outcome::Fail);
                    messages.push(format!(
                        "  `attestation_file = \"{path}\"` names a file that is not there — a \
                         policy pointing at a missing artifact is a misconfiguration, not an \
                         attestation"
                    ));
                }
                Ok(crate::signers::AttestationState::Declared) => {}
                Err(err) => {
                    outcome = outcome.weakest(Outcome::Degraded);
                    degraded_reason = degraded_reason.or(Some("scan-error"));
                    messages.push(format!("  attestation {rel} could not be read: {err:#}"));
                }
            }
        }
    }

    match degraded_reason {
        Some(reason) if outcome == Outcome::Degraded => {
            VerifyResult::degraded(id, reason, messages)
        }
        _ => VerifyResult::new(id, outcome, messages),
    }
}

/// `gh api user` → `two_factor_authentication`. The field is only populated
/// for a token carrying `read:user`, and GitHub sends `null` rather than an
/// error when it is not — so `null` is Degraded with the exact remediation,
/// never an assumed `false`.
fn github_two_factor(
    ctx: &Ctx,
    cfg: &Config,
    for_targets: &str,
) -> (Outcome, Option<&'static str>, Vec<String>) {
    // Gate on a resolvable GitHub remote before reading the ambient login,
    // the same way `verify_branch_protection` does. Without one there is no
    // evidence this project publishes under a GitHub identity at all, and the
    // account `gh` happens to be logged in as is then a GUESS — grading a
    // repository on whose laptop the check ran is precisely the false positive
    // this project refuses to ship.
    if cfg.github_repo().or_else(|| ctx.origin_slug()).is_none() {
        return (
            Outcome::Degraded,
            Some("no-remote"),
            vec![format!(
                "{for_targets} publish under a GitHub identity, but this repository has no                  GitHub remote and no `general.github_repo` — so which account that is cannot                  be determined from here, and the locally logged-in one would only be a guess"
            )],
        );
    }
    if exec::find_in_path("gh").is_none() {
        return (
            Outcome::Degraded,
            Some("tool-missing"),
            vec![format!(
                "{for_targets} publish under a GitHub identity, and its 2FA state was not read \
                 — {}",
                crate::tools::degrade_message("gh", ctx.platform)
            )],
        );
    }
    let out = match exec::run("gh", &["api", "user"], Some(&ctx.root)) {
        Ok(o) => o,
        Err(err) => {
            return (
                Outcome::Degraded,
                Some("scan-error"),
                vec![format!("gh failed reading `user`: {err:#}")],
            )
        }
    };
    if !out.success() {
        let status = tool_failure(&out.stderr);
        return (
            Outcome::Degraded,
            Some("no-access"),
            vec![format!(
                "GitHub answered {status} for `user` — run `gh auth login`. The GitHub account \
                 gates publishing for {for_targets}; unverified, not confirmed"
            )],
        );
    }
    let user: serde_json::Value = match serde_json::from_str(&out.stdout) {
        Ok(v) => v,
        Err(_) => {
            return (
                Outcome::Degraded,
                Some("scan-error"),
                vec!["`gh api user` did not return JSON".to_string()],
            )
        }
    };
    classify_github_two_factor(&user, for_targets)
}

fn classify_github_two_factor(
    user: &serde_json::Value,
    for_targets: &str,
) -> (Outcome, Option<&'static str>, Vec<String>) {
    // Only the boolean is the evidence. The login is carried for legibility
    // and is bounded first — it arrives in a payload from a credential-holding
    // command, and these messages are published.
    let login = safe_label(user.get("login").and_then(|l| l.as_str()).unwrap_or("?"));
    match user
        .get("two_factor_authentication")
        .and_then(|v| v.as_bool())
    {
        Some(true) => (
            Outcome::Pass,
            None,
            vec![format!(
                "GitHub `{login}` has 2FA enabled — the identity that publishes {for_targets} ✓"
            )],
        ),
        Some(false) => (
            Outcome::Fail,
            None,
            vec![format!(
                "GitHub `{login}` has 2FA DISABLED, and that account publishes {for_targets} — \
                 enable it at github.com/settings/security, preferably with a passkey and no \
                 TOTP fallback"
            )],
        ),
        None => (
            Outcome::Degraded,
            Some("no-access"),
            vec![format!(
                "GitHub `{login}`: `two_factor_authentication` was not in the response, which \
                 is how GitHub reports a token without the `read:user` scope — run `gh auth \
                 refresh -s read:user`. Unverified, NOT a confirmed absence of 2FA"
            )],
        ),
    }
}

/// `npm profile get --json` → `tfa.mode`. `auth-and-writes` is the only mode
/// that requires a second factor at PUBLISH time; `auth-only` leaves the
/// publish itself unprotected, which is the exact gap a stolen session or
/// token walks through, so it FAILS rather than degrading.
fn npm_tfa(ctx: &Ctx) -> (Outcome, Option<&'static str>, Vec<String>) {
    if exec::find_in_path("npm").is_none() {
        return (
            Outcome::Degraded,
            Some("tool-missing"),
            vec![crate::tools::degrade_message("npm", ctx.platform)],
        );
    }
    let out = match exec::run("npm", &["profile", "get", "--json"], Some(&ctx.root)) {
        Ok(o) => o,
        Err(err) => {
            return (
                Outcome::Degraded,
                Some("scan-error"),
                vec![format!("npm failed reading the profile: {err:#}")],
            )
        }
    };
    if !out.success() {
        // npm's failure output is the single most dangerous string in this
        // module to republish: a misconfigured `.npmrc` puts the registry URL
        // in the error, and a registry URL can carry inline basic-auth.
        let status = tool_failure(&out.stderr);
        return (
            Outcome::Degraded,
            Some("no-access"),
            vec![format!(
                "npm exited with {status} for `npm profile get` — run `npm login`. Unverified, \
                 not confirmed"
            )],
        );
    }
    classify_npm_tfa(&out.stdout)
}

fn classify_npm_tfa(stdout: &str) -> (Outcome, Option<&'static str>, Vec<String>) {
    let profile: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => {
            return (
                Outcome::Degraded,
                Some("scan-error"),
                // The parse error is withheld along with the payload. `npm
                // profile get` prints the profile, and a profile that will not
                // parse is still a profile.
                vec!["`npm profile get --json` did not return JSON".to_string()],
            );
        }
    };
    // The npm profile payload also carries `email`, `fullname`, `created` and
    // more. Only the username is read, and only after bounding — nothing else
    // in that document is this control's business.
    let who = profile
        .get("name")
        .and_then(|n| n.as_str())
        .map(safe_label)
        .unwrap_or_else(|| "the npm account".to_string());
    // npm reports `tfa` as an object `{mode: ...}`, as a bare string, or as
    // `null`/`false` when no second factor is enrolled at all. All three
    // spellings have been seen from the same CLI across versions.
    let tfa = profile.get("tfa");
    let mode = match tfa {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(false)) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(v) => v.get("mode").and_then(|m| m.as_str()).map(str::to_string),
    };
    match mode.as_deref() {
        Some("auth-and-writes") => (
            Outcome::Pass,
            None,
            vec![format!(
                "npm `{who}`: tfa.mode = auth-and-writes — a second factor is required for the \
                 PUBLISH itself, not only for login ✓"
            )],
        ),
        Some(other @ "auth-only") => (
            Outcome::Fail,
            None,
            vec![format!(
                "npm `{who}`: tfa.mode = {other} — a second factor gates LOGIN but not \
                 PUBLISH, so a stolen session or token still ships a release. Set it with \
                 `npm profile set tfa auth-and-writes`, or remove the credential entirely by \
                 moving to Trusted Publishing"
            )],
        ),
        // A mode outside npm's vocabulary is NOT echoed, and `safe_label` is
        // deliberately not used here. `tfa.mode` is a closed enum, not a name:
        // a value that is not one of the known modes is not a mode at all, and
        // a secret can be perfectly well-formed as an identifier — which is
        // exactly how `no_tool_output_is_ever_echoed_into_a_published_message`
        // caught this line echoing a planted credential that passed every
        // charset and length bound. Report the fact, withhold the value.
        Some(_) => (
            Outcome::Fail,
            None,
            vec![format!(
                "npm `{who}`: tfa.mode is a value npm does not document (withheld — an \
                 unrecognised value is not a mode, and could be anything), which is not \
                 `auth-and-writes` — treat the publish as not behind a second factor"
            )],
        ),
        None => (
            Outcome::Fail,
            None,
            vec![format!(
                "npm `{who}`: no two-factor authentication enrolled — anyone with the password \
                 or a stolen token publishes under this name. Enrol at npmjs.com → Account → \
                 Two-Factor Authentication, mode `auth-and-writes`"
            )],
        ),
    }
}

// ──────────────────────────── 4. publish-tokens ─────────────────────────────

/// Credential files that must never be committed, and what makes each one a
/// live credential rather than a config file.
const CREDENTIAL_FILES: &[(&str, &str)] = &[
    (".npmrc", "_authToken"),
    (".pypirc", "password"),
    (".cargo/credentials.toml", "token"),
    (".cargo/credentials", "token"),
];

/// Committed credentials, long-lived secrets on an OIDC-capable path, and the
/// expiry of every token the maintainer deliberately kept.
pub fn verify_publish_tokens(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "publish-tokens";
    let policy = match policy_or_fail(ctx, id) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detected = match detect_or_degrade(ctx, &policy, id) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let max_age = cfg.control_opt_int(id, "max_token_age_days").unwrap_or(90);
    let today = chrono::Utc::now().date_naive();
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;

    // A committed credential is a hard failure whether or not this repository
    // publishes anything: the token is live the moment the file is pushed, and
    // "we do not publish from here" has never stopped anyone reading it.
    let tracked = tracked_files(ctx);
    for (name, marker) in CREDENTIAL_FILES {
        let suffix = format!("/{name}");
        for path in tracked
            .iter()
            .filter(|p| p.as_str() == *name || p.ends_with(&suffix))
        {
            let text = std::fs::read_to_string(ctx.root.join(path)).unwrap_or_default();
            if text.lines().any(|l| {
                let l = l.trim();
                !l.starts_with('#') && !l.starts_with(';') && l.contains(marker)
            }) {
                outcome = outcome.weakest(Outcome::Fail);
                messages.push(format!(
                    "{path} is COMMITTED and carries `{marker}` — that is a live publishing \
                     credential in the repository's history. Revoke it at the registry first \
                     (it is already compromised), then untrack the file and add it to \
                     .gitignore. Rewriting history does not un-leak it"
                ));
            }
        }
    }

    if detected.is_empty() && policy.tokens.is_empty() {
        if outcome == Outcome::Pass {
            return no_targets(id);
        }
        return VerifyResult::new(id, outcome, messages);
    }

    // A long-lived registry secret on a path where OIDC exists.
    let workflows = workflow_files(&ctx.root);
    for target in distinct_targets(&detected) {
        let secrets_here: Vec<(String, Vec<String>)> = workflows
            .iter()
            .filter_map(|(path, text)| {
                let hits = references_token_secret(text, target.token_secrets());
                (!hits.is_empty()).then(|| (path.clone(), hits))
            })
            .collect();
        for (path, hits) in secrets_here {
            let declared = policy
                .tokens_for(target)
                .iter()
                .any(|t| !t.purpose.is_empty());
            if target.oidc_capable() {
                outcome = outcome.weakest(Outcome::Fail);
                messages.push(format!(
                    "{path}: holds {} for {} — that registry supports Trusted Publishing, so \
                     the secret is avoidable entirely. {}",
                    hits.join(", "),
                    target.registry(),
                    if declared {
                        "A `[[token]]` entry documents why it is kept; documenting a removable \
                         credential does not make it necessary"
                    } else {
                        "Delete the secret and publish via OIDC"
                    }
                ));
            } else {
                messages.push(format!(
                    "{path}: holds {} for {} — no OIDC path exists there, so a credential is \
                     unavoidable; declare it in `[[token]]` with its scope and expiry",
                    hits.join(", "),
                    target.registry()
                ));
            }
        }
    }

    // Declared tokens: expiry is the part sscsb can actually evaluate.
    for token in &policy.tokens {
        let label = format!("{} token ({})", token.target.registry(), token.purpose);
        let state = evaluate_expiry(token.expires.as_deref(), today, max_age);
        let (line, failed) = expiry_line(&label, &state);
        messages.push(line);
        if failed {
            outcome = outcome.weakest(Outcome::Fail);
        }
        if token.expires.is_none() {
            outcome = outcome.weakest(Outcome::Info);
            messages.push(format!(
                "  {}: no `expires` — a publishing credential with no stated lifetime is one \
                 nobody will remember to rotate. npm caps granular WRITE tokens at {max_age} \
                 days; give the others the same discipline",
                token.target.registry()
            ));
        }
        let mut weak = Vec::new();
        if !token.scoped {
            weak.push("not scoped to specific packages (it can publish anything the account can)");
        }
        if !token.cidr_allowlist {
            weak.push("no CIDR allowlist (it works from anywhere it is pasted)");
        }
        if !weak.is_empty() {
            outcome = outcome.weakest(Outcome::Info);
            messages.push(format!(
                "  {}: {}",
                token.target.registry(),
                weak.join("; ")
            ));
        }
        match token.stored_in.as_deref() {
            Some(where_) => messages.push(format!("  stored in {where_}")),
            None => messages.push(
                "  no `stored_in` — say where the secret actually lives, or nobody can revoke \
                 it in a hurry"
                    .to_string(),
            ),
        }
    }

    if messages.is_empty() {
        messages.push(
            "no committed credential files, no long-lived registry secrets in any workflow, and \
             no declared tokens — publishing carries no standing credential ✓"
                .to_string(),
        );
    }
    VerifyResult::new(id, outcome, messages)
}

/// Files tracked at HEAD. An untracked `.npmrc` in a working tree is the
/// maintainer's own business; a committed one is everyone's.
fn tracked_files(ctx: &Ctx) -> Vec<String> {
    exec::git_raw(&["ls-files"], &ctx.root)
        .ok()
        .filter(|o| o.success())
        .map(|o| {
            o.stdout
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

// ────────────────────────── 5. publish-provenance ───────────────────────────

/// Did the artifact people actually download come with provenance?
///
/// Configuration is not observable: npm does not expose whether a trusted
/// publisher is configured, and neither does crates.io. What IS observable,
/// anonymously, is the PUBLISHED ARTIFACT — so the probe asks the registry
/// about the latest release and reads whether it carries an attestation. That
/// is the honest proxy, and it measures the outcome rather than the intent.
///
/// `probe_registry = false` turns the network off entirely for an air-gapped
/// lane, and says so rather than pretending the local checks were the whole
/// check.
pub fn verify_publish_provenance(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "publish-provenance";
    let policy = match policy_or_fail(ctx, id) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detected = match detect_or_degrade(ctx, &policy, id) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if detected.is_empty() {
        return no_targets(id);
    }
    let probe = cfg.control_opt_bool(id, "probe_registry").unwrap_or(true);
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    let mut degraded_reason: Option<&'static str> = None;
    // Registry-level facts are stated once, not once per manifest. A workspace
    // with four publishable crates would otherwise print the identical
    // paragraph about crates.io four times, which is how a report teaches
    // people to skim past it.
    let mut said: BTreeSet<PublishTarget> = BTreeSet::new();

    for d in &detected {
        match d.target {
            PublishTarget::Homebrew => {
                let (o, lines) = homebrew_sha_pins(ctx, &d.manifest);
                outcome = outcome.weakest(o);
                messages.extend(lines);
            }
            // Nothing was verified in either arm below, so the control must
            // not come back reading as a pass. An ecosystem with no provenance
            // model to check is `Info` — a fact reported, not a claim earned.
            PublishTarget::CratesIo => {
                outcome = outcome.weakest(Outcome::Info);
                if said.insert(d.target) {
                    messages.push(
                        "crates.io: no artifact-level provenance exists in the ecosystem yet — \
                         Trusted Publishing is the strongest available claim, and \
                         `trusted-publishing` grades it. Reported, not graded"
                            .to_string(),
                    );
                }
            }
            PublishTarget::Chocolatey | PublishTarget::WinGet => {
                outcome = outcome.weakest(Outcome::Info);
                if said.insert(d.target) {
                    messages.push(format!(
                        "{}: provenance is the installer's Authenticode signature plus the \
                         manifest checksum — `dist-manifests` checks the checksum locally; the \
                         signature is a `[signing]` claim",
                        d.target.registry()
                    ));
                }
            }
            PublishTarget::Npm | PublishTarget::PyPi => {
                if !probe {
                    outcome = outcome.weakest(Outcome::Info);
                    messages.push(format!(
                        "{}: `probe_registry = false`, so the published artifact was NOT \
                         checked. Local checks only — that is a narrower claim than this \
                         control normally makes, not a passing one",
                        d.target.registry()
                    ));
                    continue;
                }
                let Some(pkg) = d.package.as_deref().filter(|p| !p.is_empty()) else {
                    outcome = outcome.weakest(Outcome::Degraded);
                    degraded_reason = degraded_reason.or(Some("no-inventory"));
                    messages.push(format!(
                        "{} ({}): the manifest states no package name, so there is nothing to \
                         ask the registry about",
                        d.target.registry(),
                        d.manifest
                    ));
                    continue;
                };
                let (o, reason, lines) = probe_provenance(d.target, pkg);
                outcome = outcome.weakest(o);
                degraded_reason = degraded_reason.or(reason);
                messages.extend(lines);
            }
        }
    }
    match degraded_reason {
        Some(reason) if outcome == Outcome::Degraded => {
            VerifyResult::degraded(id, reason, messages)
        }
        _ => VerifyResult::new(id, outcome, messages),
    }
}

/// The URL the provenance probe asks, per target. Separated so it is
/// unit-testable without a network.
pub fn provenance_probe_url(target: PublishTarget, package: &str) -> Option<String> {
    match target {
        // npm serves attestations for a specific version, so the probe reads
        // the packument first for `dist-tags.latest`; this is the second call.
        PublishTarget::Npm => Some(format!(
            "https://registry.npmjs.org/-/npm/v1/attestations/{package}"
        )),
        PublishTarget::PyPi => Some(format!("https://pypi.org/simple/{package}/")),
        _ => None,
    }
}

fn probe_provenance(
    target: PublishTarget,
    package: &str,
) -> (Outcome, Option<&'static str>, Vec<String>) {
    let Some(url) = provenance_probe_url(target, package) else {
        return (Outcome::Info, None, Vec::new());
    };
    let fetched = fetch(&url);
    classify_probe(target, package, &url, fetched)
}

/// The verdict half of the probe, with the network response passed IN.
///
/// Split from [`probe_provenance`] for the same reason `deps.rs` threads
/// `registry_exists` into `deps_check_with`: every branch here is a verdict a
/// maintainer acts on — "never published" is a skip, an unreachable registry is
/// UNVERIFIED rather than absent, and only a real attestation is a Pass — and
/// none of them is reachable from a test while the socket call is inlined. The
/// one remaining untestable line is the socket itself.
fn classify_probe(
    target: PublishTarget,
    package: &str,
    url: &str,
    fetched: FetchResult,
) -> (Outcome, Option<&'static str>, Vec<String>) {
    match fetched {
        FetchResult::NotFound => (
            Outcome::Info,
            None,
            vec![format!(
                "{} `{package}`: never published (the registry has no record) — nothing to \
                 check yet, and an unpublished package is not a failing one",
                target.registry()
            )],
        ),
        FetchResult::Error(err) => (
            Outcome::Degraded,
            Some("scan-error"),
            vec![format!(
                "{} `{package}`: could not reach {url} ({err}) — the published artifact's \
                 provenance is UNVERIFIED, not absent. Set `probe_registry = false` to decline \
                 this check deliberately",
                target.registry()
            )],
        ),
        FetchResult::Body(body) => {
            let (has, detail) = classify_provenance(target, &body);
            if has {
                (
                    Outcome::Pass,
                    None,
                    vec![format!(
                        "{} `{package}`: the published artifact carries provenance ({detail}) ✓",
                        target.registry()
                    )],
                )
            } else {
                (
                    Outcome::Fail,
                    None,
                    vec![format!(
                        "{} `{package}`: the published artifact carries NO provenance \
                         ({detail}) — publish through Trusted Publishing{}, so consumers can \
                         bind the tarball to this repository and this commit",
                        target.registry(),
                        match target {
                            PublishTarget::Npm => " with `npm publish --provenance`",
                            _ => " (PEP 740 attestations are generated automatically)",
                        }
                    )],
                )
            }
        }
    }
}

/// Pure classifier over a registry response body, so both verdicts are
/// testable against embedded payloads with no network.
pub fn classify_provenance(target: PublishTarget, body: &str) -> (bool, String) {
    match target {
        PublishTarget::Npm => {
            let v: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        false,
                        "the attestations endpoint did not return JSON".into(),
                    )
                }
            };
            let bundles = v
                .get("attestations")
                .and_then(|a| a.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let kinds: Vec<String> = v
                .get("attestations")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.get("predicateType").and_then(|p| p.as_str()))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if bundles == 0 {
                (false, "npm holds no attestation bundle for it".into())
            } else if kinds.is_empty() {
                (true, format!("{bundles} attestation bundle(s)"))
            } else {
                (true, kinds.join(", "))
            }
        }
        PublishTarget::PyPi => {
            // PyPI's PEP 691 simple index marks each file with
            // `provenance` (a URL) once PEP 740 attestations exist.
            let v: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                // The HTML simple index is served when JSON is not requested;
                // fall back to the textual marker rather than guessing.
                Err(_) => {
                    return if body.contains("data-provenance") {
                        (
                            true,
                            "PEP 740 attestations listed on the simple index".into(),
                        )
                    } else {
                        (false, "no PEP 740 attestation on the simple index".into())
                    }
                }
            };
            let files = v.get("files").and_then(|f| f.as_array());
            let attested = files
                .map(|f| {
                    f.iter()
                        .filter(|x| x.get("provenance").is_some_and(|p| !p.is_null()))
                        .count()
                })
                .unwrap_or(0);
            let total = files.map(|f| f.len()).unwrap_or(0);
            if attested > 0 {
                (
                    true,
                    format!("{attested} of {total} distribution(s) carry PEP 740 attestations"),
                )
            } else {
                (
                    false,
                    format!("none of {total} distribution(s) carry a PEP 740 attestation"),
                )
            }
        }
        _ => (false, "no provenance model for this registry".into()),
    }
}

enum FetchResult {
    Body(String),
    NotFound,
    Error(String),
}

/// The same bounded, anonymous `ureq` shape [`crate::deps::registry_exists`]
/// uses: a 10-second ceiling and an honest user agent, so a hung registry
/// cannot hang `sscsb verify`.
fn fetch(url: &str) -> FetchResult {
    let resp = ureq::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("sscsb (https://github.com/p4gs/sscs-bootstrapper)")
        .build()
        .get(url)
        // PyPI answers the simple index as JSON only when asked to.
        .set(
            "Accept",
            "application/vnd.pypi.simple.v1+json, application/json",
        )
        .call();
    match resp {
        Ok(r) => match r.into_string() {
            Ok(body) => FetchResult::Body(body),
            Err(e) => FetchResult::Error(e.to_string()),
        },
        Err(ureq::Error::Status(404, _)) => FetchResult::NotFound,
        Err(e) => FetchResult::Error(e.to_string()),
    }
}

/// A Homebrew formula's artifacts are OUR signed GitHub Releases, so the
/// question here is only whether the formula pins them by digest. A formula
/// with a `url` and no `sha256` installs whatever that URL serves today.
fn homebrew_sha_pins(ctx: &Ctx, manifest: &str) -> (Outcome, Vec<String>) {
    if manifest == OVERRIDE_MANIFEST {
        return (
            Outcome::Info,
            vec![
                "Homebrew: declared in `[targets]`, so the formula is not in this repository — \
                 its `sha256` pins are checkable only where the tap lives"
                    .to_string(),
            ],
        );
    }
    let path = ctx.root.join(manifest);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (
            Outcome::Degraded,
            vec![format!("Homebrew: could not read {manifest}")],
        );
    };
    let urls = text.matches("url ").count();
    let shas = text.matches("sha256 ").count();
    if urls == 0 {
        return (
            Outcome::Info,
            vec![format!(
                "Homebrew {manifest}: no `url` stanza — nothing is downloaded, so there is \
                 nothing to pin"
            )],
        );
    }
    if shas >= urls {
        (
            Outcome::Pass,
            vec![format!(
                "Homebrew {manifest}: {shas} `sha256` pin(s) for {urls} `url`(s) — the formula \
                 installs a specific artifact, not whatever that URL serves today ✓"
            )],
        )
    } else {
        (
            Outcome::Fail,
            vec![format!(
                "Homebrew {manifest}: {urls} `url`(s) but only {shas} `sha256` pin(s) — an \
                 unpinned download installs whatever the URL serves at install time. Run \
                 `brew fetch --force` and paste the digest"
            )],
        )
    }
}

// ─────────────────────────── 6. dist-manifests ──────────────────────────────

/// Local checksum integrity for the three PR-published ecosystems.
///
/// Homebrew, Chocolatey and WinGet all ship a manifest that names a download
/// and its expected digest. The digest is the whole trust boundary on the
/// consumer's machine, it is checkable offline, and a manifest missing it is a
/// concrete failure rather than an unverifiable claim.
pub fn verify_dist_manifests(ctx: &Ctx, _cfg: &Config) -> VerifyResult {
    let id = "dist-manifests";
    let policy = match policy_or_fail(ctx, id) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detected = match detect_or_degrade(ctx, &policy, id) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let manifest_targets: Vec<&DetectedTarget> = detected
        .iter()
        .filter(|d| {
            matches!(
                d.target,
                PublishTarget::Homebrew | PublishTarget::Chocolatey | PublishTarget::WinGet
            )
        })
        .collect();
    if manifest_targets.is_empty() {
        if detected.is_empty() {
            return no_targets(id);
        }
        return VerifyResult::new(
            id,
            Outcome::Info,
            vec![
                "no Homebrew, Chocolatey or WinGet manifest in this repository — the registries \
                 that publish by manifest are the ones with a locally checkable checksum, and \
                 this repository uses none of them"
                    .into(),
            ],
        );
    }

    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    for d in &manifest_targets {
        // A target that exists only because `[targets]` declares it has no
        // local manifest by construction — a tap in another repository, most
        // often. Saying so is the honest answer; degrading would blame the
        // maintainer for a file that was never supposed to be here.
        if d.manifest == OVERRIDE_MANIFEST {
            outcome = outcome.weakest(Outcome::Info);
            messages.push(format!(
                "{}: declared in `[targets]`, so its manifest is not in this repository and \
                 its checksums cannot be checked from here — run sscsb in the repository that \
                 holds the manifest",
                d.target.registry()
            ));
            continue;
        }
        let path = ctx.root.join(&d.manifest);
        let Ok(text) = std::fs::read_to_string(&path) else {
            outcome = outcome.weakest(Outcome::Degraded);
            messages.push(format!("could not read {}", d.manifest));
            continue;
        };
        let (o, lines) = check_manifest_checksums(d.target, &d.manifest, &text, &ctx.root);
        outcome = outcome.weakest(o);
        messages.extend(lines);
    }

    // The Authenticode claim: Windows' real trust anchor, and not verifiable
    // from macOS or Linux — so it is recorded, and only its expiry is graded.
    let windows = manifest_targets
        .iter()
        .any(|d| matches!(d.target, PublishTarget::Chocolatey | PublishTarget::WinGet));
    if windows {
        let today = chrono::Utc::now().date_naive();
        if policy.signing.authenticode {
            let subject = policy.signing.subject.as_deref().unwrap_or("(no subject)");
            let state = evaluate_expiry(policy.signing.expires.as_deref(), today, 0);
            let (line, failed) = expiry_line(&format!("Authenticode `{subject}`"), &state);
            messages.push(format!(
                "{line} — a declared claim; sscsb cannot verify an Authenticode chain off \
                 Windows and does not pretend to"
            ));
            if failed {
                outcome = outcome.weakest(Outcome::Fail);
            }
        } else {
            outcome = outcome.weakest(Outcome::Info);
            messages.push(
                "no `[signing]` block — Authenticode is what Windows actually checks before it \
                 runs your installer, and a checksum in a manifest does not replace it. Declare \
                 the certificate in .sscsb/policy/distribution.toml"
                    .to_string(),
            );
        }
    }
    VerifyResult::new(id, outcome, messages)
}

/// Per-ecosystem checksum check over a manifest's text. Pure apart from the
/// Chocolatey install-script read, which is the only case where the digest
/// lives in a sibling file.
fn check_manifest_checksums(
    target: PublishTarget,
    manifest: &str,
    text: &str,
    root: &Path,
) -> (Outcome, Vec<String>) {
    match target {
        PublishTarget::Homebrew => {
            let urls = text.matches("url ").count();
            let shas = text.matches("sha256 ").count();
            if urls == 0 {
                (
                    Outcome::Info,
                    vec![format!("{manifest}: no `url` stanza — nothing to pin")],
                )
            } else if shas >= urls {
                (
                    Outcome::Pass,
                    vec![format!(
                        "{manifest}: {shas} sha256 pin(s) for {urls} url(s) ✓"
                    )],
                )
            } else {
                (
                    Outcome::Fail,
                    vec![format!(
                        "{manifest}: {urls} url(s) but only {shas} sha256 pin(s) — an unpinned \
                         download installs whatever that URL serves at install time"
                    )],
                )
            }
        }
        PublishTarget::Chocolatey => {
            // The nuspec is metadata; the digest lives in the install script
            // beside it, which is the file that actually downloads anything.
            let dir = Path::new(manifest).parent().unwrap_or(Path::new(""));
            let candidates = [
                dir.join("tools/chocolateyinstall.ps1"),
                dir.join("chocolateyinstall.ps1"),
                Path::new("tools/chocolateyinstall.ps1").to_path_buf(),
            ];
            let found = candidates.iter().find_map(|rel| {
                std::fs::read_to_string(root.join(rel))
                    .ok()
                    .map(|t| (rel.to_string_lossy().replace('\\', "/"), t))
            });
            match found {
                None => (
                    Outcome::Fail,
                    vec![format!(
                        "{manifest}: no `chocolateyinstall.ps1` found beside it — the nuspec is \
                         metadata, and the install script is where the download and its \
                         `$checksum` live. Without one, nothing verifies what gets installed"
                    )],
                ),
                Some((script, body)) => {
                    let downloads = body.contains("Install-ChocolateyPackage")
                        || body.contains("Get-ChocolateyWebFile")
                        || body.contains("url");
                    let has_checksum = body.contains("checksum");
                    let has_type = body.contains("checksumType");
                    if !downloads {
                        (
                            Outcome::Pass,
                            vec![format!(
                                "{script}: downloads nothing (the package embeds its payload) — \
                                 no remote artifact to checksum ✓"
                            )],
                        )
                    } else if has_checksum && has_type {
                        (
                            Outcome::Pass,
                            vec![format!(
                                "{script}: declares `checksum` and `checksumType` for its \
                                 download ✓"
                            )],
                        )
                    } else if has_checksum {
                        (
                            Outcome::Fail,
                            vec![format!(
                                "{script}: has a `checksum` but no `checksumType` — Chocolatey \
                                 then guesses the algorithm, and a guess is not a verification. \
                                 Set `checksumType = 'sha256'`"
                            )],
                        )
                    } else {
                        (
                            Outcome::Fail,
                            vec![format!(
                                "{script}: downloads an artifact with NO `checksum` — every \
                                 install takes whatever the URL serves at that moment, which is \
                                 the exact shape of the Polyfill.io hijack"
                            )],
                        )
                    }
                }
            }
        }
        PublishTarget::WinGet => {
            if text.contains("InstallerSha256") {
                (
                    Outcome::Pass,
                    vec![format!("{manifest}: declares `InstallerSha256` ✓")],
                )
            } else {
                (
                    Outcome::Fail,
                    vec![format!(
                        "{manifest}: no `InstallerSha256` — microsoft/winget-pkgs requires it \
                         and the client checks it, so a manifest without one cannot be the \
                         manifest you ship"
                    )],
                )
            }
        }
        _ => (Outcome::Info, Vec::new()),
    }
}

// ────────────────────────────── `sscsb dist` ────────────────────────────────

/// `sscsb dist status`: what this repository publishes, and the posture in one
/// screen. Deliberately NOT a publish wrapper — see `docs/phase-6.md` for why
/// `sscsb publish` was considered and rejected.
pub fn render_status(ctx: &Ctx) -> Result<String> {
    let policy = load_policy(&policy_path(ctx))?;
    let detected = detect_targets(&ctx.root, &policy)?;
    let mut out = String::new();
    out.push_str("SSCS Bootstrapper — distribution status\n\n");
    if detected.is_empty() {
        out.push_str(
            "No publish target detected. sscsb looks for a Cargo.toml with [package], a\n\
             package.json without \"private\": true, a pyproject.toml with [project],\n\
             Formula/*.rb, a *.nuspec, or a winget *.installer.yaml — at the repository root\n\
             and one level down. Declare a target explicitly under [targets] in\n\
             .sscsb/policy/distribution.toml if that is wrong.\n",
        );
        return Ok(out);
    }
    out.push_str("Detected targets\n");
    for d in &detected {
        let pkg = d
            .package
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or("—");
        let _ = writeln!(out, "  {:<12} {:<28} {}", d.target.id(), pkg, d.manifest);
    }
    out.push('\n');
    out.push_str("Trusted Publishing\n");
    for target in distinct_targets(&detected) {
        let line = if target.oidc_capable() {
            match target.template() {
                Some(t) if ctx.root.join(t).is_file() => format!("{t} installed"),
                Some(t) => format!("{t} MISSING — run `sscsb init`"),
                None => "—".to_string(),
            }
        } else {
            match target {
                PublishTarget::Chocolatey => "no OIDC path in the ecosystem".to_string(),
                _ => "publishes by pull request (GitHub identity)".to_string(),
            }
        };
        let _ = writeln!(out, "  {:<12} {line}", target.id());
    }
    out.push('\n');
    if policy.accounts.is_empty() && policy.tokens.is_empty() {
        out.push_str(
            "No [[account]] or [[token]] claims declared. `sscsb verify maintainer-mfa` reads\n\
             what the registry APIs expose; the phishing-resistance of your second factor is\n\
             not one of those things, so it needs a dated claim.\n",
        );
    } else {
        out.push_str("Declared claims\n");
        for a in &policy.accounts {
            let _ = writeln!(
                out,
                "  account  {:<12} {} — mfa {} (attested {})",
                a.target.id(),
                a.identity,
                a.mfa.label(),
                a.attested.as_deref().unwrap_or("never")
            );
        }
        for t in &policy.tokens {
            let _ = writeln!(
                out,
                "  token    {:<12} {} — expires {}",
                t.target.id(),
                t.purpose,
                t.expires.as_deref().unwrap_or("never stated")
            );
        }
    }
    out.push_str(
        "\nRun `sscsb dist check` for the full phase-6 verdict (network probes included).\n",
    );
    Ok(out)
}

/// The six phase-6 control ids, in report order.
pub const PHASE_6_CONTROLS: &[&str] = &[
    "publish-targets",
    "trusted-publishing",
    "maintainer-mfa",
    "publish-tokens",
    "publish-provenance",
    "dist-manifests",
];

/// `sscsb dist check`: run every phase-6 verifier, whatever the config says
/// about the others. A break-glass preflight before an emergency manual
/// publish, when running the whole of `sscsb verify` is not what you have time
/// for.
pub fn run_check(ctx: &Ctx) -> Result<Vec<VerifyResult>> {
    let cfg = ctx.require_config()?;
    Ok(PHASE_6_CONTROLS
        .iter()
        .filter_map(|id| crate::controls::control(id))
        .map(|def| crate::controls::verify_control(ctx, cfg, def))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{audit_workflow, Severity};

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()
    }

    fn empty_policy() -> Policy {
        Policy::default()
    }

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        crate::exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], dir.path()).unwrap();
        crate::exec::git(
            &["config", "user.email", "sscsb-test@example.com"],
            dir.path(),
        )
        .unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// Flip one generated config option in place. The key already exists (the
    /// registry emits it), so appending a second `[controls.…]` section would
    /// be a TOML duplicate-key error rather than an override.
    fn set_option(root: &Path, from: &str, to: &str) {
        let path = root.join(".sscsb/config.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(from), "config has no `{from}` to replace");
        std::fs::write(&path, text.replace(from, to)).unwrap();
    }

    // ───────────────────────────── detection ────────────────────────────────

    #[test]
    fn a_workspace_only_cargo_manifest_publishes_nothing_but_its_members_do() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/a\"]\n",
        );
        let found = detect_targets(root, &empty_policy()).unwrap();
        assert!(
            found.is_empty(),
            "a pure [workspace] manifest publishes nothing: {found:?}"
        );

        write(
            root,
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        );
        let found = detect_targets(root, &empty_policy()).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].target, PublishTarget::CratesIo);
        assert_eq!(found[0].package.as_deref(), Some("a"));
        assert_eq!(found[0].manifest, "crates/a/Cargo.toml");
    }

    /// Regression, found by dogfooding sscsb on its own repository: `fuzz/`
    /// carries `publish = false`, and detection reported it as a second
    /// crates.io target — a crate that cannot be published even on purpose,
    /// dragging the repository's phase-6 verdict down for nothing.
    #[test]
    fn a_cargo_crate_marked_unpublishable_is_not_a_crates_io_target() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"real\"\nversion = \"0.1.0\"\n",
        );
        for body in [
            "[package]\nname = \"f\"\nversion = \"0.0.0\"\npublish = false\n",
            "[package]\nname = \"f\"\nversion = \"0.0.0\"\npublish = []\n",
        ] {
            write(root, "fuzz/Cargo.toml", body);
            let found = detect_targets(root, &empty_policy()).unwrap();
            assert_eq!(
                found.len(),
                1,
                "`{}` declares it is never uploaded: {found:?}",
                body.lines().last().unwrap()
            );
            assert_eq!(found[0].package.as_deref(), Some("real"));
        }
        // A private-registry allowlist is still a publish target — it names
        // where the crate goes, not that it goes nowhere.
        write(
            root,
            "fuzz/Cargo.toml",
            "[package]\nname = \"f\"\nversion = \"0.0.0\"\npublish = [\"internal\"]\n",
        );
        assert_eq!(detect_targets(root, &empty_policy()).unwrap().len(), 2);
    }

    #[test]
    fn a_private_package_json_is_not_an_npm_target_and_a_public_one_is() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","private":true}"#);
        assert!(detect_targets(root, &empty_policy()).unwrap().is_empty());

        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        let found = detect_targets(root, &empty_policy()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, PublishTarget::Npm);
        assert_eq!(found[0].package.as_deref(), Some("x"));
    }

    #[test]
    fn a_pyproject_with_only_a_build_system_publishes_nothing() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "pyproject.toml",
            "[build-system]\nrequires = [\"setuptools\"]\n\n[tool.ruff]\nline-length = 100\n",
        );
        assert!(
            detect_targets(root, &empty_policy()).unwrap().is_empty(),
            "a tooling-only pyproject declares no distributable package"
        );

        write(
            root,
            "pyproject.toml",
            "[project]\nname = \"thing\"\nversion = \"0.1.0\"\n",
        );
        let found = detect_targets(root, &empty_policy()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, PublishTarget::PyPi);
        assert_eq!(found[0].package.as_deref(), Some("thing"));
    }

    #[test]
    fn manifest_shapes_for_the_three_pr_published_ecosystems_are_recognised() {
        let dir = repo();
        let root = dir.path();
        write(root, "Formula/mytool.rb", "class Mytool < Formula\nend\n");
        write(root, "mytool.nuspec", "<package/>\n");
        write(
            root,
            "manifests/Me.Tool.installer.yaml",
            "InstallerSha256: x\n",
        );
        let found = detect_targets(root, &empty_policy()).unwrap();
        let targets: Vec<PublishTarget> = found.iter().map(|d| d.target).collect();
        assert!(targets.contains(&PublishTarget::Homebrew), "{found:?}");
        assert!(targets.contains(&PublishTarget::Chocolatey), "{found:?}");
        assert!(targets.contains(&PublishTarget::WinGet), "{found:?}");
    }

    #[test]
    fn detection_skips_build_output_and_vendored_trees() {
        let dir = repo();
        let root = dir.path();
        // A dependency's manifest says nothing about what WE publish. Without
        // the skip list, a single `npm install` would make every repository on
        // earth look like an npm publisher.
        write(
            root,
            "node_modules/left-pad/package.json",
            r#"{"name":"left-pad"}"#,
        );
        write(
            root,
            "target/package/thing/Cargo.toml",
            "[package]\nname=\"thing\"\n",
        );
        assert!(
            detect_targets(root, &empty_policy()).unwrap().is_empty(),
            "vendored and build-output manifests must never be read as our targets"
        );
    }

    #[test]
    fn targets_overrides_can_silence_a_real_detection_and_declare_an_absent_one() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x"}"#);

        let off = parse_policy("[targets]\nnpm = \"off\"\n").unwrap();
        assert!(
            detect_targets(root, &off).unwrap().is_empty(),
            "`off` must silence a detection the filesystem genuinely supports"
        );

        // The tap lives in another repository, so nothing local can prove it.
        let on = parse_policy("[targets]\nhomebrew = \"on\"\n").unwrap();
        let found = detect_targets(root, &on).unwrap();
        assert!(found.iter().any(|d| d.target == PublishTarget::Homebrew));
        assert!(found.iter().any(|d| d.target == PublishTarget::Npm));
    }

    #[test]
    fn a_homebrew_tap_is_detected_from_the_repository_name_alone() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("homebrew-tap");
        std::fs::create_dir_all(&root).unwrap();
        let found = detect_targets(&root, &empty_policy()).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].target, PublishTarget::Homebrew);
        assert_eq!(found[0].package.as_deref(), Some("tap"));
    }

    // ──────────────────────────── policy parsing ────────────────────────────

    #[test]
    fn the_shipped_template_parses_and_declares_nothing() {
        let policy = parse_policy(DISTRIBUTION_TEMPLATE).expect("the template must parse");
        assert_eq!(
            policy,
            Policy::default(),
            "every block in the template is commented out, so a fresh install asserts nothing"
        );
        for target in ALL_TARGETS {
            assert_eq!(policy.target_mode(*target), TargetMode::Auto);
        }
    }

    #[test]
    fn a_malformed_policy_is_an_error_not_an_empty_policy() {
        // Each of these is a typo a human would make, and each would be
        // silently read as "nothing declared" by a lenient parser — turning a
        // missing control into a passing one.
        for (body, needle) in [
            ("[targets]\nnpmm = \"on\"\n", "is not a publish target"),
            ("[targets]\nnpm = \"yes\"\n", "auto | on | off"),
            ("[[account]]\ntarget = \"npm\"\n", "needs an `identity`"),
            (
                "[[account]]\ntarget = \"npm\"\nidentity = \"a\"\nmfa = \"strong\"\n",
                "webauthn-only",
            ),
            (
                "[[account]]\ntarget = \"npm\"\nidentity = \"a\"\nmfa = \"totp\"\nattested = \"last tuesday\"\n",
                "not a YYYY-MM-DD date",
            ),
            ("[[token]]\ntarget = \"npm\"\n", "needs a `purpose`"),
            ("[signing]\nexpires = \"soon\"\n", "not a YYYY-MM-DD date"),
        ] {
            let err = format!("{:#}", parse_policy(body).unwrap_err());
            assert!(err.contains(needle), "`{body}` → `{err}`, wanted `{needle}`");
        }
    }

    #[test]
    fn two_accounts_for_one_target_is_an_unresolvable_policy() {
        let err = format!(
            "{:#}",
            parse_policy(
                "[[account]]\ntarget = \"npm\"\nidentity = \"a\"\nmfa = \"totp\"\n\n\
                 [[account]]\ntarget = \"npm\"\nidentity = \"b\"\nmfa = \"none\"\n"
            )
            .unwrap_err()
        );
        assert!(err.contains("two `[[account]]` entries for `npm`"), "{err}");
    }

    #[test]
    fn a_bare_toml_date_is_accepted_as_well_as_a_quoted_one() {
        // TOML parses `2026-01-15` into its own date type. Rejecting the
        // obvious spelling would make the policy file a guessing game.
        let policy = parse_policy(
            "[[account]]\ntarget = \"npm\"\nidentity = \"a\"\nmfa = \"webauthn-only\"\nattested = 2026-01-15\n",
        )
        .unwrap();
        assert_eq!(policy.accounts[0].attested.as_deref(), Some("2026-01-15"));
    }

    #[test]
    fn an_absent_policy_file_is_an_empty_policy_and_not_an_error() {
        let dir = repo();
        let policy = load_policy(&dir.path().join(".sscsb/policy/distribution.toml")).unwrap();
        assert_eq!(policy, Policy::default());
    }

    // ───────────────────────────── templates ────────────────────────────────

    /// ∀ publish templates: zero audit ERRORS under sscsb's OWN extended
    /// actions audit. Mirrors `workflows.rs`'s check rather than modifying it,
    /// because `DIST_ARTIFACTS` is deliberately a separate table.
    #[test]
    fn every_publish_template_passes_sscsbs_own_audit() {
        for a in DIST_ARTIFACTS {
            let rendered = crate::workflows::render(a.content, "owner/repo", "main");
            let findings = audit_workflow(a.dest, &rendered, true)
                .unwrap_or_else(|e| panic!("{} failed to parse: {e:#}", a.dest));
            let bad: Vec<_> = findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .collect();
            assert!(
                bad.is_empty(),
                "{} fails sscsb's own audit: {bad:?}",
                a.dest
            );
        }
    }

    #[test]
    fn every_publish_template_hardens_every_runner_and_holds_the_oidc_permission() {
        for a in DIST_ARTIFACTS {
            assert!(
                a.content.contains(
                    "step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920"
                ),
                "{} lacks the pinned harden-runner step",
                a.dest
            );
            assert!(
                a.content.contains("id-token: write"),
                "{} publishes without an OIDC identity — that is the whole control",
                a.dest
            );
            assert!(
                a.content.contains("environment: release"),
                "{} has no environment gate; an OIDC identity with no reviewer is a \
                 workflow_dispatch button wired to your namespace",
                a.dest
            );
        }
    }

    /// The anti-pattern these templates exist to replace must not appear in
    /// them. A template that quietly kept a `secrets.NPM_TOKEN` fallback would
    /// launder the exact credential this phase is built to delete.
    #[test]
    fn no_publish_template_references_a_long_lived_registry_secret() {
        for a in DIST_ARTIFACTS {
            let hits = references_token_secret(a.content, a.target.token_secrets());
            assert!(
                hits.is_empty(),
                "{} references the long-lived secret(s) {hits:?} — Trusted Publishing means \
                 there is no such secret",
                a.dest
            );
        }
    }

    #[test]
    fn publish_templates_render_without_leftover_placeholders_or_baked_identities() {
        for a in DIST_ARTIFACTS {
            let rendered = crate::workflows::render(a.content, "owner/repo", "main");
            // `${{ … }}` is GitHub Actions' own expression syntax and must
            // survive rendering untouched; only sscsb's placeholders are
            // supposed to disappear.
            for placeholder in [
                "{{repo_slug}}",
                "{{default_branch}}",
                "{{project}}",
                "{{owner}}",
            ] {
                assert!(
                    !rendered.contains(placeholder),
                    "{} still contains the unrendered placeholder {placeholder}",
                    a.dest
                );
            }
            assert!(
                !a.content.contains("/Users/") && !a.content.contains("/home/"),
                "{} contains a hardcoded home path",
                a.dest
            );
        }
    }

    #[test]
    fn every_dist_artifact_belongs_to_an_oidc_capable_target_that_names_it() {
        for a in DIST_ARTIFACTS {
            assert!(
                a.target.oidc_capable(),
                "{} is registered for {}, which has no Trusted Publishing path",
                a.dest,
                a.target.id()
            );
            assert_eq!(
                a.target.template(),
                Some(a.dest),
                "{} and PublishTarget::template() disagree about where it is installed",
                a.dest
            );
        }
    }

    /// The reason `DIST_ARTIFACTS` is not in `workflows::ARTIFACTS`, asserted
    /// rather than only commented: `install_all` gates on control-enabled
    /// alone, so a publish template registered there lands in every repo.
    #[test]
    fn publish_templates_are_not_registered_in_the_control_gated_artifact_table() {
        for a in DIST_ARTIFACTS {
            assert!(
                !crate::workflows::ARTIFACTS.iter().any(|w| w.dest == a.dest),
                "{} is in workflows::ARTIFACTS, where it would be installed into every \
                 repository whose trusted-publishing control is on — including the ones with \
                 no {} package at all",
                a.dest,
                a.target.registry()
            );
        }
    }

    #[test]
    fn install_templates_writes_only_the_detected_targets_workflow() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        crate::init::bootstrap(root).unwrap();

        assert!(
            root.join(".github/workflows/publish-npm.yml").is_file(),
            "an npm target must get its publish workflow"
        );
        assert!(
            !root.join(".github/workflows/publish-crates.yml").exists(),
            "a repo with no Cargo.toml [package] must NOT get a crates.io publish workflow"
        );
        assert!(
            !root.join(".github/workflows/publish-pypi.yml").exists(),
            "a repo with no pyproject [project] must NOT get a PyPI publish workflow"
        );
    }

    #[test]
    fn a_target_less_repo_gets_no_publish_workflow_at_all() {
        let dir = repo();
        let root = dir.path();
        crate::init::bootstrap(root).unwrap();
        for a in DIST_ARTIFACTS {
            assert!(
                !root.join(a.dest).exists(),
                "{} installed into a repository that publishes nothing",
                a.dest
            );
        }
    }

    #[test]
    fn install_templates_is_idempotent_and_never_overwrites_an_edit() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        crate::init::bootstrap(root).unwrap();
        let path = root.join(".github/workflows/publish-npm.yml");
        std::fs::write(&path, "# locally edited\n").unwrap();

        crate::init::bootstrap(root).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# locally edited\n",
            "a re-init must never clobber a workflow the maintainer edited"
        );
    }

    #[test]
    fn disabling_trusted_publishing_stops_the_templates_being_installed() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        crate::init::bootstrap(root).unwrap();
        std::fs::remove_file(root.join(".github/workflows/publish-npm.yml")).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        crate::config::set_control_enabled(&ctx.config_path(), "trusted-publishing", false)
            .unwrap();

        let ctx = Ctx::discover(root).unwrap();
        let lines = install_templates(&ctx, ctx.require_config().unwrap()).unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("trusted-publishing disabled")),
            "{lines:?}"
        );
        assert!(!root.join(".github/workflows/publish-npm.yml").exists());
    }

    // ────────────────────────── verifier behaviour ──────────────────────────

    fn bootstrapped(root: &Path) -> Ctx {
        crate::init::bootstrap(root).unwrap();
        Ctx::discover(root).unwrap()
    }

    #[test]
    fn every_phase_six_verifier_reports_info_and_never_fails_a_repo_that_publishes_nothing() {
        let dir = repo();
        let ctx = bootstrapped(dir.path());
        let cfg = ctx.require_config().unwrap();
        for id in PHASE_6_CONTROLS {
            let def = crate::controls::control(id).unwrap();
            let r = crate::controls::verify_control(&ctx, cfg, def);
            assert_eq!(
                r.outcome,
                Outcome::Info,
                "{id} graded a repository that publishes nothing: {:?}",
                r.messages
            );
            assert!(!r.messages.is_empty(), "{id} said nothing at all");
        }
    }

    #[test]
    fn publish_targets_inventories_every_detected_target_and_names_the_manifest() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"me\"\nversion = \"0.1.0\"\n",
        );
        write(root, "Formula/me.rb", "class Me < Formula\nend\n");
        let ctx = bootstrapped(root);
        let r = verify_publish_targets(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Info, "inventory never grades");
        let joined = r.messages.join("\n");
        assert!(joined.contains("crates.io `me` ← Cargo.toml"), "{joined}");
        assert!(joined.contains("Homebrew"), "{joined}");
        assert!(joined.contains("Trusted Publishing"), "{joined}");
    }

    #[test]
    fn a_broken_policy_file_fails_every_phase_six_control_rather_than_being_ignored() {
        let dir = repo();
        let root = dir.path();
        bootstrapped(root);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            "[targets]\nnpm = \"maybe\"\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let cfg = ctx.require_config().unwrap();
        for id in PHASE_6_CONTROLS {
            let def = crate::controls::control(id).unwrap();
            let r = crate::controls::verify_control(&ctx, cfg, def);
            assert_eq!(
                r.outcome,
                Outcome::Fail,
                "{id} read a malformed publishing policy as 'nothing declared'"
            );
            assert!(
                r.messages[0].contains("distribution policy invalid"),
                "{:?}",
                r.messages
            );
        }
    }

    #[test]
    fn trusted_publishing_fails_when_a_detected_target_has_no_publish_workflow() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        let ctx = bootstrapped(root);
        std::fs::remove_file(root.join(".github/workflows/publish-npm.yml")).unwrap();
        let r = verify_trusted_publishing(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        let joined = r.messages.join("\n");
        assert!(joined.contains("no workflow publishes to it"), "{joined}");
        assert!(joined.contains("sscsb init"), "{joined}");
    }

    #[test]
    fn trusted_publishing_fails_a_workflow_that_publishes_with_a_long_lived_token() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        let ctx = bootstrapped(root);
        // The exact anti-pattern: a hand-rolled release workflow that publishes
        // with a stored token. Our own template being installed beside it must
        // not launder this into a pass.
        write(
            root,
            ".github/workflows/release.yml",
            "name: r\non: [push]\npermissions:\n  contents: read\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
        );
        let r = verify_trusted_publishing(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        let joined = r.messages.join("\n");
        assert!(joined.contains("NPM_TOKEN"), "{joined}");
        assert!(joined.contains("Trusted Publishing"), "{joined}");
    }

    #[test]
    fn trusted_publishing_is_silent_about_targets_with_no_oidc_path() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        let ctx = bootstrapped(root);
        let r = verify_trusted_publishing(&ctx, ctx.require_config().unwrap());
        assert_eq!(
            r.outcome,
            Outcome::Info,
            "Chocolatey has no OIDC path, so there is nothing to fail: {:?}",
            r.messages
        );
        assert!(r.messages.join("\n").contains("no Trusted Publishing path"));
    }

    /// The environments API answers 404 for BOTH "no such environment" and "a
    /// token that cannot see environments". Asserting the first would tell a
    /// maintainer to create an environment that already exists.
    #[test]
    fn an_ambiguous_404_on_the_environment_read_degrades_rather_than_asserting_absence() {
        let protected = serde_json::json!({
            "name": "release",
            "protection_rules": [
                {"type": "required_reviewers", "reviewers": [{"type": "User"}]},
                {"type": "wait_timer", "wait_timer": 10}
            ]
        });
        match classify_environment(&protected) {
            EnvironmentRead::Protected(d) => {
                assert!(d.contains("1 required reviewer(s)"), "{d}");
                assert!(d.contains("10-minute wait timer"), "{d}");
            }
            _ => panic!("a reviewed, timed environment is protected"),
        }

        let bare = serde_json::json!({"name": "release", "protection_rules": []});
        assert!(
            matches!(classify_environment(&bare), EnvironmentRead::Unprotected),
            "an environment with no rules is a label, not a gate"
        );

        let branch_only = serde_json::json!({
            "name": "release",
            "protection_rules": [],
            "deployment_branch_policy": {"protected_branches": true}
        });
        assert!(
            matches!(
                classify_environment(&branch_only),
                EnvironmentRead::Protected(_)
            ),
            "a deployment-branch policy is a real restriction"
        );

        let nameless = serde_json::json!({"message": "Not Found"});
        assert!(matches!(
            classify_environment(&nameless),
            EnvironmentRead::Missing
        ));
    }

    // ────────────────────────── maintainer-mfa ──────────────────────────────

    #[test]
    fn github_two_factor_passes_on_true_fails_on_false_and_degrades_on_the_missing_scope() {
        let (o, reason, m) = classify_github_two_factor(
            &serde_json::json!({"login": "me", "two_factor_authentication": true}),
            "crates.io",
        );
        assert_eq!(o, Outcome::Pass);
        assert_eq!(reason, None);
        assert!(m[0].contains("2FA enabled"), "{m:?}");

        let (o, _, m) = classify_github_two_factor(
            &serde_json::json!({"login": "me", "two_factor_authentication": false}),
            "crates.io",
        );
        assert_eq!(o, Outcome::Fail);
        assert!(m[0].contains("2FA DISABLED"), "{m:?}");

        // The field is absent for a token without `read:user`. Reading that as
        // `false` would accuse a maintainer with a passkey of having no 2FA.
        let (o, reason, m) =
            classify_github_two_factor(&serde_json::json!({"login": "me"}), "crates.io");
        assert_eq!(o, Outcome::Degraded);
        assert_eq!(reason, Some("no-access"));
        assert!(m[0].contains("gh auth refresh -s read:user"), "{m:?}");
        assert!(
            m[0].contains("NOT a confirmed absence"),
            "the message must not read as a verdict: {m:?}"
        );
    }

    #[test]
    fn npm_tfa_passes_only_on_auth_and_writes() {
        let (o, _, m) = classify_npm_tfa(r#"{"name":"me","tfa":{"mode":"auth-and-writes"}}"#);
        assert_eq!(o, Outcome::Pass);
        assert!(m[0].contains("auth-and-writes"), "{m:?}");

        // `auth-only` gates login but not the publish itself — the exact gap a
        // stolen token walks through, so it fails rather than degrading.
        let (o, _, m) = classify_npm_tfa(r#"{"name":"me","tfa":{"mode":"auth-only"}}"#);
        assert_eq!(o, Outcome::Fail);
        assert!(m[0].contains("not PUBLISH"), "{m:?}");

        for body in [
            r#"{"name":"me","tfa":null}"#,
            r#"{"name":"me","tfa":false}"#,
            r#"{"name":"me"}"#,
        ] {
            let (o, _, m) = classify_npm_tfa(body);
            assert_eq!(o, Outcome::Fail, "{body}");
            assert!(m[0].contains("no two-factor"), "{body} → {m:?}");
        }

        // npm has shipped `tfa` as a bare string too.
        let (o, _, _) = classify_npm_tfa(r#"{"name":"me","tfa":"auth-and-writes"}"#);
        assert_eq!(o, Outcome::Pass);

        let (o, reason, m) = classify_npm_tfa("not json");
        assert_eq!(o, Outcome::Degraded);
        assert_eq!(reason, Some("scan-error"));
        assert!(m[0].contains("did not return JSON"), "{m:?}");
        // The unparseable payload is withheld along with the parse error: a
        // profile that will not parse is still a profile.
        assert!(!m[0].contains("not json"), "{m:?}");
    }

    #[test]
    fn pypi_and_chocolatey_report_their_registry_facts_without_grading_them() {
        let dir = repo();
        let root = dir.path();
        write(root, "pyproject.toml", "[project]\nname = \"p\"\n");
        write(root, "p.nuspec", "<package/>\n");
        let ctx = bootstrapped(root);
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        let joined = r.messages.join("\n");
        assert!(joined.contains("2FA is MANDATORY"), "{joined}");
        assert!(
            joined.contains("deliberately NOT a failure"),
            "an unfixable ecosystem gap must not make --strict permanently red: {joined}"
        );
        assert_ne!(
            r.outcome,
            Outcome::Fail,
            "neither registry fact is a repository failure: {joined}"
        );
    }

    #[test]
    fn a_stale_mfa_claim_fails_and_a_fresh_one_only_documents() {
        let dir = repo();
        let root = dir.path();
        write(root, "pyproject.toml", "[project]\nname = \"p\"\n");
        bootstrapped(root);

        // Fresh: reported, never a pass it could not earn.
        let fresh = chrono::Utc::now().date_naive() - chrono::Duration::days(5);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[account]]\ntarget = \"pypi\"\nidentity = \"me\"\nmfa = \"webauthn-only\"\nattested = \"{fresh}\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        assert_ne!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages.join("\n").contains("phishing-resistant"),
            "{:?}",
            r.messages
        );

        // Stale: the claim is older than the window, so it FAILS — an expired
        // assertion about a publishing account is as actionable as an expired key.
        let stale = chrono::Utc::now().date_naive() - chrono::Duration::days(400);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[account]]\ntarget = \"pypi\"\nidentity = \"me\"\nmfa = \"webauthn-only\"\nattested = \"{stale}\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages.join("\n").contains("past the 180d window"),
            "{:?}",
            r.messages
        );
    }

    /// `attested` and `expires` run in OPPOSITE directions, and conflating
    /// them type-checks while grading backwards.
    ///
    /// `expires` is a future date and a bigger gap is better; `attested` is a
    /// past date and a bigger gap is worse. If `[[account]] attested` were fed
    /// to `evaluate_expiry`, a claim last checked years ago would land in
    /// `Expired` (which happens to fail, so the bug would hide) while a claim
    /// dated *tomorrow* would read as comfortably `Valid` — a claim about the
    /// future, treated as fresher than one made today. Both directions are
    /// pinned here because only the second one is visibly wrong.
    #[test]
    fn account_freshness_counts_backward_while_token_expiry_counts_forward() {
        let dir = repo();
        let root = dir.path();
        write(root, "pyproject.toml", "[project]\nname = \"p\"\n");
        bootstrapped(root);
        let today = chrono::Utc::now().date_naive();

        // A date in the FUTURE is not freshness — it is a claim about a check
        // that has not happened. It must not read as the healthiest state.
        let tomorrow = today + chrono::Duration::days(1);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[account]]\ntarget = \"pypi\"\nidentity = \"me\"\nmfa = \"webauthn-only\"\nattested = \"{tomorrow}\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        assert!(
            r.messages.join("\n").contains("confirmed -1d ago"),
            "a future `attested` must be reported as the nonsense it is, not as \
             maximally fresh: {:?}",
            r.messages
        );

        // The same span in the other direction on a `[[token]] expires` is the
        // healthy case, which is what makes the two fields' directions real.
        write(root, "t.nuspec", "<package/>\n");
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[token]]\ntarget = \"chocolatey\"\npurpose = \"push key\"\nscoped = true\ncidr_allowlist = true\nexpires = \"{tomorrow}\"\nstored_in = \"1Password\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        assert_ne!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages.join("\n").contains("valid, 1d left"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn an_attestation_file_that_is_not_there_is_a_misconfiguration_not_an_attestation() {
        let dir = repo();
        let root = dir.path();
        write(root, "pyproject.toml", "[project]\nname = \"p\"\n");
        bootstrapped(root);
        let fresh = chrono::Utc::now().date_naive();
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[account]]\ntarget = \"pypi\"\nidentity = \"me\"\nmfa = \"webauthn-only\"\nattested = \"{fresh}\"\nattestation_file = \".sscsb/policy/attestations/nope.png\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages
                .join("\n")
                .contains("names a file that is not there"),
            "{:?}",
            r.messages
        );

        // Present: hashed and reported, and it does NOT lift the verdict.
        write(root, ".sscsb/policy/attestations/nope.png", "bytes");
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        assert!(
            r.messages.join("\n").contains("sha256:"),
            "{:?}",
            r.messages
        );
    }

    // ────────────────────────── publish-tokens ──────────────────────────────

    #[test]
    fn a_committed_npmrc_with_an_auth_token_is_a_hard_failure() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        // The VALUE is deliberately not token-shaped. The detector keys on the
        // `_authToken` marker, never on the value, so a realistic-looking
        // literal would buy the test nothing and would put a string that
        // pattern-matches a real npm granular token into this repository's own
        // history — which is the thing this control exists to prevent.
        write(root, ".npmrc", "//registry.npmjs.org/:_authToken=EXAMPLE\n");
        bootstrapped(root);
        crate::exec::git(&["add", "-A"], root).unwrap();
        crate::exec::git(&["commit", "--no-verify", "-m", "fixture"], root).unwrap();

        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        let joined = r.messages.join("\n");
        assert!(joined.contains(".npmrc is COMMITTED"), "{joined}");
        assert!(
            joined.contains("Revoke it at the registry first"),
            "the only correct first step for a leaked credential: {joined}"
        );
    }

    #[test]
    fn an_untracked_npmrc_is_the_maintainers_own_business() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        write(root, ".npmrc", "//registry.npmjs.org/:_authToken=x\n");
        let ctx = bootstrapped(root);
        // Never committed, so `git ls-files` does not list it.
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        assert!(
            !r.messages.iter().any(|m| m.contains("COMMITTED")),
            "an untracked credential file is not in anyone else's hands: {:?}",
            r.messages
        );
    }

    #[test]
    fn an_expired_declared_token_fails_and_a_live_one_is_only_reported() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        bootstrapped(root);

        let expired = chrono::Utc::now().date_naive() - chrono::Duration::days(3);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[token]]\ntarget = \"chocolatey\"\npurpose = \"push key\"\nscoped = true\nexpires = \"{expired}\"\nstored_in = \"1Password\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages.join("\n").contains("EXPIRED"),
            "{:?}",
            r.messages
        );

        let live = chrono::Utc::now().date_naive() + chrono::Duration::days(30);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[[token]]\ntarget = \"chocolatey\"\npurpose = \"push key\"\nscoped = true\ncidr_allowlist = true\nexpires = \"{live}\"\nstored_in = \"1Password\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        assert_ne!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(r.messages.join("\n").contains("valid,"), "{:?}", r.messages);
    }

    #[test]
    fn a_token_secret_on_a_registry_with_an_oidc_path_fails_and_one_without_does_not() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        let ctx = bootstrapped(root);
        write(
            root,
            ".github/workflows/old-release.yml",
            "name: r\non: [push]\npermissions:\n  contents: read\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo publish\n        env:\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n",
        );
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages
                .join("\n")
                .contains("supports Trusted Publishing, so the secret is avoidable"),
            "{:?}",
            r.messages
        );
    }

    /// The Trusted-Publishing spelling and the stored-credential spelling use
    /// the SAME environment variable name. Keying on `secrets.` is what keeps
    /// our own template from failing the control it implements.
    #[test]
    fn an_oidc_exchanged_token_is_not_mistaken_for_a_stored_credential() {
        let template = DIST_ARTIFACTS
            .iter()
            .find(|a| a.target == PublishTarget::CratesIo)
            .unwrap();
        assert!(
            template.content.contains("CARGO_REGISTRY_TOKEN"),
            "precondition: the template does set that env var, from the OIDC exchange"
        );
        assert!(
            references_token_secret(template.content, PublishTarget::CratesIo.token_secrets())
                .is_empty(),
            "a `steps.auth.outputs.token` value is the OPPOSITE of a stored secret"
        );
    }

    // ──────────────────────── publish-provenance ────────────────────────────

    #[test]
    fn the_npm_provenance_classifier_reads_both_verdicts_off_a_real_payload_shape() {
        let attested = r#"{"attestations":[
            {"predicateType":"https://slsa.dev/provenance/v1","bundle":{}},
            {"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1","bundle":{}}
        ]}"#;
        let (has, detail) = classify_provenance(PublishTarget::Npm, attested);
        assert!(has, "{detail}");
        assert!(detail.contains("slsa.dev/provenance"), "{detail}");

        let (has, detail) = classify_provenance(PublishTarget::Npm, r#"{"attestations":[]}"#);
        assert!(!has);
        assert!(detail.contains("no attestation bundle"), "{detail}");

        let (has, detail) = classify_provenance(PublishTarget::Npm, "<html>502</html>");
        assert!(!has);
        assert!(detail.contains("did not return JSON"), "{detail}");
    }

    #[test]
    fn the_pypi_provenance_classifier_counts_attested_distributions() {
        let attested = r#"{"files":[
            {"filename":"p-1.0.tar.gz","provenance":"https://pypi.org/integrity/.../provenance"},
            {"filename":"p-1.0-py3-none-any.whl","provenance":"https://pypi.org/integrity/.../provenance"}
        ]}"#;
        let (has, detail) = classify_provenance(PublishTarget::PyPi, attested);
        assert!(has, "{detail}");
        assert!(detail.contains("2 of 2"), "{detail}");

        let bare = r#"{"files":[{"filename":"p-1.0.tar.gz","provenance":null}]}"#;
        let (has, detail) = classify_provenance(PublishTarget::PyPi, bare);
        assert!(!has);
        assert!(detail.contains("none of 1"), "{detail}");
    }

    /// Every verdict the registry probe can reach, with the response injected.
    ///
    /// The distinctions here are the whole control: an unpublished package is
    /// a SKIP (you cannot fail to attest something you never shipped), an
    /// unreachable registry is UNVERIFIED and must never read as "no
    /// provenance", and only a real attestation earns a Pass.
    #[test]
    fn every_registry_probe_verdict_is_reachable_and_says_the_right_thing() {
        let url = "https://registry.npmjs.org/-/npm/v1/attestations/p";

        let (o, reason, m) = classify_probe(PublishTarget::Npm, "p", url, FetchResult::NotFound);
        assert_eq!(o, Outcome::Info, "never-published is a skip, not a failure");
        assert_eq!(reason, None);
        assert!(m[0].contains("never published"), "{m:?}");

        let (o, reason, m) = classify_probe(
            PublishTarget::Npm,
            "p",
            url,
            FetchResult::Error("dns failure".into()),
        );
        assert_eq!(o, Outcome::Degraded);
        assert_eq!(reason, Some("scan-error"));
        assert!(
            m[0].contains("UNVERIFIED, not absent"),
            "an unreachable registry is not evidence of missing provenance: {m:?}"
        );
        assert!(m[0].contains("probe_registry = false"), "{m:?}");

        let (o, _, m) = classify_probe(
            PublishTarget::Npm,
            "p",
            url,
            FetchResult::Body(
                r#"{"attestations":[{"predicateType":"https://slsa.dev/provenance/v1"}]}"#.into(),
            ),
        );
        assert_eq!(o, Outcome::Pass);
        assert!(m[0].contains("carries provenance"), "{m:?}");

        let (o, _, m) = classify_probe(
            PublishTarget::Npm,
            "p",
            url,
            FetchResult::Body(r#"{"attestations":[]}"#.into()),
        );
        assert_eq!(o, Outcome::Fail);
        assert!(m[0].contains("NO provenance"), "{m:?}");
        assert!(
            m[0].contains("npm publish --provenance"),
            "the remediation must be the npm one: {m:?}"
        );

        // PyPI's remediation differs — attestations are automatic there, so
        // telling someone to pass `--provenance` would be wrong advice.
        let (o, _, m) = classify_probe(
            PublishTarget::PyPi,
            "p",
            "https://pypi.org/simple/p/",
            FetchResult::Body(r#"{"files":[{"filename":"p-1.0.tar.gz"}]}"#.into()),
        );
        assert_eq!(o, Outcome::Fail);
        assert!(
            m[0].contains("PEP 740 attestations are generated automatically"),
            "{m:?}"
        );

        // A registry with no provenance model reaches no verdict at all.
        let (o, _, m) = probe_provenance(PublishTarget::CratesIo, "p");
        assert_eq!(o, Outcome::Info);
        assert!(m.is_empty(), "no endpoint means nothing to say here: {m:?}");
    }

    #[test]
    fn probe_urls_are_built_only_for_the_registries_that_serve_provenance() {
        assert_eq!(
            provenance_probe_url(PublishTarget::Npm, "left-pad").as_deref(),
            Some("https://registry.npmjs.org/-/npm/v1/attestations/left-pad")
        );
        assert_eq!(
            provenance_probe_url(PublishTarget::PyPi, "requests").as_deref(),
            Some("https://pypi.org/simple/requests/")
        );
        for t in [
            PublishTarget::CratesIo,
            PublishTarget::Homebrew,
            PublishTarget::Chocolatey,
            PublishTarget::WinGet,
        ] {
            assert_eq!(
                provenance_probe_url(t, "x"),
                None,
                "{} has no artifact-provenance endpoint to probe",
                t.id()
            );
        }
    }

    /// The air-gapped opt-out must be hermetic: no socket is opened, and the
    /// control says the check was narrowed rather than claiming it passed.
    #[test]
    fn probe_registry_false_makes_the_control_hermetic_and_says_so() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        let ctx = bootstrapped(root);
        drop(ctx);
        set_option(root, "probe_registry = true", "probe_registry = false");
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_provenance(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Info);
        let joined = r.messages.join("\n");
        assert!(joined.contains("probe_registry = false"), "{joined}");
        assert!(
            joined.contains("not a passing one"),
            "declining a check must not read as passing it: {joined}"
        );
    }

    #[test]
    fn crates_io_reports_the_ecosystem_gap_rather_than_inventing_a_verdict() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        let ctx = bootstrapped(root);
        drop(ctx);
        set_option(root, "probe_registry = true", "probe_registry = false");
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_provenance(&ctx, ctx.require_config().unwrap());
        assert!(
            r.messages
                .join("\n")
                .contains("no artifact-level provenance exists in the ecosystem yet"),
            "{:?}",
            r.messages
        );
        assert_ne!(r.outcome, Outcome::Fail);
    }

    #[test]
    fn an_unpinned_homebrew_formula_fails_and_a_pinned_one_passes() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Formula/t.rb",
            "class T < Formula\n  url \"https://example.com/t.tar.gz\"\nend\n",
        );
        let ctx = bootstrapped(root);
        let r = verify_publish_provenance(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages
                .join("\n")
                .contains("installs whatever the URL serves"),
            "{:?}",
            r.messages
        );

        write(
            root,
            "Formula/t.rb",
            "class T < Formula\n  url \"https://example.com/t.tar.gz\"\n  sha256 \"abc\"\nend\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_provenance(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
    }

    // ─────────────────────────── dist-manifests ─────────────────────────────

    #[test]
    fn a_winget_manifest_without_an_installer_digest_fails() {
        let dir = repo();
        let root = dir.path();
        write(root, "manifests/T.installer.yaml", "InstallerType: exe\n");
        let ctx = bootstrapped(root);
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages.join("\n").contains("no `InstallerSha256`"),
            "{:?}",
            r.messages
        );

        write(
            root,
            "manifests/T.installer.yaml",
            "InstallerType: exe\nInstallerSha256: ABC123\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        let joined = r.messages.join("\n");
        assert!(joined.contains("declares `InstallerSha256`"), "{joined}");
    }

    #[test]
    fn a_chocolatey_install_script_that_downloads_without_a_checksum_fails() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        write(
            root,
            "tools/chocolateyinstall.ps1",
            "Install-ChocolateyPackage -Url 'https://example.com/t.exe'\n",
        );
        let ctx = bootstrapped(root);
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        let joined = r.messages.join("\n");
        assert!(joined.contains("NO `checksum`"), "{joined}");
        assert!(joined.contains("Polyfill.io"), "{joined}");

        // A checksum with no algorithm makes Chocolatey guess, and a guess is
        // not a verification.
        write(
            root,
            "tools/chocolateyinstall.ps1",
            "Install-ChocolateyPackage -Url 'https://example.com/t.exe' -checksum 'abc'\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages.join("\n").contains("no `checksumType`"),
            "{:?}",
            r.messages
        );

        write(
            root,
            "tools/chocolateyinstall.ps1",
            "Install-ChocolateyPackage -Url 'https://example.com/t.exe' -checksum 'abc' -checksumType 'sha256'\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert!(
            r.messages
                .join("\n")
                .contains("declares `checksum` and `checksumType`"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn a_nuspec_with_no_install_script_beside_it_fails_rather_than_passing_vacuously() {
        let dir = repo();
        let root = dir.path();
        write(root, "packages/t/t.nuspec", "<package/>\n");
        let ctx = bootstrapped(root);
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages.join("\n").contains("no `chocolateyinstall.ps1`"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn an_expired_authenticode_claim_fails_and_a_missing_block_is_only_flagged() {
        let dir = repo();
        let root = dir.path();
        write(root, "manifests/T.installer.yaml", "InstallerSha256: ABC\n");
        let ctx = bootstrapped(root);
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Info, "{:?}", r.messages);
        assert!(r.messages.join("\n").contains("no `[signing]` block"));

        let expired = chrono::Utc::now().date_naive() - chrono::Duration::days(10);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            &format!(
                "[signing]\nauthenticode = true\nsubject = \"CN=Me\"\nexpires = \"{expired}\"\n"
            ),
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Fail);
        let joined = r.messages.join("\n");
        assert!(joined.contains("EXPIRED"), "{joined}");
        assert!(
            joined.contains("cannot verify an Authenticode chain off"),
            "the claim must never read as a verification: {joined}"
        );
    }

    /// A target declared only by `[targets]` has no local manifest by
    /// construction — a Homebrew tap in another repository is the motivating
    /// case. The checksum controls must say that, not degrade as though a file
    /// were missing: the sentinel is not a path, and a tool that misreads its
    /// own sentinel produces a finding about itself.
    #[test]
    fn a_target_declared_only_by_override_has_no_manifest_to_check_and_says_so() {
        let dir = repo();
        let root = dir.path();
        bootstrapped(root);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            "[targets]\nhomebrew = \"on\"\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let cfg = ctx.require_config().unwrap();

        let r = verify_dist_manifests(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Info, "{:?}", r.messages);
        let joined = r.messages.join("\n");
        assert!(joined.contains("declared in `[targets]`"), "{joined}");
        assert!(
            !joined.contains("could not read"),
            "the sentinel must never be read as a filename: {joined}"
        );

        let r = verify_publish_provenance(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Info, "{:?}", r.messages);
        assert!(
            !r.messages.join("\n").contains("could not read"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn dist_manifests_is_silent_for_a_repo_that_publishes_only_to_code_registries() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        let ctx = bootstrapped(root);
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Info);
        assert!(
            r.messages.join("\n").contains("publish by manifest"),
            "{:?}",
            r.messages
        );
    }

    // ────────────────────────────── expiry ──────────────────────────────────

    #[test]
    fn expiry_lines_reuse_the_signer_vocabulary_and_only_two_states_fail() {
        for (state, fails, needle) in [
            (ExpiryState::Unset, false, "no expiry declared"),
            (ExpiryState::Valid { days_left: 12 }, false, "12d left"),
            (ExpiryState::Expired { days_ago: 3 }, true, "EXPIRED 3d ago"),
            (
                ExpiryState::WindowTooLong {
                    days_left: 400,
                    max: 90,
                },
                false,
                "longer than the 90d window",
            ),
            (ExpiryState::Unparseable, true, "not a YYYY-MM-DD"),
        ] {
            let (line, failed) = expiry_line("t", &state);
            assert_eq!(failed, fails, "{line}");
            assert!(line.contains(needle), "{line}");
        }
        // And the evaluator itself is signers.rs's, not a second copy.
        assert_eq!(
            evaluate_expiry(Some("2026-05-01"), today(), 0),
            ExpiryState::Expired { days_ago: 31 }
        );
    }

    // ──────────────────────────── `sscsb dist` ──────────────────────────────

    #[test]
    fn dist_status_names_every_target_its_manifest_and_whether_the_template_is_there() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"me\"\nversion = \"0.1.0\"\n",
        );
        let ctx = bootstrapped(root);
        let text = render_status(&ctx).unwrap();
        assert!(text.contains("crates-io"), "{text}");
        assert!(text.contains("Cargo.toml"), "{text}");
        assert!(text.contains("publish-crates.yml installed"), "{text}");
        assert!(
            text.contains("No [[account]] or [[token]] claims"),
            "{text}"
        );

        std::fs::remove_file(root.join(".github/workflows/publish-crates.yml")).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let text = render_status(&ctx).unwrap();
        assert!(text.contains("MISSING — run `sscsb init`"), "{text}");
    }

    #[test]
    fn dist_status_on_a_repo_that_publishes_nothing_explains_what_it_looked_for() {
        let dir = repo();
        let ctx = bootstrapped(dir.path());
        let text = render_status(&ctx).unwrap();
        assert!(text.contains("No publish target detected"), "{text}");
        assert!(text.contains("pyproject.toml with [project]"), "{text}");
    }

    // ───────────────── gh / npm paths, with fake tools on PATH ─────────────
    //
    // These verifiers shell out, so their real branches are unreachable from a
    // fixture unless the tool is made to answer. `testutil`'s decoy-PATH
    // helpers give each case a `gh` or `npm` that returns exactly the payload
    // under test, which is the only way to exercise a Pass, a Fail and a
    // degrade through the SAME code an operator runs.

    /// The three environment verdicts, end to end through `verify`, not just
    /// through the pure classifier. The environment gate is half of
    /// `trusted-publishing`: an OIDC identity nobody reviews is a
    /// workflow_dispatch button, so "no rules" must FAIL and not merely note.
    #[test]
    fn the_environment_gate_fails_unprotected_and_passes_reviewed_through_the_real_verifier() {
        let (dir, _) = crate::testutil::repo_with_gh_repo("o/r", "main");
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        crate::init::bootstrap(root).unwrap();

        let cases = [
            (
                r#"{"name":"release","protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User"}]}]}"#,
                Outcome::Pass,
                "environment protected",
            ),
            (
                r#"{"name":"release","protection_rules":[]}"#,
                Outcome::Fail,
                "a label rather than a gate",
            ),
            (
                r#"{"message":"Not Found"}"#,
                Outcome::Fail,
                "create it and add required reviewers",
            ),
        ];
        for (payload, want, needle) in cases {
            let r = crate::testutil::with_env(|lock| {
                lock.fake_tool("gh", &format!("cat <<'EOF'\n{payload}\nEOF"));
                let ctx = Ctx::discover(root).unwrap();
                verify_trusted_publishing(&ctx, ctx.require_config().unwrap())
            });
            let joined = r.messages.join("\n");
            assert_eq!(r.outcome, want, "payload {payload} → {joined}");
            assert!(joined.contains(needle), "payload {payload} → {joined}");
        }
    }

    /// `gh` present but refusing is NOT `gh` absent, and neither is a verdict
    /// about the repository. Both degrade, with different reasons, so a
    /// consumer can tell "install a tool" from "grant a scope".
    #[test]
    fn an_unreadable_environment_degrades_with_the_reason_that_actually_applies() {
        let (dir, _) = crate::testutil::repo_with_gh_repo("o/r", "main");
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        crate::init::bootstrap(root).unwrap();

        // A 404 is ambiguous — no such environment, OR a token that cannot see
        // environments. Asserting the first would tell a maintainer to create
        // something that already exists.
        let r = crate::testutil::with_env(|lock| {
            lock.fake_tool("gh", "echo 'gh: Not Found (HTTP 404)' >&2; exit 1");
            let ctx = Ctx::discover(root).unwrap();
            verify_trusted_publishing(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("no-access"));
        assert!(
            r.messages.join("\n").contains("not confirmed absent"),
            "{:?}",
            r.messages
        );

        // No gh at all is a different reason entirely.
        let r = crate::testutil::with_env(|lock| {
            // `hide_from_path`, NOT `only_git_on_path`: on a GitHub runner `gh`
            // lives in /usr/bin beside `git`, so masking PATH down to git's own
            // directory leaves gh perfectly resolvable and the test then
            // asserts the opposite of what it set up. Green on a Mac, red on
            // the runner. Hide the one binary instead.
            lock.hide_from_path(&["gh"]);
            assert!(
                exec::find_in_path("gh").is_none(),
                "precondition: this case is about gh being ABSENT, and a fixture that \
                 quietly failed to hide it would assert a degrade it never set up"
            );
            let ctx = Ctx::discover(root).unwrap();
            verify_trusted_publishing(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("tool-missing"));
    }

    /// The far-left control, through the real verifier: 2FA on passes, 2FA off
    /// FAILS, and a response missing the field degrades rather than convicting
    /// a maintainer who holds a passkey.
    #[test]
    fn maintainer_mfa_reads_the_github_account_through_the_real_verifier() {
        let (dir, _) = crate::testutil::repo_with_gh_repo("o/r", "main");
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        crate::init::bootstrap(root).unwrap();

        for (payload, want, needle) in [
            (
                r#"{"login":"maintainer","two_factor_authentication":true}"#,
                Outcome::Pass,
                "2FA enabled",
            ),
            (
                r#"{"login":"maintainer","two_factor_authentication":false}"#,
                Outcome::Fail,
                "2FA DISABLED",
            ),
            (
                r#"{"login":"maintainer"}"#,
                Outcome::Degraded,
                "gh auth refresh -s read:user",
            ),
        ] {
            let r = crate::testutil::with_env(|lock| {
                lock.fake_tool("gh", &format!("cat <<'EOF'\n{payload}\nEOF"));
                let ctx = Ctx::discover(root).unwrap();
                verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
            });
            let joined = r.messages.join("\n");
            assert_eq!(r.outcome, want, "payload {payload} → {joined}");
            assert!(joined.contains(needle), "payload {payload} → {joined}");
        }
    }

    /// Without a GitHub remote, the account `gh` is logged in as is whoever
    /// owns the laptop — not whoever owns the package. Grading on that is the
    /// false positive this project refuses to ship, so it degrades instead.
    #[test]
    fn maintainer_mfa_will_not_grade_a_repo_with_no_remote_on_the_ambient_login() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        bootstrapped(root);
        let r = crate::testutil::with_env(|lock| {
            // A `gh` that WOULD answer, to prove the gate is the remote and
            // not merely the tool's absence.
            lock.fake_tool(
                "gh",
                "cat <<'EOF'\n{\"login\":\"somebody\",\"two_factor_authentication\":false}\nEOF",
            );
            let ctx = Ctx::discover(root).unwrap();
            verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("no-remote"));
        assert!(
            r.messages.join("\n").contains("would only be a guess"),
            "{:?}",
            r.messages
        );
    }

    /// An undated claim is the quiet failure mode of any attestation scheme:
    /// it can never go stale, which is exactly why it can never be trusted.
    /// Reported, never counted as evidence.
    #[test]
    fn an_undated_account_claim_is_reported_as_uncheckable_rather_than_accepted() {
        let dir = repo();
        let root = dir.path();
        write(root, "pyproject.toml", "[project]\nname = \"p\"\n");
        bootstrapped(root);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            "[[account]]\ntarget = \"pypi\"\nidentity = \"me\"\nmfa = \"webauthn-only\"\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_maintainer_mfa(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Info, "{:?}", r.messages);
        let joined = r.messages.join("\n");
        assert!(joined.contains("no `attested` date"), "{joined}");
        assert!(joined.contains("cannot go stale"), "{joined}");
    }

    /// A repo that DOES name a GitHub remote, with no `gh` to ask: the account
    /// is knowable in principle and unreadable in practice, which is a degrade
    /// naming the tool — distinct from the no-remote case above, where the
    /// account is not knowable at all.
    #[test]
    fn a_missing_gh_degrades_on_the_tool_when_the_remote_is_known() {
        let (dir, _) = crate::testutil::repo_with_gh_repo("o/r", "main");
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        crate::init::bootstrap(root).unwrap();
        let r = crate::testutil::with_env(|lock| {
            // git and gh share /usr/bin on a GitHub runner, so only hiding the
            // one binary actually hides it.
            lock.hide_from_path(&["gh"]);
            assert!(
                exec::find_in_path("gh").is_none(),
                "precondition: gh is hidden"
            );
            let ctx = Ctx::discover(root).unwrap();
            verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("tool-missing"));
        assert!(
            r.messages
                .join("\n")
                .contains("publish under a GitHub identity, and its 2FA state was not read"),
            "{:?}",
            r.messages
        );
    }

    /// npm's `tfa.mode`, through the real verifier rather than the classifier.
    #[test]
    fn maintainer_mfa_reads_npm_tfa_mode_through_the_real_verifier() {
        let dir = repo();
        let root = dir.path();
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        bootstrapped(root);

        for (payload, want, needle) in [
            (
                r#"{"name":"me","tfa":{"mode":"auth-and-writes"}}"#,
                Outcome::Pass,
                "auth-and-writes",
            ),
            (
                r#"{"name":"me","tfa":{"mode":"auth-only"}}"#,
                Outcome::Fail,
                "not PUBLISH",
            ),
        ] {
            let r = crate::testutil::with_env(|lock| {
                lock.fake_tool("npm", &format!("cat <<'EOF'\n{payload}\nEOF"));
                let ctx = Ctx::discover(root).unwrap();
                verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
            });
            let joined = r.messages.join("\n");
            assert_eq!(r.outcome, want, "payload {payload} → {joined}");
            assert!(joined.contains(needle), "payload {payload} → {joined}");
        }

        // Unauthenticated npm is Degraded, never a verdict about the account.
        let r = crate::testutil::with_env(|lock| {
            lock.fake_tool("npm", "echo 'npm ERR! code ENEEDAUTH' >&2; exit 1");
            let ctx = Ctx::discover(root).unwrap();
            verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert!(
            r.messages.join("\n").contains("npm login"),
            "{:?}",
            r.messages
        );

        // And npm absent degrades for a DIFFERENT reason than npm refusing.
        let r = crate::testutil::with_env(|lock| {
            lock.hide_from_path(&["npm"]);
            assert!(
                exec::find_in_path("npm").is_none(),
                "precondition: npm is hidden"
            );
            let ctx = Ctx::discover(root).unwrap();
            verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("tool-missing"));
    }

    /// An unauthenticated `gh` is not a verdict about the account. This is the
    /// difference between "we looked and 2FA is off" (a finding someone must
    /// act on) and "we could not look" (a finding about the lane).
    #[test]
    fn a_refusing_gh_degrades_on_access_rather_than_convicting_the_account() {
        let (dir, _) = crate::testutil::repo_with_gh_repo("o/r", "main");
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        crate::init::bootstrap(root).unwrap();
        let r = crate::testutil::with_env(|lock| {
            lock.fake_tool("gh", "echo 'gh: authentication required' >&2; exit 1");
            let ctx = Ctx::discover(root).unwrap();
            verify_maintainer_mfa(&ctx, ctx.require_config().unwrap())
        });
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("no-access"));
        let joined = r.messages.join("\n");
        assert!(joined.contains("gh auth login"), "{joined}");
        assert!(joined.contains("unverified, not confirmed"), "{joined}");
    }

    /// An npm `tfa.mode` nobody has seen before is still weaker than
    /// `auth-and-writes` until proven otherwise, so it fails rather than being
    /// waved through as "probably fine".
    #[test]
    fn an_unrecognised_npm_tfa_mode_fails_rather_than_being_assumed_adequate() {
        let (o, reason, m) = classify_npm_tfa(r#"{"name":"me","tfa":{"mode":"some-new-mode"}}"#);
        assert_eq!(o, Outcome::Fail);
        assert_eq!(reason, None);
        assert!(m[0].contains("not `auth-and-writes`"), "{m:?}");
        // The value is deliberately NOT named. `tfa.mode` is a closed enum, so
        // a value outside it is not a mode — and this message is signed and
        // published, where "it looked like a plain identifier" is not a good
        // enough reason to copy a credential-holding tool's output. A planted
        // secret passing every charset and length bound is exactly how
        // `no_tool_output_is_ever_echoed_into_a_published_message` caught this
        // line leaking.
        assert!(
            !m[0].contains("some-new-mode"),
            "an undocumented mode must be withheld, not echoed: {m:?}"
        );
        assert!(m[0].contains("withheld"), "{m:?}");
    }

    /// A credential for a registry with NO OIDC alternative is unavoidable, so
    /// it is reported and scoped rather than failed. Failing it would demand a
    /// migration that does not exist — the fastest way to teach someone to
    /// ignore a tool.
    #[test]
    fn a_token_secret_for_a_registry_without_oidc_is_reported_not_failed() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        write(
            root,
            "tools/chocolateyinstall.ps1",
            "Install-ChocolateyPackage -Url 'https://e.com/t.exe' -checksum 'a' -checksumType 'sha256'\n",
        );
        let ctx = bootstrapped(root);
        write(
            root,
            ".github/workflows/push-choco.yml",
            "name: p\non: [workflow_dispatch]\npermissions:\n  contents: read\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: choco push\n        env:\n          CHOCO_API_KEY: ${{ secrets.CHOCO_API_KEY }}\n",
        );
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        let joined = r.messages.join("\n");
        assert_ne!(
            r.outcome,
            Outcome::Fail,
            "Chocolatey has no OIDC path, so the credential is not avoidable: {joined}"
        );
        assert!(joined.contains("CHOCO_API_KEY"), "{joined}");
        assert!(joined.contains("no OIDC path exists there"), "{joined}");
        assert!(joined.contains("declare it in `[[token]]`"), "{joined}");
    }

    /// For the Windows ecosystems the provenance story is Authenticode plus the
    /// manifest digest, and `publish-provenance` says so rather than inventing
    /// a verdict it has no evidence for.
    #[test]
    fn windows_targets_defer_provenance_to_signing_and_the_manifest_checksum() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        write(root, "manifests/T.installer.yaml", "InstallerSha256: ABC\n");
        let ctx = bootstrapped(root);
        let r = verify_publish_provenance(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Info, "{:?}", r.messages);
        let joined = r.messages.join("\n");
        assert!(joined.contains("Authenticode signature"), "{joined}");
        assert!(joined.contains("dist-manifests"), "{joined}");
        // Once each, not once per manifest.
        assert_eq!(
            joined.matches("Authenticode signature").count(),
            2,
            "{joined}"
        );
    }

    // ──────────────── nothing a tool says is ever republished ───────────────

    /// The load-bearing security property of this module, asserted end to end.
    ///
    /// `maintainer-mfa` and `trusted-publishing` ask CREDENTIAL-HOLDING
    /// commands about an ACCOUNT, and a `VerifyResult`'s `messages` are not
    /// merely printed: `machine.rs` serializes them into `--format json` and
    /// into the local-scan record that is SIGNED, COMMITTED and PUBLISHED to
    /// the public directory. So a byte of `npm`'s stderr reaching a message is
    /// not a log-hygiene nit — it is a credential in a signed artifact, from
    /// the tool whose entire purpose is stopping that.
    ///
    /// Every case below hands the verifier a plausible hostile answer with a
    /// distinctive secret in it, and asserts the secret appears in NO message.
    /// Each string is fake and none is a live credential.
    #[test]
    fn no_tool_output_is_ever_echoed_into_a_published_message() {
        const SECRET: &str = "SUPERSECRETVALUE";
        let (dir, _) = crate::testutil::repo_with_gh_repo("o/r", "main");
        let root = dir.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
        );
        write(root, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
        crate::init::bootstrap(root).unwrap();

        // A real shape: npm puts the registry URL in its error, and a
        // misconfigured .npmrc makes that URL carry inline basic-auth.
        let npm_stderr = format!(
            "echo 'npm ERR! 401 Unauthorized - GET https://user:{SECRET}@registry.npmjs.org/-/whoami' >&2; exit 1"
        );
        // A profile whose free-form fields carry things nobody should publish.
        let npm_profile = format!(
            "cat <<'EOF'\n{{\"name\":\"me {SECRET}\",\"email\":\"me@example.com\",\"tfa\":{{\"mode\":\"{SECRET}\"}}}}\nEOF"
        );
        let gh_stderr = format!("echo 'gh: 403 Forbidden (token ghp_{SECRET})' >&2; exit 1");
        let gh_user = format!(
            "cat <<'EOF'\n{{\"login\":\"me {SECRET}\",\"email\":\"me@example.com\",\"two_factor_authentication\":false}}\nEOF"
        );

        for (label, gh, npm) in [
            ("npm stderr", "echo '{}'", npm_stderr.as_str()),
            ("npm payload", "echo '{}'", npm_profile.as_str()),
            ("gh stderr", gh_stderr.as_str(), "echo '{}'"),
            ("gh payload", gh_user.as_str(), "echo '{}'"),
        ] {
            let results = crate::testutil::with_env(|lock| {
                lock.fake_tool("gh", gh);
                lock.fake_tool("npm", npm);
                let ctx = Ctx::discover(root).unwrap();
                let cfg = ctx.require_config().unwrap();
                vec![
                    verify_maintainer_mfa(&ctx, cfg),
                    verify_trusted_publishing(&ctx, cfg),
                ]
            });
            for r in &results {
                let joined = r.messages.join("\n");
                assert!(
                    !joined.contains(SECRET),
                    "{label}: `{}` republished tool output into a message that gets SIGNED and \
                     PUBLISHED:\n{joined}",
                    r.control
                );
            }
        }
    }

    /// The bound itself, at its edges. A label that is not a plain identifier
    /// is REFUSED rather than truncated: a truncated secret is still a secret
    /// prefix, and half a token in a signed record is not half a problem.
    #[test]
    fn safe_label_passes_plain_identifiers_and_refuses_everything_else() {
        for ok in [
            "p4gs",
            "some-user",
            "user.name",
            "a_b",
            "me@example.com",
            "o/r",
        ] {
            assert_eq!(safe_label(ok), ok, "{ok} is a plain identifier");
        }
        for bad in [
            "",
            "   ",
            "user name",              // whitespace splices a message
            "https://u:pw@registry/", // inline basic-auth
            "tok\nen",                // a newline forges a second line
            "café",                   // non-ascii
        ] {
            assert_eq!(
                safe_label(bad),
                "(unprintable)",
                "{bad:?} must be refused, not published"
            );
        }
        // Over-length is refused whole, never truncated to a secret prefix.
        let long = "a".repeat(MAX_ECHOED + 1);
        assert_eq!(safe_label(&long), "(unprintable)");
        assert_eq!(safe_label(&"a".repeat(MAX_ECHOED)), "a".repeat(MAX_ECHOED));
    }

    /// A failed tool is reported by STATUS, never by output. The status is the
    /// whole diagnostic value of the line it replaces — authenticate, grant a
    /// scope, or look elsewhere — and it is the one part that cannot carry a
    /// credential.
    #[test]
    fn tool_failure_reports_a_status_and_never_the_output() {
        assert_eq!(
            tool_failure("npm ERR! 401 Unauthorized - GET https://u:pw@registry/"),
            "HTTP 401"
        );
        assert_eq!(tool_failure("gh: Not Found (HTTP 404)"), "HTTP 404");
        let opaque = tool_failure("something went wrong with token ghp_abcdef");
        assert!(!opaque.contains("ghp_abcdef"), "{opaque}");
        assert!(opaque.contains("output withheld"), "{opaque}");
    }

    // ─────────────────────── reporting surfaces ────────────────────────────

    /// `dist status` renders declared claims, not just the empty case — the
    /// branch an operator who HAS done the policy work actually sees.
    #[test]
    fn dist_status_renders_declared_accounts_and_tokens() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        bootstrapped(root);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            "[[account]]\ntarget = \"chocolatey\"\nidentity = \"pkg-owner\"\nmfa = \"totp\"\nattested = \"2026-01-15\"\n\n\
             [[token]]\ntarget = \"chocolatey\"\npurpose = \"push key\"\nscoped = true\nexpires = \"2026-12-31\"\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let text = render_status(&ctx).unwrap();
        assert!(text.contains("Declared claims"), "{text}");
        assert!(text.contains("account  chocolatey"), "{text}");
        assert!(text.contains("pkg-owner"), "{text}");
        assert!(text.contains("mfa totp (attested 2026-01-15)"), "{text}");
        assert!(text.contains("token    chocolatey"), "{text}");
        assert!(text.contains("expires 2026-12-31"), "{text}");
        assert!(
            text.contains("no OIDC path in the ecosystem"),
            "Chocolatey's gap belongs in the summary too: {text}"
        );
    }

    /// A declared token with none of the compensating controls is reported as
    /// weak on every axis. Keeping a credential is defensible; keeping an
    /// unscoped, unrestricted, unlocated, undated one is the thing that gets
    /// people owned, and the report must say so rather than tick a box.
    #[test]
    fn a_declared_token_with_no_compensating_controls_is_called_out_on_every_axis() {
        let dir = repo();
        let root = dir.path();
        write(root, "thing.nuspec", "<package/>\n");
        bootstrapped(root);
        write(
            root,
            ".sscsb/policy/distribution.toml",
            "[[token]]\ntarget = \"chocolatey\"\npurpose = \"push key\"\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_publish_tokens(&ctx, ctx.require_config().unwrap());
        let joined = r.messages.join("\n");
        assert_ne!(
            r.outcome,
            Outcome::Fail,
            "an undated token is weak, not broken"
        );
        assert!(joined.contains("no expiry declared"), "{joined}");
        assert!(joined.contains("no `expires`"), "{joined}");
        assert!(
            joined.contains("not scoped to specific packages"),
            "{joined}"
        );
        assert!(joined.contains("no CIDR allowlist"), "{joined}");
        assert!(joined.contains("no `stored_in`"), "{joined}");
    }

    /// `dist-manifests`' own Homebrew arm — distinct code from
    /// `publish-provenance`'s formula check, and it must reach the same verdict.
    #[test]
    fn dist_manifests_checks_a_homebrew_formula_and_agrees_with_the_provenance_control() {
        let dir = repo();
        let root = dir.path();
        write(
            root,
            "Formula/t.rb",
            "class T < Formula\n  url \"https://example.com/t.tar.gz\"\nend\n",
        );
        let ctx = bootstrapped(root);
        let cfg = ctx.require_config().unwrap();
        let manifests = verify_dist_manifests(&ctx, cfg);
        let provenance = verify_publish_provenance(&ctx, cfg);
        assert_eq!(manifests.outcome, Outcome::Fail);
        assert_eq!(
            manifests.outcome, provenance.outcome,
            "two controls reading the same formula must not disagree about it"
        );
        assert!(
            manifests
                .messages
                .join("\n")
                .contains("only 0 sha256 pin(s)"),
            "{:?}",
            manifests.messages
        );

        write(
            root,
            "Formula/t.rb",
            "class T < Formula\n  url \"https://example.com/t.tar.gz\"\n  sha256 \"abc\"\nend\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);

        // A formula that downloads nothing has nothing to pin, and that is not
        // a failure — it is a cask pointing at an existing artifact.
        write(
            root,
            "Formula/t.rb",
            "class T < Formula\n  desc \"x\"\nend\n",
        );
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_dist_manifests(&ctx, ctx.require_config().unwrap());
        assert!(
            r.messages.join("\n").contains("nothing to pin"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn dist_check_runs_exactly_the_six_phase_six_controls() {
        let dir = repo();
        let ctx = bootstrapped(dir.path());
        let results = run_check(&ctx).unwrap();
        assert_eq!(results.len(), PHASE_6_CONTROLS.len());
        let ids: Vec<&str> = results.iter().map(|r| r.control).collect();
        assert_eq!(ids, PHASE_6_CONTROLS);
        for def in crate::controls::CONTROLS.iter().filter(|c| c.phase == 6) {
            assert!(
                PHASE_6_CONTROLS.contains(&def.id),
                "`{}` is a phase-6 control that `sscsb dist check` would never run",
                def.id
            );
        }
    }

    /// `PHASE_6_CONTROLS` and the registry are two lists of the same facts.
    #[test]
    fn the_dist_check_list_and_the_registry_agree_on_what_phase_six_is() {
        let registry: BTreeSet<&str> = crate::controls::CONTROLS
            .iter()
            .filter(|c| c.phase == 6)
            .map(|c| c.id)
            .collect();
        let listed: BTreeSet<&str> = PHASE_6_CONTROLS.iter().copied().collect();
        assert_eq!(registry, listed);
    }
}
