//! Package-trust controls: dependency-manifest awareness, new-package
//! approval baseline, registry existence validation (anti-slopsquatting for
//! AI-hallucinated names), and typosquat heuristics.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use anyhow::{Context as _, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub const MANIFEST_FILES: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "Gemfile",
];

pub fn is_dependency_manifest(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    MANIFEST_FILES.contains(&name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPi,
    Go,
    RubyGems,
}

impl Ecosystem {
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Go => "go",
            Ecosystem::RubyGems => "rubygems",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "cargo" => Some(Ecosystem::Cargo),
            "npm" => Some(Ecosystem::Npm),
            "pypi" => Some(Ecosystem::PyPi),
            "go" => Some(Ecosystem::Go),
            "rubygems" => Some(Ecosystem::RubyGems),
            _ => None,
        }
    }

    pub fn of_manifest(path: &str) -> Option<Self> {
        let name = path.rsplit('/').next().unwrap_or(path);
        match name {
            "Cargo.toml" => Some(Ecosystem::Cargo),
            "package.json" => Some(Ecosystem::Npm),
            "requirements.txt" | "pyproject.toml" => Some(Ecosystem::PyPi),
            "go.mod" => Some(Ecosystem::Go),
            "Gemfile" => Some(Ecosystem::RubyGems),
            _ => None,
        }
    }
}

/// Extract direct dependency names from a manifest's content.
pub fn parse_deps(eco: Ecosystem, content: &str) -> BTreeSet<String> {
    match eco {
        Ecosystem::Cargo => parse_cargo(content),
        Ecosystem::Npm => parse_npm(content),
        Ecosystem::PyPi => parse_python(content),
        Ecosystem::Go => parse_go(content),
        Ecosystem::RubyGems => parse_gemfile(content),
    }
}

/// Where a dependency's code actually comes from. Registry is the trusted,
/// name-resolvable case; everything else points at code the registry never
/// vetted, so a change TO one of these — even for an already-approved name — is
/// a fresh trust decision, not a no-op.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepSource {
    Registry,
    Git(String),
    Path(String),
    /// npm `"a": "npm:b@1"` — `a` resolves to a DIFFERENT package `b`.
    Alias(String),
    Url(String),
    /// A cargo alternate registry (`registry = "…"`), or a go `replace` target.
    Other(String),
}

impl DepSource {
    fn tag(&self) -> String {
        match self {
            DepSource::Registry => String::new(),
            DepSource::Git(u) => format!("git:{u}"),
            DepSource::Path(p) => format!("path:{p}"),
            DepSource::Alias(t) => format!("alias:{t}"),
            DepSource::Url(u) => format!("url:{u}"),
            DepSource::Other(o) => format!("other:{o}"),
        }
    }
    fn describe(&self) -> Option<String> {
        match self {
            DepSource::Registry => None,
            DepSource::Git(u) => Some(format!("git source {u}")),
            DepSource::Path(p) => Some(format!("path source {p}")),
            DepSource::Alias(t) => Some(format!("npm alias to `{t}`")),
            DepSource::Url(u) => Some(format!("url source {u}")),
            DepSource::Other(o) => Some(format!("non-default source {o}")),
        }
    }
}

/// A dependency as a (name, source) pair — the real trust unit. Two entries are
/// the same trust only if BOTH match, so repointing `serde` from the registry to
/// a git URL is a new entry, not an unchanged one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepSpec {
    pub name: String,
    pub source: DepSource,
}

impl DepSpec {
    fn key(&self) -> String {
        let tag = self.source.tag();
        if tag.is_empty() {
            self.name.clone()
        } else {
            format!("{}\u{1}{tag}", self.name)
        }
    }
}

/// Source-aware parse: every direct dependency with where it comes from.
pub fn parse_dep_specs(eco: Ecosystem, content: &str) -> BTreeSet<DepSpec> {
    match eco {
        Ecosystem::Cargo => cargo_specs(content),
        Ecosystem::Npm => npm_specs(content),
        Ecosystem::PyPi => python_specs(content),
        Ecosystem::Go => go_specs(content),
        Ecosystem::RubyGems => gemfile_specs(content),
    }
}

fn cargo_specs(content: &str) -> BTreeSet<DepSpec> {
    let mut out = BTreeSet::new();
    let Ok(table) = content.parse::<toml::Table>() else {
        return out;
    };
    let mut sections: Vec<&toml::Table> = Vec::new();
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = table.get(key).and_then(|v| v.as_table()) {
            sections.push(t);
        }
    }
    if let Some(ws) = table
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|w| w.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        sections.push(ws);
    }
    for s in sections {
        for (name, val) in s {
            let real = val
                .as_table()
                .and_then(|t| t.get("package"))
                .and_then(|p| p.as_str())
                .unwrap_or(name)
                .to_string();
            let source = match val.as_table() {
                None => DepSource::Registry, // `name = "1.0"`
                Some(t) if t.get("git").and_then(|v| v.as_str()).is_some() => {
                    DepSource::Git(t["git"].as_str().unwrap().to_string())
                }
                Some(t) if t.get("path").and_then(|v| v.as_str()).is_some() => {
                    DepSource::Path(t["path"].as_str().unwrap().to_string())
                }
                Some(t) if t.get("registry").and_then(|v| v.as_str()).is_some() => {
                    DepSource::Other(format!("registry {}", t["registry"].as_str().unwrap()))
                }
                Some(_) => DepSource::Registry, // `name = { version = "1" }`
            };
            out.insert(DepSpec { name: real, source });
        }
    }
    out
}

fn npm_specs(content: &str) -> BTreeSet<DepSpec> {
    let mut out = BTreeSet::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = v.get(key).and_then(|d| d.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            let spec = spec.as_str().unwrap_or("");
            let (real, source) = if let Some(rest) = spec.strip_prefix("npm:") {
                // "a": "npm:realtarget@1.2.3" — the installed package is the alias
                // target, so THAT is the name whose trust matters.
                let target = rest.rsplit_once('@').map(|(n, _)| n).unwrap_or(rest);
                let target = if target.is_empty() { rest } else { target };
                (target.to_string(), DepSource::Alias(target.to_string()))
            } else if spec.starts_with("git") || spec.starts_with("github:") || spec.contains("://")
            {
                (name.clone(), DepSource::Git(spec.to_string()))
            } else if spec.starts_with("file:") {
                (name.clone(), DepSource::Path(spec.to_string()))
            } else {
                (name.clone(), DepSource::Registry)
            };
            out.insert(DepSpec { name: real, source });
        }
    }
    out
}

fn python_specs(content: &str) -> BTreeSet<DepSpec> {
    // PEP 508 direct references (`pkg @ git+https://…`) are the source-swap
    // vector; a plain `pkg==1.2` is registry-sourced.
    let classify = |req: &str| -> Option<DepSpec> {
        let name = python_req_name(req)?;
        let source = if let Some((_, rhs)) = req.split_once('@') {
            let rhs = rhs.trim();
            if rhs.starts_with("git") {
                DepSource::Git(rhs.to_string())
            } else if rhs.contains("://") {
                DepSource::Url(rhs.to_string())
            } else {
                DepSource::Registry
            }
        } else {
            DepSource::Registry
        };
        Some(DepSpec { name, source })
    };
    let mut out = BTreeSet::new();
    if let Ok(table) = content.parse::<toml::Table>() {
        if let Some(deps) = table
            .get("project")
            .and_then(|p| p.as_table())
            .and_then(|p| p.get("dependencies"))
            .and_then(|d| d.as_array())
        {
            for d in deps {
                if let Some(spec) = d.as_str().and_then(classify) {
                    out.insert(spec);
                }
            }
            return out;
        }
    }
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        if let Some(spec) = classify(line) {
            out.insert(spec);
        }
    }
    out
}

fn go_specs(content: &str) -> BTreeSet<DepSpec> {
    let mut out: BTreeSet<DepSpec> = go_specs_require(content);
    // `replace old => new` (or `=> ../local`) repoints a module — a trust change
    // even though the required name is unchanged.
    for line in content.lines() {
        let line = line.trim();
        let body = line.strip_prefix("replace ").unwrap_or(line);
        if let Some((lhs, rhs)) = body.split_once("=>") {
            let name = lhs.split_whitespace().next().unwrap_or("").to_string();
            if !name.contains('/') {
                continue;
            }
            let target = rhs.trim().to_string();
            let source = if target.starts_with('.') || target.starts_with('/') {
                DepSource::Path(target)
            } else {
                DepSource::Other(format!("replaced by {target}"))
            };
            out.insert(DepSpec { name, source });
        }
    }
    out
}

fn go_specs_require(content: &str) -> BTreeSet<DepSpec> {
    parse_go(content)
        .into_iter()
        .map(|name| DepSpec {
            name,
            source: DepSource::Registry,
        })
        .collect()
}

fn gemfile_specs(content: &str) -> BTreeSet<DepSpec> {
    let mut out = BTreeSet::new();
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("gem ") else {
            continue;
        };
        let rest_name = rest.trim_start_matches(['\'', '"']);
        let name: String = rest_name
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let source = if let Some(i) = rest.find("git:") {
            DepSource::Git(extract_ruby_value(&rest[i + 4..]))
        } else if let Some(i) = rest.find("github:") {
            DepSource::Git(extract_ruby_value(&rest[i + 7..]))
        } else if let Some(i) = rest.find("path:") {
            DepSource::Path(extract_ruby_value(&rest[i + 5..]))
        } else {
            DepSource::Registry
        };
        out.insert(DepSpec { name, source });
    }
    out
}

fn extract_ruby_value(s: &str) -> String {
    s.trim()
        .trim_start_matches(['\'', '"', ' ', '>'])
        .chars()
        .take_while(|c| *c != '\'' && *c != '"')
        .collect()
}

fn parse_cargo(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(table) = content.parse::<toml::Table>() else {
        return out;
    };
    let mut sections: Vec<&toml::Table> = Vec::new();
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = table.get(key).and_then(|v| v.as_table()) {
            sections.push(t);
        }
    }
    if let Some(ws) = table
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|w| w.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        sections.push(ws);
    }
    for s in sections {
        for (name, val) in s {
            // `package = "real-name"` renames take precedence.
            let real = val
                .as_table()
                .and_then(|t| t.get("package"))
                .and_then(|p| p.as_str())
                .unwrap_or(name);
            out.insert(real.to_string());
        }
    }
    out
}

fn parse_npm(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(map) = v.get(key).and_then(|d| d.as_object()) {
            out.extend(map.keys().cloned());
        }
    }
    out
}

fn parse_python(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // pyproject.toml
    if let Ok(table) = content.parse::<toml::Table>() {
        if let Some(deps) = table
            .get("project")
            .and_then(|p| p.as_table())
            .and_then(|p| p.get("dependencies"))
            .and_then(|d| d.as_array())
        {
            for d in deps {
                if let Some(s) = d.as_str() {
                    if let Some(name) = python_req_name(s) {
                        out.insert(name);
                    }
                }
            }
            return out;
        }
    }
    // requirements.txt
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        if let Some(name) = python_req_name(line) {
            out.insert(name);
        }
    }
    out
}

fn python_req_name(req: &str) -> Option<String> {
    let name: String = req
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

fn parse_go(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_require = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && line.starts_with(')') {
            in_require = false;
            continue;
        }
        let candidate = if in_require {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        if let Some(module) = candidate.split_whitespace().next() {
            if module.contains('/') && !candidate.contains("// indirect") {
                out.insert(module.to_string());
            }
        }
    }
    out
}

fn parse_gemfile(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gem ") {
            let rest = rest.trim_start_matches(['\'', '"']);
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

// ─────────────────────────── Approval baseline ──────────────────────────────

pub fn packages_policy_path(ctx: &Ctx) -> PathBuf {
    ctx.sscsb_dir().join("policy").join("packages.toml")
}

pub const PACKAGES_TEMPLATE: &str = r#"# sscsb approved-packages baseline.
#
# A dependency not in this baseline (and not already in the previous manifest
# revision) blocks at commit time until a human approves it:
#   sscsb deps check              # validate existence + typosquat heuristics
#   sscsb deps approve <eco>:<name>
#   sscsb deps baseline           # approve everything currently in manifests
#
# [approved]
# cargo = ["serde"]
# npm = []
# pypi = []
# go = []
# rubygems = []
"#;

pub fn load_approved(ctx: &Ctx) -> Result<BTreeSet<String>> {
    let path = packages_policy_path(ctx);
    if !path.is_file() {
        return Ok(BTreeSet::new());
    }
    let table: toml::Table = std::fs::read_to_string(&path)?
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;
    let mut out = BTreeSet::new();
    if let Some(approved) = table.get("approved").and_then(|v| v.as_table()) {
        for (eco, list) in approved {
            if let Some(arr) = list.as_array() {
                for item in arr {
                    if let Some(name) = item.as_str() {
                        out.insert(format!("{eco}:{name}"));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Reasons a package should not be blindly approved. Empty ⇒ safe to approve.
///
/// This is the check that makes the anti-slopsquat machinery ENFORCING instead
/// of advisory: `approve` and `baseline` run it before writing to the baseline,
/// so a typosquat or a hallucinated (registry-absent) name cannot be blessed
/// without a human seeing the warning and overriding on purpose.
pub fn approval_warnings(qualified: &str, offline: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some((label, name)) = qualified.split_once(':') else {
        return warnings;
    };
    let Some(eco) = Ecosystem::from_label(label) else {
        return warnings;
    };
    if let Some(shadowed) = typosquat_suspect(eco, name) {
        warnings.push(format!(
            "`{qualified}` is one edit from popular package `{shadowed}` — possible \
             typosquat/slopsquat"
        ));
    }
    if !offline {
        match registry_exists(eco, name) {
            RegistryStatus::NotFound => warnings.push(format!(
                "`{qualified}` was NOT FOUND on its public registry — likely a hallucinated \
                 (slopsquat) name; do not approve without verifying it is real"
            )),
            RegistryStatus::Unknown(e) => warnings.push(format!(
                "`{qualified}` existence could not be confirmed ({e}) — verify manually before \
                 approving (a registry outage must not launder an unverified package)"
            )),
            RegistryStatus::Exists => {}
        }
    }
    warnings
}

pub fn approve_package(ctx: &Ctx, qualified: &str) -> Result<()> {
    let (eco, name) = qualified
        .split_once(':')
        .context("expected <ecosystem>:<name>, e.g. cargo:serde")?;
    let valid = ["cargo", "npm", "pypi", "go", "rubygems"];
    if !valid.contains(&eco) {
        anyhow::bail!("unknown ecosystem `{eco}` — one of {}", valid.join("|"));
    }
    let path = packages_policy_path(ctx);
    std::fs::create_dir_all(path.parent().unwrap())?;
    let text = if path.is_file() {
        std::fs::read_to_string(&path)?
    } else {
        PACKAGES_TEMPLATE.to_string()
    };
    let mut doc: toml_edit::DocumentMut = text.parse()?;
    let approved = doc
        .entry("approved")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let table = approved
        .as_table_mut()
        .context("`approved` is not a table")?;
    if !table.contains_key(eco) {
        table.insert(eco, toml_edit::value(toml_edit::Array::new()));
    }
    let arr = table
        .get_mut(eco)
        .and_then(|v| v.as_array_mut())
        .context("ecosystem entry is not an array")?;
    if !arr.iter().any(|v| v.as_str() == Some(name)) {
        arr.push(name);
    }
    std::fs::write(&path, doc.to_string())?;
    Ok(())
}

/// Current direct deps across all manifests in the repo root (qualified
/// `eco:name`).
pub fn current_deps(ctx: &Ctx) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for mf in MANIFEST_FILES {
        let path = ctx.root.join(mf);
        if !path.is_file() {
            continue;
        }
        let eco = Ecosystem::of_manifest(mf).expect("manifest list");
        let content = std::fs::read_to_string(&path)?;
        for dep in parse_deps(eco, &content) {
            out.insert(format!("{}:{dep}", eco.label()));
        }
    }
    Ok(out)
}

/// Why a staged dependency needs a fresh trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewDepReason {
    /// The package name is new and not in the approved baseline.
    NotInBaseline,
    /// The package points at code the registry never vetted (git/path/alias/url),
    /// so it needs review even if the NAME was previously approved.
    NonRegistrySource(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDep {
    pub qualified: String,
    pub reason: NewDepReason,
}

impl NewDep {
    pub fn explain(&self) -> String {
        match &self.reason {
            NewDepReason::NotInBaseline => format!(
                "new dependency `{}` is not in the approved baseline — validate it \
                 (`sscsb deps check`) then approve it (`sscsb deps approve {}`)",
                self.qualified, self.qualified
            ),
            NewDepReason::NonRegistrySource(desc) => format!(
                "dependency `{}` uses a non-registry source ({desc}) — the registry \
                 never vetted this code, so it needs explicit review even though the \
                 name may already be approved; confirm intent, then `sscsb deps approve {}`",
                self.qualified, self.qualified
            ),
        }
    }
}

/// True if a relative `path = "<rel>"` dependency declared in `manifest`
/// (repo-relative path) resolves to a location INSIDE the repo — the repo's own
/// code, already reviewed here (e.g. a cargo-fuzz project's `path = ".."`).
/// Absolute paths, or `..` components that escape above the repo root, are false.
fn path_resolves_within_repo(manifest: &str, rel: &str) -> bool {
    use std::path::{Component, Path};
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return false;
    }
    let manifest_dir = Path::new(manifest)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let mut depth: i32 = 0;
    for c in manifest_dir.join(rel_path).components() {
        match c {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false; // escaped above the repo root
                }
            }
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// STAGED dependency changes that need a fresh trust decision. Source-aware: a
/// previously-approved name repointed to a git/path/alias/url source is flagged,
/// because that is a change of what code will actually run, not a no-op.
/// In-tree path sources (own code) are exempt — see `path_resolves_within_repo`.
pub fn new_unapproved_deps(ctx: &Ctx) -> Result<Vec<NewDep>> {
    let staged = exec::git(
        &[
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
        ],
        &ctx.root,
    )?;
    let approved = load_approved(ctx)?;
    let mut out = Vec::new();
    for file in staged
        .split('\0')
        .filter(|f| !f.is_empty() && is_dependency_manifest(f))
    {
        let Some(eco) = Ecosystem::of_manifest(file) else {
            continue;
        };
        let staged_content = exec::git_raw(&["show", &format!(":{file}")], &ctx.root)?;
        if !staged_content.success() {
            continue;
        }
        let head_content = exec::git_raw(&["show", &format!("HEAD:{file}")], &ctx.root)
            .map(|o| if o.success() { o.stdout } else { String::new() })
            .unwrap_or_default();
        let before = parse_dep_specs(eco, &head_content);
        let after = parse_dep_specs(eco, &staged_content.stdout);
        let before_keys: BTreeSet<String> = before.iter().map(DepSpec::key).collect();
        for spec in &after {
            // Unchanged trust unit (same name AND same source) → nothing to do.
            if before_keys.contains(&spec.key()) {
                continue;
            }
            let qualified = format!("{}:{}", eco.label(), spec.name);
            if let Some(desc) = spec.source.describe() {
                // In-tree path sources — a cargo-fuzz project (or similar)
                // depending on THIS repo's own crate — point at code that
                // already lives in and is reviewed within this repo, not
                // external unvetted code. Exempt them. Out-of-tree paths and
                // git/url/alias sources still need explicit review.
                if let DepSource::Path(p) = &spec.source {
                    if path_resolves_within_repo(file, p) {
                        continue;
                    }
                }
                // Any other non-registry source needs review, regardless of baseline.
                out.push(NewDep {
                    qualified,
                    reason: NewDepReason::NonRegistrySource(desc),
                });
            } else if !approved.contains(&qualified) {
                out.push(NewDep {
                    qualified,
                    reason: NewDepReason::NotInBaseline,
                });
            }
        }
    }
    // Dedup by qualified name, keeping the strongest reason (non-registry wins).
    out.sort_by(|a, b| a.qualified.cmp(&b.qualified));
    out.dedup_by(|a, b| {
        if a.qualified == b.qualified {
            if matches!(a.reason, NewDepReason::NonRegistrySource(_)) {
                b.reason = a.reason.clone();
            }
            true
        } else {
            false
        }
    });
    Ok(out)
}

/// Qualified names of staged dependencies needing approval (thin wrapper over
/// [`new_unapproved_deps`] for callers that only need the names).
pub fn unapproved_new_packages(ctx: &Ctx) -> Result<Vec<String>> {
    Ok(new_unapproved_deps(ctx)?
        .into_iter()
        .map(|d| d.qualified)
        .collect())
}

// ─────────────────────────── Registry existence ─────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryStatus {
    Exists,
    NotFound,
    Unknown(String),
}

/// Validate that a package NAME EXISTS on its public registry. A 404 on a
/// freshly-introduced dependency is the classic AI-slopsquatting signal.
pub fn registry_exists(eco: Ecosystem, name: &str) -> RegistryStatus {
    let url = match eco {
        Ecosystem::Cargo => format!("https://crates.io/api/v1/crates/{name}"),
        Ecosystem::Npm => format!("https://registry.npmjs.org/{name}"),
        Ecosystem::PyPi => format!("https://pypi.org/pypi/{name}/json"),
        Ecosystem::Go => format!("https://proxy.golang.org/{}/@latest", name.to_lowercase()),
        Ecosystem::RubyGems => format!("https://rubygems.org/api/v1/gems/{name}.json"),
    };
    let resp = ureq::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("sscsb (https://github.com/p4gs/sscs-bootstrapper)")
        .build()
        .get(&url)
        .call();
    match resp {
        Ok(_) => RegistryStatus::Exists,
        Err(ureq::Error::Status(404, _)) => RegistryStatus::NotFound,
        Err(e) => RegistryStatus::Unknown(e.to_string()),
    }
}

// ─────────────────────────── Typosquat heuristic ────────────────────────────

/// Popular package names per ecosystem (embedded, deliberately small): a NEW
/// dependency within edit-distance 1 of one of these — but not equal to it —
/// is a typosquat suspect.
pub const POPULAR: &[(&str, &[&str])] = &[
    (
        "cargo",
        &[
            "serde",
            "serde_json",
            "tokio",
            "anyhow",
            "thiserror",
            "clap",
            "rand",
            "regex",
            "log",
            "tracing",
            "reqwest",
            "hyper",
            "axum",
            "chrono",
            "itertools",
            "futures",
            "syn",
            "quote",
            "libc",
            "base64",
            "sha2",
            "hex",
            "uuid",
            "url",
            "bytes",
        ],
    ),
    (
        "npm",
        &[
            "react",
            "lodash",
            "express",
            "axios",
            "chalk",
            "commander",
            "debug",
            "typescript",
            "webpack",
            "vite",
            "next",
            "vue",
            "jest",
            "eslint",
            "prettier",
            "dotenv",
            "zod",
            "moment",
            "uuid",
            "glob",
        ],
    ),
    (
        "pypi",
        &[
            "requests",
            "numpy",
            "pandas",
            "flask",
            "django",
            "pytest",
            "boto3",
            "urllib3",
            "setuptools",
            "pydantic",
            "cryptography",
            "click",
            "rich",
            "httpx",
            "pillow",
        ],
    ),
];

/// Damerau-Levenshtein distance of at most 1: one substitution, insertion,
/// deletion, **or adjacent transposition**.
///
/// The transposition case earns its complexity. Swapping two neighbouring
/// characters (`tokoi` for `tokio`, `reqeusts` for `requests`) is both the most
/// common human typo and the most common typosquat shape — yet plain
/// Levenshtein scores it as distance 2 and would wave it straight through.
fn edit_distance_leq1(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    if la == lb {
        let diffs: Vec<usize> = (0..la).filter(|&i| a[i] != b[i]).collect();
        return match diffs.as_slice() {
            [] | [_] => true,
            // Two adjacent mismatches that are exactly each other's swap.
            [i, j] if *j == i + 1 => a[*i] == b[*j] && a[*j] == b[*i],
            _ => false,
        };
    }
    // One insertion/deletion.
    let (short, long) = if la < lb { (&a, &b) } else { (&b, &a) };
    let mut i = 0;
    let mut skipped = false;
    for c in long.iter() {
        if i < short.len() && short[i] == *c {
            i += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
        }
    }
    true
}

fn normalize(name: &str) -> String {
    name.to_lowercase().replace(['-', '_'], "")
}

/// Typosquat suspicion for a new package name. Returns the popular package it
/// shadows, if any.
pub fn typosquat_suspect(eco: Ecosystem, name: &str) -> Option<&'static str> {
    let list = POPULAR
        .iter()
        .find(|(label, _)| *label == eco.label())
        .map(|(_, l)| *l)?;
    if list.contains(&name) {
        return None; // it IS the popular package
    }
    list.iter()
        .find(|popular| {
            edit_distance_leq1(name, popular)
                || (normalize(name) == normalize(popular) && name != **popular)
        })
        .copied()
}

// ─────────────────────────── verify / CLI entry ─────────────────────────────

pub fn verify_package_trust(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = Vec::new();
    if !crate::hooks::hooks_installed(ctx) {
        return VerifyResult::new(
            "package-trust",
            Outcome::Fail,
            vec!["hooks not installed — run `sscsb init`".into()],
        );
    }
    messages.push("new-package approval gate enforced in commit-msg hook".into());
    let outcome = if packages_policy_path(ctx).is_file() {
        let approved = load_approved(ctx).map(|s| s.len()).unwrap_or(0);
        messages.push(format!("approved baseline present ({approved} package(s))"));
        Outcome::Pass
    } else {
        messages.push(
            "no approved-packages baseline yet — run `sscsb deps baseline` to bless current deps"
                .into(),
        );
        Outcome::Degraded
    };
    if cfg
        .control_opt_bool("package-trust", "registry_check")
        .unwrap_or(true)
    {
        messages
            .push("registry existence validation on `sscsb deps check` (anti-slopsquat)".into());
    }
    VerifyResult::new("package-trust", outcome, messages)
}

pub fn verify_socket_control(ctx: &Ctx) -> VerifyResult {
    let sfw = exec::find_in_path("sfw");
    let messages = vec![
        match sfw {
            Some(ref p) => format!("Socket Firewall CLI (sfw) found at {}", p.display()),
            None => "Socket Firewall CLI (sfw) not found — install per \
                     https://docs.socket.dev/docs/socket-firewall and wrap installs: \
                     `sfw npm install`, `sfw pip install`, `sfw cargo add`"
                .to_string(),
        },
        "socket-firewall blocks known-malicious packages at install time (optional layer)".into(),
    ];
    let outcome = if sfw.is_some() {
        Outcome::Pass
    } else {
        Outcome::Degraded
    };
    let _ = ctx;
    VerifyResult::new("socket-firewall", outcome, messages)
}

/// `sscsb deps check`: validate current (or staged-new) packages.
pub fn deps_check(ctx: &Ctx, offline: bool) -> Result<(Vec<String>, Vec<String>)> {
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let new_pkgs = unapproved_new_packages(ctx)?;
    let targets: Vec<String> = if new_pkgs.is_empty() {
        current_deps(ctx)?.into_iter().collect()
    } else {
        notes.push(format!("checking {} staged new package(s)", new_pkgs.len()));
        new_pkgs
    };
    for qualified in &targets {
        let Some((eco_label, name)) = qualified.split_once(':') else {
            continue;
        };
        let eco = match eco_label {
            "cargo" => Ecosystem::Cargo,
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPi,
            "go" => Ecosystem::Go,
            "rubygems" => Ecosystem::RubyGems,
            _ => continue,
        };
        if let Some(shadowed) = typosquat_suspect(eco, name) {
            problems.push(format!(
                "{qualified}: name is one edit away from popular package `{shadowed}` — \
                 possible typosquat/slopsquat; verify intent before approving"
            ));
        }
        if !offline {
            match registry_exists(eco, name) {
                RegistryStatus::Exists => notes.push(format!("{qualified}: exists on registry")),
                RegistryStatus::NotFound => problems.push(format!(
                    "{qualified}: NOT FOUND on its public registry — likely hallucinated \
                     (slopsquatting target) or private; do not approve without verification"
                )),
                RegistryStatus::Unknown(e) => {
                    notes.push(format!("{qualified}: registry check inconclusive ({e})"));
                }
            }
        }
    }
    Ok((problems, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_detection() {
        assert!(is_dependency_manifest("Cargo.toml"));
        assert!(is_dependency_manifest("sub/dir/package.json"));
        assert!(!is_dependency_manifest("src/main.rs"));
    }

    #[test]
    fn cargo_parsing_includes_rename_and_workspace() {
        let deps = parse_cargo(
            "[dependencies]\nserde = \"1\"\nfancy = { package = \"real-crate\", version = \"1\" }\n\
             [dev-dependencies]\ntempfile = \"3\"\n[workspace.dependencies]\nanyhow = \"1\"\n",
        );
        assert!(deps.contains("serde"));
        assert!(deps.contains("real-crate"));
        assert!(!deps.contains("fancy"));
        assert!(deps.contains("tempfile"));
        assert!(deps.contains("anyhow"));
    }

    #[test]
    fn npm_python_go_gemfile_parsing() {
        let npm = parse_npm(r#"{"dependencies":{"react":"18"},"devDependencies":{"jest":"29"}}"#);
        assert!(npm.contains("react") && npm.contains("jest"));

        let py = parse_python("requests==2.31.0\n# comment\nflask>=2\n");
        assert!(py.contains("requests") && py.contains("flask"));

        let pyproject = parse_python("[project]\nname = \"x\"\ndependencies = [\"pydantic>=2\"]\n");
        assert!(pyproject.contains("pydantic"));

        let go = parse_go("module m\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/sys v0.1.0 // indirect\n)\n");
        assert!(go.contains("github.com/pkg/errors"));
        assert!(!go.iter().any(|d| d.contains("x/sys")), "indirect excluded");

        let gems = parse_gemfile("source 'https://rubygems.org'\ngem 'rails', '~> 7'\n");
        assert!(gems.contains("rails"));
    }

    fn source_of<'a>(specs: &'a BTreeSet<DepSpec>, name: &str) -> &'a DepSource {
        &specs
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no dep named {name} in {specs:?}"))
            .source
    }

    #[test]
    fn cargo_specs_classify_every_source_kind() {
        let specs = cargo_specs(
            "[dependencies]\n\
             plain = \"1\"\n\
             tabled = { version = \"1\" }\n\
             gitdep = { git = \"https://example/repo\" }\n\
             localdep = { path = \"../x\" }\n\
             altreg = { version = \"1\", registry = \"corp\" }\n\
             renamed = { package = \"real-crate\", version = \"1\" }\n",
        );
        assert_eq!(*source_of(&specs, "plain"), DepSource::Registry);
        assert_eq!(*source_of(&specs, "tabled"), DepSource::Registry);
        assert_eq!(
            *source_of(&specs, "gitdep"),
            DepSource::Git("https://example/repo".into())
        );
        assert_eq!(
            *source_of(&specs, "localdep"),
            DepSource::Path("../x".into())
        );
        assert!(matches!(source_of(&specs, "altreg"), DepSource::Other(_)));
        // A rename is keyed by the REAL crate name, registry-sourced.
        assert_eq!(*source_of(&specs, "real-crate"), DepSource::Registry);
        assert!(specs.iter().all(|s| s.name != "renamed"));
    }

    #[test]
    fn npm_specs_detect_alias_git_and_file_sources() {
        let specs = npm_specs(
            r#"{"dependencies":{
                "plain":"^1.0.0",
                "aliased":"npm:real-target@2.0.0",
                "fromgit":"git+https://example/repo",
                "local":"file:../x"
            }}"#,
        );
        assert_eq!(*source_of(&specs, "plain"), DepSource::Registry);
        // The alias resolves to the REAL installed package name.
        assert_eq!(
            *source_of(&specs, "real-target"),
            DepSource::Alias("real-target".into())
        );
        assert!(specs.iter().all(|s| s.name != "aliased"));
        assert!(matches!(source_of(&specs, "fromgit"), DepSource::Git(_)));
        assert!(matches!(source_of(&specs, "local"), DepSource::Path(_)));
    }

    #[test]
    fn python_specs_flag_pep508_direct_references() {
        let specs = python_specs("requests==2.31.0\nmalicious @ git+https://evil/x\n");
        assert_eq!(*source_of(&specs, "requests"), DepSource::Registry);
        assert!(matches!(source_of(&specs, "malicious"), DepSource::Git(_)));

        let proj = python_specs(
            "[project]\nname=\"x\"\ndependencies = [\"pydantic>=2\", \"pkg @ https://host/x.whl\"]\n",
        );
        assert_eq!(*source_of(&proj, "pydantic"), DepSource::Registry);
        assert!(matches!(source_of(&proj, "pkg"), DepSource::Url(_)));
    }

    #[test]
    fn go_specs_flag_replace_directives() {
        let specs = go_specs(
            "module m\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n\
             replace github.com/pkg/errors => ../local-fork\n",
        );
        // The require is registry; the replace repoints it to a path.
        assert!(matches!(
            source_of(&specs, "github.com/pkg/errors"),
            DepSource::Path(_) | DepSource::Registry
        ));
        // The replace target specifically must be represented.
        assert!(
            specs.iter().any(
                |s| s.name == "github.com/pkg/errors" && matches!(s.source, DepSource::Path(_))
            ),
            "replace to a local path must be captured: {specs:?}"
        );
    }

    #[test]
    fn gemfile_specs_detect_git_and_path() {
        let specs = gemfile_specs(
            "gem 'rails', '~> 7'\ngem 'evil', git: 'https://evil/x'\ngem 'local', path: '../x'\n",
        );
        assert_eq!(*source_of(&specs, "rails"), DepSource::Registry);
        assert!(matches!(source_of(&specs, "evil"), DepSource::Git(_)));
        assert!(matches!(source_of(&specs, "local"), DepSource::Path(_)));
    }

    #[test]
    fn dep_source_describe_and_key_are_stable() {
        assert!(DepSource::Registry.describe().is_none());
        assert!(DepSource::Git("u".into())
            .describe()
            .unwrap()
            .contains("git"));
        let registry = DepSpec {
            name: "serde".into(),
            source: DepSource::Registry,
        };
        assert_eq!(registry.key(), "serde"); // registry key is just the name
        let git = DepSpec {
            name: "serde".into(),
            source: DepSource::Git("u".into()),
        };
        assert_ne!(git.key(), registry.key()); // repoint changes the trust key
    }

    #[test]
    fn approval_warnings_flags_typosquat_offline_and_nothing_for_clean() {
        assert!(approval_warnings("cargo:tokoi", true)
            .iter()
            .any(|w| w.contains("tokio")));
        assert!(approval_warnings("cargo:serde", true).is_empty());
        // Unknown ecosystem or malformed input is simply not flagged.
        assert!(approval_warnings("bogus:x", true).is_empty());
        assert!(approval_warnings("no-colon", true).is_empty());
    }

    #[test]
    fn new_dep_explain_distinguishes_baseline_from_source() {
        let baseline = NewDep {
            qualified: "cargo:x".into(),
            reason: NewDepReason::NotInBaseline,
        };
        assert!(baseline.explain().contains("approved baseline"));
        let source = NewDep {
            qualified: "cargo:serde".into(),
            reason: NewDepReason::NonRegistrySource("git source u".into()),
        };
        assert!(source.explain().contains("non-registry source"));
    }

    #[test]
    fn from_label_round_trips_every_ecosystem() {
        for eco in [
            Ecosystem::Cargo,
            Ecosystem::Npm,
            Ecosystem::PyPi,
            Ecosystem::Go,
            Ecosystem::RubyGems,
        ] {
            assert_eq!(Ecosystem::from_label(eco.label()), Some(eco));
        }
        assert_eq!(Ecosystem::from_label("cocoapods"), None);
    }

    #[test]
    fn typosquat_heuristic_flags_near_misses_not_exact() {
        assert_eq!(typosquat_suspect(Ecosystem::PyPi, "requests"), None);
        assert_eq!(
            typosquat_suspect(Ecosystem::PyPi, "reqests"),
            Some("requests")
        );
        assert_eq!(typosquat_suspect(Ecosystem::Cargo, "serde"), None);
        assert_eq!(typosquat_suspect(Ecosystem::Cargo, "serd"), Some("serde"));
        // underscore/hyphen swap
        assert_eq!(
            typosquat_suspect(Ecosystem::Cargo, "serde-json"),
            Some("serde_json")
        );
        assert_eq!(
            typosquat_suspect(Ecosystem::Cargo, "completely-unrelated"),
            None
        );
    }

    #[test]
    fn adjacent_transpositions_are_caught() {
        // Levenshtein calls these distance 2; Damerau calls them 1. They are
        // the most common typosquat shape, so they must flag.
        assert_eq!(typosquat_suspect(Ecosystem::Cargo, "tokoi"), Some("tokio"));
        assert_eq!(
            typosquat_suspect(Ecosystem::PyPi, "reqeusts"),
            Some("requests")
        );
        assert!(edit_distance_leq1("ab", "ba"));
        // Two NON-adjacent substitutions stay distance 2 — still not a match.
        assert!(!edit_distance_leq1("abcde", "xbcdy"));
        // A swap of non-adjacent characters is distance 2, not a transposition.
        assert!(!edit_distance_leq1("abcd", "dbca"));
    }

    #[test]
    fn edit_distance_boundaries() {
        assert!(edit_distance_leq1("abc", "abc"));
        assert!(edit_distance_leq1("abc", "abd"));
        assert!(edit_distance_leq1("abc", "abcd"));
        assert!(edit_distance_leq1("abc", "ab"));
        assert!(!edit_distance_leq1("abc", "axd"));
        assert!(!edit_distance_leq1("abc", "abcde"));
    }

    // ───────────────────────── ecosystem & dispatcher ────────────────────────

    #[test]
    fn ecosystem_label_covers_every_variant() {
        for (eco, label) in [
            (Ecosystem::Cargo, "cargo"),
            (Ecosystem::Npm, "npm"),
            (Ecosystem::PyPi, "pypi"),
            (Ecosystem::Go, "go"),
            (Ecosystem::RubyGems, "rubygems"),
        ] {
            assert_eq!(eco.label(), label);
        }
    }

    #[test]
    fn of_manifest_covers_every_known_filename_and_rejects_unknown_ones() {
        assert_eq!(Ecosystem::of_manifest("Cargo.toml"), Some(Ecosystem::Cargo));
        assert_eq!(Ecosystem::of_manifest("package.json"), Some(Ecosystem::Npm));
        assert_eq!(
            Ecosystem::of_manifest("requirements.txt"),
            Some(Ecosystem::PyPi)
        );
        assert_eq!(
            Ecosystem::of_manifest("pyproject.toml"),
            Some(Ecosystem::PyPi)
        );
        assert_eq!(Ecosystem::of_manifest("go.mod"), Some(Ecosystem::Go));
        assert_eq!(
            Ecosystem::of_manifest("nested/dir/Gemfile"),
            Some(Ecosystem::RubyGems)
        );
        assert_eq!(Ecosystem::of_manifest("random.txt"), None);
    }

    #[test]
    fn parse_deps_dispatches_to_every_ecosystem_parser() {
        assert!(parse_deps(Ecosystem::Cargo, "[dependencies]\nserde = \"1\"\n").contains("serde"));
        assert!(parse_deps(Ecosystem::Npm, r#"{"dependencies":{"react":"18"}}"#).contains("react"));
        assert!(parse_deps(Ecosystem::PyPi, "requests==2.31.0\n").contains("requests"));
        assert!(parse_deps(
            Ecosystem::Go,
            "module m\n\nrequire github.com/pkg/errors v0.9.1\n"
        )
        .contains("github.com/pkg/errors"));
        assert!(parse_deps(Ecosystem::RubyGems, "gem 'rails'\n").contains("rails"));
    }

    #[test]
    fn parse_cargo_on_unparseable_toml_yields_an_empty_set_not_a_panic() {
        assert!(parse_cargo("this is { not valid toml").is_empty());
    }

    // ───────────────────────── python parsing edge cases ─────────────────────

    #[test]
    fn parse_python_pyproject_skips_non_string_and_unnameable_array_entries() {
        // TOML 1.0 arrays may be heterogeneous; a stray integer and an empty
        // string must be skipped rather than corrupting the result.
        let deps =
            parse_python("[project]\nname = \"x\"\ndependencies = [123, \"\", \"pydantic>=2\"]\n");
        assert_eq!(deps, BTreeSet::from(["pydantic".to_string()]));
    }

    #[test]
    fn parse_python_pyproject_without_a_dependencies_array_falls_back_to_a_line_scan() {
        // A minimal PEP 621 pyproject.toml with no `[project.dependencies]`
        // array is still valid TOML, so parsing does not early-return; it
        // falls through to the requirements.txt-shaped scan of the same raw
        // text. That scan is line-oriented and does not understand TOML
        // table syntax, so it picks up bare keys like `name`/`version` as
        // candidate names — a known limitation (see the accompanying report:
        // Poetry-style `[tool.poetry.dependencies]` manifests hit this same
        // path and deserve first-class parsing instead of this accidental
        // fallback).
        let deps = parse_python("[project]\nname = \"mypkg\"\nversion = \"0.1.0\"\n");
        assert_eq!(
            deps,
            BTreeSet::from(["name".to_string(), "version".to_string()])
        );
    }

    #[test]
    fn parse_python_requirements_txt_skips_directives_blanks_and_unnameable_lines() {
        let deps = parse_python("# a comment\n-e .\n\n==1.0\nrequests\n");
        assert_eq!(deps, BTreeSet::from(["requests".to_string()]));
    }

    // ───────────────────────── Ctx-backed deps surface ────────────────────────

    fn repo_ctx() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
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

    #[test]
    fn packages_policy_path_is_under_the_sscsb_policy_dir() {
        let (_d, ctx) = repo_ctx();
        assert_eq!(
            packages_policy_path(&ctx),
            ctx.sscsb_dir().join("policy").join("packages.toml")
        );
    }

    #[test]
    fn approve_package_rejects_malformed_and_unknown_ecosystem_input() {
        let (_d, ctx) = repo_ctx();
        let err = approve_package(&ctx, "no-colon-here").unwrap_err();
        assert!(format!("{err:#}").contains("expected <ecosystem>:<name>"));

        let err = approve_package(&ctx, "cocoapods:AFNetworking").unwrap_err();
        assert!(format!("{err:#}").contains("unknown ecosystem"));
    }

    #[test]
    fn load_approved_is_empty_then_grows_and_dedupes_across_ecosystems() {
        let (_d, ctx) = repo_ctx();
        assert!(load_approved(&ctx).unwrap().is_empty());

        approve_package(&ctx, "cargo:serde").unwrap();
        let approved = load_approved(&ctx).unwrap();
        assert!(approved.contains("cargo:serde"));

        // Re-approving the same package is idempotent, not a duplicate.
        approve_package(&ctx, "cargo:serde").unwrap();
        assert_eq!(load_approved(&ctx).unwrap().len(), approved.len());

        // A second ecosystem key is created independently.
        approve_package(&ctx, "npm:react").unwrap();
        let approved = load_approved(&ctx).unwrap();
        assert!(approved.contains("cargo:serde") && approved.contains("npm:react"));
    }

    #[test]
    fn load_approved_reports_a_parse_error_for_malformed_policy_toml() {
        let (_d, ctx) = repo_ctx();
        std::fs::write(packages_policy_path(&ctx), "not [ valid toml").unwrap();
        let err = load_approved(&ctx).unwrap_err();
        assert!(format!("{err:#}").contains("parsing"));
    }

    #[test]
    fn load_approved_skips_non_array_and_non_string_entries_without_erroring() {
        let (_d, ctx) = repo_ctx();
        std::fs::write(
            packages_policy_path(&ctx),
            "[approved]\ncargo = [\"serde\", 42]\nnpm = \"not-an-array\"\n",
        )
        .unwrap();
        let approved = load_approved(&ctx).unwrap();
        assert_eq!(approved, BTreeSet::from(["cargo:serde".to_string()]));
    }

    #[test]
    fn current_deps_reads_every_present_manifest_and_ignores_absent_ones() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        write_file(&ctx, "package.json", r#"{"dependencies":{"react":"18"}}"#);
        let deps = current_deps(&ctx).unwrap();
        assert!(deps.contains("cargo:serde"));
        assert!(deps.contains("npm:react"));
        assert!(
            !deps
                .iter()
                .any(|d| d.starts_with("pypi:") || d.starts_with("go:")),
            "no requirements.txt/go.mod present: {deps:?}"
        );
    }

    #[test]
    fn unapproved_new_packages_diffs_staged_content_against_head() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        stage(&ctx, "Cargo.toml");
        exec::git_raw(
            &["commit", "-m", "chore: baseline", "--no-verify"],
            &ctx.root,
        )
        .unwrap();

        // Nothing staged yet → nothing new.
        assert!(unapproved_new_packages(&ctx).unwrap().is_empty());

        write_file(
            &ctx,
            "Cargo.toml",
            "[dependencies]\nserde = \"1\"\nanyhow = \"1\"\n",
        );
        stage(&ctx, "Cargo.toml");
        assert_eq!(
            unapproved_new_packages(&ctx).unwrap(),
            vec!["cargo:anyhow".to_string()]
        );

        // A staged non-manifest file is ignored entirely.
        write_file(&ctx, "README.md", "docs\n");
        stage(&ctx, "README.md");
        assert_eq!(
            unapproved_new_packages(&ctx).unwrap(),
            vec!["cargo:anyhow".to_string()]
        );
    }

    #[test]
    fn typosquat_suspect_is_none_for_ecosystems_without_a_curated_popular_list() {
        // POPULAR only curates cargo/npm/pypi; go and rubygems fall through
        // the lookup's `?` and correctly return None rather than panicking.
        assert_eq!(
            typosquat_suspect(Ecosystem::Go, "github.com/pkg/errors"),
            None
        );
        assert_eq!(typosquat_suspect(Ecosystem::RubyGems, "rails"), None);
    }

    #[test]
    fn deps_check_offline_flags_typosquats_and_never_touches_the_network() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\ntokoi = \"1\"\n");
        let (problems, notes) = deps_check(&ctx, true).unwrap();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("typosquat") && p.contains("tokio")),
            "{problems:?}"
        );
        assert!(
            !notes.iter().any(|n| n.contains("exists on registry")),
            "offline mode must not report registry results: {notes:?}"
        );
        assert!(!problems.iter().any(|p| p.contains("NOT FOUND")));
    }

    #[test]
    fn deps_check_prefers_staged_new_packages_over_the_full_manifest() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        stage(&ctx, "Cargo.toml");
        exec::git_raw(
            &["commit", "-m", "chore: baseline", "--no-verify"],
            &ctx.root,
        )
        .unwrap();

        write_file(
            &ctx,
            "Cargo.toml",
            "[dependencies]\nserde = \"1\"\ntokoi = \"1\"\n",
        );
        stage(&ctx, "Cargo.toml");
        let (problems, notes) = deps_check(&ctx, true).unwrap();
        assert!(notes
            .iter()
            .any(|n| n.contains("checking 1 staged new package")));
        assert!(problems
            .iter()
            .any(|p| p.contains("cargo:tokoi") && p.contains("tokio")));
    }

    #[test]
    fn deps_check_online_leaves_a_registry_note_for_every_target_regardless_of_connectivity() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        let (problems, notes) = deps_check(&ctx, false).unwrap();
        assert!(!problems.iter().any(|p| p.contains("typosquat")));
        assert!(
            !notes.is_empty(),
            "the registry outcome for `serde` must always be recorded, online or degraded: {notes:?}"
        );
    }

    #[test]
    fn registry_exists_classifies_a_real_and_an_impossible_package_name() {
        // Real network call. Both assertions tolerate a degraded/offline
        // network by accepting `Unknown` — only a definite wrong answer
        // (NotFound for something real, Exists for something impossible)
        // would fail the test.
        match registry_exists(Ecosystem::Cargo, "serde") {
            RegistryStatus::Exists | RegistryStatus::Unknown(_) => {}
            RegistryStatus::NotFound => panic!("serde must exist on crates.io"),
        }
        let status = registry_exists(
            Ecosystem::Npm,
            "sscsb-definitely-nonexistent-slopsquat-probe-xyz",
        );
        assert!(
            matches!(
                status,
                RegistryStatus::NotFound | RegistryStatus::Unknown(_)
            ),
            "{status:?}"
        );
    }

    #[test]
    fn verify_package_trust_fails_without_hooks_degrades_without_baseline_passes_once_baselined() {
        // No `sscsb init` at all: the hard-fail path.
        let dir = tempfile::tempdir().unwrap();
        exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join(".sscsb")).unwrap();
        std::fs::write(
            dir.path().join(".sscsb/config.toml"),
            crate::config::default_config_toml(None),
        )
        .unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        let cfg = ctx.require_config().unwrap();
        assert_eq!(verify_package_trust(&ctx, cfg).outcome, Outcome::Fail);

        // Bootstrapped (hooks installed), but the baseline file itself is
        // absent — `sscsb init` writes it from PACKAGES_TEMPLATE, so exercise
        // the pre-init-completion state by removing it again.
        let (_d, ctx) = repo_ctx();
        let cfg = ctx.require_config().unwrap();
        std::fs::remove_file(packages_policy_path(&ctx)).unwrap();
        let result = verify_package_trust(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("no approved-packages baseline")));

        // Once the baseline file exists again (e.g. a package is approved),
        // the control passes.
        approve_package(&ctx, "cargo:serde").unwrap();
        assert_eq!(verify_package_trust(&ctx, cfg).outcome, Outcome::Pass);
    }

    #[test]
    fn verify_socket_control_reports_presence_or_absence_of_sfw() {
        let (_d, ctx) = repo_ctx();
        let result = verify_socket_control(&ctx);
        let found = exec::find_in_path("sfw").is_some();
        assert_eq!(
            result.outcome,
            if found {
                Outcome::Pass
            } else {
                Outcome::Degraded
            }
        );
        assert!(
            result.messages[0].contains("sfw") || result.messages[0].contains("Socket Firewall")
        );
    }

    #[test]
    fn path_within_repo_exempts_intree_but_not_escapes() {
        // in-tree (own code) — exempt
        assert!(path_resolves_within_repo("fuzz/Cargo.toml", "..")); // → repo root
        assert!(path_resolves_within_repo("fuzz/Cargo.toml", "../src"));
        assert!(path_resolves_within_repo("Cargo.toml", "."));
        assert!(path_resolves_within_repo("a/b/Cargo.toml", "../.."));
        // escapes the repo — still flagged
        assert!(!path_resolves_within_repo("fuzz/Cargo.toml", "../.."));
        assert!(!path_resolves_within_repo("Cargo.toml", ".."));
        assert!(!path_resolves_within_repo("fuzz/Cargo.toml", "/etc/passwd"));
    }
}
