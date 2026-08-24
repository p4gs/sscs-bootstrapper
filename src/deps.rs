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

/// Extract dependency names from a manifest's content.
///
/// Derived from [`parse_dep_specs`] rather than implemented twice. There used
/// to be a second family of per-ecosystem name parsers here, and the two
/// families drifted: whichever one a caller happened to use decided which
/// declaration sections were visible. One parser, one answer.
pub fn parse_deps(eco: Ecosystem, content: &str) -> BTreeSet<String> {
    parse_dep_specs(eco, content)
        .into_iter()
        .map(|s| s.name)
        .collect()
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
    /// A cargo alternate registry (`registry = "…"`), a cargo
    /// `[patch]`/`[replace]` override, or a go `replace` target.
    Other(String),
    /// A pip index/link directive (`--extra-index-url`, `--find-links`, …).
    /// Not a package at all: it re-points where EVERY name in the file may
    /// resolve from, which is a trust decision the gate has to see.
    Index(String),
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
            DepSource::Index(u) => format!("index:{u}"),
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
            DepSource::Index(u) => Some(format!(
                "alternate package index {u} — it re-points where every dependency \
                 in this file may resolve from"
            )),
        }
    }

    /// Whether this dependency's NAME is what resolves its code on the public
    /// registry — i.e. whether asking the registry about the name says anything
    /// true about what will actually be built.
    ///
    /// For a `path`, `git`, `url`, alternate-registry or index-directive
    /// source it does not: the code comes from disk, a URL, or somebody else's
    /// index, and a public package that happens to share the name is an
    /// unrelated package. Resolving those anyway is a name/source confusion in
    /// the very tool that exists to catch name/source confusion — it reported
    /// an in-repo crate as validated on a collision, and an ordinary
    /// sibling-repo path dep as a slopsquatting target.
    ///
    /// An npm alias IS resolvable: `"a": "npm:b@1"` installs the real registry
    /// package `b`, and `b` is the name whose existence matters.
    pub fn is_registry_resolvable(&self) -> bool {
        matches!(self, DepSource::Registry | DepSource::Alias(_))
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
/// Why this manifest could not be read, or `None` if it parses.
///
/// The set-returning parsers below deliberately keep their infallible shape —
/// they are called from a fuzz target and from `current_deps`, where a partial
/// answer is fine. This is the separate question the GATE has to ask, because
/// there the difference between "declares nothing" and "cannot be read" decides
/// whether a commit is allowed through.
///
/// Only the two structured formats can fail: `Cargo.toml` (TOML) and
/// `package.json` (JSON). The line-scanned formats — requirements.txt, go.mod,
/// Gemfile — have no failure mode, they simply match fewer lines, so they are
/// `None` by construction rather than by omission. `pyproject.toml` is checked
/// as TOML because that is what it is, even though the parser falls back to a
/// line scan when `[project].dependencies` is absent.
pub fn manifest_parse_error(eco: Ecosystem, file: &str, content: &str) -> Option<String> {
    // An empty staged file declares nothing and parses as nothing; that is a
    // real answer, not a failure.
    if content.trim().is_empty() {
        return None;
    }
    match eco {
        Ecosystem::Cargo => content.parse::<toml::Table>().err().map(|e| e.to_string()),
        Ecosystem::Npm => serde_json::from_str::<serde_json::Value>(content)
            .err()
            .map(|e| e.to_string()),
        Ecosystem::PyPi if file.ends_with("pyproject.toml") => {
            content.parse::<toml::Table>().err().map(|e| e.to_string())
        }
        // requirements.txt, go.mod and Gemfile are line-scanned: no parse step,
        // so no parse failure to distinguish from an empty declaration.
        Ecosystem::PyPi | Ecosystem::Go | Ecosystem::RubyGems => None,
    }
}

pub fn parse_dep_specs(eco: Ecosystem, content: &str) -> BTreeSet<DepSpec> {
    match eco {
        Ecosystem::Cargo => cargo_specs(content),
        Ecosystem::Npm => npm_specs(content),
        Ecosystem::PyPi => python_specs(content),
        Ecosystem::Go => go_specs(content),
        Ecosystem::RubyGems => gemfile_specs(content),
    }
}

/// The three dependency-table names cargo accepts, both at the top level and
/// under every `[target.<cfg>]` key.
const CARGO_DEP_KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// `package = "real-name"` renames take precedence: the crate that is actually
/// fetched and compiled is the one whose trust matters.
fn cargo_real_name(key: &str, val: &toml::Value) -> String {
    val.as_table()
        .and_then(|t| t.get("package"))
        .and_then(|p| p.as_str())
        .unwrap_or(key)
        .to_string()
}

fn cargo_dep_source(val: &toml::Value) -> DepSource {
    let Some(t) = val.as_table() else {
        return DepSource::Registry; // `name = "1.0"`
    };
    if let Some(u) = t.get("git").and_then(|v| v.as_str()) {
        DepSource::Git(u.to_string())
    } else if let Some(p) = t.get("path").and_then(|v| v.as_str()) {
        DepSource::Path(p.to_string())
    } else if let Some(r) = t.get("registry").and_then(|v| v.as_str()) {
        DepSource::Other(format!("registry {r}"))
    } else {
        DepSource::Registry // `name = { version = "1" }`
    }
}

fn cargo_specs(content: &str) -> BTreeSet<DepSpec> {
    let mut out = BTreeSet::new();
    let Ok(table) = content.parse::<toml::Table>() else {
        return out;
    };
    let mut sections: Vec<&toml::Table> = Vec::new();
    for key in CARGO_DEP_KINDS {
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
    // `[target.'cfg(unix)'.dependencies]` and friends. Platform-conditional
    // dependencies are ordinary dependencies that happen to build on one
    // platform; reading only the unconditional tables meant a dependency added
    // here was never a "new package" at all — a one-line bypass of the gate.
    if let Some(targets) = table.get("target").and_then(|v| v.as_table()) {
        for spec in targets.values() {
            let Some(spec) = spec.as_table() else {
                continue;
            };
            for key in CARGO_DEP_KINDS {
                if let Some(t) = spec.get(key).and_then(|v| v.as_table()) {
                    sections.push(t);
                }
            }
        }
    }
    for s in sections {
        for (name, val) in s {
            out.insert(DepSpec {
                name: cargo_real_name(name, val),
                source: cargo_dep_source(val),
            });
        }
    }
    cargo_override_specs(&table, &mut out);
    out
}

/// `[patch.<registry>]` and the deprecated `[replace]` are the nastiest members
/// of this class: the NAME stays whatever it already was — very possibly an
/// already-approved, entirely reputable name — while the CODE behind it is
/// replaced wholesale by a git checkout, a local directory, or another
/// registry. A name-keyed diff sees nothing change, which is exactly the
/// dependency-substitution shape this gate exists to catch.
fn cargo_override_specs(table: &toml::Table, out: &mut BTreeSet<DepSpec>) {
    if let Some(patch) = table.get("patch").and_then(|v| v.as_table()) {
        for entries in patch.values() {
            let Some(entries) = entries.as_table() else {
                continue;
            };
            for (name, val) in entries {
                out.insert(DepSpec {
                    name: cargo_real_name(name, val),
                    source: cargo_override_source(val),
                });
            }
        }
    }
    if let Some(replace) = table.get("replace").and_then(|v| v.as_table()) {
        for (spec_key, val) in replace {
            // `[replace]` keys are `name:semver`, e.g. `"serde:1.0.0"`.
            let name = spec_key
                .rsplit_once(':')
                .map_or(spec_key.as_str(), |(n, _)| n);
            out.insert(DepSpec {
                name: name.to_string(),
                source: cargo_override_source(val),
            });
        }
    }
}

/// An override must never classify as `Registry`: that would give it the same
/// trust key as the ordinary declaration it overrides, and the whole point is
/// that it is NOT the same code. Anything cargo will accept here that is not
/// git/path/alternate-registry still gets a distinct, visible source.
fn cargo_override_source(val: &toml::Value) -> DepSource {
    match cargo_dep_source(val) {
        DepSource::Registry => DepSource::Other("cargo [patch]/[replace] override".into()),
        other => other,
    }
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

/// PEP 508 direct references (`pkg @ git+https://…`) are the source-swap
/// vector; a plain `pkg==1.2` is registry-sourced.
fn python_requirement_spec(req: &str) -> Option<DepSpec> {
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
}

/// The two file shapes that share `Ecosystem::PyPi`: a `pyproject.toml` (TOML)
/// and a `requirements.txt` (line-oriented). Nothing hands the filename down
/// here, so the content decides — and a TOML document that announces itself as a
/// pyproject is parsed as one and NEVER line-scanned.
///
/// The old rule was "line-scan whenever the TOML parse produced nothing", and it
/// produced a garbage trust baseline. A Poetry manifest declares its
/// dependencies in `[tool.poetry.dependencies]`, so the PEP 621 read found
/// nothing, fell through, and scanned TOML source as if it were pip
/// requirements: `python = "^3.11"` became a dependency called `python`,
/// `version = "0.1.0"` became one called `version`, and the real dependencies
/// were never seen at all. Those fictions then got written into
/// `.sscsb/policy/packages.toml` by `deps baseline` and asked about on PyPI by
/// `deps check`.
fn python_specs(content: &str) -> BTreeSet<DepSpec> {
    let mut out = BTreeSet::new();
    if let Ok(table) = content.parse::<toml::Table>() {
        if is_pyproject(&table) {
            pyproject_specs(&table, &mut out);
            return out;
        }
    }
    for line in content.lines() {
        requirements_line_spec(line, &mut out);
    }
    out
}

/// A `pyproject.toml` announces itself with one of the four tables that can
/// legitimately open one: PEP 518 `[build-system]`, PEP 621 `[project]`,
/// PEP 735 `[dependency-groups]`, or a `[tool.…]` section. A requirements.txt
/// is not valid TOML at all once it contains a single requirement line, so this
/// only has to be right about documents that already parsed.
fn is_pyproject(table: &toml::Table) -> bool {
    ["build-system", "project", "dependency-groups", "tool"]
        .iter()
        .any(|k| table.contains_key(*k))
}

/// Every place a pyproject.toml declares installable code.
///
/// Reading only `[project].dependencies` left whole sections invisible:
/// `[project.optional-dependencies]` (extras — `pip install pkg[dev]` installs
/// them, and CI almost always does), `[dependency-groups]` (PEP 735, where
/// modern tooling puts dev dependencies), and everything any non-PEP-621 build
/// backend declares under `[tool]`.
fn pyproject_specs(table: &toml::Table, out: &mut BTreeSet<DepSpec>) {
    let project = table.get("project").and_then(|p| p.as_table());
    if let Some(arr) = project
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        push_python_reqs(arr, out);
    }
    if let Some(extras) = project
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
    {
        for list in extras.values() {
            if let Some(arr) = list.as_array() {
                push_python_reqs(arr, out);
            }
        }
    }
    if let Some(groups) = table.get("dependency-groups").and_then(|d| d.as_table()) {
        for list in groups.values() {
            // A group entry may be `{ include-group = "other" }`; those are not
            // requirement strings and `as_str` skips them.
            if let Some(arr) = list.as_array() {
                push_python_reqs(arr, out);
            }
        }
    }
    if let Some(tool) = table.get("tool").and_then(|t| t.as_table()) {
        if let Some(poetry) = tool.get("poetry").and_then(|p| p.as_table()) {
            poetry_specs(poetry, out);
        }
        tool_requirement_arrays(tool, out);
    }
}

/// Poetry, which is neither PEP 621 nor pip.
///
/// Its dependencies live under `[tool.poetry]`, and — uniquely among the
/// formats here — they are a TABLE of `name = constraint` rather than an array
/// of PEP 508 strings. Constraints may be a bare version string, an inline table
/// naming a `git`/`path`/`url`/`source` origin, or an ARRAY of such tables when
/// one package is constrained differently per Python version.
fn poetry_specs(poetry: &toml::Table, out: &mut BTreeSet<DepSpec>) {
    let mut tables: Vec<&toml::Table> = Vec::new();
    // `dev-dependencies` is the pre-1.2 spelling; `[tool.poetry.group.<g>]` is
    // the current one. Both are still in the wild and both install code.
    for key in ["dependencies", "dev-dependencies"] {
        if let Some(t) = poetry.get(key).and_then(|v| v.as_table()) {
            tables.push(t);
        }
    }
    if let Some(groups) = poetry.get("group").and_then(|v| v.as_table()) {
        for group in groups.values() {
            if let Some(t) = group
                .as_table()
                .and_then(|g| g.get("dependencies"))
                .and_then(|v| v.as_table())
            {
                tables.push(t);
            }
        }
    }
    for t in tables {
        for (name, val) in t {
            // `python = "^3.11"` is the interpreter constraint, not a package —
            // and it is one of the two names the old line scan invented.
            if name == "python" {
                continue;
            }
            push_poetry_dep(name, val, out);
        }
    }
    // `[[tool.poetry.source]]` is Poetry's `--extra-index-url`: it re-points
    // where names may resolve from, which is a trust decision about every
    // dependency in the file, not about one package.
    if let Some(sources) = poetry.get("source").and_then(|v| v.as_array()) {
        for s in sources {
            if let Some(url) = s
                .as_table()
                .and_then(|t| t.get("url"))
                .and_then(|v| v.as_str())
            {
                out.insert(DepSpec {
                    name: url.to_string(),
                    source: DepSource::Index(url.to_string()),
                });
            }
        }
    }
}

fn push_poetry_dep(name: &str, val: &toml::Value, out: &mut BTreeSet<DepSpec>) {
    // `foo = [{ version = "1", python = "<3.9" }, { version = "2" }]` — one
    // package, several constrained alternatives, each with its own source.
    if let Some(arr) = val.as_array() {
        for entry in arr {
            push_poetry_dep(name, entry, out);
        }
        return;
    }
    if let Some(name) = python_req_name(name) {
        out.insert(DepSpec {
            name,
            source: poetry_dep_source(val),
        });
    }
}

fn poetry_dep_source(val: &toml::Value) -> DepSource {
    let Some(t) = val.as_table() else {
        return DepSource::Registry; // `requests = "^2.31"`
    };
    if let Some(u) = t.get("git").and_then(|v| v.as_str()) {
        DepSource::Git(u.to_string())
    } else if let Some(p) = t.get("path").and_then(|v| v.as_str()) {
        DepSource::Path(p.to_string())
    } else if let Some(u) = t.get("url").and_then(|v| v.as_str()) {
        DepSource::Url(u.to_string())
    } else if let Some(s) = t.get("source").and_then(|v| v.as_str()) {
        // Pinned to a named `[[tool.poetry.source]]` rather than PyPI.
        DepSource::Other(format!("poetry source {s}"))
    } else {
        DepSource::Registry // `requests = { version = "^2.31" }`
    }
}

/// The remaining `[tool.<x>]` sections that hold plain PEP 508 requirement
/// strings in arrays. They all decompose the same way, so they share one reader
/// rather than each growing a parser.
fn tool_requirement_arrays(tool: &toml::Table, out: &mut BTreeSet<DepSpec>) {
    // PDM: `[tool.pdm.dev-dependencies]` is a table of named groups.
    if let Some(groups) = tool
        .get("pdm")
        .and_then(|v| v.as_table())
        .and_then(|p| p.get("dev-dependencies"))
        .and_then(|v| v.as_table())
    {
        for list in groups.values() {
            if let Some(arr) = list.as_array() {
                push_python_reqs(arr, out);
            }
        }
    }
    // uv, before it adopted PEP 735: a single `[tool.uv] dev-dependencies` array.
    if let Some(arr) = tool
        .get("uv")
        .and_then(|v| v.as_table())
        .and_then(|u| u.get("dev-dependencies"))
        .and_then(|v| v.as_array())
    {
        push_python_reqs(arr, out);
    }
    // Hatch: one array per environment.
    if let Some(envs) = tool
        .get("hatch")
        .and_then(|v| v.as_table())
        .and_then(|h| h.get("envs"))
        .and_then(|v| v.as_table())
    {
        for env in envs.values() {
            let Some(env) = env.as_table() else {
                continue;
            };
            for key in ["dependencies", "extra-dependencies"] {
                if let Some(arr) = env.get(key).and_then(|v| v.as_array()) {
                    push_python_reqs(arr, out);
                }
            }
        }
    }
}

fn push_python_reqs(arr: &[toml::Value], out: &mut BTreeSet<DepSpec>) {
    for d in arr {
        if let Some(spec) = d.as_str().and_then(python_requirement_spec) {
            out.insert(spec);
        }
    }
}

/// One requirements.txt line.
///
/// `line.starts_with('-')` used to skip every option line wholesale, which
/// discarded two real trust decisions: `-e git+https://…` installs from an
/// arbitrary VCS URL, and `--extra-index-url` / `--find-links` re-point where
/// every OTHER name in the file may resolve from. Options that genuinely carry
/// no dependency (`-r`, `-c`, `--hash`, `--no-binary`, …) are still skipped.
fn requirements_line_spec(line: &str, out: &mut BTreeSet<DepSpec>) {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return;
    }
    // pip's inline comment is a `#` preceded by whitespace — a bare `#` is a
    // URL fragment (`…#egg=name`) and must survive.
    let line = match line.find(" #") {
        Some(i) => line[..i].trim_end(),
        None => line,
    };
    if line.is_empty() {
        return;
    }
    // Split at the first separator so `-e X`, `--index-url=X` and a bare
    // `pkg==1` all decompose the same way.
    let (opt, rest) = match line.split_once(['=', ' ', '\t']) {
        Some((o, r)) => (o, r.trim()),
        None => (line, ""),
    };
    match opt {
        "-e" | "--editable" => {
            if let Some(spec) = python_direct_reference(rest) {
                out.insert(spec);
            }
            return;
        }
        "-i" | "--index-url" | "--extra-index-url" | "-f" | "--find-links" => {
            if !rest.is_empty() {
                out.insert(DepSpec {
                    name: rest.to_string(),
                    source: DepSource::Index(rest.to_string()),
                });
            }
            return;
        }
        // -r/-c includes, --hash, --no-binary, --require-hashes, …
        _ if opt.starts_with('-') => return,
        _ => {}
    }
    // A bare direct reference: `https://host/x.whl`, `git+ssh://…`, `./pkg`.
    // These used to collapse to the name `https` (or `.`), which made every
    // such line ONE interchangeable trust unit — swap the URL, keep the key.
    if let Some(spec) = python_direct_reference_if_bare(line) {
        out.insert(spec);
        return;
    }
    if let Some(spec) = python_requirement_spec(line) {
        out.insert(spec);
    }
}

fn python_direct_reference_if_bare(line: &str) -> Option<DepSpec> {
    let is_url = match line.split_once("://") {
        Some((scheme, _)) => {
            !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-')
        }
        None => ["git+", "hg+", "svn+", "bzr+"]
            .iter()
            .any(|p| line.starts_with(p)),
    };
    let is_path = line == "."
        || line == ".."
        || line.starts_with("./")
        || line.starts_with("../")
        || line.starts_with('/');
    if is_url || is_path {
        python_direct_reference(line)
    } else {
        None
    }
}

/// A `-e`/bare direct reference. The trust unit is the URL or path itself —
/// two different URLs are two different dependencies even when neither names a
/// package — unless a `#egg=NAME` fragment names one.
fn python_direct_reference(target: &str) -> Option<DepSpec> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }
    let name = target
        .rsplit_once("#egg=")
        .map(|(_, egg)| {
            egg.split(['&', '#'])
                .next()
                .unwrap_or(egg)
                .trim()
                .to_string()
        })
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| target.to_string());
    let source = if ["git+", "hg+", "svn+", "bzr+", "git:", "git@"]
        .iter()
        .any(|p| target.starts_with(p))
    {
        DepSource::Git(target.to_string())
    } else if target.contains("://") {
        DepSource::Url(target.to_string())
    } else {
        DepSource::Path(target.to_string())
    };
    Some(DepSpec { name, source })
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

/// A requirement's package name.
///
/// `is_alphanumeric` rather than `is_ascii_alphanumeric` deliberately: a name
/// carrying a non-ASCII homoglyph (Cyrillic `г` for Latin `r`) used to stop the
/// scan on its first character, yield an empty name, and drop the entire line —
/// so the gate never saw the dependency at all. Surfacing the name is what
/// turns a silent blind spot into something the existence check can reject.
fn python_req_name(req: &str) -> Option<String> {
    let name: String = req
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
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
            // NOTE: `// indirect` is deliberately NOT a filter. It is a comment
            // the go toolchain writes as bookkeeping; it is not a trust
            // boundary, and `go build` will happily compile a module whose
            // require line carries it. Skipping those lines meant appending
            // eight characters to a require made a dependency invisible to this
            // gate. The cost is that a `go get` which pulls new transitive
            // modules now needs them approved too — which is the honest answer,
            // since that is new code entering the build; `sscsb deps baseline`
            // blesses a whole manifest at once.
            if module.contains('/') {
                out.insert(module.to_string());
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
    // A hand-typed `sscsb deps approve <pkg>` names a package to resolve from
    // the registry; that is exactly the Registry case.
    approval_warnings_for(qualified, &DepSource::Registry, offline)
}

/// [`approval_warnings`] for a dependency whose declared source is known.
///
/// Both warnings here interrogate the NAME — is it one edit from a popular
/// package, does it exist on the public registry — and both are meaningless
/// when the name is not what resolves the code. A `path`/`git`/`url` dependency
/// gets neither, because a public package sharing its name is an unrelated
/// package; those sources are flagged on their own terms by
/// [`new_unapproved_deps`], which does not care about the baseline at all.
pub fn approval_warnings_for(qualified: &str, source: &DepSource, offline: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some((label, name)) = qualified.split_once(':') else {
        return warnings;
    };
    let Some(eco) = Ecosystem::from_label(label) else {
        return warnings;
    };
    if !source.is_registry_resolvable() {
        return warnings;
    }
    if let Some(shadowed) = typosquat_suspect(eco, name) {
        warnings.push(format!(
            "`{qualified}` is one edit from popular package `{shadowed}` — possible \
             typosquat/slopsquat"
        ));
    }
    if !offline {
        warnings.extend(registry_problem(qualified, &registry_exists(eco, name)));
    }
    warnings
}

/// What one registry outcome MEANS — in one place, because the two callers used
/// to disagree about it.
///
/// [`approval_warnings_for`] treated `Unknown` as a reason not to approve, while
/// [`deps_check`] filed it as a *note*, left `problems` empty, and printed
/// `deps check: clean` at exit 0. So a DNS failure, a proxy, a 503, or an
/// offline laptop turned the anti-slopsquat control into a rubber stamp: every
/// hallucinated name in the manifest reported clean, with the reason buried in
/// a `note:` line nobody's CI reads.
///
/// An outage is not evidence of existence. `Unknown` is a failure to answer, and
/// the only honest report of a failure to answer is that the check did not pass.
/// `--offline` remains the way to decline the question deliberately.
fn registry_problem(qualified: &str, status: &RegistryStatus) -> Option<String> {
    match status {
        RegistryStatus::Exists => None,
        RegistryStatus::NotFound => Some(format!(
            "{qualified}: NOT FOUND on its public registry — likely hallucinated \
             (slopsquatting target) or private; do not approve without verification"
        )),
        RegistryStatus::Unknown(e) => Some(format!(
            "{qualified}: registry check inconclusive ({e}) — existence was NOT confirmed, \
             and a registry outage is not evidence that a package is real; verify manually, \
             or pass --offline to decline the existence check on purpose"
        )),
    }
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

/// Current deps across all manifests in the repo root, each keeping the source
/// it was declared with.
///
/// The source is the half [`current_deps`] throws away, and throwing it away is
/// what let `deps check` ask the public registry about a `path` dependency.
/// A `BTreeSet`, so the same dependency declared in two manifests of one
/// ecosystem (requirements.txt and pyproject.toml both naming `requests`) is
/// one target, not two registry lookups.
pub fn current_dep_specs(ctx: &Ctx) -> Result<BTreeSet<(Ecosystem, DepSpec)>> {
    let mut out = BTreeSet::new();
    for mf in MANIFEST_FILES {
        let path = ctx.root.join(mf);
        if !path.is_file() {
            continue;
        }
        let eco = Ecosystem::of_manifest(mf).expect("manifest list");
        let content = std::fs::read_to_string(&path)?;
        for spec in parse_dep_specs(eco, &content) {
            out.insert((eco, spec));
        }
    }
    Ok(out)
}

/// Current dependency NAMES across all manifests in the repo root (qualified
/// `eco:name`). Anything that has to know where the code comes from must use
/// [`current_dep_specs`] instead.
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
    /// The staged manifest is present but could not be parsed, so what it
    /// declares is UNKNOWN — not empty.
    ///
    /// Conflating those two is how this gate was bypassed: a parse failure
    /// yielded an empty dependency set, the staged-vs-HEAD diff found nothing
    /// new, and the commit passed with no output at all. A UTF-8 BOM on
    /// `package.json` was enough — npm strips it and installs happily,
    /// `serde_json` does not. A JSONC comment or any TOML syntax error did the
    /// same. A gate that cannot read its input must fail closed.
    UnparseableManifest(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDep {
    pub qualified: String,
    pub reason: NewDepReason,
    /// Where this dependency's code comes from. `None` only for
    /// [`NewDepReason::UnparseableManifest`], where `qualified` is a file path
    /// rather than a package and there is no source to speak of.
    ///
    /// Callers that validate a package by NAME — registry existence, typosquat
    /// distance — must consult this first: those questions are only meaningful
    /// when the name is what resolves the code. See
    /// [`DepSource::is_registry_resolvable`].
    pub source: Option<DepSource>,
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
            NewDepReason::UnparseableManifest(detail) => format!(
                "staged manifest `{}` could not be parsed ({detail}) — its dependencies \
                 are UNKNOWN, not none, so this gate cannot clear the commit. Note a \
                 UTF-8 BOM or a JSONC-style comment will do this: the package manager \
                 tolerates them, the strict parser does not. Fix the file, or stage a \
                 version that parses.",
                self.qualified
            ),
        }
    }
}

/// True if a relative `path = "<rel>"` dependency declared in `manifest`
/// (repo-relative path) resolves to a location INSIDE the repo — the repo's own
/// code, already reviewed here (e.g. a cargo-fuzz project's `path = ".."`).
/// Absolute paths, or `..` components that escape above the repo root, are false.
///
/// Two checks, in order, because neither alone is enough:
///
/// 1. A lexical component walk. This is the only answer available for a path
///    that is not on disk yet (a staged manifest may name a directory that
///    arrives in a later commit), and it is the one that must fail closed.
/// 2. If the path DOES exist, `canonicalize` on both sides, which resolves
///    symlinks. Without this the walk was purely textual, so `path =
///    "link/pkg"` where `link` is a symlink pointing out of the repo counted as
///    the repo's own reviewed code and was exempted from the gate. The doc
///    comment above claimed "resolves to a location INSIDE the repo"; before
///    this it only claimed to *spell* one.
fn path_resolves_within_repo(root: &std::path::Path, manifest: &str, rel: &str) -> bool {
    use std::path::{Component, Path};
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return false;
    }
    let manifest_dir = Path::new(manifest)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let joined = manifest_dir.join(rel_path);
    let mut depth: i32 = 0;
    for c in joined.components() {
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
    // Physical check. If either side cannot be canonicalized the path is not
    // on disk to be followed, so the lexical answer stands.
    match (root.join(&joined).canonicalize(), root.canonicalize()) {
        (Ok(target), Ok(root)) => target.starts_with(root),
        _ => true,
    }
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
        // Fail closed on a manifest we cannot read. Its dependencies are
        // unknown, not none, and treating them as none is exactly how this gate
        // was bypassed. Only the STAGED side matters: an unparseable HEAD is
        // history we cannot change, and blocking on it would wedge the repo.
        if let Some(detail) = manifest_parse_error(eco, file, &staged_content.stdout) {
            out.push(NewDep {
                qualified: file.to_string(),
                reason: NewDepReason::UnparseableManifest(detail),
                source: None,
            });
            continue;
        }
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
                    if path_resolves_within_repo(&ctx.root, file, p) {
                        continue;
                    }
                }
                // Any other non-registry source needs review, regardless of baseline.
                out.push(NewDep {
                    qualified,
                    reason: NewDepReason::NonRegistrySource(desc),
                    source: Some(spec.source.clone()),
                });
            } else if !approved.contains(&qualified) {
                out.push(NewDep {
                    qualified,
                    reason: NewDepReason::NotInBaseline,
                    source: Some(spec.source.clone()),
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
///
/// The list is doing two jobs at once, which is why membership also *clears* a
/// name: an entry is a package worth protecting AND a package asserted to be
/// real, so `rake` and `rack` — one edit apart, both entirely legitimate — must
/// either both be here or neither.
///
/// Go and RubyGems used to be absent, so `typosquat_suspect` returned `None` for
/// them and two whole ecosystems had no typosquat coverage at all. Go is
/// arguably where it matters most: module paths are case-sensitive, and
/// `github.com/Sirupsen/logrus` versus `github.com/sirupsen/logrus` is a real
/// historical split that the `normalize` arm below catches.
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
    (
        "go",
        &[
            "github.com/stretchr/testify",
            "github.com/sirupsen/logrus",
            "github.com/spf13/cobra",
            "github.com/spf13/viper",
            "github.com/pkg/errors",
            "github.com/google/uuid",
            "github.com/gorilla/mux",
            "github.com/gin-gonic/gin",
            "github.com/prometheus/client_golang",
            "github.com/davecgh/go-spew",
            "github.com/lib/pq",
            "github.com/go-sql-driver/mysql",
            "github.com/mattn/go-sqlite3",
            "github.com/aws/aws-sdk-go-v2",
            "go.uber.org/zap",
            "google.golang.org/grpc",
            "google.golang.org/protobuf",
            "gopkg.in/yaml.v3",
            "golang.org/x/crypto",
            "golang.org/x/net",
            "golang.org/x/sync",
            "golang.org/x/sys",
            "golang.org/x/text",
        ],
    ),
    (
        "rubygems",
        &[
            "rails",
            // `rake` and `rack` are one edit apart and both real. Listing both
            // is what stops each from being reported as a squat of the other.
            "rake",
            "rack",
            "rspec",
            "nokogiri",
            "puma",
            "sinatra",
            "devise",
            "pg",
            "mysql2",
            "sqlite3",
            "sidekiq",
            "redis",
            "activerecord",
            "activesupport",
            "bundler",
            "json",
            "faraday",
            "rubocop",
            "httparty",
            "jwt",
            "dotenv",
            "pry",
            "minitest",
            "octokit",
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

/// Split a name into its stem and its trailing run of ASCII digits.
fn split_digit_suffix(name: &str) -> (&str, &str) {
    name.split_at(name.trim_end_matches(|c: char| c.is_ascii_digit()).len())
}

/// True when two names are members of one *family*, distinguished only by a
/// trailing digit — `sha1`/`sha2`/`sha3`, `base32`/`base64`,
/// `gopkg.in/yaml.v2`/`gopkg.in/yaml.v3`.
///
/// These are not typos of one another, and treating them as such was a real
/// false positive: `sha1` and `sha3` are ubiquitous RustCrypto crates, yet each
/// was reported as a typosquat of `sha2` and could not be baselined without
/// `--force`. A false "unapproved dependency" blocks somebody's commit, so the
/// heuristic has to be right about this class, not merely loud.
///
/// A typosquat works by *misreading or mistyping* a name. A trailing digit is
/// the one token nobody glosses over — it is the whole semantic payload of the
/// name (which SHA? which base?) and picking the wrong one lands you on a
/// different real package that fails to compile, not on attacker-controlled
/// code.
///
/// Three conditions keep this from becoming a bypass, and all three are load-
/// bearing:
///
/// * **Both** sides must carry a digit suffix. `requests2` shadowing `requests`,
///   or `boto` shadowing `boto3`, is a classic squat and stays flagged — only
///   one side has digits.
/// * The digit runs must be the **same length**, so `sha22` is still a suspect
///   of `sha2` while `sha1` is not.
/// * The stems must be identical and non-empty, so this never fires on names
///   that merely both happen to end in a digit.
///
/// The residue: it does exempt an unknown `<popular-stem><other-digit>` — `sha7`,
/// `urllib2` — from the *distance* heuristic. Those names still go through the
/// registry-existence check, which is the arm that actually knows whether a name
/// is real; the distance heuristic never did.
fn digit_variant_siblings(a: &str, b: &str) -> bool {
    let (stem_a, digits_a) = split_digit_suffix(a);
    let (stem_b, digits_b) = split_digit_suffix(b);
    !digits_a.is_empty()
        && !digits_b.is_empty()
        && digits_a.len() == digits_b.len()
        && digits_a != digits_b
        && !stem_a.is_empty()
        && stem_a == stem_b
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
            !digit_variant_siblings(name, popular)
                && (edit_distance_leq1(name, popular)
                    || (normalize(name) == normalize(popular) && name != **popular))
        })
        .copied()
}

// ─────────────────────────── verify / CLI entry ─────────────────────────────

pub fn verify_package_trust(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = Vec::new();
    let hooks = crate::hooks::hook_integrity(ctx);
    if let Some(blocked) = hooks.blocking("package-trust") {
        return blocked;
    }
    messages.push("new-package approval gate enforced in commit-msg hook".into());
    messages.extend(hooks.messages.iter().cloned());
    let outcome = if packages_policy_path(ctx).is_file() {
        // A baseline that cannot be parsed is not a baseline of zero packages —
        // it is a baseline nobody can read, and the commit gate that consumes it
        // cannot evaluate. Swallowing the error into `0 package(s)` reported the
        // broken state as PASS.
        match load_approved(ctx) {
            Ok(approved) => {
                messages.push(format!(
                    "approved baseline present ({} package(s))",
                    approved.len()
                ));
                Outcome::Pass
            }
            Err(err) => {
                messages.push(format!(
                    "approved baseline UNREADABLE — the commit gate cannot evaluate it: {err:#}"
                ));
                messages.push(
                    "fix .sscsb/policy/packages.toml (or delete it and re-run \
                     `sscsb deps baseline`) — nothing was verified"
                        .into(),
                );
                Outcome::Degraded
            }
        }
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
    VerifyResult::new("package-trust", outcome.weakest(hooks.outcome), messages)
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
///
/// Every check below asks a question ABOUT A NAME — is it one edit from a
/// popular package, does the public registry have it — so every check first has
/// to know whether the name is what resolves the code. It did not: targets were
/// built from name-only lists, the source was discarded, and a `path`
/// dependency was resolved against crates.io like any other. That got both
/// answers wrong in the same run — an in-repo crate reported as "exists on
/// registry" on nothing but a name collision with an unrelated public crate,
/// and a sibling-repo path dep (`../grc-controls/…`, an ordinary multi-repo
/// layout) reported as a likely slopsquatting target at exit 1.
pub fn deps_check(ctx: &Ctx, offline: bool) -> Result<(Vec<String>, Vec<String>)> {
    deps_check_with(ctx, offline, registry_exists)
}

/// [`deps_check`] with the registry lookup injected, so the outage path can be
/// exercised without an outage (and without a network call).
fn deps_check_with(
    ctx: &Ctx,
    offline: bool,
    resolve: impl Fn(Ecosystem, &str) -> RegistryStatus,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let new_deps = new_unapproved_deps(ctx)?;
    let targets: Vec<(String, Option<DepSource>)> = if new_deps.is_empty() {
        current_dep_specs(ctx)?
            .into_iter()
            .map(|(eco, spec)| (format!("{}:{}", eco.label(), spec.name), Some(spec.source)))
            .collect()
    } else {
        notes.push(format!("checking {} staged new package(s)", new_deps.len()));
        new_deps
            .into_iter()
            .map(|d| (d.qualified, d.source))
            .collect()
    };
    for (qualified, source) in &targets {
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
        // Not registry-resolvable → the name answers nothing. Say so and move
        // on; the commit gate flags these on their own terms (a non-registry
        // source needs review whatever the baseline says), so staying silent
        // here loses no coverage — it only stops inventing a verdict.
        if let Some(source) = source.as_ref().filter(|s| !s.is_registry_resolvable()) {
            if let Some(desc) = source.describe() {
                notes.push(format!(
                    "{qualified}: {desc} — not resolved by name against the public \
                     {eco_label} registry, because the name is not what resolves it"
                ));
            }
            continue;
        }
        if let Some(shadowed) = typosquat_suspect(eco, name) {
            problems.push(format!(
                "{qualified}: name is one edit away from popular package `{shadowed}` — \
                 possible typosquat/slopsquat; verify intent before approving"
            ));
        }
        if !offline {
            match registry_problem(qualified, &resolve(eco, name)) {
                Some(problem) => problems.push(problem),
                None => notes.push(format!("{qualified}: exists on registry")),
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
        let deps = parse_deps(
            Ecosystem::Cargo,
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
        let npm = parse_deps(
            Ecosystem::Npm,
            r#"{"dependencies":{"react":"18"},"devDependencies":{"jest":"29"}}"#,
        );
        assert!(npm.contains("react") && npm.contains("jest"));

        let py = parse_deps(Ecosystem::PyPi, "requests==2.31.0\n# comment\nflask>=2\n");
        assert!(py.contains("requests") && py.contains("flask"));

        let pyproject = parse_deps(
            Ecosystem::PyPi,
            "[project]\nname = \"x\"\ndependencies = [\"pydantic>=2\"]\n",
        );
        assert!(pyproject.contains("pydantic"));

        let go = parse_go("module m\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/sys v0.1.0 // indirect\n)\n");
        assert!(go.contains("github.com/pkg/errors"));
        // `// indirect` used to exclude the line. It is a toolchain comment, not
        // a trust boundary — appending it to a require was a one-line way to
        // hide a module from this gate — so an indirect require is now visible
        // like any other.
        assert!(
            go.contains("golang.org/x/sys"),
            "an `// indirect` require is still a module in the build: {go:?}"
        );

        let gems = parse_deps(
            Ecosystem::RubyGems,
            "source 'https://rubygems.org'\ngem 'rails', '~> 7'\n",
        );
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
            source: Some(DepSource::Registry),
        };
        assert!(baseline.explain().contains("approved baseline"));
        let source = NewDep {
            qualified: "cargo:serde".into(),
            reason: NewDepReason::NonRegistrySource("git source u".into()),
            source: Some(DepSource::Git("u".into())),
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
        assert!(parse_deps(Ecosystem::Cargo, "this is { not valid toml").is_empty());
    }

    // ───────────────────────── python parsing edge cases ─────────────────────

    #[test]
    fn parse_python_pyproject_skips_non_string_and_unnameable_array_entries() {
        // TOML 1.0 arrays may be heterogeneous; a stray integer and an empty
        // string must be skipped rather than corrupting the result.
        let deps = parse_deps(
            Ecosystem::PyPi,
            "[project]\nname = \"x\"\ndependencies = [123, \"\", \"pydantic>=2\"]\n",
        );
        assert_eq!(deps, BTreeSet::from(["pydantic".to_string()]));
    }

    /// M10: a pyproject.toml is never line-scanned as if it were pip
    /// requirements.
    ///
    /// It used to be, whenever the PEP 621 read came up empty — and a
    /// line-oriented scan of TOML source does not find dependencies, it finds
    /// bare keys. A minimal pyproject.toml declaring no dependencies at all
    /// yielded two: `name` and `version`.
    #[test]
    fn a_pyproject_declaring_nothing_yields_nothing_not_its_own_toml_keys() {
        let deps = parse_deps(
            Ecosystem::PyPi,
            "[project]\nname = \"mypkg\"\nversion = \"0.1.0\"\n",
        );
        assert!(
            deps.is_empty(),
            "a pyproject.toml with no dependency section declares no \
             dependencies; `name`/`version` are TOML keys, not packages: {deps:?}"
        );

        // A build-system-only pyproject is the same story.
        assert!(parse_deps(
            Ecosystem::PyPi,
            "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n",
        )
        .is_empty());

        // …and the requirements.txt path is untouched: a real requirements file
        // is not valid TOML, so it still line-scans.
        assert!(parse_deps(Ecosystem::PyPi, "requests==2.31.0\nflask>=2\n").contains("requests"));
    }

    /// M10: Poetry manifests produced a garbage trust baseline.
    ///
    /// Poetry declares dependencies in `[tool.poetry.dependencies]`, so the
    /// PEP 621 read found nothing and the file fell through to the pip line
    /// scan. The result was not "some dependencies missed" — it was
    /// `python` and `version` written into `.sscsb/policy/packages.toml` as
    /// approved packages, and the real dependencies never seen at all.
    #[test]
    fn poetry_dependencies_are_parsed_instead_of_line_scanned_into_nonsense() {
        let specs = python_specs(
            "[tool.poetry]\n\
             name = \"mypkg\"\n\
             version = \"0.1.0\"\n\
             [tool.poetry.dependencies]\n\
             python = \"^3.11\"\n\
             requests = \"^2.31\"\n\
             pydantic = { version = \"^2.0\", extras = [\"email\"] }\n\
             evil = { git = \"https://evil.example/x.git\", branch = \"main\" }\n\
             localpkg = { path = \"../localpkg\" }\n\
             wheelpkg = { url = \"https://evil.example/x.whl\" }\n\
             privpkg = { version = \"^1\", source = \"corp\" }\n\
             [tool.poetry.dev-dependencies]\n\
             pytest = \"^7\"\n\
             [tool.poetry.group.docs.dependencies]\n\
             sphinx = \"^7\"\n\
             [[tool.poetry.source]]\n\
             name = \"corp\"\n\
             url = \"https://corp.example/simple\"\n",
        );
        let names: BTreeSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();

        // The real dependencies, from all three declaration shapes.
        assert!(names.contains("requests"), "{specs:?}");
        assert!(names.contains("pydantic"), "{specs:?}");
        assert!(
            names.contains("pytest"),
            "legacy dev-dependencies: {specs:?}"
        );
        assert!(names.contains("sphinx"), "poetry groups: {specs:?}");

        // The nonsense the line scan used to invent.
        assert!(
            !names.contains("python"),
            "`python` is the interpreter constraint, not a package: {specs:?}"
        );
        assert!(
            !names.contains("version") && !names.contains("name"),
            "TOML keys are not packages: {specs:?}"
        );

        // Sources are classified, so a repointed Poetry dependency is a fresh
        // trust decision rather than a name that looks unchanged.
        assert!(matches!(source_of(&specs, "evil"), DepSource::Git(_)));
        assert!(matches!(source_of(&specs, "localpkg"), DepSource::Path(_)));
        assert!(matches!(source_of(&specs, "wheelpkg"), DepSource::Url(_)));
        assert!(matches!(source_of(&specs, "privpkg"), DepSource::Other(_)));
        assert_eq!(*source_of(&specs, "requests"), DepSource::Registry);
        assert_eq!(*source_of(&specs, "pydantic"), DepSource::Registry);
        assert!(
            specs
                .iter()
                .any(|s| matches!(s.source, DepSource::Index(_))
                    && s.name.contains("corp.example")),
            "an added [[tool.poetry.source]] re-points every name in the file: {specs:?}"
        );
    }

    /// Poetry's multi-constraint form is one package with several alternatives,
    /// each of which may carry its own source.
    #[test]
    fn poetry_multiple_constraint_dependencies_are_read_per_alternative() {
        let specs = python_specs(
            "[tool.poetry.dependencies]\n\
             backport = [\n\
               { version = \"^1.0\", python = \"<3.9\" },\n\
               { git = \"https://evil.example/backport.git\", python = \">=3.9\" },\n\
             ]\n",
        );
        assert!(
            specs
                .iter()
                .any(|s| s.name == "backport" && s.source == DepSource::Registry),
            "{specs:?}"
        );
        assert!(
            specs
                .iter()
                .any(|s| s.name == "backport" && matches!(s.source, DepSource::Git(_))),
            "the git alternative must be its own trust unit: {specs:?}"
        );
    }

    /// The other `[tool.*]` backends that hold plain requirement arrays. Each
    /// used to line-scan into its own group NAME (`test`, `lint`) instead of the
    /// packages inside it.
    #[test]
    fn pdm_uv_and_hatch_dependency_sections_are_parsed() {
        let pdm = parse_deps(
            Ecosystem::PyPi,
            "[tool.pdm.dev-dependencies]\ntest = [\"pytest>=7\"]\nlint = [\"ruff\"]\n",
        );
        assert!(pdm.contains("pytest") && pdm.contains("ruff"), "{pdm:?}");
        assert!(!pdm.contains("test") && !pdm.contains("lint"), "{pdm:?}");

        let uv = parse_deps(
            Ecosystem::PyPi,
            "[tool.uv]\ndev-dependencies = [\"pytest>=7\", \"mypy\"]\n",
        );
        assert!(uv.contains("pytest") && uv.contains("mypy"), "{uv:?}");

        let hatch = parse_deps(
            Ecosystem::PyPi,
            "[tool.hatch.envs.default]\ndependencies = [\"coverage\"]\n\
             [tool.hatch.envs.docs]\nextra-dependencies = [\"mkdocs\"]\n",
        );
        assert!(
            hatch.contains("coverage") && hatch.contains("mkdocs"),
            "{hatch:?}"
        );
    }

    #[test]
    fn parse_python_requirements_txt_skips_directives_blanks_and_unnameable_lines() {
        // `-e .` is no longer skipped: an editable install IS a dependency, and
        // `-e` was the same option prefix that hid `-e git+https://…`. A local
        // editable path is recorded as a path source, which the commit gate
        // exempts when it stays inside the repo — so nothing new blocks — while
        // `==1.0` (no name) and comments are still dropped.
        let deps = parse_deps(Ecosystem::PyPi, "# a comment\n-e .\n\n==1.0\nrequests\n");
        assert_eq!(
            deps,
            BTreeSet::from([".".to_string(), "requests".to_string()])
        );
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

    /// A manifest that is present but unreadable must fail the gate closed.
    ///
    /// Before this, every parser turned a parse failure into an EMPTY dependency
    /// set, so the staged-vs-HEAD diff found nothing new and the commit passed
    /// with no output at all. The cheapest trigger is a UTF-8 BOM on
    /// `package.json`: npm strips it and installs happily, `serde_json` does
    /// not. Reproduced end to end — clean manifest blocked at exit 1, the same
    /// manifest with a BOM exited 0 silently.
    #[test]
    fn unparseable_staged_manifest_blocks_instead_of_reading_as_no_dependencies() {
        for (file, baseline, broken) in [
            (
                "package.json",
                r#"{"dependencies":{"lodash":"4"}}"#.to_string(),
                // BOM first: the package manager tolerates it, the parser does not.
                format!("\u{feff}{}", r#"{"dependencies":{"evil-abc":"1"}}"#),
            ),
            (
                "package.json",
                r#"{"dependencies":{"lodash":"4"}}"#.to_string(),
                "// deps\n{\"dependencies\":{\"evil-abc\":\"1\"}}".to_string(),
            ),
            (
                "Cargo.toml",
                "[dependencies]\nserde = \"1\"\n".to_string(),
                "[dependencies]\nserde = \"1\"\n= = =\n".to_string(),
            ),
        ] {
            let (_d, ctx) = repo_ctx();
            write_file(&ctx, file, &baseline);
            stage(&ctx, file);
            exec::git_raw(&["commit", "-m", "base", "--no-verify"], &ctx.root).unwrap();

            write_file(&ctx, file, &broken);
            stage(&ctx, file);

            let found = new_unapproved_deps(&ctx).unwrap();
            assert_eq!(
                found.len(),
                1,
                "{file}: an unreadable manifest must produce exactly one problem, got {found:?}"
            );
            assert!(
                matches!(found[0].reason, NewDepReason::UnparseableManifest(_)),
                "{file}: expected UnparseableManifest, got {:?}",
                found[0].reason
            );
            assert!(
                found[0].explain().contains("UNKNOWN, not none"),
                "the message must say why an empty read is not a clean read"
            );
        }
    }

    /// The guard must not fire on manifests that legitimately declare nothing,
    /// or on the three line-scanned formats that have no parse step at all.
    #[test]
    fn manifest_parse_error_distinguishes_unreadable_from_empty() {
        // Structured formats: real failures.
        assert!(manifest_parse_error(Ecosystem::Npm, "package.json", "{ not json").is_some());
        assert!(manifest_parse_error(Ecosystem::Cargo, "Cargo.toml", "= = =").is_some());
        assert!(
            manifest_parse_error(Ecosystem::PyPi, "pyproject.toml", "= = =").is_some(),
            "pyproject.toml is TOML and must be checked as TOML"
        );

        // Valid, and validly empty.
        assert!(manifest_parse_error(Ecosystem::Npm, "package.json", "{}").is_none());
        assert!(manifest_parse_error(Ecosystem::Cargo, "Cargo.toml", "").is_none());
        assert!(manifest_parse_error(Ecosystem::Npm, "package.json", "   \n ").is_none());

        // Line-scanned formats cannot fail to parse; they match fewer lines.
        // These are None by construction, not by omission.
        assert!(manifest_parse_error(Ecosystem::PyPi, "requirements.txt", "= = =").is_none());
        assert!(manifest_parse_error(Ecosystem::Go, "go.mod", "= = =").is_none());
        assert!(manifest_parse_error(Ecosystem::RubyGems, "Gemfile", "= = =").is_none());
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

    /// M17 (a): `sha1`, `sha2` and `sha3` are three different, ubiquitous
    /// crates. Each was reported as a typosquat of the others, so baselining a
    /// perfectly ordinary hashing dependency needed `--force`. A false
    /// "unapproved dependency" blocks somebody's commit; that is the expensive
    /// direction to be wrong in.
    #[test]
    fn digit_variant_siblings_are_a_family_not_a_typosquat() {
        // `sha2` is the POPULAR entry; its siblings must clear.
        assert_eq!(typosquat_suspect(Ecosystem::Cargo, "sha1"), None);
        assert_eq!(typosquat_suspect(Ecosystem::Cargo, "sha3"), None);
        // `base64` is a POPULAR entry and `base32` is a real crate.
        assert_eq!(typosquat_suspect(Ecosystem::Cargo, "base32"), None);
        // Go: `gopkg.in/yaml.v2` and `.v3` are both in wide use.
        assert_eq!(
            typosquat_suspect(Ecosystem::Go, "gopkg.in/yaml.v2"),
            None,
            "the two live major versions of a module are not typos of each other"
        );

        // …and none of the three guards may be relaxed. Each of these is still
        // a suspect, which is what stops the exemption becoming a bypass.
        assert_eq!(
            typosquat_suspect(Ecosystem::Cargo, "shal"),
            Some("sha2"),
            "a lookalike letter for the digit is exactly the squat this catches"
        );
        assert_eq!(
            typosquat_suspect(Ecosystem::Cargo, "sha22"),
            Some("sha2"),
            "differing digit-run LENGTH is an appended digit, not a sibling"
        );
        assert_eq!(
            typosquat_suspect(Ecosystem::PyPi, "boto"),
            Some("boto3"),
            "only one side carries digits — dropping the `3` is a squat shape"
        );
        assert_eq!(
            typosquat_suspect(Ecosystem::Cargo, "sha"),
            Some("sha2"),
            "same: no digit suffix on one side"
        );

        // The predicate itself, at its boundaries.
        assert!(digit_variant_siblings("sha1", "sha2"));
        assert!(!digit_variant_siblings("sha1", "sha1")); // identical digits
        assert!(!digit_variant_siblings("sha", "sha2")); // one side bare
        assert!(!digit_variant_siblings("sha2", "sha22")); // different lengths
        assert!(!digit_variant_siblings("1", "2")); // empty stem
        assert!(!digit_variant_siblings("abc1", "xyz2")); // different stems
    }

    /// M17 (b): `POPULAR` curated cargo/npm/pypi only, so `typosquat_suspect`
    /// fell out of the lookup's `?` for Go and RubyGems and two whole
    /// ecosystems had NO typosquat coverage — `sscsb deps check` on a Go or
    /// Rails repo could not flag a single lookalike.
    #[test]
    fn go_and_rubygems_have_typosquat_coverage() {
        // Go: a transposed module path.
        assert_eq!(
            typosquat_suspect(Ecosystem::Go, "github.com/stretchr/testfiy"),
            Some("github.com/stretchr/testify")
        );
        // Go's own hazard: module paths are case-sensitive, so a capitalised
        // path is a different module that reads identically.
        assert_eq!(
            typosquat_suspect(Ecosystem::Go, "github.com/Sirupsen/logrus"),
            Some("github.com/sirupsen/logrus")
        );
        // The real ones still clear.
        assert_eq!(
            typosquat_suspect(Ecosystem::Go, "github.com/pkg/errors"),
            None
        );
        assert_eq!(typosquat_suspect(Ecosystem::Go, "golang.org/x/sync"), None);
        assert_eq!(
            typosquat_suspect(Ecosystem::Go, "github.com/something/entirely-else"),
            None
        );

        // RubyGems.
        assert_eq!(
            typosquat_suspect(Ecosystem::RubyGems, "nokogiri "),
            Some("nokogiri"),
            "a trailing space is a distinct gem name one edit away"
        );
        assert_eq!(
            typosquat_suspect(Ecosystem::RubyGems, "sinatr"),
            Some("sinatra")
        );
        assert_eq!(typosquat_suspect(Ecosystem::RubyGems, "rails"), None);
        // `rake` and `rack` are one edit apart and BOTH real: listing both is
        // what keeps each from being reported as a squat of the other.
        assert_eq!(typosquat_suspect(Ecosystem::RubyGems, "rake"), None);
        assert_eq!(typosquat_suspect(Ecosystem::RubyGems, "rack"), None);
        assert_eq!(
            typosquat_suspect(Ecosystem::RubyGems, "unrelated-gem"),
            None
        );
    }

    /// Structural guard for the same finding: every ecosystem sscsb can parse
    /// must have a curated list, or `typosquat_suspect` drops out of the
    /// lookup's `?` and that ecosystem gets no coverage at all — silently, with
    /// `deps check` reporting clean.
    ///
    /// And every curated name must clear its own ecosystem's heuristic,
    /// otherwise adding a protected name silently converts it into a suspect —
    /// which is precisely the `rake`/`rack` trap.
    #[test]
    fn every_ecosystem_has_a_popular_list_and_no_curated_name_is_a_suspect() {
        for eco in [
            Ecosystem::Cargo,
            Ecosystem::Npm,
            Ecosystem::PyPi,
            Ecosystem::Go,
            Ecosystem::RubyGems,
        ] {
            assert!(
                POPULAR.iter().any(|(label, _)| *label == eco.label()),
                "`{}` has no curated popular list, so it has no typosquat coverage at all",
                eco.label()
            );
        }
        for (label, names) in POPULAR {
            let eco = Ecosystem::from_label(label).expect("POPULAR label is an ecosystem");
            for name in *names {
                assert_eq!(
                    typosquat_suspect(eco, name),
                    None,
                    "{label}: `{name}` is curated as popular and must never be \
                     reported as a squat of another curated name"
                );
            }
        }
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
    fn deps_check_online_records_the_registry_outcome_for_every_target() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        let (problems, notes) = deps_check(&ctx, false).unwrap();
        assert!(!problems.iter().any(|p| p.contains("typosquat")));
        // Online: `serde` exists → a note. Degraded: the lookup could not
        // answer → a PROBLEM, never silence. Either way the outcome is on the
        // record; what must never happen is neither.
        assert!(
            notes.iter().any(|n| n.contains("cargo:serde"))
                || problems.iter().any(|p| p.contains("cargo:serde")),
            "the registry outcome for `serde` must always be recorded, online or \
             degraded: problems={problems:?} notes={notes:?}"
        );
    }

    /// M11: a registry outage used to report `deps check: clean` at exit 0.
    ///
    /// The two `registry_exists` callers disagreed about what `Unknown` means:
    /// `approval_warnings_for` treated it as a reason not to approve, while
    /// `deps_check` filed it as a *note*, left `problems` empty, and let the CLI
    /// print `deps check: clean`. One blocked DNS lookup, one corporate proxy,
    /// one crates.io 503, and the anti-slopsquat control passed every
    /// hallucinated name in the manifest.
    ///
    /// The lookup is injected, so this proves the policy without a network call
    /// and without waiting for a real outage.
    #[test]
    fn a_registry_outage_is_a_problem_not_a_clean_check() {
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nsome-crate = \"1\"\n");
        let outage = |_: Ecosystem, _: &str| RegistryStatus::Unknown("dns error".into());

        let (problems, notes) = deps_check_with(&ctx, false, outage).unwrap();
        assert!(
            problems.iter().any(
                |p| p.contains("cargo:some-crate") && p.contains("registry check inconclusive")
            ),
            "an unanswered existence check must fail the check, not annotate it: \
             problems={problems:?} notes={notes:?}"
        );
        assert!(
            !notes.iter().any(|n| n.contains("some-crate")),
            "an outage must not be filed as a passing note: {notes:?}"
        );

        // …and the two callers now agree, because they share one verdict.
        let status = RegistryStatus::Unknown("dns error".into());
        assert_eq!(
            registry_problem("cargo:some-crate", &status),
            problems.first().cloned(),
            "`deps check` and `deps approve` must reach the same verdict"
        );
        assert!(registry_problem("cargo:serde", &RegistryStatus::Exists).is_none());
        assert!(registry_problem("cargo:nope", &RegistryStatus::NotFound)
            .is_some_and(|p| p.contains("NOT FOUND")));

        // `--offline` remains the deliberate way to decline the question.
        let (offline_problems, _) = deps_check_with(&ctx, true, outage).unwrap();
        assert!(
            offline_problems.is_empty(),
            "--offline declines the existence check on purpose: {offline_problems:?}"
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

    /// Regression (H4): a baseline file that exists but cannot be parsed is not
    /// a baseline of zero packages — it is a baseline the commit gate cannot
    /// evaluate. `load_approved(..).map(len).unwrap_or(0)` swallowed the parse
    /// error and reported `approved baseline present (0 package(s))` under a
    /// PASS verdict, so corrupting the file looked healthier than deleting it.
    #[test]
    fn verify_package_trust_degrades_when_the_baseline_cannot_be_parsed() {
        let (_d, ctx) = repo_ctx();
        let cfg = ctx.require_config().unwrap();
        // Sanity: the pristine bootstrapped baseline passes.
        assert_eq!(verify_package_trust(&ctx, cfg).outcome, Outcome::Pass);

        // One appended line — the whole file stops parsing.
        let path = packages_policy_path(&ctx);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("garbage [ not toml\n");
        std::fs::write(&path, text).unwrap();

        let result = verify_package_trust(&ctx, cfg);
        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("approved baseline UNREADABLE")),
            "{:?}",
            result.messages
        );
        assert!(
            !result
                .messages
                .iter()
                .any(|m| m.contains("baseline present (0 package(s))")),
            "an unparseable baseline must never be reported as an empty one: {:?}",
            result.messages
        );
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
        // None of these exist on disk, so only the lexical walk can answer —
        // which is the case the physical check must leave alone.
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        // in-tree (own code) — exempt
        assert!(path_resolves_within_repo(root, "fuzz/Cargo.toml", "..")); // → repo root
        assert!(path_resolves_within_repo(root, "fuzz/Cargo.toml", "../src"));
        assert!(path_resolves_within_repo(root, "Cargo.toml", "."));
        assert!(path_resolves_within_repo(root, "a/b/Cargo.toml", "../.."));
        // escapes the repo — still flagged
        assert!(!path_resolves_within_repo(root, "fuzz/Cargo.toml", "../.."));
        assert!(!path_resolves_within_repo(root, "Cargo.toml", ".."));
        assert!(!path_resolves_within_repo(
            root,
            "fuzz/Cargo.toml",
            "/etc/passwd"
        ));
    }

    /// The physical half of the same predicate. A lexical walk can only tell
    /// you how a path is SPELLED; `link/pkg` spells an in-tree location while
    /// resolving anywhere the symlink points.
    #[cfg(unix)]
    #[test]
    fn path_within_repo_follows_symlinks_before_deciding() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("pkg")).unwrap();
        std::fs::create_dir_all(root.path().join("real")).unwrap();
        symlink(outside.path(), root.path().join("link")).unwrap();

        assert!(
            !path_resolves_within_repo(root.path(), "Cargo.toml", "link/pkg"),
            "a symlink out of the repo is not the repo's own reviewed code"
        );
        // A real in-tree directory still resolves in-tree.
        assert!(path_resolves_within_repo(root.path(), "Cargo.toml", "real"));
    }

    // ───────── H7: declaration classes that must not be invisible ─────────
    //
    // Each of these is a way to put code into the build that the trust gate
    // never looked at. They are regressions, not features: every one of them
    // passed at exit 0 before the parsers below learned to read the section.

    /// `[target.'cfg(unix)'.dependencies]` is a real, buildable dependency
    /// table. Reading only the three unconditional tables meant a
    /// platform-gated dependency was never a "new package" at all.
    #[test]
    fn cargo_target_specific_sections_are_not_invisible() {
        let specs = cargo_specs(
            "[dependencies]\n\
             serde = \"1\"\n\
             [target.'cfg(unix)'.dependencies]\n\
             unixdep = \"1\"\n\
             [target.\"cfg(windows)\".dev-dependencies]\n\
             windep = \"1\"\n\
             [target.'cfg(target_os = \"macos\")'.build-dependencies]\n\
             macdep = \"1\"\n\
             [target.'cfg(unix)'.dependencies.gitdep]\n\
             git = \"https://evil.example/repo\"\n",
        );
        let names: BTreeSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains("unixdep"), "{specs:?}");
        assert!(names.contains("windep"), "{specs:?}");
        assert!(names.contains("macdep"), "{specs:?}");
        assert!(
            matches!(source_of(&specs, "gitdep"), DepSource::Git(_)),
            "a target-gated git source must still classify as git: {specs:?}"
        );
        // The name-only view must agree — it feeds the baseline.
        assert!(parse_deps(
            Ecosystem::Cargo,
            "[target.'cfg(unix)'.dependencies]\nunixdep = \"1\"\n"
        )
        .contains("unixdep"));
    }

    /// `[patch.crates-io]` is the nastiest of the class: the NAME stays the
    /// already-approved one while the CODE is replaced wholesale by an
    /// attacker-controlled git checkout. A name-keyed diff sees nothing.
    /// `[replace]` is the deprecated spelling of the same swap.
    #[test]
    fn cargo_patch_and_replace_repoint_a_trusted_name_to_an_untrusted_source() {
        let specs = cargo_specs(
            "[dependencies]\n\
             serde = \"1\"\n\
             [patch.crates-io]\n\
             serde = { git = \"https://evil.example/serde\" }\n",
        );
        assert!(
            specs
                .iter()
                .any(|s| s.name == "serde" && matches!(s.source, DepSource::Git(_))),
            "a [patch.crates-io] git override must be a distinct trust unit: {specs:?}"
        );

        let replaced = cargo_specs(
            "[dependencies]\nserde = \"1\"\n\
             [replace]\n\"serde:1.0.0\" = { git = \"https://evil.example/serde\" }\n",
        );
        assert!(
            replaced
                .iter()
                .any(|s| s.name == "serde" && matches!(s.source, DepSource::Git(_))),
            "[replace] must be read too: {replaced:?}"
        );
    }

    /// `[project.optional-dependencies]` (PEP 621 extras) and
    /// `[dependency-groups]` (PEP 735) install real code. The parser returned
    /// early on `[project].dependencies` and never looked at either.
    #[test]
    fn pyproject_optional_dependencies_and_dependency_groups_are_parsed() {
        let specs = python_specs(
            "[project]\nname = \"x\"\ndependencies = [\"requests==2.31.0\"]\n\
             [project.optional-dependencies]\n\
             dev = [\"evil-extra==1.0\"]\n\
             docs = [\"sphinx\"]\n",
        );
        let names: BTreeSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains("requests"), "{specs:?}");
        assert!(names.contains("evil-extra"), "{specs:?}");
        assert!(names.contains("sphinx"), "{specs:?}");

        let groups = python_specs(
            "[project]\nname = \"x\"\ndependencies = []\n\
             [dependency-groups]\ntest = [\"evil-group @ git+https://evil.example/x\"]\n",
        );
        assert!(
            groups
                .iter()
                .any(|s| s.name == "evil-group" && matches!(s.source, DepSource::Git(_))),
            "PEP 735 dependency groups must be read, with their sources: {groups:?}"
        );
    }

    /// `// indirect` is a comment. `go build` does not treat it as a trust
    /// boundary and neither may this gate: appending it to a `require` line
    /// hid the module completely.
    #[test]
    fn go_indirect_comment_cannot_hide_a_required_module() {
        let deps = parse_go(
            "module m\n\nrequire (\n\tevil.example/pkg v1.0.0 // indirect\n)\n\
             require evil.example/two v1.0.0 // indirect\n",
        );
        assert!(deps.contains("evil.example/pkg"), "{deps:?}");
        assert!(deps.contains("evil.example/two"), "{deps:?}");
    }

    /// requirements.txt option lines were skipped wholesale by
    /// `line.starts_with('-')`. `-e git+…` installs from an arbitrary VCS URL
    /// and `--extra-index-url` re-points resolution for EVERY package in the
    /// file — both are trust decisions, not formatting.
    #[test]
    fn requirements_editable_and_index_directives_are_parsed_not_skipped() {
        let specs = python_specs(
            "requests==2.31.0  # pinned by security\n\
             -e git+https://evil.example/x#egg=evil-editable\n\
             --extra-index-url https://evil.example/simple\n\
             https://evil.example/wheels/first.whl\n\
             -r shared/base.txt\n\
             --require-hashes\n",
        );
        // An inline comment is stripped, but the `#` of a `#egg=` fragment (no
        // preceding space) is not — that one names the package.
        assert!(
            specs
                .iter()
                .any(|s| s.name == "requests" && s.source == DepSource::Registry),
            "{specs:?}"
        );
        // Options that carry no dependency are still skipped.
        assert!(
            specs.iter().all(|s| !s.name.contains("base.txt")),
            "a -r include names no package of its own: {specs:?}"
        );
        assert!(
            specs
                .iter()
                .any(|s| s.name == "evil-editable" && matches!(s.source, DepSource::Git(_))),
            "-e git+… must be a git-sourced dependency: {specs:?}"
        );
        assert!(
            specs
                .iter()
                .any(|s| s.name.contains("evil.example/simple") && s.source != DepSource::Registry),
            "--extra-index-url must be visible as a non-registry source: {specs:?}"
        );
        assert!(
            specs
                .iter()
                .any(|s| s.name.contains("evil.example/wheels/first.whl")),
            "a bare direct-reference URL must not collapse to the name `https`: {specs:?}"
        );
        assert!(
            specs.iter().all(|s| s.name != "https"),
            "every URL line collapsing to `https` made them one interchangeable \
             trust unit: {specs:?}"
        );
    }

    /// A name outside ASCII was dropped on the floor — `python_req_name`
    /// returned `None` and the whole line vanished from the gate's view. Whether
    /// such a name can resolve anywhere is a separate question; a manifest line
    /// the gate cannot see is a blind spot either way.
    #[test]
    fn a_non_ascii_package_name_is_surfaced_not_silently_dropped() {
        // Cyrillic 'г' (U+0433) in place of Latin 'r'.
        let specs = python_specs("\u{0433}equests==2.31.0\n");
        assert_eq!(
            specs.len(),
            1,
            "a homoglyph name must still be a visible dependency: {specs:?}"
        );
        assert_eq!(specs.iter().next().unwrap().name, "\u{0433}equests");
    }

    /// The gate itself, not just the parser: both bypasses have to change the
    /// staged-vs-HEAD verdict.
    #[test]
    fn the_commit_gate_sees_target_specific_and_patched_cargo_dependencies() {
        // (a) a platform-gated new dependency
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        stage(&ctx, "Cargo.toml");
        exec::git_raw(&["commit", "-m", "base", "--no-verify"], &ctx.root).unwrap();
        write_file(
            &ctx,
            "Cargo.toml",
            "[dependencies]\nserde = \"1\"\n[target.'cfg(unix)'.dependencies]\nsneaky = \"1\"\n",
        );
        stage(&ctx, "Cargo.toml");
        let flagged = new_unapproved_deps(&ctx).unwrap();
        assert!(
            flagged.iter().any(|d| d.qualified == "cargo:sneaky"),
            "a target-gated new dependency must reach the gate: {flagged:?}"
        );

        // (b) an APPROVED name whose code is swapped by [patch.crates-io]
        let (_d, ctx) = repo_ctx();
        write_file(&ctx, "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        stage(&ctx, "Cargo.toml");
        exec::git_raw(&["commit", "-m", "base", "--no-verify"], &ctx.root).unwrap();
        approve_package(&ctx, "cargo:serde").unwrap();
        assert!(unapproved_new_packages(&ctx).unwrap().is_empty());

        write_file(
            &ctx,
            "Cargo.toml",
            "[dependencies]\nserde = \"1\"\n\
             [patch.crates-io]\nserde = { git = \"https://evil.example/serde\" }\n",
        );
        stage(&ctx, "Cargo.toml");
        let flagged = new_unapproved_deps(&ctx).unwrap();
        assert!(
            flagged.iter().any(|d| d.qualified == "cargo:serde"
                && matches!(d.reason, NewDepReason::NonRegistrySource(_))),
            "patching an approved crate to a git URL must be flagged: {flagged:?}"
        );
    }
    // ─────────── R1: `deps check` must consult the source, not the name ───────

    /// A `path` dependency's code comes from disk, never from the public
    /// registry. Resolving its NAME there answered a question nobody asked and
    /// got both possible answers wrong: an in-repo crate was reported as
    /// "exists on registry" purely on a name collision with an unrelated public
    /// crate, and a perfectly ordinary sibling-repo path dep was reported as a
    /// slopsquatting target at exit 1.
    ///
    /// Note the `offline = false` argument: post-fix this test makes no network
    /// call at all, because a non-registry source is never resolved by name.
    /// Pre-fix it did, and every arm of that match — Exists, NotFound, Unknown —
    /// pushed one of the strings asserted absent below, so the test fails
    /// regardless of connectivity.
    #[test]
    fn deps_check_never_resolves_a_non_registry_dependency_by_name_on_the_public_registry() {
        let (_d, ctx) = repo_ctx();
        write_file(
            &ctx,
            "Cargo.toml",
            "[dependencies]\n\
             serde = { path = \"vendor/serde\" }\n\
             sibling-crate = { path = \"../outside/sibling-crate\" }\n",
        );
        let (problems, notes) = deps_check(&ctx, false).unwrap();

        assert!(
            !notes.iter().any(|n| n.contains("exists on registry")),
            "a path dependency must never be VALIDATED by a same-named public \
             crate: {notes:?}"
        );
        assert!(
            !problems.iter().any(|p| p.contains("NOT FOUND")),
            "a sibling-repo path dependency is a normal multi-repo layout, not a \
             slopsquatting target: {problems:?}"
        );
        assert!(
            !notes
                .iter()
                .any(|n| n.contains("registry check inconclusive")),
            "no registry lookup should have been attempted at all: {notes:?}"
        );
        assert!(
            problems.is_empty(),
            "a repo whose only deps are path deps must exit clean: {problems:?}"
        );
        assert!(
            notes.iter().any(|n| n.contains("sibling-crate"))
                && notes.iter().any(|n| n.contains("path source")),
            "the user still has to be told WHY the name was not checked: {notes:?}"
        );
    }

    /// `path_resolves_within_repo` walked path components lexically with no
    /// `canonicalize`, so `path = "link/pkg"` where `link` is a symlink out of
    /// the repo counted as the repo's own reviewed code and was exempted.
    #[cfg(unix)]
    #[test]
    fn a_path_dependency_through_a_symlink_that_escapes_the_repo_is_not_exempt() {
        use std::os::unix::fs::symlink;
        let (_d, ctx) = repo_ctx();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("pkg")).unwrap();
        std::fs::write(
            outside.path().join("pkg/Cargo.toml"),
            "[package]\nname = \"pkg\"\n",
        )
        .unwrap();
        symlink(outside.path(), ctx.root.join("link")).unwrap();

        write_file(&ctx, "Cargo.toml", "[package]\nname = \"root\"\n");
        stage(&ctx, "Cargo.toml");
        exec::git_raw(&["commit", "-m", "base", "--no-verify"], &ctx.root).unwrap();

        write_file(
            &ctx,
            "Cargo.toml",
            "[package]\nname = \"root\"\n[dependencies]\npkg = { path = \"link/pkg\" }\n",
        );
        stage(&ctx, "Cargo.toml");
        let flagged = new_unapproved_deps(&ctx).unwrap();
        assert!(
            flagged.iter().any(|d| d.qualified == "cargo:pkg"
                && matches!(d.reason, NewDepReason::NonRegistrySource(_))),
            "a path that only LOOKS in-tree must not be exempted: {flagged:?}"
        );
    }
}
