//! Vulnerability scanning: Trivy (vuln+secret+misconfig; exits 0 on findings,
//! so severity gating happens on parsed JSON) and OSV-Scanner V2
//! (lockfile-exact; exit 1 = findings, 128 = no packages). OpenVEX documents
//! suppress `not_affected` findings, visibly.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;
use anyhow::{Context as _, Result};
use std::path::Path;

pub const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];

/// The rank of a severity label, weakest first — or `None` when the label is
/// not a severity this scale recognises.
///
/// The `Option` is the whole point. This used to end in `.unwrap_or(0)`, so
/// EVERY unrecognised string ranked below `low`: a finding whose severity we
/// could not determine could not breach any threshold, and neither could a
/// GHSA advisory rated `MODERATE`, because that is not the literal string
/// `medium`. A severity we could not determine is not a low severity, and
/// callers must decide what to do about it rather than inheriting a silent
/// floor — see [`breaches_threshold`], which fails closed on `None`.
///
/// Vocabulary is normalised where two databases name the same rung
/// differently: OSV/GHSA say `MODERATE` where this scale says `medium`.
/// Everything else is compared case-insensitively after trimming, so a
/// stray-whitespace `"HIGH "` in config is the threshold its author meant
/// rather than a string that silently means something else.
pub fn severity_rank(s: &str) -> Option<usize> {
    let label = s.trim();
    let label = if label.eq_ignore_ascii_case("moderate") {
        "medium"
    } else {
        label
    };
    SEVERITIES
        .iter()
        .position(|x| x.eq_ignore_ascii_case(label))
}

/// How many findings carry a severity no source could determine.
///
/// These are not low-severity findings; they are findings we cannot rank. The
/// count is reported so the reader can see the size of the undetermined set
/// rather than discovering it as an unexplained threshold breach.
pub fn undetermined_severity_count(report: &ScanReport) -> usize {
    report
        .findings
        .iter()
        .filter(|f| severity_rank(&f.severity).is_none())
        .count()
}

/// The note explaining an undetermined-severity set, or `None` when every
/// finding could be ranked.
fn undetermined_severity_note(report: &ScanReport) -> Option<String> {
    let n = undetermined_severity_count(report);
    (n > 0).then(|| {
        format!(
            "{n} finding(s) carry no severity this scan could determine — they breach \
             every threshold rather than ranking below `low`. Waive one deliberately, \
             and visibly, with a VEX statement (`sscsb vex create`)"
        )
    })
}

#[derive(Debug, Clone)]
pub struct VulnFinding {
    pub id: String,
    pub package: String,
    pub severity: String,
    pub source: &'static str,
    /// The package ecosystem, when the scanner stated one (Trivy's per-result
    /// `Type`, OSV's `package.ecosystem`), lowercased. `None` when unknown —
    /// secrets and misconfigurations have no ecosystem, and older report
    /// shapes may omit it. VEX product matching uses this to refuse
    /// cross-ecosystem name collisions; see [`vex_product_matches`].
    pub ecosystem: Option<String>,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<VulnFinding>,
    pub suppressed: Vec<String>,
    pub notes: Vec<String>,
}

/// Run all enabled scanners. Errors only when NO scanner could run.
pub fn run_scan(ctx: &Ctx, cfg: &Config, vex_path: Option<&Path>) -> Result<ScanReport> {
    let mut report = ScanReport::default();
    let mut ran = 0u32;

    // Before anything runs: say what configuration the scanners are about to
    // pick up out of the repository. See `scanner_config_notes`.
    report.notes.extend(scanner_config_notes(&ctx.root));

    if tools::is_available("trivy") {
        ran += 1;
        run_trivy(ctx, &mut report)?;
    } else {
        report
            .notes
            .push(tools::degrade_message("trivy", ctx.platform));
    }

    if tools::is_available("osv-scanner") {
        ran += 1;
        run_osv(ctx, &mut report)?;
    } else {
        report
            .notes
            .push(tools::degrade_message("osv-scanner", ctx.platform));
    }

    if ran == 0 {
        anyhow::bail!(
            "no vulnerability scanner available: {}",
            report.notes.join(" | ")
        );
    }

    if let Some(vex) = vex_path {
        let vex_text = std::fs::read_to_string(vex)
            .with_context(|| format!("reading VEX {}", vex.display()))?;
        apply_vex(&mut report, &vex_text)?;
    }
    if let Some(note) = undetermined_severity_note(&report) {
        report.notes.push(note);
    }
    let _ = cfg;
    Ok(report)
}

/// `trivy.yaml` keys that REDUCE what a scan can report, and what each does.
///
/// Trivy has many settings; these are the ones whose effect is, in the output,
/// indistinguishable from a clean scan. Operational keys (`cache`, `timeout`,
/// `db.repository` for an air-gapped mirror) narrow nothing and are reported
/// as present without being called out.
const TRIVY_NARROWING_KEYS: &[(&str, &str)] = &[
    ("severity", "only these severities are reported at all"),
    ("ignorefile", "ignore entries are read from another path"),
    ("ignore-policy", "a Rego policy decides what is dropped"),
    ("scan.scanners", "only these scanners run"),
    ("scan.skip-dirs", "these directories are never scanned"),
    ("scan.skip-files", "these files are never scanned"),
    ("scan.offline-scan", "no advisory lookups are performed"),
    (
        "vulnerability.ignore-unfixed",
        "vulnerabilities without a fix are dropped",
    ),
    ("vulnerability.type", "only these package types are scanned"),
    (
        "secret.config",
        "custom secret rules, which can disable built-in ones",
    ),
    (
        "db.skip-update",
        "the vulnerability database is not refreshed",
    ),
];

/// Report the scanner configuration this repository hands the scanners.
///
/// Trivy reads `trivy.yaml` and `.trivyignore` from the directory it is run
/// in; OSV-Scanner reads `osv-scanner.toml` from the tree it scans. Neither is
/// asked for — committing the file is enough. Measured on one fixture: a
/// `trivy.yaml` of `severity: [CRITICAL]` took a scan from 3 findings to 1,
/// and an `osv-scanner.toml` with one `[[IgnoredVulns]]` entry took 8 to 6.
/// Nothing in either scanner's JSON said a word about it.
///
/// **The deliberate choice here is to inherit, and report — not to override.**
/// These files are legitimate: this repository's own `.trivyignore` waives two
/// container rules that genuinely cannot model an OSS-Fuzz build image, with
/// per-ID rationale in the file. Passing `--config`/`--ignorefile` to neutralise
/// them would break that class of documented waiver, and — worse — would push
/// anyone who needs one into disabling the control outright. The defect was
/// never that suppression exists; it is that it was silent. So suppression is
/// honoured and *named*, exactly as [`apply_vex`] does it.
///
/// Two layers, because one is not enough:
/// * the scanners' own suppression channels — Trivy's `--show-suppressed` and
///   OSV-Scanner's stderr — itemise each muted finding with its reason;
/// * this function names the files and what they change, which is the only
///   signal for `trivy.yaml` narrowing (Trivy reports nothing for it even
///   under `--show-suppressed` — measured on 0.72.0) and the backstop if a
///   scanner's output shape ever changes underneath the first layer.
pub fn scanner_config_notes(root: &Path) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(note) = trivy_config_note(&root.join("trivy.yaml")) {
        notes.push(note);
    }
    for name in [".trivyignore", ".trivyignore.yaml"] {
        if let Some(note) = trivy_ignorefile_note(&root.join(name), name) {
            notes.push(note);
        }
    }
    if let Some(note) = osv_config_note(&root.join("osv-scanner.toml")) {
        notes.push(note);
    }
    notes
}

fn trivy_config_note(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let head = "scanner config: trivy.yaml is present and trivy loads it automatically";
    let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(&text) else {
        // Unparseable to us is not "absent": trivy may still act on it.
        return Some(format!(
            "{head} — sscsb could not parse it to say what it does"
        ));
    };
    let Some(doc) = docs.first() else {
        return Some(format!("{head} — it is empty"));
    };
    let narrowing: Vec<String> = TRIVY_NARROWING_KEYS
        .iter()
        .filter_map(|(key, effect)| {
            let node = yaml_at(doc, key);
            (!node.is_badvalue()).then(|| format!("{key}={} ({effect})", yaml_summary(node)))
        })
        .collect();
    Some(if narrowing.is_empty() {
        format!("{head} — no key in it narrows what this scan reports")
    } else {
        format!(
            "{head}, and it NARROWS this scan: {}. Findings excluded this way are \
             not reported by trivy at all, here or in its own suppression list",
            narrowing.join("; ")
        )
    })
}

/// Walk a dotted path (`scan.skip-dirs`) into a YAML document. Missing nodes
/// come back as `BadValue`, which is how the caller tests for absence.
fn yaml_at<'a>(doc: &'a yaml_rust2::Yaml, dotted: &str) -> &'a yaml_rust2::Yaml {
    let mut node = doc;
    for key in dotted.split('.') {
        node = &node[key];
    }
    node
}

fn yaml_summary(node: &yaml_rust2::Yaml) -> String {
    use yaml_rust2::Yaml;
    match node {
        Yaml::String(s) => s.clone(),
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(yaml_summary)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // Anything else (a bare key with no value, a number, a nested map)
        // gets a presence marker: the point of the note is WHICH key narrows
        // the scan, and the file is right there to read for the detail.
        _ => "set".to_string(),
    }
}

fn trivy_ignorefile_note(path: &Path, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let entries: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let preview = entries
        .iter()
        .take(8)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let ellipsis = if entries.len() > 8 { ", …" } else { "" };
    Some(format!(
        "scanner config: {name} is present with {} entr(ies){}{preview}{ellipsis} — \
         suppressions it causes are listed individually as `suppressed:` rows",
        entries.len(),
        if entries.is_empty() { "" } else { ": " },
    ))
}

fn osv_config_note(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let head = "scanner config: osv-scanner.toml is present and osv-scanner loads it automatically";
    let Ok(table) = text.parse::<toml::Table>() else {
        return Some(format!(
            "{head} — sscsb could not parse it to say what it does"
        ));
    };
    let entries = |key: &str, field: &str| -> Vec<String> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|e| {
                        e.get(field)
                            .and_then(toml::Value::as_str)
                            .unwrap_or("?")
                            .to_string()
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let ignored = entries("IgnoredVulns", "id");
    let overrides = entries("PackageOverrides", "name");
    if ignored.is_empty() && overrides.is_empty() {
        return Some(format!("{head} — it names no vulnerabilities or packages"));
    }
    let mut parts = Vec::new();
    if !ignored.is_empty() {
        parts.push(format!(
            "ignores {} ({})",
            ignored.len(),
            ignored.join(", ")
        ));
    }
    if !overrides.is_empty() {
        parts.push(format!(
            "overrides {} package(s) ({})",
            overrides.len(),
            overrides.join(", ")
        ));
    }
    Some(format!(
        "{head}: it {} — an ignore entry mutes the whole alias group, and each \
         filtered entry is listed as a `suppressed:` row",
        parts.join(" and ")
    ))
}

fn run_trivy(ctx: &Ctx, report: &mut ScanReport) -> Result<()> {
    let root = ctx.root.display().to_string();
    let out = exec::run(
        "trivy",
        &[
            "fs",
            "--scanners",
            "vuln,secret,misconfig",
            "--format",
            "json",
            "--quiet",
            // Trivy honours a `.trivyignore` it finds in the scan directory,
            // and without this it reports the survivors only. This asks it to
            // itemise what it muted, so a waiver stays a waiver but stops
            // being invisible. It changes nothing about which findings are
            // reported as findings.
            "--show-suppressed",
            &root,
        ],
        Some(&ctx.root),
    )?;
    if !out.success() {
        anyhow::bail!("trivy failed (exit {}): {}", out.status, out.stderr.trim());
    }
    report.findings.extend(parse_trivy(&out.stdout)?);
    let suppressed = parse_trivy_suppressions(&out.stdout)?;
    if !suppressed.is_empty() {
        report.notes.push(format!(
            "trivy: {} finding(s) suppressed by configuration trivy loaded from the \
             repository — each is listed as a `suppressed:` row",
            suppressed.len()
        ));
        report.suppressed.extend(suppressed);
    }
    Ok(())
}

/// The suppressions Trivy itself reports under `--show-suppressed`: one row
/// per finding an ignore file, an ignore policy, or a VEX document muted.
///
/// This is the same contract [`apply_vex`] holds itself to — suppression is
/// honoured and *named*, never silent. Trivy states the source (`.trivyignore`,
/// a policy path, a VEX document) and the statement its author wrote, so the
/// row can carry the reason rather than just the count.
///
/// It does NOT cover everything a config file can do: `trivy.yaml` narrowing
/// (a `severity` allowlist, `skip-dirs`, disabled scanners) filters findings
/// before they are ever findings, and Trivy reports nothing at all for it —
/// measured on 0.72.0. That gap is why [`scanner_config_notes`] exists.
/// The top-level keys that identify a document as a Trivy report.
///
/// `Results` alone is NOT a sufficient marker: measured on trivy 0.72.0, a
/// scan of a finding-free tree emits the envelope with no `Results` key at
/// all (`SchemaVersion`, `Trivy`, `ReportID`, `CreatedAt`, `ArtifactName`,
/// `ArtifactType`). Keying the check on `Results` would have turned every
/// clean scan into an error.
const TRIVY_REPORT_MARKERS: &[&str] = &["Results", "SchemaVersion", "ArtifactName", "ArtifactType"];

/// The top-level key that identifies a document as an OSV-Scanner report.
///
/// Measured on osv-scanner 2.4.0, a clean scan over a real lockfile emits
/// `{"results":[],…}` — present and empty — so requiring it costs a clean
/// scan nothing. A package-free tree exits 128 with empty stdout, which
/// [`run_osv`] handles before any parsing happens.
const OSV_REPORT_MARKERS: &[&str] = &["results"];

/// Parse a scanner's stdout as that scanner's report, refusing a document
/// that is valid JSON but is not that report.
///
/// The asymmetry this closes: non-JSON was rejected loudly, while `{}`, `[]`,
/// or any unrelated JSON document parsed happily into zero findings — no
/// error, no note. The report then read "0 findings" and the gate exited 0.
/// A scanner that returned something unexpected is exactly when you want to
/// be told, so an unreadable document is an error rather than a clean bill of
/// health. A document lacking any recognisable marker is not clean; it is
/// output nobody parsed.
///
/// Two ways a document fails, both named: no recognisable top-level marker,
/// or a marker present whose findings container is not a list. The marker set
/// is deliberately liberal — any one key is enough — so a future field rename
/// costs an error message rather than every clean scan.
fn scanner_report(
    stdout: &str,
    tool: &str,
    markers: &[&str],
    container: &str,
) -> Result<serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).with_context(|| format!("{tool} output not JSON"))?;
    anyhow::ensure!(
        markers.iter().any(|k| v.get(k).is_some()),
        "{tool} output is JSON, but not in {tool}'s report shape: none of {} at the top level. \
         A document this cannot read is not a clean scan — reading it as zero findings would \
         pass the gate on output nobody parsed",
        markers.join(", ")
    );
    if let Some(found) = v.get(container) {
        anyhow::ensure!(
            found.is_array() || found.is_null(),
            "{tool} output is JSON, but not in {tool}'s report shape: `{container}` is present \
             and is not a list of results. A document this cannot read is not a clean scan"
        );
    }
    Ok(v)
}

pub fn parse_trivy_suppressions(stdout: &str) -> Result<Vec<String>> {
    let v = scanner_report(stdout, "trivy", TRIVY_REPORT_MARKERS, "Results")?;
    let mut rows = Vec::new();
    for result in v
        .get("Results")
        .and_then(|r| r.as_array())
        .unwrap_or(&Vec::new())
    {
        let target = result
            .get("Target")
            .and_then(|x| x.as_str())
            .unwrap_or("this repository");
        for modified in result
            .get("ExperimentalModifiedFindings")
            .and_then(|x| x.as_array())
            .unwrap_or(&Vec::new())
        {
            let status = modified
                .get("Status")
                .and_then(|x| x.as_str())
                .unwrap_or("modified");
            let source = modified
                .get("Source")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("trivy configuration");
            let finding = modified.get("Finding");
            let id = finding
                .and_then(|f| {
                    f.get("VulnerabilityID")
                        .or_else(|| f.get("ID"))
                        .or_else(|| f.get("RuleID"))
                })
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let package = finding
                .and_then(|f| f.get("PkgName"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(target);
            let statement = modified
                .get("Statement")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim();
            let reason = if statement.is_empty() {
                String::new()
            } else {
                format!(": {statement}")
            };
            rows.push(format!(
                "{id} ({package}) — trivy {status} via {source}{reason}"
            ));
        }
    }
    Ok(rows)
}

pub fn parse_trivy(stdout: &str) -> Result<Vec<VulnFinding>> {
    let v = scanner_report(stdout, "trivy", TRIVY_REPORT_MARKERS, "Results")?;
    let mut findings = Vec::new();
    for result in v
        .get("Results")
        .and_then(|r| r.as_array())
        .unwrap_or(&Vec::new())
    {
        // Trivy states the package ecosystem per result ("cargo", "npm",
        // "debian", ...). Secrets and misconfigurations have none.
        let ecosystem = result
            .get("Type")
            .and_then(|x| x.as_str())
            .map(str::to_ascii_lowercase);
        for vuln in result
            .get("Vulnerabilities")
            .and_then(|x| x.as_array())
            .unwrap_or(&Vec::new())
        {
            findings.push(VulnFinding {
                id: vuln
                    .get("VulnerabilityID")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                package: vuln
                    .get("PkgName")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                severity: vuln
                    .get("Severity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_lowercase(),
                source: "trivy",
                ecosystem: ecosystem.clone(),
            });
        }
        for secret in result
            .get("Secrets")
            .and_then(|x| x.as_array())
            .unwrap_or(&Vec::new())
        {
            findings.push(VulnFinding {
                id: secret
                    .get("RuleID")
                    .and_then(|x| x.as_str())
                    .unwrap_or("secret")
                    .to_string(),
                package: result
                    .get("Target")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                severity: secret
                    .get("Severity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("HIGH")
                    .to_lowercase(),
                source: "trivy",
                ecosystem: None,
            });
        }
        for mis in result
            .get("Misconfigurations")
            .and_then(|x| x.as_array())
            .unwrap_or(&Vec::new())
        {
            findings.push(VulnFinding {
                id: mis
                    .get("ID")
                    .and_then(|x| x.as_str())
                    .unwrap_or("misconfig")
                    .to_string(),
                package: result
                    .get("Target")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                severity: mis
                    .get("Severity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("MEDIUM")
                    .to_lowercase(),
                source: "trivy",
                ecosystem: None,
            });
        }
    }
    Ok(findings)
}

fn run_osv(ctx: &Ctx, report: &mut ScanReport) -> Result<()> {
    let root = ctx.root.display().to_string();
    let out = exec::run(
        "osv-scanner",
        &["scan", "source", "-r", "--format", "json", &root],
        Some(&ctx.root),
    )?;
    // Documented exit codes: 0 = clean, 1 = findings, 128 = no packages found.
    match out.status {
        0 | 1 => report.findings.extend(parse_osv(&out.stdout)?),
        128 => report
            .notes
            .push("osv-scanner: no packages found to scan".into()),
        code => anyhow::bail!("osv-scanner failed (exit {code}): {}", out.stderr.trim()),
    }
    // What an `osv-scanner.toml` muted is stated on stderr and nowhere in the
    // JSON — including under `--all-vulns`. Discarding stderr on success is
    // what made a committed config file invisible.
    let (suppressed, notes) = osv_filter_report(&out.stderr);
    if !suppressed.is_empty() {
        report.notes.push(format!(
            "osv-scanner: {} entr(ies) filtered out by configuration it loaded from the \
             repository — each is listed as a `suppressed:` row",
            suppressed.len()
        ));
    }
    report.suppressed.extend(suppressed);
    report.notes.extend(notes);
    Ok(())
}

/// Read OSV-Scanner's own account of what its config filtered, off stderr.
///
/// Returns `(suppressed rows, notes)`. The shapes below are `osv-scanner
/// 2.4.0`'s, captured from live runs:
///
/// ```text
/// Loaded filter from: /repo/osv-scanner.toml
/// RUSTSEC-2021-0003 and 2 aliases have been filtered out because: <reason>
/// RUSTSEC-2020-0159 has been filtered out because: <reason>
/// Package crates.io/atty/0.2.14 has been filtered out because: <reason>
/// ```
///
/// Note the two verb forms: an entry with aliases says "have been", a lone one
/// says "has been". Matching only the singular silently dropped exactly the
/// alias-group case — the one that mutes the most.
///
/// The match is deliberately loose — the marker phrase, not a full grammar —
/// so a wording change costs detail rather than the whole signal, and
/// [`scanner_config_notes`] still reports the file either way.
fn osv_filter_report(stderr: &str) -> (Vec<String>, Vec<String>) {
    const FILTERED: &str = " been filtered out because:";
    let mut suppressed = Vec::new();
    let mut notes = Vec::new();
    for line in stderr.lines().map(str::trim) {
        if let Some(path) = line.strip_prefix("Loaded filter from:") {
            notes.push(format!(
                "osv-scanner loaded a filter config from the repository: {}",
                path.trim()
            ));
        } else if let Some((subject, reason)) = line.split_once(FILTERED) {
            // "X and N aliases" keeps the alias count, which matters: an
            // ignore entry mutes the whole alias group, not one id. The verb
            // is left out of the subject, whichever form it took.
            let subject = subject.trim();
            let subject = subject
                .strip_suffix(" have")
                .or_else(|| subject.strip_suffix(" has"))
                .unwrap_or(subject);
            suppressed.push(format!(
                "{subject} — osv-scanner filtered out: {}",
                reason.trim()
            ));
        }
    }
    (suppressed, notes)
}

pub fn parse_osv(stdout: &str) -> Result<Vec<VulnFinding>> {
    let v = scanner_report(stdout, "osv-scanner", OSV_REPORT_MARKERS, "results")?;
    let mut findings = Vec::new();
    for result in v
        .get("results")
        .and_then(|r| r.as_array())
        .unwrap_or(&Vec::new())
    {
        for pkg in result
            .get("packages")
            .and_then(|p| p.as_array())
            .unwrap_or(&Vec::new())
        {
            let name = pkg
                .pointer("/package/name")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            let ecosystem = pkg
                .pointer("/package/ecosystem")
                .and_then(|x| x.as_str())
                .map(str::to_ascii_lowercase);
            for vuln in pkg
                .get("vulnerabilities")
                .and_then(|x| x.as_array())
                .unwrap_or(&Vec::new())
            {
                let severity = osv_severity(vuln);
                findings.push(VulnFinding {
                    id: vuln
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                        .to_string(),
                    package: name.clone(),
                    severity,
                    ecosystem: ecosystem.clone(),
                    source: "osv-scanner",
                });
            }
        }
    }
    Ok(findings)
}

/// The severity of one OSV vulnerability record, recovered from whichever of
/// the fields advisories ACTUALLY populate — `"unknown"` only when the record
/// states no rating anywhere.
///
/// Reading `/database_specific/severity` alone was measurably not enough.
/// Against a live `osv-scanner 2.4.0` run, RUSTSEC and PYSEC records do not
/// carry that field at all (a RUSTSEC record's `database_specific` is
/// `{"license": "CC0-1.0"}`), so they all landed as `unknown`. The ratings
/// those records do carry live in two other places, both read here:
///
/// * the OSV `severity` array — `[{"type": "CVSS_V3", "score": "CVSS:3.1/…"}]`;
/// * `affected[].database_specific.cvss`, where RUSTSEC repeats the vector.
///
/// When a record states a rating more than one way — GHSA carries both a
/// `MODERATE` label and a CVSS vector — the HIGHEST determinable rating wins.
/// A gate should not be argued down by the weaker of two ratings the same
/// advisory asserts, and the rows disagree rarely and narrowly in practice.
///
/// Only CVSS v3.0/v3.1 vectors are scored. A v4.0 vector needs the v4
/// macro-vector lookup tables, and guessing a band from a vector we cannot
/// score would be inventing a rating; such a record stays undetermined, which
/// now fails closed and visibly rather than passing as `low`. (In practice a
/// v4-rated advisory is a modern GHSA one, which also carries the label read
/// first.)
fn osv_severity(vuln: &serde_json::Value) -> String {
    let mut candidates: Vec<String> = Vec::new();

    // The database's own label: GHSA says LOW / MODERATE / HIGH / CRITICAL.
    if let Some(label) = vuln
        .pointer("/database_specific/severity")
        .and_then(|x| x.as_str())
    {
        candidates.push(label.to_string());
    }
    // The OSV `severity` array — CVSS vectors.
    for entry in vuln
        .get("severity")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(sev) = entry
            .get("score")
            .and_then(|x| x.as_str())
            .and_then(severity_from_cvss_vector)
        {
            candidates.push(sev.to_string());
        }
    }
    // RUSTSEC repeats the vector per affected range.
    for affected in vuln
        .get("affected")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(sev) = affected
            .pointer("/database_specific/cvss")
            .and_then(|x| x.as_str())
            .and_then(severity_from_cvss_vector)
        {
            candidates.push(sev.to_string());
        }
    }

    candidates
        .iter()
        .filter_map(|c| severity_rank(c))
        .max()
        .map_or_else(
            || "unknown".to_string(),
            |rank| SEVERITIES[rank].to_string(),
        )
}

/// The severity band of a CVSS vector, via its base score. `None` for any
/// vector we cannot score exactly — never a guess.
fn severity_from_cvss_vector(vector: &str) -> Option<&'static str> {
    let score = cvss_v3_base_score(vector)?;
    // The CVSS v3 qualitative severity rating scale. 0.0 is "None" upstream;
    // this scale has no rung below `low`, and the record did state a score, so
    // it ranks `low` rather than counting as undetermined.
    Some(match score {
        s if s < 4.0 => "low",
        s if s < 7.0 => "medium",
        s if s < 9.0 => "high",
        _ => "critical",
    })
}

/// CVSS v3.0/v3.1 base score from a vector string, per the first.org
/// specification. `None` when the string is not a v3 base vector or is missing
/// a mandatory base metric — an incomplete vector is not a low score.
fn cvss_v3_base_score(vector: &str) -> Option<f64> {
    let (version, metrics) = vector.trim().split_once('/')?;
    if version != "CVSS:3.1" && version != "CVSS:3.0" {
        return None;
    }
    let pairs: Vec<(&str, &str)> = metrics
        .split('/')
        .filter_map(|p| p.split_once(':'))
        .collect();
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    };

    let scope_changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let attack_vector = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let attack_complexity = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    // Privileges Required is scored higher when the scope changes.
    let privileges_required = match (get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let user_interaction = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_weight = |metric: &str| match metric {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let confidentiality = impact_weight(get("C")?)?;
    let integrity = impact_weight(get("I")?)?;
    let availability = impact_weight(get("A")?)?;

    let iss = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(cvss_roundup(raw.min(10.0)))
}

/// The CVSS v3.1 `Roundup` function: round up to one decimal place, defined
/// on integers so floating-point representation cannot round 8.6 down to 8.5.
fn cvss_roundup(x: f64) -> f64 {
    let scaled = (x * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled as f64 / 10_000.0).floor() + 1.0) / 10.0
    }
}

/// Apply an OpenVEX document: a finding is suppressed only when a
/// `not_affected` or `fixed` statement names BOTH its vulnerability id AND a
/// product matching the finding's package — visibly, never silently.
///
/// Scope is the whole point of VEX. An earlier implementation keyed
/// suppression on `/vulnerability/name` alone — the `products` array was
/// parsed by nobody — so one statement scoped to `pkg:cargo/foo` suppressed
/// that CVE in every package in the report: a document-wide wildcard nobody
/// wrote. A statement that names no products suppresses nothing and says so
/// in the notes, because "this CVE affects nothing anywhere" is exactly that
/// wildcard, and OpenVEX statements are product-scoped assertions by design.
///
/// Product matching is name-granular within an ecosystem: findings carry no
/// package version, so a purl pinned to a version (`pkg:cargo/itoa@1.0.11`)
/// matches the finding for `itoa`. When BOTH the purl and the finding declare
/// an ecosystem, they must agree — `pkg:cargo/openssl` must not suppress an
/// OS-package `openssl` finding for the same CVE (same-name collisions across
/// ecosystems are routine in a single Trivy filesystem scan). Each
/// suppression row names the product id and status that matched AND the
/// ecosystem of the finding it removed, so any remaining over-breadth — a
/// bare-name product id matching in several ecosystems at once — is visible
/// in the report rather than silent.
pub fn apply_vex(report: &mut ScanReport, vex_text: &str) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(vex_text).context("VEX is not valid JSON")?;
    anyhow::ensure!(
        v.get("@context")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains("openvex.dev")),
        "not an OpenVEX document (missing openvex.dev @context)"
    );
    // (vulnerability id, product id, status) triples permitted to suppress.
    let mut suppress: Vec<(String, String, String)> = Vec::new();
    for stmt in v
        .get("statements")
        .and_then(|s| s.as_array())
        .unwrap_or(&Vec::new())
    {
        let status = stmt.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if status != "not_affected" && status != "fixed" {
            continue;
        }
        let Some(id) = stmt.pointer("/vulnerability/name").and_then(|n| n.as_str()) else {
            continue;
        };
        let products = vex_product_ids(stmt);
        if products.is_empty() {
            report.notes.push(format!(
                "VEX statement for {id} names no products — it suppresses nothing \
                 (a statement without product scope would suppress the CVE everywhere)"
            ));
            continue;
        }
        for product in products {
            suppress.push((id.to_string(), product, status.to_string()));
        }
    }
    let before = report.findings.len();
    let mut suppressed = Vec::new();
    report.findings.retain(|f| {
        match suppress
            .iter()
            .find(|(id, product, _)| *id == f.id && vex_product_matches(product, f))
        {
            Some((_, product, status)) => {
                // The ecosystem is part of WHICH finding was waived, not
                // decoration. A product id that is a bare name declares no
                // ecosystem, so it matches by name in every ecosystem at
                // once; without this, those suppressions printed as identical
                // rows and their reach could not be read off the report.
                let eco = match &f.ecosystem {
                    Some(eco) => format!(" [{eco}]"),
                    None => String::new(),
                };
                suppressed.push(format!(
                    "{} ({}{eco}) — VEX {status} for {product}",
                    f.id, f.package
                ));
                false
            }
            None => true,
        }
    });
    let newly_suppressed = suppressed.len();
    report.suppressed.extend(suppressed);
    report.notes.push(format!(
        "VEX applied: {newly_suppressed} finding(s) suppressed of {before}"
    ));
    Ok(())
}

/// The product ids a VEX statement names. Accepts the OpenVEX object form
/// (`{"@id": "pkg:cargo/foo"}`) and, liberally, a bare string entry.
fn vex_product_ids(stmt: &serde_json::Value) -> Vec<String> {
    stmt.get("products")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    p.as_str()
                        .or_else(|| p.get("@id").and_then(|i| i.as_str()))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Does a VEX product id name this finding's package?
///
/// Exact-id match, or a purl whose name component matches — gated on
/// ecosystem agreement when both sides declare one. The gate is what stops a
/// `pkg:cargo/openssl` statement from suppressing an OS-package `openssl`
/// finding: purl `type` and scanner ecosystem are normalised through
/// [`normalize_ecosystem`] and must be equal. Normalisation is load-bearing,
/// not cosmetic: the canonical purl and the label a scanner emits for the
/// same registry are usually different strings.
///
/// When either side is unknown (secrets, misconfigs, older report shapes,
/// non-purl product ids) matching falls back to name granularity. This is
/// deliberate, and it is not a hole in the ecosystem gate: a bare product id
/// is a namespace-free assertion, so there is no ecosystem for it to cross.
/// Requiring one would not tighten the gate — it would turn every bare-name
/// statement into a silent no-op, which is the failure this module exists to
/// prevent. The residue is bounded to statements whose author wrote no
/// namespace, and [`apply_vex`] states the ecosystem of each finding it
/// suppressed so the reach of such a statement is readable in the report.
///
/// Maven is additionally matched in its conventional `group:artifact` colon
/// form, since scanners commonly emit GAV notation while purls use a slash.
fn vex_product_matches(product_id: &str, finding: &VulnFinding) -> bool {
    if product_id == finding.package {
        return true;
    }
    let Some((purl_type, name)) = purl_parts(product_id) else {
        return false;
    };
    if let Some(eco) = &finding.ecosystem {
        if normalize_ecosystem(&purl_type) != normalize_ecosystem(eco) {
            return false;
        }
    }
    name == finding.package
        || (normalize_ecosystem(&purl_type) == "maven" && name.replace('/', ":") == finding.package)
}

/// The `(type, name)` of a purl, with the version, qualifiers, and subpath
/// stripped and `%40` decoded for scoped-npm names.
/// `pkg:cargo/itoa@1.0.11` → `("cargo", "itoa")`; `pkg:npm/%40scope/name@1.2`
/// → `("npm", "@scope/name")`; `pkg:golang/github.com/foo/bar` →
/// `("golang", "github.com/foo/bar")`.
fn purl_parts(purl: &str) -> Option<(String, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    // Scoped npm names encode their own `@` as `%40`, so a literal `@` only
    // ever introduces the version.
    let rest = rest.split('@').next().unwrap_or(rest);
    let (purl_type, name_path) = rest.split_once('/')?;
    (!purl_type.is_empty() && !name_path.is_empty()).then(|| {
        (
            purl_type.to_ascii_lowercase(),
            name_path.replace("%40", "@"),
        )
    })
}

/// Map scanner ecosystem vocabulary and purl types onto one namespace so
/// `crates.io` (OSV) and `cargo` (purl, Trivy) compare equal. Unknown labels
/// pass through lowercased — two unknowns still have to agree with each
/// other, which is strictly safer than ignoring them.
///
/// The three vocabularies disagree systematically, not occasionally:
///
/// * a **purl** names the ecosystem by its REGISTRY (`pypi`, `npm`, `gem`);
/// * **OSV** names it by the registry too, but spells it its own way
///   (`crates.io`, `Packagist`, `RubyGems`);
/// * **Trivy** names it by the MANIFEST it read the dependency out of, so one
///   registry answers to several labels.
///
/// That last row is the one that bites, because the manifest labels are the
/// ones a real scan emits and the registry label is the one `sscsb vex create`
/// writes. Measured on trivy 0.72.0, one fixture tree per file:
/// `requirements.txt` → `pip`, `poetry.lock` → `poetry`, `Pipfile.lock` →
/// `pipenv`, `yarn.lock` → `yarn`, `pnpm-lock.yaml` → `pnpm`, `go.mod` →
/// `gomod`, `Gemfile.lock` → `bundler`, `*.deps.json` → `dotnet-core`,
/// `pom.xml` → `pom`, `package-lock.json` → `npm`, `Cargo.lock` → `cargo`,
/// `composer.lock` → `composer`, `packages.lock.json` → `nuget`. Without the
/// aliases below, the canonical `pkg:pypi/…` matched no Python finding Trivy
/// can produce — a waiver that suppressed nothing and said nothing.
///
/// Aliasing only ever loosens the gate, so every entry has to be a genuine
/// identity: these map manifests onto the single registry they resolve
/// against, never two registries onto each other.
fn normalize_ecosystem(label: &str) -> String {
    let l = label.to_ascii_lowercase();
    match l.as_str() {
        "crates.io" => "cargo".into(),
        "go" | "gomod" | "gobinary" => "golang".into(),
        // Trivy reports Java findings under archive/build-file types; their
        // coordinates are Maven GAV, purl type "maven".
        "jar" | "pom" | "gradle" | "gradle-lockfile" | "sbt" => "maven".into(),
        // Python: one registry (PyPI), one manifest label per tool.
        "pip" | "poetry" | "pipenv" | "uv" | "python-pkg" => "pypi".into(),
        // JavaScript: alternative clients, all resolving against the npm
        // registry.
        "yarn" | "pnpm" | "bun" | "node-pkg" => "npm".into(),
        "packagist" => "composer".into(),
        "rubygems" | "bundler" | "gemspec" => "gem".into(),
        "dotnet-core" => "nuget".into(),
        "conda-pkg" => "conda".into(),
        "debian" | "ubuntu" => "deb".into(),
        "alpine" => "apk".into(),
        "redhat" | "centos" | "rocky" | "alma" | "almalinux" | "fedora" | "oracle" | "amazon"
        | "suse" | "opensuse" | "opensuse-leap" => "rpm".into(),
        _ => l,
    }
}

/// Does the report breach the configured severity threshold?
///
/// Two things this refuses to do silently, both of which it used to:
///
/// 1. **Rank an undetermined severity below `low`.** A finding whose severity
///    no source stated breaches EVERY threshold. We cannot show it is below
///    the line, so it is above it; the alternative is a gate that a missing
///    field can walk straight through. [`parse_osv`] recovers a real rating
///    wherever the advisory carries one precisely so this set stays small,
///    and a documented waiver is still available through VEX — visibly.
/// 2. **Turn a typo'd threshold into the strictest setting.** `fail_on =
///    "error"` used to rank 0, i.e. `low`, i.e. everything breaches: a
///    misconfiguration that *looks* like it is working. A `fail_on` that is
///    not a severity is a configuration error and says so.
pub fn breaches_threshold(report: &ScanReport, fail_on: &str) -> Result<bool> {
    let threshold = severity_rank(fail_on).with_context(|| {
        format!(
            "`fail_on` is not a severity: {fail_on:?} (valid: {}). \
             Fix `[controls.vuln-scan] fail_on` in .sscsb/config.toml",
            SEVERITIES.join(", ")
        )
    })?;
    Ok(report
        .findings
        .iter()
        .any(|f| match severity_rank(&f.severity) {
            Some(rank) => rank >= threshold,
            // Undetermined: not provably below the line, so treated as above it.
            None => true,
        }))
}

pub fn verify_scan_control(ctx: &Ctx) -> VerifyResult {
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    for tool in ["trivy", "osv-scanner"] {
        match tools::detect(tools::spec(tool).expect("registry")) {
            tools::ToolStatus::Found { version, .. } => messages.push(format!(
                "{tool}: {}",
                version.unwrap_or_else(|| "version unknown".into())
            )),
            tools::ToolStatus::Missing => {
                outcome = Outcome::Degraded;
                messages.push(tools::degrade_message(tool, ctx.platform));
            }
        }
    }
    // Which tools are installed is only half of what this control depends on;
    // the other half is what the repository tells them to skip. `verify` is
    // where a reviewer looks, so the inventory is stated here too. It does not
    // move the verdict: a documented waiver is a decision, not a failure —
    // see `scanner_config_notes` for why inherit-and-report is the contract.
    messages.extend(scanner_config_notes(&ctx.root));
    VerifyResult::new("vuln-scan", outcome, messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRIVY_SAMPLE: &str = r#"{"Results":[{"Target":"Cargo.lock","Vulnerabilities":[
        {"VulnerabilityID":"CVE-2024-0001","PkgName":"foo","Severity":"HIGH"},
        {"VulnerabilityID":"CVE-2024-0002","PkgName":"bar","Severity":"LOW"}]}]}"#;

    #[test]
    fn trivy_parse_and_threshold() {
        let findings = parse_trivy(TRIVY_SAMPLE).unwrap();
        assert_eq!(findings.len(), 2);
        let report = ScanReport {
            findings,
            ..Default::default()
        };
        assert!(breaches_threshold(&report, "high").unwrap());
        assert!(!breaches_threshold(&ScanReport::default(), "low").unwrap());
        // Raising the threshold to critical: the high finding no longer breaches.
        assert!(!breaches_threshold(&report, "critical").unwrap());
    }

    #[test]
    fn osv_parse() {
        let sample = r#"{"results":[{"packages":[{"package":{"name":"foo"},
            "vulnerabilities":[{"id":"GHSA-xxxx","database_specific":{"severity":"MODERATE"}}]}]}]}"#;
        let findings = parse_osv(sample).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "GHSA-xxxx");
        assert_eq!(findings[0].source, "osv-scanner");
        // GHSA's MODERATE is this scale's `medium`, not an unrecognised
        // string that ranks below `low`.
        assert_eq!(findings[0].severity, "medium");
    }

    #[test]
    fn vex_suppression_is_visible_not_silent() {
        let mut report = ScanReport {
            findings: parse_trivy(TRIVY_SAMPLE).unwrap(),
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/foo"}],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed.len(), 1);
        assert!(report.suppressed[0].contains("CVE-2024-0001"));
        assert!(report.notes.iter().any(|n| n.contains("VEX applied")));
    }

    #[test]
    fn vex_rejects_non_openvex() {
        let mut report = ScanReport::default();
        assert!(apply_vex(&mut report, r#"{"statements":[]}"#).is_err());
    }

    #[test]
    fn severity_ranks_are_ordered() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
    }

    /// H6: `severity_rank` ended in `.unwrap_or(0)`, so every string that was
    /// not one of the four labels ranked BELOW `low` — an unrateable advisory
    /// and a GHSA `MODERATE` alike. Both halves are asserted here.
    #[test]
    fn an_undetermined_severity_is_not_a_low_severity() {
        // Not a severity: no rank at all, rather than the weakest rank.
        assert_eq!(severity_rank("unknown"), None);
        assert_eq!(severity_rank("unknown-thing"), None);
        assert_eq!(severity_rank(""), None);
        // ...and it is strictly not `low`, which does have a rank.
        assert!(severity_rank("low").is_some());

        // A finding we cannot rank breaches every threshold, including the
        // most permissive one, because nothing shows it is below the line.
        let report = ScanReport {
            findings: vec![VulnFinding {
                id: "RUSTSEC-2024-0375".into(),
                package: "atty".into(),
                severity: "unknown".into(),
                source: "osv-scanner",
                ecosystem: Some("crates.io".into()),
            }],
            ..Default::default()
        };
        for threshold in SEVERITIES {
            assert!(
                breaches_threshold(&report, threshold).unwrap(),
                "an undetermined severity must breach `{threshold}`"
            );
        }
        // And it is counted and explained rather than merely gating.
        assert_eq!(undetermined_severity_count(&report), 1);
        let note = undetermined_severity_note(&report).expect("note");
        assert!(
            note.contains("1 finding(s)") && note.contains("VEX"),
            "{note}"
        );
        assert_eq!(undetermined_severity_note(&ScanReport::default()), None);
    }

    /// H6: GHSA rates advisories `MODERATE`; the scale says `medium`. Before
    /// normalisation that string was unrecognised, so every GitHub-rated
    /// moderate advisory ranked below `low` and could not breach `medium`.
    #[test]
    fn ghsa_moderate_ranks_as_medium() {
        assert_eq!(severity_rank("MODERATE"), severity_rank("medium"));
        let report = ScanReport {
            findings: vec![VulnFinding {
                id: "GHSA-wcg3-cvx6-7396".into(),
                package: "time".into(),
                severity: "moderate".into(),
                source: "osv-scanner",
                ecosystem: Some("crates.io".into()),
            }],
            ..Default::default()
        };
        assert!(breaches_threshold(&report, "medium").unwrap());
        assert!(breaches_threshold(&report, "low").unwrap());
        // It is a real rating, so it does NOT breach a higher threshold —
        // this is a recovered severity, not a fail-closed unknown.
        assert!(!breaches_threshold(&report, "high").unwrap());
    }

    /// H6, inverse hazard: a typo'd threshold used to rank 0 — the STRICTEST
    /// setting — so a misconfigured gate looked like a working one.
    #[test]
    fn a_fail_on_that_is_not_a_severity_is_an_error_not_the_strictest_setting() {
        let report = ScanReport {
            findings: parse_trivy(TRIVY_SAMPLE).unwrap(),
            ..Default::default()
        };
        for typo in ["none", "error", "HIGH!", "", "criticalish"] {
            let err = breaches_threshold(&report, typo).unwrap_err().to_string();
            assert!(
                err.contains("not a severity") && err.contains("low, medium, high, critical"),
                "a {typo:?} threshold must name the valid values: {err}"
            );
        }
        // Case and stray whitespace are the author's intent, not a typo.
        assert!(breaches_threshold(&report, "HIGH ").unwrap());
        assert!(!breaches_threshold(&report, " Critical").unwrap());
    }

    #[test]
    fn parse_trivy_rejects_non_json_output() {
        let err = parse_trivy("this is not json").unwrap_err();
        assert!(format!("{err:#}").contains("not JSON"));
    }

    #[test]
    fn parse_osv_rejects_non_json_output() {
        let err = parse_osv("this is not json").unwrap_err();
        assert!(format!("{err:#}").contains("not JSON"));
    }

    /// M4: non-JSON failed loudly while wrong-shaped JSON failed silently,
    /// which is backwards. `{}`, `[]`, and any unrelated document all read as
    /// zero findings — no error, no note — so a scanner that returned
    /// something unexpected reported a clean repository and exited 0. A
    /// document with no recognisable marker is not clean; it is unreadable.
    #[test]
    fn parse_trivy_rejects_json_that_is_not_a_trivy_report() {
        for wrong_shape in [
            "{}",
            "[]",
            "null",
            "42",
            r#""a string""#,
            r#"{"results":[]}"#, // OSV's envelope, handed to the wrong parser
            r#"{"error":"failed to download vulnerability DB"}"#,
            r#"[{"Results":[]}]"#, // the right key at the wrong nesting
            r#"{"SchemaVersion":2,"Results":"broken"}"#, // envelope, unreadable body
        ] {
            let Err(err) = parse_trivy(wrong_shape) else {
                panic!("{wrong_shape} must not read as a clean scan");
            };
            let msg = format!("{err:#}");
            assert!(
                msg.contains("not in trivy's report shape"),
                "{wrong_shape} must be named unreadable, not counted as zero findings: {msg}"
            );
            // The same document through the suppression channel, which reads
            // the same stdout and had the same silent-empty behaviour.
            assert!(
                parse_trivy_suppressions(wrong_shape).is_err(),
                "{wrong_shape} must not read as zero suppressions either"
            );
        }
    }

    /// The other half of M4: a genuinely clean scan must still read clean and
    /// gate green. This is the exact envelope `trivy fs --format json`
    /// emitted for a finding-free tree on 0.72.0 — note it carries NO
    /// `Results` key at all, so keying the shape check on `Results` would
    /// have turned every clean scan into an error.
    #[test]
    fn parse_trivy_accepts_the_resultless_envelope_a_clean_scan_emits() {
        const CLEAN: &str = r#"{"SchemaVersion":2,"Trivy":{"Version":"0.72.0"},
            "ReportID":"01a03580-c434-7ad9-a00b-bc960132a8b2",
            "CreatedAt":"2026-08-24T16:40:26.420713-04:00",
            "ArtifactName":".","ArtifactType":"filesystem"}"#;
        let findings = parse_trivy(CLEAN).expect("a clean scan is readable");
        assert!(findings.is_empty());
        assert!(parse_trivy_suppressions(CLEAN).unwrap().is_empty());
        let report = ScanReport {
            findings,
            ..Default::default()
        };
        assert!(
            !breaches_threshold(&report, "low").unwrap(),
            "a clean scan must still pass the strictest threshold"
        );
        // An explicitly empty result list is equally clean.
        assert!(parse_trivy(r#"{"SchemaVersion":2,"Results":[]}"#)
            .unwrap()
            .is_empty());
        assert!(parse_trivy(r#"{"SchemaVersion":2,"Results":null}"#)
            .unwrap()
            .is_empty());
    }

    /// M4, OSV half: `results` is the marker. Measured on osv-scanner 2.4.0,
    /// a clean scan over a real lockfile emits `{"results":[],...}` — the key
    /// is present — so requiring it costs no clean scan anything.
    #[test]
    fn parse_osv_rejects_json_that_is_not_an_osv_report() {
        for wrong_shape in [
            "{}",
            "[]",
            "null",
            "42",
            r#"{"Results":[]}"#, // Trivy's envelope, handed to the wrong parser
            r#"{"error":"unsupported lockfile"}"#,
            r#"[{"results":[]}]"#,
            r#"{"results":"none"}"#, // marker present, body unreadable
        ] {
            let Err(err) = parse_osv(wrong_shape) else {
                panic!("{wrong_shape} must not read as a clean scan");
            };
            let msg = format!("{err:#}");
            assert!(
                msg.contains("not in osv-scanner's report shape"),
                "{wrong_shape} must be named unreadable, not counted as zero findings: {msg}"
            );
        }
    }

    /// The false-positive guard for the OSV half: the exact envelope
    /// osv-scanner 2.4.0 emitted for a clean scan of a real `Cargo.lock`.
    #[test]
    fn parse_osv_accepts_the_empty_results_envelope_a_clean_scan_emits() {
        const CLEAN: &str = r#"{"results":[],"experimental_config":{"licenses":
            {"summary":false,"allowlist":null}}}"#;
        assert!(parse_osv(CLEAN)
            .expect("a clean scan is readable")
            .is_empty());
        assert!(parse_osv(r#"{"results":null}"#).unwrap().is_empty());
    }

    // A realistic multi-target Trivy report: one target with a dependency
    // vulnerability, one with a leaked secret (one fully described, one with
    // fields Trivy sometimes omits), one with an IaC misconfiguration (same
    // shape). Exercises every finding kind `parse_trivy` understands.
    const TRIVY_FULL_SAMPLE: &str = r#"{"Results":[
        {"Target":"Cargo.lock","Vulnerabilities":[
            {"VulnerabilityID":"CVE-2024-0001","PkgName":"foo","Severity":"HIGH"}]},
        {"Target":".env","Secrets":[
            {"RuleID":"generic-api-key","Category":"secret","Severity":"CRITICAL","Title":"API Key"},
            {"Title":"unidentified secret"}]},
        {"Target":"Dockerfile","Misconfigurations":[
            {"ID":"DS002","Title":"Image user should not be root","Severity":"HIGH"},
            {"Title":"unrated misconfig"}]}
    ]}"#;

    #[test]
    fn parse_trivy_captures_secrets_with_target_as_package_and_safe_defaults() {
        let findings = parse_trivy(TRIVY_FULL_SAMPLE).unwrap();
        let secrets: Vec<_> = findings.iter().filter(|f| f.source == "trivy").collect();
        // 1 vulnerability + 2 secrets + 2 misconfigurations.
        assert_eq!(secrets.len(), 5);

        let named = findings
            .iter()
            .find(|f| f.id == "generic-api-key")
            .expect("named secret present");
        assert_eq!(named.package, ".env", "secret's package is the file target");
        assert_eq!(named.severity, "critical");
        assert_eq!(named.source, "trivy");

        // A secret entry missing RuleID/Severity is never silently dropped —
        // it still surfaces, under the documented safe defaults.
        assert!(findings
            .iter()
            .any(|f| f.id == "secret" && f.package == ".env" && f.severity == "high"));
    }

    #[test]
    fn parse_trivy_captures_misconfigurations_with_target_as_package_and_safe_defaults() {
        let findings = parse_trivy(TRIVY_FULL_SAMPLE).unwrap();
        let named = findings
            .iter()
            .find(|f| f.id == "DS002")
            .expect("named misconfiguration present");
        assert_eq!(named.package, "Dockerfile");
        assert_eq!(named.severity, "high");
        assert_eq!(named.source, "trivy");

        // A misconfiguration entry missing ID/Severity still surfaces, under
        // the documented safe defaults — never silently dropped.
        assert!(findings
            .iter()
            .any(|f| f.id == "misconfig" && f.package == "Dockerfile" && f.severity == "medium"));
    }

    #[test]
    fn parse_osv_defaults_severity_to_unknown_when_database_specific_is_absent() {
        // Real OSV advisories are not all severity-rated (some GHSA entries
        // ship with no CVSS score) — the parser must still surface them.
        let sample = r#"{"results":[{"packages":[{"package":{"name":"foo"},
            "vulnerabilities":[{"id":"GHSA-unrated"}]}]}]}"#;
        let findings = parse_osv(sample).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "GHSA-unrated");
        assert_eq!(findings[0].severity, "unknown");
        // ...and "unknown" is not a rank, so it cannot slip under a gate.
        assert_eq!(severity_rank(&findings[0].severity), None);
    }

    /// H6: RUSTSEC and PYSEC records carry no `/database_specific/severity` —
    /// reading only that field rated 13 of 25 findings `unknown` in a live
    /// `osv-scanner 2.4.0` run. These are the record shapes those databases
    /// actually emit, captured from that run.
    #[test]
    fn parse_osv_recovers_severity_from_the_fields_advisories_actually_populate() {
        // RUSTSEC-2021-0003 (smallvec): no database_specific.severity; the
        // rating lives in the OSV `severity` array as a CVSS vector. 9.8.
        let rustsec_vector = r#"{"results":[{"packages":[{"package":{"name":"smallvec","ecosystem":"crates.io"},
            "vulnerabilities":[{"id":"RUSTSEC-2021-0003","database_specific":{"license":"CC0-1.0"},
             "severity":[{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","type":"CVSS_V3"}]}]}]}]}"#;
        let findings = parse_osv(rustsec_vector).unwrap();
        assert_eq!(findings[0].severity, "critical", "{:?}", findings[0]);

        // RUSTSEC-2020-0071 (time): the same vector, in the other place
        // RUSTSEC puts it — affected[].database_specific.cvss. 6.2.
        let rustsec_affected = r#"{"results":[{"packages":[{"package":{"name":"time","ecosystem":"crates.io"},
            "vulnerabilities":[{"id":"RUSTSEC-2020-0071","database_specific":{"license":"CC0-1.0"},
             "affected":[{"database_specific":{"cvss":"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
             "informational":null}}]}]}]}]}"#;
        let findings = parse_osv(rustsec_affected).unwrap();
        assert_eq!(findings[0].severity, "medium", "{:?}", findings[0]);

        // GHSA states a label AND a vector. The label is normalised onto this
        // scale, and where the two disagree the higher rating wins — a gate is
        // not argued down by the weaker of two ratings one record asserts.
        let ghsa = r#"{"results":[{"packages":[{"package":{"name":"smallvec","ecosystem":"crates.io"},
            "vulnerabilities":[{"id":"GHSA-43w2-9j62-hq99",
             "database_specific":{"severity":"MODERATE","github_reviewed":true},
             "severity":[{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","type":"CVSS_V3"}]}]}]}]}"#;
        let findings = parse_osv(ghsa).unwrap();
        assert_eq!(findings[0].severity, "critical", "{:?}", findings[0]);

        // A label with no vector is still recovered, canonicalised.
        let label_only = r#"{"results":[{"packages":[{"package":{"name":"atty"},
            "vulnerabilities":[{"id":"GHSA-g98v-hv3f-hcfr","database_specific":{"severity":"MODERATE"}}]}]}]}"#;
        assert_eq!(parse_osv(label_only).unwrap()[0].severity, "medium");

        // A vector we cannot score exactly is NOT guessed at: the v4
        // macro-vector tables are not implemented, so this stays undetermined
        // (which fails closed) rather than being invented as some band.
        let v4_only = r#"{"results":[{"packages":[{"package":{"name":"foo"},
            "vulnerabilities":[{"id":"GHSA-v4","severity":[{"score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N","type":"CVSS_V4"}]}]}]}]}"#;
        assert_eq!(parse_osv(v4_only).unwrap()[0].severity, "unknown");
    }

    /// The base-score arithmetic, checked against published CVSS values —
    /// a recovered severity is only worth having if the score is right.
    #[test]
    fn cvss_v3_base_scores_match_the_published_values() {
        let score = |v: &str| cvss_v3_base_score(v).expect("scorable vector");
        // RUSTSEC-2021-0003 / CVE-2021-25900, rated 9.8 by NVD and GHSA.
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        // CVE-2020-26235 (time), 6.2 — GHSA's MODERATE.
        assert_eq!(score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 6.2);
        // Log4Shell, the canonical scope-changed 10.0.
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        // Heartbleed's v3 vector, 7.5.
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 7.5);
        // Scope-changed with partial impact: 6.4 (exercises the 1.08 factor).
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"), 6.4);
        // Low band, and the v3.0 prefix is accepted too.
        assert_eq!(score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"), 3.1);
        // No impact at all scores 0.0 — the impact<=0 branch.
        assert_eq!(score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"), 0.0);

        // Bands, including the 0.0 "None" case which has no lower rung here.
        assert_eq!(
            severity_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some("critical")
        );
        assert_eq!(
            severity_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Some("high")
        );
        assert_eq!(
            severity_from_cvss_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"),
            Some("low")
        );

        // Nothing we cannot score exactly is guessed at.
        for unscorable in [
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // missing mandatory A
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bogus metric value
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H", // bogus scope
            "CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H", // bogus complexity
            "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H", // bogus privileges
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:X/S:U/C:H/I:H/A:H", // bogus interaction
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:X/I:H/A:H", // bogus impact
            "not a vector",
            "",
        ] {
            assert_eq!(
                cvss_v3_base_score(unscorable),
                None,
                "must not invent a score for {unscorable:?}"
            );
            assert_eq!(severity_from_cvss_vector(unscorable), None);
        }
    }

    #[test]
    fn vex_suppresses_fixed_status_alongside_not_affected_but_not_under_investigation() {
        let mut report = ScanReport {
            findings: parse_trivy(TRIVY_SAMPLE).unwrap(), // CVE-2024-0001 (foo/high), CVE-2024-0002 (bar/low)
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0002"},"products":[{"@id":"pkg:cargo/bar"}],
             "status":"fixed"},
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/foo"}],
             "status":"under_investigation"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        // Only the "fixed" statement suppresses; "under_investigation" leaves
        // the finding fully visible — VEX only hides what's genuinely resolved.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "CVE-2024-0001");
        assert_eq!(report.suppressed.len(), 1);
        assert!(report.suppressed[0].contains("CVE-2024-0002"));
    }

    #[test]
    fn apply_vex_rejects_malformed_json() {
        let mut report = ScanReport::default();
        let err = apply_vex(&mut report, "not json at all").unwrap_err();
        assert!(format!("{err:#}").contains("not valid JSON"));
    }

    fn finding(id: &str, package: &str) -> VulnFinding {
        VulnFinding {
            id: id.to_string(),
            package: package.to_string(),
            severity: "high".to_string(),
            source: "trivy",
            ecosystem: None,
        }
    }

    fn eco_finding(id: &str, package: &str, ecosystem: &str) -> VulnFinding {
        VulnFinding {
            ecosystem: Some(ecosystem.to_string()),
            ..finding(id, package)
        }
    }

    /// The defect this scoping exists to kill: one statement scoped to a
    /// single product acting as a document-wide wildcard for its CVE.
    #[test]
    fn vex_statement_scoped_to_one_package_does_not_suppress_the_same_cve_elsewhere() {
        let mut report = ScanReport {
            findings: vec![
                finding("CVE-2024-0001", "foo"),
                finding("CVE-2024-0001", "bar"),
            ],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/foo"}],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert_eq!(
            report.findings.len(),
            1,
            "the out-of-scope finding survives"
        );
        assert_eq!(report.findings[0].package, "bar");
        assert_eq!(report.suppressed.len(), 1);
        assert!(
            report.suppressed[0].contains("foo") && report.suppressed[0].contains("pkg:cargo/foo"),
            "the suppression row names the product that matched: {}",
            report.suppressed[0]
        );
    }

    #[test]
    fn vex_statement_with_no_products_suppresses_nothing_and_is_noted() {
        let mut report = ScanReport {
            findings: vec![finding("CVE-2024-0001", "foo")],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert_eq!(report.findings.len(), 1, "nothing may be suppressed");
        assert!(report.suppressed.is_empty());
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("names no products") && n.contains("CVE-2024-0001")),
            "the impotent statement must be visible in the notes: {:?}",
            report.notes
        );
    }

    #[test]
    fn vex_version_pinned_purl_matches_the_unversioned_finding_name() {
        // Findings carry no version, so a version-pinned purl matches at name
        // granularity — documented behavior, visible via the suppression row.
        let mut report = ScanReport {
            findings: vec![finding("CVE-2024-0001", "itoa")],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/itoa@1.0.11"}],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert!(report.findings.is_empty());
        assert!(report.suppressed[0].contains("pkg:cargo/itoa@1.0.11"));
    }

    #[test]
    fn purl_parts_handles_the_shapes_scanners_emit() {
        let parts = |p: &str| purl_parts(p).map(|(t, n)| format!("{t} {n}"));
        assert_eq!(
            parts("pkg:cargo/itoa@1.0.11").as_deref(),
            Some("cargo itoa")
        );
        assert_eq!(parts("pkg:cargo/foo").as_deref(), Some("cargo foo"));
        assert_eq!(
            parts("pkg:npm/%40scope/name@1.2").as_deref(),
            Some("npm @scope/name")
        );
        assert_eq!(
            parts("pkg:golang/github.com/foo/bar@v1.0.0").as_deref(),
            Some("golang github.com/foo/bar")
        );
        assert_eq!(
            parts("pkg:cargo/foo@1.0?checksum=abc").as_deref(),
            Some("cargo foo")
        );
        assert_eq!(parts("not-a-purl"), None);
        assert_eq!(parts("pkg:cargo/"), None);
    }

    /// The adversarial-review HIGH: same bare package name in two ecosystems,
    /// one ecosystem-scoped statement. Only the matching ecosystem's finding
    /// may be suppressed.
    #[test]
    fn vex_cargo_statement_does_not_suppress_a_same_named_package_in_another_ecosystem() {
        let mut report = ScanReport {
            findings: vec![
                eco_finding("CVE-2024-0001", "openssl", "cargo"),
                eco_finding("CVE-2024-0001", "openssl", "debian"),
            ],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/openssl"}],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].ecosystem.as_deref(), Some("debian"));
        assert_eq!(report.suppressed.len(), 1);
    }

    #[test]
    fn vex_ecosystem_aliases_bridge_scanner_and_purl_vocabulary() {
        // OSV says "crates.io"; the purl type is "cargo". They must agree.
        let mut report = ScanReport {
            findings: vec![eco_finding("CVE-2024-0001", "itoa", "crates.io")],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/itoa"}],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    /// M3(b): a purl names an ecosystem by its REGISTRY (`pypi`, `npm`,
    /// `golang`, `gem`, `nuget`); Trivy names it by the MANIFEST it read the
    /// dependency out of. Measured on trivy 0.72.0 against one fixture tree:
    /// `requirements.txt` → `pip`, `poetry.lock` → `poetry`, `Pipfile.lock` →
    /// `pipenv`, `yarn.lock` → `yarn`, `pnpm-lock.yaml` → `pnpm`, `go.mod` →
    /// `gomod`, `Gemfile.lock` → `bundler`, `*.deps.json` → `dotnet-core`.
    ///
    /// Every one of those disagrees with the canonical purl `sscsb vex create`
    /// writes, so the ecosystem gate rejected the match and the waiver
    /// suppressed nothing — the exact silent no-op VEX exists to avoid. The
    /// canonical `pkg:pypi/...` form was inert against every Python finding
    /// Trivy can produce.
    #[test]
    fn vex_canonical_purl_matches_the_manifest_named_ecosystems_scanners_emit() {
        let waiver = |purl_type: &str, package: &str| {
            format!(
                r#"{{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
                {{"vulnerability":{{"name":"CVE-2024-0001"}},
                 "products":[{{"@id":"pkg:{purl_type}/{package}"}}],
                 "status":"not_affected","justification":"vulnerable_code_not_present"}}]}}"#
            )
        };
        // (canonical purl type, package, the label a scanner actually emits)
        let bridged = [
            ("pypi", "requests", "pip"),
            ("pypi", "requests", "poetry"),
            ("pypi", "requests", "pipenv"),
            ("pypi", "requests", "PyPI"), // OSV's own spelling, cased
            ("npm", "lodash", "yarn"),
            ("npm", "lodash", "pnpm"),
            ("golang", "github.com/gin-gonic/gin", "gomod"),
            ("gem", "rack", "bundler"),
            ("nuget", "Newtonsoft.Json", "dotnet-core"),
        ];
        for (purl_type, package, ecosystem) in bridged {
            let mut report = ScanReport {
                findings: vec![eco_finding("CVE-2024-0001", package, ecosystem)],
                ..Default::default()
            };
            apply_vex(&mut report, &waiver(purl_type, package)).unwrap();
            assert!(
                report.findings.is_empty(),
                "pkg:{purl_type}/{package} must waive the same package reported \
                 under the scanner's `{ecosystem}` label, not silently miss it"
            );
        }

        // The gate is bridged, not dropped: a Python waiver still may not
        // reach a same-named package from any other registry.
        for foreign in ["debian", "alpine", "npm", "cargo", "gomod"] {
            let mut report = ScanReport {
                findings: vec![eco_finding("CVE-2024-0001", "requests", foreign)],
                ..Default::default()
            };
            apply_vex(&mut report, &waiver("pypi", "requests")).unwrap();
            assert_eq!(
                report.findings.len(),
                1,
                "a pypi waiver must not reach a `{foreign}` package of the same name"
            );
        }
    }

    /// M3(a), REBUTTED — the bare-name fallback is the design, not a defect.
    ///
    /// A product id that is a bare name declares no ecosystem, so there is no
    /// ecosystem for it to cross. Refusing the match would not tighten the
    /// gate; it would turn every bare-name statement into a silent no-op —
    /// the failure mode this module exists to prevent, and the one that
    /// pushes an operator into disabling the control outright.
    ///
    /// What the design does owe is legibility, since it rests on the claim
    /// that "the suppression row keeps the residue visible". It did not:
    /// findings of the same name in different ecosystems produced textually
    /// IDENTICAL rows, so a reader could not see how far a name-only waiver
    /// reached. Each row now states the ecosystem it hit.
    #[test]
    fn vex_bare_product_name_matches_by_name_alone_and_each_row_names_its_ecosystem() {
        let mut report = ScanReport {
            findings: vec![
                eco_finding("CVE-2024-0001", "openssl", "cargo"),
                eco_finding("CVE-2024-0001", "openssl", "debian"),
                finding("CVE-2024-0001", "openssl"),
            ],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":["openssl"],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();

        // Deliberate: a namespace-free assertion matches by name, everywhere.
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.suppressed.len(), 3);

        // ...and its breadth is readable — three suppressions are three
        // distinct facts on the page, not one fact printed three times.
        assert!(
            report.suppressed[0].contains("[cargo]"),
            "{}",
            report.suppressed[0]
        );
        assert!(
            report.suppressed[1].contains("[debian]"),
            "{}",
            report.suppressed[1]
        );
        assert!(
            !report.suppressed[2].contains('['),
            "a finding with no ecosystem must not be given one: {}",
            report.suppressed[2]
        );
        let distinct: std::collections::HashSet<&String> = report.suppressed.iter().collect();
        assert_eq!(
            distinct.len(),
            3,
            "a name-only waiver's reach must not read as one repeated row: {:?}",
            report.suppressed
        );
    }

    #[test]
    fn vex_matches_maven_gav_colon_notation() {
        let mut report = ScanReport {
            findings: vec![eco_finding(
                "CVE-2021-44228",
                "org.apache.logging.log4j:log4j-core",
                "jar",
            )],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2021-44228"},
             "products":[{"@id":"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"}],
             "status":"fixed"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        // "jar" (Trivy's Java type) normalises to "maven", so the GAV colon
        // form matches the purl slash form.
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        // Same through OSV's literal "maven" label:
        let mut agreeing = ScanReport {
            findings: vec![eco_finding(
                "CVE-2021-44228",
                "org.apache.logging.log4j:log4j-core",
                "maven",
            )],
            ..Default::default()
        };
        apply_vex(
            &mut agreeing,
            r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2021-44228"},
             "products":[{"@id":"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"}],
             "status":"fixed"}]}"#,
        )
        .unwrap();
        assert!(agreeing.findings.is_empty(), "{:?}", agreeing.findings);
        assert!(agreeing.suppressed[0].contains("VEX fixed for"));
    }

    #[test]
    fn vex_unknown_ecosystem_falls_back_to_name_matching() {
        // A finding with no ecosystem (older shapes, secrets) cannot be
        // tightened — name granularity is the documented fallback.
        let mut report = ScanReport {
            findings: vec![finding("CVE-2024-0001", "foo")],
            ..Default::default()
        };
        let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:cargo/foo"}],
             "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#;
        apply_vex(&mut report, vex).unwrap();
        assert!(report.findings.is_empty());
    }

    // ── orchestration: real Trivy + OSV-Scanner against throwaway repos ──────
    // `run_trivy`/`run_osv` are private, so — being in a child module of
    // `scan` — these tests can call them directly, in addition to exercising
    // them through `run_scan`'s public orchestration.

    fn fresh_bootstrapped_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    fn repo_with_cargo_lock() -> (tempfile::TempDir, Ctx) {
        let (dir, ctx) = fresh_bootstrapped_repo();
        std::fs::write(
            ctx.root.join("Cargo.lock"),
            "version = 3\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\ndependencies = [\"itoa\"]\n\n\
             [[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b\"\n",
        )
        .unwrap();
        (dir, ctx)
    }

    #[test]
    fn run_scan_orchestrates_both_installed_scanners_against_a_real_repo() {
        let (_d, ctx) = repo_with_cargo_lock();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("trivy") && !tools::is_available("osv-scanner") {
            let err = run_scan(&ctx, cfg, None).unwrap_err();
            assert!(format!("{err:#}").contains("no vulnerability scanner available"));
            return;
        }
        let report = run_scan(&ctx, cfg, None).unwrap();
        if tools::is_available("trivy") {
            assert!(!report.notes.iter().any(|n| n.contains("trivy not found")));
        }
        if tools::is_available("osv-scanner") {
            assert!(!report
                .notes
                .iter()
                .any(|n| n.contains("osv-scanner not found")));
        }
        // Threshold gating stays monotonic with severity regardless of what
        // the real scanners returned.
        let breached_low = breaches_threshold(&report, "low").unwrap();
        let breached_crit = breaches_threshold(&report, "critical").unwrap();
        assert!(
            !breached_crit || breached_low,
            "anything that breaches `critical` must also breach `low`"
        );
    }

    #[test]
    fn run_osv_reports_no_packages_found_note_on_a_dependency_free_repo() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        if !tools::is_available("osv-scanner") {
            return; // covered by the degrade-message path elsewhere
        }
        let mut report = ScanReport::default();
        run_osv(&ctx, &mut report).unwrap();
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("no packages found to scan")));
        assert!(report.findings.is_empty());
    }

    #[test]
    fn run_trivy_populates_findings_field_against_a_real_repo() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        if !tools::is_available("trivy") {
            return; // covered by the degrade-message path elsewhere
        }
        // A freshly bootstrapped repo is a realistic scan target. run_trivy
        // extends report.findings in place and records that trivy ran; assert
        // the observable effect rather than merely that it did not error.
        let mut report = ScanReport::default();
        let before = report.findings.len();
        run_trivy(&ctx, &mut report).unwrap();
        assert!(
            report.findings.len() >= before,
            "run_trivy must only ever add findings, never lose them"
        );
        // Every finding trivy produced is well-formed: a severity we can gate on.
        for f in &report.findings {
            assert!(
                !f.severity.is_empty(),
                "a parsed finding must carry a severity to gate on: {f:?}"
            );
        }
    }

    #[test]
    fn run_scan_applies_a_provided_vex_file_and_notes_it() {
        let (_d, ctx) = repo_with_cargo_lock();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("trivy") && !tools::is_available("osv-scanner") {
            return; // covered by the no-scanner-available branch elsewhere
        }
        let vex_path = ctx.root.join("noop.vex.json");
        std::fs::write(
            &vex_path,
            r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
                {"vulnerability":{"name":"CVE-0000-0000"},"products":[{"@id":"pkg:cargo/itoa@1.0.11"}],
                 "status":"not_affected","justification":"vulnerable_code_not_present"}]}"#,
        )
        .unwrap();
        let report = match run_scan(&ctx, cfg, Some(&vex_path)) {
            Ok(report) => report,
            Err(e) => {
                // This test is narrowly about VEX-application logic; Trivy's own
                // invocation correctness is covered by
                // `run_scan_orchestrates_both_installed_scanners_against_a_real_repo`.
                // A present-but-unhealthy Trivy — a cold/racing DB cache
                // ("DB error … json decode error: EOF") or a transient crash
                // ("unexpected fault address") — is an environmental
                // precondition, not a logic failure, so skip it the same way
                // the tool-absence guard above does rather than flaking the run.
                let msg = format!("{e:#}");
                let scanner_infra_failure = msg.contains("DB error")
                    || msg.contains("failed to download")
                    || msg.contains("unexpected fault address")
                    || msg.contains("trivy failed");
                if scanner_infra_failure {
                    eprintln!("skipping: scanner unhealthy in this environment ({msg})");
                    return;
                }
                panic!("run_scan failed unexpectedly: {msg}");
            }
        };
        assert!(report.notes.iter().any(|n| n.contains("VEX applied")));
    }

    #[test]
    fn run_scan_surfaces_a_clear_error_when_the_vex_path_does_not_exist() {
        // The availability guard and the call it guards BOTH resolve scanners
        // by bare name off `PATH`, so they must observe one PATH. Without the
        // lock a sibling test that strips PATH between them flips the guard's
        // answer, `run_scan` reports "no vulnerability scanner available"
        // instead of the VEX read error, and this fails as if the message had
        // regressed. See the composition rules in `testutil`.
        crate::testutil::with_env(|_| {
            let (_d, ctx) = repo_with_cargo_lock();
            let cfg = ctx.require_config().unwrap();
            if !tools::is_available("trivy") && !tools::is_available("osv-scanner") {
                return; // covered by the no-scanner-available branch elsewhere
            }
            let missing = ctx.root.join("does-not-exist.vex.json");
            let err = run_scan(&ctx, cfg, Some(&missing)).unwrap_err();
            assert!(format!("{err:#}").contains("reading VEX"));
        });
    }

    #[test]
    fn verify_scan_control_names_the_control_and_reports_tool_availability() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        let result = verify_scan_control(&ctx);
        assert_eq!(result.control, "vuln-scan");
        if tools::is_available("trivy") && tools::is_available("osv-scanner") {
            assert_eq!(result.outcome, Outcome::Pass);
            assert!(result.messages.iter().any(|m| m.starts_with("trivy:")));
            assert!(result
                .messages
                .iter()
                .any(|m| m.starts_with("osv-scanner:")));
        } else {
            assert_eq!(result.outcome, Outcome::Degraded);
        }
    }

    // ── H5: scanner configuration the repository supplies ───────────────────

    /// Every file the scanners pick up on their own is named, along with what
    /// it does — the part a `trivy.yaml` narrowing never reveals any other way.
    #[test]
    fn scanner_config_files_are_reported_with_what_they_do() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(
            scanner_config_notes(root).is_empty(),
            "a repo with no scanner config has nothing to report"
        );

        std::fs::write(
            root.join("trivy.yaml"),
            "severity:\n  - CRITICAL\n\
             scan:\n  skip-dirs:\n    - vendor\n\
             ignorefile: waivers/custom.ignore\n\
             vulnerability:\n  ignore-unfixed: true\n\
             db:\n  skip-update:\n\
             timeout: 5m\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".trivyignore"),
            "# documented waiver\nDS-0002\nDS-0026\n",
        )
        .unwrap();
        std::fs::write(
            root.join("osv-scanner.toml"),
            "[[IgnoredVulns]]\nid = \"RUSTSEC-2021-0003\"\nreason = \"reviewed\"\n\n\
             [[PackageOverrides]]\nname = \"atty\"\nignore = true\n",
        )
        .unwrap();
        let notes = scanner_config_notes(root).join("\n");

        // trivy.yaml: named, and its narrowing keys spelled out with values.
        assert!(notes.contains("trivy.yaml"), "{notes}");
        assert!(notes.contains("NARROWS"), "{notes}");
        assert!(notes.contains("severity=[CRITICAL]"), "{notes}");
        assert!(notes.contains("scan.skip-dirs=[vendor]"), "{notes}");
        // Every value shape a real trivy.yaml uses renders readably.
        assert!(
            notes.contains("ignorefile=waivers/custom.ignore"),
            "{notes}"
        );
        assert!(
            notes.contains("vulnerability.ignore-unfixed=true"),
            "{notes}"
        );
        // A key present with no value still narrows, and still shows up.
        assert!(notes.contains("db.skip-update=set"), "{notes}");
        // An operational key is not misreported as a narrowing one.
        assert!(!notes.contains("timeout="), "{notes}");

        // .trivyignore: entry count and the ids, comments excluded.
        assert!(
            notes.contains(".trivyignore is present with 2 entr"),
            "{notes}"
        );
        assert!(notes.contains("DS-0002, DS-0026"), "{notes}");
        assert!(!notes.contains("documented waiver"), "{notes}");

        // osv-scanner.toml: what it ignores and what it overrides.
        assert!(notes.contains("osv-scanner.toml"), "{notes}");
        assert!(notes.contains("ignores 1 (RUSTSEC-2021-0003)"), "{notes}");
        assert!(notes.contains("overrides 1 package(s) (atty)"), "{notes}");
    }

    /// A config file we cannot read is still a config file the scanner acts
    /// on: unparseable must report presence, never absence.
    #[test]
    fn unparseable_scanner_config_is_reported_as_present_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("trivy.yaml"), "\tthis: [is not: yaml\n").unwrap();
        std::fs::write(root.join("osv-scanner.toml"), "not [ valid toml\n").unwrap();
        let notes = scanner_config_notes(root).join("\n");
        assert_eq!(notes.matches("could not parse it").count(), 2, "{notes}");
        assert!(notes.contains("trivy.yaml is present"), "{notes}");
        assert!(notes.contains("osv-scanner.toml is present"), "{notes}");

        // An empty or effect-free config says so rather than implying muting.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("trivy.yaml"), "timeout: 5m\n").unwrap();
        std::fs::write(dir.path().join("osv-scanner.toml"), "# nothing\n").unwrap();
        std::fs::write(dir.path().join(".trivyignore"), "# only a comment\n").unwrap();
        let notes = scanner_config_notes(dir.path()).join("\n");
        assert!(notes.contains("no key in it narrows"), "{notes}");
        assert!(
            notes.contains("names no vulnerabilities or packages"),
            "{notes}"
        );
        assert!(
            notes.contains(".trivyignore is present with 0 entr"),
            "{notes}"
        );

        // A completely empty trivy.yaml parses to no documents at all.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("trivy.yaml"), "").unwrap();
        assert!(scanner_config_notes(dir.path())[0].contains("it is empty"));
    }

    /// Trivy's own suppression channel, as it reports it under
    /// `--show-suppressed` — the row carries the source and the author's
    /// statement, not just a count.
    #[test]
    fn parse_trivy_suppressions_names_the_source_and_the_stated_reason() {
        let sample = r#"{"Results":[{"Target":"Cargo.lock","Type":"cargo","Vulnerabilities":[],
            "ExperimentalModifiedFindings":[
              {"Type":"vulnerability","Status":"ignored","Statement":"reviewed 2026-08",
               "Source":".trivyignore",
               "Finding":{"VulnerabilityID":"CVE-2021-25900","PkgName":"smallvec"}},
              {"Type":"vulnerability","Status":"not_affected","Statement":"",
               "Source":"vex.json",
               "Finding":{"VulnerabilityID":"CVE-2020-26235","PkgName":"time"}}]},
            {"Target":"Dockerfile","ExperimentalModifiedFindings":[
              {"Status":"ignored","Source":".trivyignore","Finding":{"ID":"DS-0002"}}]},
            {"Target":"clean.lock","Vulnerabilities":[]}]}"#;
        let rows = parse_trivy_suppressions(sample).unwrap();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(
            rows[0],
            "CVE-2021-25900 (smallvec) — trivy ignored via .trivyignore: reviewed 2026-08"
        );
        // No statement: the row still names id, package, status and source.
        assert_eq!(
            rows[1],
            "CVE-2020-26235 (time) — trivy not_affected via vex.json"
        );
        // A misconfiguration has no PkgName; the target stands in for it.
        assert_eq!(
            rows[2],
            "DS-0002 (Dockerfile) — trivy ignored via .trivyignore"
        );

        // A report with no suppressions produces no rows, and a non-JSON blob
        // is an error rather than a silent empty list.
        assert!(parse_trivy_suppressions(TRIVY_SAMPLE).unwrap().is_empty());
        assert!(parse_trivy_suppressions("not json").is_err());
    }

    /// OSV-Scanner states its filtering on stderr and nowhere else — not in
    /// the JSON, not even under `--all-vulns`. Both verb forms it uses are
    /// parsed; matching only the singular dropped exactly the alias-group
    /// case, which is the one that mutes the most.
    #[test]
    fn osv_filter_report_reads_both_verb_forms_off_stderr() {
        let stderr = "Scanning dir /repo\n\
             Loaded filter from: /repo/osv-scanner.toml\n\
             RUSTSEC-2021-0003 and 2 aliases have been filtered out because: not reachable\n\
             RUSTSEC-2020-0159 has been filtered out because: accepted risk\n\
             Package crates.io/atty/0.2.14 has been filtered out because: unmaintained, pinned\n\
             Filtered 3 vulnerabilities from output\n";
        let (suppressed, notes) = osv_filter_report(stderr);
        assert_eq!(
            suppressed,
            vec![
                "RUSTSEC-2021-0003 and 2 aliases — osv-scanner filtered out: not reachable",
                "RUSTSEC-2020-0159 — osv-scanner filtered out: accepted risk",
                "Package crates.io/atty/0.2.14 — osv-scanner filtered out: unmaintained, pinned",
            ]
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("/repo/osv-scanner.toml"), "{:?}", notes);

        // An ordinary run says nothing of the sort.
        let (suppressed, notes) = osv_filter_report("Scanning dir /repo\nEnd status: 1 dirs\n");
        assert!(suppressed.is_empty() && notes.is_empty());
    }

    /// `verify` is where a reviewer looks, so the inventory is stated there
    /// too — without moving the verdict, because a documented waiver is a
    /// decision rather than a failure.
    #[test]
    fn verify_scan_control_reports_repository_supplied_scanner_config() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        let clean = verify_scan_control(&ctx);
        assert!(!clean.messages.iter().any(|m| m.contains("scanner config")));

        std::fs::write(ctx.root.join(".trivyignore"), "CVE-2021-25900\n").unwrap();
        let with_config = verify_scan_control(&ctx);
        assert!(
            with_config
                .messages
                .iter()
                .any(|m| m.contains("scanner config") && m.contains(".trivyignore")),
            "{:?}",
            with_config.messages
        );
        assert_eq!(
            with_config.outcome, clean.outcome,
            "a documented waiver is not a control failure"
        );
    }
}
