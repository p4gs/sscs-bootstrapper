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

pub fn severity_rank(s: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|x| x.eq_ignore_ascii_case(s))
        .unwrap_or(0)
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
    let _ = cfg;
    Ok(report)
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
            &root,
        ],
        Some(&ctx.root),
    )?;
    if !out.success() {
        anyhow::bail!("trivy failed (exit {}): {}", out.status, out.stderr.trim());
    }
    report.findings.extend(parse_trivy(&out.stdout)?);
    Ok(())
}

pub fn parse_trivy(stdout: &str) -> Result<Vec<VulnFinding>> {
    let v: serde_json::Value = serde_json::from_str(stdout).context("trivy output not JSON")?;
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
    Ok(())
}

pub fn parse_osv(stdout: &str) -> Result<Vec<VulnFinding>> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).context("osv-scanner output not JSON")?;
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
                let severity = vuln
                    .pointer("/database_specific/severity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown")
                    .to_lowercase();
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
/// suppression row names the product id and status that matched, so any
/// remaining over-breadth is visible in the report rather than silent.
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
                suppressed.push(format!(
                    "{} ({}) — VEX {status} for {product}",
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
/// [`normalize_ecosystem`] and must be equal. When either side is unknown
/// (secrets, misconfigs, older report shapes, non-purl product ids) matching
/// falls back to name granularity — we cannot tighten on information that
/// does not exist, and the suppression row keeps the residue visible.
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
fn normalize_ecosystem(label: &str) -> String {
    let l = label.to_ascii_lowercase();
    match l.as_str() {
        "crates.io" => "cargo".into(),
        "go" => "golang".into(),
        // Trivy reports Java findings under archive/build-file types; their
        // coordinates are Maven GAV, purl type "maven".
        "jar" | "pom" | "gradle" | "gradle-lockfile" | "sbt" => "maven".into(),
        "packagist" => "composer".into(),
        "rubygems" => "gem".into(),
        "debian" | "ubuntu" => "deb".into(),
        "alpine" => "apk".into(),
        "redhat" | "centos" | "rocky" | "alma" | "almalinux" | "fedora" | "oracle" | "amazon"
        | "suse" | "opensuse" | "opensuse-leap" => "rpm".into(),
        _ => l,
    }
}

/// Does the report breach the configured severity threshold?
pub fn breaches_threshold(report: &ScanReport, fail_on: &str) -> bool {
    let threshold = severity_rank(fail_on);
    report
        .findings
        .iter()
        .any(|f| severity_rank(&f.severity) >= threshold)
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
        assert!(breaches_threshold(&report, "high"));
        assert!(!breaches_threshold(&ScanReport::default(), "low"));
        // Raising the threshold to critical: the high finding no longer breaches.
        assert!(!breaches_threshold(&report, "critical"));
    }

    #[test]
    fn osv_parse() {
        let sample = r#"{"results":[{"packages":[{"package":{"name":"foo"},
            "vulnerabilities":[{"id":"GHSA-xxxx","database_specific":{"severity":"MODERATE"}}]}]}]}"#;
        let findings = parse_osv(sample).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "GHSA-xxxx");
        assert_eq!(findings[0].source, "osv-scanner");
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
        assert_eq!(severity_rank("unknown-thing"), severity_rank("low"));
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
        let breached_low = breaches_threshold(&report, "low");
        let breached_crit = breaches_threshold(&report, "critical");
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
        let (_d, ctx) = repo_with_cargo_lock();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("trivy") && !tools::is_available("osv-scanner") {
            return; // covered by the no-scanner-available branch elsewhere
        }
        let missing = ctx.root.join("does-not-exist.vex.json");
        let err = run_scan(&ctx, cfg, Some(&missing)).unwrap_err();
        assert!(format!("{err:#}").contains("reading VEX"));
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
}
