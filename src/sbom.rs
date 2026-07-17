//! SBOM generation via Syft (CycloneDX default, SPDX optional) and the
//! optional SBOM-first Grype scan.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;
use anyhow::{Context as _, Result};
use std::path::{Path, PathBuf};

pub const SBOM_FORMATS: &[&str] = &["cyclonedx-json", "spdx-json"];

pub fn sbom_output_path(ctx: &Ctx, format: &str) -> PathBuf {
    let ext = match format {
        "spdx-json" => "spdx.json",
        _ => "cdx.json",
    };
    ctx.sscsb_dir().join("out").join(format!("sbom.{ext}"))
}

/// Generate an SBOM for the repo with Syft. Returns the output path.
pub fn generate(ctx: &Ctx, cfg: &Config, format_override: Option<&str>) -> Result<PathBuf> {
    if !tools::is_available("syft") {
        anyhow::bail!("{}", tools::degrade_message("syft", ctx.platform));
    }
    let format = format_override
        .map(str::to_string)
        .or_else(|| cfg.control_opt_str("sbom", "format"))
        .unwrap_or_else(|| "cyclonedx-json".to_string());
    if !SBOM_FORMATS.contains(&format.as_str()) {
        anyhow::bail!(
            "unsupported SBOM format `{format}` — one of {}",
            SBOM_FORMATS.join(", ")
        );
    }
    let out_path = sbom_output_path(ctx, &format);
    std::fs::create_dir_all(out_path.parent().unwrap())?;
    let target = format!("dir:{}", ctx.root.display());
    let output_arg = format!("{format}={}", out_path.display());
    let out = exec::run("syft", &[&target, "-o", &output_arg], Some(&ctx.root))?;
    if !out.success() {
        anyhow::bail!("syft failed (exit {}): {}", out.status, out.stderr.trim());
    }
    validate_sbom(&out_path, &format)?;
    Ok(out_path)
}

/// Sanity-check the generated SBOM has the expected shape.
pub fn validate_sbom(path: &Path, format: &str) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading SBOM {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text).context("SBOM is not valid JSON")?;
    match format {
        "cyclonedx-json" => {
            let bom_format = v.get("bomFormat").and_then(|b| b.as_str());
            anyhow::ensure!(
                bom_format == Some("CycloneDX"),
                "expected bomFormat=CycloneDX, got {bom_format:?}"
            );
        }
        "spdx-json" => {
            anyhow::ensure!(
                v.get("spdxVersion").is_some(),
                "expected spdxVersion field in SPDX document"
            );
        }
        _ => {}
    }
    Ok(())
}

pub fn verify_sbom_control(ctx: &Ctx) -> VerifyResult {
    match tools::detect(tools::spec("syft").expect("registry")) {
        tools::ToolStatus::Found { version, .. } => VerifyResult::new(
            "sbom",
            Outcome::Pass,
            vec![format!(
                "syft {} available — `sscsb sbom` emits CycloneDX (default) or SPDX JSON",
                version.unwrap_or_else(|| "?".into())
            )],
        ),
        tools::ToolStatus::Missing => VerifyResult::new(
            "sbom",
            Outcome::Degraded,
            vec![tools::degrade_message("syft", ctx.platform)],
        ),
    }
}

/// Optional Grype scan over a Syft SBOM (SBOM-first workflow).
pub fn grype_scan(ctx: &Ctx, sbom_path: &Path) -> Result<(usize, Vec<String>)> {
    if !tools::is_available("grype") {
        anyhow::bail!("{}", tools::degrade_message("grype", ctx.platform));
    }
    let target = format!("sbom:{}", sbom_path.display());
    let out = exec::run("grype", &[&target, "-o", "json"], Some(&ctx.root))?;
    // grype exits non-zero when findings exceed --fail-on severity; parse output regardless.
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .with_context(|| format!("grype output not JSON (exit {})", out.status))?;
    let matches = v
        .get("matches")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    let summaries = matches
        .iter()
        .take(20)
        .map(|m| {
            format!(
                "{} {} ({})",
                m.pointer("/vulnerability/id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?"),
                m.pointer("/artifact/name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?"),
                m.pointer("/vulnerability/severity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?"),
            )
        })
        .collect();
    Ok((matches.len(), summaries))
}

pub fn verify_grype_control(ctx: &Ctx) -> VerifyResult {
    match tools::detect(tools::spec("grype").expect("registry")) {
        tools::ToolStatus::Found { version, .. } => VerifyResult::new(
            "grype",
            Outcome::Pass,
            vec![format!(
                "grype {} available — `sscsb scan --grype` runs SBOM-first scanning",
                version.unwrap_or_else(|| "?".into())
            )],
        ),
        tools::ToolStatus::Missing => VerifyResult::new(
            "grype",
            Outcome::Degraded,
            vec![tools::degrade_message("grype", ctx.platform)],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbom_validation_accepts_cyclonedx_rejects_junk() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("sbom.cdx.json");
        std::fs::write(
            &good,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#,
        )
        .unwrap();
        assert!(validate_sbom(&good, "cyclonedx-json").is_ok());

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, r#"{"something":"else"}"#).unwrap();
        assert!(validate_sbom(&bad, "cyclonedx-json").is_err());

        let spdx = dir.path().join("sbom.spdx.json");
        std::fs::write(&spdx, r#"{"spdxVersion":"SPDX-2.3"}"#).unwrap();
        assert!(validate_sbom(&spdx, "spdx-json").is_ok());
    }

    #[test]
    fn unsupported_format_rejected_before_tool_invocation() {
        assert!(!SBOM_FORMATS.contains(&"xml"));
    }

    #[test]
    fn validate_sbom_reports_a_clear_error_when_the_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");
        let err = validate_sbom(&missing, "cyclonedx-json").unwrap_err();
        assert!(format!("{err:#}").contains("reading SBOM"));
    }

    #[test]
    fn validate_sbom_rejects_non_json_content() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("not-json.json");
        std::fs::write(&bad, "this is not json").unwrap();
        let err = validate_sbom(&bad, "cyclonedx-json").unwrap_err();
        assert!(format!("{err:#}").contains("not valid JSON"));
    }

    #[test]
    fn validate_sbom_skips_shape_checks_for_an_unrecognized_format() {
        // `generate()` only ever calls `validate_sbom` with a format it just
        // checked against `SBOM_FORMATS`, but `validate_sbom` is itself
        // public — called directly with anything else, it must not panic or
        // reject; it simply has no shape rule for that format.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weird.json");
        std::fs::write(&path, r#"{"anything":"goes"}"#).unwrap();
        assert!(validate_sbom(&path, "xml").is_ok());
    }

    // ── orchestration: real Syft + Grype against throwaway repos ─────────────

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

    /// A repo with a real npm dependency (lodash 4.17.4) carrying long-standing,
    /// stable-identity CVEs — real enough for Syft to catalog and Grype to
    /// actually match, so the summary-building path gets genuine findings
    /// rather than a lucky-empty scan.
    fn repo_with_vulnerable_npm_package() -> (tempfile::TempDir, Ctx) {
        let (dir, ctx) = fresh_bootstrapped_repo();
        std::fs::write(
            ctx.root.join("package.json"),
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}"#,
        )
        .unwrap();
        std::fs::write(
            ctx.root.join("package-lock.json"),
            r#"{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "fixture",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.4"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.4",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
      "integrity": "sha512-Ogr1L7BW/Vy2yBRTAJhOG4wc/Fj4mQZK5AGOe/w8LQTVgP0TIjntC0PmUlKAJ3Ni8BiSfvUFO4KqNFmO1x0R7A=="
    }
  }
}
"#,
        )
        .unwrap();
        (dir, ctx)
    }

    #[test]
    fn sbom_output_path_maps_supported_formats_to_their_conventional_extensions() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        assert!(sbom_output_path(&ctx, "cyclonedx-json").ends_with("sbom.cdx.json"));
        assert!(sbom_output_path(&ctx, "spdx-json").ends_with("sbom.spdx.json"));
    }

    #[test]
    fn generate_writes_a_valid_cyclonedx_sbom_by_default_and_validates_it() {
        let (_d, ctx) = repo_with_vulnerable_npm_package();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("syft") {
            let err = generate(&ctx, cfg, None).unwrap_err();
            assert!(format!("{err:#}").contains("syft"));
            return;
        }
        let path = generate(&ctx, cfg, None).unwrap();
        assert!(path.ends_with("sbom.cdx.json"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(
            text.contains("lodash"),
            "the planted dependency is in the BOM"
        );
    }

    #[test]
    fn generate_honors_an_explicit_spdx_format_override() {
        let (_d, ctx) = repo_with_vulnerable_npm_package();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("syft") {
            return; // covered by the syft-missing branch above
        }
        let path = generate(&ctx, cfg, Some("spdx-json")).unwrap();
        assert!(path.ends_with("sbom.spdx.json"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("spdxVersion"));
    }

    #[test]
    fn generate_defaults_to_cyclonedx_when_config_has_no_format_key() {
        let (_d, ctx) = repo_with_vulnerable_npm_package();
        if !tools::is_available("syft") {
            return; // covered by the syft-missing branch above
        }
        // A hand-edited config with no `format` option under [controls.sbom]
        // — the generated-default case is not the only real one, so the
        // in-code fallback must still produce CycloneDX.
        let cfg_path = ctx.config_path();
        let edited: String = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .lines()
            .filter(|l| *l != "format = \"cyclonedx-json\"")
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&cfg_path, edited).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        assert_eq!(cfg.control_opt_str("sbom", "format"), None);

        let path = generate(&ctx, cfg, None).unwrap();
        assert!(path.ends_with("sbom.cdx.json"));
    }

    #[test]
    fn generate_rejects_an_unsupported_format_before_invoking_syft() {
        let (_d, ctx) = repo_with_vulnerable_npm_package();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("syft") {
            return; // covered by the syft-missing branch above
        }
        let err = generate(&ctx, cfg, Some("xml")).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported SBOM format"));
    }

    #[test]
    fn verify_sbom_control_names_the_control_and_reports_tool_availability() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        let result = verify_sbom_control(&ctx);
        assert_eq!(result.control, "sbom");
        if tools::is_available("syft") {
            assert_eq!(result.outcome, Outcome::Pass);
            assert!(result.messages[0].contains("syft"));
        } else {
            assert_eq!(result.outcome, Outcome::Degraded);
        }
    }

    #[test]
    fn verify_grype_control_names_the_control_and_reports_tool_availability() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        let result = verify_grype_control(&ctx);
        assert_eq!(result.control, "grype");
        if tools::is_available("grype") {
            assert_eq!(result.outcome, Outcome::Pass);
            assert!(result.messages[0].contains("grype"));
        } else {
            assert_eq!(result.outcome, Outcome::Degraded);
        }
    }

    #[test]
    fn grype_scan_summarizes_real_findings_from_a_generated_sbom() {
        let (_d, ctx) = repo_with_vulnerable_npm_package();
        let cfg = ctx.require_config().unwrap();
        if !tools::is_available("syft") || !tools::is_available("grype") {
            return; // both tool-missing branches are covered elsewhere
        }
        let sbom_path = generate(&ctx, cfg, None).unwrap();
        let (count, summaries) = grype_scan(&ctx, &sbom_path).unwrap();
        assert!(
            count > 0,
            "the planted lodash 4.17.4 dependency carries known CVEs"
        );
        assert!(!summaries.is_empty());
        assert!(summaries.len() <= count);
        assert!(summaries.len() <= 20, "summaries are capped for display");
        // "<vuln-id> <artifact> (<severity>)" — every summary line is built
        // from the same three pointer lookups.
        assert!(summaries
            .iter()
            .all(|s| s.contains(" (") && s.ends_with(')')));
    }

    #[test]
    fn grype_scan_errors_loudly_instead_of_a_false_clean_when_the_sbom_is_missing() {
        let (_d, ctx) = fresh_bootstrapped_repo();
        if !tools::is_available("grype") {
            return; // covered by the grype-missing branch above
        }
        let missing = ctx.root.join("does-not-exist.cdx.json");
        let err = grype_scan(&ctx, &missing).unwrap_err();
        assert!(format!("{err:#}").contains("grype output not JSON"));
    }
}
