//! Machine-readable compliance map (control → SLSA v1.2 / NIST SSDF v1.2 /
//! EU CRA / OpenSSF Badge) and the `sscsb report` renderer. The map is
//! embedded at compile time so the report never depends on network or cwd.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{self, Outcome, VerifyResult};
use anyhow::{Context as _, Result};

pub const COMPLIANCE_MAP_JSON: &str = include_str!("../templates/compliance/map.json");

pub fn map() -> Result<serde_json::Value> {
    serde_json::from_str(COMPLIANCE_MAP_JSON).context("embedded compliance map is invalid JSON")
}

/// Is a control enabled, from config with registry-default fallback?
fn enabled(cfg: Option<&Config>, id: &str, default: bool) -> bool {
    cfg.and_then(|c| c.control_enabled(id)).unwrap_or(default)
}

/// Render the human-readable coverage report.
pub fn render_report(ctx: &Ctx) -> Result<String> {
    let map = map()?;
    let cfg = ctx.config.as_ref();
    let mut out = String::new();
    out.push_str("SSCS Bootstrapper — control → framework coverage\n");
    out.push_str(
        "frameworks: SLSA v1.2 (Build L3 + Source L3) · NIST SSDF v1.2 · EU CRA · OSPS Baseline · OpenSSF Badge\n\n",
    );
    for phase in 1..=5u8 {
        out.push_str(&format!("Phase {phase}\n"));
        for def in controls::phase_controls(phase) {
            let entry = &map["controls"][def.id];
            let state = if enabled(cfg, def.id, def.default_enabled) {
                "ENABLED "
            } else {
                "disabled"
            };
            out.push_str(&format!("  [{state}] {} — {}\n", def.id, def.name));
            for (key, label) in [
                ("slsa", "SLSA"),
                ("ssdf", "SSDF"),
                ("cra", "CRA "),
                ("osps", "OSPS"),
                ("badge", "Badge"),
            ] {
                let items: Vec<&str> = entry[key]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                if !items.is_empty() {
                    out.push_str(&format!("      {label}: {}\n", items.join("; ")));
                }
            }
        }
        out.push('\n');
    }
    let total = controls::CONTROLS.len();
    let on = controls::CONTROLS
        .iter()
        .filter(|d| enabled(cfg, d.id, d.default_enabled))
        .count();
    out.push_str(&format!(
        "{on}/{total} controls enabled. JSON: `sscsb report --format json`\n"
    ));
    Ok(out)
}

/// Machine-readable report: the compliance map merged with live enabled state.
pub fn render_report_json(ctx: &Ctx) -> Result<String> {
    let mut map = map()?;
    let cfg = ctx.config.as_ref();
    if let Some(entries) = map["controls"].as_object_mut() {
        for (id, entry) in entries {
            let default = controls::control(id)
                .map(|d| d.default_enabled)
                .unwrap_or(false);
            entry["enabled"] = serde_json::Value::Bool(enabled(cfg, id, default));
        }
    }
    Ok(serde_json::to_string_pretty(&map)?)
}

pub fn verify_compliance_control(_ctx: &Ctx) -> VerifyResult {
    match map() {
        Err(err) => VerifyResult::new("compliance-map", Outcome::Fail, vec![format!("{err:#}")]),
        Ok(m) => {
            let missing: Vec<&str> = controls::CONTROLS
                .iter()
                .map(|d| d.id)
                .filter(|id| m["controls"].get(*id).is_none())
                .collect();
            if missing.is_empty() {
                VerifyResult::new(
                    "compliance-map",
                    Outcome::Pass,
                    vec![format!(
                        "map covers all {} controls across SLSA/SSDF/CRA/Badge",
                        controls::CONTROLS.len()
                    )],
                )
            } else {
                VerifyResult::new(
                    "compliance-map",
                    Outcome::Fail,
                    vec![format!("map missing controls: {}", missing.join(", "))],
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_map_parses_and_covers_every_control() {
        let m = map().expect("map must parse");
        for def in controls::CONTROLS {
            let entry = m["controls"].get(def.id);
            assert!(
                entry.is_some(),
                "control {} missing from compliance map",
                def.id
            );
            let entry = entry.unwrap();
            // Every control must map to at least one of slsa/ssdf/cra.
            let mapped = ["slsa", "ssdf", "cra"]
                .iter()
                .any(|k| entry[*k].as_array().is_some_and(|a| !a.is_empty()));
            assert!(mapped, "control {} has no framework mappings", def.id);
            assert_eq!(
                entry["phase"].as_u64(),
                Some(u64::from(def.phase)),
                "phase mismatch for {}",
                def.id
            );
        }
    }

    #[test]
    fn map_has_no_orphan_controls() {
        let m = map().unwrap();
        for (id, _) in m["controls"].as_object().unwrap() {
            assert!(
                controls::control(id).is_some(),
                "compliance map entry `{id}` has no registered control"
            );
        }
    }

    #[test]
    fn frameworks_block_names_all_five() {
        let m = map().unwrap();
        for fw in ["slsa", "ssdf", "cra", "osps", "badge"] {
            assert!(m["frameworks"].get(fw).is_some(), "missing framework {fw}");
        }
    }

    fn init_repo(dir: &std::path::Path) {
        let out = crate::exec::run("git", &["init", "-b", "main"], Some(dir)).unwrap();
        assert!(out.success());
    }

    fn ctx_with_config(dir: &std::path::Path) -> Ctx {
        init_repo(dir);
        std::fs::create_dir_all(dir.join(".sscsb")).unwrap();
        std::fs::write(
            dir.join(".sscsb/config.toml"),
            crate::config::default_config_toml(None),
        )
        .unwrap();
        Ctx::discover(dir).unwrap()
    }

    #[test]
    fn render_report_lists_every_phase_and_the_live_enabled_state() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_config(dir.path());
        let text = render_report(&ctx).unwrap();
        for marker in [
            "Phase 1",
            "Phase 5",
            "SLSA",
            "SSDF",
            "CRA ",
            "Badge",
            "controls enabled",
            "[ENABLED ] secrets",
        ] {
            assert!(text.contains(marker), "report missing `{marker}`: {text}");
        }
        // A disabled control renders with the "disabled" state, not "ENABLED".
        assert!(text.contains("[disabled] grype"), "{text}");
    }

    #[test]
    fn render_report_falls_back_to_registry_defaults_without_a_loaded_config() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let ctx = Ctx::discover(dir.path()).unwrap();
        assert!(ctx.config.is_none());
        let text = render_report(&ctx).unwrap();
        assert!(text.contains("[ENABLED ] secrets"), "{text}");
        assert!(text.contains("[disabled] grype"), "{text}");

        let json: serde_json::Value =
            serde_json::from_str(&render_report_json(&ctx).unwrap()).unwrap();
        assert_eq!(json["controls"]["secrets"]["enabled"], true);
        assert_eq!(json["controls"]["grype"]["enabled"], false);
    }

    #[test]
    fn render_report_json_reflects_a_config_override() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_config(dir.path());
        crate::config::set_control_enabled(&ctx.config_path(), "grype", true).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&render_report_json(&ctx).unwrap()).unwrap();
        assert_eq!(json["controls"]["grype"]["enabled"], true);
        assert_eq!(json["controls"]["witness"]["enabled"], false);
        assert!(json["controls"]["slsa-provenance"]["slsa"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("Build L3")));
    }

    #[test]
    fn verify_compliance_control_passes_when_the_embedded_map_covers_every_control() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_config(dir.path());
        let result = verify_compliance_control(&ctx);
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result.messages[0].contains(&controls::CONTROLS.len().to_string()));
    }
}
