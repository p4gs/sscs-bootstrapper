//! Declarative configuration: `.sscsb/config.toml` is the single source of
//! truth for which controls are enabled and how they behave. The default
//! config is GENERATED from the control registry, so config keys and controls
//! cannot drift. Enable/disable edits preserve user comments via toml_edit.

use crate::controls::CONTROLS;
use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Config {
    table: toml::Table,
    pub path: PathBuf,
}

impl Config {
    /// Load `.sscsb/config.toml` under `repo_root` if it exists.
    pub fn load(repo_root: &Path) -> Result<Option<Self>> {
        let path = repo_root.join(".sscsb").join("config.toml");
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let table: toml::Table = text
            .parse()
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(Config { table, path }))
    }

    fn control_table(&self, id: &str) -> Option<&toml::Table> {
        self.table.get("controls")?.as_table()?.get(id)?.as_table()
    }

    /// Whether a control is enabled. `None` when the section is absent
    /// (caller falls back to the registry default).
    pub fn control_enabled(&self, id: &str) -> Option<bool> {
        self.control_table(id)?.get("enabled")?.as_bool()
    }

    pub fn control_opt_bool(&self, id: &str, key: &str) -> Option<bool> {
        self.control_table(id)?.get(key)?.as_bool()
    }

    pub fn control_opt_str(&self, id: &str, key: &str) -> Option<String> {
        Some(self.control_table(id)?.get(key)?.as_str()?.to_string())
    }

    pub fn protected_branches(&self) -> Vec<String> {
        self.table
            .get("general")
            .and_then(|g| g.as_table())
            .and_then(|g| g.get("protected_branches"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| vec!["main".to_string(), "master".to_string()])
    }

    /// Fail-open is a deliberate, visible weakening; secure default is false.
    pub fn fail_open(&self) -> bool {
        self.table
            .get("general")
            .and_then(|g| g.as_table())
            .and_then(|g| g.get("fail_open"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    }

    pub fn github_repo(&self) -> Option<String> {
        self.table
            .get("general")
            .and_then(|g| g.as_table())
            .and_then(|g| g.get("github_repo"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }
}

/// Flip `controls.<id>.enabled` in place, preserving comments/layout.
/// Returns an error naming valid ids when `id` is unknown.
pub fn set_control_enabled(config_path: &Path, id: &str, enabled: bool) -> Result<()> {
    if crate::controls::control(id).is_none() {
        let ids: Vec<&str> = CONTROLS.iter().map(|c| c.id).collect();
        anyhow::bail!("unknown control `{id}`. Valid controls: {}", ids.join(", "));
    }
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("parsing {}", config_path.display()))?;
    let controls = doc
        .entry("controls")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let section = controls
        .as_table_mut()
        .context("`controls` is not a table")?
        .entry(id)
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    section
        .as_table_mut()
        .with_context(|| format!("`controls.{id}` is not a table"))?
        .insert("enabled", toml_edit::value(enabled));
    std::fs::write(config_path, doc.to_string())
        .with_context(|| format!("writing {}", config_path.display()))?;
    Ok(())
}

/// Generate the default commented config from the control registry.
pub fn default_config_toml(repo_slug: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(
        "# SSCS Bootstrapper configuration — the single source of truth for which\n\
         # controls are enabled. Every control is independently toggleable here;\n\
         # no code changes required. Secure defaults are ON; optional integrations\n\
         # that need external services or extra tooling are OFF.\n\
         #\n\
         # Toggle:   sscsb enable <control> | sscsb disable <control>\n\
         # Inspect:  sscsb status | sscsb verify | sscsb report\n\n",
    );
    out.push_str("[general]\n");
    out.push_str("# Branches where human-only signing and merge policy are enforced.\n");
    out.push_str("protected_branches = [\"main\", \"master\"]\n");
    out.push_str(
        "# fail_open = true would let hooks pass when scanners are missing. Keep false.\n",
    );
    out.push_str("fail_open = false\n");
    match repo_slug {
        Some(slug) => {
            let _ = writeln!(out, "github_repo = \"{slug}\"");
        }
        None => out.push_str("# github_repo = \"owner/repo\"  # set to enable GitHub API checks\n"),
    }
    out.push('\n');

    let mut phase = 0u8;
    for c in CONTROLS {
        if c.phase != phase {
            phase = c.phase;
            let title = match phase {
                1 => "Phase 1 — Local source integrity",
                2 => "Phase 2 — Dependency & vulnerability visibility",
                3 => "Phase 3 — Provenance, signing & credential federation",
                4 => "Phase 4 — Deeper code security & CI hardening",
                _ => "Phase 5 — Observability & governance",
            };
            let _ = writeln!(out, "# ── {title} ──\n");
        }
        let _ = writeln!(out, "# {}: {}", c.name, c.summary);
        let _ = writeln!(out, "[controls.{}]", c.id);
        let _ = writeln!(out, "enabled = {}", c.default_enabled);
        for (k, v) in c.default_options {
            let _ = writeln!(out, "{k} = {v}");
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_default() -> toml::Table {
        default_config_toml(Some("owner/repo")).parse().unwrap()
    }

    #[test]
    fn default_config_parses_and_covers_every_control() {
        let t = parsed_default();
        let controls = t.get("controls").unwrap().as_table().unwrap();
        for c in CONTROLS {
            let section = controls
                .get(c.id)
                .unwrap_or_else(|| panic!("control {} missing from default config", c.id))
                .as_table()
                .unwrap();
            assert_eq!(
                section.get("enabled").unwrap().as_bool().unwrap(),
                c.default_enabled,
                "default enabled mismatch for {}",
                c.id
            );
            for (k, _) in c.default_options {
                assert!(
                    section.contains_key(*k),
                    "option {k} missing for control {}",
                    c.id
                );
            }
        }
    }

    #[test]
    fn default_config_is_fail_closed_with_protected_branches() {
        let t = parsed_default();
        let general = t.get("general").unwrap().as_table().unwrap();
        assert_eq!(general.get("fail_open").unwrap().as_bool(), Some(false));
        let branches = general
            .get("protected_branches")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(branches.iter().any(|b| b.as_str() == Some("main")));
    }

    #[test]
    fn enable_disable_round_trip_preserves_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, default_config_toml(None)).unwrap();

        set_control_enabled(&path, "secrets", false).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("# SSCS Bootstrapper configuration"),
            "comments lost"
        );
        let t: toml::Table = text.parse().unwrap();
        assert_eq!(t["controls"]["secrets"]["enabled"].as_bool(), Some(false));

        set_control_enabled(&path, "secrets", true).unwrap();
        let t: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(t["controls"]["secrets"]["enabled"].as_bool(), Some(true));
    }

    #[test]
    fn unknown_control_rejected_with_valid_ids_listed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, default_config_toml(None)).unwrap();
        let err = set_control_enabled(&path, "not-a-control", true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown control"));
        assert!(msg.contains("secrets"));
    }

    #[test]
    fn config_accessors_read_generated_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let sscsb = dir.path().join(".sscsb");
        std::fs::create_dir_all(&sscsb).unwrap();
        std::fs::write(sscsb.join("config.toml"), default_config_toml(Some("o/r"))).unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.control_enabled("secrets"), Some(true));
        assert_eq!(cfg.control_enabled("grype"), Some(false));
        assert_eq!(cfg.control_opt_bool("secrets", "trufflehog"), Some(true));
        assert_eq!(
            cfg.control_opt_str("sbom", "format").as_deref(),
            Some("cyclonedx-json")
        );
        assert_eq!(cfg.github_repo().as_deref(), Some("o/r"));
        assert!(!cfg.fail_open());
    }

    #[test]
    fn missing_config_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Config::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn loading_an_unparseable_config_file_is_a_reported_error() {
        let dir = tempfile::tempdir().unwrap();
        let sscsb = dir.path().join(".sscsb");
        std::fs::create_dir_all(&sscsb).unwrap();
        std::fs::write(sscsb.join("config.toml"), "not [ valid toml").unwrap();
        let err = Config::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("parsing"));
    }

    #[test]
    fn protected_branches_reads_a_custom_list_and_falls_back_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let sscsb = dir.path().join(".sscsb");
        std::fs::create_dir_all(&sscsb).unwrap();

        std::fs::write(sscsb.join("config.toml"), default_config_toml(None)).unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.protected_branches(),
            vec!["main".to_string(), "master".to_string()]
        );

        // No `[general]` section at all: falls back to the same secure default.
        std::fs::write(sscsb.join("config.toml"), "# nothing here\n").unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.protected_branches(),
            vec!["main".to_string(), "master".to_string()]
        );

        // A custom list is honored verbatim, including a single branch.
        std::fs::write(
            sscsb.join("config.toml"),
            "[general]\nprotected_branches = [\"release\"]\n",
        )
        .unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.protected_branches(), vec!["release".to_string()]);
    }

    #[test]
    fn github_repo_is_none_when_commented_out_or_blank() {
        let dir = tempfile::tempdir().unwrap();
        let sscsb = dir.path().join(".sscsb");
        std::fs::create_dir_all(&sscsb).unwrap();

        // default_config_toml(None) emits `# github_repo = "owner/repo"` —
        // a comment, not a live key.
        std::fs::write(sscsb.join("config.toml"), default_config_toml(None)).unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.github_repo(), None);

        std::fs::write(sscsb.join("config.toml"), "[general]\ngithub_repo = \"\"\n").unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.github_repo(), None, "blank value must be filtered out");
    }

    #[test]
    fn fail_open_falls_back_to_false_when_the_key_or_section_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let sscsb = dir.path().join(".sscsb");
        std::fs::create_dir_all(&sscsb).unwrap();
        std::fs::write(sscsb.join("config.toml"), "# nothing here\n").unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert!(!cfg.fail_open());
    }

    #[test]
    fn set_control_enabled_creates_a_missing_controls_section_from_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // No pre-existing `[controls]` table at all: `set_control_enabled`
        // must create the section, not just flip an existing key.
        std::fs::write(&path, "[general]\nfail_open = false\n").unwrap();
        set_control_enabled(&path, "secrets", true).unwrap();
        let t: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(t["controls"]["secrets"]["enabled"].as_bool(), Some(true));
    }
}
