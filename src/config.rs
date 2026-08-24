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
    /// Keys sscsb does not recognize. Not fatal — a config written by another
    /// version of sscsb must keep working — but said out loud, because the far
    /// likelier cause is a typo that silently does nothing.
    pub warnings: Vec<String>,
}

/// `[general]` keys and the TOML type each must have.
const GENERAL_KEYS: &[(&str, &str)] = &[
    ("protected_branches", "array"),
    ("fail_open", "boolean"),
    ("github_repo", "string"),
];

/// The type the registry's own default for an option has. Deriving the
/// expectation from the same literal that GENERATES the config is what keeps
/// the validator and the generated file from drifting apart.
fn expected_option_value(literal: &str) -> Option<toml::Value> {
    let table: toml::Table = format!("v = {literal}").parse().ok()?;
    table.get("v").cloned()
}

/// "a" or "an" for a TOML type name (`integer` and `array` take "an").
fn article(type_name: &str) -> &'static str {
    match type_name.chars().next() {
        Some('a' | 'e' | 'i' | 'o' | 'u') => "an",
        _ => "a",
    }
}

/// The offending value, quoted back at the reader so the message names what is
/// actually in their file — `"false"` reads very differently from `false`.
fn render(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => format!("{s:?}"),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => d.to_string(),
        toml::Value::Array(_) => "[…]".to_string(),
        toml::Value::Table(_) => "{…}".to_string(),
    }
}

/// Everything wrong with a parsed config, split into what must stop the run and
/// what is only worth saying out loud.
#[derive(Default)]
struct Inspection {
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl Inspection {
    /// A known key holding the wrong TOML type. Unambiguous, and silently
    /// wrong: `enabled = "false"` is a *string*, so the bool accessor returns
    /// None, the caller falls back to the registry default — `true` for most
    /// controls — and the user who thought they turned a control off is still
    /// running it.
    fn check_type(&mut self, path: &str, expected: &str, found: &toml::Value) {
        if found.type_str() != expected {
            self.errors.push(format!(
                "{path} must be {} {expected}, found {} ({})",
                article(expected),
                found.type_str(),
                render(found)
            ));
            return;
        }
        // A list option whose registry default is strings must stay strings:
        // the accessor filters non-strings out, so `["a", 1]` silently becomes
        // a one-element list.
        if let toml::Value::Array(items) = found {
            for (i, item) in items.iter().enumerate() {
                if !item.is_str() {
                    self.errors.push(format!(
                        "{path}[{i}] must be a string, found {}",
                        item.type_str()
                    ));
                }
            }
        }
    }
}

/// Type- and key-check a parsed config against the control registry.
fn inspect(table: &toml::Table) -> Inspection {
    let mut out = Inspection::default();
    for key in table.keys() {
        if key != "general" && key != "controls" {
            out.warnings
                .push(format!("`{key}` is not a section sscsb reads — ignored"));
        }
    }
    match table.get("general") {
        None => {}
        Some(toml::Value::Table(general)) => {
            for (key, value) in general {
                match GENERAL_KEYS.iter().find(|(k, _)| k == key) {
                    Some((_, expected)) => {
                        out.check_type(&format!("general.{key}"), expected, value)
                    }
                    None => out.warnings.push(format!(
                        "general.{key} is not a setting sscsb reads — ignored"
                    )),
                }
            }
        }
        Some(other) => out.errors.push(format!(
            "`general` must be a table (`[general]`), found {}",
            other.type_str()
        )),
    }
    let controls = match table.get("controls") {
        None => return out,
        Some(toml::Value::Table(controls)) => controls,
        Some(other) => {
            out.errors.push(format!(
                "`controls` must be a table, found {}",
                other.type_str()
            ));
            return out;
        }
    };
    for (id, section) in controls {
        // An unknown control section is the forward/backward-compatible case —
        // a config written by a version of sscsb with a control this binary
        // does not have. Legal, but worth naming: the other way to get here is
        // a misspelt id, which silently configures nothing.
        let Some(def) = crate::controls::control(id) else {
            out.warnings.push(format!(
                "controls.{id} is not a control this sscsb knows — ignored (check the \
                 spelling against `sscsb status`)"
            ));
            continue;
        };
        let Some(section) = section.as_table() else {
            out.errors.push(format!(
                "controls.{id} must be a table (`[controls.{id}]`), found {}",
                section.type_str()
            ));
            continue;
        };
        for (key, value) in section {
            let path = format!("controls.{id}.{key}");
            if key == "enabled" {
                out.check_type(&path, "boolean", value);
                continue;
            }
            match def
                .default_options
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, literal)| expected_option_value(literal))
            {
                Some(expected) => out.check_type(&path, expected.type_str(), value),
                None => out
                    .warnings
                    .push(format!("{path} is not an option of `{id}` — ignored")),
            }
        }
    }
    out
}

impl Config {
    /// Load `.sscsb/config.toml` under `repo_root` if it exists.
    ///
    /// A key that is *absent* is always legal — the config is generated from
    /// the registry and `sscsb init` never overwrites an existing one, so every
    /// config written by an older sscsb is missing whatever has been added
    /// since, and the caller falls back to the registry default. A key that is
    /// PRESENT with the wrong type is a different thing entirely, and is an
    /// error rather than a silent fallback.
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
        let found = inspect(&table);
        if !found.errors.is_empty() {
            anyhow::bail!(
                "{} has {} invalid value(s):\n  {}\n\
                 fix them, or use `sscsb enable <control>` / `sscsb disable <control>`, \
                 which always write the right type",
                path.display(),
                found.errors.len(),
                found.errors.join("\n  ")
            );
        }
        for warning in &found.warnings {
            eprintln!("sscsb: {}: {warning}", path.display());
        }
        Ok(Some(Config {
            table,
            path,
            warnings: found.warnings,
        }))
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

    /// A control option that is a TOML array of strings (e.g. `allowed_backends`).
    /// `None` when the key is absent; an empty vec when it is present-but-empty.
    pub fn control_opt_str_list(&self, id: &str, key: &str) -> Option<Vec<String>> {
        Some(
            self.control_table(id)?
                .get(key)?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        )
    }

    /// A control option that is a TOML integer (e.g. `max_key_age_days`).
    pub fn control_opt_int(&self, id: &str, key: &str) -> Option<i64> {
        self.control_table(id)?.get(key)?.as_integer()
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

    /// Write `body` as a repo's config and load it.
    fn load_config(body: &str) -> (tempfile::TempDir, Result<Option<Config>>) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".sscsb")).unwrap();
        std::fs::write(dir.path().join(".sscsb/config.toml"), body).unwrap();
        let loaded = Config::load(dir.path());
        (dir, loaded)
    }

    /// Regression (M24): `enabled = "false"` is a STRING, so `as_bool()`
    /// returned None, the caller fell back to the registry default — `true` for
    /// most controls — and a user who believed they had turned secret scanning
    /// off was still running it. The wrong type on a known key is unambiguous
    /// and must be an error, never a silent fallback to the opposite meaning.
    #[test]
    fn a_wrong_typed_enabled_is_an_error_not_a_silent_fallback() {
        let (_d, loaded) = load_config("[controls.secrets]\nenabled = \"false\"\n");
        let err = format!("{:#}", loaded.unwrap_err());
        assert!(err.contains("controls.secrets.enabled"), "{err}");
        assert!(err.contains("must be a boolean"), "{err}");
        // The message quotes the value back, because `"false"` and `false`
        // differ by exactly the thing that went wrong.
        assert!(err.contains("found string (\"false\")"), "{err}");
        assert!(err.contains("sscsb disable"), "{err}");

        // The same key with the right type is fine, and MEANS what it says.
        let (_d, loaded) = load_config("[controls.secrets]\nenabled = false\n");
        let cfg = loaded.unwrap().unwrap();
        assert_eq!(cfg.control_enabled("secrets"), Some(false));
    }

    /// Options carry types too, and a list option whose elements are silently
    /// filtered out is the same bug wearing a different hat.
    #[test]
    fn wrong_typed_options_and_list_elements_are_errors() {
        let (_d, loaded) =
            load_config("[controls.agent-signing]\nenabled = true\nmax_key_age_days = \"90\"\n");
        let err = format!("{:#}", loaded.unwrap_err());
        assert!(
            err.contains("controls.agent-signing.max_key_age_days must be an integer"),
            "{err}"
        );

        // `allowed_backends` is an array of strings in the registry; a numeric
        // element would be dropped by the accessor without a word.
        let (_d, loaded) =
            load_config("[controls.agent-signing]\nallowed_backends = [\"tpm\", 7]\n");
        let err = format!("{:#}", loaded.unwrap_err());
        assert!(
            err.contains("controls.agent-signing.allowed_backends[1] must be a string"),
            "{err}"
        );

        // `[general]` is type-checked on the same terms.
        let (_d, loaded) = load_config("[general]\nfail_open = \"yes\"\n");
        let err = format!("{:#}", loaded.unwrap_err());
        assert!(err.contains("general.fail_open must be a boolean"), "{err}");

        // Every invalid value is reported at once, not one per run.
        let (_d, loaded) = load_config(
            "[general]\nfail_open = 1\n[controls.secrets]\nenabled = \"no\"\ngitleaks = 0\n",
        );
        let err = format!("{:#}", loaded.unwrap_err());
        assert!(err.contains("3 invalid value(s)"), "{err}");
    }

    /// A section or key sscsb does not know is the forward-compatible case — a
    /// config written by another version — so it must still load. It is also
    /// how a typo looks, so it is said out loud rather than swallowed.
    #[test]
    fn unknown_sections_and_keys_warn_but_still_load() {
        let (_d, loaded) = load_config(
            "[general]\nprotectd_brnaches = [\"x\"]\n\
             [controls.secrets]\nenabled = false\ntrufflhog = true\n\
             [controls.not-a-control]\nenabled = true\n\
             [extras]\nfoo = 1\n",
        );
        let cfg = loaded.unwrap().unwrap();
        // Loaded, and the known-good part of the file still works.
        assert_eq!(cfg.control_enabled("secrets"), Some(false));
        let warnings = cfg.warnings.join("\n");
        assert!(warnings.contains("general.protectd_brnaches"), "{warnings}");
        assert!(
            warnings.contains("controls.secrets.trufflhog is not an option of `secrets`"),
            "{warnings}"
        );
        assert!(warnings.contains("controls.not-a-control"), "{warnings}");
        assert!(warnings.contains("`extras` is not a section"), "{warnings}");
        assert_eq!(cfg.warnings.len(), 4, "{warnings}");
    }

    /// A section that is not a table at all cannot be read as one.
    #[test]
    fn sections_that_are_not_tables_are_errors() {
        for (body, expected) in [
            ("controls = 3\n", "`controls` must be a table"),
            ("general = \"x\"\n", "`general` must be a table"),
            (
                "[controls]\nsecrets = 1\n",
                "controls.secrets must be a table",
            ),
        ] {
            let (_d, loaded) = load_config(body);
            let err = format!("{:#}", loaded.unwrap_err());
            assert!(err.contains(expected), "{body} → {err}");
        }
    }

    /// The load-time check must never turn on a config that already works.
    /// `.sscsb/config.toml` is generated from the registry and `sscsb init`
    /// never overwrites an existing one, so a stricter loader meets configs
    /// written by older versions: MISSING is legal, and stays legal.
    #[test]
    fn generated_and_older_configs_load_without_a_single_complaint() {
        for slug in [Some("owner/repo"), None] {
            let (_d, loaded) = load_config(&default_config_toml(slug));
            let cfg = loaded.unwrap().unwrap();
            assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
        }

        // An older config: whole control sections absent, and `[general]`
        // missing keys. Absent is not wrong — the caller falls back to the
        // registry default — so nothing is reported.
        let (_d, loaded) =
            load_config("[general]\nfail_open = false\n[controls.secrets]\nenabled = true\n");
        let cfg = loaded.unwrap().unwrap();
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
        assert_eq!(cfg.control_enabled("secrets"), Some(true));
        assert_eq!(cfg.control_enabled("sbom"), None, "absent stays absent");
        // An empty config is a config.
        let (_d, loaded) = load_config("# nothing here\n");
        assert!(loaded.unwrap().unwrap().warnings.is_empty());
    }

    /// sscsb's own repository config — 36 of 44 registered controls, written by
    /// an older version — must keep loading cleanly and silently.
    #[test]
    fn this_repos_own_config_loads_without_error_or_warning() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let cfg = Config::load(root)
            .expect("sscsb's own config must load")
            .expect("sscsb's own config must exist");
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
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
    fn control_opt_str_list_and_int_read_typed_options() {
        let dir = tempfile::tempdir().unwrap();
        let sscsb = dir.path().join(".sscsb");
        std::fs::create_dir_all(&sscsb).unwrap();
        std::fs::write(
            sscsb.join("config.toml"),
            "[controls.agent-signing]\nenabled = true\nallowed_backends = [\"github-app\", \"tpm\"]\nempty_backends = []\nmax_key_age_days = 90\n",
        )
        .unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.control_opt_str_list("agent-signing", "allowed_backends"),
            Some(vec!["github-app".to_string(), "tpm".to_string()])
        );
        // Present-but-empty array is Some(vec![]), distinct from an absent key.
        assert_eq!(
            cfg.control_opt_str_list("agent-signing", "empty_backends"),
            Some(Vec::<String>::new())
        );
        assert_eq!(
            cfg.control_opt_str_list("agent-signing", "absent_key"),
            None
        );
        assert_eq!(
            cfg.control_opt_int("agent-signing", "max_key_age_days"),
            Some(90)
        );
        assert_eq!(cfg.control_opt_int("agent-signing", "absent_key"), None);
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
