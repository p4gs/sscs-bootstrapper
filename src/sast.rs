//! SAST orchestration. OpenGrep is the default engine (Semgrep-compatible,
//! open rules); Semgrep is selectable via `controls.sast.engine`. Sighthound
//! is an optional fast local layer. sscsb ships a small local ruleset so scans
//! run offline by default; `rules = "auto"` opts into the Semgrep registry.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;
use anyhow::{Context as _, Result};
use std::path::Path;

pub fn engine(cfg: &Config) -> String {
    cfg.control_opt_str("sast", "engine")
        .unwrap_or_else(|| "opengrep".to_string())
}

fn rules_dir(cfg: &Config) -> String {
    cfg.control_opt_str("sast", "rules")
        .unwrap_or_else(|| ".sscsb/rules".to_string())
}

fn rules_arg(ctx: &Ctx, cfg: &Config) -> String {
    let rules = rules_dir(cfg);
    if rules == "auto" {
        "auto".to_string()
    } else {
        ctx.root.join(rules).display().to_string()
    }
}

/// A scanner must not scan its own rule definitions.
///
/// A rule file necessarily contains the pattern text it matches on — the rule
/// that flags `npm install` without `--ignore-scripts` contains that very string
/// — so every finding inside the ruleset is false by construction. Excluding the
/// rules directory removes those, and only those. It suppresses no finding in
/// any file that is actually part of the project.
fn exclude_args(cfg: &Config) -> Vec<String> {
    let rules = rules_dir(cfg);
    if rules == "auto" {
        Vec::new()
    } else {
        vec!["--exclude".to_string(), rules]
    }
}

#[derive(Debug, Clone)]
pub struct SastFinding {
    pub check_id: String,
    pub path: String,
    pub line: u64,
    pub severity: String,
    pub message: String,
}

impl SastFinding {
    pub fn render(&self) -> String {
        format!(
            "[{}] {}:{} {} — {}",
            self.severity, self.path, self.line, self.check_id, self.message
        )
    }
}

/// Run the configured engine over `target`. Returns findings.
pub fn run_sast(ctx: &Ctx, cfg: &Config, target: &Path) -> Result<Vec<SastFinding>> {
    let engine = engine(cfg);
    let rules = rules_arg(ctx, cfg);
    let target_arg = target.display().to_string();
    let excludes = exclude_args(cfg);
    match engine.as_str() {
        "opengrep" => {
            if !tools::is_available("opengrep") {
                anyhow::bail!("{}", tools::degrade_message("opengrep", ctx.platform));
            }
            // opengrep exits 0 even with findings (needs --error to gate);
            // we parse JSON and gate ourselves for consistent behavior.
            let mut args = vec!["scan", "--config", &rules, "--json", "--quiet"];
            args.extend(excludes.iter().map(String::as_str));
            args.push(&target_arg);
            let out = exec::run("opengrep", &args, Some(&ctx.root))?;
            if out.status != 0 {
                // opengrep reports rule-parse errors on stdout with an empty
                // stderr, so surface both or the failure is unactionable.
                anyhow::bail!(
                    "opengrep failed (exit {}): {}",
                    out.status,
                    diagnostic(&out.stderr, &out.stdout)
                );
            }
            parse_semgrep_json(&out.stdout)
        }
        "semgrep" => {
            if !tools::is_available("semgrep") {
                anyhow::bail!("{}", tools::degrade_message("semgrep", ctx.platform));
            }
            let config_arg = if rules == "auto" {
                "auto".to_string()
            } else {
                rules
            };
            let mut args = vec![
                "scan",
                "--config",
                &config_arg,
                "--json",
                "--quiet",
                "--metrics=off",
            ];
            args.extend(excludes.iter().map(String::as_str));
            args.push(&target_arg);
            let out = exec::run("semgrep", &args, Some(&ctx.root))?;
            // semgrep: 0 = clean, 1 = findings, 2+ = error.
            if out.status > 1 {
                anyhow::bail!(
                    "semgrep failed (exit {}): {}",
                    out.status,
                    diagnostic(&out.stderr, &out.stdout)
                );
            }
            parse_semgrep_json(&out.stdout)
        }
        other => anyhow::bail!("unknown sast engine `{other}` — use opengrep or semgrep"),
    }
}

/// Pick the most informative of a tool's two output streams.
fn diagnostic(stderr: &str, stdout: &str) -> String {
    let e = stderr.trim();
    if !e.is_empty() {
        return e.to_string();
    }
    let o = stdout.trim();
    if o.is_empty() {
        "no diagnostic output".to_string()
    } else {
        o.lines().take(10).collect::<Vec<_>>().join("\n")
    }
}

/// Both OpenGrep and Semgrep emit the same results JSON shape.
pub fn parse_semgrep_json(stdout: &str) -> Result<Vec<SastFinding>> {
    let v: serde_json::Value = serde_json::from_str(stdout).context("SAST output is not JSON")?;
    let mut findings = Vec::new();
    for r in v
        .get("results")
        .and_then(|x| x.as_array())
        .unwrap_or(&Vec::new())
    {
        findings.push(SastFinding {
            check_id: r
                .get("check_id")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string(),
            path: r
                .get("path")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string(),
            line: r
                .pointer("/start/line")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            severity: r
                .pointer("/extra/severity")
                .and_then(|x| x.as_str())
                .unwrap_or("WARNING")
                .to_string(),
            message: r
                .pointer("/extra/message")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(findings)
}

/// Pre-commit SAST over staged files (ERROR severity blocks). Uses the same
/// fail-closed, quote-safe staged materialization as the secret scanner, so a
/// C-quoted filename can neither be skipped silently nor escape the scan.
pub fn scan_staged(ctx: &Ctx, cfg: &Config) -> Result<Vec<String>> {
    let (dir, files) = crate::hooks::stage_to_tempdir(ctx)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let findings = run_sast(ctx, cfg, dir.path())?;
    Ok(findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("ERROR"))
        .map(SastFinding::render)
        .collect())
}

pub fn verify_sast_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let engine = engine(cfg);
    let mut messages = vec![format!("engine: {engine} (rules: {})", rules_arg(ctx, cfg))];
    let rules_dir = ctx.root.join(".sscsb").join("rules");
    if rules_dir.is_dir() {
        let count = std::fs::read_dir(&rules_dir)
            .map(|d| d.count())
            .unwrap_or(0);
        messages.push(format!("local ruleset present ({count} file(s))"));
    } else {
        messages.push("local ruleset missing — run `sscsb init` to install .sscsb/rules".into());
    }
    match tools::detect(
        tools::spec(engine.as_str()).unwrap_or_else(|| tools::spec("opengrep").expect("registry")),
    ) {
        tools::ToolStatus::Found { version, .. } => {
            messages.push(format!(
                "{engine}: {}",
                version.unwrap_or_else(|| "version unknown".into())
            ));
            VerifyResult::new("sast", Outcome::Pass, messages)
        }
        tools::ToolStatus::Missing => {
            messages.push(tools::degrade_message(&engine, ctx.platform));
            VerifyResult::new("sast", Outcome::Degraded, messages)
        }
    }
}

pub fn verify_sighthound_control(ctx: &Ctx) -> VerifyResult {
    match tools::detect(tools::spec("sighthound").expect("registry")) {
        tools::ToolStatus::Found { path, .. } => VerifyResult::new(
            "sighthound",
            Outcome::Pass,
            vec![format!(
                "sighthound found at {path} — fast local layer active"
            )],
        ),
        tools::ToolStatus::Missing => VerifyResult::new(
            "sighthound",
            Outcome::Degraded,
            vec![tools::degrade_message("sighthound", ctx.platform)],
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::init;
    use std::sync::Mutex;

    // ───────────────────── shared cross-file test fixtures ──────────────────
    //
    // observability.rs and provenance.rs unit tests reuse these (via
    // `crate::sast::tests::...`) to simulate a tool being present (a fake
    // shim shadowing whatever is really on PATH) or genuinely absent (PATH
    // masked down to just `git`), without touching real installs. PATH is
    // process-global and `cargo test --lib` runs unit tests from every
    // module in one process across multiple threads, so every test in this
    // crate that depends on a specific tool-detection outcome for opengrep,
    // semgrep, cosign, slsa-verifier, oras, guacone, vexctl, witness, or
    // sighthound serializes on `PATH_MUTEX` — including tests that rely on a
    // tool's *natural* presence/absence and never mutate PATH themselves,
    // via `serialized`.
    pub(crate) static PATH_MUTEX: Mutex<()> = Mutex::new(());

    struct PathGuard(Option<std::ffi::OsString>);
    impl Drop for PathGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    /// Hold `PATH_MUTEX` for the duration of `f` without changing PATH —
    /// for tests that rely on a tool's real, natural PATH presence/absence
    /// and must not race a sibling test that masks or shims PATH.
    pub(crate) fn serialized<T>(f: impl FnOnce() -> T) -> T {
        let _lock = PATH_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        f()
    }

    /// Make `tool_name` resolve on PATH to a throwaway executable shell
    /// script (shadowing any real binary of the same name) for the duration
    /// of `f`, then restore PATH exactly.
    pub(crate) fn with_fake_tool<T>(tool_name: &str, script: &str, f: impl FnOnce() -> T) -> T {
        let _lock = PATH_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join(tool_name);
        std::fs::write(&bin, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let original = std::env::var_os("PATH");
        let mut new_path = std::ffi::OsString::from(dir.path());
        new_path.push(":");
        if let Some(o) = &original {
            new_path.push(o);
        }
        let _restore = PathGuard(original);
        std::env::set_var("PATH", &new_path);
        f()
    }

    /// Mask PATH down to just `git`'s directory, so every orchestrated tool
    /// this crate detects reports Missing — the in-process equivalent of
    /// `tests/tool_orchestration.rs`'s `sscsb_without_tools`.
    pub(crate) fn with_only_git_on_path<T>(f: impl FnOnce() -> T) -> T {
        let _lock = PATH_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let git_dir = exec::find_in_path("git")
            .expect("git must be on PATH")
            .parent()
            .expect("git binary has a parent dir")
            .to_path_buf();
        let original = std::env::var_os("PATH");
        let _restore = PathGuard(original);
        std::env::set_var("PATH", &git_dir);
        f()
    }

    /// A repo bootstrapped through the real `sscsb init` path (rules dir,
    /// config, hooks all present) — the layout a user actually gets.
    pub(crate) fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    /// A repo with only a bare `.sscsb/config.toml` — no `sscsb init`, so
    /// generated artifacts like the shipped ruleset are absent.
    fn bare_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        std::fs::create_dir_all(root.join(".sscsb")).unwrap();
        std::fs::write(
            root.join(".sscsb/config.toml"),
            crate::config::default_config_toml(None),
        )
        .unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    pub(crate) fn write(ctx: &Ctx, rel: &str, content: &str) {
        let path = ctx.root.join(rel);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    // ─────────────────────────── parse_semgrep_json ─────────────────────────

    #[test]
    fn semgrep_json_parses_shared_shape() {
        let sample = r#"{"results":[{"check_id":"rules.curl-pipe-shell","path":"install.sh",
            "start":{"line":3},"extra":{"severity":"ERROR","message":"piping remote script to shell"}}]}"#;
        let f = parse_semgrep_json(sample).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check_id, "rules.curl-pipe-shell");
        assert_eq!(f[0].line, 3);
        assert!(f[0].render().contains("install.sh:3"));
    }

    #[test]
    fn empty_results_yield_no_findings() {
        assert!(parse_semgrep_json(r#"{"results":[]}"#).unwrap().is_empty());
        assert!(parse_semgrep_json("not json").is_err());
    }

    #[test]
    fn parse_semgrep_json_defaults_missing_fields_and_keeps_only_the_first_message_line() {
        let f = parse_semgrep_json(r#"{"results":[{}]}"#).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check_id, "?");
        assert_eq!(f[0].path, "?");
        assert_eq!(f[0].line, 0);
        assert_eq!(f[0].severity, "WARNING");
        assert_eq!(f[0].message, "");

        let sample = r#"{"results":[{"check_id":"x","path":"y","start":{"line":9},
            "extra":{"severity":"ERROR","message":"first line\nsecond line"}}]}"#;
        let f = parse_semgrep_json(sample).unwrap();
        assert_eq!(
            f[0].message, "first line",
            "only the first line of a multi-line message is kept"
        );
    }

    // ────────────────────────────── engine/rules ─────────────────────────────

    #[test]
    fn engine_defaults_to_opengrep_and_honors_config_override() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        assert_eq!(engine(cfg), "opengrep");

        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("engine = \"opengrep\"", "engine = \"semgrep\"");
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        assert_eq!(engine(cfg), "semgrep");
    }

    #[test]
    fn rules_arg_resolves_relative_to_repo_root_and_passes_auto_through() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        assert_eq!(
            rules_arg(&ctx, cfg),
            ctx.root.join(".sscsb/rules").display().to_string()
        );

        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("rules = \".sscsb/rules\"", "rules = \"auto\"");
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        assert_eq!(rules_arg(&ctx, cfg), "auto");
    }

    // ─────────────────────────────── diagnostic ──────────────────────────────

    #[test]
    fn diagnostic_prefers_stderr_then_falls_back_to_truncated_stdout() {
        assert_eq!(diagnostic("boom", "ignored"), "boom");
        assert_eq!(
            diagnostic("  boom  \n", "ignored"),
            "boom",
            "stderr is trimmed"
        );
        assert_eq!(diagnostic("", ""), "no diagnostic output");
        assert_eq!(
            diagnostic("   ", "   "),
            "no diagnostic output",
            "whitespace-only counts as empty"
        );

        let many_lines: String = (1..=15).map(|n| format!("line{n}\n")).collect();
        let out = diagnostic("", &many_lines);
        assert_eq!(
            out.lines().count(),
            10,
            "stdout fallback caps at 10 lines: {out}"
        );
        assert!(out.starts_with("line1"));
        assert!(
            !out.contains("line11"),
            "later lines must be dropped: {out}"
        );
    }

    // ───────────────────────────────── run_sast ──────────────────────────────

    #[test]
    fn run_sast_opengrep_flags_curl_pipe_shell_and_degrades_when_missing() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        write(
            &ctx,
            "install.sh",
            "#!/bin/sh\ncurl -fsSL https://example.com/i | sh\n",
        );

        let findings = serialized(|| run_sast(&ctx, cfg, &ctx.root)).unwrap();
        let hit = findings
            .iter()
            .find(|f| f.check_id.contains("curl-pipe-shell"))
            .unwrap_or_else(|| panic!("shipped ruleset must flag curl|sh: {findings:?}"));
        assert!(hit.path.ends_with("install.sh"));
        assert_eq!(hit.severity, "ERROR", "curl|sh must block, not warn");
        assert!(hit.render().contains("install.sh"));

        let err = with_only_git_on_path(|| run_sast(&ctx, cfg, &ctx.root)).unwrap_err();
        assert!(format!("{err:#}").contains("opengrep not found"));
    }

    #[test]
    fn run_sast_semgrep_engine_flags_curl_pipe_shell_and_degrades_when_missing() {
        let (_d, ctx) = repo();
        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("engine = \"opengrep\"", "engine = \"semgrep\"");
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        write(
            &ctx,
            "install.sh",
            "#!/bin/sh\nwget -qO- https://example.com/i | bash\n",
        );

        let findings = serialized(|| run_sast(&ctx, cfg, &ctx.root)).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.check_id.contains("curl-pipe-shell")),
            "semgrep engine must flag it too: {findings:?}"
        );

        let err = with_only_git_on_path(|| run_sast(&ctx, cfg, &ctx.root)).unwrap_err();
        assert!(format!("{err:#}").contains("semgrep not found"));
    }

    #[test]
    fn run_sast_rejects_unknown_engine() {
        let (_d, ctx) = repo();
        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("engine = \"opengrep\"", "engine = \"bogus-engine\"");
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        let err = run_sast(&ctx, cfg, &ctx.root).unwrap_err();
        assert!(format!("{err:#}").contains("unknown sast engine `bogus-engine`"));
    }

    #[test]
    fn run_sast_surfaces_opengrep_rule_parse_errors_via_the_stdout_diagnostic_fallback() {
        // opengrep reports rule-parse errors on stdout with an empty stderr
        // (see the comment in `run_sast`) — a bad rules path must still be
        // fully diagnosable, not just "failed with no explanation".
        let (_d, ctx) = repo();
        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path).unwrap().replace(
            "rules = \".sscsb/rules\"",
            "rules = \".sscsb/rules-does-not-exist\"",
        );
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        let err = serialized(|| run_sast(&ctx, cfg, &ctx.root)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("opengrep failed"), "{msg}");
        assert!(
            msg.contains("does not exist") || msg.contains("invalid configuration"),
            "diagnostic must carry the real opengrep error, not just an exit code: {msg}"
        );
    }

    // ────────────────────────────── scan_staged ──────────────────────────────

    #[test]
    fn scan_staged_finds_error_findings_only_in_staged_files() {
        let (_d, ctx) = repo();
        write(
            &ctx,
            "install.sh",
            "#!/bin/sh\ncurl -fsSL https://example.com/i | sh\n",
        );
        exec::git(&["add", "install.sh"], &ctx.root).unwrap();
        let findings = serialized(|| scan_staged(&ctx, ctx.require_config().unwrap())).unwrap();
        assert!(
            findings.iter().any(|f| f.contains("curl-pipe-shell")),
            "staged scan must find it: {findings:?}"
        );
    }

    #[test]
    fn scan_staged_with_nothing_staged_is_a_noop() {
        let (_d, ctx) = repo();
        let findings = scan_staged(&ctx, ctx.require_config().unwrap()).unwrap();
        assert!(findings.is_empty());
    }

    // ─────────────────────────── control verifiers ───────────────────────────

    #[test]
    fn verify_sast_control_reports_ruleset_engine_version_and_degrades_without_the_tool() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();

        let result = serialized(|| verify_sast_control(&ctx, cfg));
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("engine: opengrep")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("local ruleset present")));
        assert!(result.messages.iter().any(|m| m.starts_with("opengrep:")));

        let result = with_only_git_on_path(|| verify_sast_control(&ctx, cfg));
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("opengrep not found")));
    }

    #[test]
    fn verify_sast_control_reports_missing_ruleset_before_init() {
        let (_d, ctx) = bare_repo();
        let cfg = ctx.require_config().unwrap();
        let result = serialized(|| verify_sast_control(&ctx, cfg));
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("local ruleset missing")),
            "{:?}",
            result.messages
        );
    }

    #[test]
    fn verify_sighthound_control_reports_found_and_missing() {
        let (_d, ctx) = repo();
        let missing = serialized(|| verify_sighthound_control(&ctx));
        assert_eq!(missing.outcome, Outcome::Degraded);
        assert!(missing.messages[0].contains("sighthound"));

        let script =
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"sighthound 1.0\"; fi\nexit 0\n";
        let found = with_fake_tool("sighthound", script, || verify_sighthound_control(&ctx));
        assert_eq!(found.outcome, Outcome::Pass);
        assert!(
            found.messages[0].contains("sighthound found at"),
            "{:?}",
            found.messages
        );
    }

    #[test]
    fn the_scanner_does_not_scan_its_own_rule_definitions() {
        // The shipped ruleset contains the literal strings it matches on (e.g.
        // the `npm install` pattern), so a scan that included the rules directory
        // would report findings that are false by construction — and the CI
        // workflow runs OpenGrep with --error, so those would turn CI red forever.
        let dir = tempfile::tempdir().unwrap();
        crate::exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        crate::init::bootstrap(dir.path()).unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        let cfg = ctx.require_config().unwrap();

        // The exclusion is passed to the engine…
        let excludes = exclude_args(cfg);
        assert_eq!(
            excludes,
            vec!["--exclude".to_string(), ".sscsb/rules".to_string()]
        );

        // …and `rules = "auto"` (the registry) has no local directory to exclude.
        let text = std::fs::read_to_string(ctx.config_path())
            .unwrap()
            .replace("rules = \".sscsb/rules\"", "rules = \"auto\"");
        std::fs::write(ctx.config_path(), text).unwrap();
        let ctx_auto = Ctx::discover(dir.path()).unwrap();
        assert!(exclude_args(ctx_auto.require_config().unwrap()).is_empty());

        if !tools::is_available("opengrep") {
            return;
        }
        // The real engine, over a real bootstrapped repo: zero findings inside
        // .sscsb/rules, even though the rule file contains its own patterns.
        let findings = run_sast(&ctx, cfg, &ctx.root).unwrap();
        assert!(
            !findings.iter().any(|f| f.path.contains(".sscsb/rules")),
            "the ruleset must never appear in its own findings: {findings:?}"
        );
    }
}
