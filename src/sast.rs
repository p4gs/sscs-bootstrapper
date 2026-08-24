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

/// Severity labels that are advisory — reported, never blocking.
///
/// The list is deliberately the *permissive* half, so the gate is closed by
/// default: a label absent from it blocks. Semgrep's rule schema documents
/// `INFO | WARNING | ERROR`, and the four-band vocabulary is what rules in the
/// wild and other tooling use; both are bridged here the way `scan.rs` bridges
/// GHSA's `MODERATE`.
const ADVISORY_SEVERITIES: &[&str] = &["INFO", "INFORMATIONAL", "NOTE", "LOW", "MEDIUM", "WARNING"];

/// The severity recorded for a finding whose severity could not be read.
///
/// It is not a label any engine emits, so it can never be confused with one,
/// and it is not in [`ADVISORY_SEVERITIES`], so it blocks.
pub const SEVERITY_UNRATED: &str = "UNRATED";

/// Does a finding at this severity block the commit?
///
/// The gate used to be the literal string `ERROR`. Measured against
/// opengrep 1.25.0 and semgrep 1.169.0: a rule declaring `severity: CRITICAL`
/// or `severity: HIGH` is accepted by both engines and echoed verbatim into
/// `extra.severity` — so the two strictest severities a rule can carry sailed
/// straight through the gate that exists to stop exactly them.
///
/// Anything unrecognised blocks, on the principle H6 established one module
/// over: a severity we cannot place is not a low severity.
pub fn blocks(severity: &str) -> bool {
    let label = severity.trim();
    !ADVISORY_SEVERITIES
        .iter()
        .any(|a| a.eq_ignore_ascii_case(label))
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

    /// See [`blocks`].
    pub fn blocks(&self) -> bool {
        blocks(&self.severity)
    }
}

/// One scan: what the engine found, and what it could not read.
#[derive(Debug, Clone)]
pub struct SastScan {
    pub findings: Vec<SastFinding>,
    /// Parts of the target the engine reported it could not fully scan — a
    /// file it failed to parse, a rule that timed out. Not findings, and not
    /// nothing either: coverage the scan does not have. Dropping these is how
    /// a scan of a file nobody read reports "clean".
    pub incomplete: Vec<String>,
}

impl SastScan {
    pub fn blocking(&self) -> impl Iterator<Item = &SastFinding> {
        self.findings.iter().filter(|f| f.blocks())
    }
}

/// Run the configured engine over `target`. Returns what it found AND what it
/// could not read.
pub fn run_sast(ctx: &Ctx, cfg: &Config, target: &Path) -> Result<SastScan> {
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
            if !out.success() {
                // opengrep reports rule-parse errors on stdout with an empty
                // stderr, so surface both or the failure is unactionable.
                anyhow::bail!(
                    "opengrep failed ({}): {}",
                    out.termination(),
                    diagnostic(&out.stderr, &out.stdout)
                );
            }
            parse_semgrep_output(&out.stdout)
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
            // semgrep: 0 = clean, 1 = findings. EVERYTHING else is a failed
            // scan — including no exit code at all, which is what an OOM kill
            // or a timeout's SIGKILL leaves behind. Gating on `status > 1`
            // ranked that below both success codes and read it as clean.
            if !matches!(out.exit_code(), Some(0 | 1)) {
                anyhow::bail!(
                    "semgrep failed ({}): {}",
                    out.termination(),
                    diagnostic(&out.stderr, &out.stdout)
                );
            }
            parse_semgrep_output(&out.stdout)
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

/// Both OpenGrep and Semgrep emit the same results JSON shape: a `results`
/// array of findings, and an `errors` array of everything the engine could not
/// do. Both are read — a scan that skipped part of its target has not cleared
/// that target.
pub fn parse_semgrep_output(stdout: &str) -> Result<SastScan> {
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
            // A finding whose severity we could not read is UNRATED, which
            // blocks. Defaulting to `WARNING` silently demoted it to advisory:
            // one schema change — a renamed field, a moved one — and every
            // finding in the scan would have stopped gating, quietly.
            severity: r
                .pointer("/extra/severity")
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(SEVERITY_UNRATED)
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
    let mut incomplete = Vec::new();
    let mut fatal = Vec::new();
    for e in v
        .get("errors")
        .and_then(|x| x.as_array())
        .unwrap_or(&Vec::new())
    {
        let level = e
            .get("level")
            .and_then(|x| x.as_str())
            .unwrap_or("error")
            .to_string();
        let path = e.get("path").and_then(|x| x.as_str()).unwrap_or("?");
        let rendered = format!("{path}: {}", scan_error_message(e));
        // `warn`/`info` mean the scan continued without part of its target;
        // anything else — including a level we do not recognise — means the
        // scan itself did not work, and its results cannot be trusted.
        if matches!(level.as_str(), "warn" | "warning" | "info") {
            incomplete.push(rendered);
        } else {
            fatal.push(format!("[{level}] {rendered}"));
        }
    }
    if !fatal.is_empty() {
        anyhow::bail!("SAST engine reported errors: {}", fatal.join("; "));
    }
    Ok(SastScan {
        findings,
        incomplete,
    })
}

/// The first line of an engine error, capped.
///
/// A parse error's message quotes the text that failed to parse, so on a
/// binary file it carries the file's own bytes — measured against opengrep
/// 1.25.0, which embedded 60 bytes of a random blob in a `PartialParsing`
/// message. That is not something to splice whole into a terminal.
fn scan_error_message(e: &serde_json::Value) -> String {
    const MAX: usize = 160;
    let raw = e
        .get("message")
        .and_then(|x| x.as_str())
        .unwrap_or("(no message)")
        .lines()
        .next()
        .unwrap_or("(no message)")
        .trim();
    let clean: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match clean.char_indices().nth(MAX) {
        None => clean,
        Some((cut, _)) => format!("{}…", &clean[..cut]),
    }
}

/// Pre-commit SAST over staged files. Blocking severities block; advisory ones
/// are reported and do not. Uses the same fail-closed, quote-safe staged
/// materialization as the secret scanner, so a C-quoted filename can neither be
/// skipped silently nor escape the scan.
///
/// A staged file the engine could not read is an ERROR, not an empty result:
/// the gate's whole claim is about the files being committed right now, and it
/// cannot make that claim about a file nobody parsed. The caller applies the
/// `general.fail_open` policy to it, exactly as it does to a scanner that could
/// not run at all.
pub fn scan_staged(ctx: &Ctx, cfg: &Config) -> Result<Vec<String>> {
    let (dir, files) = crate::hooks::stage_to_tempdir(ctx)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let scan = run_sast(ctx, cfg, dir.path())?;
    if !scan.incomplete.is_empty() {
        anyhow::bail!(
            "SAST could not scan {} of the staged file(s), so they are not covered by this \
             gate: {}",
            scan.incomplete.len(),
            scan.incomplete.join("; ")
        );
    }
    Ok(scan.blocking().map(SastFinding::render).collect())
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
    //
    // `PATH_MUTEX` IS `testutil::PATH_LOCK`: PATH is not the only process-global
    // the suite fixtures (HOME and GIT_CONFIG_* are too, for the signing
    // lanes), and a per-module lock only serializes that module against itself.
    // One lock for all of it, or the modules race each other.
    pub(crate) use crate::testutil::PATH_LOCK as PATH_MUTEX;

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

    // ────────────────────────── parse_semgrep_output ────────────────────────

    #[test]
    fn semgrep_json_parses_shared_shape() {
        let sample = r#"{"results":[{"check_id":"rules.curl-pipe-shell","path":"install.sh",
            "start":{"line":3},"extra":{"severity":"ERROR","message":"piping remote script to shell"}}]}"#;
        let f = parse_semgrep_output(sample).unwrap().findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check_id, "rules.curl-pipe-shell");
        assert_eq!(f[0].line, 3);
        assert!(f[0].render().contains("install.sh:3"));
    }

    #[test]
    fn empty_results_yield_no_findings() {
        let scan = parse_semgrep_output(r#"{"results":[]}"#).unwrap();
        assert!(scan.findings.is_empty());
        assert!(scan.incomplete.is_empty());
        assert!(parse_semgrep_output("not json").is_err());
    }

    /// M6(b): a finding whose severity could not be read defaulted to
    /// `WARNING` — i.e. advisory, i.e. it stopped gating. One renamed or moved
    /// field in the engine's schema and EVERY finding would have quietly
    /// become non-blocking, with the scan still reporting them all.
    #[test]
    fn a_finding_with_no_readable_severity_is_unrated_and_blocks() {
        let f = parse_semgrep_output(r#"{"results":[{}]}"#)
            .unwrap()
            .findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check_id, "?");
        assert_eq!(f[0].path, "?");
        assert_eq!(f[0].line, 0);
        assert_eq!(f[0].severity, SEVERITY_UNRATED);
        assert!(
            f[0].blocks(),
            "a severity we could not read is not an advisory severity"
        );
        assert_eq!(f[0].message, "");

        // Schema drift, concretely: the severity moved out from under
        // `extra`. The finding is still reported, and still gates.
        let drifted = r#"{"results":[{"check_id":"x","path":"y","severity":"ERROR"}]}"#;
        let f = parse_semgrep_output(drifted).unwrap().findings;
        assert_eq!(f[0].severity, SEVERITY_UNRATED);
        assert!(f[0].blocks());

        // An empty string is not a severity either.
        let blank = r#"{"results":[{"extra":{"severity":"  "}}]}"#;
        assert_eq!(
            parse_semgrep_output(blank).unwrap().findings[0].severity,
            SEVERITY_UNRATED
        );
    }

    #[test]
    fn parse_semgrep_output_keeps_only_the_first_message_line() {
        let sample = r#"{"results":[{"check_id":"x","path":"y","start":{"line":9},
            "extra":{"severity":"ERROR","message":"first line\nsecond line"}}]}"#;
        let f = parse_semgrep_output(sample).unwrap().findings;
        assert_eq!(
            f[0].message, "first line",
            "only the first line of a multi-line message is kept"
        );
    }

    /// M6(c): the gate was the literal string `ERROR`, so the two strictest
    /// severities a rule can declare — both accepted and echoed back by
    /// opengrep 1.25.0 and semgrep 1.169.0, measured — passed straight through.
    #[test]
    fn critical_and_high_findings_block_and_advisory_ones_do_not() {
        for blocking in ["ERROR", "CRITICAL", "HIGH", "error", " Critical ", "SEV-1"] {
            assert!(blocks(blocking), "{blocking} must block");
        }
        for advisory in ["WARNING", "INFO", "LOW", "MEDIUM", "note", "warning"] {
            assert!(!advisory.is_empty() && !blocks(advisory), "{advisory}");
        }

        let sample = r#"{"results":[
            {"check_id":"c","path":"a.py","start":{"line":1},"extra":{"severity":"CRITICAL","message":"m"}},
            {"check_id":"h","path":"b.py","start":{"line":2},"extra":{"severity":"HIGH","message":"m"}},
            {"check_id":"w","path":"c.py","start":{"line":3},"extra":{"severity":"WARNING","message":"m"}}]}"#;
        let scan = parse_semgrep_output(sample).unwrap();
        let blocking: Vec<&str> = scan.blocking().map(|f| f.check_id.as_str()).collect();
        assert_eq!(
            blocking,
            vec!["c", "h"],
            "CRITICAL and HIGH block; WARNING stays advisory"
        );
    }

    /// M6(a): the `errors` array was dropped on the floor. Both engines report
    /// a file they could not parse there and still exit 0 with results —
    /// measured on opengrep 1.25.0 and semgrep 1.169.0 — so a scan that never
    /// read a file reported that file clean.
    #[test]
    fn a_file_the_engine_could_not_parse_is_reported_not_dropped() {
        // The real shape, from an opengrep run over a binary file.
        let sample = r#"{"results":[],"errors":[{"code":3,"level":"warn",
            "type":["PartialParsing",[]],"path":"src/binary.py",
            "message":"Syntax error at line src/binary.py:1:\n `garbage` was unexpected"}]}"#;
        let scan = parse_semgrep_output(sample).unwrap();
        assert!(scan.findings.is_empty());
        assert_eq!(scan.incomplete.len(), 1, "{:?}", scan.incomplete);
        assert!(
            scan.incomplete[0].contains("src/binary.py")
                && scan.incomplete[0].contains("Syntax error"),
            "{:?}",
            scan.incomplete
        );

        // A hard engine error is not a partial result — it is a failed scan.
        let fatal = r#"{"results":[],"errors":[{"level":"error","path":"rules.yaml",
            "message":"invalid rule schema"}]}"#;
        let err = parse_semgrep_output(fatal).unwrap_err();
        assert!(format!("{err:#}").contains("invalid rule schema"));

        // An error whose level we do not recognise is treated as fatal, not
        // waved through as a warning.
        let odd = r#"{"results":[],"errors":[{"level":"catastrophe","message":"?"}]}"#;
        assert!(parse_semgrep_output(odd).is_err());
    }

    /// A parse error quotes the text that failed to parse, so on a binary file
    /// the message carries that file's own bytes (measured: opengrep 1.25.0
    /// embedded 60 bytes of a random blob). It is not spliced whole into a
    /// terminal.
    #[test]
    fn an_engine_error_message_is_first_line_control_stripped_and_capped() {
        let long = "x".repeat(500);
        // Built through serde so a real control character lands in the JSON as
        // a proper escape — the way an engine that quotes a binary file emits
        // it — instead of making the document itself unparseable.
        let sample = serde_json::json!({
            "results": [],
            "errors": [{
                "level": "warn",
                "path": "b.py",
                "message": format!("head\u{7}{long}\nsecond line"),
            }],
        })
        .to_string();
        let scan = parse_semgrep_output(&sample).unwrap();
        let note = &scan.incomplete[0];
        assert!(note.starts_with("b.py: head"), "{note}");
        assert!(note.ends_with('…'), "long messages are capped: {note}");
        assert!(
            !note.contains('\u{7}') && !note.contains("second line"),
            "control characters stripped, later lines dropped: {note:?}"
        );
        assert!(note.chars().count() < 200, "{}", note.chars().count());

        let no_message = r#"{"results":[],"errors":[{"level":"warn"}]}"#;
        assert_eq!(
            parse_semgrep_output(no_message).unwrap().incomplete,
            vec!["?: (no message)".to_string()]
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

        let findings = serialized(|| run_sast(&ctx, cfg, &ctx.root))
            .unwrap()
            .findings;
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

        let findings = serialized(|| run_sast(&ctx, cfg, &ctx.root))
            .unwrap()
            .findings;
        assert!(
            findings
                .iter()
                .any(|f| f.check_id.contains("curl-pipe-shell")),
            "semgrep engine must flag it too: {findings:?}"
        );

        let err = with_only_git_on_path(|| run_sast(&ctx, cfg, &ctx.root)).unwrap_err();
        assert!(format!("{err:#}").contains("semgrep not found"));
    }

    /// Point a bootstrapped repo's `controls.sast.engine` at `engine`.
    fn repo_with_engine(engine: &str) -> (tempfile::TempDir, Ctx) {
        let (dir, ctx) = repo();
        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("engine = \"opengrep\"", &format!("engine = \"{engine}\""));
        std::fs::write(&cfg_path, text).unwrap();
        let ctx = Ctx::discover(&ctx.root).unwrap();
        (dir, ctx)
    }

    /// M5: the semgrep arm gated on `out.status > 1`. A process killed by a
    /// signal has NO exit code — `exec` records the -1 sentinel — and -1 is not
    /// greater than 1, so an OOM-killed or timed-out scanner fell through to
    /// the parser and whatever it had managed to print was read as the result.
    /// A scanner that printed `{"results":[]}` and was then killed therefore
    /// reported a clean scan.
    #[test]
    fn a_signal_killed_scanner_is_a_failed_scan_not_a_clean_one() {
        let (_d, ctx) = repo_with_engine("semgrep");
        let cfg = ctx.require_config().unwrap();
        // Prints a plausible clean result, then dies the way the OOM killer or
        // a CI timeout kills it — after some output, never having exited.
        let script = "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then echo \"1.169.0\"; exit 0; fi\n\
             printf '{\"results\":[],\"errors\":[]}'\n\
             kill -9 $$\n";
        let err = with_fake_tool("semgrep", script, || run_sast(&ctx, cfg, &ctx.root))
            .expect_err("a killed scanner must not report a clean scan");
        let msg = format!("{err:#}");
        assert!(msg.contains("semgrep failed"), "{msg}");
        assert!(
            msg.contains("killed by signal 9"),
            "the diagnostic must name how it died, not print a fake exit code: {msg}"
        );
    }

    /// The other half of the same gate: semgrep's two DOCUMENTED codes still
    /// mean what they mean, so tightening it did not turn findings into errors.
    #[test]
    fn semgrep_exit_one_still_means_findings_not_failure() {
        let (_d, ctx) = repo_with_engine("semgrep");
        let cfg = ctx.require_config().unwrap();
        let script = "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then echo \"1.169.0\"; exit 0; fi\n\
             printf '{\"results\":[{\"check_id\":\"x\",\"path\":\"a.sh\",\"start\":{\"line\":1},\
             \"extra\":{\"severity\":\"ERROR\",\"message\":\"m\"}}],\"errors\":[]}'\n\
             exit 1\n";
        let scan = with_fake_tool("semgrep", script, || run_sast(&ctx, cfg, &ctx.root)).unwrap();
        assert_eq!(scan.findings.len(), 1, "exit 1 is `findings`, not an error");

        let clean = "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then echo \"1.169.0\"; exit 0; fi\n\
             printf '{\"results\":[],\"errors\":[]}'\n\
             exit 0\n";
        let scan = with_fake_tool("semgrep", clean, || run_sast(&ctx, cfg, &ctx.root)).unwrap();
        assert!(scan.findings.is_empty());
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

    /// M6(c), end to end through the real engine: `scan_staged` filtered on the
    /// literal string `ERROR`, so a rule declaring `severity: CRITICAL` — which
    /// both engines accept and echo back verbatim — produced a finding the
    /// pre-commit gate then ignored.
    #[test]
    fn a_critical_severity_finding_blocks_the_staged_scan() {
        let (_d, ctx) = repo();
        write(
            &ctx,
            ".sscsb/rules/sscsb-test-critical.yaml",
            "rules:\n  \
             - id: sscsb-test.critical-marker\n    \
             languages: [generic]\n    \
             severity: CRITICAL\n    \
             message: a critical marker\n    \
             pattern-regex: 'SSCSB-CRITICAL-MARKER'\n",
        );
        write(&ctx, "app.txt", "line one\nSSCSB-CRITICAL-MARKER\n");
        exec::git(&["add", "app.txt"], &ctx.root).unwrap();

        let blocking = serialized(|| scan_staged(&ctx, ctx.require_config().unwrap())).unwrap();
        assert!(
            blocking.iter().any(|f| f.contains("critical-marker")),
            "a CRITICAL finding must block the commit: {blocking:?}"
        );
        assert!(
            blocking
                .iter()
                .all(|f| !f.contains("git-protocol-insecure")),
            "advisory findings must still NOT block: {blocking:?}"
        );
    }

    /// M6(a), end to end: a staged file the engine could not parse is reported
    /// in `errors[]` while the process exits 0 with results — measured on
    /// opengrep 1.25.0 and semgrep 1.169.0. Dropping that array made the gate
    /// report "staged changes clean" about a file it never read.
    #[test]
    fn a_staged_file_the_engine_cannot_parse_is_not_a_clean_scan() {
        let (_d, ctx) = repo();
        write(
            &ctx,
            ".sscsb/rules/sscsb-test-python.yaml",
            "rules:\n  \
             - id: sscsb-test.py-eval\n    \
             languages: [python]\n    \
             severity: ERROR\n    \
             message: eval\n    \
             pattern: eval(...)\n",
        );
        // Deterministic bytes that are not Python: enough to make the parser
        // give up rather than recover.
        let garbage: Vec<u8> = (1u8..=255).chain(1u8..=255).collect();
        std::fs::write(ctx.root.join("mystery.py"), &garbage).unwrap();
        exec::git(&["add", "mystery.py"], &ctx.root).unwrap();

        let err = serialized(|| scan_staged(&ctx, ctx.require_config().unwrap()))
            .expect_err("a staged file the engine could not read is not a clean scan");
        let msg = format!("{err:#}");
        assert!(msg.contains("could not scan"), "{msg}");
        assert!(msg.contains("mystery.py"), "the file must be named: {msg}");
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
        let findings = run_sast(&ctx, cfg, &ctx.root).unwrap().findings;
        assert!(
            !findings.iter().any(|f| f.path.contains(".sscsb/rules")),
            "the ruleset must never appear in its own findings: {findings:?}"
        );
    }
}
