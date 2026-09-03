//! Machine-readable (JSON) rendering for `verify` and `status`.
//!
//! All JSON assembly lives HERE, not in `cli.rs`: `cli.rs` is excluded from
//! the coverage gate, and output that external consumers parse is exactly the
//! kind of logic that must sit where the 95% gate can see it. `cli.rs` only
//! branches on the `--format` string and prints what these functions return.
//!
//! The schema is versioned and additive: consumers pin `schema_version` and
//! ignore unknown fields; removing or renaming a field is a version bump.
//! Outcome strings are the five lowercase literals
//! `pass | fail | degraded | disabled | info` — serialized from the enum via
//! serde so a rename in Rust cannot silently change the wire format without
//! the pinned tests here failing.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{self, Outcome, VerifyResult};
use crate::{hooks, tools, workflows};
use anyhow::Result;
use serde::Serialize;

/// Bumped when a field is removed/renamed or its meaning changes.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct VerifyEntry<'a> {
    control: &'static str,
    phase: u8,
    name: &'static str,
    outcome: &'a Outcome,
    messages: &'a [String],
    /// Repo-relative paths of the committed files this control's verdict
    /// rests on. Load-bearing for external reclassifiers, which ask whether
    /// each path pre-existed in the repository before the scanner's own
    /// `init` ran.
    ///
    /// By default these are the artifacts the control's `init` installs,
    /// exported from the same `workflows::ARTIFACTS` table the binary installs
    /// from, so a consumer's artifact→control map can never drift from the
    /// version that scanned. When a control was instead proven by consolidated
    /// evidence — its real step found in another workflow COMMITTED at HEAD,
    /// such as `release.yml`, the modular template being absent, and that
    /// step passing every gate `workflows::Consolidated` lists (committed at
    /// HEAD, shape-sound, automatic trigger, no constant-false `if:`,
    /// SHA-pinned, artifact-bound, installer-before-signer, effective
    /// permissions granted) — the row reports THAT file, because it is the
    /// file the verdict examined and the one a consumer can check for
    /// pre-existence. Additive within schema v1:
    /// the field's shape and meaning ("the committed evidence") are unchanged.
    /// This field states what was examined; what a downstream directory makes
    /// of it is that directory's classification, not a claim made here.
    artifacts: Vec<&'a str>,
    /// External tools this control detects (registry order).
    tools: &'static [&'static str],
}

#[derive(Serialize)]
struct VerifySummary {
    passed: u32,
    failed: u32,
    degraded: u32,
    info: u32,
    disabled: u32,
}

#[derive(Serialize)]
struct VerifyDoc<'a> {
    schema_version: u32,
    command: &'static str,
    strict: bool,
    results: Vec<VerifyEntry<'a>>,
    summary: VerifySummary,
}

/// Build the entry rows and the summary for the `verify` document.
fn entries_and_summary(results: &[VerifyResult]) -> Result<(Vec<VerifyEntry<'_>>, VerifySummary)> {
    let mut entries = Vec::with_capacity(results.len());
    let mut summary = VerifySummary {
        passed: 0,
        failed: 0,
        degraded: 0,
        info: 0,
        disabled: 0,
    };
    for r in results {
        let def = controls::control(r.control).ok_or_else(|| {
            anyhow::anyhow!(
                "verify produced a result for unknown control `{}`",
                r.control
            )
        })?;
        match r.outcome {
            Outcome::Pass => summary.passed += 1,
            Outcome::Fail => summary.failed += 1,
            Outcome::Degraded => summary.degraded += 1,
            Outcome::Info => summary.info += 1,
            Outcome::Disabled => summary.disabled += 1,
        }
        entries.push(VerifyEntry {
            control: def.id,
            phase: def.phase,
            name: def.name,
            outcome: &r.outcome,
            messages: &r.messages,
            artifacts: if r.evidence.is_empty() {
                workflows::artifacts_for(def.id)
                    .into_iter()
                    .map(|a| a.dest)
                    .collect()
            } else {
                r.evidence.iter().map(String::as_str).collect()
            },
            tools: def.tools,
        });
    }
    Ok((entries, summary))
}

/// Render `verify` results as the v1 JSON document.
///
/// Every entry's `control` id must exist in the registry — an unknown id here
/// is a programming error upstream (verify iterates the registry), so this
/// fails loudly rather than emitting a row a consumer cannot classify.
pub fn verify_json(results: &[VerifyResult], strict: bool) -> Result<String> {
    let (entries, summary) = entries_and_summary(results)?;
    let doc = VerifyDoc {
        schema_version: SCHEMA_VERSION,
        command: "verify",
        strict,
        results: entries,
        summary,
    };
    Ok(serde_json::to_string_pretty(&doc)?)
}

// ─────────────────── the local lane's directory scan record ─────────────────
//
// A local record is not a `verify` document with a block bolted on: it IS a
// directory `ScanRecord`, the same shape `site/src/schema.ts` validates for
// every other lane, with the additive `local` block carrying the lane binding.
//
// That is forced by the contract in `docs/local-scan.md`: the signature makes
// the bytes unreshapeable afterwards, so the shape has to be right AT SIGNING
// TIME. A record the directory has to reshape before it can validate it is a
// record whose signature covers different bytes than the ones it publishes.

/// One `controls[]` row — contract line `control-fields`.
#[derive(Serialize)]
struct DirectoryControl<'a> {
    id: &'static str,
    phase: u8,
    in_scope: bool,
    raw_outcome: &'a Outcome,
    scan_outcome: &'static str,
    reclassified: bool,
    reason: Option<&'static str>,
    messages: &'a [String],
}

/// One `score.phases[]` row.
#[derive(Serialize)]
struct DirectoryPhase {
    phase: u8,
    pass: u32,
    fail: u32,
    gap: u32,
    unverified: u32,
    info: u32,
    percent: Option<f64>,
}

/// The `score` block — contract line `score-fields`.
#[derive(Serialize)]
struct DirectoryScore {
    grade: &'static str,
    provisional: bool,
    overall_percent: Option<f64>,
    evidence_coverage_percent: f64,
    phases: Vec<DirectoryPhase>,
}

/// The `repo` block — contract line `repo-fields`.
#[derive(Serialize)]
struct DirectoryRepo<'a> {
    owner: &'a str,
    name: &'a str,
    url: &'a str,
    default_branch: &'a str,
    commit: &'a str,
    description: &'static str,
}

/// The `scanner` block. A workstation has no workflow run; the fields exist
/// because the shape requires them, and the lane is established by the
/// directory's own verified sidecar, never by a URL a submitter chose.
#[derive(Serialize)]
struct DirectoryScanner {
    sscsb_version: &'static str,
    workflow_run_id: u64,
    workflow_run_url: &'static str,
}

/// The signed document — contract line `record-fields`.
#[derive(Serialize)]
struct LocalScanRecord<'a> {
    schema_version: u32,
    methodology_version: u32,
    repo: DirectoryRepo<'a>,
    scanned_at: &'a str,
    scanner: DirectoryScanner,
    request_issue: Option<u64>,
    controls: Vec<DirectoryControl<'a>>,
    score: DirectoryScore,
    local: &'a crate::local_scan::LocalBlock,
}

/// Round to one decimal, the site's `round1`.
fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The site's `gradeFor`. A+ requires exactly 100.
fn grade_for(overall: f64) -> &'static str {
    if overall == 100.0 {
        "A+"
    } else if overall >= 90.0 {
        "A"
    } else if overall >= 80.0 {
        "B"
    } else if overall >= 70.0 {
        "C"
    } else if overall >= 60.0 {
        "D"
    } else {
        "F"
    }
}

/// Coverage below this: no letter at all. Mirrors `COVERAGE_FLOOR_NA`.
const COVERAGE_FLOOR_NA: f64 = 50.0;
/// Coverage below this (but at/above the NA floor): the letter is provisional.
const COVERAGE_FLOOR_PROVISIONAL: f64 = 75.0;

/// Whether a control is in the directory's scope for this repository.
///
/// The site's rule, mirrored: scope is the registry's default-on set UNION the
/// set the repository's own config enables. A repository that switches a
/// default-on control OFF therefore keeps it in the denominator and scores a
/// gap, rather than shrinking the denominator by opting out.
fn in_scope(cfg: &Config, def: &controls::ControlDef) -> bool {
    def.default_enabled || cfg.control_enabled_or_default(def.id)
}

/// The directory's `scan_outcome` for one row, with the reason it carries.
///
/// This is a DIRECT reading of what the tool observed on this machine. The
/// scanner-init reclassification the directory applies to its own external
/// scans has no analogue here (nothing installed anything seconds ago), and
/// the evidence-class rules that decide what a row may COUNT for are the
/// directory's, applied at merge time against every source it holds — not
/// something a self-report gets to assert about itself.
fn scan_outcome_for(scoped: bool, raw: &Outcome) -> (&'static str, Option<&'static str>) {
    if !scoped {
        return (
            "info",
            Some("optional control not enabled by this repository"),
        );
    }
    match raw {
        Outcome::Pass => ("pass", None),
        Outcome::Fail => ("fail", None),
        Outcome::Degraded => (
            "unverified",
            Some("the control could not be performed on this machine — an unperformed check is never a verdict"),
        ),
        Outcome::Disabled => (
            "gap",
            Some("a default-on control this repository switched off in .sscsb/config.toml"),
        ),
        Outcome::Info => ("info", None),
    }
}

/// The site's `computeScore`, mirrored so the signed record is a complete and
/// independently checkable `ScanRecord`.
///
/// The directory RECOMPUTES the listing's score from every evidence source it
/// holds and never displays this copy as the grade — but a record that omitted
/// the block, or filled it with zeroes, would not be a valid record and could
/// not be validated by anyone offline.
fn score_of(rows: &[DirectoryControl<'_>]) -> DirectoryScore {
    let scoped: Vec<&DirectoryControl<'_>> = rows.iter().filter(|r| r.in_scope).collect();
    let mut phases = Vec::with_capacity(5);
    for phase in 1u8..=5 {
        let inp = |o: &str| {
            scoped
                .iter()
                .filter(|r| r.phase == phase && r.scan_outcome == o)
                .count() as u32
        };
        let (pass, fail, gap) = (inp("pass"), inp("fail"), inp("gap"));
        let countable = pass + fail + gap;
        phases.push(DirectoryPhase {
            phase,
            pass,
            fail,
            gap,
            unverified: inp("unverified"),
            info: inp("info"),
            percent: if countable == 0 {
                None
            } else {
                Some(round1(100.0 * f64::from(pass) / f64::from(countable)))
            },
        });
    }
    let total_pass: u32 = phases.iter().map(|p| p.pass).sum();
    let total_countable: u32 = phases.iter().map(|p| p.pass + p.fail + p.gap).sum();
    let overall = if total_countable == 0 {
        None
    } else {
        Some(round1(
            100.0 * f64::from(total_pass) / f64::from(total_countable),
        ))
    };
    let coverage = if scoped.is_empty() {
        0.0
    } else {
        round1(100.0 * f64::from(total_countable) / scoped.len() as f64)
    };
    let (grade, provisional) = match overall {
        Some(o) if coverage >= COVERAGE_FLOOR_NA => {
            (grade_for(o), coverage < COVERAGE_FLOOR_PROVISIONAL)
        }
        _ => ("NA", false),
    };
    DirectoryScore {
        grade,
        provisional,
        overall_percent: overall,
        evidence_coverage_percent: coverage,
        phases,
    }
}

/// Render the local-lane record: a directory `ScanRecord` in the shape the
/// site's `validateScanRecord` accepts, plus the additive `local` block that
/// binds it to a repository, a commit and a signer.
///
/// These are the bytes that get signed and the bytes that get committed. There
/// is no second serialization anywhere in the lane.
pub fn local_record_json(
    cfg: &Config,
    results: &[VerifyResult],
    local: &crate::local_scan::LocalBlock,
) -> Result<String> {
    let mut rows = Vec::with_capacity(results.len());
    for r in results {
        let def = controls::control(r.control).ok_or_else(|| {
            anyhow::anyhow!(
                "verify produced a result for unknown control `{}`",
                r.control
            )
        })?;
        let scoped = in_scope(cfg, def);
        let (scan_outcome, reason) = scan_outcome_for(scoped, &r.outcome);
        rows.push(DirectoryControl {
            id: def.id,
            phase: def.phase,
            in_scope: scoped,
            raw_outcome: &r.outcome,
            scan_outcome,
            reclassified: reason.is_some() && scoped,
            reason,
            messages: &r.messages,
        });
    }
    let score = score_of(&rows);
    let doc = LocalScanRecord {
        schema_version: crate::local_scan::SCHEMA_VERSION,
        methodology_version: crate::local_scan::METHODOLOGY_VERSION,
        repo: DirectoryRepo {
            owner: &local.repo.owner,
            name: &local.repo.name,
            url: &local.repo.url,
            default_branch: &local.repo.default_branch,
            commit: &local.repo.commit,
            // The directory reads a repository's description from GitHub
            // itself. A workstation has no business asserting one.
            description: "",
        },
        scanned_at: &local.generated_at,
        scanner: DirectoryScanner {
            sscsb_version: local.sscsb_version,
            workflow_run_id: 0,
            workflow_run_url: "",
        },
        request_issue: None,
        controls: rows,
        score,
        local,
    };
    Ok(serde_json::to_string_pretty(&doc)?)
}

#[derive(Serialize)]
struct ToolState {
    id: &'static str,
    present: bool,
}

#[derive(Serialize)]
struct StatusControl {
    id: &'static str,
    phase: u8,
    name: &'static str,
    enabled: bool,
    tools: Vec<ToolState>,
}

#[derive(Serialize)]
struct HooksState<'a> {
    outcome: &'a Outcome,
    messages: &'a [String],
}

#[derive(Serialize)]
struct StatusDoc<'a> {
    schema_version: u32,
    command: &'static str,
    branch: String,
    platform: String,
    config_present: bool,
    hooks: HooksState<'a>,
    controls: Vec<StatusControl>,
}

/// Render `status` as the v1 JSON document. Mirrors `cmd_status`'s text
/// output field-for-field: enabled state comes from config with the registry
/// default as fallback, tool presence from the live PATH probe.
pub fn status_json(ctx: &Ctx) -> Result<String> {
    let cfg: Option<&Config> = ctx.config.as_ref();
    let hook_state = hooks::hook_integrity(ctx);
    let mut entries = Vec::with_capacity(controls::CONTROLS.len());
    for def in controls::CONTROLS {
        let enabled = cfg
            .and_then(|c| c.control_enabled(def.id))
            .unwrap_or(def.default_enabled);
        entries.push(StatusControl {
            id: def.id,
            phase: def.phase,
            name: def.name,
            enabled,
            tools: def
                .tools
                .iter()
                .map(|t| ToolState {
                    id: t,
                    present: tools::is_available(t),
                })
                .collect(),
        });
    }
    let doc = StatusDoc {
        schema_version: SCHEMA_VERSION,
        command: "status",
        branch: ctx.current_branch().unwrap_or_else(|_| "?".into()),
        platform: ctx.platform.to_string(),
        config_present: cfg.is_some(),
        hooks: HooksState {
            outcome: &hook_state.outcome,
            messages: &hook_state.messages,
        },
        controls: entries,
    };
    Ok(serde_json::to_string_pretty(&doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn bootstrapped_ctx() -> (tempfile::TempDir, Ctx, Config) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        crate::init::bootstrap(root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let cfg = Config::load(root).unwrap().unwrap();
        (dir, ctx, cfg)
    }

    fn full_verify(ctx: &Ctx, cfg: &Config) -> Vec<VerifyResult> {
        controls::CONTROLS
            .iter()
            .map(|def| controls::verify_control(ctx, cfg, def))
            .collect()
    }

    #[test]
    fn verify_json_covers_every_control_and_matches_the_registry() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        let results = full_verify(&ctx, &cfg);
        let doc: serde_json::Value =
            serde_json::from_str(&verify_json(&results, false).unwrap()).unwrap();
        assert_eq!(doc["schema_version"], SCHEMA_VERSION);
        assert_eq!(doc["command"], "verify");
        assert_eq!(doc["strict"], false);
        let rows = doc["results"].as_array().unwrap();
        assert_eq!(rows.len(), controls::CONTROLS.len());
        for (row, def) in rows.iter().zip(controls::CONTROLS) {
            assert_eq!(row["control"], def.id);
            assert_eq!(row["phase"], def.phase);
            assert_eq!(row["name"], def.name);
        }
    }

    /// A [`crate::local_scan::LocalBlock`] fixture, so the record tests read
    /// as assertions rather than as construction.
    fn block_fixture() -> crate::local_scan::LocalBlock {
        crate::local_scan::LocalBlock {
            record_version: crate::local_scan::RECORD_VERSION,
            lane: "local",
            namespace: crate::local_scan::NAMESPACE,
            generated_at: "2026-01-01T00:00:00Z".into(),
            sscsb_version: env!("CARGO_PKG_VERSION"),
            repo: crate::local_scan::RecordRepo {
                owner: "o".into(),
                name: "r".into(),
                url: "https://github.com/o/r".into(),
                default_branch: "main".into(),
                branch: "main".into(),
                commit: "0".repeat(40),
            },
            worktree: crate::local_scan::RecordWorktree {
                clean: true,
                tracked_changes: Vec::new(),
            },
            signer: crate::local_scan::RecordSigner {
                principal: "you@example.test".into(),
                key: "ssh-ed25519 AAAA".into(),
                fingerprint: "SHA256:x".into(),
                program: "ssh-keygen".into(),
            },
            allowed_signers: crate::local_scan::RecordAnchor {
                path: crate::local_scan::ANCHOR_PATH.into(),
                sha256: "0".repeat(64),
            },
        }
    }

    /// The signed bytes must be a directory `ScanRecord` — every field the
    /// site's `validateScanRecord` requires, present at signing time.
    ///
    /// This is the blocker the lane died on: the tool signed a `verify
    /// --format json` document and the directory validated a `ScanRecord`, so
    /// nothing the tool produced could ever be ingested. The signature makes
    /// the bytes unreshapeable afterwards, so the shape has to be right here.
    #[test]
    fn a_local_record_is_a_directory_scan_record_with_one_added_block() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        let results = full_verify(&ctx, &cfg);
        let block = block_fixture();
        let doc: serde_json::Value =
            serde_json::from_str(&local_record_json(&cfg, &results, &block).unwrap()).unwrap();

        // contract line `record-fields`
        for field in [
            "schema_version",
            "methodology_version",
            "repo",
            "scanned_at",
            "scanner",
            "request_issue",
            "controls",
            "score",
        ] {
            assert!(doc.get(field).is_some(), "record is missing `{field}`");
        }
        assert_eq!(doc["schema_version"], crate::local_scan::SCHEMA_VERSION);
        assert_eq!(
            doc["methodology_version"],
            crate::local_scan::METHODOLOGY_VERSION
        );
        // contract line `repo-fields`
        for field in [
            "owner",
            "name",
            "url",
            "default_branch",
            "commit",
            "description",
        ] {
            assert!(
                doc["repo"].get(field).is_some(),
                "repo is missing `{field}`"
            );
        }
        assert_eq!(doc["repo"]["commit"].as_str().unwrap().len(), 40);
        // contract line `score-fields`
        for field in [
            "grade",
            "provisional",
            "overall_percent",
            "evidence_coverage_percent",
            "phases",
        ] {
            assert!(doc["score"].get(field).is_some(), "score missing `{field}`");
        }
        assert_eq!(doc["score"]["phases"].as_array().unwrap().len(), 5);
        // contract line `control-fields`
        let rows = doc["controls"].as_array().unwrap();
        assert_eq!(rows.len(), controls::CONTROLS.len());
        let scan_outcomes = ["pass", "fail", "gap", "unverified", "info"];
        let raw_outcomes = ["pass", "fail", "degraded", "disabled", "info"];
        for row in rows {
            for field in [
                "id",
                "phase",
                "in_scope",
                "raw_outcome",
                "scan_outcome",
                "reclassified",
                "reason",
                "messages",
            ] {
                assert!(row.get(field).is_some(), "control row missing `{field}`");
            }
            assert!(scan_outcomes.contains(&row["scan_outcome"].as_str().unwrap()));
            assert!(raw_outcomes.contains(&row["raw_outcome"].as_str().unwrap()));
            assert!(row["messages"].is_array());
        }
        // The additive lane block, and nothing that pretends to be a CI run.
        assert_eq!(doc["local"]["lane"], "local");
        assert_eq!(doc["local"]["namespace"], crate::local_scan::NAMESPACE);
        assert_eq!(doc["scanner"]["workflow_run_id"], 0);
        assert_eq!(doc["scanner"]["workflow_run_url"], "");
        assert_eq!(doc["request_issue"], serde_json::Value::Null);
    }

    /// Every row the record emits comes from the same registry walk `verify
    /// --format json` reports, so a control cannot be scored one way through
    /// CI and another way from a workstation.
    #[test]
    fn a_local_record_reports_the_same_rows_and_raw_outcomes_as_verify_json() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        let results = full_verify(&ctx, &cfg);
        let plain: serde_json::Value =
            serde_json::from_str(&verify_json(&results, false).unwrap()).unwrap();
        let block = block_fixture();
        let doc: serde_json::Value =
            serde_json::from_str(&local_record_json(&cfg, &results, &block).unwrap()).unwrap();

        let rows = doc["controls"].as_array().unwrap();
        let plain_rows = plain["results"].as_array().unwrap();
        assert_eq!(rows.len(), plain_rows.len());
        for (row, want) in rows.iter().zip(plain_rows) {
            assert_eq!(row["id"], want["control"]);
            assert_eq!(row["phase"], want["phase"]);
            assert_eq!(row["raw_outcome"], want["outcome"]);
            assert_eq!(row["messages"], want["messages"]);
        }
    }

    /// A repository that switches a default-on control OFF keeps it in the
    /// denominator and scores a gap — it does not shrink the denominator by
    /// opting out, which would be self-graded coverage.
    #[test]
    fn disabling_a_default_on_control_scores_a_gap_rather_than_leaving_scope() {
        let (dir, ctx, _cfg) = bootstrapped_ctx();
        let target = controls::CONTROLS
            .iter()
            .find(|d| d.default_enabled)
            .expect("the registry has default-on controls");
        crate::config::set_control_enabled(&ctx.config_path(), target.id, false).unwrap();
        let cfg = Config::load(dir.path()).unwrap().unwrap();
        let results: Vec<VerifyResult> = controls::CONTROLS
            .iter()
            .map(|def| controls::verify_control(&ctx, &cfg, def))
            .collect();
        let block = block_fixture();
        let doc: serde_json::Value =
            serde_json::from_str(&local_record_json(&cfg, &results, &block).unwrap()).unwrap();
        let row = doc["controls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == target.id)
            .unwrap();
        assert_eq!(row["in_scope"], true, "{} left scope", target.id);
        assert_eq!(row["raw_outcome"], "disabled");
        assert_eq!(row["scan_outcome"], "gap");
    }

    /// The record's own score is the site's arithmetic, mirrored: unverified
    /// and info rows are in NO denominator, and A+ requires exactly 100.
    #[test]
    fn the_records_score_mirrors_the_directorys_arithmetic() {
        assert_eq!(grade_for(100.0), "A+");
        assert_eq!(grade_for(99.9), "A");
        assert_eq!(grade_for(90.0), "A");
        assert_eq!(grade_for(89.9), "B");
        assert_eq!(grade_for(80.0), "B");
        assert_eq!(grade_for(70.0), "C");
        assert_eq!(grade_for(60.0), "D");
        assert_eq!(grade_for(59.9), "F");
        assert_eq!(round1(57.14285), 57.1);

        let rows = |specs: &[(u8, bool, &'static str)]| -> Vec<DirectoryControl<'static>> {
            specs
                .iter()
                .map(|(phase, scoped, outcome)| DirectoryControl {
                    id: "x",
                    phase: *phase,
                    in_scope: *scoped,
                    raw_outcome: &Outcome::Pass,
                    scan_outcome: outcome,
                    reclassified: false,
                    reason: None,
                    messages: &[],
                })
                .collect()
        };

        // 3 pass + 1 gap countable of 8 scoped: 75% overall, 50% coverage.
        let s = score_of(&rows(&[
            (1, true, "pass"),
            (1, true, "pass"),
            (1, true, "pass"),
            (1, true, "gap"),
            (2, true, "unverified"),
            (2, true, "unverified"),
            (2, true, "unverified"),
            (2, true, "info"),
        ]));
        assert_eq!(s.overall_percent, Some(75.0));
        assert_eq!(s.evidence_coverage_percent, 50.0);
        assert_eq!(s.grade, "C");
        assert!(s.provisional, "50% coverage is under the provisional floor");
        assert_eq!(s.phases[1].percent, None, "no countable rows in phase 2");

        // Nothing countable at all: no letter, not an F.
        let none = score_of(&rows(&[(1, true, "unverified"), (2, true, "info")]));
        assert_eq!(none.grade, "NA");
        assert_eq!(none.overall_percent, None);
        assert!(!none.provisional);

        // Out-of-scope rows are in no denominator, including coverage's.
        let scoped_only = score_of(&rows(&[(1, true, "pass"), (1, false, "info")]));
        assert_eq!(scoped_only.evidence_coverage_percent, 100.0);
        assert_eq!(scoped_only.grade, "A+");
        assert!(!scoped_only.provisional);
    }

    /// The five outcome literals are the wire format external consumers pin.
    /// A serde rename or enum rename must fail here, not in a consumer.
    #[test]
    fn outcome_strings_are_the_five_pinned_lowercase_literals() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        let results = full_verify(&ctx, &cfg);
        let doc: serde_json::Value =
            serde_json::from_str(&verify_json(&results, false).unwrap()).unwrap();
        let allowed = ["pass", "fail", "degraded", "disabled", "info"];
        for row in doc["results"].as_array().unwrap() {
            let o = row["outcome"].as_str().unwrap();
            assert!(allowed.contains(&o), "unexpected outcome literal `{o}`");
        }
        // Each literal individually, so a rename of any single variant fails.
        for (variant, expected) in [
            (Outcome::Pass, "\"pass\""),
            (Outcome::Fail, "\"fail\""),
            (Outcome::Degraded, "\"degraded\""),
            (Outcome::Disabled, "\"disabled\""),
            (Outcome::Info, "\"info\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), expected);
        }
    }

    #[test]
    fn verify_summary_counts_equal_a_recount_of_results() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        let results = full_verify(&ctx, &cfg);
        let doc: serde_json::Value =
            serde_json::from_str(&verify_json(&results, true).unwrap()).unwrap();
        assert_eq!(doc["strict"], true);
        let mut counts = std::collections::BTreeMap::new();
        for row in doc["results"].as_array().unwrap() {
            *counts
                .entry(row["outcome"].as_str().unwrap().to_string())
                .or_insert(0u64) += 1;
        }
        let s = &doc["summary"];
        for (key, field) in [
            ("pass", "passed"),
            ("fail", "failed"),
            ("degraded", "degraded"),
            ("info", "info"),
            ("disabled", "disabled"),
        ] {
            assert_eq!(
                s[field].as_u64().unwrap(),
                *counts.get(key).unwrap_or(&0),
                "summary.{field} disagrees with a recount"
            );
        }
    }

    fn artifacts_of(row: &serde_json::Value) -> Vec<&str> {
        row["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect()
    }

    /// `artifacts` is the load-bearing field for external reclassifiers: it
    /// must expose exactly the ARTIFACTS table's dest paths for the control.
    #[test]
    fn artifacts_field_matches_the_workflows_table() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        let results = full_verify(&ctx, &cfg);
        let doc: serde_json::Value =
            serde_json::from_str(&verify_json(&results, false).unwrap()).unwrap();
        let rows = doc["results"].as_array().unwrap();
        let codeql = rows
            .iter()
            .find(|r| r["control"] == "codeql")
            .expect("codeql row present");
        let paths = artifacts_of(codeql);
        assert!(paths.contains(&".github/workflows/codeql.yml"), "{paths:?}");
        // And for every row: exact parity with artifacts_for().
        for row in rows {
            let id = row["control"].as_str().unwrap();
            let expected: Vec<&str> = workflows::artifacts_for(id)
                .into_iter()
                .map(|a| a.dest)
                .collect();
            assert_eq!(artifacts_of(row), expected, "artifacts drift for `{id}`");
        }
    }

    /// When a control is proven by consolidated evidence — its modular
    /// template absent, its real step living in `release.yml` — the row must
    /// name the file the verdict examined, not the template that was never
    /// installed: a reclassifier checking pre-existence would otherwise mark
    /// a genuinely implemented control as a gap. Every OTHER row keeps exact
    /// registry parity, so the override is scoped to the evidence it rests on.
    #[test]
    fn artifacts_field_reports_the_consolidated_evidence_file_when_it_proved_the_control() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/release.yml"),
            crate::testutil::signed_release_workflow(),
        )
        .unwrap();
        // Only content committed at HEAD is evidence — `git add` alone is not.
        crate::exec::git(&["add", "--", ".github/workflows/release.yml"], &ctx.root).unwrap();
        crate::exec::git(
            &["commit", "-q", "-m", "test: release.yml", "--no-verify"],
            &ctx.root,
        )
        .unwrap();
        let results = full_verify(&ctx, &cfg);
        let doc: serde_json::Value =
            serde_json::from_str(&verify_json(&results, false).unwrap()).unwrap();
        let rows = doc["results"].as_array().unwrap();
        for row in rows {
            let id = row["control"].as_str().unwrap();
            if id == "sigstore-signing" {
                assert_eq!(row["outcome"], "pass", "{}", row["messages"]);
                assert_eq!(artifacts_of(row), vec![".github/workflows/release.yml"]);
                continue;
            }
            let expected: Vec<&str> = workflows::artifacts_for(id)
                .into_iter()
                .map(|a| a.dest)
                .collect();
            assert_eq!(artifacts_of(row), expected, "artifacts drift for `{id}`");
        }
    }

    #[test]
    fn disabled_control_serializes_disabled_with_its_message() {
        let (_d, ctx, cfg) = bootstrapped_ctx();
        // `witness` is default-off, so a fresh bootstrap verifies it Disabled.
        let def = controls::control("witness").unwrap();
        let results = vec![controls::verify_control(&ctx, &cfg, def)];
        let doc: serde_json::Value =
            serde_json::from_str(&verify_json(&results, false).unwrap()).unwrap();
        let row = &doc["results"][0];
        assert_eq!(row["outcome"], "disabled");
        assert_eq!(doc["summary"]["disabled"], 1);
        assert!(row["messages"][0]
            .as_str()
            .unwrap()
            .contains("disabled in .sscsb/config.toml"));
    }

    #[test]
    fn verify_json_refuses_an_unknown_control_id() {
        let bogus = VerifyResult::new("not-a-control", Outcome::Pass, vec![]);
        // &'static str is required by the type; leak a string to fabricate one.
        let err = verify_json(std::slice::from_ref(&bogus), false).unwrap_err();
        assert!(err.to_string().contains("unknown control"));
    }

    #[test]
    fn status_json_reflects_config_and_flips_with_enablement() {
        let (_d, ctx, _cfg) = bootstrapped_ctx();
        let doc: serde_json::Value = serde_json::from_str(&status_json(&ctx).unwrap()).unwrap();
        assert_eq!(doc["schema_version"], SCHEMA_VERSION);
        assert_eq!(doc["command"], "status");
        assert_eq!(doc["config_present"], true);
        assert_eq!(doc["branch"], "main");
        let rows = doc["controls"].as_array().unwrap();
        assert_eq!(rows.len(), controls::CONTROLS.len());
        let by_id = |id: &str| {
            rows.iter()
                .find(|r| r["id"] == id)
                .unwrap_or_else(|| panic!("{id} missing"))
                .clone()
        };
        // Registry defaults surface as enabled state on a fresh bootstrap.
        assert_eq!(by_id("secrets")["enabled"], true);
        assert_eq!(by_id("witness")["enabled"], false);
        // Tool states are {id, present:bool} pairs in registry order.
        let secrets_tools = by_id("secrets");
        let t = secrets_tools["tools"].as_array().unwrap();
        assert_eq!(t[0]["id"], "trufflehog");
        assert!(t[0]["present"].is_boolean());

        // Flip witness on; status must follow the config, not the default.
        crate::config::set_control_enabled(&ctx.config_path(), "witness", true).unwrap();
        let ctx2 = Ctx::discover(ctx.root.as_path()).unwrap();
        let doc2: serde_json::Value = serde_json::from_str(&status_json(&ctx2).unwrap()).unwrap();
        let w = doc2["controls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "witness")
            .unwrap()
            .clone();
        assert_eq!(w["enabled"], true);
    }

    #[test]
    fn status_json_before_init_reports_config_missing_and_hook_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&status_json(&ctx).unwrap()).unwrap();
        assert_eq!(doc["config_present"], false);
        // Hooks cannot pass before init; the outcome is one of the pinned
        // non-pass literals and messages explain why.
        assert_ne!(doc["hooks"]["outcome"], "pass");
        assert!(!doc["hooks"]["messages"].as_array().unwrap().is_empty());
    }
}
