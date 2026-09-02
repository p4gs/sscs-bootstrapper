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

/// Render `verify` results as the v1 JSON document.
///
/// Every entry's `control` id must exist in the registry — an unknown id here
/// is a programming error upstream (verify iterates the registry), so this
/// fails loudly rather than emitting a row a consumer cannot classify.
pub fn verify_json(results: &[VerifyResult], strict: bool) -> Result<String> {
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
    let doc = VerifyDoc {
        schema_version: SCHEMA_VERSION,
        command: "verify",
        strict,
        results: entries,
        summary,
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
