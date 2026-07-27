//! OpenSSF-Scorecard scan: read the live Scorecard findings this repo's
//! `scorecard.yml` publishes to GitHub code-scanning, and map each to the sscsb
//! control that addresses it plus an honest remediation status. This turns the
//! `scorecard` control from "is the workflow installed?" into "what does
//! Scorecard actually see, and what can sscsb do about each finding?".

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::Outcome;
use crate::controls::VerifyResult;
use crate::exec;

/// How a given Scorecard check relates to sscsb remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remediable {
    /// sscsb can fix it (fully or the safe part) via a control / `harden`.
    Sscsb,
    /// Structurally requires a second maintainer — a solo owner can't satisfy it.
    SoloCapped,
    /// The lowest-scoring case is a deliberate, justified exception.
    Justified,
    /// Needs an out-of-band owner action (e.g. external registration).
    External,
}

impl Remediable {
    pub fn label(self) -> &'static str {
        match self {
            Remediable::Sscsb => "sscsb-fixable",
            Remediable::SoloCapped => "solo-capped",
            Remediable::Justified => "justified-exception",
            Remediable::External => "owner-action",
        }
    }
}

/// A row in the Scorecard-check → sscsb-remediation map.
pub struct CheckMap {
    /// The Scorecard code-scanning rule id (e.g. "BranchProtectionID").
    pub rule_id: &'static str,
    /// The sscsb control (or "-" when none maps).
    pub control: &'static str,
    pub remediable: Remediable,
    /// One-line guidance.
    pub note: &'static str,
}

/// The mapping table. Every Scorecard check sscsb knows how to speak to.
pub const CHECK_MAP: &[CheckMap] = &[
    CheckMap {
        rule_id: "BranchProtectionID",
        control: "branch-protection",
        remediable: Remediable::Sscsb,
        note: "run `sscsb harden branch-protection --apply` for the solo-safe knobs; the \
               approver/code-owner/last-push tier needs a 2nd maintainer (`--require-reviews`)",
    },
    CheckMap {
        rule_id: "PinnedDependenciesID",
        control: "actions-audit",
        remediable: Remediable::Justified,
        note: "sscsb SHA-pins every action except slsa-github-generator, which MUST stay \
               tag-pinned per its trust model — the residual finding is that justified exception",
    },
    CheckMap {
        rule_id: "FuzzingID",
        control: "fuzzing",
        remediable: Remediable::Sscsb,
        note: "add cargo-fuzz targets + a ClusterFuzzLite workflow (the probe Scorecard detects \
               for Rust) — shipping as the `fuzzing` control increment",
    },
    CheckMap {
        rule_id: "SASTID",
        control: "sast",
        remediable: Remediable::Sscsb,
        note: "SAST is wired (OpenGrep + CodeQL on PRs); the score rises as commits flow \
               through PRs rather than direct pushes",
    },
    CheckMap {
        rule_id: "CodeReviewID",
        control: "branch-protection",
        remediable: Remediable::SoloCapped,
        note: "Scorecard counts approved changesets; a solo maintainer merging their own PRs \
               cannot self-approve — needs a 2nd reviewer",
    },
    CheckMap {
        rule_id: "CIIBestPracticesID",
        control: "-",
        remediable: Remediable::External,
        note: "register the project at bestpractices.dev and add the badge — an owner action \
               sscsb cannot perform",
    },
    CheckMap {
        rule_id: "SecurityPolicyID",
        control: "-",
        remediable: Remediable::Sscsb,
        note: "add a SECURITY.md (sscsb ships one in the scorecard-hardening set)",
    },
    CheckMap {
        rule_id: "TokenPermissionsID",
        control: "actions-audit",
        remediable: Remediable::Sscsb,
        note: "sscsb templates set least-privilege `permissions:` and the actions-audit control \
               flags over-broad grants",
    },
    CheckMap {
        rule_id: "DangerousWorkflowID",
        control: "workflow-audit-extended",
        remediable: Remediable::Sscsb,
        note: "the extended workflow audit flags pull_request_target misuse and script injection",
    },
];

/// Look up the mapping for a Scorecard rule id.
pub fn map_for(rule_id: &str) -> Option<&'static CheckMap> {
    CHECK_MAP.iter().find(|c| c.rule_id == rule_id)
}

/// Format one finding line for the report, given the rule id and Scorecard's
/// own message text. Pure — unit-tested.
pub fn format_finding(rule_id: &str, score_line: &str) -> String {
    match map_for(rule_id) {
        Some(m) => format!(
            "{rule_id} [{}] → {} — {} ({})",
            m.remediable.label(),
            if m.control == "-" {
                "no control"
            } else {
                m.control
            },
            score_line,
            m.note
        ),
        None => format!("{rule_id} [unmapped] — {score_line}"),
    }
}

/// Extract the first "score is N: ..." summary line from a Scorecard alert
/// message. Pure — unit-tested.
pub fn score_summary(message: &str) -> String {
    message.lines().next().unwrap_or("").trim().to_string()
}

/// Verify entry point for the `scorecard` control: confirm the workflow is
/// installed, then (best-effort) scan the live Scorecard findings from
/// code-scanning and report each mapped to remediation guidance. Network
/// fetch is best-effort — absence degrades to the install-only check.
pub fn verify_scorecard_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "scorecard";
    let mut messages = Vec::new();

    // 1. Presence of the workflow (the original install-only behaviour).
    let installed = ctx.root.join(".github/workflows/scorecard.yml").is_file();
    if installed {
        messages.push(".github/workflows/scorecard.yml installed".into());
    } else {
        return VerifyResult::new(
            id,
            Outcome::Fail,
            vec![".github/workflows/scorecard.yml MISSING — run `sscsb init`".into()],
        );
    }

    // 2. Live scan (best-effort).
    if exec::find_in_path("gh").is_none() {
        messages.push("live scan skipped: gh not installed".into());
        return VerifyResult::new(id, Outcome::Pass, messages);
    }
    let Some(slug) = cfg.github_repo().or_else(|| ctx.origin_slug()) else {
        messages.push("live scan skipped: no GitHub repo configured".into());
        return VerifyResult::new(id, Outcome::Pass, messages);
    };
    match fetch_findings(ctx, &slug) {
        Some(findings) if !findings.is_empty() => {
            messages.push(format!("live Scorecard findings ({}):", findings.len()));
            for (rule_id, msg) in &findings {
                messages.push(format!(
                    "  {}",
                    format_finding(rule_id, &score_summary(msg))
                ));
            }
        }
        Some(_) => messages.push("live scan: no open Scorecard findings 🎉".into()),
        None => messages.push(
            "live scan unavailable (no Scorecard code-scanning results yet — the workflow runs \
             on push to the default branch)"
                .into(),
        ),
    }
    VerifyResult::new(id, Outcome::Pass, messages)
}

/// Fetch open Scorecard code-scanning alerts as (rule_id, message) pairs.
/// Network boundary — excluded from coverage.
fn fetch_findings(ctx: &Ctx, slug: &str) -> Option<Vec<(String, String)>> {
    let out = exec::run(
        "gh",
        &[
            "api",
            &format!(
                "repos/{slug}/code-scanning/alerts?tool_name=Scorecard&state=open&per_page=100"
            ),
        ],
        Some(&ctx.root),
    )
    .ok()?;
    if !out.success() {
        return None;
    }
    let alerts: Vec<serde_json::Value> = serde_json::from_str(&out.stdout).ok()?;
    Some(
        alerts
            .iter()
            .filter_map(|a| {
                let rule = a.get("rule")?.get("id")?.as_str()?.to_string();
                let msg = a
                    .get("most_recent_instance")?
                    .get("message")?
                    .get("text")?
                    .as_str()?
                    .to_string();
                Some((rule, msg))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_map_row_has_a_note_and_valid_shape() {
        for c in CHECK_MAP {
            assert!(!c.rule_id.is_empty());
            assert!(!c.note.is_empty());
            // control is either "-" or a plausible id (no spaces)
            assert!(!c.control.contains(' '));
        }
    }

    #[test]
    fn branch_protection_maps_to_sscsb_fixable() {
        let m = map_for("BranchProtectionID").expect("mapped");
        assert_eq!(m.control, "branch-protection");
        assert_eq!(m.remediable, Remediable::Sscsb);
    }

    #[test]
    fn code_review_is_solo_capped_and_pinned_deps_justified() {
        assert_eq!(
            map_for("CodeReviewID").unwrap().remediable,
            Remediable::SoloCapped
        );
        assert_eq!(
            map_for("PinnedDependenciesID").unwrap().remediable,
            Remediable::Justified
        );
        assert_eq!(
            map_for("CIIBestPracticesID").unwrap().remediable,
            Remediable::External
        );
    }

    #[test]
    fn unmapped_rule_is_reported_not_dropped() {
        let line = format_finding("SomeFutureCheckID", "score is 3: whatever");
        assert!(line.contains("unmapped"));
        assert!(line.contains("SomeFutureCheckID"));
    }

    #[test]
    fn format_finding_includes_label_control_and_note() {
        let line = format_finding("FuzzingID", "score is 0: project is not fuzzed");
        assert!(line.contains("sscsb-fixable"));
        assert!(line.contains("fuzzing"));
        assert!(line.contains("cargo-fuzz"));
        assert!(line.contains("score is 0"));
    }

    #[test]
    fn score_summary_takes_first_line_trimmed() {
        assert_eq!(
            score_summary("score is 4: branch protection is not maximal\nWarn: ...\nClick ..."),
            "score is 4: branch protection is not maximal"
        );
        assert_eq!(score_summary(""), "");
    }

    #[test]
    fn label_strings_are_stable() {
        assert_eq!(Remediable::Sscsb.label(), "sscsb-fixable");
        assert_eq!(Remediable::SoloCapped.label(), "solo-capped");
        assert_eq!(Remediable::Justified.label(), "justified-exception");
        assert_eq!(Remediable::External.label(), "owner-action");
    }

    // --- live-scan path via a stubbed `gh` on PATH ---
    use crate::testutil::{fake_gh, repo_with_gh_repo, PathPrepend, PATH_LOCK};

    #[test]
    fn verify_scorecard_live_scan_maps_findings() {
        let _g = PATH_LOCK.lock().unwrap();
        let script = r#"#!/bin/sh
case "$2" in
  *code-scanning/alerts*)
    echo '[{"rule":{"id":"BranchProtectionID"},"most_recent_instance":{"message":{"text":"score is 4: branch protection is not maximal"}}},{"rule":{"id":"FuzzingID"},"most_recent_instance":{"message":{"text":"score is 0: project is not fuzzed"}}}]'
    exit 0;;
  *) echo '[]'; exit 0;;
esac
"#;
        let gh = fake_gh(script);
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        let _p = PathPrepend::new(gh.path());
        let cfg = ctx.require_config().unwrap();

        let r = verify_scorecard_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains(".github/workflows/scorecard.yml installed")));
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("live Scorecard findings (2)")));
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("BranchProtectionID") && m.contains("sscsb-fixable")));
        assert!(r.messages.iter().any(|m| m.contains("FuzzingID")));
    }

    #[test]
    fn verify_scorecard_reports_no_findings_cleanly() {
        let _g = PATH_LOCK.lock().unwrap();
        let gh = fake_gh("#!/bin/sh\necho '[]'\nexit 0\n");
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        let _p = PathPrepend::new(gh.path());
        let cfg = ctx.require_config().unwrap();
        let r = verify_scorecard_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("no open Scorecard findings")));
    }
}
