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

    // 2. Live scan. NOT "best-effort" in the verdict sense: an installed
    //    workflow proves only that a file exists. Whether Scorecard actually
    //    scores this repository — and what it sees — is the substantive half of
    //    this control, so every way of not reading it is DEGRADED, matching how
    //    `branch-protection` treats the same missing prerequisites. PASS here
    //    means "Scorecard ran and had nothing open", nothing less.
    if exec::find_in_path("gh").is_none() {
        messages.push(crate::tools::degrade_message("gh", ctx.platform));
        messages.push("live Scorecard findings NOT read — posture unverified".into());
        return VerifyResult::new(id, Outcome::Degraded, messages);
    }
    let Some(slug) = cfg.github_repo().or_else(|| ctx.origin_slug()) else {
        messages.push(
            "no GitHub repo configured (general.github_repo) and no origin remote — \
             live Scorecard findings NOT read, posture unverified"
                .into(),
        );
        return VerifyResult::new(id, Outcome::Degraded, messages);
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
            // Scorecard IS scoring this repo and it has open findings. sscsb
            // deliberately does not re-gate on another scanner's rubric — each
            // finding routes to the sscsb control that owns it, and that
            // control fails on its own evidence — but reporting PASS while
            // printing open findings manufactures assurance. INFO is the
            // honest verdict: context, not a gate.
            messages.push(
                "reported as INFO, not PASS: open Scorecard findings exist; each is routed to \
                 the sscsb control that gates it above"
                    .into(),
            );
            VerifyResult::new(id, Outcome::Info, messages)
        }
        Some(_) => {
            messages.push("live scan: no open Scorecard findings 🎉".into());
            VerifyResult::new(id, Outcome::Pass, messages)
        }
        None => {
            messages.push(
                "live Scorecard results could not be read (none published yet — the workflow \
                 runs on push to the default branch — or the code-scanning API refused) — \
                 posture unverified"
                    .into(),
            );
            VerifyResult::new(id, Outcome::Degraded, messages)
        }
    }
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
    use crate::testutil::{
        env_lock, fake_gh, path_without, repo_with_gh_repo, EnvGuard, PathPrepend, PATH_LOCK,
    };

    /// A bootstrapped repo with NO `github_repo` in config and no origin
    /// remote, so `verify_scorecard_control` cannot resolve a slug.
    fn repo_without_slug() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    /// Regression (H3a): with `gh` off PATH the live half of this control
    /// cannot run at all, and the whole verdict used to collapse to PASS on
    /// the strength of a workflow file existing — while every other
    /// gh-dependent control in the same run correctly said DEGRADED.
    #[test]
    fn scorecard_degrades_when_gh_is_absent() {
        let _g = env_lock();
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        let cfg_owned = crate::config::Config::load(&ctx.root).unwrap().unwrap();

        // Hide ONLY gh: PATH is process-global, so blanking it would break
        // whichever tool a concurrently-running test happens to need.
        let (_mirrors, path) = path_without(&["gh"]);
        let _env = EnvGuard::new(&[("PATH", Some(&path.to_string_lossy()))]);
        assert!(exec::find_in_path("gh").is_none(), "fixture must hide gh");

        let r = verify_scorecard_control(&ctx, &cfg_owned);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("gh not found on PATH")),
            "{:?}",
            r.messages
        );
        assert!(
            r.messages.iter().any(|m| m.contains("posture unverified")),
            "{:?}",
            r.messages
        );
    }

    /// Same hole, two lines further down: no slug means the code-scanning API
    /// is never queried, so nothing about Scorecard's view was read.
    #[test]
    fn scorecard_degrades_without_a_github_slug() {
        let _g = env_lock();
        let gh = fake_gh("#!/bin/sh\necho '[]'\nexit 0\n");
        let _p = PathPrepend::new(gh.path());
        let (_d, ctx) = repo_without_slug();
        let cfg = ctx.require_config().unwrap();

        let r = verify_scorecard_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("no GitHub repo configured")));
    }

    /// `gh` is present and answers, but the code-scanning query fails — the
    /// live findings still were not read, so this is not a PASS either.
    #[test]
    fn scorecard_degrades_when_live_results_cannot_be_read() {
        let _g = env_lock();
        let gh = fake_gh("#!/bin/sh\necho 'HTTP 403: Resource not accessible' 1>&2\nexit 1\n");
        let _p = PathPrepend::new(gh.path());
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        let cfg = ctx.require_config().unwrap();

        let r = verify_scorecard_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("could not be read") && m.contains("posture unverified")));
    }

    /// A missing workflow is a real, checked finding — not a degrade.
    #[test]
    fn scorecard_fails_when_the_workflow_is_not_installed() {
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        std::fs::remove_file(ctx.root.join(".github/workflows/scorecard.yml")).unwrap();
        let cfg = ctx.require_config().unwrap();
        let r = verify_scorecard_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
    }

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
        // Regression (H3b): open Scorecard findings used to be printed under a
        // PASS verdict. Scorecard is scoring the repo and it has open findings;
        // sscsb routes each to the control that gates it rather than re-gating
        // on another scanner's rubric, so the honest verdict is INFO — context,
        // not a green light.
        assert_eq!(r.outcome, Outcome::Info, "{:?}", r.messages);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("reported as INFO, not PASS")));
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
