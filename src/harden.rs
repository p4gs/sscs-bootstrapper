//! Remediation of remote GitHub settings — the write-side counterpart to the
//! read-only `verify` controls. Today this covers OpenSSF-Scorecard
//! "Branch-Protection" alignment: it sets the ruleset parameters Scorecard
//! scores that a solo maintainer can safely enable, and (only behind
//! `--require-reviews`) the second-reviewer tier that a multi-maintainer repo
//! wants.
//!
//! Safety model: DRY-RUN by default — nothing is written unless `--apply` is
//! passed. The second-reviewer knobs (required approvals / code-owner review /
//! last-push approval) are OFF unless `--require-reviews`, because enabling them
//! on a solo repo locks the owner out of merging their own PRs.

use crate::config::Config;
use crate::context::Ctx;
use crate::exec;
use serde_json::{json, Value};

/// The Scorecard-aligned `pull_request` + `required_status_checks` parameters we
/// want on a protected branch. Pure data so the diff logic is unit-testable
/// without touching the network.
#[derive(Debug, Clone, PartialEq)]
pub struct DesiredBranchProtection {
    pub dismiss_stale_reviews_on_push: bool,
    pub strict_required_status_checks_policy: bool,
    pub required_approving_review_count: u64,
    pub require_code_owner_review: bool,
    pub require_last_push_approval: bool,
}

impl DesiredBranchProtection {
    /// The target posture. `require_reviews` opts into the second-reviewer tier.
    pub fn scorecard_aligned(require_reviews: bool) -> Self {
        Self {
            // Solo-safe knobs — always set.
            dismiss_stale_reviews_on_push: true,
            strict_required_status_checks_policy: true,
            // Second-reviewer tier — only when explicitly requested.
            required_approving_review_count: if require_reviews { 1 } else { 0 },
            require_code_owner_review: require_reviews,
            require_last_push_approval: require_reviews,
        }
    }
}

/// One concrete change the remediation would make, for the dry-run plan.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedChange {
    pub field: String,
    pub from: String,
    pub to: String,
}

/// Diff the desired posture against the current `pull_request` +
/// `required_status_checks` rule parameters (as returned by the rulesets API).
/// Returns only the fields that actually change — an empty vec means the branch
/// is already Scorecard-aligned. Pure function: the heart of the dry-run.
fn bool_change(field: &str, cur: bool, want: bool) -> Option<PlannedChange> {
    (cur != want).then(|| PlannedChange {
        field: field.to_string(),
        from: cur.to_string(),
        to: want.to_string(),
    })
}

/// The outcome of planning: fields that will change, plus fields we WANTED to
/// set but cannot because the target rule is absent (reported honestly — never
/// counted as applied, so a no-op PUT can never read as success).
#[derive(Debug, Clone, PartialEq)]
pub struct BranchPlan {
    pub changes: Vec<PlannedChange>,
    pub skipped: Vec<String>,
}

/// Diff the desired posture against the current rule parameters. `None` for a
/// rule means it is ABSENT from the ruleset — its fields are skipped (and
/// surfaced), never planned.
pub fn plan_branch_protection(
    pr_params: Option<&Value>,
    scs_params: Option<&Value>,
    desired: &DesiredBranchProtection,
) -> BranchPlan {
    let mut changes = Vec::new();
    let mut skipped = Vec::new();
    match pr_params {
        Some(pr) => {
            let cur_bool = |k: &str| pr.get(k).and_then(Value::as_bool).unwrap_or(false);
            changes.extend(bool_change(
                "dismiss_stale_reviews_on_push",
                cur_bool("dismiss_stale_reviews_on_push"),
                desired.dismiss_stale_reviews_on_push,
            ));
            changes.extend(bool_change(
                "require_code_owner_review",
                cur_bool("require_code_owner_review"),
                desired.require_code_owner_review,
            ));
            changes.extend(bool_change(
                "require_last_push_approval",
                cur_bool("require_last_push_approval"),
                desired.require_last_push_approval,
            ));
            let cur_appr = pr
                .get("required_approving_review_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if cur_appr != desired.required_approving_review_count {
                changes.push(PlannedChange {
                    field: "required_approving_review_count".into(),
                    from: cur_appr.to_string(),
                    to: desired.required_approving_review_count.to_string(),
                });
            }
        }
        None => skipped.push(
            "pull_request rule absent — branch protection needs a required-PR rule \
             (`sscsb init` sets one)"
                .into(),
        ),
    }
    match scs_params {
        Some(scs) => changes.extend(bool_change(
            "strict_required_status_checks_policy",
            scs.get("strict_required_status_checks_policy")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            desired.strict_required_status_checks_policy,
        )),
        None if desired.strict_required_status_checks_policy => skipped.push(
            "strict status checks — no required_status_checks rule present; add CI checks \
             first (`sscsb init` installs them)"
                .into(),
        ),
        None => {}
    }
    BranchPlan { changes, skipped }
}

/// Apply `desired` onto a ruleset JSON body's rules array in place, returning the
/// mutated body ready to PUT back. Preserves every other rule and field.
/// Pure function so the merge is testable without the network.
pub fn apply_to_ruleset(mut ruleset: Value, desired: &DesiredBranchProtection) -> Value {
    if let Some(rules) = ruleset.get_mut("rules").and_then(Value::as_array_mut) {
        for rule in rules.iter_mut() {
            let ty = rule.get("type").and_then(Value::as_str).map(str::to_owned);
            let Some(obj) = rule.as_object_mut() else {
                continue;
            };
            match ty.as_deref() {
                Some("pull_request") => {
                    // Create parameters if the rule lacks them, so a present-but-
                    // bare rule can still be set (never a silent no-op).
                    if let Some(p) = obj
                        .entry("parameters")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                    {
                        p.insert(
                            "dismiss_stale_reviews_on_push".into(),
                            json!(desired.dismiss_stale_reviews_on_push),
                        );
                        p.insert(
                            "require_code_owner_review".into(),
                            json!(desired.require_code_owner_review),
                        );
                        p.insert(
                            "require_last_push_approval".into(),
                            json!(desired.require_last_push_approval),
                        );
                        p.insert(
                            "required_approving_review_count".into(),
                            json!(desired.required_approving_review_count),
                        );
                    }
                }
                Some("required_status_checks") => {
                    if let Some(p) = obj
                        .entry("parameters")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                    {
                        p.insert(
                            "strict_required_status_checks_policy".into(),
                            json!(desired.strict_required_status_checks_policy),
                        );
                    }
                }
                _ => {}
            }
        }
    }
    ruleset
}

/// Render the plan: the achievable changes, the honest skips, and the
/// solo-lockout caution — the warning is shown in BOTH modes because
/// --require-reviews is the mode that can actually lock a solo owner out.
pub fn render_plan(branch: &str, plan: &BranchPlan, require_reviews: bool) -> Vec<String> {
    let mut out = Vec::new();
    if plan.changes.is_empty() {
        out.push(format!(
            "{branch}: no applicable changes — already aligned for the rules present"
        ));
    } else {
        out.push(format!(
            "{branch}: {} change(s) planned:",
            plan.changes.len()
        ));
        for c in &plan.changes {
            out.push(format!("  {} : {} → {}", c.field, c.from, c.to));
        }
    }
    for s in &plan.skipped {
        out.push(format!("  skipped: {s}"));
    }
    if require_reviews {
        out.push(
            "  ⚠ --require-reviews requires a 2nd approver: a solo owner without a bypass \
             actor will be UNABLE to merge their own PRs"
                .to_string(),
        );
    } else {
        out.push(
            "  (second-reviewer knobs left off — a solo maintainer cannot self-approve; \
             re-run with --require-reviews once you have a 2nd reviewer)"
                .to_string(),
        );
    }
    out
}

/// Result of a harden run for one control.
pub struct HardenResult {
    pub id: &'static str,
    pub lines: Vec<String>,
    pub applied: bool,
    pub ok: bool,
}

/// Remediate branch protection on every protected branch.
/// `apply=false` → dry-run (print the plan). `apply=true` → PUT the updated
/// ruleset(s). This function is the network boundary (excluded from coverage);
/// the diff/merge logic it calls is unit-tested above.
pub fn harden_branch_protection(
    ctx: &Ctx,
    cfg: &Config,
    apply: bool,
    require_reviews: bool,
) -> HardenResult {
    let id = "branch-protection";
    let mut lines = Vec::new();
    if exec::find_in_path("gh").is_none() {
        return HardenResult {
            id,
            lines: vec![crate::tools::degrade_message("gh", ctx.platform)],
            applied: false,
            ok: false,
        };
    }
    let Some(slug) = cfg.github_repo().or_else(|| ctx.origin_slug()) else {
        return HardenResult {
            id,
            lines: vec!["no GitHub repo configured and no origin remote".into()],
            applied: false,
            ok: false,
        };
    };
    let desired = DesiredBranchProtection::scorecard_aligned(require_reviews);
    let mut all_ok = true;
    let mut any_applied = false;
    let mut any_ruleset = false;
    // A single ~DEFAULT_BRANCH ruleset matches both "main" and "master"; plan and
    // PUT each ruleset at most once.
    let mut handled: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for branch in cfg.protected_branches() {
        let Some((ruleset_id, ruleset)) = find_branch_ruleset(ctx, &slug, &branch) else {
            lines.push(format!(
                "{branch}: no ruleset targets this branch — skipped (does it exist / is it protected?)"
            ));
            continue;
        };
        any_ruleset = true;
        if !handled.insert(ruleset_id) {
            continue; // same ruleset already handled for another branch
        }
        let plan = plan_branch_protection(
            rule_params(&ruleset, "pull_request"),
            rule_params(&ruleset, "required_status_checks"),
            &desired,
        );
        lines.extend(render_plan(&branch, &plan, require_reviews));
        if plan.changes.is_empty() || !apply {
            continue;
        }
        let updated = apply_to_ruleset(ruleset.clone(), &desired);
        match put_ruleset(ctx, &slug, ruleset_id, &updated) {
            Ok(()) => {
                any_applied = true;
                lines.push(format!(
                    "{branch}: applied ✓ ({} field(s))",
                    plan.changes.len()
                ));
            }
            Err(e) => {
                all_ok = false;
                lines.push(format!("{branch}: apply FAILED — {e:#}"));
            }
        }
    }
    if !any_ruleset {
        lines.push(
            "no branch-protection ruleset found for any configured branch — create one \
             (`sscsb init` guidance)"
                .into(),
        );
        all_ok = false;
    }
    if !apply {
        lines.push("dry-run — re-run with --apply to write these changes".into());
    }
    HardenResult {
        id,
        lines,
        applied: any_applied,
        ok: all_ok,
    }
}

fn rule_params<'a>(ruleset: &'a Value, ty: &str) -> Option<&'a Value> {
    ruleset
        .get("rules")
        .and_then(Value::as_array)?
        .iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some(ty))
        .and_then(|r| r.get("parameters"))
}

/// Find the full ruleset object (and id) that applies a pull_request rule to
/// `branch`. Network boundary — excluded from coverage.
fn find_branch_ruleset(ctx: &Ctx, slug: &str, branch: &str) -> Option<(u64, Value)> {
    let list = exec::run(
        "gh",
        &["api", &format!("repos/{slug}/rulesets")],
        Some(&ctx.root),
    )
    .ok()?;
    if !list.success() {
        return None;
    }
    let rulesets: Vec<Value> = serde_json::from_str(&list.stdout).unwrap_or_default();
    for rs in rulesets {
        // Skip a malformed/transient entry rather than abandoning the whole search.
        let Some(id) = rs.get("id").and_then(Value::as_u64) else {
            continue;
        };
        let Ok(full) = exec::run(
            "gh",
            &["api", &format!("repos/{slug}/rulesets/{id}")],
            Some(&ctx.root),
        ) else {
            continue;
        };
        if !full.success() {
            continue;
        }
        let body: Value = serde_json::from_str(&full.stdout).unwrap_or_default();
        let has_pr = body
            .get("rules")
            .and_then(Value::as_array)
            .map(|rules| {
                rules
                    .iter()
                    .any(|r| r.get("type").and_then(Value::as_str) == Some("pull_request"))
            })
            .unwrap_or(false);
        let targets_branch = ruleset_targets_branch(&body, branch);
        if has_pr && targets_branch {
            return Some((id, body));
        }
    }
    None
}

fn ruleset_targets_branch(body: &Value, branch: &str) -> bool {
    let includes = body
        .get("conditions")
        .and_then(|c| c.get("ref_name"))
        .and_then(|r| r.get("include"))
        .and_then(Value::as_array);
    match includes {
        Some(list) => list.iter().filter_map(Value::as_str).any(|inc| {
            inc == "~DEFAULT_BRANCH" || inc == "~ALL" || inc == format!("refs/heads/{branch}")
        }),
        None => false,
    }
}

/// Project a ruleset GET response down to only the fields the PUT API accepts.
/// The GET also returns read-only fields (id, node_id, _links, created_at,
/// updated_at, current_user_can_bypass, source, source_type) that a PUT may
/// reject — send only the documented writable subset. Pure/testable.
pub fn writable_ruleset_body(body: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for k in [
        "name",
        "target",
        "enforcement",
        "conditions",
        "rules",
        "bypass_actors",
    ] {
        if let Some(v) = body.get(k) {
            out.insert(k.to_string(), v.clone());
        }
    }
    Value::Object(out)
}

/// PUT the updated ruleset back, piping the JSON body via stdin (`--input -`).
/// Network boundary — excluded from coverage.
fn put_ruleset(ctx: &Ctx, slug: &str, id: u64, body: &Value) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(&writable_ruleset_body(body))?;
    let out = exec::run_with_stdin(
        "gh",
        &[
            "api",
            "-X",
            "PUT",
            &format!("repos/{slug}/rulesets/{id}"),
            "--input",
            "-",
        ],
        Some(&ctx.root),
        Some(&payload),
    )?;
    if out.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "{}",
            out.stderr.lines().next().unwrap_or("gh api PUT failed")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scorecard_aligned_solo_leaves_review_knobs_off() {
        let d = DesiredBranchProtection::scorecard_aligned(false);
        assert!(d.dismiss_stale_reviews_on_push);
        assert!(d.strict_required_status_checks_policy);
        assert_eq!(d.required_approving_review_count, 0);
        assert!(!d.require_code_owner_review);
        assert!(!d.require_last_push_approval);
    }

    #[test]
    fn scorecard_aligned_with_reviews_sets_second_reviewer_tier() {
        let d = DesiredBranchProtection::scorecard_aligned(true);
        assert_eq!(d.required_approving_review_count, 1);
        assert!(d.require_code_owner_review);
        assert!(d.require_last_push_approval);
    }

    #[test]
    fn plan_reports_only_changed_fields() {
        let pr = json!({
            "dismiss_stale_reviews_on_push": false,
            "require_code_owner_review": false,
            "require_last_push_approval": false,
            "required_approving_review_count": 0
        });
        let scs = json!({ "strict_required_status_checks_policy": false });
        let desired = DesiredBranchProtection::scorecard_aligned(false);
        let changes = plan_branch_protection(Some(&pr), Some(&scs), &desired).changes;
        // Solo posture flips dismiss_stale + strict only; review knobs already 0/false.
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"dismiss_stale_reviews_on_push"));
        assert!(fields.contains(&"strict_required_status_checks_policy"));
        assert!(!fields.contains(&"require_code_owner_review"));
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn plan_empty_when_already_aligned() {
        let pr = json!({
            "dismiss_stale_reviews_on_push": true,
            "require_code_owner_review": false,
            "require_last_push_approval": false,
            "required_approving_review_count": 0
        });
        let scs = json!({ "strict_required_status_checks_policy": true });
        let desired = DesiredBranchProtection::scorecard_aligned(false);
        assert!(plan_branch_protection(Some(&pr), Some(&scs), &desired)
            .changes
            .is_empty());
    }

    #[test]
    fn plan_skips_strict_when_no_status_checks_rule_and_flags_absent_pr() {
        // scs rule absent → strict is SKIPPED (never planned → never falsely applied)
        let pr =
            json!({ "dismiss_stale_reviews_on_push": true, "required_approving_review_count": 0 });
        let desired = DesiredBranchProtection::scorecard_aligned(false);
        let plan = plan_branch_protection(Some(&pr), None, &desired);
        assert!(plan.changes.is_empty(), "{:?}", plan.changes);
        assert!(plan
            .skipped
            .iter()
            .any(|s| s.contains("required_status_checks")));
        // pr rule absent → flagged as skipped too
        let plan2 = plan_branch_protection(None, None, &desired);
        assert!(plan2
            .skipped
            .iter()
            .any(|s| s.contains("pull_request rule absent")));
    }

    #[test]
    fn writable_ruleset_body_keeps_only_put_fields() {
        let body = json!({
            "id": 7, "node_id": "R_x", "created_at": "2020", "updated_at": "2021",
            "current_user_can_bypass": "always", "_links": {}, "source": "repo", "source_type": "Repository",
            "name": "bp", "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
            "rules": [{"type": "deletion"}], "bypass_actors": []
        });
        let w = writable_ruleset_body(&body);
        let obj = w.as_object().unwrap();
        for k in [
            "name",
            "target",
            "enforcement",
            "conditions",
            "rules",
            "bypass_actors",
        ] {
            assert!(obj.contains_key(k), "missing writable {k}");
        }
        for k in [
            "id",
            "node_id",
            "created_at",
            "updated_at",
            "current_user_can_bypass",
            "_links",
            "source",
            "source_type",
        ] {
            assert!(!obj.contains_key(k), "read-only {k} should be stripped");
        }
    }

    #[test]
    fn apply_creates_parameters_when_a_present_rule_lacks_them() {
        // pull_request rule with NO parameters object — apply must create + set it.
        let ruleset = json!({ "rules": [{ "type": "pull_request" }] });
        let desired = DesiredBranchProtection::scorecard_aligned(false);
        let out = apply_to_ruleset(ruleset, &desired);
        let p = out["rules"][0]
            .get("parameters")
            .expect("parameters created");
        assert_eq!(p.get("dismiss_stale_reviews_on_push").unwrap(), true);
    }

    #[test]
    fn require_reviews_plans_the_second_reviewer_tier() {
        let pr = json!({
            "dismiss_stale_reviews_on_push": true,
            "require_code_owner_review": false,
            "require_last_push_approval": false,
            "required_approving_review_count": 0
        });
        let scs = json!({ "strict_required_status_checks_policy": true });
        let desired = DesiredBranchProtection::scorecard_aligned(true);
        let changes = plan_branch_protection(Some(&pr), Some(&scs), &desired).changes;
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"require_code_owner_review"));
        assert!(fields.contains(&"require_last_push_approval"));
        assert!(fields.contains(&"required_approving_review_count"));
        assert_eq!(changes.len(), 3);
    }

    #[test]
    fn apply_to_ruleset_mutates_pr_and_scs_preserving_other_rules() {
        let ruleset = json!({
            "id": 42,
            "name": "bp",
            "rules": [
                { "type": "deletion" },
                { "type": "pull_request", "parameters": {
                    "dismiss_stale_reviews_on_push": false,
                    "required_approving_review_count": 0,
                    "require_code_owner_review": false,
                    "require_last_push_approval": false,
                    "allowed_merge_methods": ["squash"]
                }},
                { "type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": false,
                    "required_status_checks": [{"context": "test"}]
                }}
            ]
        });
        let desired = DesiredBranchProtection::scorecard_aligned(false);
        let out = apply_to_ruleset(ruleset, &desired);
        let rules = out.get("rules").unwrap().as_array().unwrap();
        // deletion rule preserved untouched
        assert_eq!(rules[0].get("type").unwrap(), "deletion");
        let pr = rules[1].get("parameters").unwrap();
        assert_eq!(pr.get("dismiss_stale_reviews_on_push").unwrap(), true);
        // sibling param preserved
        assert_eq!(pr.get("allowed_merge_methods").unwrap()[0], "squash");
        // review knobs stay solo-safe
        assert_eq!(pr.get("required_approving_review_count").unwrap(), 0);
        let scs = rules[2].get("parameters").unwrap();
        assert_eq!(
            scs.get("strict_required_status_checks_policy").unwrap(),
            true
        );
        assert_eq!(
            scs.get("required_status_checks").unwrap()[0]
                .get("context")
                .unwrap(),
            "test"
        );
    }

    #[test]
    fn render_plan_notes_solo_cap_and_empty_case() {
        let empty = render_plan(
            "main",
            &BranchPlan {
                changes: vec![],
                skipped: vec![],
            },
            false,
        );
        assert!(empty[0].contains("no applicable changes"));
        let plan = BranchPlan {
            changes: vec![PlannedChange {
                field: "dismiss_stale_reviews_on_push".into(),
                from: "false".into(),
                to: "true".into(),
            }],
            skipped: vec!["strict status checks — no required_status_checks rule".into()],
        };
        let solo = render_plan("main", &plan, false);
        assert!(solo
            .iter()
            .any(|l| l.contains("second-reviewer knobs left off")));
        assert!(solo.iter().any(|l| l.contains("skipped:")));
        // --require-reviews mode shows the lockout warning, not the "left off" note.
        let rr = render_plan("main", &plan, true);
        assert!(rr.iter().any(|l| l.contains("UNABLE to merge")));
        assert!(!rr
            .iter()
            .any(|l| l.contains("second-reviewer knobs left off")));
    }

    #[test]
    fn ruleset_targets_branch_matches_default_and_explicit() {
        let default_branch = json!({"conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"]}}});
        assert!(ruleset_targets_branch(&default_branch, "main"));
        let explicit = json!({"conditions":{"ref_name":{"include":["refs/heads/main"]}}});
        assert!(ruleset_targets_branch(&explicit, "main"));
        let other = json!({"conditions":{"ref_name":{"include":["refs/heads/dev"]}}});
        assert!(!ruleset_targets_branch(&other, "main"));
        let none = json!({"conditions":{}});
        assert!(!ruleset_targets_branch(&none, "main"));
    }

    // --- network-boundary tests via a stubbed `gh` on PATH ---
    use crate::testutil::{fake_gh, repo_with_gh_repo, PathPrepend, PATH_LOCK};

    const RULESET_STUB: &str = r#"#!/bin/sh
case "$1 $2 $3" in
  "api repos/acme/demo/rulesets ")
    echo '[{"id":7}]'; exit 0;;
  "api repos/acme/demo/rulesets/7 ")
    echo '{"id":7,"name":"bp","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"bypass_actors":[],"rules":[{"type":"pull_request","parameters":{"dismiss_stale_reviews_on_push":false,"require_code_owner_review":false,"require_last_push_approval":false,"required_approving_review_count":0}},{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true}}]}'; exit 0;;
  "api -X PUT")
    cat >/dev/null; echo '{"id":7}'; exit 0;;
  *) echo '[]'; exit 0;;
esac
"#;

    #[test]
    fn harden_branch_protection_dry_run_then_apply() {
        let _g = PATH_LOCK.lock().unwrap();
        let gh = fake_gh(RULESET_STUB);
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        let _p = PathPrepend::new(gh.path());
        let cfg = ctx.require_config().unwrap();

        let dry = harden_branch_protection(&ctx, cfg, false, false);
        assert!(dry.ok && !dry.applied, "{:?}", dry.lines);
        assert!(dry
            .lines
            .iter()
            .any(|l| l.contains("dismiss_stale_reviews_on_push")));
        assert!(dry.lines.iter().any(|l| l.contains("dry-run")));

        let applied = harden_branch_protection(&ctx, cfg, true, false);
        assert!(applied.ok && applied.applied, "{:?}", applied.lines);
        assert!(applied.lines.iter().any(|l| l.contains("applied ✓")));
    }

    #[test]
    fn harden_reports_missing_ruleset() {
        let _g = PATH_LOCK.lock().unwrap();
        let gh = fake_gh("#!/bin/sh\necho '[]'\nexit 0\n");
        let (_d, ctx) = repo_with_gh_repo("acme/demo", "main");
        let _p = PathPrepend::new(gh.path());
        let cfg = ctx.require_config().unwrap();
        let r = harden_branch_protection(&ctx, cfg, false, false);
        assert!(!r.ok);
        assert!(r
            .lines
            .iter()
            .any(|l| l.contains("no ruleset targets this branch")));
        assert!(r
            .lines
            .iter()
            .any(|l| l.contains("no branch-protection ruleset found for any configured branch")));
    }
}
