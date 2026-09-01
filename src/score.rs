//! SSCSB Scorecard: the repository's live control posture as one
//! machine-readable, signable, publishable document.
//!
//! `sscsb verify` answers "is this repo healthy?" for the person standing in
//! it. The scorecard answers the same question for everyone else — the SSCSB
//! Directory, a badge, a dependency-picker comparing two libraries — and that
//! audience changes the shape of the answer in three ways:
//!
//! 1. **It is a document, not an exit code.** Every control's outcome and
//!    messages, plus an aggregate score, in one JSON file a site can ingest.
//! 2. **Unknown is not failure.** A control that could not be evaluated
//!    (DEGRADED — tool missing, no token, no GitHub repo configured) is
//!    excluded from the score and *counted against completeness* instead.
//!    A scan run without repository credentials is honestly labeled
//!    `partial`; the same repo scanned by its own CI — where `GITHUB_TOKEN`
//!    can read settings no outsider can — earns `complete`. The gap between
//!    the two tiers is the pitch for installing the publish workflow, never
//!    a hidden penalty.
//! 3. **A published result must be provable.** The document is keyless-signed
//!    in the producing repo's own CI (cosign sign-blob, GitHub OIDC), and
//!    `sscsb score verify` pins the certificate identity to *that repo's
//!    canonical publish workflow on its live default branch* — the same
//!    trust construction OpenSSF Scorecard's results API uses, and the same
//!    one this repo's own `release-attest.yml` applies to artifacts:
//!    verifying that *something* signed a result is close to worthless;
//!    verifying that *this repo's scorecard workflow* did is the control.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{self, Outcome};
use crate::exec;
use crate::provenance;
use crate::tools;
use anyhow::{Context as _, Result};
use std::path::{Path, PathBuf};

/// Document type URI for SSCSB Scorecard results (namespaced to this
/// project's repository, like `RECEIPT_PREDICATE_TYPE`).
pub const SCORECARD_DOC_TYPE: &str =
    "https://github.com/p4gs/sscs-bootstrapper/scorecard-result/v1";

/// Schema majors this sscsb knows how to verify. An unknown major means the
/// structural checks below are not evidence of anything.
pub const KNOWN_SCHEMA_MAJORS: &[u64] = &[1];

/// The canonical publish workflow path. Verification pins the signing
/// certificate to exactly this path in the claimed repository — a result
/// signed by any *other* workflow, even in the right repo, does not verify.
pub const SCORECARD_WORKFLOW_PATH: &str = ".github/workflows/sscsb-scorecard.yml";

/// Where `score emit` writes by default (`.sscsb/out/` is gitignored by
/// `sscsb init`; in a scratch checkout the location is simply conventional).
pub const DEFAULT_OUTPUT_REL: &str = ".sscsb/out/score/sscsb-scorecard.json";

// ─────────────────────────── scoring math ───────────────────────────────────

/// Aggregate score over the *determinate* outcomes only.
///
/// PASS and FAIL are verdicts; everything else is either a policy choice
/// (disabled), a non-verdict (INFO), or an absence of evidence (DEGRADED),
/// and averaging absences into a number would let an unreadable repo look
/// worse — or better — than a read one. `None` when nothing was determinate:
/// a score computed over zero checks is not 0.0, it is no score at all.
pub fn score_from_counts(passes: u32, fails: u32) -> Option<f64> {
    let determinate = passes + fails;
    if determinate == 0 {
        return None;
    }
    // 0–10 with one decimal, Scorecard-style.
    Some((f64::from(passes) / f64::from(determinate) * 100.0).round() / 10.0)
}

/// `complete` only when every enabled control produced evidence. One
/// DEGRADED control means something went unevaluated, and a tier that
/// stayed `complete` anyway would make the label meaningless.
pub fn completeness_tier(enabled: u32, degraded: u32) -> &'static str {
    if enabled > 0 && degraded == 0 {
        "complete"
    } else {
        "partial"
    }
}

// ─────────────────────────── document build ─────────────────────────────────

/// Run every registered control and fold the outcomes into the scorecard
/// document.
///
/// Works with or without `.sscsb/config.toml`: the SSCSB Directory scores
/// arbitrary public repositories, and for a repo that never ran `sscsb init`
/// the honest baseline is the registry defaults — the same config `init`
/// would write — recorded in the document as `"config": "registry-defaults"`
/// so a reader can tell a scored-as-found repo from a configured one.
pub fn build_document(ctx: &Ctx) -> Result<serde_json::Value> {
    let synthesized;
    let (cfg, config_source) = match ctx.config.as_ref() {
        Some(c) => (c, "repo"),
        None => {
            synthesized = Config::defaults();
            (&synthesized, "registry-defaults")
        }
    };

    let mut rows = Vec::with_capacity(controls::CONTROLS.len());
    let (mut passes, mut fails, mut degraded, mut disabled, mut info) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    for def in controls::CONTROLS {
        let result = controls::verify_control(ctx, cfg, def);
        match result.outcome {
            Outcome::Pass => passes += 1,
            Outcome::Fail => fails += 1,
            Outcome::Degraded => degraded += 1,
            Outcome::Disabled => disabled += 1,
            Outcome::Info => info += 1,
        }
        rows.push(serde_json::json!({
            "id": result.control,
            "phase": def.phase,
            "outcome": result.outcome.symbol(),
            "messages": result.messages,
        }));
    }

    let total = u32::try_from(controls::CONTROLS.len()).expect("registry fits in u32");
    let enabled = total - disabled;
    let evaluated = enabled - degraded;
    let slug = cfg.github_repo().or_else(|| ctx.origin_slug());
    let commit = exec::git(&["rev-parse", "--verify", "HEAD"], &ctx.root).ok();

    Ok(serde_json::json!({
        "documentType": SCORECARD_DOC_TYPE,
        "schemaVersion": 1,
        "generator": {
            "tool": "sscsb",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "repo": {
            "slug": slug,
            "commit": commit,
            "defaultBranch": ctx.default_branch(),
        },
        "config": config_source,
        "score": {
            "value": score_from_counts(passes, fails),
            "passes": passes,
            "fails": fails,
            "determinate": passes + fails,
        },
        "completeness": {
            "tier": completeness_tier(enabled, degraded),
            "enabled": enabled,
            "evaluated": evaluated,
            "degraded": degraded,
            "disabled": disabled,
            "informational": info,
        },
        "controls": rows,
    }))
}

// ─────────────────────────── emit ───────────────────────────────────────────

/// `sscsb score emit`. Always exit 0 on success: the *document* is the
/// deliverable, and a repo full of FAILs still emits faithfully — gating is
/// `sscsb verify`'s job, and an emit that failed on a bad score could never
/// score a bad repo.
pub fn cmd_score_emit(ctx: &Ctx, output: Option<&Path>, to_stdout: bool, sign: bool) -> Result<u8> {
    let doc = build_document(ctx)?;
    let rendered = serde_json::to_string_pretty(&doc)?;

    if to_stdout {
        if sign {
            anyhow::bail!("--sign needs a file to sign — drop --stdout or pass --output");
        }
        println!("{rendered}");
        return Ok(0);
    }

    let path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| ctx.root.join(DEFAULT_OUTPUT_REL));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, &rendered).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", path.display());
    summarize(&doc);

    if sign {
        let bundle = provenance::receipt_bundle_path(&path);
        provenance::cosign_sign_blob(ctx, &path, &bundle)?;
        println!("signed: bundle at {}", bundle.display());
    }
    Ok(0)
}

fn summarize(doc: &serde_json::Value) {
    let score = doc
        .pointer("/score/value")
        .and_then(serde_json::Value::as_f64)
        .map_or_else(|| "n/a".to_string(), |v| format!("{v:.1}"));
    let tier = doc
        .pointer("/completeness/tier")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let degraded = doc
        .pointer("/completeness/degraded")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    println!("score: {score}/10 — completeness: {tier} ({degraded} control(s) unevaluated)");
}

// ─────────────────────────── verify ─────────────────────────────────────────

/// Live default branch of `slug`, from the GitHub API.
///
/// The pinned certificate identity names the publish workflow *on the
/// default branch*, and the branch has to come from GitHub, not from the
/// document: a document that named its own trusted branch would let a
/// signature minted on any branch nominate itself.
///
/// Network boundary — excluded from coverage.
fn live_default_branch(root: &Path, slug: &str) -> Option<String> {
    let out = exec::run(
        "gh",
        &["api", &format!("repos/{slug}"), "--jq", ".default_branch"],
        Some(root),
    )
    .ok()?;
    if !out.success() {
        return None;
    }
    let branch = out.stdout.trim().to_string();
    if branch.is_empty() {
        None
    } else {
        Some(branch)
    }
}

/// The certificate identity a genuine publish run produces: the canonical
/// workflow path in the claimed repository, on the given branch.
pub fn expected_identity(slug: &str, branch: &str) -> String {
    format!("https://github.com/{slug}/{SCORECARD_WORKFLOW_PATH}@refs/heads/{branch}")
}

/// `sscsb score verify` — the Directory-side (or anyone-side) check that a
/// scorecard result really came from the repository it claims to describe.
///
/// Exit 1 is a *verdict* (the document failed verification); operational
/// errors — no cosign, no way to construct the pinned identity — are `Err`
/// (exit 2), because "could not check" must never be printable as "checked
/// and failed", in either direction.
///
/// What is checked, in order, failing closed at each step:
/// 1. the document parses, is a scorecard result, and has a known schema major;
/// 2. the repo it claims to describe is the repo the caller expects (`--repo`);
/// 3. a Sigstore bundle exists beside it — an unsigned result is a claim,
///    not evidence, so absence is a FAIL rather than a shrug;
/// 4. cosign verifies the bundle against the pinned identity: the canonical
///    `sscsb-scorecard.yml` of that exact repository at its *live* default
///    branch (fetched from GitHub, never trusted from the document), issued
///    by GitHub Actions' OIDC issuer.
///
/// Residual trust, said out loud: this proves the result was produced and
/// signed by that repo's own publish workflow — nobody else can forge it —
/// but a repository owner who edits their workflow can still sign whatever
/// it emits. Closing that (fetching the workflow at the certificate's commit
/// and rule-checking it, as OpenSSF Scorecard's API does) is the Directory's
/// ingestion-hardening follow-up, not a property this command claims.
pub fn cmd_score_verify(
    ctx: &Ctx,
    result: &Path,
    repo: &str,
    identity: Option<&str>,
    issuer: Option<&str>,
    bundle: Option<&Path>,
) -> Result<u8> {
    let text =
        std::fs::read_to_string(result).with_context(|| format!("reading {}", result.display()))?;

    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            println!("[FAIL] {} is not valid JSON: {e}", result.display());
            return Ok(1);
        }
    };
    if doc.get("documentType").and_then(serde_json::Value::as_str) != Some(SCORECARD_DOC_TYPE) {
        println!("[FAIL] not an SSCSB Scorecard result (documentType != {SCORECARD_DOC_TYPE})");
        return Ok(1);
    }
    let major = doc.get("schemaVersion").and_then(serde_json::Value::as_u64);
    if !major.is_some_and(|m| KNOWN_SCHEMA_MAJORS.contains(&m)) {
        println!(
            "[FAIL] unknown schemaVersion {major:?} — this sscsb verifies majors {KNOWN_SCHEMA_MAJORS:?}, \
             and structural checks against an unknown schema are not evidence"
        );
        return Ok(1);
    }
    let claimed = doc
        .pointer("/repo/slug")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if claimed != repo {
        println!(
            "[FAIL] document claims repository `{claimed}`, expected `{repo}` — \
             a result is only evidence about the repo whose workflow signed it"
        );
        return Ok(1);
    }

    let bundle_path: PathBuf = bundle
        .map(Path::to_path_buf)
        .unwrap_or_else(|| provenance::receipt_bundle_path(result));
    if !bundle_path.is_file() {
        println!(
            "[FAIL] no Sigstore bundle at {} — an unsigned scorecard result is a claim, \
             not evidence; the Directory lists only verified results",
            bundle_path.display()
        );
        return Ok(1);
    }

    // Operational prerequisites AFTER the structural verdicts: a missing tool
    // must not mask "this document is wrong about itself".
    if !tools::is_available("cosign") {
        anyhow::bail!("{}", tools::degrade_message("cosign", ctx.platform));
    }
    let identity_owned;
    let identity = match identity {
        Some(i) => i,
        None => {
            if exec::find_in_path("gh").is_none() {
                anyhow::bail!(
                    "cannot construct the pinned certificate identity: the identity names \
                     the publish workflow on the repo's LIVE default branch, which needs the \
                     GitHub API — install `gh`, or pass --identity explicitly"
                );
            }
            let branch = live_default_branch(&ctx.root, repo).ok_or_else(|| {
                anyhow::anyhow!(
                    "could not read the default branch of {repo} from the GitHub API — \
                     without it the pinned identity cannot be constructed; pass --identity \
                     to supply one explicitly"
                )
            })?;
            identity_owned = expected_identity(repo, &branch);
            &identity_owned
        }
    };
    let issuer = issuer.unwrap_or(provenance::GITHUB_OIDC_ISSUER);

    match provenance::cosign_verify_blob(ctx, result, &bundle_path, identity, issuer) {
        Ok(_) => {
            println!("[PASS] scorecard result VERIFIED for {repo}");
            println!("       identity: {identity}");
            println!("       issuer:   {issuer}");
            println!("       bundle:   {}", bundle_path.display());
            summarize(&doc);
            Ok(0)
        }
        Err(e) => {
            println!("[FAIL] signature verification failed: {e:#}");
            println!("       pinned identity was: {identity}");
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init;
    use crate::testutil;

    fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let out = exec::run("git", &["init", "-b", "main"], Some(dir.path())).unwrap();
        assert!(out.success());
        for (k, v) in [("user.name", "t"), ("user.email", "t@example.invalid")] {
            exec::run("git", &["config", k, v], Some(dir.path())).unwrap();
        }
        exec::run(
            "git",
            &["config", "commit.gpgsign", "false"],
            Some(dir.path()),
        )
        .unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        (dir, ctx)
    }

    fn bootstrapped() -> (tempfile::TempDir, Ctx) {
        let (dir, _) = repo();
        init::bootstrap(dir.path()).unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn score_math_scores_only_determinate_outcomes() {
        assert_eq!(score_from_counts(0, 0), None);
        assert_eq!(score_from_counts(10, 0), Some(10.0));
        assert_eq!(score_from_counts(0, 10), Some(0.0));
        assert_eq!(score_from_counts(1, 2), Some(3.3));
        assert_eq!(score_from_counts(2, 1), Some(6.7));
    }

    #[test]
    fn completeness_tier_is_partial_the_moment_anything_went_unevaluated() {
        assert_eq!(completeness_tier(40, 0), "complete");
        assert_eq!(completeness_tier(40, 1), "partial");
        // Zero enabled controls cannot be a "complete" evaluation of anything.
        assert_eq!(completeness_tier(0, 0), "partial");
    }

    #[test]
    fn expected_identity_names_the_canonical_workflow_on_the_given_branch() {
        assert_eq!(
            expected_identity("p4gs/example", "main"),
            "https://github.com/p4gs/example/.github/workflows/sscsb-scorecard.yml@refs/heads/main"
        );
    }

    #[test]
    fn document_covers_every_registered_control_exactly_once() {
        let (_dir, ctx) = bootstrapped();
        let doc = build_document(&ctx).unwrap();
        assert_eq!(doc["documentType"].as_str().unwrap(), SCORECARD_DOC_TYPE);
        assert_eq!(doc["schemaVersion"].as_u64().unwrap(), 1);
        assert_eq!(doc["config"].as_str().unwrap(), "repo");
        let rows = doc["controls"].as_array().unwrap();
        assert_eq!(rows.len(), controls::CONTROLS.len());
        let mut ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), controls::CONTROLS.len(), "duplicate control row");
    }

    #[test]
    fn document_counts_are_internally_consistent() {
        let (_dir, ctx) = bootstrapped();
        let doc = build_document(&ctx).unwrap();
        let rows = doc["controls"].as_array().unwrap();
        let count = |sym: &str| {
            u64::try_from(
                rows.iter()
                    .filter(|r| r["outcome"].as_str() == Some(sym))
                    .count(),
            )
            .unwrap()
        };
        assert_eq!(
            doc.pointer("/score/passes").unwrap().as_u64(),
            Some(count("PASS"))
        );
        assert_eq!(
            doc.pointer("/score/fails").unwrap().as_u64(),
            Some(count("FAIL"))
        );
        assert_eq!(
            doc.pointer("/completeness/degraded").unwrap().as_u64(),
            Some(count("DEGRADED"))
        );
        assert_eq!(
            doc.pointer("/completeness/disabled").unwrap().as_u64(),
            Some(count("disabled"))
        );
        let enabled = doc
            .pointer("/completeness/enabled")
            .unwrap()
            .as_u64()
            .unwrap();
        let disabled = doc
            .pointer("/completeness/disabled")
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(
            enabled + disabled,
            u64::try_from(controls::CONTROLS.len()).unwrap()
        );
        // A fresh bootstrap degrades several controls (documented in
        // AGENTS.md), so the fixture exercises the partial tier for real.
        assert_eq!(
            doc.pointer("/completeness/tier").unwrap().as_str(),
            Some("partial")
        );
    }

    #[test]
    fn an_unbootstrapped_repo_is_scored_against_registry_defaults_and_says_so() {
        let (_dir, ctx) = repo();
        assert!(ctx.config.is_none());
        let doc = build_document(&ctx).unwrap();
        assert_eq!(doc["config"].as_str().unwrap(), "registry-defaults");
        // Un-bootstrapped ≠ unscoreable: the whole Directory funnel rests on
        // arbitrary repos getting an honest (low) score, not an error.
        assert_eq!(
            doc["controls"].as_array().unwrap().len(),
            controls::CONTROLS.len()
        );
    }

    #[test]
    fn emit_writes_the_document_and_stdout_mode_refuses_to_sign() {
        let (_dir, ctx) = bootstrapped();
        let out = ctx.root.join("scorecard.json");
        assert_eq!(cmd_score_emit(&ctx, Some(&out), false, false).unwrap(), 0);
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(doc["documentType"].as_str().unwrap(), SCORECARD_DOC_TYPE);

        let err = cmd_score_emit(&ctx, None, true, true).unwrap_err();
        assert!(format!("{err:#}").contains("--sign needs a file"));
    }

    #[test]
    fn emit_defaults_to_the_conventional_out_path() {
        let (_dir, ctx) = bootstrapped();
        assert_eq!(cmd_score_emit(&ctx, None, false, false).unwrap(), 0);
        assert!(ctx.root.join(DEFAULT_OUTPUT_REL).is_file());
    }

    #[test]
    fn emit_sign_produces_a_bundle_via_cosign() {
        let lock = testutil::env_lock();
        let script = r#"#!/bin/sh
# `tools::detect` probes `cosign version` and needs exit 0 + output.
case "$1" in version) echo "cosign version 3.1.1"; exit 0;; esac
# args: sign-blob <artifact> --bundle <path> --yes
bundle=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--bundle" ]; then bundle="$a"; fi
  prev="$a"
done
echo '{"stub":"bundle"}' > "$bundle"
exit 0
"#;
        lock.fake_tool("cosign", script);
        let (_dir, ctx) = bootstrapped();
        let out = ctx.root.join("scorecard.json");
        assert_eq!(cmd_score_emit(&ctx, Some(&out), false, true).unwrap(), 0);
        assert!(provenance::receipt_bundle_path(&out).is_file());
    }

    fn write_doc(ctx: &Ctx, mutate: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
        let mut doc = build_document(ctx).unwrap();
        mutate(&mut doc);
        let path = ctx.root.join("result.json");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        path
    }

    #[test]
    fn verify_rejects_documents_that_are_wrong_about_themselves() {
        let (_dir, ctx) = bootstrapped();

        // Not JSON at all.
        let garbled = ctx.root.join("garbled.json");
        std::fs::write(&garbled, "not json").unwrap();
        assert_eq!(
            cmd_score_verify(&ctx, &garbled, "p4gs/example", None, None, None).unwrap(),
            1
        );

        // Wrong document type.
        let wrong_type = write_doc(&ctx, |d| {
            d["documentType"] = serde_json::json!("https://example.invalid/other/v1");
        });
        assert_eq!(
            cmd_score_verify(&ctx, &wrong_type, "p4gs/example", None, None, None).unwrap(),
            1
        );

        // Unknown schema major.
        let wrong_major = write_doc(&ctx, |d| {
            d["schemaVersion"] = serde_json::json!(99);
        });
        assert_eq!(
            cmd_score_verify(&ctx, &wrong_major, "p4gs/example", None, None, None).unwrap(),
            1
        );

        // Claims a different repository than the caller expects.
        let wrong_repo = write_doc(&ctx, |d| {
            d["repo"]["slug"] = serde_json::json!("someone/else");
        });
        assert_eq!(
            cmd_score_verify(&ctx, &wrong_repo, "p4gs/example", None, None, None).unwrap(),
            1
        );
    }

    #[test]
    fn verify_fails_closed_on_a_missing_bundle() {
        let (_dir, ctx) = bootstrapped();
        let doc = write_doc(&ctx, |d| {
            d["repo"]["slug"] = serde_json::json!("p4gs/example");
        });
        // No .sigstore.json beside it: unsigned is a verdict, not a shrug.
        assert_eq!(
            cmd_score_verify(&ctx, &doc, "p4gs/example", None, None, None).unwrap(),
            1
        );
    }

    #[test]
    fn verify_without_an_identity_source_is_an_error_not_a_verdict() {
        let lock = testutil::env_lock();
        // cosign present (so the tool gate passes), gh absent (so the pinned
        // identity cannot be constructed).
        lock.fake_tool("cosign", "#!/bin/sh\necho 'cosign version 3.1.1'\nexit 0\n");
        lock.hide_from_path(&["gh"]);
        let (_dir, ctx) = bootstrapped();
        let doc = write_doc(&ctx, |d| {
            d["repo"]["slug"] = serde_json::json!("p4gs/example");
        });
        std::fs::write(provenance::receipt_bundle_path(&doc), "{}").unwrap();
        let err = cmd_score_verify(&ctx, &doc, "p4gs/example", None, None, None).unwrap_err();
        assert!(
            format!("{err:#}").contains("LIVE default branch"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn verify_pins_identity_from_the_live_default_branch_and_passes() {
        let lock = testutil::env_lock();
        // gh answers the default-branch query; cosign records its arguments
        // so the test can assert exactly what identity was pinned.
        lock.fake_tool(
            "gh",
            "#!/bin/sh\ncase \"$2\" in repos/*) echo trunk; exit 0;; esac\nexit 1\n",
        );
        let (_dir, ctx) = bootstrapped();
        let argfile = ctx.root.join("cosign-args.txt");
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in version) echo 'cosign version 3.1.1'; exit 0;; esac\n\
             printf '%s\\n' \"$@\" > {}\necho verified\nexit 0\n",
            argfile.display()
        );
        lock.fake_tool("cosign", &script);

        let doc = write_doc(&ctx, |d| {
            d["repo"]["slug"] = serde_json::json!("p4gs/example");
        });
        std::fs::write(provenance::receipt_bundle_path(&doc), "{}").unwrap();
        assert_eq!(
            cmd_score_verify(&ctx, &doc, "p4gs/example", None, None, None).unwrap(),
            0
        );
        let args = std::fs::read_to_string(&argfile).unwrap();
        assert!(
            args.contains(&expected_identity("p4gs/example", "trunk")),
            "cosign was not pinned to the canonical workflow identity: {args}"
        );
        assert!(args.contains(provenance::GITHUB_OIDC_ISSUER));
    }

    #[test]
    fn verify_reports_a_failed_signature_as_a_verdict() {
        let lock = testutil::env_lock();
        lock.fake_tool(
            "cosign",
            "#!/bin/sh\ncase \"$1\" in version) echo 'cosign version 3.1.1'; exit 0;; esac\n\
             echo 'no match' >&2\nexit 1\n",
        );
        let (_dir, ctx) = bootstrapped();
        let doc = write_doc(&ctx, |d| {
            d["repo"]["slug"] = serde_json::json!("p4gs/example");
        });
        std::fs::write(provenance::receipt_bundle_path(&doc), "{}").unwrap();
        // Explicit --identity: no gh needed, straight to cosign, which fails.
        assert_eq!(
            cmd_score_verify(
                &ctx,
                &doc,
                "p4gs/example",
                Some("https://github.com/p4gs/example/.github/workflows/sscsb-scorecard.yml@refs/heads/main"),
                None,
                None
            )
            .unwrap(),
            1
        );
    }
}
