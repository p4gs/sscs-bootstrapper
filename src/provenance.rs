//! Provenance & signing orchestration: slsa-verifier verification gates,
//! DSSE/in-toto statement inspection, cosign keyless sign/verify wrappers,
//! and (optional) AI provenance receipts.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;
use anyhow::{Context as _, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::path::Path;

// ─────────────────────────── slsa-verifier ──────────────────────────────────

pub struct ProvenanceArgs<'a> {
    pub artifact: &'a Path,
    pub provenance: &'a Path,
    pub source_uri: &'a str,
    pub source_tag: Option<&'a str>,
}

/// Verify an artifact's SLSA provenance with slsa-verifier. Returns the tool's
/// stdout on success.
pub fn verify_artifact(ctx: &Ctx, args: &ProvenanceArgs) -> Result<String> {
    if !tools::is_available("slsa-verifier") {
        anyhow::bail!("{}", tools::degrade_message("slsa-verifier", ctx.platform));
    }
    let artifact = args.artifact.display().to_string();
    let provenance = args.provenance.display().to_string();
    let mut argv: Vec<&str> = vec![
        "verify-artifact",
        &artifact,
        "--provenance-path",
        &provenance,
        "--source-uri",
        args.source_uri,
    ];
    if let Some(tag) = args.source_tag {
        argv.push("--source-tag");
        argv.push(tag);
    }
    let out = exec::run("slsa-verifier", &argv, None)?;
    if !out.success() {
        anyhow::bail!(
            "slsa-verifier FAILED (exit {}):\n{}{}",
            out.status,
            out.stdout,
            out.stderr
        );
    }
    Ok(format!("{}{}", out.stdout, out.stderr))
}

// ─────────────────────────── DSSE / in-toto ─────────────────────────────────

#[derive(Debug)]
pub struct StatementSummary {
    pub statement_type: String,
    pub predicate_type: String,
    pub subjects: Vec<(String, String)>,
    pub builder_id: Option<String>,
}

/// Inspect a DSSE envelope (or `.intoto.jsonl` line) and summarize the
/// in-toto statement inside.
pub fn inspect_dsse(text: &str) -> Result<StatementSummary> {
    // A .intoto.jsonl file may hold one envelope per line; take the first.
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .context("empty provenance file")?;
    let envelope: serde_json::Value =
        serde_json::from_str(line).context("provenance is not JSON")?;
    let statement: serde_json::Value =
        if let Some(payload) = envelope.get("payload").and_then(|p| p.as_str()) {
            let payload_type = envelope
                .get("payloadType")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            anyhow::ensure!(
                payload_type == "application/vnd.in-toto+json",
                "unexpected DSSE payloadType `{payload_type}`"
            );
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(payload)
                .context("DSSE payload is not base64")?;
            serde_json::from_slice(&decoded).context("DSSE payload is not JSON")?
        } else {
            envelope // bare in-toto statement
        };
    let subjects = statement
        .get("subject")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .map(|s| {
                    let name = s.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    let digest = s
                        .get("digest")
                        .and_then(|d| d.as_object())
                        .and_then(|d| d.iter().next())
                        .map(|(alg, v)| format!("{alg}:{}", v.as_str().unwrap_or("?")))
                        .unwrap_or_else(|| "?".to_string());
                    (name.to_string(), digest)
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(StatementSummary {
        statement_type: statement
            .get("_type")
            .and_then(|t| t.as_str())
            .unwrap_or("?")
            .to_string(),
        predicate_type: statement
            .get("predicateType")
            .and_then(|t| t.as_str())
            .unwrap_or("?")
            .to_string(),
        subjects,
        builder_id: statement
            .pointer("/predicate/runDetails/builder/id")
            .or_else(|| statement.pointer("/predicate/builder/id"))
            .and_then(|b| b.as_str())
            .map(str::to_string),
    })
}

// ─────────────────────────── cosign wrappers ────────────────────────────────

/// Keyless sign-blob. Interactive OIDC in a headless session will fail — that
/// failure is surfaced verbatim (this is primarily a CI-side operation, where
/// ambient OIDC exists).
pub fn cosign_sign_blob(ctx: &Ctx, artifact: &Path, bundle_out: &Path) -> Result<String> {
    if !tools::is_available("cosign") {
        anyhow::bail!("{}", tools::degrade_message("cosign", ctx.platform));
    }
    let artifact_s = artifact.display().to_string();
    let bundle_s = bundle_out.display().to_string();
    let out = exec::run(
        "cosign",
        &["sign-blob", &artifact_s, "--bundle", &bundle_s, "--yes"],
        None,
    )?;
    if !out.success() {
        anyhow::bail!(
            "cosign sign-blob failed (exit {}): {} — keyless signing needs an OIDC identity \
             (ambient in CI; interactive browser flow locally)",
            out.status,
            out.stderr.trim()
        );
    }
    Ok(out.stderr) // cosign logs to stderr
}

pub fn cosign_verify_blob(
    ctx: &Ctx,
    artifact: &Path,
    bundle: &Path,
    identity: &str,
    issuer: &str,
) -> Result<String> {
    if !tools::is_available("cosign") {
        anyhow::bail!("{}", tools::degrade_message("cosign", ctx.platform));
    }
    let artifact_s = artifact.display().to_string();
    let bundle_s = bundle.display().to_string();
    let out = exec::run(
        "cosign",
        &[
            "verify-blob",
            &artifact_s,
            "--bundle",
            &bundle_s,
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
        ],
        None,
    )?;
    if !out.success() {
        anyhow::bail!(
            "cosign verify-blob FAILED (exit {}): {}",
            out.status,
            out.stderr.trim()
        );
    }
    Ok(format!("{}{}", out.stdout, out.stderr))
}

// ─────────────────────────── AI receipts ────────────────────────────────────

/// Predicate type URI for sscsb AI provenance receipts (namespaced to this
/// project's repository).
pub const RECEIPT_PREDICATE_TYPE: &str =
    "https://github.com/p4gs/sscs-bootstrapper/ai-provenance/v1";

/// Create an in-toto-style AI provenance receipt for a commit: binds the
/// commit id + a sha256 of its full patch to the declared AI tool/model/role.
pub fn create_receipt(ctx: &Ctx, commit: &str, out_dir: &Path) -> Result<std::path::PathBuf> {
    let sha = exec::git(&["rev-parse", commit], &ctx.root)?;
    let patch = exec::git(&["show", "--format=", "--no-color", &sha], &ctx.root)?;
    let patch_digest = hex::encode(Sha256::digest(patch.as_bytes()));
    let body = exec::git(&["log", "-1", "--format=%B", &sha], &ctx.root)?;
    let trailers = crate::hooks::parse_trailers(&body);
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": format!("git-commit:{sha}"),
            "digest": { "gitCommit": sha, "sha256": patch_digest }
        }],
        "predicateType": RECEIPT_PREDICATE_TYPE,
        "predicate": {
            "aiAssisted": trailers.get("AI-Assisted").cloned().unwrap_or_else(|| "undeclared".into()),
            "aiTool": trailers.get("AI-Tool").cloned(),
            "aiModel": trailers.get("AI-Model").cloned(),
            "aiRole": trailers.get("AI-Role").cloned(),
            "patchSha256": patch_digest,
            "generatedBy": format!("sscsb {}", env!("CARGO_PKG_VERSION")),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }
    });
    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join(format!("receipt-{}.json", &sha[..12]));
    std::fs::write(&path, serde_json::to_string_pretty(&statement)?)?;
    Ok(path)
}

/// Verify a receipt against the repository: recompute the commit's patch
/// digest and compare.
pub fn verify_receipt(ctx: &Ctx, receipt_path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(receipt_path)?;
    let v: serde_json::Value = serde_json::from_str(&text).context("receipt is not JSON")?;
    anyhow::ensure!(
        v.get("predicateType").and_then(|p| p.as_str()) == Some(RECEIPT_PREDICATE_TYPE),
        "not an sscsb AI provenance receipt"
    );
    let commit = v
        .pointer("/subject/0/digest/gitCommit")
        .and_then(|c| c.as_str())
        .context("receipt missing gitCommit digest")?;
    let claimed = v
        .pointer("/subject/0/digest/sha256")
        .and_then(|c| c.as_str())
        .context("receipt missing sha256 digest")?;
    let patch = exec::git(&["show", "--format=", "--no-color", commit], &ctx.root)?;
    let actual = hex::encode(Sha256::digest(patch.as_bytes()));
    anyhow::ensure!(
        actual == claimed,
        "receipt DIGEST MISMATCH for {commit}: receipt claims {claimed}, repository has {actual} \
         — the commit or the receipt has been tampered with"
    );
    Ok(format!(
        "receipt verified: commit {commit} patch digest {actual} matches"
    ))
}

// ─────────────────────────── control verifiers ──────────────────────────────

pub fn verify_provenance_control(ctx: &Ctx) -> VerifyResult {
    let mut messages = Vec::new();
    let mut outcome = Outcome::Pass;
    for tool in ["slsa-verifier", "cosign"] {
        match tools::detect(tools::spec(tool).expect("registry")) {
            tools::ToolStatus::Found { version, .. } => messages.push(format!(
                "{tool}: {}",
                version.unwrap_or_else(|| "available".into())
            )),
            tools::ToolStatus::Missing => {
                outcome = Outcome::Degraded;
                messages.push(tools::degrade_message(tool, ctx.platform));
            }
        }
    }
    messages.push(
        "gate: `sscsb provenance verify --artifact <f> --provenance <f>.intoto.jsonl \
         --source-uri github.com/<owner>/<repo> [--source-tag vX.Y.Z]`"
            .into(),
    );
    let deploy_gate = ctx
        .root
        .join(".github")
        .join("workflows")
        .join("deploy-gate.yml");
    if deploy_gate.is_file() {
        messages.push("deploy-gate workflow present (verification before publish)".into());
    }
    VerifyResult::new("provenance-verify", outcome, messages)
}

pub fn verify_receipts_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = vec![
        "receipts: `sscsb receipt create [commit]` → .sscsb/out/receipts/, \
         `sscsb receipt verify <file>` recomputes the patch digest"
            .into(),
    ];
    let sign = cfg
        .control_opt_bool("ai-receipts", "sign_with_cosign")
        .unwrap_or(false);
    if sign {
        if tools::is_available("cosign") {
            messages.push("cosign signing of receipts: enabled and cosign available".into());
        } else {
            messages.push(tools::degrade_message("cosign", ctx.platform));
            return VerifyResult::new("ai-receipts", Outcome::Degraded, messages);
        }
    } else {
        messages.push("cosign signing of receipts: disabled (sign_with_cosign=false)".into());
    }
    VerifyResult::new("ai-receipts", Outcome::Pass, messages)
}

pub fn verify_witness_control(ctx: &Ctx) -> VerifyResult {
    match tools::detect(tools::spec("witness").expect("registry")) {
        tools::ToolStatus::Found { version, .. } => VerifyResult::new(
            "witness",
            Outcome::Pass,
            vec![format!(
                "witness {} available — see docs/phase-3.md for run wrapping",
                version.unwrap_or_else(|| "?".into())
            )],
        ),
        tools::ToolStatus::Missing => VerifyResult::new(
            "witness",
            Outcome::Degraded,
            vec![tools::degrade_message("witness", ctx.platform)],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init;
    use crate::sast::tests::{serialized, with_fake_tool, with_only_git_on_path};

    fn repo() -> (tempfile::TempDir, Ctx) {
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

    fn write(ctx: &Ctx, rel: &str, content: &str) {
        let path = ctx.root.join(rel);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn commit_all(ctx: &Ctx, message: &str) {
        exec::git(&["add", "-A"], &ctx.root).unwrap();
        exec::git(&["commit", "-m", message, "--no-verify"], &ctx.root).unwrap();
    }

    // ─────────────────────────────── DSSE / in-toto ─────────────────────────

    #[test]
    fn inspect_dsse_decodes_envelope() {
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact.tgz", "digest": {"sha256": "abc123"}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"runDetails": {"builder": {"id": "https://github.com/slsa-framework/builder"}}}
        });
        let payload = base64::engine::general_purpose::STANDARD.encode(statement.to_string());
        let envelope = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": []
        });
        let summary = inspect_dsse(&envelope.to_string()).unwrap();
        assert_eq!(summary.statement_type, "https://in-toto.io/Statement/v1");
        assert_eq!(summary.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(summary.subjects[0].0, "artifact.tgz");
        assert_eq!(summary.subjects[0].1, "sha256:abc123");
        assert!(summary.builder_id.unwrap().contains("slsa-framework"));
    }

    #[test]
    fn inspect_dsse_rejects_wrong_payload_type() {
        let envelope = serde_json::json!({
            "payloadType": "application/json",
            "payload": "e30=",
        });
        assert!(inspect_dsse(&envelope.to_string()).is_err());
        assert!(inspect_dsse("").is_err());
    }

    #[test]
    fn inspect_accepts_bare_statement() {
        let statement =
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x"}"#;
        let s = inspect_dsse(statement).unwrap();
        assert_eq!(s.predicate_type, "x");
        assert!(s.subjects.is_empty());
    }

    #[test]
    fn inspect_dsse_rejects_non_json_input() {
        let err = inspect_dsse("not json at all").unwrap_err();
        assert!(format!("{err:#}").contains("not JSON"));
    }

    #[test]
    fn inspect_dsse_rejects_payload_that_is_not_base64() {
        let envelope = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": "!!! not base64 !!!",
        });
        let err = inspect_dsse(&envelope.to_string()).unwrap_err();
        assert!(format!("{err:#}").contains("not base64"));
    }

    #[test]
    fn inspect_dsse_rejects_base64_payload_that_is_not_json() {
        let payload = base64::engine::general_purpose::STANDARD.encode("not json inside");
        let envelope = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
        });
        let err = inspect_dsse(&envelope.to_string()).unwrap_err();
        assert!(format!("{err:#}").contains("DSSE payload is not JSON"));
    }

    #[test]
    fn inspect_dsse_takes_the_first_non_blank_line_of_a_jsonl_file() {
        let statement =
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"first"}"#;
        let text = format!(
            "\n  \n{statement}\n{{\"_type\":\"x\",\"subject\":[],\"predicateType\":\"second\"}}\n"
        );
        let s = inspect_dsse(&text).unwrap();
        assert_eq!(s.predicate_type, "first");
    }

    #[test]
    fn inspect_dsse_falls_back_to_unknown_builder_id_and_subject_digest_shape() {
        let statement =
            r#"{"_type":"x","subject":[{"digest":{"sha256":"deadbeef"}}],"predicateType":"y"}"#;
        let s = inspect_dsse(statement).unwrap();
        assert!(s.builder_id.is_none(), "no builder id present in predicate");
        assert_eq!(s.subjects[0].0, "?", "missing subject name falls back to ?");
        assert_eq!(s.subjects[0].1, "sha256:deadbeef");
    }

    // ─────────────────────────── slsa-verifier wrapper ───────────────────────

    #[test]
    fn verify_artifact_degrades_when_slsa_verifier_missing_and_fails_loudly_when_present() {
        let (_d, ctx) = repo();
        let artifact = ctx.root.join("artifact.txt");
        let provenance = ctx.root.join("nope.intoto.jsonl");
        std::fs::write(&artifact, b"hello\n").unwrap();

        let args = ProvenanceArgs {
            artifact: &artifact,
            provenance: &provenance,
            source_uri: "github.com/o/r",
            source_tag: None,
        };
        let err = with_only_git_on_path(|| verify_artifact(&ctx, &args)).unwrap_err();
        assert!(format!("{err:#}").contains("slsa-verifier not found"));

        // Real binary, bogus provenance path: must fail LOUDLY (never a silent
        // pass), and the optional --source-tag argument branch is exercised.
        let args_tagged = ProvenanceArgs {
            artifact: &artifact,
            provenance: &provenance,
            source_uri: "github.com/o/r",
            source_tag: Some("v1.0.0"),
        };
        let err = serialized(|| verify_artifact(&ctx, &args_tagged)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("FAILED") || msg.to_lowercase().contains("no such file"),
            "{msg}"
        );
    }

    // ────────────────────────────── cosign wrappers ──────────────────────────

    #[test]
    fn cosign_sign_blob_degrades_when_missing_and_surfaces_a_failure_when_present() {
        let (_d, ctx) = repo();
        let artifact = ctx.root.join("artifact.txt");
        let bundle = ctx.root.join("bundle.json");
        std::fs::write(&artifact, b"hello\n").unwrap();

        let err = with_only_git_on_path(|| cosign_sign_blob(&ctx, &artifact, &bundle)).unwrap_err();
        assert!(format!("{err:#}").contains("cosign not found"));

        // A real `cosign sign-blob` needs an interactive/ambient OIDC identity
        // that a headless test cannot provide and would otherwise hang on a
        // device-flow prompt — shim a `cosign` that reports a deterministic
        // signing failure instead, exercising the exact same success-check
        // and error-formatting code as a real failed signing attempt.
        let script = "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"cosign 0.0.0\"; exit 0; fi\necho 'Error: no OIDC identity available' 1>&2\nexit 1\n";
        let err = with_fake_tool("cosign", script, || {
            cosign_sign_blob(&ctx, &artifact, &bundle)
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cosign sign-blob failed"), "{msg}");
        assert!(
            msg.contains("keyless signing needs an OIDC identity"),
            "{msg}"
        );
        assert!(
            !bundle.exists(),
            "a failed signing attempt must not leave a bundle behind"
        );
    }

    #[test]
    fn cosign_verify_blob_degrades_when_missing_and_rejects_a_bogus_bundle_when_present() {
        let (_d, ctx) = repo();
        let artifact = ctx.root.join("artifact.txt");
        let bundle = ctx.root.join("bogus.sigstore.json");
        std::fs::write(&artifact, b"hello\n").unwrap();
        std::fs::write(&bundle, r#"{"not":"a bundle"}"#).unwrap();

        let err = with_only_git_on_path(|| cosign_verify_blob(&ctx, &artifact, &bundle, "x", "y"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("cosign not found"));

        let err = serialized(|| {
            cosign_verify_blob(
                &ctx,
                &artifact,
                &bundle,
                "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main",
                "https://token.actions.githubusercontent.com",
            )
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("cosign verify-blob FAILED"),
            "a bogus bundle must not verify: {err:#}"
        );
    }

    // ─────────────────────────────── AI receipts ─────────────────────────────

    #[test]
    fn receipts_bind_commits_and_detect_tampering() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(
            &ctx,
            "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft",
        );
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");
        let receipt = create_receipt(&ctx, "HEAD", &out_dir).unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&receipt).unwrap()).unwrap();
        assert_eq!(doc["predicateType"], RECEIPT_PREDICATE_TYPE);
        assert_eq!(doc["predicate"]["aiTool"], "Claude Code");
        assert_eq!(doc["predicate"]["aiRole"], "draft");
        assert_eq!(doc["predicate"]["aiAssisted"], "true");

        let ok = verify_receipt(&ctx, &receipt).unwrap();
        assert!(ok.contains("receipt verified"));

        // Tampered digest is caught — this is the tamper-detection contract;
        // it must keep failing closed and must never be weakened.
        let text = std::fs::read_to_string(&receipt).unwrap();
        std::fs::write(
            &receipt,
            text.replacen("\"sha256\": \"", "\"sha256\": \"ff", 1),
        )
        .unwrap();
        let err = verify_receipt(&ctx, &receipt).unwrap_err();
        assert!(format!("{err:#}").contains("DIGEST MISMATCH"));

        // A non-receipt JSON file is rejected.
        let other = ctx.root.join("other.json");
        std::fs::write(
            &other,
            r#"{"predicateType":"https://slsa.dev/provenance/v1"}"#,
        )
        .unwrap();
        let err = verify_receipt(&ctx, &other).unwrap_err();
        assert!(format!("{err:#}").contains("not an sscsb AI provenance receipt"));
    }

    #[test]
    fn create_receipt_defaults_ai_assisted_to_undeclared_without_trailers() {
        let (_d, ctx) = repo();
        write(&ctx, "b.txt", "b\n");
        commit_all(&ctx, "chore: plain commit, no AI trailers");
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");
        let receipt = create_receipt(&ctx, "HEAD", &out_dir).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&receipt).unwrap()).unwrap();
        assert_eq!(doc["predicate"]["aiAssisted"], "undeclared");
        assert!(doc["predicate"]["aiTool"].is_null());
    }

    #[test]
    fn verify_receipt_reports_unreadable_file_and_malformed_json() {
        let (_d, ctx) = repo();
        let err = verify_receipt(&ctx, &ctx.root.join("does-not-exist.json")).unwrap_err();
        assert!(!format!("{err:#}").is_empty());

        let bad = ctx.root.join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        let err = verify_receipt(&ctx, &bad).unwrap_err();
        assert!(format!("{err:#}").contains("receipt is not JSON"));
    }

    #[test]
    fn verify_receipt_requires_gitcommit_and_sha256_digest_fields() {
        let (_d, ctx) = repo();
        let missing_commit = ctx.root.join("missing-commit.json");
        std::fs::write(
            &missing_commit,
            serde_json::json!({"predicateType": RECEIPT_PREDICATE_TYPE, "subject": [{"digest": {}}]})
                .to_string(),
        )
        .unwrap();
        let err = verify_receipt(&ctx, &missing_commit).unwrap_err();
        assert!(format!("{err:#}").contains("missing gitCommit digest"));

        let missing_sha = ctx.root.join("missing-sha.json");
        std::fs::write(
            &missing_sha,
            serde_json::json!({
                "predicateType": RECEIPT_PREDICATE_TYPE,
                "subject": [{"digest": {"gitCommit": "deadbeef"}}]
            })
            .to_string(),
        )
        .unwrap();
        let err = verify_receipt(&ctx, &missing_sha).unwrap_err();
        assert!(format!("{err:#}").contains("missing sha256 digest"));
    }

    // ─────────────────────────── control verifiers ───────────────────────────

    #[test]
    fn verify_provenance_control_reports_both_tools_and_the_deploy_gate_workflow() {
        let (_d, ctx) = repo();
        let result = serialized(|| verify_provenance_control(&ctx));
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result
            .messages
            .iter()
            .any(|m| m.starts_with("slsa-verifier:")));
        assert!(result.messages.iter().any(|m| m.starts_with("cosign:")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("deploy-gate workflow present")));
    }

    #[test]
    fn verify_provenance_control_degrades_when_both_tools_are_missing() {
        let (_d, ctx) = repo();
        let result = with_only_git_on_path(|| verify_provenance_control(&ctx));
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("slsa-verifier not found")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("cosign not found")));
    }

    #[test]
    fn verify_receipts_control_reflects_signing_toggle_and_cosign_availability() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        let result = serialized(|| verify_receipts_control(&ctx, cfg));
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("cosign signing of receipts: disabled")));

        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace("sign_with_cosign = false", "sign_with_cosign = true");
        std::fs::write(&cfg_path, text).unwrap();
        let ctx2 = Ctx::discover(&ctx.root).unwrap();
        let cfg2 = ctx2.require_config().unwrap();

        let result = serialized(|| verify_receipts_control(&ctx2, cfg2));
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("enabled and cosign available")));

        let result = with_only_git_on_path(|| verify_receipts_control(&ctx2, cfg2));
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("cosign not found")));
    }

    #[test]
    fn verify_witness_control_reports_found_and_missing() {
        let (_d, ctx) = repo();
        let missing = serialized(|| verify_witness_control(&ctx));
        assert_eq!(missing.outcome, Outcome::Degraded);
        assert!(missing.messages[0].contains("witness"));

        let script =
            "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"witness 0.12.0\"; fi\nexit 0\n";
        let found = with_fake_tool("witness", script, || verify_witness_control(&ctx));
        assert_eq!(found.outcome, Outcome::Pass);
        assert!(
            found.messages[0].contains("witness") && found.messages[0].contains("available"),
            "{:?}",
            found.messages
        );
    }
}
