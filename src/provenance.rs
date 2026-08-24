//! Provenance & signing orchestration: slsa-verifier verification gates,
//! DSSE/in-toto statement inspection, cosign keyless sign/verify wrappers,
//! and (optional) AI provenance receipts.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::exec::is_object_name;
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
    // `commit` is a CLI argument, so a revision *expression* (`HEAD~2`, a tag, a
    // branch) is legitimate and must keep working; the strict shape guard is
    // applied to the resolved sha, and to receipt-supplied names in
    // `verify_receipt`. `--end-of-options` is what stops git reading a
    // leading-dash value as a flag.
    let sha = exec::git(
        &["rev-parse", "--verify", "--end-of-options", commit],
        &ctx.root,
    )?;
    let file_name = receipt_file_name(commit, &sha)?;
    let patch = exec::git(&["show", "--format=", "--no-color", &sha], &ctx.root)?;
    let patch_digest = hex::encode(Sha256::digest(patch.as_bytes()));
    let claim = AiClaim::from_commit(ctx, &sha)?;
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": format!("git-commit:{sha}"),
            "digest": { "gitCommit": sha, "sha256": patch_digest }
        }],
        "predicateType": RECEIPT_PREDICATE_TYPE,
        "predicate": {
            "aiAssisted": claim.assisted,
            "aiTool": claim.tool,
            "aiModel": claim.model,
            "aiRole": claim.role,
            "patchSha256": patch_digest,
            "generatedBy": format!("sscsb {}", env!("CARGO_PKG_VERSION")),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }
    });
    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join(file_name);
    std::fs::write(&path, serde_json::to_string_pretty(&statement)?)?;
    Ok(path)
}

/// The receipt filename for a sha that `git rev-parse --verify` resolved.
///
/// Reported (M16): `sscsb receipt create -- --raw` exited 101. Before
/// `--verify`, the resolver was a bare `git rev-parse <commit>`, and rev-parse
/// ECHOES an unrecognised option back at exit 0 — `git rev-parse --raw` prints
/// `--raw`, five characters — so this function's twelve-character slice ran off
/// the end: "end byte index 12 is out of bounds for string of length 5".
/// A CLI must never abort on its own argument.
///
/// `--verify` closed that door; the length check closes the class. `rev-parse
/// --verify` resolves to a FULL object name — 40 hex under sha1, 64 under
/// sha256 — while [`is_object_name`] deliberately admits abbreviations from 7
/// characters, because a RECEIPT may legitimately carry an abbreviated name.
/// This value did not come from a receipt, so anything shorter than a full oid
/// means the invocation did not do what the caller believes it did, and the
/// honest answer is an error rather than a filename built from a slice that
/// happens not to panic.
fn receipt_file_name(commit: &str, sha: &str) -> Result<String> {
    anyhow::ensure!(
        is_object_name(sha) && matches!(sha.len(), 40 | 64),
        "rev-parse resolved {commit:?} to {sha:?}, which is not a full git object name"
    );
    // Belt and braces: `get` cannot panic even if the guard above is ever
    // loosened. A filename is not worth a process abort.
    Ok(format!("receipt-{}.json", sha.get(..12).unwrap_or(sha)))
}

/// The AI claim a receipt makes about a commit: exactly the four trailers
/// `create_receipt` reads, in one place so creation and verification cannot
/// drift apart.
#[derive(Debug, PartialEq, Eq)]
struct AiClaim {
    assisted: String,
    tool: Option<String>,
    model: Option<String>,
    role: Option<String>,
}

impl AiClaim {
    /// What the repository says, right now, about `sha`.
    fn from_commit(ctx: &Ctx, sha: &str) -> Result<Self> {
        let body = exec::git(
            &["log", "-1", "--format=%B", "--end-of-options", sha],
            &ctx.root,
        )?;
        let t = crate::hooks::parse_trailers(&body);
        Ok(AiClaim {
            assisted: t
                .get("AI-Assisted")
                .cloned()
                .unwrap_or_else(|| "undeclared".into()),
            tool: t.get("AI-Tool").cloned(),
            model: t.get("AI-Model").cloned(),
            role: t.get("AI-Role").cloned(),
        })
    }

    /// What the receipt says.
    fn from_predicate(predicate: &serde_json::Value) -> Self {
        let field = |k: &str| {
            predicate
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        AiClaim {
            assisted: field("aiAssisted").unwrap_or_else(|| "undeclared".into()),
            tool: field("aiTool"),
            model: field("aiModel"),
            role: field("aiRole"),
        }
    }

    /// Field-by-field differences, `self` being the receipt's claim.
    fn differences_from(&self, commit: &AiClaim) -> Vec<String> {
        let show = |v: &Option<String>| match v {
            Some(s) => format!("{s:?}"),
            None => "absent".to_string(),
        };
        let mut out = Vec::new();
        if self.assisted != commit.assisted {
            out.push(format!(
                "aiAssisted: receipt claims {:?}, commit says {:?}",
                self.assisted, commit.assisted
            ));
        }
        for (name, mine, theirs) in [
            ("aiTool", &self.tool, &commit.tool),
            ("aiModel", &self.model, &commit.model),
            ("aiRole", &self.role, &commit.role),
        ] {
            if mine != theirs {
                out.push(format!(
                    "{name}: receipt claims {}, commit says {}",
                    show(mine),
                    show(theirs)
                ));
            }
        }
        out
    }
}

/// Where `receipt create --sign` puts a receipt's cosign bundle. One function
/// so the writer and the reader cannot disagree about the name — until now
/// nothing read it at all.
pub fn receipt_bundle_path(receipt: &Path) -> std::path::PathBuf {
    let mut name = receipt.as_os_str().to_os_string();
    name.push(".sigstore.json");
    std::path::PathBuf::from(name)
}

/// The default OIDC issuer for keyless signatures made in GitHub Actions.
pub const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Verify a receipt against the repository:
///
/// 1. the commit's patch still hashes to the digest the receipt binds, and
/// 2. the commit still declares the AI tool/model/role the receipt claims, and
/// 3. any cosign bundle sitting beside the receipt actually verifies.
///
/// Reported (M8): only (1) existed. A receipt's whole purpose is to bind a
/// commit to a DECLARED AI tool, model and role, and that declaration was the
/// one thing never checked — a receipt whose `aiTool` said "Claude Code" while
/// the commit's trailer said something else verified happily, because the patch
/// bytes were untouched. `--sign` wrote a bundle that nothing ever read, so a
/// signed receipt and an unsigned one verified identically.
///
/// `identity`/`issuer` come from the command line and fall back to
/// `[controls.ai-receipts]` `cosign_identity`/`cosign_issuer`. A bundle that is
/// PRESENT but cannot be checked — no identity to check it against, or no
/// cosign — is an error, not a footnote: "receipt verified" must not be
/// printable next to a signature nobody looked at.
pub fn verify_receipt(
    ctx: &Ctx,
    receipt_path: &Path,
    identity: Option<&str>,
    issuer: Option<&str>,
) -> Result<String> {
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
    // The receipt is the thing under suspicion, so its object name is untrusted
    // input. Reject anything that is not a bare hex object name BEFORE it can
    // reach git's argument parser.
    anyhow::ensure!(
        is_object_name(commit),
        "receipt gitCommit {commit:?} is not a git object name (expected 7-64 lowercase hex) \
         — refusing to pass it to git"
    );
    let claimed = v
        .pointer("/subject/0/digest/sha256")
        .and_then(|c| c.as_str())
        .context("receipt missing sha256 digest")?;
    let patch = exec::git(
        &[
            "show",
            "--format=",
            "--no-color",
            "--end-of-options",
            commit,
        ],
        &ctx.root,
    )?;
    let actual = hex::encode(Sha256::digest(patch.as_bytes()));
    anyhow::ensure!(
        actual == claimed,
        "receipt DIGEST MISMATCH for {commit}: receipt claims {claimed}, repository has {actual} \
         — the commit or the receipt has been tampered with"
    );

    // The claim itself. The patch digest proves the commit's CONTENT is the one
    // the receipt was made from; it says nothing about the AI declaration, which
    // lives in the commit message and is the thing the receipt exists to bind.
    let declared = AiClaim::from_predicate(
        v.get("predicate")
            .context("receipt missing predicate — nothing to check the commit against")?,
    );
    let recorded = AiClaim::from_commit(ctx, commit)?;
    let differences = declared.differences_from(&recorded);
    anyhow::ensure!(
        differences.is_empty(),
        "receipt CLAIM MISMATCH for {commit}: {} \
         — the receipt no longer describes the commit it names",
        differences.join("; ")
    );

    // Any signature sitting beside the receipt.
    let signature = verify_receipt_signature(ctx, receipt_path, identity, issuer)?;

    Ok(format!(
        "receipt verified: commit {commit} patch digest {actual} matches; \
         AI claim matches the commit trailers (aiAssisted={}, aiTool={}); {signature}",
        declared.assisted,
        declared.tool.as_deref().unwrap_or("absent"),
    ))
}

/// Check the cosign bundle beside `receipt_path`, if there is one.
///
/// Fails closed in both directions a signature can be unverifiable: no identity
/// to check it against, and no cosign to check it with. Either way the caller
/// must not go on to print "receipt verified".
fn verify_receipt_signature(
    ctx: &Ctx,
    receipt_path: &Path,
    identity: Option<&str>,
    issuer: Option<&str>,
) -> Result<String> {
    let bundle = receipt_bundle_path(receipt_path);
    if !bundle.is_file() {
        return Ok(format!(
            "no signature bundle at {} (`sscsb receipt create --sign` writes one)",
            bundle.display()
        ));
    }
    let opt = |key: &str| {
        ctx.config
            .as_ref()
            .and_then(|c| c.control_opt_str("ai-receipts", key))
            .filter(|s| !s.trim().is_empty())
    };
    let identity = identity
        .map(str::to_string)
        .or_else(|| opt("cosign_identity"));
    let identity = identity.context(
        "this receipt is SIGNED but there is no identity to verify the signature against — \
         pass `--identity <certificate identity>` or set cosign_identity under \
         [controls.ai-receipts] in .sscsb/config.toml. A signature nobody checks is not \
         evidence, so this is a failure rather than a warning",
    )?;
    let issuer = issuer
        .map(str::to_string)
        .or_else(|| opt("cosign_issuer"))
        .unwrap_or_else(|| GITHUB_OIDC_ISSUER.to_string());
    cosign_verify_blob(ctx, receipt_path, &bundle, &identity, &issuer)?;
    Ok(format!(
        "signature verified against identity {identity} (issuer {issuer})"
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
         `sscsb receipt verify <file>` recomputes the patch digest, re-reads the commit's \
         AI trailers, and verifies any cosign bundle beside the receipt"
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

        let ok = verify_receipt(&ctx, &receipt, None, None).unwrap();
        assert!(ok.contains("receipt verified"));

        // Tampered digest is caught — this is the tamper-detection contract;
        // it must keep failing closed and must never be weakened.
        let text = std::fs::read_to_string(&receipt).unwrap();
        std::fs::write(
            &receipt,
            text.replacen("\"sha256\": \"", "\"sha256\": \"ff", 1),
        )
        .unwrap();
        let err = verify_receipt(&ctx, &receipt, None, None).unwrap_err();
        assert!(format!("{err:#}").contains("DIGEST MISMATCH"));

        // A non-receipt JSON file is rejected.
        let other = ctx.root.join("other.json");
        std::fs::write(
            &other,
            r#"{"predicateType":"https://slsa.dev/provenance/v1"}"#,
        )
        .unwrap();
        let err = verify_receipt(&ctx, &other, None, None).unwrap_err();
        assert!(format!("{err:#}").contains("not an sscsb AI provenance receipt"));
    }

    /// Reported (M8): the receipt's actual CLAIM was never verified.
    ///
    /// A receipt exists to bind a commit to a declared AI tool, model and role.
    /// Verification only recomputed the patch digest — which proves the
    /// commit's CONTENT is what the receipt was made from and says nothing
    /// about the declaration, because the trailers live in the commit message
    /// and are not part of `git show --format=`. So a receipt claiming one tool
    /// over a commit declaring another verified happily, at exit 0.
    #[test]
    fn verify_receipt_rejects_a_claim_the_commit_no_longer_supports() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(
            &ctx,
            "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft",
        );
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");
        let receipt = create_receipt(&ctx, "HEAD", &out_dir).unwrap();
        let genuine = std::fs::read_to_string(&receipt).unwrap();

        // Every field, edited one at a time. The patch digest is left alone in
        // each case, which is exactly why the digest check cannot see any of
        // them: the commit's bytes are untouched.
        let forgeries = [
            ("aiTool", serde_json::json!("Some Other Tool")),
            ("aiModel", serde_json::json!("Some Other Model")),
            ("aiRole", serde_json::json!("author")),
            ("aiAssisted", serde_json::json!("false")),
            // Dropping the declaration entirely is the most useful forgery of
            // all: it launders AI-assisted work into apparently unassisted work.
            ("aiTool", serde_json::json!(null)),
        ];
        for (field, value) in forgeries {
            let mut doc: serde_json::Value = serde_json::from_str(&genuine).unwrap();
            doc["predicate"][field] = value.clone();
            let forged = ctx.root.join("forged-claim.json");
            std::fs::write(&forged, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

            let err = verify_receipt(&ctx, &forged, None, None).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("CLAIM MISMATCH") && msg.contains(field),
                "editing {field} to {value} must be caught and named: {msg}"
            );
        }

        // The unedited receipt still verifies, and says so about the claim.
        let ok = verify_receipt(&ctx, &receipt, None, None).unwrap();
        assert!(ok.contains("AI claim matches"), "{ok}");
        assert!(ok.contains("Claude Code"), "{ok}");
    }

    /// The other half of M8: `--sign` wrote a cosign bundle beside the receipt
    /// and NOTHING ever read it, so a signed receipt and an unsigned one
    /// verified identically. A signature that is present but unchecked must not
    /// be printable next to the words "receipt verified".
    #[test]
    fn verify_receipt_refuses_a_signed_receipt_it_cannot_check() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(&ctx, "feat: x\n\nAI-Assisted: true");
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");
        let receipt = create_receipt(&ctx, "HEAD", &out_dir).unwrap();

        // No bundle: verification says plainly that there is nothing to check.
        let ok = verify_receipt(&ctx, &receipt, None, None).unwrap();
        assert!(ok.contains("no signature bundle"), "{ok}");

        // A bundle appears, and there is no identity to check it against.
        let bundle = receipt_bundle_path(&receipt);
        std::fs::write(&bundle, r#"{"not":"a real bundle"}"#).unwrap();
        let err = verify_receipt(&ctx, &receipt, None, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SIGNED but there is no identity"), "{msg}");
        assert!(msg.contains("--identity"), "names the fix: {msg}");

        // With an identity, the bogus bundle is actually put to cosign, and
        // fails. (When cosign is absent the degrade message is the failure —
        // either way it must not be an Ok.)
        let err = verify_receipt(
            &ctx,
            &receipt,
            Some("https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main"),
            None,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cosign verify-blob FAILED") || msg.contains("cosign not found"),
            "a bogus bundle must never verify: {msg}"
        );
    }

    /// A cosign that says yes is believed, and the identity it was checked
    /// against is named in the verdict — an operator must be able to see WHICH
    /// identity a receipt was accepted for. The identity also comes from
    /// config, so a repo can set its signing policy once.
    #[test]
    fn verify_receipt_reports_the_identity_a_signature_was_checked_against() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(&ctx, "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code");
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");
        let receipt = create_receipt(&ctx, "HEAD", &out_dir).unwrap();
        std::fs::write(receipt_bundle_path(&receipt), r#"{"a":"bundle"}"#).unwrap();

        let script = "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo 'cosign 0.0.0'; exit 0; \
                      fi\necho 'Verified OK' 1>&2\nexit 0\n";
        let ok = with_fake_tool("cosign", script, || {
            verify_receipt(
                &ctx,
                &receipt,
                Some("ci@example.invalid"),
                Some("https://issuer"),
            )
        })
        .unwrap();
        assert!(ok.contains("signature verified"), "{ok}");
        assert!(ok.contains("ci@example.invalid"), "{ok}");
        assert!(ok.contains("https://issuer"), "{ok}");

        // Same thing, but the identity comes from .sscsb/config.toml.
        let cfg_path = ctx.config_path();
        let text = std::fs::read_to_string(&cfg_path).unwrap().replace(
            "cosign_identity = \"\"",
            "cosign_identity = \"from-config@example.invalid\"",
        );
        assert!(
            text.contains("from-config@example.invalid"),
            "the generated [controls.ai-receipts] block changed shape — fix this test"
        );
        std::fs::write(&cfg_path, text).unwrap();
        let ctx2 = Ctx::discover(&ctx.root).unwrap();
        let ok = with_fake_tool("cosign", script, || {
            verify_receipt(&ctx2, &receipt, None, None)
        })
        .unwrap();
        assert!(ok.contains("from-config@example.invalid"), "{ok}");
    }

    /// A receipt's `gitCommit` is untrusted input — it is the thing under
    /// suspicion. Before this guard, git accepted it as an OPTION: `-s`
    /// suppressed the diff so a receipt claiming sha256("") "verified", and
    /// `--output=<path>` additionally wrote the diff over an arbitrary file
    /// while leaving stdout empty, so the same forged digest matched. Both
    /// reproduced at exit 0 against the real binary before the fix.
    #[test]
    fn forged_receipt_naming_a_git_option_is_refused_and_writes_nothing() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(&ctx, "feat: real commit");
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");
        let receipt = create_receipt(&ctx, "HEAD", &out_dir).unwrap();
        let genuine = std::fs::read_to_string(&receipt).unwrap();

        // sha256 of the empty string — what git prints when the diff is
        // suppressed or redirected away from stdout.
        const EMPTY_SHA256: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let victim = ctx.root.join("victim.txt");
        std::fs::write(&victim, "ORIGINAL CONTENT\n").unwrap();

        for payload in ["-s".to_string(), format!("--output={}", victim.display())] {
            let mut doc: serde_json::Value = serde_json::from_str(&genuine).unwrap();
            doc["subject"][0]["digest"]["gitCommit"] = serde_json::json!(payload);
            doc["subject"][0]["digest"]["sha256"] = serde_json::json!(EMPTY_SHA256);
            let forged = ctx.root.join("forged.json");
            std::fs::write(&forged, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

            let err = verify_receipt(&ctx, &forged, None, None)
                .expect_err("a receipt whose gitCommit is a git option must not verify");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("is not a git object name"),
                "expected the shape guard to reject {payload:?}, got: {msg}"
            );
        }

        // The arbitrary-write half: the victim file must be untouched.
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL CONTENT\n",
            "verifying a forged receipt must never write to a file on disk"
        );
    }

    /// The guard must reject option-shaped names without rejecting the real
    /// ones: a genuine receipt still verifies, and `create_receipt` still
    /// accepts revision *expressions*, which are legitimate on the CLI.
    #[test]
    fn object_name_guard_admits_real_receipts_and_revision_expressions() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(&ctx, "feat: first");
        write(&ctx, "b.txt", "b\n");
        commit_all(&ctx, "feat: second");
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");

        for rev in ["HEAD", "HEAD~1", "main"] {
            let receipt = create_receipt(&ctx, rev, &out_dir)
                .unwrap_or_else(|e| panic!("revision expression {rev:?} must still work: {e:#}"));
            let ok = verify_receipt(&ctx, &receipt, None, None).unwrap();
            assert!(
                ok.contains("receipt verified"),
                "{rev} receipt should verify"
            );
        }

        assert!(is_object_name("1234567"));
        assert!(is_object_name(&"a".repeat(40)));
        assert!(!is_object_name("-s"));
        assert!(!is_object_name("--output=/tmp/x"));
        assert!(!is_object_name("HEAD"));
        assert!(!is_object_name("123456")); // too short to be an abbreviation
        assert!(!is_object_name("DEADBEEF1")); // uppercase is not git's output form
    }

    /// Reported (M16): `sscsb receipt create -- --raw` exited 101.
    ///
    /// Before `--verify`, the resolver was `git rev-parse <commit>`, and
    /// rev-parse ECHOES an unrecognised option back at exit 0 — `git rev-parse
    /// --raw` prints `--raw`, five characters — so the receipt filename's
    /// `&sha[..12]` sliced past the end. Reproduced at
    /// "end byte index 12 is out of bounds for string of length 5".
    ///
    /// `--verify` shut that particular door, but the slice was still one
    /// unexpected short answer away from a crash, because `is_object_name`
    /// admits a 7-character abbreviation: a resolver answering with one used to
    /// clear the guard and then abort the process. Asserted directly on the
    /// filename derivation, which is where the slice lives — shimming `git`
    /// itself onto PATH would break every other test in this threaded suite.
    #[test]
    fn receipt_file_name_errors_rather_than_panicking_on_anything_but_a_full_sha() {
        // The exact reported payload, five characters, and the abbreviations
        // `is_object_name` admits — all of them refused, none of them fatal.
        for bad in [
            "--raw",           // what `git rev-parse --raw` echoes back at exit 0
            "-s",              //
            "deadbee",         // 7 hex: passes is_object_name, too short to slice
            "deadbeef1234def", // 15 hex: long enough to slice, still not an oid
            "",
            "HEAD",
        ] {
            let err = receipt_file_name("HEAD", bad)
                .expect_err("{bad:?} must be an error, never a process abort");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("not a full git object name"),
                "for {bad:?}: {msg}"
            );
            assert!(msg.contains(bad), "the message names what it got: {msg}");
        }

        // Both real widths still work — the guard must not become a false
        // positive for the answers rev-parse actually gives.
        assert_eq!(
            receipt_file_name("HEAD", &"a".repeat(40)).unwrap(),
            "receipt-aaaaaaaaaaaa.json"
        );
        assert_eq!(
            receipt_file_name("HEAD", &"b".repeat(64)).unwrap(),
            "receipt-bbbbbbbbbbbb.json"
        );
    }

    /// The reported invocation itself, pinned end to end at the library level:
    /// a leading-dash revision is refused by git under `--end-of-options` and
    /// surfaces as an ordinary error.
    #[test]
    fn create_receipt_refuses_an_option_shaped_revision_without_panicking() {
        let (_d, ctx) = repo();
        write(&ctx, "a.txt", "a\n");
        commit_all(&ctx, "feat: x");
        let out_dir = ctx.sscsb_dir().join("out").join("receipts");

        let victim = ctx.root.join("victim.txt");
        std::fs::write(&victim, "ORIGINAL CONTENT\n").unwrap();

        for revision in ["--raw", "-s", &format!("--output={}", victim.display())] {
            let err = create_receipt(&ctx, revision, &out_dir)
                .expect_err("an option-shaped revision must be refused, not turned into a receipt");
            assert!(
                !format!("{err:#}").is_empty(),
                "{revision} must produce a real error"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL CONTENT\n",
            "creating a receipt must never write to a file on disk"
        );
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
        let err =
            verify_receipt(&ctx, &ctx.root.join("does-not-exist.json"), None, None).unwrap_err();
        assert!(!format!("{err:#}").is_empty());

        let bad = ctx.root.join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        let err = verify_receipt(&ctx, &bad, None, None).unwrap_err();
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
        let err = verify_receipt(&ctx, &missing_commit, None, None).unwrap_err();
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
        let err = verify_receipt(&ctx, &missing_sha, None, None).unwrap_err();
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
