//! Phase 5 observability & governance: Dependency-Track BOM upload, GUAC
//! ingestion, native OpenVEX generation, optional ORAS OCI push.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;
use anyhow::{Context as _, Result};
use base64::Engine as _;
use std::path::Path;

// ─────────────────────────── Dependency-Track ───────────────────────────────

/// Upload a CycloneDX BOM to Dependency-Track (`PUT /api/v1/bom`, X-Api-Key
/// auth, base64 BOM body, autoCreate by project name). The API key comes ONLY
/// from `DTRACK_API_KEY` in the environment — never from config files.
pub fn dtrack_upload(ctx: &Ctx, cfg: &Config, bom_path: &Path) -> Result<String> {
    let url = cfg
        .control_opt_str("dependency-track", "url")
        .filter(|u| !u.is_empty())
        .context(
            "dependency-track.url not configured in .sscsb/config.toml — \
             set it to your server (e.g. http://localhost:8081) or start one with \
             `docker compose -f .sscsb/templates/dependency-track-compose.yml up`",
        )?;
    let api_key = std::env::var("DTRACK_API_KEY").context(
        "DTRACK_API_KEY not set — create an API key in Dependency-Track \
         (Administration → Teams) and export DTRACK_API_KEY=<key>",
    )?;
    let project = cfg
        .control_opt_str("dependency-track", "project_name")
        .filter(|p| !p.is_empty())
        .or_else(|| ctx.origin_slug().map(|s| s.replace('/', "-")))
        .unwrap_or_else(|| "sscsb-project".to_string());
    let bom =
        std::fs::read(bom_path).with_context(|| format!("reading BOM {}", bom_path.display()))?;
    let payload = serde_json::json!({
        "projectName": project,
        "projectVersion": "default",
        "autoCreate": true,
        "bom": base64::engine::general_purpose::STANDARD.encode(&bom),
    });
    let endpoint = format!("{}/api/v1/bom", url.trim_end_matches('/'));
    let resp = ureq::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .put(&endpoint)
        .set("X-Api-Key", &api_key)
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string())
        .map_err(|e| anyhow::anyhow!("Dependency-Track upload failed: {e}"))?;
    let body: serde_json::Value = resp.into_json().unwrap_or_default();
    let token = body
        .get("token")
        .and_then(|t| t.as_str())
        .unwrap_or("<none>");
    Ok(format!(
        "BOM uploaded to {endpoint} (project `{project}`), processing token: {token}"
    ))
}

pub fn verify_dtrack_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let mut messages = Vec::new();
    let url = cfg
        .control_opt_str("dependency-track", "url")
        .filter(|u| !u.is_empty());
    let compose = ctx
        .sscsb_dir()
        .join("templates")
        .join("dependency-track-compose.yml");
    if compose.is_file() {
        messages.push("docker-compose quickstart template installed".into());
    }
    match url {
        Some(u) => {
            messages.push(format!("server configured: {u}"));
            if std::env::var("DTRACK_API_KEY").is_ok() {
                messages.push("DTRACK_API_KEY present in environment".into());
                VerifyResult::new("dependency-track", Outcome::Pass, messages)
            } else {
                messages.push("DTRACK_API_KEY not set — upload will fail until exported".into());
                VerifyResult::new("dependency-track", Outcome::Degraded, messages)
            }
        }
        None => {
            messages.push(
                "no server configured (dependency-track.url) — `sscsb dtrack upload` will \
                 explain how to start one; see docs/phase-5.md"
                    .into(),
            );
            VerifyResult::new("dependency-track", Outcome::Degraded, messages)
        }
    }
}

// ─────────────────────────── GUAC ───────────────────────────────────────────

/// Ingest SBOMs/attestations from `.sscsb/out` into GUAC via `guacone collect files`.
pub fn guac_ingest(ctx: &Ctx, dir: Option<&Path>) -> Result<String> {
    if !tools::is_available("guacone") {
        anyhow::bail!("{}", tools::degrade_message("guacone", ctx.platform));
    }
    let target = dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| ctx.sscsb_dir().join("out"));
    anyhow::ensure!(
        target.is_dir(),
        "nothing to ingest: {} does not exist — generate artifacts first (`sscsb sbom`)",
        target.display()
    );
    let target_s = target.display().to_string();
    let out = exec::run("guacone", &["collect", "files", &target_s], Some(&ctx.root))?;
    if !out.success() {
        anyhow::bail!(
            "guacone collect failed (exit {}): {} — is the GUAC compose stack running? \
             (see docs/phase-5.md)",
            out.status,
            out.stderr.trim()
        );
    }
    Ok(format!("ingested {} into GUAC", target.display()))
}

pub fn verify_guac_control(ctx: &Ctx) -> VerifyResult {
    match tools::detect(tools::spec("guacone").expect("registry")) {
        tools::ToolStatus::Found { version, .. } => VerifyResult::new(
            "guac",
            Outcome::Pass,
            vec![format!(
                "guacone {} available — `sscsb guac ingest` feeds .sscsb/out into the graph",
                version.unwrap_or_else(|| "?".into())
            )],
        ),
        tools::ToolStatus::Missing => VerifyResult::new(
            "guac",
            Outcome::Degraded,
            vec![
                tools::degrade_message("guacone", ctx.platform),
                "GUAC quickstart: wget guac-demo-compose.yaml from the guacsec/guac release, \
                 `docker compose up`; example graph queries in docs/phase-5.md"
                    .into(),
            ],
        ),
    }
}

// ─────────────────────────── OpenVEX ────────────────────────────────────────

pub struct VexArgs<'a> {
    pub vuln: &'a str,
    pub product: &'a str,
    pub status: &'a str,
    pub justification: Option<&'a str>,
}

pub const VEX_STATUSES: &[&str] = &["not_affected", "affected", "fixed", "under_investigation"];

/// Generate a minimal, valid OpenVEX document natively (vexctl-compatible;
/// vexctl adds merge/attest when installed).
pub fn vex_create(ctx: &Ctx, args: &VexArgs) -> Result<std::path::PathBuf> {
    anyhow::ensure!(
        VEX_STATUSES.contains(&args.status),
        "invalid status `{}` — one of {}",
        args.status,
        VEX_STATUSES.join("|")
    );
    if args.status == "not_affected" {
        anyhow::ensure!(
            args.justification.is_some(),
            "status not_affected requires --justification (OpenVEX spec)"
        );
    }
    let author = ctx
        .origin_slug()
        .map(|s| format!("https://github.com/{s}"))
        .unwrap_or_else(|| "sscsb".to_string());
    let now = chrono::Utc::now().to_rfc3339();
    let mut statement = serde_json::json!({
        "vulnerability": { "name": args.vuln },
        "products": [{ "@id": args.product }],
        "status": args.status,
    });
    if let Some(j) = args.justification {
        statement["justification"] = serde_json::Value::String(j.to_string());
    }
    let doc = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("https://openvex.dev/docs/sscsb-{}", &now[..10]),
        "author": author,
        "timestamp": now,
        "version": 1,
        "statements": [statement],
    });
    let out_dir = ctx.sscsb_dir().join("out");
    std::fs::create_dir_all(&out_dir)?;
    let path = out_dir.join(format!(
        "{}.vex.json",
        args.vuln.to_lowercase().replace(['/', ':'], "-")
    ));
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    Ok(path)
}

pub fn verify_openvex_control(_ctx: &Ctx) -> VerifyResult {
    let mut messages = vec![
        "native OpenVEX generation: `sscsb vex create --vuln CVE-… --product pkg:… \
         --status not_affected --justification …`"
            .into(),
        "ingestion: `sscsb scan --vex <file>` suppresses not_affected/fixed findings visibly"
            .into(),
    ];
    match tools::detect(tools::spec("vexctl").expect("registry")) {
        tools::ToolStatus::Found { version, .. } => messages.push(format!(
            "vexctl {} also available (merge/attest)",
            version.unwrap_or_else(|| "?".into())
        )),
        tools::ToolStatus::Missing => {
            messages.push("vexctl not installed (optional — brew install vexctl)".into());
        }
    }
    VerifyResult::new("openvex", Outcome::Pass, messages)
}

// ─────────────────────────── ORAS ───────────────────────────────────────────

pub fn oras_push(ctx: &Ctx, reference: &str, file: &Path) -> Result<String> {
    if !tools::is_available("oras") {
        anyhow::bail!("{}", tools::degrade_message("oras", ctx.platform));
    }
    let file_arg = format!("{}:application/json", file.display());
    let out = exec::run(
        "oras",
        &[
            "push",
            "--artifact-type",
            "application/vnd.cyclonedx+json",
            reference,
            &file_arg,
        ],
        Some(&ctx.root),
    )?;
    if !out.success() {
        anyhow::bail!(
            "oras push failed (exit {}): {}",
            out.status,
            out.stderr.trim()
        );
    }
    Ok(format!("pushed {} to {reference}", file.display()))
}

pub fn verify_oras_control(ctx: &Ctx) -> VerifyResult {
    match tools::detect(tools::spec("oras").expect("registry")) {
        tools::ToolStatus::Found { version, .. } => VerifyResult::new(
            "oras",
            Outcome::Pass,
            vec![format!(
                "oras {} available — `sscsb oras push <registry-ref> <file>`",
                version.unwrap_or_else(|| "?".into())
            )],
        ),
        tools::ToolStatus::Missing => VerifyResult::new(
            "oras",
            Outcome::Degraded,
            vec![tools::degrade_message("oras", ctx.platform)],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// `DTRACK_API_KEY` is process-global, so the tests that set or clear it must
    /// not run concurrently with each other.
    static ENV: Mutex<()> = Mutex::new(());

    fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        init::bootstrap(dir.path()).unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        (dir, ctx)
    }

    /// Point the dependency-track control at `url`, the way a user would.
    fn set_url(ctx: &Ctx, url: &str) {
        let text = std::fs::read_to_string(ctx.config_path()).unwrap();
        let patched = text.replace(
            "[controls.dependency-track]\nenabled = false\nurl = \"\"",
            &format!("[controls.dependency-track]\nenabled = true\nurl = \"{url}\""),
        );
        assert_ne!(
            text, patched,
            "the generated [controls.dependency-track] block changed shape — fix this test"
        );
        std::fs::write(ctx.config_path(), patched).unwrap();
    }

    /// Minimal Dependency-Track stand-in: records the request it received and
    /// answers the way the real API does.
    struct StubDtrack {
        url: String,
        handle: std::thread::JoinHandle<(String, String)>,
    }

    fn stub_dtrack() -> StubDtrack {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                headers.push_str(&line);
            }
            // Read exactly Content-Length bytes: replying early makes ureq
            // report a malformed response instead of the real behavior.
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n\
                      {\"token\":\"abc-123-processing\"}",
                )
                .unwrap();
            (headers, String::from_utf8(body).unwrap())
        });
        StubDtrack { url, handle }
    }

    #[test]
    fn dtrack_upload_sends_the_documented_api_contract() {
        let _guard = ENV.lock().unwrap();
        let (_d, ctx) = repo();
        let stub = stub_dtrack();
        set_url(&ctx, &stub.url);
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();

        let bom = ctx.root.join("bom.json");
        std::fs::write(&bom, r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#).unwrap();
        std::env::set_var("DTRACK_API_KEY", "test-key-not-a-real-credential");

        let msg = dtrack_upload(&ctx, cfg, &bom).unwrap();
        assert!(msg.contains("/api/v1/bom"));
        assert!(
            msg.contains("abc-123-processing"),
            "token must be surfaced: {msg}"
        );

        let (headers, body) = stub.handle.join().unwrap();
        let headers = headers.to_lowercase();
        // The key travels in a header — never in the URL, where it would leak
        // into access logs, proxy logs, and browser history.
        assert!(headers.contains("x-api-key: test-key-not-a-real-credential"));
        assert!(!msg.contains("test-key-not-a-real-credential"));

        let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(sent["autoCreate"], true);
        assert_eq!(sent["projectVersion"], "default");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(sent["bom"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#,
            "the BOM must arrive base64-encoded and byte-identical"
        );
        std::env::remove_var("DTRACK_API_KEY");
    }

    #[test]
    fn dtrack_upload_refuses_without_url_or_api_key() {
        let _guard = ENV.lock().unwrap();
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        let bom = ctx.root.join("bom.json");
        std::fs::write(&bom, "{}").unwrap();

        // No server configured.
        std::env::set_var("DTRACK_API_KEY", "test-key-not-a-real-credential");
        let err = dtrack_upload(&ctx, cfg, &bom).unwrap_err();
        assert!(format!("{err:#}").contains("dependency-track.url not configured"));

        // Server configured, but no key in the environment. The key is NEVER
        // read from the config file, so this must fail rather than fall back.
        std::env::remove_var("DTRACK_API_KEY");
        set_url(&ctx, "http://127.0.0.1:1");
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        let err = dtrack_upload(&ctx, cfg, &bom).unwrap_err();
        assert!(format!("{err:#}").contains("DTRACK_API_KEY not set"));
    }

    #[test]
    fn dtrack_upload_surfaces_an_unreachable_server() {
        let _guard = ENV.lock().unwrap();
        let (_d, ctx) = repo();
        // Port 1 refuses connections — a down server must be reported, not swallowed.
        set_url(&ctx, "http://127.0.0.1:1");
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();
        let bom = ctx.root.join("bom.json");
        std::fs::write(&bom, "{}").unwrap();
        std::env::set_var("DTRACK_API_KEY", "test-key-not-a-real-credential");

        let err = dtrack_upload(&ctx, cfg, &bom).unwrap_err();
        assert!(format!("{err:#}").contains("Dependency-Track upload failed"));

        // A missing BOM file is likewise an error, not an empty upload.
        let err = dtrack_upload(&ctx, cfg, &ctx.root.join("nope.json")).unwrap_err();
        assert!(format!("{err:#}").contains("reading BOM"));
        std::env::remove_var("DTRACK_API_KEY");
    }

    #[test]
    fn dtrack_verify_reports_url_and_key_state_separately() {
        let _guard = ENV.lock().unwrap();
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();

        // No URL → degraded, and it says how to get one.
        let r = verify_dtrack_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("no server configured")));

        set_url(&ctx, "http://localhost:8081");
        let ctx = Ctx::discover(&ctx.root).unwrap();
        let cfg = ctx.require_config().unwrap();

        // URL but no key → degraded, naming the missing key.
        std::env::remove_var("DTRACK_API_KEY");
        let r = verify_dtrack_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("DTRACK_API_KEY not set")));

        // Both → pass.
        std::env::set_var("DTRACK_API_KEY", "test-key-not-a-real-credential");
        let r = verify_dtrack_control(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(r.messages.iter().any(|m| m.contains("localhost:8081")));
        std::env::remove_var("DTRACK_API_KEY");
    }

    #[test]
    fn guac_ingest_requires_the_tool_and_something_to_ingest() {
        let (_d, ctx) = repo();
        let err = guac_ingest(&ctx, None).unwrap_err();
        let msg = format!("{err:#}");
        if tools::is_available("guacone") {
            // Tool present, but .sscsb/out does not exist yet.
            assert!(msg.contains("nothing to ingest"), "{msg}");
        } else {
            assert!(msg.contains("guacone not found"), "{msg}");
            assert!(
                msg.contains("1.1.0"),
                "degrade message names the pinned version"
            );
        }
    }

    #[test]
    fn guac_verify_degrades_with_a_quickstart_hint_when_absent() {
        let (_d, ctx) = repo();
        let r = verify_guac_control(&ctx);
        if tools::is_available("guacone") {
            assert_eq!(r.outcome, Outcome::Pass);
        } else {
            assert_eq!(r.outcome, Outcome::Degraded);
            assert!(r.messages.iter().any(|m| m.contains("guacone not found")));
            assert!(r.messages.iter().any(|m| m.contains("docker compose")));
        }
    }

    #[test]
    fn vex_create_writes_a_valid_openvex_document() {
        let (_d, ctx) = repo();
        let path = vex_create(
            &ctx,
            &VexArgs {
                vuln: "CVE-2024-12345",
                product: "pkg:cargo/itoa@1.0.11",
                status: "not_affected",
                justification: Some("vulnerable_code_not_present"),
            },
        )
        .unwrap();
        assert!(path.ends_with("cve-2024-12345.vex.json"));

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(doc["version"], 1);
        assert!(doc["timestamp"].as_str().unwrap().contains('T'));
        let s = &doc["statements"][0];
        assert_eq!(s["vulnerability"]["name"], "CVE-2024-12345");
        assert_eq!(s["products"][0]["@id"], "pkg:cargo/itoa@1.0.11");
        assert_eq!(s["status"], "not_affected");
        assert_eq!(s["justification"], "vulnerable_code_not_present");
    }

    #[test]
    fn vex_create_enforces_the_openvex_status_rules() {
        let (_d, ctx) = repo();

        // `not_affected` without a justification is exactly the assertion OpenVEX
        // refuses to take on trust — and so do we.
        let err = vex_create(
            &ctx,
            &VexArgs {
                vuln: "CVE-2024-1",
                product: "pkg:cargo/x@1",
                status: "not_affected",
                justification: None,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("requires --justification"));

        // Other statuses do not need one.
        let path = vex_create(
            &ctx,
            &VexArgs {
                vuln: "CVE-2024-2",
                product: "pkg:cargo/x@1",
                status: "fixed",
                justification: None,
            },
        )
        .unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["statements"][0]["status"], "fixed");
        assert!(doc["statements"][0].get("justification").is_none());

        // An invented status is rejected rather than written out.
        let err = vex_create(
            &ctx,
            &VexArgs {
                vuln: "CVE-2024-3",
                product: "pkg:cargo/x@1",
                status: "wontfix",
                justification: None,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("invalid status"));
    }

    #[test]
    fn openvex_control_always_passes_because_generation_is_native() {
        let (_d, ctx) = repo();
        let r = verify_openvex_control(&ctx);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(r.messages.iter().any(|m| m.contains("sscsb vex create")));
        // vexctl is optional either way; the control states which it found.
        let mentions_vexctl = r.messages.iter().any(|m| m.contains("vexctl"));
        assert!(mentions_vexctl);
    }

    #[test]
    fn oras_push_reports_a_failed_push_rather_than_claiming_success() {
        let (_d, ctx) = repo();
        let file = ctx.root.join("sbom.cdx.json");
        std::fs::write(&file, r#"{"bomFormat":"CycloneDX"}"#).unwrap();
        // 127.0.0.1:1 is not a registry. Whether oras is installed or not, this
        // must be an Err — never an "uploaded!" message.
        let err = oras_push(&ctx, "127.0.0.1:1/x:tag", &file).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("oras push failed") || msg.contains("oras not found"),
            "{msg}"
        );
    }

    #[test]
    fn oras_verify_reflects_tool_presence() {
        let (_d, ctx) = repo();
        let r = verify_oras_control(&ctx);
        if tools::is_available("oras") {
            assert_eq!(r.outcome, Outcome::Pass);
            assert!(r.messages.iter().any(|m| m.contains("sscsb oras push")));
        } else {
            assert_eq!(r.outcome, Outcome::Degraded);
            assert!(r.messages.iter().any(|m| m.contains("oras not found")));
        }
    }

    #[test]
    fn vex_statuses_closed_set() {
        assert!(VEX_STATUSES.contains(&"not_affected"));
        assert!(!VEX_STATUSES.contains(&"wontfix"));
        assert_eq!(VEX_STATUSES.len(), 4);
    }
}
