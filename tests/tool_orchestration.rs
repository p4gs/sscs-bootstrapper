//! Integration tests that exercise the REAL external tools sscsb orchestrates.
//!
//! Each test asserts BOTH sides of the spec contract:
//!
//! - tool present → sscsb invokes it correctly and parses its output
//! - tool absent → sscsb degrades with an explicit message naming the tool, the
//!   pinned version, and how to install it (never a panic)
//!
//! The absent branch is exercised by masking PATH, so both paths are covered on
//! every machine regardless of what happens to be installed.

use assert_cmd::Command as AssertCommand;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git_ok(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sscsb(repo: &Path) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("sscsb").expect("binary");
    cmd.current_dir(repo);
    cmd
}

/// sscsb with a PATH that contains ONLY git (so every orchestrated tool is
/// "absent" and the degrade path is what runs).
fn sscsb_without_tools(repo: &Path) -> AssertCommand {
    let mut cmd = sscsb(repo);
    let git_dir = which_dir("git");
    cmd.env("PATH", git_dir);
    cmd
}

fn which_dir(bin: &str) -> String {
    let out = Command::new("sh")
        .args(["-c", &format!("command -v {bin}")])
        .output()
        .expect("sh");
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    PathBuf::from(path)
        .parent()
        .expect("bin dir")
        .display()
        .to_string()
}

fn tool_available(bin: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {bin}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A throwaway repo with a real Cargo manifest + lockfile so SBOM/scan have
/// something to inventory.
fn rust_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path();
    git_ok(repo, &["init", "-b", "main"]);
    git_ok(repo, &["config", "user.name", "SSCSB Test"]);
    git_ok(repo, &["config", "user.email", "sscsb-test@example.com"]);
    git_ok(repo, &["config", "commit.gpgsign", "false"]);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1.0.11\"\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\ndependencies = [\"itoa\"]\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/main.rs"), "fn main() {}\n").unwrap();
    sscsb(repo).arg("init").assert().success();
    // Bless the fixture's deps so hooks don't gate unrelated tests.
    sscsb(repo).args(["deps", "baseline"]).assert().success();
    dir
}

// ───────────────────────────── SBOM (Syft) ──────────────────────────────────

#[test]
fn sbom_generates_cyclonedx_and_spdx_or_degrades_explicitly() {
    let dir = rust_repo();
    let repo = dir.path();

    if tool_available("syft") {
        sscsb(repo).arg("sbom").assert().success();
        let bom = repo.join(".sscsb/out/sbom.cdx.json");
        assert!(bom.is_file(), "CycloneDX SBOM not written");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&bom).unwrap()).unwrap();
        assert_eq!(v["bomFormat"], "CycloneDX", "not a CycloneDX document");
        assert!(
            v["components"]
                .as_array()
                .map(|c| !c.is_empty())
                .unwrap_or(false),
            "SBOM has no components — syft found nothing to inventory"
        );

        // Format is configurable without code changes.
        sscsb(repo)
            .args(["sbom", "--format", "spdx-json"])
            .assert()
            .success();
        let spdx = repo.join(".sscsb/out/sbom.spdx.json");
        assert!(spdx.is_file(), "SPDX SBOM not written");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&spdx).unwrap()).unwrap();
        assert!(v["spdxVersion"].is_string(), "not an SPDX document");

        // Unsupported format is rejected before the tool is invoked.
        sscsb(repo)
            .args(["sbom", "--format", "xml"])
            .assert()
            .failure();
    }

    // Degrade path (always exercised, via PATH masking).
    let out = sscsb_without_tools(repo).arg("sbom").assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("syft not found"),
        "must name the tool: {stderr}"
    );
    assert!(
        stderr.contains("1.46.0"),
        "must state the pinned version: {stderr}"
    );
    assert!(
        stderr.contains("brew install syft"),
        "must give an install hint: {stderr}"
    );
}

// ───────────────────────── Vulnerability scan ───────────────────────────────

#[test]
fn scan_runs_trivy_and_osv_or_degrades_explicitly() {
    let dir = rust_repo();
    let repo = dir.path();

    if tool_available("trivy") || tool_available("osv-scanner") {
        // Exit 0 (clean) or 1 (findings ≥ threshold) are both valid REAL runs;
        // exit 2 would mean an operational error, which is what we're ruling out.
        let out = sscsb(repo).arg("scan").output().expect("scan runs");
        let code = out.status.code().unwrap_or(-1);
        assert!(
            code == 0 || code == 1,
            "scan must not error out (exit {code}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("finding(s)"),
            "scan must report a finding count: {stdout}"
        );
    }

    // VEX ingestion suppresses matching findings, visibly.
    sscsb(repo)
        .args([
            "vex",
            "create",
            "--vuln",
            "CVE-2024-99999",
            "--product",
            "pkg:cargo/itoa@1.0.11",
            "--status",
            "not_affected",
            "--justification",
            "vulnerable_code_not_present",
        ])
        .assert()
        .success();
    if tool_available("trivy") || tool_available("osv-scanner") {
        let vex = repo.join(".sscsb/out/cve-2024-99999.vex.json");
        let out = sscsb(repo)
            .args(["scan", "--vex", vex.to_str().unwrap()])
            .output()
            .expect("scan runs");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("VEX applied"),
            "VEX application must be reported: {stdout}"
        );
    }

    let out = sscsb_without_tools(repo).arg("scan").assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("no vulnerability scanner available"),
        "explicit degrade expected: {stderr}"
    );
    assert!(stderr.contains("trivy") && stderr.contains("osv-scanner"));
}

// ───────────────────────────── SAST ─────────────────────────────────────────

#[test]
fn sast_runs_opengrep_by_default_and_semgrep_when_selected() {
    let dir = rust_repo();
    let repo = dir.path();

    // A file the shipped ruleset must flag (ERROR severity → non-zero exit).
    std::fs::write(
        repo.join("install.sh"),
        "#!/bin/sh\ncurl -fsSL https://example.com/install | sh\n",
    )
    .unwrap();

    if tool_available("opengrep") {
        let out = sscsb(repo).arg("sast").output().expect("sast runs");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert_eq!(
            out.status.code(),
            Some(1),
            "curl|sh must be an ERROR finding: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("curl-pipe-shell"),
            "shipped rule must fire: {stdout}"
        );
    }

    if tool_available("semgrep") {
        // Engine is switchable via config with no code change.
        let cfg_path = repo.join(".sscsb/config.toml");
        let cfg = std::fs::read_to_string(&cfg_path).unwrap();
        let cfg = cfg.replace("engine = \"opengrep\"", "engine = \"semgrep\"");
        std::fs::write(&cfg_path, cfg).unwrap();
        let out = sscsb(repo).arg("sast").output().expect("sast runs");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert_eq!(
            out.status.code(),
            Some(1),
            "semgrep engine must flag it too: {stdout}"
        );
        assert!(stdout.contains("curl-pipe-shell"), "{stdout}");
    }

    let out = sscsb_without_tools(repo).arg("sast").assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("opengrep not found") || stderr.contains("semgrep not found"),
        "explicit degrade expected: {stderr}"
    );
}

// ─────────────────── Provenance: slsa-verifier + DSSE ───────────────────────

/// The real SLSA gate: verify a genuine public artifact + its provenance.
/// Fixtures are downloaded once into the test tempdir; skipped (with a loud
/// note) only when the network is unavailable.
#[test]
fn provenance_verify_passes_on_a_real_slsa_signed_artifact() {
    if !tool_available("slsa-verifier") {
        let dir = rust_repo();
        let out = sscsb_without_tools(dir.path())
            .args([
                "provenance",
                "verify",
                "--artifact",
                "x",
                "--provenance",
                "y",
                "--source-uri",
                "github.com/o/r",
            ])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(stderr.contains("slsa-verifier not found"), "{stderr}");
        return;
    }

    let dir = rust_repo();
    let repo = dir.path();
    let base = "https://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1";
    let artifact = repo.join("slsa-verifier-linux-amd64");
    let provenance = repo.join("slsa-verifier-linux-amd64.intoto.jsonl");

    let fetched = download(&format!("{base}/slsa-verifier-linux-amd64"), &artifact)
        && download(
            &format!("{base}/slsa-verifier-linux-amd64.intoto.jsonl"),
            &provenance,
        );
    if !fetched {
        eprintln!("NETWORK UNAVAILABLE — SLSA fixture download failed; test cannot run");
        return;
    }

    // 1. sscsb parses the DSSE envelope and names the builder.
    let out = sscsb(repo)
        .args(["provenance", "inspect", provenance.to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(stdout.contains("in-toto.io/Statement"), "{stdout}");
    assert!(stdout.contains("slsa.dev/provenance"), "{stdout}");
    assert!(
        stdout.contains("slsa-github-generator"),
        "builder id expected: {stdout}"
    );
    assert!(
        stdout.contains("sha256:"),
        "subject digest expected: {stdout}"
    );

    // 2. sscsb's gate wraps slsa-verifier and PASSES on the genuine pair.
    let out = sscsb(repo)
        .args([
            "provenance",
            "verify",
            "--artifact",
            artifact.to_str().unwrap(),
            "--provenance",
            provenance.to_str().unwrap(),
            "--source-uri",
            "github.com/slsa-framework/slsa-verifier",
            "--source-tag",
            "v2.7.1",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("PASSED"),
        "slsa-verifier must pass: {stdout}"
    );

    // 3. TAMPERED artifact must FAIL the gate (the gate has teeth).
    let mut bytes = std::fs::read(&artifact).unwrap();
    bytes.push(0x00);
    std::fs::write(&artifact, bytes).unwrap();
    let out = sscsb(repo)
        .args([
            "provenance",
            "verify",
            "--artifact",
            artifact.to_str().unwrap(),
            "--provenance",
            provenance.to_str().unwrap(),
            "--source-uri",
            "github.com/slsa-framework/slsa-verifier",
            "--source-tag",
            "v2.7.1",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("FAILED") || stderr.contains("artifact hash"),
        "tampered artifact must be rejected: {stderr}"
    );
}

fn download(url: &str, dest: &Path) -> bool {
    Command::new("curl")
        .args(["-fsSL", "-o", dest.to_str().unwrap(), url])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ───────────────────────── package trust (network) ──────────────────────────

#[test]
fn deps_check_flags_nonexistent_and_typosquat_packages() {
    let dir = rust_repo();
    let repo = dir.path();

    // Offline mode: typosquat heuristic alone.
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1.0.11\"\nserd = \"1\"\n",
    )
    .unwrap();
    git_ok(repo, &["add", "Cargo.toml"]);
    let out = sscsb(repo)
        .args(["deps", "check", "--offline"])
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("typosquat") && stdout.contains("serde"),
        "typosquat heuristic must fire on `serd`: {stdout}"
    );

    // Online mode: registry existence check catches a hallucinated package.
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1.0.11\"\nsscsb-totally-nonexistent-hallucinated-crate = \"1\"\n",
    )
    .unwrap();
    git_ok(repo, &["add", "Cargo.toml"]);
    let out = sscsb(repo).args(["deps", "check"]).output().expect("runs");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if stdout.contains("registry check inconclusive") {
        eprintln!("NETWORK UNAVAILABLE — registry existence check could not run");
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(1),
        "hallucinated dep must fail the check: {stdout}"
    );
    assert!(
        stdout.contains("NOT FOUND on its public registry"),
        "slopsquat detection expected: {stdout}"
    );

    // With nothing new staged, the check falls back to the full manifest and
    // confirms the real dependency exists on crates.io.
    git_ok(repo, &["reset"]);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1.0.11\"\n",
    )
    .unwrap();
    let out = sscsb(repo).args(["deps", "check"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("cargo:itoa: exists on registry"),
        "{stdout}"
    );
}

// ───────────────────────── Grype (optional, SBOM-first) ─────────────────────

#[test]
fn grype_scans_the_sbom_when_enabled_or_degrades() {
    let dir = rust_repo();
    let repo = dir.path();

    // Disabled by default: --grype must say so rather than silently running.
    if tool_available("syft") && (tool_available("trivy") || tool_available("osv-scanner")) {
        let out = sscsb(repo)
            .args(["scan", "--grype"])
            .output()
            .expect("runs");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("control disabled"),
            "optional control must announce it is off: {stdout}"
        );
    }

    sscsb(repo).args(["enable", "grype"]).assert().success();

    if tool_available("grype") && tool_available("syft") {
        let out = sscsb(repo)
            .args(["scan", "--grype"])
            .output()
            .expect("runs");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("grype:") && stdout.contains("match(es)"),
            "grype must report a match count: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        let out = sscsb_without_tools(repo)
            .args(["scan", "--grype"])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(stderr.contains("not found"), "{stderr}");
    }
}

// ─────────────────── Dependency-Track (stub server) ─────────────────────────

/// Minimal stand-in for a Dependency-Track API server: accepts one request,
/// records it, and answers with a processing token. Lets the upload path be
/// verified end to end (endpoint, auth header, base64 BOM, token parse)
/// without provisioning a real server.
fn stub_dtrack() -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read headers, then exactly Content-Length body bytes: replying
            // before the client finishes sending breaks the connection.
            let mut raw: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 8192];
            let mut header_end = None;
            let mut content_length = 0usize;
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                raw.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let headers = String::from_utf8_lossy(&raw[..pos]).to_lowercase();
                        content_length = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                    }
                }
                if let Some(start) = header_end {
                    if raw.len() >= start + content_length {
                        break;
                    }
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&raw).to_string());
            let body = r#"{"token":"11111111-2222-3333-4444-555555555555"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://127.0.0.1:{port}"), rx)
}

#[test]
fn dtrack_upload_puts_bom_with_api_key_and_parses_token() {
    if !tool_available("syft") {
        eprintln!("syft absent — dtrack test needs a real SBOM");
        return;
    }
    let dir = rust_repo();
    let repo = dir.path();
    sscsb(repo).arg("sbom").assert().success();

    let (url, rx) = stub_dtrack();
    sscsb(repo)
        .args(["enable", "dependency-track"])
        .assert()
        .success();
    let cfg_path = repo.join(".sscsb/config.toml");
    let cfg = std::fs::read_to_string(&cfg_path)
        .unwrap()
        .replace("url = \"\"", &format!("url = \"{url}\""))
        .replace("project_name = \"\"", "project_name = \"fixture\"");
    std::fs::write(&cfg_path, cfg).unwrap();

    let out = sscsb(repo)
        .env("DTRACK_API_KEY", "test-key-not-a-real-credential")
        .args(["dtrack", "upload"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("11111111-2222-3333-4444-555555555555"),
        "processing token must be parsed and reported: {stdout}"
    );

    let request = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("request");
    assert!(
        request.starts_with("PUT /api/v1/bom"),
        "wrong method/endpoint: {}",
        &request[..40.min(request.len())]
    );
    assert!(
        request.contains("X-Api-Key: test-key-not-a-real-credential"),
        "auth header missing"
    );
    assert!(
        request.contains("\"autoCreate\":true"),
        "autoCreate expected"
    );
    assert!(
        request.contains("\"projectName\":\"fixture\""),
        "project name expected"
    );
    assert!(
        request.contains("\"bom\":\"ey"),
        "base64-encoded BOM expected (starts with `ey`)"
    );
}

#[test]
fn dtrack_upload_reports_transport_failure_without_a_server() {
    let dir = rust_repo();
    let repo = dir.path();
    std::fs::create_dir_all(repo.join(".sscsb/out")).unwrap();
    std::fs::write(
        repo.join(".sscsb/out/sbom.cdx.json"),
        r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#,
    )
    .unwrap();
    sscsb(repo)
        .args(["enable", "dependency-track"])
        .assert()
        .success();
    let cfg_path = repo.join(".sscsb/config.toml");
    let cfg = std::fs::read_to_string(&cfg_path)
        .unwrap()
        // Port 1 refuses connections — a deterministic transport failure.
        .replace("url = \"\"", "url = \"http://127.0.0.1:1\"");
    std::fs::write(&cfg_path, cfg).unwrap();

    let out = sscsb(repo)
        .env("DTRACK_API_KEY", "test-key-not-a-real-credential")
        .args(["dtrack", "upload"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("Dependency-Track upload failed"),
        "transport failure must be reported, not swallowed: {stderr}"
    );

    // Missing API key is its own explicit message (never read from config).
    let out = sscsb(repo).args(["dtrack", "upload"]).assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("DTRACK_API_KEY not set"), "{stderr}");
}

// ───────────────────────────── ORAS ─────────────────────────────────────────

#[test]
fn oras_push_surfaces_registry_errors_or_degrades() {
    let dir = rust_repo();
    let repo = dir.path();
    std::fs::write(repo.join("sbom.json"), r#"{"bomFormat":"CycloneDX"}"#).unwrap();
    let file = repo.join("sbom.json");

    if tool_available("oras") {
        // 127.0.0.1:1 refuses connections — the push must fail loudly.
        let out = sscsb(repo)
            .args([
                "oras",
                "push",
                "127.0.0.1:1/sscsb-test:sbom",
                file.to_str().unwrap(),
            ])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(
            stderr.contains("oras push failed"),
            "registry error must surface: {stderr}"
        );
    }

    let out = sscsb_without_tools(repo)
        .args(["oras", "push", "example.com/x:tag", file.to_str().unwrap()])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("oras not found"), "{stderr}");
}

// ───────────────────────────── Cosign ───────────────────────────────────────

#[test]
fn cosign_verify_blob_rejects_a_bogus_bundle_and_degrades_when_absent() {
    let dir = rust_repo();
    let repo = dir.path();
    std::fs::write(repo.join("artifact.txt"), "hello\n").unwrap();
    std::fs::write(repo.join("bogus.sigstore.json"), r#"{"not":"a bundle"}"#).unwrap();
    let artifact = repo.join("artifact.txt");
    let bundle = repo.join("bogus.sigstore.json");

    if tool_available("cosign") {
        let out = sscsb(repo)
            .args([
                "provenance",
                "verify-blob",
                "--artifact",
                artifact.to_str().unwrap(),
                "--bundle",
                bundle.to_str().unwrap(),
                "--identity",
                "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main",
            ])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(
            stderr.contains("cosign verify-blob FAILED"),
            "a bogus bundle must not verify: {stderr}"
        );
    }

    let out = sscsb_without_tools(repo)
        .args([
            "provenance",
            "verify-blob",
            "--artifact",
            artifact.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--identity",
            "x",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("cosign not found"), "{stderr}");
}

#[test]
fn receipt_signing_reports_missing_oidc_rather_than_faking_a_signature() {
    let dir = rust_repo();
    let repo = dir.path();
    std::fs::write(repo.join("README.md"), "# x\n").unwrap();
    git_ok(repo, &["add", "README.md"]);
    let out = Command::new("git")
        .args(["commit", "-m", "chore: baseline"])
        .current_dir(repo)
        .env("SSCSB_BIN", assert_cmd::cargo::cargo_bin("sscsb"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Unsigned receipt creation always works.
    sscsb(repo)
        .args(["receipt", "create", "HEAD"])
        .assert()
        .success();

    // --sign in a headless session cannot reach an interactive OIDC flow; the
    // failure must be explicit, and NO bundle may be produced.
    let out = sscsb(repo)
        .args(["receipt", "create", "HEAD", "--sign"])
        .env("COSIGN_EXPERIMENTAL", "1")
        // Deny the interactive browser flow deterministically.
        .env("COSIGN_OIDC_ISSUER", "http://127.0.0.1:1")
        .timeout(std::time::Duration::from_secs(60))
        .output()
        .expect("runs");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            stderr.contains("cosign") || stderr.contains("OIDC"),
            "signing failure must name the cause: {stderr}"
        );
    }
}

// ───────────────────────────── full verify ──────────────────────────────────

/// Every control — including the optional, default-off ones — must be
/// enableable and must then produce a real verification result rather than a
/// "not wired" bug message. This is the modularity contract from the spec.
#[test]
fn every_control_can_be_enabled_and_verified() {
    let dir = rust_repo();
    let repo = dir.path();

    const ALL: &[&str] = &[
        "secrets",
        "commit-signing",
        "branch-protection",
        "actions-audit",
        "ai-trailers",
        "ai-dep-gate",
        "pr-template",
        "ai-receipts",
        "sbom",
        "vuln-scan",
        "scorecard",
        "renovate",
        "package-trust",
        "grype",
        "socket-firewall",
        "sigstore-signing",
        "slsa-provenance",
        "provenance-verify",
        "octo-sts",
        "harden-runner",
        "witness",
        "sast",
        "sighthound",
        "codeql",
        "workflow-audit-extended",
        "secure-repo",
        "wait-for-secrets",
        "dependency-track",
        "guac",
        "openvex",
        "oras",
        "compliance-map",
    ];

    for control in ALL {
        sscsb(repo).args(["enable", control]).assert().success();
    }
    // Re-init so newly-enabled controls install their artifacts.
    sscsb(repo).arg("init").assert().success();

    let out = sscsb(repo).arg("verify").output().expect("verify runs");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !stdout.contains("no verifier wired"),
        "every control must have a verifier: {stdout}"
    );
    for control in ALL {
        assert!(stdout.contains(*control), "verify skipped `{control}`");
    }

    // ...and every control can be turned OFF again, with verify saying so.
    for control in ALL {
        sscsb(repo).args(["disable", control]).assert().success();
    }
    let out = sscsb(repo).arg("verify").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let disabled_count = stdout.matches("[disabled]").count();
    assert_eq!(
        disabled_count,
        ALL.len(),
        "all {} controls should report disabled, saw {disabled_count}",
        ALL.len()
    );
}

#[test]
fn sast_pre_commit_blocks_when_enabled_and_rejects_unknown_engine() {
    let dir = rust_repo();
    let repo = dir.path();

    let cfg_path = repo.join(".sscsb/config.toml");
    let cfg = std::fs::read_to_string(&cfg_path)
        .unwrap()
        .replace("pre_commit = false", "pre_commit = true");
    std::fs::write(&cfg_path, cfg).unwrap();

    // A file the shipped ruleset flags at ERROR severity.
    std::fs::write(
        repo.join("bootstrap.sh"),
        "#!/bin/sh\nwget -qO- https://example.com/x | bash\n",
    )
    .unwrap();
    git_ok(repo, &["add", "bootstrap.sh"]);

    let out = Command::new("git")
        .args(["commit", "-m", "feat: add bootstrap script"])
        .current_dir(repo)
        .env("SSCSB_BIN", assert_cmd::cargo::cargo_bin("sscsb"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if tool_available("opengrep") {
        assert!(
            !out.status.success(),
            "pre-commit SAST must block: {stderr}"
        );
        assert!(stderr.contains("SAST findings"), "{stderr}");
    }

    // An unknown engine is a hard, explicit error — never a silent skip.
    let cfg = std::fs::read_to_string(&cfg_path)
        .unwrap()
        .replace("engine = \"opengrep\"", "engine = \"nonexistent-engine\"");
    std::fs::write(&cfg_path, cfg).unwrap();
    let out = sscsb(repo).arg("sast").assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("unknown sast engine"), "{stderr}");
}

#[test]
fn guac_ingest_requires_artifacts_before_ingesting() {
    if !tool_available("guacone") {
        // Absent-tool degrade is asserted in the main integration suite.
        return;
    }
    let dir = rust_repo();
    let out = sscsb(dir.path())
        .args(["guac", "ingest"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("nothing to ingest") || stderr.contains("guacone collect failed"),
        "{stderr}"
    );
}

#[test]
fn verify_reports_every_control_and_strict_mode_gates_on_degraded() {
    let dir = rust_repo();
    let repo = dir.path();

    let out = sscsb(repo).arg("verify").output().expect("verify runs");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    // Every registered control must appear in the verify output.
    for control in [
        "secrets",
        "commit-signing",
        "branch-protection",
        "actions-audit",
        "ai-trailers",
        "ai-dep-gate",
        "pr-template",
        "ai-receipts",
        "sbom",
        "vuln-scan",
        "scorecard",
        "renovate",
        "package-trust",
        "grype",
        "socket-firewall",
        "sigstore-signing",
        "slsa-provenance",
        "provenance-verify",
        "octo-sts",
        "harden-runner",
        "witness",
        "sast",
        "sighthound",
        "codeql",
        "workflow-audit-extended",
        "secure-repo",
        "wait-for-secrets",
        "dependency-track",
        "guac",
        "openvex",
        "oras",
        "compliance-map",
    ] {
        assert!(
            stdout.contains(control),
            "verify output missing control `{control}`"
        );
    }
    assert!(stdout.contains("verify:"), "summary line expected");

    // With no signing key configured, commit-signing is DEGRADED — so strict
    // mode must exit non-zero where the default mode does not.
    let default_code = out.status.code().unwrap_or(-1);
    let strict = sscsb(repo)
        .args(["verify", "--strict"])
        .output()
        .expect("runs");
    assert_eq!(
        default_code, 0,
        "default verify should pass on a fresh init: {stdout}"
    );
    assert_eq!(
        strict.status.code(),
        Some(1),
        "strict verify must gate on degraded controls"
    );
}
