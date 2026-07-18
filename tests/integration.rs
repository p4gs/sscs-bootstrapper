//! End-to-end integration tests on THROWAWAY repos in tempdirs.
//!
//! Secret-fixture policy: no secret-shaped string ever exists in this
//! repository's tree — planted secrets are constructed at RUNTIME (string
//! concatenation / ssh-keygen) inside tempdirs, so sscsb's own hooks and CI
//! scanners never trip on the test suite itself.
//!
//! External-tool policy: tests assert the REAL path when a tool is installed
//! and the explicit DEGRADE path when it is not — both behaviors are
//! spec-required, so neither branch is a skip.

use assert_cmd::Command as AssertCommand;
use std::path::{Path, PathBuf};
use std::process::Command;

fn sscsb_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin("sscsb")
}

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("SSCSB_BIN", sscsb_bin())
        .output()
        .expect("git runs")
}

fn git_ok(repo: &Path, args: &[&str]) {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sscsb(repo: &Path) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("sscsb").expect("binary");
    cmd.current_dir(repo);
    cmd
}

/// A fresh throwaway repo with identity configured and signing off.
fn throwaway_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path();
    git_ok(repo, &["init", "-b", "main"]);
    git_ok(repo, &["config", "user.name", "SSCSB Test"]);
    git_ok(repo, &["config", "user.email", "sscsb-test@example.com"]);
    git_ok(repo, &["config", "commit.gpgsign", "false"]);
    dir
}

fn init_sscsb(repo: &Path) {
    sscsb(repo).arg("init").assert().success();
}

fn tool_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn write(repo: &Path, rel: &str, content: &str) {
    let path = repo.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn commit_with_message(repo: &Path, message: &str) -> std::process::Output {
    git(repo, &["commit", "-m", message])
}

// ───────────────────────── init / config / toggles ──────────────────────────

#[test]
fn init_creates_config_hooks_policies_and_templates() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    for expected in [
        ".sscsb/config.toml",
        ".sscsb/hooks/pre-commit",
        ".sscsb/hooks/commit-msg",
        ".sscsb/hooks/pre-push",
        ".sscsb/policy/signers.toml",
        ".sscsb/policy/packages.toml",
        ".sscsb/policy/allowed_signers",
        ".sscsb/rules/sscsb-default.yaml",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/workflows/secrets-scan.yml",
        ".github/workflows/sbom.yml",
        ".github/workflows/vuln-scan.yml",
        ".github/workflows/scorecard.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/sast-opengrep.yml",
        ".github/workflows/release-sign.yml",
        ".github/workflows/release-slsa.yml",
        ".github/workflows/release-attest.yml",
        ".github/workflows/deploy-gate.yml",
        ".github/workflows/octo-sts-example.yml",
        ".github/chainguard/sscsb-automation.sts.yaml",
        ".gitleaks.toml",
        "renovate.json5",
    ] {
        assert!(
            repo.join(expected).is_file(),
            "{expected} not created by init"
        );
    }
    // Optional/off-by-default controls must NOT install their artifacts.
    assert!(
        !repo
            .join(".github/workflows/wait-for-secrets-example.yml")
            .exists(),
        "wait-for-secrets is default-off"
    );
    assert!(
        !repo
            .join(".sscsb/templates/dependency-track-compose.yml")
            .exists(),
        "dependency-track is default-off"
    );
    // hooksPath wired.
    let out = git(repo, &["config", "core.hooksPath"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), ".sscsb/hooks");
}

#[test]
fn enable_disable_toggles_config_and_verify_behavior() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    // Enabling dependency-track installs its template on re-init.
    sscsb(repo)
        .args(["enable", "dependency-track"])
        .assert()
        .success();
    init_sscsb(repo);
    assert!(repo
        .join(".sscsb/templates/dependency-track-compose.yml")
        .is_file());

    // Disabling secrets makes verify report it as disabled.
    sscsb(repo).args(["disable", "secrets"]).assert().success();
    let out = sscsb(repo).args(["verify", "secrets"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("disabled"),
        "verify should show disabled: {stdout}"
    );

    // Unknown control is a hard error naming valid ids.
    sscsb(repo)
        .args(["enable", "definitely-not-a-control"])
        .assert()
        .failure();
}

#[test]
fn status_and_report_render_all_phases() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    let out = sscsb(repo).arg("status").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for phase in ["Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5"] {
        assert!(stdout.contains(phase), "status missing {phase}");
    }

    let out = sscsb(repo).arg("report").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for marker in [
        "SLSA",
        "SSDF",
        "CRA",
        "commit-signing",
        "sigstore-signing",
        "compliance-map",
    ] {
        assert!(stdout.contains(marker), "report missing {marker}");
    }

    let out = sscsb(repo)
        .args(["report", "--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("report json parses");
    assert!(v["controls"]["secrets"]["enabled"].as_bool().unwrap());
}

// ───────────────────────── secret blocking (THE demo) ───────────────────────

#[test]
fn planted_secret_is_blocked_at_commit() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    // Baseline commit so the repo has a HEAD.
    write(repo, "README.md", "# throwaway\n");
    git_ok(repo, &["add", "README.md"]);
    let out = commit_with_message(repo, "chore: baseline");
    assert!(
        out.status.success(),
        "clean baseline commit must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Plant a runtime-constructed GitHub-PAT-shaped token (never a real one,
    // never present in this repo's sources as one string). Chosen because
    // gitleaks' github-pat rule fires on shape+entropy deterministically,
    // with no network verification needed.
    let fake_key = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
    write(
        repo,
        "config.env",
        &format!("github_token = \"{fake_key}\"\n"),
    );
    git_ok(repo, &["add", "config.env"]);
    let out = commit_with_message(repo, "feat: add config");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if tool_available("gitleaks") || tool_available("trufflehog") {
        assert!(
            !out.status.success(),
            "commit with planted secret MUST be blocked; stderr: {stderr}"
        );
        assert!(
            stderr.contains("BLOCKED"),
            "block message expected: {stderr}"
        );
    } else {
        // Fail-closed degrade: with no scanner available the commit must ALSO fail.
        assert!(
            !out.status.success(),
            "fail-closed expected with no scanners"
        );
        assert!(stderr.contains("fail-closed") || stderr.contains("no secret scanner"));
    }

    // Unstage the plant; a clean commit then passes.
    git_ok(repo, &["reset", "HEAD", "config.env"]);
    std::fs::remove_file(repo.join("config.env")).unwrap();
    write(repo, "notes.md", "clean content\n");
    git_ok(repo, &["add", "notes.md"]);
    let out = commit_with_message(repo, "docs: clean change");
    assert!(
        out.status.success(),
        "clean commit must pass after removing plant"
    );
}

#[test]
fn planted_private_key_is_blocked_at_commit() {
    if !tool_available("gitleaks") && !tool_available("trufflehog") {
        // Degrade path is covered by planted_secret_is_blocked_at_commit.
        eprintln!("scanners absent — private-key plant covered by fail-closed test");
        return;
    }
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(repo, "README.md", "# throwaway\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(repo, "chore: baseline")
        .status
        .success());

    // Generate a REAL private key at runtime (throwaway, guards nothing).
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "planted", "-f"])
        .arg(dir.path().join("planted_key"))
        .output()
        .expect("ssh-keygen");
    assert!(out.status.success());
    std::fs::copy(dir.path().join("planted_key"), repo.join("deploy_key")).unwrap();

    git_ok(repo, &["add", "deploy_key"]);
    let out = commit_with_message(repo, "feat: add deploy key");
    assert!(
        !out.status.success(),
        "private key commit MUST be blocked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ───────────────────────── CommitSigningGuard (THE other demo) ──────────────

fn bare_remote(dir: &Path) -> PathBuf {
    let remote = dir.join("origin.git");
    let out = Command::new("git")
        .args(["init", "--bare"])
        .arg(&remote)
        .output()
        .unwrap();
    assert!(out.status.success());
    remote
}

#[test]
fn unsigned_commit_to_protected_branch_is_blocked_at_push() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(repo, "README.md", "# throwaway\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(repo, "chore: baseline (unsigned)")
        .status
        .success());

    let remote = bare_remote(dir.path());
    git_ok(repo, &["remote", "add", "origin", remote.to_str().unwrap()]);

    let out = git(repo, &["push", "origin", "main"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "unsigned push to protected branch MUST be blocked: {stderr}"
    );
    assert!(
        stderr.contains("UNSIGNED") || stderr.contains("no approved signers"),
        "expected signing-guard reason, got: {stderr}"
    );

    // Same commit to a NON-protected branch passes the signing guard
    // (secret range scan may still run — content is clean).
    git_ok(repo, &["checkout", "-b", "feature/x"]);
    let out = git(repo, &["push", "origin", "feature/x"]);
    assert!(
        out.status.success(),
        "unsigned push to feature branch should pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn signed_commit_by_approved_human_passes_and_ai_class_is_rejected() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    // Generate a signing key (software key stands in for the hardware key in
    // this test; policy hardware_backed is asserted true so the guard's
    // key-class logic — not hardware detection — is what's under test).
    let keyfile = dir.path().join("signing_key");
    let out = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "sscsb-test@example.com",
            "-f",
        ])
        .arg(&keyfile)
        .output()
        .unwrap();
    assert!(out.status.success());
    let pubkey = std::fs::read_to_string(keyfile.with_extension("pub")).unwrap();

    git_ok(repo, &["config", "gpg.format", "ssh"]);
    git_ok(
        repo,
        &["config", "user.signingkey", keyfile.to_str().unwrap()],
    );

    // Approve the key as class=human.
    write(
        repo,
        ".sscsb/policy/signers.toml",
        &format!(
            "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = true\nssh_public_key = \"{}\"\n",
            pubkey.trim()
        ),
    );

    write(repo, "README.md", "# throwaway\n");
    git_ok(repo, &["add", "README.md"]);
    let out = git(repo, &["commit", "-S", "-m", "chore: signed baseline"]);
    assert!(
        out.status.success(),
        "signed commit: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let remote = bare_remote(dir.path());
    git_ok(repo, &["remote", "add", "origin", remote.to_str().unwrap()]);
    let out = git(repo, &["push", "origin", "main"]);
    assert!(
        out.status.success(),
        "signed+approved human push must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Reclassify the SAME key as class=ai → push of a new signed commit must be blocked.
    write(
        repo,
        ".sscsb/policy/signers.toml",
        &format!(
            "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"ai\"\nssh_public_key = \"{}\"\n",
            pubkey.trim()
        ),
    );
    write(repo, "more.md", "more\n");
    git_ok(repo, &["add", "more.md"]);
    let out = git(repo, &["commit", "-S", "-m", "feat: another signed commit"]);
    assert!(out.status.success());
    let out = git(repo, &["push", "origin", "main"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "ai-class signer must be rejected: {stderr}"
    );
}

// ───────────────────────── AI trailers & gates ───────────────────────────────

#[test]
fn ai_trailer_discipline_is_enforced_at_commit_msg() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(repo, "a.txt", "a\n");
    git_ok(repo, &["add", "a.txt"]);

    // Malformed: AI-Assisted without tool/model/role → blocked.
    let out = commit_with_message(repo, "feat: x\n\nAI-Assisted: true\n");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "incomplete AI trailers must block: {stderr}"
    );
    assert!(stderr.contains("AI-Role") || stderr.contains("AI-Tool"));

    // Complete trailers → accepted.
    let out = commit_with_message(
        repo,
        "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n",
    );
    assert!(
        out.status.success(),
        "complete AI trailers must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ai_dependency_gate_blocks_manifest_changes_without_review_trailer() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(repo, "README.md", "# x\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(repo, "chore: baseline")
        .status
        .success());

    // AI-assisted commit adding a dependency manifest without review trailer.
    write(
        repo,
        "package.json",
        r#"{"name":"t","dependencies":{"left-pad":"1.0.0"}}"#,
    );
    git_ok(repo, &["add", "package.json"]);
    let ai_msg = "feat: deps\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n";
    let out = commit_with_message(repo, ai_msg);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "AI dep change must gate: {stderr}");
    assert!(
        stderr.contains("AI-Dependency-Review"),
        "gate hint expected: {stderr}"
    );

    // Approve the package AND add the review trailer → passes.
    sscsb(repo)
        .args(["deps", "approve", "npm:left-pad"])
        .assert()
        .success();
    let out = commit_with_message(repo, &format!("{ai_msg}AI-Dependency-Review: approved\n"));
    assert!(
        out.status.success(),
        "approved + reviewed dep change must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn new_package_approval_gate_blocks_unapproved_deps_even_for_humans() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(repo, "README.md", "# x\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(repo, "chore: baseline")
        .status
        .success());

    write(
        repo,
        "package.json",
        r#"{"name":"t","dependencies":{"some-new-pkg":"1.0.0"}}"#,
    );
    git_ok(repo, &["add", "package.json"]);
    let out = commit_with_message(repo, "feat: human adds dep");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "unapproved new package must block: {stderr}"
    );
    assert!(
        stderr.contains("sscsb deps approve"),
        "approval hint expected: {stderr}"
    );

    // --offline: this is a fictional package, so the network existence check
    // (which now gates approval) would correctly refuse it; offline still runs
    // the typosquat heuristic, which this name does not trip.
    sscsb(repo)
        .args(["deps", "approve", "npm:some-new-pkg", "--offline"])
        .assert()
        .success();
    let out = commit_with_message(repo, "feat: human adds dep (approved)");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ───────────────────────── actions audit fixtures ────────────────────────────

#[test]
fn actions_audit_flags_fixture_and_passes_own_templates() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    // sscsb's own installed templates must pass its audit (self-audit contract).
    let out = sscsb(repo)
        .args(["verify", "actions-audit"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("PASS"),
        "own templates must pass audit: {stdout}"
    );

    // A mutable-ref, permissionless fixture must FAIL the audit.
    write(
        repo,
        ".github/workflows/bad.yml",
        "name: bad\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo hi\n",
    );
    let out = sscsb(repo)
        .args(["verify", "actions-audit"])
        .assert()
        .code(1);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("mutable ref"),
        "audit must flag @v4: {stdout}"
    );
    assert!(
        stdout.contains("permissions"),
        "audit must flag missing permissions: {stdout}"
    );
}

#[test]
fn extended_audit_flags_pwn_request_fixture() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(
        repo,
        ".github/workflows/prt.yml",
        "name: prt\non: pull_request_target\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          persist-credentials: false\n      - run: make test\n",
    );
    let out = sscsb(repo)
        .args(["verify", "workflow-audit-extended"])
        .assert()
        .code(1);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("pwn-request"),
        "extended audit must flag: {stdout}"
    );
}

// ───────────────────────── receipts ─────────────────────────────────────────

#[test]
fn receipt_create_verify_and_tamper_detection() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    write(repo, "README.md", "# x\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(
        repo,
        "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n"
    )
    .status
    .success());

    let out = sscsb(repo)
        .args(["receipt", "create", "HEAD"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let receipt_path = stdout.trim().rsplit(' ').next().unwrap().to_string();
    assert!(Path::new(&receipt_path).is_file());

    // Verify passes.
    sscsb(repo)
        .args(["receipt", "verify", &receipt_path])
        .assert()
        .success();

    // Tamper with the receipt digest → verify must fail loudly.
    let text = std::fs::read_to_string(&receipt_path).unwrap();
    let tampered = text.replacen("\"sha256\": \"", "\"sha256\": \"00", 1);
    std::fs::write(&receipt_path, tampered).unwrap();
    let out = sscsb(repo)
        .args(["receipt", "verify", &receipt_path])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("MISMATCH"),
        "tamper must be detected: {stderr}"
    );
}

// ───────────────────────── vex / observability ──────────────────────────────

#[test]
fn vex_create_produces_valid_openvex_and_scan_can_ingest_shape() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    let out = sscsb(repo)
        .args([
            "vex",
            "create",
            "--vuln",
            "CVE-2024-99999",
            "--product",
            "pkg:cargo/example@1.0.0",
            "--status",
            "not_affected",
            "--justification",
            "vulnerable_code_not_present",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let path = stdout.trim().rsplit(' ').next().unwrap().to_string();
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["statements"][0]["status"], "not_affected");

    // not_affected without justification must be rejected.
    sscsb(repo)
        .args([
            "vex",
            "create",
            "--vuln",
            "CVE-2024-1",
            "--product",
            "pkg:cargo/x@1",
            "--status",
            "not_affected",
        ])
        .assert()
        .failure();
}

#[test]
fn dtrack_upload_degrades_explicitly_without_server_config() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    // Fabricate a BOM file so the command reaches the config check.
    write(
        repo,
        ".sscsb/out/sbom.cdx.json",
        r#"{"bomFormat":"CycloneDX"}"#,
    );
    let out = sscsb(repo).args(["dtrack", "upload"]).assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("dependency-track.url not configured"),
        "explicit degrade message expected: {stderr}"
    );
}

#[test]
fn guac_ingest_degrades_explicitly_when_guacone_missing() {
    if tool_available("guacone") {
        eprintln!("guacone installed — degrade branch not applicable on this machine");
        return;
    }
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    write(
        repo,
        ".sscsb/out/sbom.cdx.json",
        r#"{"bomFormat":"CycloneDX"}"#,
    );
    let out = sscsb(repo).args(["guac", "ingest"]).assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("guacone not found"),
        "degrade must name the tool: {stderr}"
    );
    assert!(
        stderr.contains("docs.guac.sh") || stderr.contains("guac"),
        "install hint expected"
    );
}

// ─────────────────────── SBOM + SAST orchestration ──────────────────────────

/// `sscsb sbom` must drive the real Syft binary and write a CycloneDX SBOM to
/// the repo's output directory. Proves the SBOM subcommand end-to-end through
/// the CLI, not just the library function.
#[test]
fn sbom_command_writes_a_cyclonedx_bom_with_syft() {
    if !tool_available("syft") {
        eprintln!("skipping: syft not installed");
        return;
    }
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    write(
        repo,
        "Cargo.toml",
        "[package]\nname = \"d\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1\"\n",
    );
    let out = sscsb(repo).arg("sbom").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(stdout.contains("SBOM written"), "sbom output: {stdout}");
    let bom = repo.join(".sscsb/out/sbom.cdx.json");
    assert!(bom.is_file(), "SBOM file must exist at {bom:?}");
    let body = std::fs::read_to_string(&bom).unwrap();
    assert!(
        body.contains("bomFormat") && body.contains("CycloneDX"),
        "SBOM must be a CycloneDX document"
    );
}

/// `sscsb sast` must drive the real OpenGrep binary against the working tree
/// and report a finding count without erroring. Proves the SAST subcommand
/// end-to-end through the CLI.
#[test]
fn sast_command_runs_opengrep_and_reports_a_finding_count() {
    if !tool_available("opengrep") {
        eprintln!("skipping: opengrep not installed");
        return;
    }
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    write(repo, "app.py", "import os\nprint(os.getcwd())\n");
    let out = sscsb(repo).arg("sast").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("finding(s)"),
        "sast must report a finding count: {stdout}"
    );
}

// ───────────────────────── tool detection surface ───────────────────────────

#[test]
fn tools_command_lists_registry_with_pins() {
    let dir = throwaway_repo();
    let out = sscsb(dir.path()).arg("tools").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for tool in [
        "trufflehog",
        "gitleaks",
        "syft",
        "trivy",
        "osv-scanner",
        "cosign",
        "slsa-verifier",
        "opengrep",
        "semgrep",
        "guacone",
        "oras",
        "vexctl",
        "witness",
    ] {
        assert!(stdout.contains(tool), "tools output missing {tool}");
    }
    assert!(!stdout.contains("latest"), "no pin may be 'latest'");
}
