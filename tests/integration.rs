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
        ".sscsb/policy/signing-model.toml",
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
        ".github/workflows/release-attest-sbom.yml",
        ".github/workflows/deploy-gate.yml",
        ".github/workflows/octo-sts-example.yml",
        ".github/chainguard/sscsb-automation.sts.yaml",
        ".gitleaks.toml",
        "renovate.json5",
        "security-insights.yml",
        ".sscsb/best-practices-badge.md",
        ".sscsb/osps-baseline.md",
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
    assert!(
        !repo.join(".github/workflows/cflite-pr.yml").exists(),
        "fuzzing is default-off"
    );
    // The whole ClusterFuzzLite scaffold is gated behind the (default-off)
    // fuzzing control — a repo without fuzzing gets none of it, .trivyignore
    // included (so we never drop a waiver on a repo that has nothing to waive).
    assert!(
        !repo.join(".clusterfuzzlite/Dockerfile").exists()
            && !repo.join(".clusterfuzzlite/build.sh").exists()
            && !repo.join(".trivyignore").exists(),
        "fuzzing scaffold (Dockerfile/build.sh/.trivyignore) is default-off"
    );
    assert!(
        !repo.join(".github/workflows/release.yml").exists(),
        "release-immutability is default-off"
    );
    // OpenSSF default-off controls install nothing until enabled.
    assert!(
        !repo.join(".github/workflows/sign-models.yml").exists(),
        "model-signing is default-off"
    );
    assert!(
        !repo.join(".github/workflows/gittuf-verify.yml").exists(),
        "gittuf is default-off"
    );
    // Publishing a scorecard is a disclosure decision, so its workflow only
    // installs once the owner opts in.
    assert!(
        !repo.join(".github/workflows/sscsb-scorecard.yml").exists(),
        "sscsb-scorecard is default-off"
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

/// A typo'd control id must never read as a clean run.
///
/// `sscsb verify not-a-real-control` used to filter the registry down to
/// nothing, run zero controls, print `verify: 0 failed, 0 degraded` and exit
/// `0` — so a typo in a CI invocation was indistinguishable from a genuine
/// clean verification of a control that never existed. That is the precise
/// false assurance this tool exists to eliminate, and it is worse than a
/// crash: the exit code, which `AGENTS.md` tells agents to read INSTEAD of
/// scraping stdout, affirmatively lied.
///
/// Per the documented contract an unknown id is a usage error (`2`), not a
/// gate failure (`1`) — nothing about the repository's security posture was
/// learned. `enable`/`disable` already rejected unknown ids this way; `verify`
/// was the outlier.
#[test]
fn verify_rejects_an_unknown_control_id_instead_of_reporting_a_clean_run() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);

    // 1. An unknown id alone: exit 2, and NO clean verdict on stdout.
    let out = sscsb(repo)
        .args(["verify", "not-a-real-control"])
        .assert()
        .code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        !stdout.contains("0 failed, 0 degraded"),
        "an unknown id must not print a clean summary: {stdout}"
    );
    assert!(
        stderr.contains("not-a-real-control"),
        "the message must name the invalid id: {stderr}"
    );
    assert!(
        stderr.contains("secrets"),
        "the message must list the valid control ids: {stderr}"
    );

    // 2. A PARTIALLY valid invocation must not half-run and report success.
    //    `secrets` is a real control that would otherwise PASS here, so a
    //    surviving `[PASS    ]` line is proof the run started anyway.
    let out = sscsb(repo)
        .args(["verify", "secrets", "not-a-real-control"])
        .assert()
        .code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stdout.is_empty(),
        "no control may run when any named id is invalid: {stdout}"
    );
    assert!(
        stderr.contains("not-a-real-control"),
        "the invalid id must be named: {stderr}"
    );
    assert!(
        !stderr.contains("`secrets`"),
        "the VALID id must not be reported as invalid: {stderr}"
    );

    // 3. Every named id being real still verifies normally — the gate above
    //    rejects typos, not legitimate selective verification.
    let out = sscsb(repo).args(["verify", "secrets"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("secrets") && stdout.contains("verify: 0 failed"),
        "a valid selective verify must still run: {stdout}"
    );
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

/// Reported (M16): `sscsb receipt create -- --raw` exited 101 — a panic, not a
/// diagnosis. The resolver used `git rev-parse <commit>` with no `--verify`,
/// and rev-parse echoes an unrecognised option back at exit 0, so the receipt
/// filename's 12-character slice ran off the end of `--raw`.
///
/// A CLI must never abort on its own argument. Exit 101 is what this pins
/// against: any other non-zero exit with a message on stderr is fine.
#[test]
fn receipt_create_diagnoses_an_option_shaped_revision_instead_of_panicking() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    write(repo, "README.md", "# x\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(repo, "feat: x\n").status.success());

    for revision in ["--raw", "-s"] {
        let out = sscsb(repo)
            .args(["receipt", "create", "--", revision])
            .assert()
            .failure();
        let code = out.get_output().status.code();
        assert_ne!(
            code,
            Some(101),
            "`receipt create -- {revision}` panicked instead of reporting an error"
        );
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(
            !stderr.contains("panicked at"),
            "`receipt create -- {revision}` panicked: {stderr}"
        );
        assert!(
            stderr.contains("sscsb error:"),
            "`receipt create -- {revision}` must say what went wrong: {stderr}"
        );
    }
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

// ─────────────── the five-environment commit-signing model (CLI) ────────────
//
// `sscsb signing` probes and converges the MACHINE, so every test here runs
// against a throwaway one: an isolated HOME plus an isolated git *global*
// config (`GIT_CONFIG_GLOBAL` governs both reads and writes), and a fake `gh`
// on PATH so the forge-facing probes are deterministic and offline. Nothing
// below can reach the developer's real ~/.gitconfig, ~/.claude, or the network.

/// A throwaway machine for the signing lanes.
struct FakeMachine {
    dir: tempfile::TempDir,
}

impl FakeMachine {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".ssh")).unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::write(dir.path().join("gitconfig"), "").unwrap();
        let m = FakeMachine { dir };
        // Answers the only two endpoints the signing lanes call.
        m.set_gh(
            "#!/bin/sh\ncase \"$2\" in\n  user) echo '{\"two_factor_authentication\": true}' ;;\n  \
             repos/*) printf 'human@example.invalid\\ttrue\\tvalid\\n' ;;\n  *) exit 1 ;;\nesac\n",
        );
        m
    }

    fn home(&self) -> &Path {
        self.dir.path()
    }

    fn gitconfig(&self) -> PathBuf {
        self.dir.path().join("gitconfig")
    }

    /// Replace the fake `gh` this machine puts on PATH.
    ///
    /// Every shim answers `--version` first, whatever the caller's script does
    /// with the API endpoints, because a real `gh` does — even one that is not
    /// authenticated. Tool detection reads exactly that probe, so a shim that
    /// failed it would be modelling a BROKEN `gh` rather than the API answers
    /// the test is actually about.
    fn set_gh(&self, script: &str) {
        let (shebang, rest) = script.split_once('\n').unwrap_or(("#!/bin/sh", script));
        let script = format!(
            "{shebang}\nif [ \"$1\" = \"--version\" ]; then \
             echo 'gh version 2.96.0 (test shim)'; exit 0; fi\n{rest}"
        );
        let path = self.dir.path().join("bin/gh");
        std::fs::write(&path, &script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn git(&self, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .args(args)
            .env("HOME", self.home())
            .env("GIT_CONFIG_GLOBAL", self.gitconfig())
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .output()
            .expect("git runs")
    }

    /// `git config --global <key> <value>` on the fixture machine.
    fn set(&self, key: &str, value: &str) {
        let out = self.git(&["config", "--global", key, value]);
        assert!(
            out.status.success(),
            "fixture git config {key}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The machine's current global value for `key`, if any.
    fn get(&self, key: &str) -> Option<String> {
        let out = self.git(&["config", "--global", key]);
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn write_home(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.home().join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    /// The inputs a human brings before `setup human-local` runs: a signing key
    /// on disk, an allowed_signers file, and a git identity.
    fn with_human_identity(&self) -> PathBuf {
        let key = self.write_home(".ssh/git_signing_key.pub", "ssh-ed25519 AAAAC3Nz human\n");
        self.write_home(
            ".ssh/allowed_signers",
            "me@example.invalid ssh-ed25519 AAAAC3Nz\n",
        );
        self.set("user.signingkey", key.to_str().unwrap());
        self.set("user.email", "me@example.invalid");
        self.set("user.name", "Human Example");
        key
    }
}

/// `sscsb` bound to a throwaway repo AND a throwaway machine.
fn sscsb_on(repo: &Path, machine: &FakeMachine) -> AssertCommand {
    let path = format!(
        "{}:{}",
        machine.home().join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = sscsb(repo);
    cmd.env("HOME", machine.home())
        .env("GIT_CONFIG_GLOBAL", machine.gitconfig())
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .env("PATH", path);
    cmd
}

fn stdout_of(out: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&out.get_output().stdout).to_string()
}

#[test]
fn signing_status_reports_every_lane_and_names_each_gap() {
    let dir = throwaway_repo();
    let machine = FakeMachine::new();

    let assert = sscsb_on(dir.path(), &machine)
        .args(["signing", "status"])
        .assert()
        .success();
    let stdout = stdout_of(&assert);

    for lane in [
        "human-local",
        "agent-claude-code",
        "cloud-claude",
        "github-web",
        "codespaces",
    ] {
        assert!(stdout.contains(lane), "status omits `{lane}`: {stdout}");
    }
    // Each lane's state is rendered, and an unconfigured machine shows both an
    // incomplete local lane and a lane that only guided setup can advance.
    assert!(stdout.contains("PARTIAL"), "{stdout}");
    assert!(stdout.contains("GUIDED"), "{stdout}");
    // Gaps are named with their remedy, not merely counted.
    assert!(
        stdout.contains("git global user.signingkey unset"),
        "{stdout}"
    );
    assert!(
        stdout.contains("commit.gpgsign not enabled globally"),
        "{stdout}"
    );
    assert!(stdout.contains("agent settings not found"), "{stdout}");
    assert!(stdout.contains("sscsb signing setup"), "{stdout}");
}

#[test]
fn signing_setup_human_local_converges_the_machine_and_status_then_agrees() {
    // The feature's core promise, end to end through the real binary: one
    // `setup` turns a partially-configured lane into a configured one, and the
    // writes are real `git config --global` state.
    let dir = throwaway_repo();
    let machine = FakeMachine::new();
    machine.with_human_identity();

    let assert = sscsb_on(dir.path(), &machine)
        .args(["signing", "setup", "human-local"])
        .assert()
        .success();
    let stdout = stdout_of(&assert);
    assert!(
        stdout.contains("set git global gpg.format = ssh"),
        "{stdout}"
    );
    assert!(stdout.contains("env-proof `git sign` alias"), "{stdout}");
    // Steps that cannot be automated are numbered rather than silently skipped.
    assert!(
        stdout.contains("Manual steps sscsb cannot perform"),
        "{stdout}"
    );
    assert!(stdout.contains("Register your human key"), "{stdout}");

    assert_eq!(machine.get("gpg.format").as_deref(), Some("ssh"));
    assert_eq!(machine.get("commit.gpgsign").as_deref(), Some("true"));
    let alias = machine.get("alias.sign").expect("alias.sign written");
    assert!(
        alias.contains("-c user.email='me@example.invalid'")
            && alias.contains("-c commit.gpgsign=true"),
        "alias must pin the human identity via -c overrides: {alias}"
    );

    let status = stdout_of(
        &sscsb_on(dir.path(), &machine)
            .args(["signing", "status"])
            .assert()
            .success(),
    );
    assert!(
        status.contains("[CONFIGURED] human-local"),
        "status must agree with setup: {status}"
    );
}

#[test]
fn signing_setup_dry_run_previews_without_touching_the_machine() {
    let dir = throwaway_repo();
    let machine = FakeMachine::new();
    machine.with_human_identity();
    let before = std::fs::read_to_string(machine.gitconfig()).unwrap();

    let assert = sscsb_on(dir.path(), &machine)
        .args(["signing", "setup", "human-local", "--dry-run"])
        .assert()
        .success();
    assert!(
        stdout_of(&assert).contains("gpg.format"),
        "must still preview"
    );

    assert_eq!(
        std::fs::read_to_string(machine.gitconfig()).unwrap(),
        before,
        "--dry-run mutated the global git config"
    );
    assert!(machine.get("alias.sign").is_none());
}

#[test]
fn signing_setup_rejects_an_unknown_environment_and_lists_the_valid_ids() {
    let dir = throwaway_repo();
    let machine = FakeMachine::new();

    let assert = sscsb_on(dir.path(), &machine)
        .args(["signing", "setup", "laptop"])
        .assert()
        .code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("unknown environment `laptop`"), "{stderr}");
    assert!(stderr.contains("human-local"), "{stderr}");
    assert!(stderr.contains("codespaces"), "{stderr}");
}

#[test]
fn signing_setup_agent_provisions_a_distinct_identity_without_clobbering_settings() {
    // The highest-blast-radius write in the module: it must back up the
    // existing agent settings, preserve every unrelated key, and give the agent
    // its OWN key and email — never the human's.
    //
    // ssh-keygen is used unconditionally (as elsewhere in this suite): the
    // agent lane cannot mint a key without it, so its absence is a real
    // failure, not a reason to skip.
    let dir = throwaway_repo();
    let machine = FakeMachine::new();
    machine.with_human_identity();
    machine.write_home(
        ".claude/settings.json",
        r#"{"model":"opus","env":{"UNRELATED":"keep-me"}}"#,
    );

    sscsb_on(dir.path(), &machine)
        .args([
            "signing",
            "setup",
            "agent-claude-code",
            "--agent-name",
            "Test Agent",
            "--agent-email",
            "agent@example.invalid",
        ])
        .assert()
        .success();

    // The pre-existing file was backed up verbatim before being rewritten.
    let backup = machine.home().join(".claude/settings.json.sscsb-backup");
    assert!(
        backup.exists(),
        "existing agent settings were not backed up"
    );
    assert!(std::fs::read_to_string(&backup)
        .unwrap()
        .contains("keep-me"));

    let merged: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(machine.home().join(".claude/settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(merged["model"], "opus", "unrelated keys must survive");
    assert_eq!(merged["env"]["UNRELATED"], "keep-me");
    let block = merged["env"].as_object().unwrap();
    let values: Vec<&str> = block
        .iter()
        .filter(|(k, _)| k.starts_with("GIT_CONFIG_VALUE_"))
        .filter_map(|(_, v)| v.as_str())
        .collect();
    assert!(values.contains(&"agent@example.invalid"), "{values:?}");
    assert!(
        !values.contains(&"me@example.invalid"),
        "the agent must never author as the human: {values:?}"
    );

    // A real, distinct agent key was generated, and it is NOT the human's.
    // The basename is derived from the agent's OWN name: v0.2.0 hard-coded one
    // contributor's personal assistant name here and shipped it in the public
    // binary, so every user got a key named after someone else's agent.
    let agent_key = machine.home().join(".ssh/test_agent_agent_signing_key");
    assert!(agent_key.exists(), "agent key was not generated");
    assert!(
        !machine.home().join(".ssh/jai_agent_signing_key").exists(),
        "a personal assistant name must never name another user's key"
    );
    assert_ne!(
        machine.get("user.signingkey").unwrap(),
        agent_key.to_string_lossy(),
        "agent and human must not share a key"
    );
    // allowed_signers maps the agent to its own address so its signatures are
    // locally verifiable AS the agent.
    let allowed = std::fs::read_to_string(machine.home().join(".ssh/allowed_signers")).unwrap();
    assert!(allowed.contains("agent@example.invalid"), "{allowed}");

    let status = stdout_of(
        &sscsb_on(dir.path(), &machine)
            .args(["signing", "status"])
            .assert()
            .success(),
    );
    assert!(
        status.contains("[CONFIGURED] agent-claude-code"),
        "{status}"
    );
}

#[test]
fn signing_setup_agent_refuses_to_forge_the_humans_identity() {
    // The single hard refusal in the model: if the agent's email is the
    // human's, setup must stop and write nothing at all.
    let dir = throwaway_repo();
    let machine = FakeMachine::new();
    machine.with_human_identity();

    let assert = sscsb_on(dir.path(), &machine)
        .args([
            "signing",
            "setup",
            "agent-claude-code",
            "--agent-name",
            "Impostor",
            "--agent-email",
            "me@example.invalid",
        ])
        .assert()
        .code(1);
    let stdout = stdout_of(&assert);
    assert!(stdout.contains("REFUSED"), "{stdout}");
    assert!(stdout.contains("forge your identity"), "{stdout}");

    assert!(
        !machine.home().join(".claude/settings.json").exists(),
        "a refused setup must not create agent settings"
    );
    // No key under EITHER the derived basename or the legacy personal one.
    assert!(!machine
        .home()
        .join(".ssh/impostor_agent_signing_key")
        .exists());
    assert!(!machine.home().join(".ssh/jai_agent_signing_key").exists());
}

#[test]
fn signing_setup_cloud_writes_the_repo_attribution_block_once() {
    let dir = throwaway_repo();
    let repo = dir.path();
    let machine = FakeMachine::new();

    let first = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "setup", "cloud-claude"])
            .assert()
            .success(),
    );
    assert!(first.contains("wrote attribution block"), "{first}");
    assert!(first.contains("Authorize the Claude GitHub App"), "{first}");

    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(settings["attribution"]["sessionUrl"], true);

    // Re-running recognises its own work instead of rewriting the file.
    let second = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "setup", "cloud-claude"])
            .assert()
            .success(),
    );
    assert!(
        second.contains("already has an attribution block"),
        "{second}"
    );
}

#[test]
fn confirming_a_guided_lane_records_a_dated_attestation_that_verify_reads_back() {
    // github-web and codespaces live behind web toggles with no read API, so
    // the recorded confirmation date is the only evidence `verify` has.
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    let machine = FakeMachine::new();

    let setup = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "setup", "github-web", "--confirm"])
            .assert()
            .success(),
    );
    assert!(setup.contains("Enable vigilant mode"), "{setup}");
    assert!(setup.contains("recorded 2 attestation(s)"), "{setup}");

    let policy =
        std::fs::read_to_string(repo.join(".sscsb/policy/signing-model.toml")).expect("policy");
    assert!(policy.contains("[github-web]"), "{policy}");
    assert!(policy.contains("vigilant_mode"), "{policy}");
    assert!(policy.contains("phishing_resistant_mfa"), "{policy}");

    let verify = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "verify"])
            .assert()
            .success(),
    );
    assert!(
        verify.contains("[ATTESTED ] github-web"),
        "a lane confirmed today must read as attested: {verify}"
    );
    // Lanes never confirmed stay visibly pending, with the command to fix them.
    assert!(
        verify.contains("gpg_verification: not attested"),
        "{verify}"
    );
    assert!(verify.contains("some lanes pending"), "{verify}");
}

#[test]
fn confirming_a_guided_lane_under_dry_run_records_nothing() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    let machine = FakeMachine::new();

    // `sscsb init` scaffolds the policy file as an all-commented template; a
    // dry-run --confirm must leave it exactly that way.
    let policy_path = repo.join(".sscsb/policy/signing-model.toml");
    let before = std::fs::read_to_string(&policy_path).expect("init scaffolds the template");

    let out = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "setup", "codespaces", "--confirm", "--dry-run"])
            .assert()
            .success(),
    );
    assert!(out.contains("[dry-run] --confirm would record"), "{out}");
    assert_eq!(
        std::fs::read_to_string(&policy_path).unwrap(),
        before,
        "--dry-run recorded an attestation"
    );

    // And `verify` still reports the lane as unattested.
    let verify = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "verify"])
            .assert()
            .success(),
    );
    assert!(
        verify.contains("gpg_verification: not attested"),
        "{verify}"
    );
}

#[test]
fn signing_verify_classifies_recent_history_against_the_model() {
    let dir = throwaway_repo();
    let repo = dir.path();
    init_sscsb(repo);
    git_ok(
        repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/p4gs/sscs-bootstrapper.git",
        ],
    );
    let machine = FakeMachine::new();
    machine.set_gh(
        "#!/bin/sh\ncase \"$2\" in\n  user) echo '{\"two_factor_authentication\": true}' ;;\n  \
         repos/*) printf 'agent@example.invalid\\tfalse\\tunknown_key\\n' ;;\n  *) exit 1 ;;\nesac\n",
    );

    let verify = stdout_of(
        &sscsb_on(repo, &machine)
            .args(["signing", "verify"])
            .assert()
            .success(),
    );
    assert!(verify.contains("recent-history classification"), "{verify}");
    assert!(
        verify.contains("expected for the agent lane"),
        "an unregistered key on the agent lane is the DESIGNED state, and the \
         report must say so rather than flag it: {verify}"
    );
}

#[test]
fn signing_verify_fails_only_when_the_agent_wears_the_humans_identity() {
    // Absence is a to-do (exit 0, lanes pending); identity blur is a breach.
    let dir = throwaway_repo();
    let repo = dir.path();
    let machine = FakeMachine::new();
    machine.with_human_identity();

    sscsb_on(repo, &machine)
        .args(["signing", "verify"])
        .assert()
        .success();

    // Hand the agent the human's own email.
    machine.write_home(
        ".claude/settings.json",
        r#"{"env":{"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"user.email","GIT_CONFIG_VALUE_0":"me@example.invalid"}}"#,
    );

    let assert = sscsb_on(repo, &machine)
        .args(["signing", "verify"])
        .assert()
        .code(1);
    let stdout = stdout_of(&assert);
    assert!(stdout.contains("[FAIL     ] agent-claude-code"), "{stdout}");
    assert!(stdout.contains("IDENTITY BLUR"), "{stdout}");
}

// ────────────────── Foreign-repository shapes (from the QA corpus) ──────────

/// The two repository shapes that produced real findings when `sscsb` was first
/// run against twenty repositories other than its own, pinned so CI exercises
/// them on every push rather than only a corpus run on someone's laptop.
///
/// **Docs-only.** A repository whose entire tracked content is a `README.md` has
/// no dependency manifest and nothing to release. Every dependency-facing
/// command must answer cleanly rather than inventing a finding, and — the part
/// that actually bit — `init` must not be the thing that decides such a
/// repository needs a release stack.
///
/// **No remote.** The controls that ask a forge about itself cannot answer
/// without one. The contract is that they DEGRADE, because "I could not check"
/// and "this is fine" are different answers; a bare `verify` still exits 0
/// because nothing failed, while `--strict` refuses on the unknowns. That
/// asymmetry is the whole point of the verdict model and is worth a test that
/// fails loudly if either half drifts.
#[test]
fn a_docs_only_repository_with_no_remote_is_answered_honestly() {
    let dir = throwaway_repo();
    let repo = dir.path();

    // Deliberately the entire tracked content: no manifest, no source, no remote.
    write(repo, "README.md", "# docs only\n");
    git_ok(repo, &["add", "README.md"]);
    assert!(commit_with_message(repo, "docs: readme").status.success());

    init_sscsb(repo);

    // Dependency-facing commands: nothing to find is not a finding.
    sscsb(repo).arg("deps").arg("list").assert().success();
    sscsb(repo)
        .args(["deps", "check", "--offline"])
        .assert()
        .success();

    // `verify` exits 0 — nothing FAILED — but must report unknowns rather than
    // claiming forge-side posture it never checked.
    let out = sscsb(repo)
        .arg("verify")
        .assert()
        .success()
        .get_output()
        .clone();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains("DEGRADED"),
        "a repo with no remote must report DEGRADED controls, not silent success:\n{text}"
    );

    // The exit-code half of the same contract: --strict refuses the unknowns.
    sscsb(repo).args(["verify", "--strict"]).assert().failure();

    // `report` and `status` must work without a config-dependent forge answer.
    sscsb(repo).arg("status").assert().success();
    sscsb(repo).arg("report").assert().success();
}
