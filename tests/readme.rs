//! README.md must never describe a `sscsb` that does not exist.
//!
//! `tests/agents_md.rs` pins AGENTS.md to the binary. README.md is the same
//! rot class in a different file, and it had drifted the same two ways AGENTS.md
//! had before its own evidence pass: it printed a verdict symbol the binary
//! never emits, and it defined `DEGRADED` narrowly enough to send a reader
//! hunting for a tool that is already installed.
//!
//! These guards are deliberately the same shape as the AGENTS.md ones. A doc
//! that lies to a human costs less than one that lies to an agent, but the
//! repository claims both files are true.

use assert_cmd::Command;
use sscsb::controls;

const README_MD: &str = include_str!("../README.md");

/// A throwaway repo with `sscsb init` already run in it.
///
/// Duplicated from `tests/agents_md.rs` because each integration test file is
/// its own crate; sharing it would mean a `tests/common/` module and a churn
/// of the file another guard already depends on.
fn bootstrapped_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path();
    for args in [
        vec!["init", "-b", "main"],
        vec!["config", "user.name", "SSCSB Doc Guard"],
        vec!["config", "user.email", "doc-guard@example.com"],
        vec!["config", "commit.gpgsign", "false"],
    ] {
        let out = std::process::Command::new("git")
            .args(&args)
            .current_dir(repo)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?} failed");
    }
    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .arg("init")
        .current_dir(repo)
        .assert()
        .success();
    dir
}

fn sscsb_in(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("runs")
}

/// README's verdict table must spell the outcomes the way the binary prints
/// them. `Outcome::Disabled` renders as lowercase `disabled` while every other
/// symbol is uppercase; README carried `DISABLED` — a spelling `sscsb verify`
/// never produces — so a reader grepping their own output for the documented
/// string found nothing.
#[test]
fn readme_verdict_table_uses_the_binary_symbols() {
    for outcome in [
        controls::Outcome::Pass,
        controls::Outcome::Fail,
        controls::Outcome::Degraded,
        controls::Outcome::Disabled,
        controls::Outcome::Info,
    ] {
        let symbol = outcome.symbol();
        assert!(
            README_MD.contains(&format!("`{symbol}`")),
            "README.md's verdict table is missing the exact symbol `{symbol}` \
             that the binary prints"
        );
    }
}

/// Presence alone would still pass if a future edit ADDED the lowercase row and
/// left the uppercase one beside it, leaving the doc claiming two verdicts where
/// the binary has one. `DISABLED` is not a string `sscsb` can ever print, so its
/// presence anywhere in README is the defect itself.
#[test]
fn readme_never_prints_a_verdict_symbol_the_binary_cannot_emit() {
    let real: Vec<&str> = [
        controls::Outcome::Pass,
        controls::Outcome::Fail,
        controls::Outcome::Degraded,
        controls::Outcome::Disabled,
        controls::Outcome::Info,
    ]
    .iter()
    .map(|o| o.symbol())
    .collect();
    assert!(
        !real.contains(&"DISABLED"),
        "fixture drifted: the binary now emits `DISABLED`, so this guard is \
         asserting the wrong thing"
    );
    assert!(
        !README_MD.contains("DISABLED"),
        "README.md contains `DISABLED`, which `sscsb verify` never prints — it \
         renders `Outcome::Disabled` as lowercase `disabled`"
    );
}

/// README defined `DEGRADED` as "the control is on but a tool is missing" and
/// annotated `--strict` as "DEGRADED (missing tool)". A missing tool is only one
/// of the reasons. On a fresh bootstrap, `commit-signing` degrades with every
/// tool present and healthy, because no signer is configured yet — a reader
/// following README goes looking for a binary that is already installed.
///
/// The behavioural half is proven against a real bootstrap rather than asserted,
/// so the broadened wording is a fact about the code, not editorial preference.
#[test]
fn readme_degraded_is_not_defined_as_a_missing_tool() {
    let dir = bootstrapped_repo();
    let out = sscsb_in(dir.path(), &["verify", "commit-signing"]);
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("[DEGRADED]"),
        "fixture drifted: a freshly bootstrapped repo with no signers should \
         degrade `commit-signing`. Got:\n{text}"
    );
    // `tools::degrade_message` is the only thing that emits this phrase, so its
    // absence proves nothing was missing from PATH.
    assert!(
        !text.contains("not found on PATH"),
        "this control degraded because of a MISSING TOOL, which would make \
         README's old definition correct and this guard meaningless:\n{text}"
    );

    let degraded_row = README_MD
        .lines()
        .find(|l| l.starts_with("| `DEGRADED`"))
        .expect("README.md must have a `DEGRADED` verdict row");
    assert!(
        !degraded_row.contains("on but a tool is missing"),
        "README.md still defines DEGRADED narrowly as a missing tool, but a \
         fresh bootstrap degrades `commit-signing` with every tool present"
    );
    assert!(
        README_MD.contains("could not be performed"),
        "README.md's DEGRADED row must define the outcome as the check not \
         happening, not narrowly as a missing tool"
    );
    assert!(
        !README_MD.contains("DEGRADED (missing tool)"),
        "README.md's `--strict` annotation still calls DEGRADED a missing tool"
    );
}
