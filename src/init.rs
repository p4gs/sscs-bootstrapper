//! Repository bootstrap: everything `sscsb init` does, as a library function.
//!
//! Init is a core path, so it lives here rather than in the CLI shell — the
//! command layer only prints what this returns.
//!
//! Re-running init on a live repo cannot clobber local edits, but the rule is
//! not "nothing is overwritten" — it is "nothing you are meant to edit is
//! overwritten". Three classes:
//!
//! - **Kept if present** (`write_if_absent`): `.sscsb/config.toml`, the policy
//!   TOMLs (`signers`, `packages`, `signing-model`), and every workflow or
//!   config artifact. These are yours; a local edit survives forever.
//! - **Always regenerated**: the three hook shims and
//!   `.sscsb/policy/allowed_signers`. The shims carry a `DO NOT EDIT` banner and
//!   are rewritten so a tampered or stale shim is repaired; `allowed_signers` is
//!   derived from `signers.toml` and is rewritten on every push that touches a
//!   protected branch, not only here. Hand edits to either are discarded.
//! - **Extended, never rewritten**: the repo's `.gitignore`, which gains a rule
//!   for `.sscsb/out/` only when git says that path is not already ignored.
//!   See [`ensure_out_ignored`].
//!
//! This is why the idempotence test asserts the second run writes *strictly
//! fewer* lines than the first rather than zero — a claim of zero would be false.
//!
//! `AGENTS.md` documents this split for agents, and `tests/agents_md.rs` pins
//! the doc to the behaviour: a file that starts being regenerated without the
//! doc naming it fails the build.

use crate::config;
use crate::context::Ctx;
use crate::controls;
use crate::deps;
use crate::exec;
use crate::hooks;
use crate::workflows;
use anyhow::Result;
use std::path::Path;

/// The ignore rule `init` ensures is in force for `.sscsb/out/`.
pub const OUT_IGNORE_RULE: &str = ".sscsb/out/";

/// The comment written above [`OUT_IGNORE_RULE`], so a reader who finds the
/// line in their `.gitignore` knows who put it there and why.
const OUT_IGNORE_HEADER: &str = "# sscsb: generated output (SBOMs, receipts, VEX), not policy";

/// A representative file *inside* `.sscsb/out/`, used to ask git whether the
/// directory's contents are already ignored.
///
/// Deliberately a neutral name rather than a real artifact like
/// `sbom.cdx.json`: a narrow pre-existing rule (`.sscsb/out/*.json`) would
/// match the real artifact and we would conclude the boundary was already
/// covered, leaving receipts and VEX documents exposed. A neutral probe fails
/// that check and we append the broad rule — erring toward making the
/// guarantee true.
const OUT_IGNORE_PROBE: &str = ".sscsb/out/probe";

/// Ensure files under `.sscsb/out/` are ignored. Returns the log line, or
/// `None` when the path was already ignored and nothing needed doing.
///
/// `.sscsb/` holds two different kinds of thing: policy, which belongs in
/// history, and generated output — SBOMs, receipts, VEX documents — which does
/// not. Nothing enforced that boundary, so a `git add .` after `sscsb sbom`
/// committed a regenerated SBOM into the same tree as the signed policy beside
/// it, burying real policy diffs in review noise.
///
/// Strictly additive in both directions:
///
/// - **git decides** whether the path is already ignored, so a rule the user
///   spelled differently (`.sscsb/out/**`), or one living in
///   `.git/info/exclude` or their global excludes file, counts — and nothing
///   is appended.
/// - **Appended, never rewritten.** An existing `.gitignore` keeps its
///   contents and their order; this only ever adds two lines to the end.
///
/// Adding an ignore rule cannot untrack anything, so a repo that has already
/// committed files under `.sscsb/out/` keeps tracking them — this closes the
/// hole for new repos without silently changing an existing one's contents.
fn ensure_out_ignored(ctx: &Ctx) -> Result<Option<String>> {
    let probe = exec::git_raw(
        &["check-ignore", "-q", "--no-index", OUT_IGNORE_PROBE],
        &ctx.root,
    )?;
    match probe.status {
        0 => return Ok(None), // already ignored, by whatever rule
        1 => {}               // not ignored — add the rule
        other => anyhow::bail!(
            "git check-ignore failed (exit {other}) while checking whether {OUT_IGNORE_PROBE} \
             is ignored: {}",
            probe.stderr.trim()
        ),
    }

    let path = ctx.root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut next = existing.clone();
    if !next.is_empty() {
        // Never glue our rule onto the user's last line: a file saved without
        // a trailing newline would otherwise turn `target/` into
        // `target/# sscsb: …`, silently dropping one of their rules.
        if !next.ends_with('\n') {
            next.push('\n');
        }
        next.push('\n');
    }
    next.push_str(OUT_IGNORE_HEADER);
    next.push('\n');
    next.push_str(OUT_IGNORE_RULE);
    next.push('\n');
    std::fs::write(&path, next)?;

    Ok(Some(if existing.is_empty() {
        format!("write .gitignore ({OUT_IGNORE_RULE} — generated output, not policy)")
    } else {
        format!("update .gitignore (+ {OUT_IGNORE_RULE} — generated output, not policy)")
    }))
}

/// Bootstrap `cwd`'s repository. Returns the log of what was written or kept.
pub fn bootstrap(cwd: &Path) -> Result<Vec<String>> {
    let mut log = Vec::new();
    let ctx = Ctx::discover(cwd)?;

    let config_path = ctx.config_path();
    if config_path.is_file() {
        log.push("keep .sscsb/config.toml (exists)".to_string());
    } else {
        std::fs::create_dir_all(ctx.sscsb_dir())?;
        let slug = ctx.origin_slug();
        std::fs::write(&config_path, config::default_config_toml(slug.as_deref()))?;
        log.push(format!(
            "write .sscsb/config.toml ({} controls, secure defaults)",
            controls::CONTROLS.len()
        ));
    }

    // Reload so the context sees the config we just wrote.
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.require_config()?;

    for hook in hooks::install_hooks(&ctx)? {
        log.push(format!(
            "write {hook} (POSIX shim → `sscsb hook …`, fail-closed)"
        ));
    }
    log.push("set core.hooksPath = .sscsb/hooks".to_string());

    if workflows::write_if_absent(
        &ctx.root,
        ".sscsb/policy/signers.toml",
        hooks::SIGNERS_TEMPLATE,
    )? {
        log.push("write .sscsb/policy/signers.toml (add your hardware-backed key!)".to_string());
    }
    if workflows::write_if_absent(
        &ctx.root,
        ".sscsb/policy/packages.toml",
        deps::PACKAGES_TEMPLATE,
    )? {
        log.push("write .sscsb/policy/packages.toml".to_string());
    }
    if workflows::write_if_absent(
        &ctx.root,
        ".sscsb/policy/signing-model.toml",
        crate::signing_setup::SIGNING_MODEL_TEMPLATE,
    )? {
        log.push("write .sscsb/policy/signing-model.toml".to_string());
    }
    hooks::regenerate_allowed_signers(&ctx, hooks::agent_signing_enabled(cfg))?;
    log.push("write .sscsb/policy/allowed_signers (generated from signers.toml)".to_string());

    if let Some(line) = ensure_out_ignored(&ctx)? {
        log.push(line);
    }

    log.extend(workflows::install_all(&ctx, cfg)?);
    Ok(log)
}

/// The next steps printed after a bootstrap. Kept beside `bootstrap` so the
/// guidance and the work it refers to cannot drift apart.
pub const NEXT_STEPS: &[&str] = &[
    "  1. Add your signing identity: .sscsb/policy/signers.toml (docs/signing.md)",
    "  2. Bless current dependencies: sscsb deps baseline",
    "  3. Check posture:              sscsb verify && sscsb report",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        dir
    }

    #[test]
    fn bootstrap_is_idempotent_and_never_clobbers_local_edits() {
        let dir = fresh_repo();
        let first = bootstrap(dir.path()).unwrap();
        assert!(first.iter().any(|l| l.contains("write .sscsb/config.toml")));

        // A local edit to a generated file must survive a re-init.
        let rules = dir.path().join(".sscsb/rules/sscsb-default.yaml");
        std::fs::write(&rules, "# locally edited\n").unwrap();

        let second = bootstrap(dir.path()).unwrap();
        assert!(second.iter().any(|l| l.contains("keep .sscsb/config.toml")));
        assert_eq!(
            std::fs::read_to_string(&rules).unwrap(),
            "# locally edited\n",
            "re-init must not overwrite an existing file"
        );
        assert!(
            second.iter().filter(|l| l.starts_with("write")).count()
                < first.iter().filter(|l| l.starts_with("write")).count(),
            "the second run writes strictly less than the first"
        );
    }

    #[test]
    fn bootstrap_outside_a_git_repo_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let err = bootstrap(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("not inside a git repository"));
    }

    /// Ask git, not the file text: the only thing that matters is whether a
    /// generated SBOM would be swept up by `git add .`.
    fn is_ignored(root: &Path, rel: &str) -> bool {
        exec::git_raw(&["check-ignore", "-q", rel], root)
            .unwrap()
            .status
            == 0
    }

    #[test]
    fn bootstrap_ignores_generated_output() {
        let dir = fresh_repo();
        assert!(
            !is_ignored(dir.path(), ".sscsb/out/sbom.cdx.json"),
            "precondition: a bare repo does not ignore .sscsb/out yet"
        );

        bootstrap(dir.path()).unwrap();

        assert!(
            is_ignored(dir.path(), ".sscsb/out/sbom.cdx.json"),
            "init must leave generated output ignored — otherwise `git add .` \
             commits SBOMs into policy history"
        );
        assert!(
            !is_ignored(dir.path(), ".sscsb/policy/signers.toml"),
            "policy must stay committable; only .sscsb/out is generated output"
        );
    }

    #[test]
    fn bootstrap_gitignore_entry_is_idempotent() {
        let dir = fresh_repo();
        bootstrap(dir.path()).unwrap();
        let after_first = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();

        let second = bootstrap(dir.path()).unwrap();

        let after_second = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(
            after_first, after_second,
            "a re-init must not append the ignore rule a second time"
        );
        assert_eq!(
            after_second.matches(OUT_IGNORE_RULE).count(),
            1,
            "exactly one `{OUT_IGNORE_RULE}` rule, not one per init"
        );
        assert!(
            !second.iter().any(|l| l.contains(".gitignore")),
            "the second run has nothing to do and must not claim it wrote .gitignore"
        );
    }

    #[test]
    fn bootstrap_appends_without_clobbering_an_existing_gitignore() {
        let dir = fresh_repo();
        let existing = "# my rules\ntarget/\n*.log\n";
        std::fs::write(dir.path().join(".gitignore"), existing).unwrap();

        bootstrap(dir.path()).unwrap();

        let after = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(
            after.starts_with(existing),
            "the user's rules must survive verbatim and in order; got:\n{after}"
        );
        assert!(is_ignored(dir.path(), ".sscsb/out/sbom.cdx.json"));
        assert!(
            is_ignored(dir.path(), "some.log"),
            "the user's own rules must still be in force"
        );
    }

    #[test]
    fn bootstrap_leaves_an_existing_ignore_rule_alone() {
        let dir = fresh_repo();
        // A broader rule the user chose, spelled differently to ours.
        let existing = "# mine\n.sscsb/out/**\n";
        std::fs::write(dir.path().join(".gitignore"), existing).unwrap();

        bootstrap(dir.path()).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join(".gitignore")).unwrap(),
            existing,
            "the path is already ignored; init must not append a redundant rule"
        );
    }

    #[test]
    fn bootstrap_gitignore_survives_a_file_with_no_trailing_newline() {
        let dir = fresh_repo();
        std::fs::write(dir.path().join(".gitignore"), "target/").unwrap();

        bootstrap(dir.path()).unwrap();

        let after = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(
            is_ignored(dir.path(), "target/debug"),
            "appending must not glue our rule onto the user's last line: {after:?}"
        );
        assert!(is_ignored(dir.path(), ".sscsb/out/sbom.cdx.json"));
    }
}
