//! Repository bootstrap: everything `sscsb init` does, as a library function.
//!
//! Init is a core path, so it lives here rather than in the CLI shell — the
//! command layer only prints what this returns. Every step is idempotent: an
//! existing config, hook, policy file, or workflow is kept, never overwritten,
//! so re-running init on a live repo cannot clobber local edits.

use crate::config;
use crate::context::Ctx;
use crate::controls;
use crate::deps;
use crate::hooks;
use crate::workflows;
use anyhow::Result;
use std::path::Path;

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
    hooks::regenerate_allowed_signers(&ctx)?;
    log.push("write .sscsb/policy/allowed_signers (generated from signers.toml)".to_string());

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
    use crate::exec;

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
}
