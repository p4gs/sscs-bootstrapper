//! Repository context: where we are, what the repo looks like, which platform
//! we run on. Everything downstream receives a `Ctx`.

use crate::config::Config;
use crate::exec;
use crate::platform::Platform;
use anyhow::{Context as _, Result};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Ctx {
    pub root: PathBuf,
    pub platform: Platform,
    pub config: Option<Config>,
}

impl Ctx {
    /// Discover the enclosing git repository from `start`, loading
    /// `.sscsb/config.toml` if present.
    pub fn discover(start: &Path) -> Result<Self> {
        let root = exec::git(&["rev-parse", "--show-toplevel"], start)
            .context("not inside a git repository")?;
        let root = PathBuf::from(root);
        let config = Config::load(&root)?;
        Ok(Ctx {
            root,
            platform: Platform::detect(),
            config,
        })
    }

    pub fn sscsb_dir(&self) -> PathBuf {
        self.root.join(".sscsb")
    }

    pub fn config_path(&self) -> PathBuf {
        self.sscsb_dir().join("config.toml")
    }

    /// Require a loaded config, with a pointed message if `sscsb init` hasn't run.
    pub fn require_config(&self) -> Result<&Config> {
        self.config
            .as_ref()
            .context("no .sscsb/config.toml found — run `sscsb init` first")
    }

    /// `owner/repo` parsed from the `origin` remote, if any.
    pub fn origin_slug(&self) -> Option<String> {
        let url = exec::git(&["remote", "get-url", "origin"], &self.root).ok()?;
        parse_repo_slug(&url)
    }

    /// Default branch: origin/HEAD if known, else "main".
    pub fn default_branch(&self) -> String {
        exec::git(
            &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            &self.root,
        )
        .ok()
        .and_then(|s| s.rsplit('/').next().map(str::to_string))
        .unwrap_or_else(|| "main".to_string())
    }

    pub fn current_branch(&self) -> Result<String> {
        exec::git(&["branch", "--show-current"], &self.root)
    }
}

/// Parse `owner/repo` out of common git remote URL shapes.
pub fn parse_repo_slug(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches(".git");
    if let Some(rest) = url.strip_prefix("git@") {
        // git@github.com:owner/repo
        let (_, path) = rest.split_once(':')?;
        return two_segments(path);
    }
    if let Some(idx) = url.find("://") {
        // https://github.com/owner/repo
        let after = &url[idx + 3..];
        let (_, path) = after.split_once('/')?;
        return two_segments(path);
    }
    None
}

fn two_segments(path: &str) -> Option<String> {
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let owner = parts.next()?;
    let repo = parts.next()?;
    Some(format!("{owner}/{repo}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_and_https_remotes() {
        assert_eq!(
            parse_repo_slug("git@github.com:p4gs/sscs-bootstrapper.git"),
            Some("p4gs/sscs-bootstrapper".into())
        );
        assert_eq!(
            parse_repo_slug("https://github.com/p4gs/sscs-bootstrapper.git"),
            Some("p4gs/sscs-bootstrapper".into())
        );
        assert_eq!(
            parse_repo_slug("https://github.com/p4gs/sscs-bootstrapper"),
            Some("p4gs/sscs-bootstrapper".into())
        );
        assert_eq!(parse_repo_slug("not-a-url"), None);
    }

    #[test]
    fn parse_repo_slug_rejects_urls_missing_owner_or_repo_segments() {
        // `git@` prefix present but no `:owner/repo` after it.
        assert_eq!(parse_repo_slug("git@github.com"), None);
        // `://` present but nothing after the host slash.
        assert_eq!(parse_repo_slug("https://github.com/"), None);
        assert_eq!(parse_repo_slug("https://github.com"), None);
        // Only an owner, no repo segment.
        assert_eq!(parse_repo_slug("git@github.com:p4gs"), None);
        // Extra trailing slash segments are ignored beyond owner/repo.
        assert_eq!(
            parse_repo_slug("https://github.com/p4gs/sscs-bootstrapper/"),
            Some("p4gs/sscs-bootstrapper".into())
        );
    }

    fn init_repo(dir: &Path) {
        let out = exec::run("git", &["init", "-b", "main"], Some(dir)).unwrap();
        assert!(out.success());
    }

    #[test]
    fn discover_finds_the_repo_root_and_reports_absent_config() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let ctx = Ctx::discover(dir.path()).unwrap();
        assert!(ctx.config.is_none());
        assert_eq!(ctx.sscsb_dir(), ctx.root.join(".sscsb"));
        assert_eq!(
            ctx.config_path(),
            ctx.root.join(".sscsb").join("config.toml")
        );
        let err = ctx.require_config().unwrap_err();
        assert!(format!("{err:#}").contains("sscsb init"));
    }

    #[test]
    fn discover_outside_a_git_repository_fails_with_a_pointed_message() {
        let dir = tempfile::tempdir().unwrap();
        let err = Ctx::discover(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("not inside a git repository"));
    }

    #[test]
    fn require_config_succeeds_once_a_config_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        std::fs::create_dir_all(dir.path().join(".sscsb")).unwrap();
        std::fs::write(
            dir.path().join(".sscsb/config.toml"),
            crate::config::default_config_toml(None),
        )
        .unwrap();
        let ctx = Ctx::discover(dir.path()).unwrap();
        assert!(ctx.require_config().is_ok());
    }

    #[test]
    fn origin_slug_and_default_branch_track_the_configured_remote() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let ctx = Ctx::discover(dir.path()).unwrap();

        // No `origin` remote yet: origin_slug is None, default_branch falls
        // back to "main", current_branch reflects the real (unborn) branch.
        assert!(ctx.origin_slug().is_none());
        assert_eq!(ctx.default_branch(), "main");
        assert_eq!(ctx.current_branch().unwrap(), "main");

        let add = exec::run(
            "git",
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/p4gs/sscs-bootstrapper.git",
            ],
            Some(dir.path()),
        )
        .unwrap();
        assert!(add.success());
        assert_eq!(ctx.origin_slug().as_deref(), Some("p4gs/sscs-bootstrapper"));
    }
}
