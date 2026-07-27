//! Shared test-only helpers: a fake `gh` on PATH so gh-shelling code paths can
//! be exercised deterministically without the network. Mirrors the harness in
//! `audit.rs`'s tests; extracted so `harden` and `scorecard` reuse it.
#![cfg(test)]

use crate::context::Ctx;

/// Serializes tests that temporarily prepend a fake `gh` onto PATH.
pub static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard: prepend `dir` to PATH, restore on drop (even on panic).
pub struct PathPrepend {
    original: Option<std::ffi::OsString>,
}

impl PathPrepend {
    pub fn new(dir: &std::path::Path) -> Self {
        let original = std::env::var_os("PATH");
        let mut joined = std::ffi::OsString::from(dir.as_os_str());
        if let Some(orig) = &original {
            joined.push(":");
            joined.push(orig);
        }
        std::env::set_var("PATH", joined);
        PathPrepend { original }
    }
}

impl Drop for PathPrepend {
    fn drop(&mut self) {
        match self.original.take() {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }
}

/// Write an executable POSIX `gh` shim running `script` into a fresh temp dir.
pub fn fake_gh(script: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gh");
    std::fs::write(&path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

/// A throwaway repo bootstrapped through the real `sscsb init`, with
/// `github_repo` set to `slug` and a single protected branch.
pub fn repo_with_gh_repo(slug: &str, branch: &str) -> (tempfile::TempDir, Ctx) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    crate::exec::git(&["init", "-b", "main"], root).unwrap();
    crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
    crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
    crate::init::bootstrap(root).expect("bootstrap");
    let cfgp = root.join(".sscsb/config.toml");
    let txt = std::fs::read_to_string(&cfgp)
        .unwrap()
        .replace(
            "# github_repo = \"owner/repo\"  # set to enable GitHub API checks",
            &format!("github_repo = \"{slug}\""),
        )
        .replace(
            "protected_branches = [\"main\", \"master\"]",
            &format!("protected_branches = [\"{branch}\"]"),
        );
    std::fs::write(&cfgp, txt).unwrap();
    let ctx = Ctx::discover(root).expect("discover");
    (dir, ctx)
}
