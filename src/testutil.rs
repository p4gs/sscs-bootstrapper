//! Shared test-only helpers: a fake `gh` on PATH so gh-shelling code paths can
//! be exercised deterministically without the network. Mirrors the harness in
//! `audit.rs`'s tests; extracted so `harden` and `scorecard` reuse it.
#![cfg(test)]

use crate::context::Ctx;

/// Serializes every test that mutates process-global environment state — a
/// prepended fake `gh` on PATH, a fixture HOME, a fixture `GIT_CONFIG_GLOBAL`.
/// `setenv` is not thread-safe and the test harness is multi-threaded, so ALL
/// such tests share this one lock, not one lock per variable.
pub static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`PATH_LOCK`], ignoring poisoning from an unrelated failing test (the
/// guarded data is `()`, so a poisoned lock carries no corrupt state — without
/// this a single panicking test cascades into spurious failures everywhere).
pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII guard for process-global environment variables: sets each name to the
/// given value (or removes it when `None`), restoring every previous value on
/// drop, even on panic. Callers MUST hold [`env_lock`] for the guard's
/// lifetime — see the note on [`PATH_LOCK`].
pub struct EnvGuard {
    saved: Vec<(String, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    pub fn new(vars: &[(&str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(vars.len());
        for (key, value) in vars {
            saved.push(((*key).to_string(), std::env::var_os(key)));
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        EnvGuard { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            match value {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
    }
}

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
