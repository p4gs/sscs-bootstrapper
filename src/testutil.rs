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

/// Build a `PATH` that resolves everything the real `PATH` does **except** the
/// named binaries, so a test can prove the "tool is missing" branch of a
/// verifier without lying to the rest of the suite.
///
/// PATH is process-global and the harness is multi-threaded: simply pointing
/// PATH at an empty directory hides *every* tool, and a concurrently-running
/// test that shells out to trufflehog or gitleaks then fails for reasons that
/// have nothing to do with it. So directories that do not contain a hidden
/// binary are reused as-is, and a directory that does is replaced by a mirror
/// of symlinks with just that entry omitted.
///
/// Returns the temp dirs backing any mirrors (keep them alive for the duration
/// of the test) and the PATH value to install with [`EnvGuard`]. Callers MUST
/// hold [`env_lock`].
pub fn path_without(hidden: &[&str]) -> (Vec<tempfile::TempDir>, std::ffi::OsString) {
    let mut keep = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if !hidden.iter().any(|b| dir.join(b).is_file()) {
            dirs.push(dir);
            continue;
        }
        // When no mirror can be built (non-unix), the directory is dropped
        // rather than left with the binary resolvable — correctness of the test
        // under way beats the (already unlikely) concurrency cost.
        if let Some(mirror) = mirror_without(&dir, hidden) {
            dirs.push(mirror.path().to_path_buf());
            keep.push(mirror);
        }
    }
    let joined = std::env::join_paths(dirs).expect("PATH entries must not contain ':'");
    (keep, joined)
}

/// Symlink every entry of `dir` into a fresh temp dir except the `hidden` names.
#[cfg(unix)]
fn mirror_without(dir: &std::path::Path, hidden: &[&str]) -> Option<tempfile::TempDir> {
    let mirror = tempfile::tempdir().ok()?;
    for entry in std::fs::read_dir(dir).ok()?.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        if hidden.iter().any(|h| std::ffi::OsStr::new(h) == name) {
            continue;
        }
        let _ = std::os::unix::fs::symlink(entry.path(), mirror.path().join(&name));
    }
    Some(mirror)
}

#[cfg(not(unix))]
fn mirror_without(_dir: &std::path::Path, _hidden: &[&str]) -> Option<tempfile::TempDir> {
    None
}

/// Run `f` with PATH masked down to `dir` followed by git's own directory, so
/// a decoy written into `dir` is the ONLY candidate for its name whatever the
/// host machine has installed — the fixture cannot be fooled by a real
/// `guacone`/`oras` sitting further along the real PATH.
///
/// Deliberately NOT built on [`path_without`]: that mirrors a whole PATH
/// directory into a tempdir which is deleted when the test ends, and a
/// concurrently-running test that resolved a tool through the mirror and spawns
/// it a moment later gets ENOENT for a tool that is installed. git's own
/// directory is real and permanent, so there is nothing to tear down.
///
/// Takes [`env_lock`] for the duration — callers must not already hold it.
pub fn with_decoy_dir_on_path<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let _lock = env_lock();
    let git_dir = crate::exec::find_in_path("git")
        .expect("git must be on PATH")
        .parent()
        .expect("git binary has a parent dir")
        .to_path_buf();
    let mut joined = std::ffi::OsString::from(dir);
    joined.push(":");
    joined.push(&git_dir);
    let _env = EnvGuard::new(&[("PATH", Some(&joined.to_string_lossy()))]);
    f()
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
