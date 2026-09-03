//! Shared test-only helpers, and the crate's **single** process-global
//! environment lock.
//!
//! # Why this module owns the lock
//!
//! `cargo test --lib` runs every unit test in this crate in ONE process across
//! MULTIPLE threads. The environment (`PATH`, `HOME`, `GIT_CONFIG_*`,
//! `DTRACK_API_KEY`, …) is process-global, and `setenv(3)` is not thread-safe:
//! on glibc and macOS libc it may reallocate the `environ` array, so a
//! concurrent `getenv(3)` on another thread can read a stale or freed pointer.
//! That is true even when the two threads touch *different* variables.
//!
//! Therefore: **every** mutation of **any** environment variable in this suite
//! must happen under **one** lock, and every test that depends on a variable's
//! value — including tests that only *read* it, such as anything resolving a
//! tool by bare name off `PATH` — must hold that same lock while it does.
//!
//! # Why the lock is a value, not a convention
//!
//! This used to be enforced by asking test authors to remember. It failed
//! repeatedly and expensively:
//!
//! * `provenance::tests::verify_receipt_refuses_a_signed_receipt_it_cannot_check`
//!   resolved the real `cosign` holding no lock while a sibling installed a
//!   fake `cosign` that exits 0 for anything, so a garbage bundle "verified".
//! * `provenance::tests::cosign_sign_blob_degrades…` failed in CI reporting its
//!   *own* fake as present-but-not-working, despite correctly taking the lock —
//!   because `observability`'s tests serialized on a **second, disjoint**
//!   `Mutex<()>` of their own and mutated `DTRACK_API_KEY` outside this lock
//!   entirely. Two locks over one environment is the same as no lock.
//! * `signers::tests::verify_policy_changes_*` died on `fatal: unknown error
//!   occurred while reading the configuration files` because a fixture deleted
//!   the directory `GIT_CONFIG_GLOBAL` pointed at *before* restoring the
//!   variable, and that fixture's teardown was not ordered against the lock.
//!
//! Each was patched at the victim. The hole stayed open because acquiring the
//! lock was voluntary and hand-rolling a mutator was easy — three separate
//! `PathPrepend` structs existed, none of which took a lock.
//!
//! So the lock is now a **capability token**: [`EnvLock`]. It is the only thing
//! in the crate that can mutate the environment, it restores every change when
//! it drops, and it drops *after* the last mutation by construction because the
//! mutation and the restore live on the same object. You cannot forget to take
//! it, because you cannot name a mutator without it.
//!
//! # Composition rules
//!
//! [`EnvLock`] is **not reentrant**. Acquiring it twice on one thread would
//! deadlock, so [`env_lock`] detects that and panics with a named message
//! instead of hanging a CI job.
//!
//! * Own the lock in one place per test. Take it with [`env_lock`] (or the
//!   scoped [`with_env`]) at the top of the test.
//! * The scoped helpers — [`with_env`], [`with_decoy_dir_on_path`], and
//!   `sast::tests::{serialized, with_fake_tool, with_only_git_on_path}` —
//!   acquire it themselves. **Never call one while already holding the lock.**
//!   Pass the `&EnvLock` you already have instead: every mutation is available
//!   as a method on it.
//! * Never store an `EnvLock` in a `static`/`OnceLock`; its whole contract is
//!   that it is released at the end of a test.
//!
//! These rules are enforced, not merely documented — see the `invariants`
//! tests at the bottom of this file.
#![cfg(test)]

use crate::context::Ctx;
use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// The one and only lock over process-global environment state.
///
/// Private on purpose: the lock is reachable exclusively through [`env_lock`],
/// which returns the [`EnvLock`] capability. Handing out the raw `Mutex` is how
/// callers ended up taking it without owning the restore.
static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

thread_local! {
    /// Whether *this* thread already holds [`ENV_MUTEX`], so a nested
    /// acquisition can be reported as a panic rather than a deadlock.
    static LOCK_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One recorded mutation: the variable and the value it had beforehand.
type Saved = (String, Option<OsString>);

/// Proof that the caller holds the process-global environment lock, and the
/// owner of every change made under it.
///
/// Mutation and restoration are the same object, which removes a whole class of
/// teardown bug: there is no separate guard that could outlive the lock, drop in
/// the wrong order relative to it, or be forgotten. When this value drops it
/// restores every variable it touched — in reverse order, so repeated writes to
/// one variable land back on the original — and only then releases the mutex and
/// deletes any directories it was asked to keep alive.
///
/// Obtain one with [`env_lock`] or [`with_env`]. See the module docs for the
/// composition rules.
pub struct EnvLock {
    /// Reverse-chronological log of what to put back.
    saved: RefCell<Vec<Saved>>,
    /// Temp dirs that must outlive the environment pointing at them.
    keep: RefCell<Vec<tempfile::TempDir>>,
    /// Dropped last. `Option` only so `Drop` can sequence it explicitly.
    guard: Option<std::sync::MutexGuard<'static, ()>>,
}

/// Acquire the process-global environment lock.
///
/// Poisoning is deliberately ignored: the guarded data is `()`, so a poisoned
/// lock carries no corrupt state, and without this one panicking test cascades
/// into spurious failures across the suite.
///
/// # Panics
///
/// If this thread already holds the lock. That would otherwise self-deadlock
/// and hang the test binary until CI times out, with no indication of why —
/// see the composition rules in the module docs.
pub fn env_lock() -> EnvLock {
    assert!(
        !LOCK_HELD.with(std::cell::Cell::get),
        "env_lock() is already held on this thread — acquiring it again would \
         deadlock. Do not call env_lock(), with_env(), with_decoy_dir_on_path(), \
         serialized(), with_fake_tool() or with_only_git_on_path() from inside a \
         scope that already holds an EnvLock; pass the &EnvLock you have and use \
         its methods instead. See src/testutil.rs composition rules."
    );
    let guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    LOCK_HELD.with(|h| h.set(true));
    EnvLock {
        saved: RefCell::new(Vec::new()),
        keep: RefCell::new(Vec::new()),
        guard: Some(guard),
    }
}

/// Run `f` holding the environment lock, handing it the capability.
///
/// The scoped form of [`env_lock`]. Prefer it when the lock's lifetime is
/// exactly one expression; use [`env_lock`] when a fixture needs to own it.
pub fn with_env<T>(f: impl FnOnce(&EnvLock) -> T) -> T {
    let lock = env_lock();
    f(&lock)
}

impl EnvLock {
    /// Set each named variable to the given value, or remove it when `None`.
    /// Every previous value is restored when this lock drops.
    pub fn set(&self, vars: &[(&str, Option<&str>)]) {
        for (key, value) in vars {
            match value {
                Some(v) => self.set_os(key, Some(OsStr::new(v))),
                None => self.set_os(key, None),
            }
        }
    }

    /// [`EnvLock::set`] for a single variable, without requiring valid UTF-8.
    ///
    /// # Panics
    ///
    /// If a write to `PATH` would leave `git` unresolvable. Most of this suite
    /// holds no lock — it does not touch the environment, so it has no reason
    /// to — but a great deal of it shells out to `git`. A fixture that points
    /// `PATH` at an empty directory to prove some *other* tool is missing takes
    /// `git` away from every one of those tests for the width of its critical
    /// section, and they fail with errors that look like their own bugs. Mask
    /// narrowly with [`EnvLock::hide_from_path`] instead, which removes only
    /// the binaries you name.
    pub fn set_os(&self, key: &str, value: Option<&OsStr>) {
        self.saved
            .borrow_mut()
            .push((key.to_string(), std::env::var_os(key)));
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        assert!(
            key != "PATH" || crate::exec::find_in_path("git").is_some(),
            "this PATH write hides `git` from the whole test process. Tests that \
             hold no lock still shell out to git and would fail for reasons that \
             are not theirs. Use EnvLock::hide_from_path(&[..]) to remove only \
             the binaries under test, or EnvLock::only_git_on_path() to strip \
             everything else. See src/testutil.rs."
        );
    }

    /// Prepend `dir` to `PATH`, so a binary placed in `dir` shadows any real
    /// one of the same name for the lifetime of this lock.
    pub fn prepend_path(&self, dir: &Path) {
        let mut joined = OsString::from(dir.as_os_str());
        if let Some(orig) = std::env::var_os("PATH") {
            joined.push(":");
            joined.push(orig);
        }
        self.set_os("PATH", Some(&joined));
    }

    /// Replace `PATH` outright.
    pub fn set_path(&self, value: &OsStr) {
        self.set_os("PATH", Some(value));
    }

    /// Keep `dir` alive until *after* this lock has restored the environment.
    ///
    /// Deletion order is load-bearing. A temp dir named by `PATH` or
    /// `GIT_CONFIG_GLOBAL` must not vanish while the variable still points at
    /// it: for the width of that window any concurrently-spawned `git` dies
    /// with `fatal: unknown error occurred while reading the configuration
    /// files`, which reads like a bug in whichever test caught it. Handing the
    /// dir to the lock makes the ordering structural instead of a comment.
    pub fn keep_alive(&self, dir: tempfile::TempDir) {
        self.keep.borrow_mut().push(dir);
    }

    /// Write an executable POSIX shim named `tool_name` running `script`, and
    /// put it first on `PATH` so it shadows any real binary of that name.
    ///
    /// The backing temp dir is kept alive by this lock and deleted only after
    /// `PATH` has been restored.
    pub fn fake_tool(&self, tool_name: &str, script: &str) {
        let dir = tempfile::tempdir().unwrap();
        write_shim(&dir.path().join(tool_name), script);
        self.prepend_path(dir.path());
        self.keep_alive(dir);
    }

    /// Build a `PATH` that resolves everything the real `PATH` does **except**
    /// the named binaries, and install it.
    ///
    /// Pointing `PATH` at an empty directory would hide *every* tool, so a
    /// concurrently-running test that shells out to something unrelated fails
    /// for reasons that have nothing to do with it. Instead, directories that do
    /// not contain a hidden binary are reused as-is, and a directory that does
    /// is replaced by a mirror of symlinks with just that entry omitted. The
    /// mirrors are kept alive by this lock.
    pub fn hide_from_path(&self, hidden: &[&str]) {
        let mut dirs: Vec<PathBuf> = Vec::new();
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path_var) {
            if !hidden.iter().any(|b| dir.join(b).is_file()) {
                dirs.push(dir);
                continue;
            }
            // When no mirror can be built (non-unix), the directory is dropped
            // rather than left with the binary resolvable — correctness of the
            // test under way beats the (already unlikely) concurrency cost.
            if let Some(mirror) = mirror_without(&dir, hidden) {
                dirs.push(mirror.path().to_path_buf());
                self.keep_alive(mirror);
            }
        }
        let joined = std::env::join_paths(dirs).expect("PATH entries must not contain ':'");
        self.set_path(&joined);
    }

    /// Mask `PATH` down to just `git`'s own directory, so every orchestrated
    /// tool this crate detects reports Missing — the in-process equivalent of
    /// `tests/tool_orchestration.rs`'s `sscsb_without_tools`.
    ///
    /// Deliberately NOT built on [`EnvLock::hide_from_path`]: that mirrors PATH
    /// directories into temp dirs, and git's own directory is real and
    /// permanent, so there is nothing to tear down.
    pub fn only_git_on_path(&self) {
        self.set_path(git_dir().as_os_str());
    }

    /// Mask `PATH` down to `dir` followed by git's own directory, so a decoy
    /// written into `dir` is the ONLY candidate for its name whatever the host
    /// machine has installed — the fixture cannot be fooled by a real
    /// `guacone`/`oras` sitting further along the real `PATH`.
    pub fn only_decoy_dir_on_path(&self, dir: &Path) {
        let mut joined = OsString::from(dir);
        joined.push(":");
        joined.push(git_dir());
        self.set_path(&joined);
    }
}

impl Drop for EnvLock {
    fn drop(&mut self) {
        // Reverse order: repeated writes to one variable unwind to the original.
        for (key, value) in self.saved.borrow_mut().drain(..).rev() {
            match value {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
        // Only now may directories the environment named be deleted, and only
        // then does another thread get to observe any of it.
        self.keep.borrow_mut().clear();
        LOCK_HELD.with(|h| h.set(false));
        drop(self.guard.take());
    }
}

/// The directory holding the real `git`, resolved off the ambient `PATH`.
fn git_dir() -> PathBuf {
    crate::exec::find_in_path("git")
        .expect("git must be on PATH")
        .parent()
        .expect("git binary has a parent dir")
        .to_path_buf()
}

/// Write `script` to `path` and make it executable.
fn write_shim(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Symlink every entry of `dir` into a fresh temp dir except the `hidden` names.
#[cfg(unix)]
fn mirror_without(dir: &Path, hidden: &[&str]) -> Option<tempfile::TempDir> {
    let mirror = tempfile::tempdir().ok()?;
    for entry in std::fs::read_dir(dir).ok()?.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        if hidden.iter().any(|h| OsStr::new(h) == name) {
            continue;
        }
        let _ = std::os::unix::fs::symlink(entry.path(), mirror.path().join(&name));
    }
    Some(mirror)
}

#[cfg(not(unix))]
fn mirror_without(_dir: &Path, _hidden: &[&str]) -> Option<tempfile::TempDir> {
    None
}

/// Run `f` with `PATH` masked down to `dir` followed by git's own directory.
///
/// Takes the environment lock for the duration — callers must not already hold
/// it. When you do already hold one, call
/// [`EnvLock::only_decoy_dir_on_path`] on it instead.
pub fn with_decoy_dir_on_path<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    with_env(|lock| {
        lock.only_decoy_dir_on_path(dir);
        f()
    })
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

// ───────────────────── consolidated release.yml fixtures ─────────────────────
//
// Minimal, shape-Sound `release.yml` bodies carrying the REAL steps the
// provenance controls look for when their modular template is absent. Shared
// by `workflows` (the recognizer) and `machine` (the JSON `artifacts` field)
// so both test the same evidence.

/// The SHA the shipped `release.yml` template pins `sigstore/cosign-installer`
/// to. A 40-hex value is what the recognizer requires; this one is real.
pub const COSIGN_INSTALLER_SHA: &str = "6f9f17788090df1f26f669e9d70d6ae9567deba6";
pub const ATTEST_BUILD_PROVENANCE_SHA: &str = "0f67c3f4856b2e3261c31976d6725780e5e4c373";
pub const ATTEST_SHA: &str = "a1948c3f048ba23858d222213b7c278aabede763";

/// A single-job release workflow: `permissions` is the job-level block (YAML
/// scopes, one per line, already indented six spaces) and `steps` the job's
/// step list (indented six spaces, starting with `- `).
pub fn release_workflow(job_permissions: &str, steps: &str) -> String {
    format!(
        "name: Release\non:\n  push:\n    tags: [\"v*\"]\npermissions:\n  contents: read\n\
         jobs:\n  release:\n    runs-on: ubuntu-latest\n    permissions:\n{job_permissions}\n\
         \x20   steps:\n{steps}\n"
    )
}

/// Steps that keyless-sign `dist/*` with a bundle, via a pinned installer.
pub fn cosign_sign_steps(installer_ref: &str, sign_cmd: &str) -> String {
    format!(
        "      - uses: sigstore/cosign-installer@{installer_ref}\n\
         \x20     - run: |\n\
         \x20         for f in dist/*; do\n\
         \x20           {sign_cmd}\n\
         \x20         done"
    )
}

pub const COSIGN_SIGN_BUNDLED: &str = "cosign sign-blob \"$f\" --bundle \"$f.sigstore.json\" --yes";

/// The job-level permissions block release.yml grants its release job.
pub const RELEASE_JOB_PERMISSIONS: &str =
    "      contents: write\n      id-token: write\n      attestations: write";

/// A release workflow proving `sigstore-signing` in full.
pub fn signed_release_workflow() -> String {
    release_workflow(
        RELEASE_JOB_PERMISSIONS,
        &cosign_sign_steps(COSIGN_INSTALLER_SHA, COSIGN_SIGN_BUNDLED),
    )
}

// ─────────────────────────── invariant enforcement ───────────────────────────
//
// The rules above are only worth stating if breaking them fails a build. These
// tests are the enforcement: two source lints that a future author trips
// automatically, and one concurrency probe that exercises the race the lock
// exists to prevent.
#[cfg(test)]
mod invariants {
    use super::*;

    /// Every `.rs` file in `src/`, as (name, contents).
    fn crate_sources() -> Vec<(String, String)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&src).expect("src/ is readable") {
            let path = entry.expect("readable dir entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                out.push((name, std::fs::read_to_string(&path).expect("readable")));
            }
        }
        assert!(
            out.len() > 10,
            "expected the whole crate, got {}",
            out.len()
        );
        out
    }

    /// Source lines outside comments, as (1-based line number, text).
    fn code_lines(body: &str) -> impl Iterator<Item = (usize, &str)> {
        body.lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l.trim()))
            .filter(|(_, l)| !l.starts_with("//"))
    }

    /// `testutil` must be the only place in the crate that writes the
    /// environment.
    ///
    /// This is the lint that keeps [`EnvLock`] from being merely the *polite*
    /// way to do it. Three separate `PathPrepend` structs — in `testutil`, in
    /// `audit`'s tests and in `signers`' tests — each hand-rolled
    /// `std::env::set_var("PATH", …)` and none took a lock. Types alone cannot
    /// stop a fourth being written; this can.
    #[test]
    fn no_module_outside_testutil_writes_the_environment() {
        let mut offenders = Vec::new();
        for (name, body) in crate_sources() {
            if name == "testutil.rs" {
                continue;
            }
            for (n, line) in code_lines(&body) {
                if line.contains("env::set_var") || line.contains("env::remove_var") {
                    offenders.push(format!("src/{name}:{n}: {line}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "process-global environment writes outside src/testutil.rs:\n  {}\n\n\
             The environment is shared by every test in this multi-threaded \
             binary and setenv(3) is not thread-safe. Take the lock with \
             testutil::env_lock() / with_env() and mutate through the EnvLock \
             methods, which restore on drop under the lock. See the composition \
             rules in src/testutil.rs.",
            offenders.join("\n  ")
        );
    }

    /// There must be exactly ONE environment lock in the crate.
    ///
    /// `observability`'s tests declared a private `static ENV: Mutex<()>` and
    /// serialized on it while thirty-odd tests elsewhere serialized on this
    /// module's lock. Two disjoint locks over one environment provide no mutual
    /// exclusion at all, which is what let a correctly-locked `with_fake_tool`
    /// test see a poisoned `PATH`. A `Mutex<()>` guards nothing but a critical
    /// section, so a second one is always this bug.
    #[test]
    fn no_module_declares_a_second_environment_lock() {
        let mut offenders = Vec::new();
        for (name, body) in crate_sources() {
            if name == "testutil.rs" {
                continue;
            }
            for (n, line) in code_lines(&body) {
                if line.contains("Mutex<()>") {
                    offenders.push(format!("src/{name}:{n}: {line}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "second serialization lock declared outside src/testutil.rs:\n  {}\n\n\
             The crate has exactly one environment lock, testutil::env_lock(). A \
             separate Mutex<()> does not exclude tests holding that one, so both \
             sets race. Use testutil::env_lock().",
            offenders.join("\n  ")
        );
    }

    /// Taking the lock twice on one thread must fail loudly, not hang.
    ///
    /// The lock is not reentrant, so the honest failure mode of a nested
    /// acquisition is a deadlock: the test binary stops, CI times out, and the
    /// log names no test. Panicking instead turns it into a normal failure.
    #[test]
    fn reentrant_acquisition_panics_instead_of_deadlocking() {
        let outcome = std::thread::spawn(|| {
            let _held = env_lock();
            // Would block forever without the reentrancy check.
            let _nested = env_lock();
        })
        .join();
        let err = outcome.expect_err("nested env_lock() must not succeed");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            msg.contains("already held on this thread"),
            "panic must name the reentrancy problem, got: {msg}"
        );
    }

    /// The lock must be released after a panic unwinds through it, and the
    /// environment restored — otherwise one failing test corrupts the rest.
    #[test]
    fn a_panic_restores_the_environment_and_frees_the_lock() {
        const VAR: &str = "SSCSB_TESTUTIL_PANIC_PROBE";
        let before = std::env::var_os(VAR);
        let _ = std::thread::spawn(|| {
            let lock = env_lock();
            lock.set(&[(VAR, Some("set-then-panicked"))]);
            panic!("simulated test failure");
        })
        .join();
        // Reacquiring proves the mutex was freed; the value proves the restore.
        let lock = env_lock();
        assert_eq!(
            std::env::var_os(VAR),
            before,
            "a panicking test must not leak its environment mutation"
        );
        drop(lock);
    }

    /// The race the lock exists to prevent, run head-on.
    ///
    /// Half the threads shim a uniquely-named fake tool onto `PATH` and assert
    /// they resolve *their own* shim; the other half resolve the real `git` and
    /// assert they get a real, executable binary. Unsynchronized, the shimmers'
    /// `PATH` writes are visible to the resolvers and to each other, and both
    /// assertions can fail. Every thread takes the one lock, so neither does.
    ///
    /// Measured: with `env_lock()` removed from `EnvLock` (mutating without the
    /// mutex), this test fails reliably within a handful of runs. With it, it
    /// passes. It is a probe for a real race, not a proof of its absence — the
    /// two source lints above are what make the invariant structural.
    #[test]
    fn concurrent_shimmers_and_resolvers_do_not_observe_each_other() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 40;

        let real_git = git_dir().join("git");
        assert!(real_git.is_file(), "fixture needs a real git");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                // A name unique per thread, so a shimmer that resolves another
                // shimmer's directory is a detectable failure rather than a
                // coincidental pass.
                let tool = format!("sscsb-probe-tool-{t}");
                barrier.wait();
                for _ in 0..ROUNDS {
                    if t % 2 == 0 {
                        // Shimmer: my fake must be what my own name resolves to.
                        with_env(|lock| {
                            lock.fake_tool(&tool, "#!/bin/sh\nexit 0\n");
                            let found = crate::exec::find_in_path(&tool)
                                .unwrap_or_else(|| panic!("{tool} must resolve to my own shim"));
                            assert!(
                                found.is_file(),
                                "{tool} resolved to a path that is not a file: {}",
                                found.display()
                            );
                            assert_eq!(
                                found.file_name().unwrap().to_string_lossy(),
                                tool,
                                "resolved someone else's shim"
                            );
                        });
                    } else {
                        // Resolver: the real PATH must still find the real git,
                        // and must not find any sibling's private shim.
                        with_env(|lock| {
                            let _ = lock; // holding it is the point
                            let found = crate::exec::find_in_path("git")
                                .expect("git must stay resolvable on the real PATH");
                            assert!(
                                found.is_file(),
                                "git resolved to a vanished path: {}",
                                found.display()
                            );
                            for other in 0..THREADS {
                                assert!(
                                    crate::exec::find_in_path(&format!("sscsb-probe-tool-{other}"))
                                        .is_none(),
                                    "a sibling's shim leaked onto my PATH"
                                );
                            }
                        });
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("no thread may observe another's PATH");
        }
    }
}
