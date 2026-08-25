//! Thin process-execution layer. sscsb ORCHESTRATES external tools — every
//! invocation goes through here so detection, degrade messaging, and argument
//! construction stay auditable. Uses argument arrays only (never shell
//! interpolation).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The -1 `status` placeholder used when a child has no exit code at all.
/// It is a sentinel, never a code: read it through [`CmdOutput::exit_code`].
const NO_EXIT_CODE: i32 = -1;

#[derive(Debug, Clone)]
pub struct CmdOutput {
    /// The child's exit code, or [`NO_EXIT_CODE`] when it was killed by a
    /// signal. Prefer [`CmdOutput::exit_code`], which cannot be mistaken for
    /// a small exit code by a comparison like `status > 1`.
    pub status: i32,
    /// `Some(sig)` when the child was terminated by a signal — an OOM kill, a
    /// timeout's SIGKILL, a segfault — and therefore never exited at all.
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.exit_code() == Some(0)
    }

    /// The child's exit code, or `None` if it did not exit normally.
    ///
    /// A killed process has NO exit code. Representing that as -1 and then
    /// comparing numerically ranks "we do not know how this ended" below every
    /// real failure code — which is how a killed scanner reads as a clean one.
    pub fn exit_code(&self) -> Option<i32> {
        match self.signal {
            Some(_) => None,
            None => Some(self.status),
        }
    }

    /// How the child ended, for diagnostics: `exit 2`, or `killed by signal 9`.
    pub fn termination(&self) -> String {
        match self.signal {
            Some(sig) => format!("killed by signal {sig}"),
            None => format!("exit {}", self.status),
        }
    }
}

/// A child's output with stdout kept as raw BYTES.
///
/// `CmdOutput.stdout` is `String::from_utf8_lossy`, which is lossy by name and
/// by nature: every byte sequence that is not valid UTF-8 becomes U+FFFD, three
/// bytes of `EF BF BD`. For a tool's diagnostics that is harmless. For a file's
/// CONTENT it is destructive and silent — the bytes change, the length changes,
/// and nothing reports it. Use this whenever a child's stdout *is* content
/// (a git blob, an archive) rather than a message.
#[derive(Debug, Clone)]
pub struct RawOutput {
    /// See [`CmdOutput::status`] — same sentinel, same caveat.
    pub status: i32,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl RawOutput {
    pub fn success(&self) -> bool {
        self.signal.is_none() && self.status == 0
    }
}

/// Run `bin` with `args`, optionally in `cwd`, capturing output.
pub fn run(bin: &str, args: &[&str], cwd: Option<&Path>) -> Result<CmdOutput> {
    run_with_stdin(bin, args, cwd, None)
}

/// Run with optional bytes piped to stdin.
pub fn run_with_stdin(
    bin: &str,
    args: &[&str],
    cwd: Option<&Path>,
    stdin: Option<&[u8]>,
) -> Result<CmdOutput> {
    let raw = run_raw(bin, args, cwd, stdin)?;
    Ok(CmdOutput {
        status: raw.status,
        signal: raw.signal,
        stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
        stderr: raw.stderr,
    })
}

/// Run `bin`, capturing stdout as raw bytes. See [`RawOutput`].
pub fn run_bytes(bin: &str, args: &[&str], cwd: Option<&Path>) -> Result<RawOutput> {
    run_raw(bin, args, cwd, None)
}

fn run_raw(
    bin: &str,
    args: &[&str],
    cwd: Option<&Path>,
    stdin: Option<&[u8]>,
) -> Result<RawOutput> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{bin}` (is it installed and on PATH?)"))?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        use std::io::Write;
        // Ignore broken-pipe: the child may exit before reading all input.
        let _ = pipe.write_all(bytes);
    }
    let out = child
        .wait_with_output()
        .with_context(|| format!("failed while waiting for `{bin}`"))?;
    Ok(RawOutput {
        status: out.status.code().unwrap_or(NO_EXIT_CODE),
        signal: terminating_signal(&out.status),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// The signal that killed a child, if one did. Windows has no signals, and its
/// `ExitStatus::code()` always yields a code, so this is `None` there.
fn terminating_signal(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

/// True for a bare git object name: 7-64 lowercase hex characters.
///
/// Argument arrays stop the *shell* reinterpreting a value; they do not stop
/// **git** reading one as an option. `git show`, `git log`, and `git rev-list`
/// all inherit git's diff options including `--output=<file>`, so a value like
/// `--output=/etc/thing` becomes a file write, and `-s` suppresses output
/// entirely so a caller comparing digests sees `sha256("")`. Both reproduced
/// against git 2.50.1.
///
/// Two defences, used together because they suit different call shapes:
///
/// - `--end-of-options` before the revision, where the revision is the LAST
///   argument. Deliberately **not** `--`: after `--`, git treats arguments as
///   PATHSPECS, so `git show --format= -- <sha>` exits 0 with EMPTY output,
///   turning a digest comparison into a universal forgery — strictly worse
///   than the bug it would be fixing.
/// - This guard, where trailing flags must follow the revision (`rev-list
///   <sha> --not --remotes`) and `--end-of-options` would swallow them.
///
/// Values built with a fixed non-option prefix (`:{file}`, `HEAD:{file}`) are
/// safe by construction and need neither.
pub fn is_object_name(s: &str) -> bool {
    (7..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// True when the OS would actually execute `path`.
///
/// On Unix that is a regular file with an execute bit. `metadata` follows
/// symlinks deliberately: PATH directories are full of them (Homebrew,
/// update-alternatives, cargo shims) and it is the *target* that gets executed.
///
/// The test is "any execute bit", not "executable by me": reading the effective
/// answer needs `access(2)`, which std does not expose, and this crate takes no
/// libc dependency. The residual over-acceptance is a root-only-executable file
/// — orders of magnitude narrower than accepting every regular file, and the
/// spawn still fails loudly rather than silently passing a control.
#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Windows carries executability in the file *extension* (PATHEXT), not a mode
/// bit — `is_file()` is the right test there, and the caller only ever offers
/// candidates at executable extensions.
#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Locate an executable on PATH (adds `.exe`/`.cmd` on Windows).
///
/// A candidate only counts when it is EXECUTABLE. Accepting any regular file —
/// which is what `is_file()` alone does — means a plain text file dropped into
/// a PATH directory under a tool's name is reported as that tool being
/// installed. Combined with [`crate::tools::detect`], which used to swallow the
/// version probe's failure, a non-executable three-line shell script named
/// `guacone` flipped `sscsb verify --strict guac` from exit 1 (DEGRADED, tool
/// absent) to exit 0 (PASS). Reproduced end to end against the real binary.
///
/// This is the root of the class: every orchestrated tool — cosign,
/// slsa-verifier, guacone, oras, witness, gh — resolves through here.
pub fn find_in_path(bin: &str) -> Option<PathBuf> {
    find_in(&std::env::var_os("PATH")?, bin)
}

/// The lookup itself, against an explicit PATH value.
///
/// Split out so the search can be tested without mutating the process
/// environment: PATH is process-global and the test harness is threaded, so
/// every env-mutating test steals time from every other one and risks handing
/// a neighbour a PATH that does not contain the tool it is about to spawn.
pub fn find_in(path_var: &std::ffi::OsStr, bin: &str) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(path_var) {
        for ext in exts {
            let candidate = dir.join(format!("{bin}{ext}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Run git with args in `cwd`, returning trimmed stdout on success.
pub fn git(args: &[&str], cwd: &Path) -> Result<String> {
    let out = run("git", args, Some(cwd))?;
    if !out.success() {
        anyhow::bail!(
            "git {} failed (exit {}): {}",
            args.join(" "),
            out.status,
            out.stderr.trim()
        );
    }
    Ok(out.stdout.trim().to_string())
}

/// Run git, returning the full CmdOutput without failing on non-zero exit.
pub fn git_raw(args: &[&str], cwd: &Path) -> Result<CmdOutput> {
    run("git", args, Some(cwd))
}

/// Run git, keeping stdout as raw bytes — for `git show :<file>` and friends,
/// where stdout is a blob's content and must survive verbatim. See [`RawOutput`].
pub fn git_bytes(args: &[&str], cwd: &Path) -> Result<RawOutput> {
    run_bytes("git", args, Some(cwd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_captures_stdout_and_status() {
        let out = run("git", &["--version"], None).unwrap();
        assert!(out.success());
        assert!(out.stdout.contains("git version"));
    }

    #[test]
    fn run_missing_binary_is_error_not_panic() {
        let err = run("sscsb-definitely-not-a-real-binary", &[], None);
        assert!(err.is_err());
        let msg = format!("{:#}", err.unwrap_err());
        assert!(msg.contains("is it installed"));
    }

    #[test]
    fn find_in_path_finds_git_and_misses_garbage() {
        assert!(find_in_path("git").is_some());
        assert!(find_in_path("sscsb-definitely-not-a-real-binary").is_none());
    }

    /// A PATH entry is only a tool when the OS would actually run it.
    ///
    /// Before the executable check, `is_file()` accepted ANY regular file, so a
    /// plain text file named after a tool was reported as that tool being
    /// installed — the root of the `guacone`/`oras` false-detection class that
    /// flipped `sscsb verify --strict` from exit 1 to exit 0.
    ///
    /// Unix-only because executability is only a mode bit on Unix; on Windows
    /// it is carried by the file extension, and there the second layer
    /// (`tools::detect`'s version probe, which cannot spawn an extensionless
    /// file) is what closes the same hole.
    #[cfg(unix)]
    #[test]
    fn find_in_path_refuses_a_non_executable_file_named_after_a_tool() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path_var = std::ffi::OsString::from(dir.path());
        let decoy = dir.path().join("guacone");
        std::fs::write(&decoy, "#!/bin/sh\n# never chmod +x\necho hi\n").unwrap();
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            find_in(&path_var, "guacone").is_none(),
            "a non-executable regular file must never be reported as an installed tool"
        );

        // The other side of the guard: the SAME file, once executable, is
        // found. The check must not become a false negative for a tool that is
        // genuinely installed.
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            find_in(&path_var, "guacone").as_deref(),
            Some(decoy.as_path()),
            "an executable file on PATH must still be found"
        );
    }

    /// PATH entries are routinely symlinks (Homebrew, update-alternatives), and
    /// it is the TARGET that gets executed — so the mode check must follow the
    /// link rather than reading the symlink's own (always 0777) mode.
    #[cfg(unix)]
    #[test]
    fn find_in_path_follows_symlinks_to_judge_executability() {
        use std::os::unix::fs::PermissionsExt;
        let target_dir = tempfile::tempdir().unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let path_var = std::ffi::OsString::from(link_dir.path());

        let target = target_dir.path().join("real-payload");
        std::fs::write(&target, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = link_dir.path().join("oras");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            find_in(&path_var, "oras").is_none(),
            "a symlink to a NON-executable file is not an installed tool"
        );

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            find_in(&path_var, "oras").as_deref(),
            Some(link.as_path()),
            "a symlink to an executable file is a normal, valid install"
        );
    }

    /// The first EXECUTABLE candidate wins, not the first file: a decoy
    /// earlier on PATH must not mask the real tool behind it.
    #[cfg(unix)]
    #[test]
    fn find_in_path_skips_a_non_executable_candidate_and_keeps_searching() {
        use std::os::unix::fs::PermissionsExt;
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();

        let decoy = first.path().join("witness");
        std::fs::write(&decoy, "not a binary\n").unwrap();
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o644)).unwrap();
        let real = second.path().join("witness");
        std::fs::write(&real, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path_var =
            std::env::join_paths([first.path(), second.path()]).expect("joinable PATH entries");
        assert_eq!(
            find_in(&path_var, "witness").as_deref(),
            Some(real.as_path()),
            "the search must step over the decoy and find the real install"
        );
    }

    /// `find_in_path` is `find_in` bound to the process PATH — pinned so the
    /// pure-function tests above really do describe the real lookup.
    #[test]
    fn find_in_path_is_find_in_against_the_process_path() {
        let path_var = std::env::var_os("PATH").expect("PATH is set");
        assert_eq!(find_in_path("git"), find_in(&path_var, "git"));
        assert_eq!(
            find_in_path("sscsb-definitely-not-a-real-binary"),
            find_in(&path_var, "sscsb-definitely-not-a-real-binary")
        );
    }

    #[test]
    fn stdin_is_delivered() {
        // `git hash-object --stdin` reads stdin deterministically.
        let out = run_with_stdin(
            "git",
            &["hash-object", "--stdin"],
            None,
            Some(b"sscsb-test\n"),
        )
        .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.trim().len(), 40);
    }

    #[test]
    fn git_returns_trimmed_stdout_on_success_and_bails_with_context_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        git(&["init", "-b", "main"], dir.path()).unwrap();
        let branch = git(&["branch", "--show-current"], dir.path()).unwrap();
        assert_eq!(branch, "main", "stdout must be trimmed, not just captured");

        let err = git(&["not-a-real-git-subcommand"], dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("git not-a-real-git-subcommand failed"));
        assert!(msg.contains("exit"));
    }

    /// A killed child has no exit code, and saying so is the whole point of
    /// `signal`/`exit_code`: the -1 in `status` is a sentinel, and any caller
    /// that compares it numerically ranks "we do not know how this ended"
    /// below every real failure code.
    #[cfg(unix)]
    #[test]
    fn a_signal_killed_child_has_no_exit_code_only_a_signal() {
        let killed = run("sh", &["-c", "printf partial; kill -9 $$"], None).unwrap();
        assert_eq!(killed.signal, Some(9));
        assert_eq!(killed.exit_code(), None);
        assert!(!killed.success());
        assert_eq!(killed.termination(), "killed by signal 9");
        assert_eq!(
            killed.stdout, "partial",
            "whatever it printed before dying is still captured — which is how \
             a killed scanner can look like a finished one"
        );

        let exited = run("sh", &["-c", "exit 3"], None).unwrap();
        assert_eq!(exited.signal, None);
        assert_eq!(exited.exit_code(), Some(3));
        assert!(!exited.success());
        assert_eq!(exited.termination(), "exit 3");

        let ok = run("sh", &["-c", "exit 0"], None).unwrap();
        assert!(ok.success());
        assert_eq!(ok.exit_code(), Some(0));
    }

    /// The distinction `RawOutput` exists for: `CmdOutput.stdout` is decoded
    /// lossily, so a child whose stdout is CONTENT (a git blob) cannot be read
    /// through it. Both halves are asserted — the bytes survive `git_bytes`,
    /// and they demonstrably do NOT survive the `CmdOutput` path.
    #[test]
    fn run_bytes_preserves_non_utf8_stdout_that_the_string_path_replaces() {
        let dir = tempfile::tempdir().unwrap();
        git(&["init", "-b", "main"], dir.path()).unwrap();
        let blob: Vec<u8> = (0u8..=255).collect();
        let written = run_with_stdin(
            "git",
            &["hash-object", "-w", "--stdin"],
            Some(dir.path()),
            Some(&blob),
        )
        .unwrap();
        assert!(written.success());
        let sha = written.stdout.trim().to_string();

        let raw = git_bytes(&["cat-file", "blob", &sha], dir.path()).unwrap();
        assert!(raw.success());
        assert_eq!(raw.stdout, blob, "raw bytes must round-trip verbatim");

        let lossy = git_raw(&["cat-file", "blob", &sha], dir.path()).unwrap();
        assert_ne!(
            lossy.stdout.as_bytes(),
            blob.as_slice(),
            "the String path is lossy — if this ever holds, RawOutput is pointless"
        );

        let failed = git_bytes(&["not-a-real-git-subcommand"], dir.path()).unwrap();
        assert!(!failed.success());
        assert!(failed.stdout.is_empty());
    }

    #[test]
    fn git_raw_never_fails_on_non_zero_exit_unlike_git() {
        let dir = tempfile::tempdir().unwrap();
        git(&["init", "-b", "main"], dir.path()).unwrap();
        // A failing git invocation is a normal Ok(CmdOutput) from git_raw —
        // callers that need to tolerate non-zero exits (e.g. probing whether
        // a ref exists) rely on this, unlike `git()` which bails.
        let out = git_raw(&["not-a-real-git-subcommand"], dir.path()).unwrap();
        assert!(!out.success());
        assert_ne!(out.status, 0);
    }
}
