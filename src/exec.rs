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

/// Locate an executable on PATH (adds `.exe` on Windows).
pub fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate = dir.join(format!("{bin}{ext}"));
            if candidate.is_file() {
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
