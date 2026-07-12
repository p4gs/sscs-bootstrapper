//! Thin process-execution layer. sscsb ORCHESTRATES external tools — every
//! invocation goes through here so detection, degrade messaging, and argument
//! construction stay auditable. Uses argument arrays only (never shell
//! interpolation).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.status == 0
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
    Ok(CmdOutput {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
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
