//! `binary-artifacts`: a compiled program checked in beside the source is the
//! classic carrier for a poisoned commit — nobody reviews it, and a build
//! ships it as if it had been built from that source. OpenSSF Scorecard's
//! Binary-Artifacts check fails a repository that carries one; this control
//! reads the bytes rather than trusting the name, so an executable committed
//! as `logo.png` is still an executable, and only files git tracks count.

use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use anyhow::{Context as _, Result};
use std::io::Read;

/// Leading bytes that identify a compiled program regardless of its name.
/// `ca fe ba be` is both a Mach-O fat binary and a Java class file; either
/// is a finding, so the ambiguity costs nothing.
const EXECUTABLE_MAGICS: &[(&[u8], &str)] = &[
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE (Windows) executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable (64-bit)"),
    (
        b"\xce\xfa\xed\xfe",
        "Mach-O executable (32-bit, little-endian)",
    ),
    (
        b"\xcf\xfa\xed\xfe",
        "Mach-O executable (64-bit, little-endian)",
    ),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary or Java class file"),
    (b"!<arch>", "static archive (ar)"),
];

/// Extensions that carry compiled code even when the leading bytes are an
/// archive container's: OpenSSF Scorecard's list, less the pure-data types.
const CARRY_CODE_EXTENSIONS: &[&str] = &[
    "jar", "war", "ear", "class", "pyc", "pyo", "whl", "egg", "wasm", "dex", "apk", "rpm", "deb",
    "msi", "exe", "so", "dylib", "dll", "o", "a", "iso", "com",
];

/// What the leading bytes say a tracked file is, if anything a build should
/// not have to trust.
fn executable_kind(head: &[u8]) -> Option<&'static str> {
    EXECUTABLE_MAGICS
        .iter()
        .find(|(magic, _)| head.len() >= magic.len() && &head[..magic.len()] == *magic)
        .map(|(_, kind)| *kind)
}

fn carry_code_extension(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())?;
    CARRY_CODE_EXTENSIONS.iter().find(|e| **e == ext).copied()
}

/// One finding: the tracked path and why it counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryArtifact {
    pub path: String,
    pub reason: String,
}

/// Every tracked file that is, or carries, compiled code. Symlinks are not
/// followed: the link is the tracked object, and its target may be outside
/// the repository entirely.
pub fn find_binary_artifacts(ctx: &Ctx) -> Result<(usize, Vec<BinaryArtifact>)> {
    let tracked = exec::git(&["ls-files", "-z"], &ctx.root).context("git ls-files")?;
    let mut examined = 0usize;
    let mut found = Vec::new();
    for path in tracked.split('\0').filter(|p| !p.is_empty()) {
        let full = ctx.root.join(path);
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            continue; // deleted from the tree but still in the index
        };
        if !meta.is_file() {
            continue;
        }
        examined += 1;
        let mut head = [0u8; 8];
        let n = std::fs::File::open(&full)
            .and_then(|mut f| f.read(&mut head))
            .unwrap_or(0);
        if let Some(kind) = executable_kind(&head[..n]) {
            found.push(BinaryArtifact {
                path: path.to_string(),
                reason: format!("{kind} by its leading bytes"),
            });
            continue;
        }
        if let Some(ext) = carry_code_extension(path) {
            found.push(BinaryArtifact {
                path: path.to_string(),
                reason: format!("`.{ext}` carries compiled code"),
            });
        }
    }
    Ok((examined, found))
}

/// `verify binary-artifacts`.
pub fn verify_binary_artifacts(ctx: &Ctx) -> VerifyResult {
    let id = "binary-artifacts";
    let (examined, found) = match find_binary_artifacts(ctx) {
        Ok(r) => r,
        Err(err) => {
            return VerifyResult::degraded(
                id,
                "scan-error",
                vec![format!("could not list tracked files: {err:#}")],
            )
        }
    };
    if found.is_empty() {
        return VerifyResult::new(
            id,
            Outcome::Pass,
            vec![format!(
                "{examined} tracked file(s), none a compiled program or a code-carrying archive"
            )],
        );
    }
    const SHOWN: usize = 20;
    let mut messages: Vec<String> = found
        .iter()
        .take(SHOWN)
        .map(|a| format!("{}: {}", a.path, a.reason))
        .collect();
    if found.len() > SHOWN {
        messages.push(format!("… and {} more", found.len() - SHOWN));
    }
    messages.push(format!(
        "{} binary artifact(s) among {examined} tracked file(s) — a committed binary is code \
         nobody reviewed; build it in CI from source, or fetch it pinned by digest at build time",
        found.len()
    ));
    VerifyResult::new(id, Outcome::Fail, messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_with(files: &[(&str, &[u8])]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        for (path, bytes) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        exec::git(&["add", "-A"], root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    const ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00rest";
    const PE: &[u8] = b"MZ\x90\x00rest";
    const MACHO64: &[u8] = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01";
    const FAT_OR_CLASS: &[u8] = b"\xca\xfe\xba\xbe\x00\x00\x00\x02";
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00";

    /// ISC-33: every executable magic and every code-carrying extension is
    /// a finding, each naming its path.
    #[test]
    fn executables_by_magic_and_archives_by_extension_are_findings() {
        let (_d, ctx) = repo_with(&[
            ("bin/tool", ELF),
            ("bin/tool.exe", PE),
            ("bin/mac", MACHO64),
            ("bin/universal", FAT_OR_CLASS),
            ("lib/x.jar", b"PK\x03\x04data"),
            ("lib/x.so", b"\x7fELFdata"),
            ("build/mod.pyc", b"\x61\x0d\x0d\x0a"),
            ("dist/app.wasm", b"\x00asm\x01\x00\x00\x00"),
            ("pkg/x.deb", b"!<arch>\ndebian-binary"),
            ("src/main.rs", b"fn main() {}\n"),
        ]);
        let r = verify_binary_artifacts(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        for path in [
            "bin/tool",
            "bin/tool.exe",
            "bin/mac",
            "bin/universal",
            "lib/x.jar",
            "lib/x.so",
            "build/mod.pyc",
            "dist/app.wasm",
            "pkg/x.deb",
        ] {
            assert!(
                r.messages
                    .iter()
                    .any(|m| m.starts_with(&format!("{path}: "))),
                "{path} not named: {:?}",
                r.messages
            );
        }
        assert!(!r.messages.iter().any(|m| m.starts_with("src/main.rs")));
        assert!(r
            .messages
            .last()
            .unwrap()
            .contains("9 binary artifact(s) among 10"));
    }

    /// ISC-34: images, fonts and documents are data, not code.
    #[test]
    fn data_formats_are_clean() {
        let (_d, ctx) = repo_with(&[
            ("logo.png", PNG),
            ("favicon.ico", b"\x00\x00\x01\x00rest"),
            ("font.woff2", b"wOF2rest"),
            ("paper.pdf", b"%PDF-1.7rest"),
            ("photo.jpg", b"\xff\xd8\xff\xe0rest"),
            ("README.md", b"# hi\n"),
        ]);
        let r = verify_binary_artifacts(&ctx);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert!(r.messages[0].contains("6 tracked file(s), none"));
    }

    /// ISC-35: only what git tracks is examined — an untracked or ignored
    /// binary is the working tree's business, not the repository's.
    #[test]
    fn untracked_and_ignored_binaries_are_not_examined() {
        let (_d, ctx) = repo_with(&[(".gitignore", b"target/\n"), ("src/lib.rs", b"")]);
        std::fs::create_dir_all(ctx.root.join("target")).unwrap();
        std::fs::write(ctx.root.join("target/built"), ELF).unwrap();
        std::fs::write(ctx.root.join("stray"), ELF).unwrap();
        let r = verify_binary_artifacts(&ctx);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
    }

    /// ISC-53: content beats extension — an ELF named `logo.png` is an ELF.
    #[test]
    fn an_executable_disguised_as_an_image_is_still_flagged() {
        let (_d, ctx) = repo_with(&[("assets/logo.png", ELF), ("assets/real.png", PNG)]);
        let r = verify_binary_artifacts(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(r.messages[0].starts_with("assets/logo.png: ELF executable"));
        assert!(!r.messages.iter().any(|m| m.starts_with("assets/real.png")));
    }

    #[test]
    fn a_tracked_symlink_is_not_followed() {
        let (_d, ctx) = repo_with(&[("bin/real", ELF)]);
        std::os::unix::fs::symlink("real", ctx.root.join("bin/link")).unwrap();
        exec::git(&["add", "-A"], &ctx.root).unwrap();
        let (examined, found) = find_binary_artifacts(&ctx).unwrap();
        assert_eq!(examined, 1, "the link itself is not examined");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "bin/real");
    }

    #[test]
    fn magic_and_extension_tables_agree_with_their_doc() {
        assert_eq!(executable_kind(b"\x7fELF"), Some("ELF executable"));
        assert_eq!(executable_kind(b"MZ"), Some("PE (Windows) executable"));
        assert_eq!(
            executable_kind(b"\xca\xfe\xba\xbe"),
            Some("Mach-O fat binary or Java class file")
        );
        assert_eq!(executable_kind(b"\x89PNG"), None);
        assert_eq!(executable_kind(b""), None);
        assert_eq!(carry_code_extension("a/b/c.JAR"), Some("jar"));
        assert_eq!(carry_code_extension("a/b/c.tar.gz"), None);
        assert_eq!(carry_code_extension("Makefile"), None);
    }
}
