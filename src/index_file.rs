//! Git-owned evidence, independent of the filesystem's checkout and links.

use crate::exec;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) type Entries = BTreeMap<String, Entry>;

#[derive(Debug)]
pub(crate) struct Entry {
    mode: String,
    oid: String,
    unresolved: bool,
    utf8_path: bool,
}

impl Entry {
    pub(crate) fn regular(&self) -> bool {
        !self.unresolved && matches!(self.mode.as_str(), "100644" | "100755")
    }

    pub(crate) fn may_open_worktree_path(&self) -> bool {
        self.utf8_path && !self.unresolved
    }

    pub(crate) fn blob(&self, root: &Path) -> Result<Vec<u8>> {
        anyhow::ensure!(self.regular(), "not a regular, resolved Git file");
        let out = exec::git_bytes(
            &["--no-replace-objects", "cat-file", "blob", &self.oid],
            root,
        )?;
        anyhow::ensure!(out.success(), "Git blob unavailable");
        Ok(out.stdout)
    }

    pub(crate) fn text(&self, root: &Path) -> Result<String> {
        String::from_utf8(self.blob(root)?).context("Git blob is not UTF-8")
    }

    pub(crate) fn same_blob(&self, other: &Self) -> bool {
        self.regular() && other.regular() && self.oid == other.oid
    }
}

/// Parse byte-exact, NUL-delimited output. Unmerged stages stay observable as
/// unavailable evidence and never get picked arbitrarily as the checked file.
fn parse(bytes: &[u8], index: bool) -> Result<Entries> {
    let mut entries = Entries::new();
    anyhow::ensure!(
        bytes.is_empty() || bytes.ends_with(&[0]),
        "incomplete Git inventory"
    );
    for record in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let tab = record
            .iter()
            .position(|b| *b == b'\t')
            .context("invalid Git entry")?;
        let fields: Vec<_> = std::str::from_utf8(&record[..tab])?
            .split_ascii_whitespace()
            .collect();
        let [mode, second, third] = fields.as_slice() else {
            anyhow::bail!("invalid Git metadata");
        };
        let (oid, unresolved) = if index {
            anyhow::ensure!(
                matches!(*third, "0" | "1" | "2" | "3"),
                "invalid Git index stage"
            );
            (*second, *third != "0")
        } else {
            anyhow::ensure!(
                matches!(*second, "blob" | "commit"),
                "unsupported Git object kind"
            );
            (*third, false)
        };
        anyhow::ensure!(
            matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid Git object id"
        );
        // Paths are used for classification and reporting only. The object
        // is addressed by OID, so even a non-UTF-8 ancestor remains visible;
        // an unrelated filename must not invalidate the entire inventory.
        let name_bytes = &record[tab + 1..];
        let utf8_path = std::str::from_utf8(name_bytes).is_ok();
        let name = String::from_utf8_lossy(name_bytes);
        anyhow::ensure!(!name.is_empty(), "empty Git path");
        entries
            .entry(name.to_string())
            .and_modify(|existing| existing.unresolved = true)
            .or_insert_with(|| Entry {
                mode: (*mode).into(),
                oid: oid.into(),
                unresolved,
                utf8_path,
            });
    }
    Ok(entries)
}

pub(crate) fn index(root: &Path) -> Result<Entries> {
    let out = exec::git_bytes(&["ls-files", "--stage", "-z"], root)?;
    anyhow::ensure!(out.success(), "could not list the Git index");
    parse(&out.stdout, true)
}

pub(crate) fn head(root: &Path) -> Result<Entries> {
    let commit = exec::git_raw(&["rev-parse", "--verify", "--quiet", "HEAD"], root)?;
    if commit.exit_code() == Some(1) {
        // Expect this only before the first commit. A detached or otherwise
        // unreadable HEAD must not be treated as an empty snapshot.
        let sym = exec::git_raw(&["symbolic-ref", "--quiet", "HEAD"], root)?;
        anyhow::ensure!(
            sym.success() && sym.stdout.trim().starts_with("refs/heads/"),
            "could not resolve HEAD"
        );
        let reference = sym.stdout.trim();
        let exists = exec::git_raw(&["show-ref", "--verify", "--quiet", reference], root)?;
        anyhow::ensure!(
            exists.exit_code() == Some(1),
            "could not read the HEAD commit"
        );
        return Ok(Entries::new());
    }
    anyhow::ensure!(commit.success(), "could not resolve the HEAD commit");
    let oid = commit.stdout.trim();
    anyhow::ensure!(
        matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid HEAD object id"
    );
    let out = exec::git_bytes(
        &[
            "--no-replace-objects",
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            oid,
        ],
        root,
    )?;
    anyhow::ensure!(out.success(), "could not list the HEAD tree");
    parse(&out.stdout, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nul_delimiters_preserve_spaces_and_unmerged_records_do_not_pass() {
        let oid = "0123456789012345678901234567890123456789";
        let data = format!(
            "100644 {oid} 0\tordinary path\0\
             100644 {oid} 1\tconflict\0\
             100644 {oid} 2\tconflict\0"
        );
        let entries = parse(data.as_bytes(), true).unwrap();
        assert!(entries["ordinary path"].regular());
        assert!(!entries["conflict"].regular());
        assert!(parse(&data.as_bytes()[..data.len() - 1], true).is_err());
        assert!(parse(b"100644 not-an-id 0\tfile\0", true).is_err());
    }

    #[test]
    fn unrelated_non_utf8_filename_does_not_hide_regular_evidence() {
        let oid = "0123456789012345678901234567890123456789";
        let mut data = format!("100644 {oid} 0\t.npmrc\0").into_bytes();
        data.extend_from_slice(format!("100644 {oid} 0\t").as_bytes());
        data.extend_from_slice(b"unrelated-\xff\0");
        let entries = parse(&data, true).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[".npmrc"].regular());
        assert!(!entries["unrelated-�"].may_open_worktree_path());
    }
}
