//! The **local lane**: a scan record produced on a maintainer's workstation and
//! signed with the maintainer's own git signing key.
//!
//! # Why this lane exists
//!
//! The public directory has two repo-observable lanes: `external` (the
//! directory clones a public repo and scans it) and `action` (the repo's own CI
//! runs `sscsb-action` and keyless-signs the record, which ingest verifies
//! against the repo's canonical workflow identity). Neither can see a
//! **local-environment** control — git signing configuration, the installed
//! hooks' behaviour, the package-trust baseline, a locally installed scanner.
//! Those controls score `unverified` and sit outside every denominator, which
//! is why a repository can hold a top grade and still read `provisional`.
//!
//! This module closes that gap without weakening anything.
//!
//! # What a local record proves — exactly
//!
//! A workstation has no OIDC identity, so there is nothing to keyless-sign
//! against. The anchor is instead something the repository already **commits**:
//! `.sscsb/policy/allowed_signers`, generated from `.sscsb/policy/signers.toml`
//! and already the anchor for the `commit-signing` control.
//!
//! The record is signed with the SAME configuration git itself uses —
//! `gpg.format`, `user.signingkey`, `gpg.ssh.program` — so a 1Password- or
//! hardware-backed key signs untouched, exactly as it signs commits. The
//! directory then verifies the detached SSHSIG with `ssh-keygen -Y verify`
//! against `allowed_signers` **fetched from the public repository at the
//! recorded commit** — committed content the submitter does not supply.
//!
//! So a verified local record proves precisely this and nothing more:
//!
//! > a holder of a key this repository commits as an approved signer asserts
//! > this result at commit X.
//!
//! That is attributable and auditable. It is **strictly weaker** than the
//! action lane, which proves the repository's own CI produced the result. It
//! is never presented as equivalent, and the scoring rule below makes the
//! difference structural rather than a matter of wording.
//!
//! # The scoring rule (enforced site-side, stated here so the tool cannot lie)
//!
//! The directory collects a verdict for each control from EVERY evidence
//! source it holds — the newest verified action-lane record, the newest
//! verified local-lane record, and its own external scan. Two sources that
//! disagree on a countable verdict (pass / fail / gap) score the control as a
//! **gap** carrying a contradiction flag; exactly one distinct verdict scores
//! that verdict, whichever lane produced it; no verdict stays `unverified`.
//! A contradiction therefore costs the repository, which is what removes any
//! incentive to submit a flattering local scan.
//!
//! One requirement makes that union safe: **where someone else could have
//! checked, the directory requires that someone else.** Classes A, A' and B
//! are observable from a repository scan, so a maintainer's self-report alone
//! is not countable there — the row stays `unverified` until a CI or external
//! record exists to agree or disagree with it. Class C is not independently
//! observable at all, so there the signed word is the best evidence obtainable
//! and counts on its own.
//!
//! This module therefore does not carry the class map at all: the class of a
//! control is the directory's fail-closed classification, and duplicating it in
//! Rust would only create a second copy to drift. The tool emits every row it
//! verified, honestly, in the directory's own record shape; the directory
//! decides what each row is allowed to count for.
//!
//! # The namespace
//!
//! SSHSIG signatures are namespaced so a signature minted for one protocol
//! cannot be replayed as another. Git signs commits in the `git` namespace;
//! local scan records are signed in [`NAMESPACE`]. `allowed_signers` lines
//! carry an explicit `namespaces="…"` restriction, so a key is only usable
//! here once the repository has committed that permission — one more thing the
//! anchor says out loud rather than by omission.
//!
//! # Only a human may assert a local record
//!
//! The generator ([`crate::hooks::allowed_signers_content_with_agents`]) grants
//! [`NAMESPACE`] to `class = "human"` signers ONLY. `ci` and `ai` keys keep
//! `namespaces="git"` and nothing else.
//!
//! That is not a style preference. A local record is a maintainer's attested
//! word about a machine nobody else can inspect, and it is the one lane whose
//! class-C verdicts count with no independent corroboration. CI does not need
//! it — CI has the action lane, which proves strictly more. And an `ai`-class
//! signer signing one would contradict the load-bearing invariant `crate::signers`
//! states in its own module docs: an ai-class signer never signs. Withholding
//! the namespace makes the refusal STRUCTURAL rather than a rule four programs
//! have to remember: `ssh-keygen -Y verify -n sscsb-scan-record` simply fails
//! against the committed anchor, both here (in [`verify_signature`], before a
//! record is ever submitted) and at the directory's ingest.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::VerifyResult;
use crate::{exec, machine, signing_setup};
use anyhow::{Context as _, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// The SSHSIG namespace local scan records are signed in — contract line
/// `sshsig-namespace`. Deliberately not `git`: a commit signature must never
/// be replayable as a scan record, nor the reverse.
pub const NAMESPACE: &str = "sscsb-scan-record";

/// The one command string, contract line `command`. Printed by this tool, by
/// the directory's provisional listings, and by its issue form.
pub const COMMAND: &str = "sscsb scan --local --submit";

/// Bumped when the `local` block's shape or meaning changes. Independent of
/// the record's `schema_version`, which stays 1: the block is purely additive,
/// and a consumer that does not know it ignores it and reads the same
/// `controls` rows it always read.
pub const RECORD_VERSION: u32 = 1;

/// The directory scan-record schema this record conforms to — contract line
/// `schema-version`. Matches `SCHEMA_VERSION` in the site's `schema.ts`.
pub const SCHEMA_VERSION: u32 = 1;

/// The directory scoring methodology this record was built against — contract
/// line `methodology-version`. Matches `METHODOLOGY_VERSION` in the site's
/// `config.ts`. A record missing it fails the site's `validateScanRecord`.
pub const METHODOLOGY_VERSION: u32 = 1;

/// The **committed** repo-relative path the record lives at — contract line
/// `record-path`. `sscsb init` ignores `.sscsb/out/` and nothing else, so this
/// path is tracked by design: the submission is a pointer, and the directory
/// reads these bytes out of the public repository.
pub const RECORD_PATH: &str = ".sscsb/scan-record.local.json";
/// The committed detached SSHSIG — contract line `signature-path`.
pub const SIGNATURE_PATH: &str = ".sscsb/scan-record.local.json.sig";
/// The committed trust anchor — contract line `anchor-path`.
pub const ANCHOR_PATH: &str = ".sscsb/policy/allowed_signers";

/// Generated output (the submission body). Gitignored by `sscsb init`.
pub const OUT_DIR: &str = ".sscsb/out";
/// `ssh-keygen -Y sign` writes `<file>.sig`; that is the detached signature.
pub const SIG_SUFFIX: &str = ".sig";

/// The repository hosting the directory's submission queue.
pub const DIRECTORY_REPO: &str = "p4gs/p4gs.github.io";
/// The label the local-lane ingest keys on.
pub const SUBMISSION_LABEL: &str = "local-scan-result";
/// GitHub caps an issue body at 65536 characters; stay clear of the edge so a
/// long message list cannot produce a submission that is silently truncated.
pub const MAX_ISSUE_BODY: usize = 60_000;

/// Documentation pointer used in every guard-rail message.
const SIGNING_DOC: &str = "docs/signing.md";
/// Documentation pointer for the lane itself.
const LOCAL_DOC: &str = "docs/local-scan.md";

// ───────────────────────────── allowed_signers ──────────────────────────────

/// One parsed `allowed_signers` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSigner {
    /// The comma-separated principal list, split.
    pub principals: Vec<String>,
    /// `Some(list)` when the line restricts namespaces; `None` when it does
    /// not (OpenSSH then permits every namespace).
    pub namespaces: Option<Vec<String>>,
    /// `"<keytype> <base64>"` — the comparable key identity, comment dropped.
    pub key: String,
}

impl AllowedSigner {
    /// Whether this line permits signing in `namespace`.
    ///
    /// An unrestricted line permits everything, which is OpenSSH's own rule.
    /// A restricted line permits exactly what it lists — `*` wildcards are
    /// deliberately NOT expanded: reading a wildcard as "everything" would let
    /// a line written to scope a key narrowly widen itself here.
    pub fn permits(&self, namespace: &str) -> bool {
        match &self.namespaces {
            None => true,
            Some(list) => list.iter().any(|n| n == namespace),
        }
    }
}

/// Split an `allowed_signers` line into whitespace-separated tokens, treating a
/// double-quoted run as one token.
///
/// The options field is where quoting matters: `namespaces="git,sscsb-scan-record"`
/// is one token whose value contains no space, but `command="a b"` exists in
/// the wider OpenSSH grammar and a naive split would shatter it and shift every
/// subsequent field — including the key. Quotes are consumed, not kept.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut started = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        out.push(cur);
    }
    out
}

/// Whether a token looks like an SSH public-key type.
fn is_key_type(tok: &str) -> bool {
    tok.starts_with("ssh-") || tok.starts_with("ecdsa-") || tok.starts_with("sk-")
}

/// Parse an `allowed_signers` file.
///
/// Unparseable lines are skipped rather than fatal: this file can be hand-
/// edited in a repository we did not generate it in, and one malformed line
/// must not stop us finding the maintainer's real key on the next one. A key
/// that is genuinely absent is reported by the caller with a precise message.
pub fn parse_allowed_signers(text: &str) -> Vec<AllowedSigner> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens = tokenize(line);
        // principals, [options...], keytype, base64, [comment...]
        let Some(key_idx) = tokens.iter().position(|t| is_key_type(t)) else {
            continue;
        };
        if key_idx == 0 || key_idx + 1 >= tokens.len() {
            continue;
        }
        let Some(key) = signing_setup::ssh_public_key_material(&format!(
            "{} {}",
            tokens[key_idx],
            tokens[key_idx + 1]
        )) else {
            continue;
        };
        let principals: Vec<String> = tokens[0]
            .split(',')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        if principals.is_empty() {
            continue;
        }
        let mut namespaces = None;
        for opt in &tokens[1..key_idx] {
            if let Some(value) = opt.strip_prefix("namespaces=") {
                namespaces = Some(
                    value
                        .split(',')
                        .filter(|n| !n.is_empty())
                        .map(str::to_string)
                        .collect(),
                );
            }
        }
        out.push(AllowedSigner {
            principals,
            namespaces,
            key,
        });
    }
    out
}

// ─────────────────────────── signing configuration ──────────────────────────

/// The git signing configuration this run will use, resolved with git's own
/// precedence (system → global → repo → command line).
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// The resolved `user.signingkey` value, exactly as git would read it.
    pub signing_key: String,
    /// `gpg.ssh.program`, or `ssh-keygen` when unset — the same default git uses.
    pub program: String,
    /// `"<keytype> <base64>"` for the key the value resolves to.
    pub key_material: String,
}

/// Read one config key the way git resolves it for THIS repository.
///
/// Deliberately `git config --get`, not `--global`: a repository may set its
/// own signing key, a harness may inject one at command-line scope, and the
/// point of this lane is to sign with whatever key git would sign a commit
/// with right here. Reading only the global scope would sign with a key the
/// user is not actually committing with.
///
/// `Ok(None)` means the key is genuinely **unset**; an error means the config
/// could not be READ at all. Collapsing the two — which `.ok()` on a `Result`
/// does silently — turns a malformed `.gitconfig` into the message "your
/// signing key is unset", and sends someone to configure a key they already
/// have. `git config --get` exits 1 for "no such key" and 128 for a fatal
/// read; only the first is an answer. (`signing_setup::GitValue` draws the
/// same distinction for the same reason.)
fn git_config(ctx: &Ctx, key: &str) -> Result<Option<String>> {
    let out = exec::git_raw(&["config", "--get", key], &ctx.root)
        .with_context(|| format!("could not run `git config --get {key}`"))?;
    match out.exit_code() {
        Some(0) => {
            let value = out.stdout.trim();
            Ok((!value.is_empty()).then(|| value.to_string()))
        }
        // 1 is git's documented "the key is not set".
        Some(1) => Ok(None),
        _ => {
            let why = out.stderr.trim();
            anyhow::bail!(
                "could not read git's `{key}` ({}): {}\n\
                 This is a failure to READ your configuration, not a missing setting — fix the \
                 config git is complaining about and run this again. See {SIGNING_DOC}.",
                out.termination(),
                if why.is_empty() { "no detail" } else { why }
            )
        }
    }
}

/// Resolve the signing configuration, or explain exactly what to set.
///
/// Every failure names the precise `git config` keys and points at
/// [`SIGNING_DOC`]: a maintainer who has never used the directory must be able
/// to act on the message without reading anything else first.
pub fn resolve_signing(ctx: &Ctx, home: &Path) -> Result<SigningConfig> {
    // git's own default for gpg.format is `openpgp`; only `ssh` can be
    // anchored by an allowed_signers file, which is the whole trust model here.
    match git_config(ctx, "gpg.format")?.as_deref() {
        Some("ssh") => {}
        other => {
            anyhow::bail!(
                "local scan records are signed with SSH signatures, but git's `gpg.format` is {}.\n\
                 Set it the way this repository's commit-signing control expects:\n\
                 \x20   git config --global gpg.format ssh\n\
                 \x20   git config --global user.signingkey ~/.ssh/id_ed25519.pub\n\
                 See {SIGNING_DOC}.",
                other.map_or_else(|| "unset (git defaults to `openpgp`)".to_string(), |v| format!("`{v}`"))
            );
        }
    }

    let signing_key = git_config(ctx, "user.signingkey")?.ok_or_else(|| {
        anyhow::anyhow!(
            "no signing key configured — git's `user.signingkey` is unset, so there is nothing \
             to sign this record with.\n\
             \x20   git config --global user.signingkey ~/.ssh/id_ed25519.pub\n\
             \x20   git config --global gpg.format ssh\n\
             The key must be one this repository lists in .sscsb/policy/signers.toml. \
             See {SIGNING_DOC}."
        )
    })?;

    // A path resolver cannot read a key that is not at a path, so the inline
    // spellings git accepts are tried first; only then is the value treated as
    // a filename.
    let key_material = inline_key_material(&signing_key)
        .or_else(|| signing_setup::signing_key_material(&signing_key, home))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "could not read a public key from `user.signingkey` = {signing_key}.\n\
             Expected the public key itself, a file holding it, a `.pub` sibling, or a private \
             key ssh-keygen can derive one from (an encrypted key with no agent loaded cannot be \
             read here).\n\
             See {SIGNING_DOC}."
            )
        })?;

    // Git's documented default when gpg.ssh.program is unset.
    let program = git_config(ctx, "gpg.ssh.program")?.unwrap_or_else(|| "ssh-keygen".to_string());

    Ok(SigningConfig {
        signing_key,
        program,
        key_material,
    })
}

/// The signer this run will attribute the record to.
#[derive(Debug, Clone)]
pub struct ResolvedSigner {
    /// The principal the matching `allowed_signers` line names — the `-I`
    /// argument a verifier must pass, so it travels in the record.
    pub principal: String,
    /// `"<keytype> <base64>"`.
    pub key_material: String,
    /// `SHA256:…`, the fingerprint spelling `ssh-keygen -l` prints.
    pub fingerprint: String,
}

/// The OpenSSH `SHA256:` fingerprint of `"<keytype> <base64>"`.
///
/// Computed directly rather than shelled out to `ssh-keygen -lf`: it is a
/// base64url-unpadded SHA-256 over the raw key blob, it is what every guard
/// rail message quotes back to the user, and a message that explains which key
/// is wrong must not itself depend on a subprocess succeeding.
pub fn fingerprint(key_material: &str) -> Option<String> {
    use base64::Engine;
    use sha2::Digest as _;
    let blob = key_material.split_whitespace().nth(1)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .ok()?;
    let digest = sha2::Sha256::digest(raw);
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

/// Match the configured key against the repository's committed
/// `allowed_signers`, or explain exactly what to add and commit.
pub fn match_allowed_signer(
    allowed: &[AllowedSigner],
    key_material: &str,
    namespace: &str,
) -> Result<ResolvedSigner> {
    let fp = fingerprint(key_material).unwrap_or_else(|| "SHA256:<unreadable>".to_string());
    let matching: Vec<&AllowedSigner> = allowed.iter().filter(|a| a.key == key_material).collect();
    if matching.is_empty() {
        anyhow::bail!(
            "the key git is configured to sign with is NOT an approved signer of this \
             repository.\n\
             \x20   key: {fp}\n\
             A local scan record is only meaningful because the repository itself commits who may \
             assert one. Add this key to .sscsb/policy/signers.toml:\n\n\
             \x20   [[signer]]\n\
             \x20   principal = \"you@example.com\"\n\
             \x20   class = \"human\"\n\
             \x20   ssh_public_key = \"{key_material}\"\n\n\
             then regenerate and COMMIT the anchor:\n\
             \x20   sscsb init\n\
             \x20   git add .sscsb/policy/signers.toml .sscsb/policy/allowed_signers\n\
             \x20   git commit -m 'policy: approve local scan signer'\n\
             See {SIGNING_DOC}."
        );
    }
    // A key permitted for the namespace on ANY line is permitted; the
    // restriction is a property of the grant, not of the file's ordering.
    let permitted = matching.iter().find(|a| a.permits(namespace));
    let Some(entry) = permitted else {
        anyhow::bail!(
            "your signing key is an approved signer, but the committed \
             .sscsb/policy/allowed_signers restricts it to namespaces {:?} — `{namespace}` is not \
             among them, so a verifier would reject this record.\n\
             \x20   key: {fp}\n\
             Two things produce this. Either the anchor predates this lane (it was generated \
             before `{namespace}` existed), or the key is registered under `class = \"ci\"` / \
             `class = \"ai\"` — only `class = \"human\"` signers are granted the scan namespace, \
             because a local record is a MAINTAINER's attested word about a machine nobody else \
             can inspect.\n\
             If the key is yours, confirm its entry in .sscsb/policy/signers.toml reads \
             `class = \"human\"`, then regenerate and COMMIT the anchor:\n\
             \x20   sscsb init\n\
             \x20   git add .sscsb/policy/allowed_signers\n\
             \x20   git commit -m 'policy: permit the sscsb local-scan namespace'\n\
             See {LOCAL_DOC}.",
            matching
                .iter()
                .filter_map(|a| a.namespaces.clone())
                .next()
                .unwrap_or_default()
        );
    };
    Ok(ResolvedSigner {
        // The first principal on the line is the one `%GS` and `-I` resolve to.
        principal: entry.principals[0].clone(),
        key_material: key_material.to_string(),
        fingerprint: fp,
    })
}

// ───────────────────────────── worktree binding ─────────────────────────────

/// A tracked path that differs from HEAD, with its porcelain status code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrackedChange {
    pub status: String,
    pub path: String,
}

/// Tracked changes in `git status --porcelain` output.
///
/// Untracked files (`??`) are deliberately excluded. Build output, an
/// `.sscsb/out/` directory, an editor scratch file — none of them are part of
/// the commit the record binds itself to, and refusing on them would make the
/// command unusable for the exact maintainers it exists to serve.
/// The caller MUST pass git's output untrimmed — see [`read_porcelain`].
pub fn tracked_changes(porcelain: &str) -> Vec<TrackedChange> {
    porcelain
        .lines()
        .filter(|l| l.len() > 3)
        .filter(|l| !l.starts_with("??") && !l.starts_with("!!"))
        .map(|l| {
            // Porcelain v1 is two status COLUMNS, a space, then the path.
            // Either column may itself be a space, so the path is taken by
            // offset and never by splitting on whitespace.
            match l.as_bytes().get(2) {
                Some(b' ') if l.is_char_boundary(3) => TrackedChange {
                    status: l[..2].trim().to_string(),
                    path: l[3..].trim().to_string(),
                },
                // A line that does not have the separator where the format
                // guarantees it is malformed — or arrived trimmed. Keep the
                // whole line rather than dropping the row: a change we cannot
                // parse must still block the record, and a silently discarded
                // row is how a dirty tree would slip past this guard.
                _ => TrackedChange {
                    status: String::new(),
                    path: l.trim().to_string(),
                },
            }
        })
        .collect()
}

/// The tracked changes that actually bind the record, i.e. everything except
/// the lane's OWN two output files.
///
/// [`RECORD_PATH`] and [`SIGNATURE_PATH`] are committed paths, so the moment a
/// maintainer commits the first record every subsequent run rewrites a tracked
/// file and the tree is dirty by the command's own doing. Blocking on that
/// would make the second run of `sscsb scan --local` impossible without a
/// `git stash` of the thing being replaced — a guard rail that fires on
/// nothing but itself.
///
/// Excluding them costs no safety: neither file is input to any control, and
/// neither is read to decide a verdict. Every other tracked change still
/// blocks, which is the property the guard exists for.
pub fn lane_relevant_changes(changes: &[TrackedChange]) -> Vec<TrackedChange> {
    changes
        .iter()
        .filter(|c| c.path != RECORD_PATH && c.path != SIGNATURE_PATH)
        .cloned()
        .collect()
}

/// `git status --porcelain`, byte-preserving.
///
/// [`exec::git`] trims the whole of stdout, which is right for a command whose
/// output is a value and wrong for one whose output is COLUMNS. The first
/// porcelain line of an unstaged modification begins with a space (` M path`);
/// trimming eats it, every subsequent field shifts left by one, and the path
/// silently loses its first character — which for this tool's own
/// `.sscsb/policy/…` files means the leading dot. The record still refuses, so
/// nothing is unsafe; it just names a file that does not exist and sends the
/// maintainer looking for it.
fn read_porcelain(ctx: &Ctx) -> Result<String> {
    let out = exec::git_raw(&["status", "--porcelain"], &ctx.root)
        .context("could not read the working-tree status")?;
    if !out.success() {
        anyhow::bail!(
            "`git status --porcelain` failed ({}): {}",
            out.termination(),
            out.stderr.trim()
        );
    }
    Ok(out.stdout)
}

/// Refuse to record a commit the working tree does not match.
///
/// This is the one guard rail with two defensible answers, and the choice is
/// deliberate: **refuse**, rather than record the dirty state honestly.
///
/// The record's `commit` is not decoration — it is the whole binding. The
/// directory fetches `allowed_signers` from the public repository *at that
/// commit* to check the signature, and the class-C controls this record exists
/// to resolve are read out of the working tree: the git signing configuration,
/// the installed hooks, the package-trust baseline, the local scanner set. If
/// the tree differs from the commit, the record describes files that are not
/// at the commit it names, and no reader can tell which rows are affected.
/// "Recorded honestly as dirty" would put the burden of that analysis on every
/// consumer forever, and the honest label would still sit on rows that are
/// simply wrong. A record that claims a commit it does not match is exactly the
/// failure to avoid, so it is not produced at all. Committing (or stashing) is
/// a one-line fix; a subtly-wrong published record is not.
pub fn require_clean_worktree(changes: &[TrackedChange]) -> Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    let listed: Vec<String> = changes
        .iter()
        .take(20)
        .map(|c| format!("\x20   {:<3} {}", c.status, c.path))
        .collect();
    let more = changes.len().saturating_sub(20);
    anyhow::bail!(
        "the working tree has {} tracked change{} that are not in HEAD:\n{}{}\n\
         A local scan record binds its result to a commit, and the directory verifies it against \
         content committed AT that commit — so a record produced from a tree that differs from \
         HEAD would claim a commit it does not match.\n\
         Commit or stash first:\n\
         \x20   git add -A && git commit\n\
         \x20   # or: git stash\n\
         Untracked files are ignored; only tracked changes block.",
        changes.len(),
        if changes.len() == 1 { "" } else { "s" },
        listed.join("\n"),
        if more > 0 {
            format!("\n\x20   … and {more} more")
        } else {
            String::new()
        }
    );
}

// ──────────────────────────────── the record ────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RecordRepo {
    pub owner: String,
    pub name: String,
    pub url: String,
    pub default_branch: String,
    pub branch: String,
    /// The 40-hex commit this result describes.
    pub commit: String,
}

#[derive(Debug, Serialize)]
pub struct RecordSigner {
    pub principal: String,
    pub key: String,
    pub fingerprint: String,
    /// Basename of `gpg.ssh.program` — enough to tell `ssh-keygen` from
    /// `op-ssh-sign`, without publishing a path from someone's laptop.
    pub program: String,
}

#[derive(Debug, Serialize)]
pub struct RecordAnchor {
    /// Repo-relative path of the committed anchor a verifier must fetch.
    pub path: String,
    /// SHA-256 of the anchor's bytes as they were read here — a drift signal,
    /// never the thing that authorizes anything. The verifier uses the copy it
    /// fetches from the repository, not this digest.
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RecordWorktree {
    pub clean: bool,
    pub tracked_changes: Vec<TrackedChange>,
}

/// The `local` block added to the verify document. Additive: a consumer that
/// does not know it reads the same `results` rows it always read.
#[derive(Debug, Serialize)]
pub struct LocalBlock {
    pub record_version: u32,
    /// Always `"local"` — the lane the directory's trust sidecar records.
    pub lane: &'static str,
    /// The SSHSIG namespace the detached signature was minted in.
    pub namespace: &'static str,
    pub generated_at: String,
    pub sscsb_version: &'static str,
    pub repo: RecordRepo,
    pub worktree: RecordWorktree,
    pub signer: RecordSigner,
    pub allowed_signers: RecordAnchor,
}

/// Everything the command resolved before it signed anything.
#[derive(Debug)]
pub struct Prepared {
    pub block: LocalBlock,
    pub signing: SigningConfig,
    pub slug: String,
    pub anchor_path: PathBuf,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Run every guard rail and assemble the `local` block. Nothing is written and
/// nothing is signed until this returns `Ok`.
pub fn prepare(ctx: &Ctx, home: &Path) -> Result<Prepared> {
    let signing = resolve_signing(ctx, home)?;

    let anchor_path = ctx.root.join(ANCHOR_PATH);
    let anchor = std::fs::read_to_string(&anchor_path).map_err(|e| {
        anyhow::anyhow!(
            "cannot read the approved-signer anchor at .sscsb/policy/allowed_signers ({e}).\n\
             That file IS the trust anchor for a local record — the directory fetches it from your \
             public repository at the recorded commit to check the signature. Generate it and \
             commit it:\n\
             \x20   sscsb init\n\
             \x20   git add .sscsb/policy/allowed_signers\n\
             \x20   git commit -m 'policy: commit the approved-signer anchor'\n\
             See {SIGNING_DOC}."
        )
    })?;
    let signer = match_allowed_signer(
        &parse_allowed_signers(&anchor),
        &signing.key_material,
        NAMESPACE,
    )?;

    let changes = lane_relevant_changes(&tracked_changes(&read_porcelain(ctx)?));
    require_clean_worktree(&changes)?;

    let commit = exec::git(&["rev-parse", "HEAD"], &ctx.root).context(
        "could not resolve HEAD — a local scan record must name the commit it describes",
    )?;
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("HEAD did not resolve to a 40-character commit id (got `{commit}`)");
    }

    let slug = ctx.origin_slug().ok_or_else(|| {
        anyhow::anyhow!(
            "no `origin` remote — the directory identifies a repository by its GitHub slug, and \
             verifies a local record against content committed in that public repository.\n\
             \x20   git remote add origin https://github.com/owner/repo"
        )
    })?;
    let (owner, name) = slug
        .split_once('/')
        .context("origin remote did not parse as owner/repo")?;

    let block = LocalBlock {
        record_version: RECORD_VERSION,
        lane: "local",
        namespace: NAMESPACE,
        generated_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        sscsb_version: env!("CARGO_PKG_VERSION"),
        repo: RecordRepo {
            owner: owner.to_string(),
            name: name.to_string(),
            url: format!("https://github.com/{slug}"),
            default_branch: ctx.default_branch(),
            branch: ctx.current_branch().unwrap_or_default(),
            commit,
        },
        worktree: RecordWorktree {
            clean: true,
            tracked_changes: Vec::new(),
        },
        signer: RecordSigner {
            principal: signer.principal,
            key: signer.key_material,
            fingerprint: signer.fingerprint,
            program: Path::new(&signing.program)
                .file_name()
                .map_or_else(|| signing.program.clone(), |s| s.to_string_lossy().into()),
        },
        allowed_signers: RecordAnchor {
            path: ".sscsb/policy/allowed_signers".to_string(),
            sha256: sha256_hex(anchor.as_bytes()),
        },
    };
    Ok(Prepared {
        block,
        signing,
        slug,
        anchor_path,
    })
}

// ──────────────────────────────── signing ───────────────────────────────────

/// Where the record and signature landed.
#[derive(Debug)]
pub struct SignedRecord {
    pub record_path: PathBuf,
    pub signature_path: PathBuf,
    pub record: String,
    pub signature: String,
}

/// The key file `ssh-keygen -Y sign -f` is handed.
///
/// `user.signingkey` may hold the key material inline (git's `key::ssh-ed25519 …`
/// spelling), which is not a path at all. Materialising it into a temp file
/// keeps the signing call one shape, and the private half still comes from the
/// agent exactly as it does for a commit.
fn key_file_for(signing: &SigningConfig, home: &Path, out_dir: &Path) -> Result<(PathBuf, bool)> {
    if inline_key_material(&signing.signing_key).is_some() {
        let path = out_dir.join("scan-local-signing-key.pub");
        // The RESOLVED material, not the raw value: writing `key::ssh-ed25519 …`
        // verbatim would hand the signer a file it cannot parse.
        std::fs::write(&path, format!("{}\n", signing.key_material))?;
        return Ok((path, true));
    }
    Ok((
        signing_setup::expand_home(&signing.signing_key, home),
        false,
    ))
}

/// The key material when `user.signingkey` holds the KEY rather than a path.
///
/// Git accepts the literal key under a `key::` prefix, and accepts a bare
/// `ssh-ed25519 AAAA…` line too. Neither is a filename, so a path resolver
/// reports a perfectly working configuration as unreadable — and then tells
/// the user to fix something that was never broken.
fn inline_key_material(raw: &str) -> Option<String> {
    signing_setup::ssh_public_key_material(raw.strip_prefix("key::").unwrap_or(raw))
}

/// Every path a signer program might have written the detached signature to,
/// canonical name first.
///
/// `ssh-keygen -Y sign` APPENDS `.sig` to the file it signed, giving
/// `scan-record.local.json.sig`. 1Password's `op-ssh-sign` REPLACES the
/// extension instead, giving `scan-record.local.sig`. Git never sees the divergence because it
/// signs a temporary buffer with no extension at all, where both rules produce
/// the same name — which is exactly how a drop-in signer can ship this
/// difference and have nobody notice for years.
///
/// The lane cannot inherit that ambiguity: the published signature has one
/// name, and a maintainer whose 1Password key works for commits must not be
/// told their signer is broken. So both are accepted and the result is moved to
/// the canonical name. Found by running the real 1Password signer, not by
/// reading its documentation.
fn signature_candidates(record_path: &Path) -> Vec<PathBuf> {
    let mut appended = record_path.as_os_str().to_os_string();
    appended.push(SIG_SUFFIX);
    let mut out = vec![PathBuf::from(appended)];
    // `set_extension` replaces `.json` with `.sig`; it is a no-op-shaped
    // duplicate when the record name has no extension, hence the dedupe.
    let mut replaced = record_path.to_path_buf();
    if replaced.set_extension(SIG_SUFFIX.trim_start_matches('.')) && !out.contains(&replaced) {
        out.push(replaced);
    }
    out
}

/// Write the record and produce a detached SSHSIG beside it.
///
/// Signing goes through `gpg.ssh.program` — the same binary git hands a commit
/// to — so a 1Password or hardware-backed key signs with no extra setup and no
/// key material ever passing through this process. Verification always goes
/// through plain `ssh-keygen`, because signer shims implement `-Y sign` and
/// need not implement `-Y verify`.
pub fn sign_record(
    ctx: &Ctx,
    cfg: &Config,
    prepared: &Prepared,
    results: &[VerifyResult],
    home: &Path,
) -> Result<SignedRecord> {
    let out_dir = ctx.root.join(OUT_DIR);
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let record_path = ctx.root.join(RECORD_PATH);
    let signature_path = ctx.root.join(SIGNATURE_PATH);
    if let Some(parent) = record_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    // The clean-tree check ran BEFORE the controls did, so that a maintainer
    // whose key is not in the anchor learns it in a second rather than after a
    // full scan. That leaves a window: verification runs 44 controls, some of
    // which regenerate policy files (`allowed_signers` is generated from
    // `signers.toml`, and other code paths rewrite it), and an editor can save
    // at any moment. Either would leave the record claiming `clean: true` for a
    // commit the tree no longer matches — the exact state this lane refuses to
    // publish. So the question is asked again, immediately before signing.
    let after = lane_relevant_changes(&tracked_changes(&read_porcelain(ctx)?));
    if !after.is_empty() {
        return Err(require_clean_worktree(&after).unwrap_err().context(
            "the working tree changed while the controls ran, so the record would no longer \
             describe the commit it names",
        ));
    }

    let record = machine::local_record_json(cfg, results, &prepared.block)?;
    std::fs::write(&record_path, &record)
        .with_context(|| format!("writing {}", record_path.display()))?;
    // A stale signature from an earlier run must never be mistaken for this
    // one's if signing fails part-way — at EITHER name a signer might use.
    for candidate in signature_candidates(&record_path) {
        let _ = std::fs::remove_file(candidate);
    }

    let (key_file, temporary) = key_file_for(&prepared.signing, home, &out_dir)?;
    let out = exec::run(
        &prepared.signing.program,
        &[
            "-Y",
            "sign",
            "-n",
            NAMESPACE,
            "-f",
            key_file.to_str().context("signing key path is not UTF-8")?,
            record_path.to_str().context("record path is not UTF-8")?,
        ],
        Some(&ctx.root),
    )
    .with_context(|| {
        format!(
            "could not run the configured signer `{}` (git's gpg.ssh.program). \
             See {SIGNING_DOC}.",
            prepared.signing.program
        )
    })?;
    if temporary {
        let _ = std::fs::remove_file(&key_file);
    }
    if !out.success() {
        anyhow::bail!(
            "signing the record failed ({}): {}\n\
             This is the same signer git uses for your commits (`{}` with `user.signingkey` = {}). \
             If your key lives in an agent — 1Password, a Secure Enclave, a YubiKey — make sure it \
             is unlocked and the agent is reachable, then run this again. See {SIGNING_DOC}.",
            out.termination(),
            out.stderr.trim(),
            prepared.signing.program,
            prepared.signing.signing_key
        );
    }
    let candidates = signature_candidates(&record_path);
    let written = candidates.iter().find(|p| p.is_file()).ok_or_else(|| {
        anyhow::anyhow!(
            "the signer `{}` reported success but wrote no signature (looked at {}). \
             See {SIGNING_DOC}.",
            prepared.signing.program,
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    if written != &signature_path {
        std::fs::rename(written, &signature_path).with_context(|| {
            format!(
                "moving the signature from {} to {}",
                written.display(),
                signature_path.display()
            )
        })?;
    }
    let signature = std::fs::read_to_string(&signature_path)
        .with_context(|| format!("reading {}", signature_path.display()))?;

    Ok(SignedRecord {
        record_path,
        signature_path,
        record,
        signature,
    })
}

/// Re-verify the freshly written signature the way the directory will.
///
/// Signing that "succeeded" and a signature that VERIFIES are different claims,
/// and only the second one is worth submitting. Checking it here — with plain
/// `ssh-keygen`, against the committed anchor, in the record's namespace, under
/// the principal the record names — turns a whole class of silent breakage
/// (wrong namespace grant, an anchor that does not carry this key, a signer
/// shim writing a malformed blob) into a local error instead of a rejected
/// submission.
pub fn verify_signature(ctx: &Ctx, prepared: &Prepared, signed: &SignedRecord) -> Result<String> {
    let out = exec::run_with_stdin(
        "ssh-keygen",
        &[
            "-Y",
            "verify",
            "-f",
            prepared
                .anchor_path
                .to_str()
                .context("anchor path is not UTF-8")?,
            "-I",
            &prepared.block.signer.principal,
            "-n",
            NAMESPACE,
            "-s",
            signed
                .signature_path
                .to_str()
                .context("signature path is not UTF-8")?,
        ],
        Some(&ctx.root),
        Some(signed.record.as_bytes()),
    )
    .context("could not run `ssh-keygen -Y verify` to check the signature we just made")?;
    if !out.success() {
        anyhow::bail!(
            "the record was signed, but the signature does NOT verify against the committed \
             anchor ({}): {}\n\
             The directory runs exactly this check, so this record would be rejected. Confirm \
             .sscsb/policy/allowed_signers lists `{}` for namespace `{NAMESPACE}` and is committed. \
             See {LOCAL_DOC}.",
            out.termination(),
            out.stderr.trim(),
            prepared.block.signer.fingerprint
        );
    }
    Ok(out.stdout.trim().to_string())
}

// ─────────────────────────────── submission ─────────────────────────────────

/// The issue body the local lane's intake reads.
///
/// **A pointer, not a payload.** The record and its signature are COMMITTED
/// files (contract lines `record-path` / `signature-path`), so the directory
/// reads them — and the trust anchor — out of the public repository itself.
/// Nothing typed into an issue reaches the bytes that are verified, which is
/// why the body carries only the repository URL the directory's
/// `parse-request.ts` extracts, plus context for the human reading the thread.
///
/// Inlining the record instead would invent a second copy of the signed bytes
/// whose agreement with the committed ones nobody checks, and would put the
/// submission a few hundred controls away from GitHub's issue-body cap.
pub fn submission_body(prepared: &Prepared, signed: &SignedRecord) -> String {
    let b = &prepared.block;
    format!(
        "### Repository URL\n\n{url}\n\n\
         ### Record commit\n\n{commit}\n\n\
         ### Signer principal\n\n{principal}\n\n\
         ### Signer key fingerprint\n\n{fingerprint}\n\n\
         ---\n\n\
         `{command}` produced a signed local scan record. Both files are committed on the \
         default branch, and this submission is a pointer to them:\n\n\
         - `{record_path}` — the signed bytes\n\
         - `{signature_path}` — the detached SSHSIG, namespace `{namespace}`\n\
         - `{anchor_path}` — the trust anchor, at commit `{commit}`\n\n\
         Verify it yourself, exactly as the directory does:\n\n\
         ```sh\n\
         gh api -H 'Accept: application/vnd.github.raw' \\\n\
         \x20 'repos/{owner}/{name}/contents/{anchor_path}?ref={commit}' \\\n\
         \x20 > allowed_signers\n\
         ssh-keygen -Y verify -f allowed_signers -I {principal} \\\n\
         \x20 -n {namespace} -s {signature_path} < {record_path}\n\
         ```\n\n\
         A verified local record proves that a holder of a key this repository commits as an \
         approved signer asserted this result at the recorded commit. It does **not** prove the \
         repository's own CI produced it — only the `action` lane does that. Where a repository \
         scan could observe a control, the directory requires an independent record to agree \
         with this one before the row counts; where it could not (the local-environment \
         controls), this record stands on its own. Two sources that disagree score the control \
         as a gap.\n\n\
         Record digest (sha256): `{digest}`\n",
        url = b.repo.url,
        commit = b.repo.commit,
        principal = b.signer.principal,
        fingerprint = b.signer.fingerprint,
        command = COMMAND,
        namespace = NAMESPACE,
        record_path = RECORD_PATH,
        signature_path = SIGNATURE_PATH,
        anchor_path = ANCHOR_PATH,
        owner = b.repo.owner,
        name = b.repo.name,
        digest = sha256_hex(signed.record.as_bytes()),
    )
}

/// Reject a submission that GitHub would truncate.
///
/// The body is a pointer now, so this can only fire on a pathological slug —
/// but the cap stays enforced rather than assumed, because a truncated body is
/// the worst outcome available: the request parses, the repository resolves to
/// something else, and the maintainer is told their key is wrong.
pub fn check_body_size(body: &str) -> Result<()> {
    if body.len() > MAX_ISSUE_BODY {
        anyhow::bail!(
            "the submission is {} bytes, over the {MAX_ISSUE_BODY}-byte cap GitHub issue bodies \
             leave room for. The record is at {RECORD_PATH} with its signature at \
             {SIGNATURE_PATH} — open an issue at https://github.com/{DIRECTORY_REPO}/issues and \
             link them. See {LOCAL_DOC}.",
            body.len()
        );
    }
    Ok(())
}

/// The `gh issue create` invocation used for a submission, as an argv.
pub fn submit_args<'a>(title: &'a str, body_file: &'a str) -> Vec<&'a str> {
    vec![
        "issue",
        "create",
        "--repo",
        DIRECTORY_REPO,
        "--title",
        title,
        "--label",
        SUBMISSION_LABEL,
        "--body-file",
        body_file,
    ]
}

/// Title for a submission issue, matching the existing `[action-scan] ` shape.
pub fn submission_title(slug: &str) -> String {
    format!("[local-scan] {slug}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two real, throwaway ed25519 keys generated with `ssh-keygen -t ed25519`.
    // Real keys matter here: the fingerprint function base64-decodes the blob,
    // so a hand-typed placeholder would exercise the None path while looking
    // like it exercised the happy one. The expected fingerprints below are the
    // literal output of `ssh-keygen -lf` on the same keys — this is the
    // cross-check that our own SHA-256 computation agrees with OpenSSH.
    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHI2bJBVVxHqDFleQZ8ljRSzTH7upk8k+I64OEtqmqCg";
    const FP_A: &str = "SHA256:qjuRMellGo3xOSYvEr9xWhnj3DkIHOSHaCuRzi+gPuw";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGL8dm+TodUhh3EK2CfuYUgrH/Ne4LaX3+q6kD8+JQ6";
    const FP_B: &str = "SHA256:W8wnMs8okk6fi1A03OMIH6zimU5w+OIO+wokT5ERiiM";

    fn signers(lines: &str) -> Vec<AllowedSigner> {
        parse_allowed_signers(lines)
    }

    #[test]
    fn parses_a_generated_anchor_line_with_its_namespace_grant() {
        let parsed = signers(&format!(
            "# Generated by sscsb\nyou@example.com namespaces=\"git,{NAMESPACE}\" {KEY_A} a comment\n"
        ));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].principals, vec!["you@example.com"]);
        assert_eq!(
            parsed[0].namespaces.as_deref(),
            Some(["git".to_string(), NAMESPACE.to_string()].as_slice())
        );
        assert_eq!(parsed[0].key, KEY_A);
        assert!(parsed[0].permits(NAMESPACE));
        assert!(parsed[0].permits("git"));
    }

    #[test]
    fn a_line_with_no_namespace_option_permits_every_namespace() {
        let parsed = signers(&format!("you@example.com {KEY_A}\n"));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].namespaces, None);
        assert!(parsed[0].permits(NAMESPACE));
    }

    #[test]
    fn a_namespace_restriction_that_omits_ours_does_not_permit_it() {
        let parsed = signers(&format!("you@example.com namespaces=\"git\" {KEY_A}\n"));
        assert!(parsed[0].permits("git"));
        assert!(!parsed[0].permits(NAMESPACE));
    }

    #[test]
    fn a_wildcard_namespace_is_not_read_as_permission() {
        // Refusing to expand `*` keeps a narrowly-scoped grant narrow; the
        // maintainer is told to grant the namespace explicitly instead.
        let parsed = signers(&format!("you@example.com namespaces=\"*\" {KEY_A}\n"));
        assert!(!parsed[0].permits(NAMESPACE));
    }

    #[test]
    fn multiple_principals_on_one_line_split_and_the_first_is_used() {
        let parsed = signers(&format!(
            "a@x.test,b@x.test namespaces=\"{NAMESPACE}\" {KEY_A}\n"
        ));
        assert_eq!(parsed[0].principals, vec!["a@x.test", "b@x.test"]);
        let resolved = match_allowed_signer(&parsed, KEY_A, NAMESPACE).unwrap();
        assert_eq!(resolved.principal, "a@x.test");
    }

    #[test]
    fn comments_blanks_and_malformed_lines_are_skipped_without_losing_the_real_key() {
        let text = format!(
            "# comment\n\n\
             not-a-key-line\n\
             onlyprincipal\n\
             {KEY_A}\n\
             you@example.com namespaces=\"{NAMESPACE}\" {KEY_A} trailing comment\n"
        );
        let parsed = signers(&text);
        // The bare-key line has no principal field, so it cannot be trusted as
        // a grant; only the well-formed line survives.
        assert_eq!(parsed.len(), 1, "parsed: {parsed:?}");
        assert_eq!(parsed[0].principals, vec!["you@example.com"]);
    }

    #[test]
    fn lines_that_look_like_a_grant_but_are_not_one_are_skipped() {
        // Each of these would, if accepted, put a key or a principal into the
        // anchor that the file does not actually grant — the one thing this
        // parser must never do.
        let cases = [
            // A key type with no base64 body after it.
            format!("you@example.com namespaces=\"{NAMESPACE}\" ssh-ed25519"),
            // A key type whose body is not decodable base64.
            format!("you@example.com namespaces=\"{NAMESPACE}\" ssh-ed25519 not!base64!"),
            // An empty principals field: commas only, so no principal at all.
            format!(",, namespaces=\"{NAMESPACE}\" {KEY_A}"),
        ];
        for case in cases {
            assert!(
                parse_allowed_signers(&case).is_empty(),
                "must not parse as a grant: {case}"
            );
        }
    }

    #[test]
    fn a_quoted_option_value_containing_a_space_does_not_shift_the_key_field() {
        let parsed = signers(&format!(
            "you@example.com command=\"echo hi\",namespaces=\"{NAMESPACE}\" {KEY_A}\n"
        ));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].key, KEY_A);
    }

    #[test]
    fn matching_a_key_absent_from_the_anchor_names_the_key_and_the_files_to_commit() {
        let parsed = signers(&format!(
            "you@example.com namespaces=\"{NAMESPACE}\" {KEY_B}\n"
        ));
        let err = match_allowed_signer(&parsed, KEY_A, NAMESPACE)
            .unwrap_err()
            .to_string();
        assert!(err.contains("NOT an approved signer"), "{err}");
        assert!(err.contains("signers.toml"), "{err}");
        assert!(err.contains("sscsb init"), "{err}");
        assert!(err.contains(&fingerprint(KEY_A).unwrap()), "{err}");
    }

    #[test]
    fn matching_a_key_without_the_namespace_grant_says_so_and_how_to_fix_it() {
        let parsed = signers(&format!("you@example.com namespaces=\"git\" {KEY_A}\n"));
        let err = match_allowed_signer(&parsed, KEY_A, NAMESPACE)
            .unwrap_err()
            .to_string();
        assert!(err.contains("restricts it to namespaces"), "{err}");
        assert!(err.contains("sscsb init"), "{err}");
        assert!(!err.contains("NOT an approved signer"), "{err}");
    }

    #[test]
    fn a_second_line_can_carry_the_namespace_grant_the_first_line_lacks() {
        let parsed = signers(&format!(
            "you@example.com namespaces=\"git\" {KEY_A}\n\
             scans@example.com namespaces=\"{NAMESPACE}\" {KEY_A}\n"
        ));
        let resolved = match_allowed_signer(&parsed, KEY_A, NAMESPACE).unwrap();
        assert_eq!(resolved.principal, "scans@example.com");
    }

    #[test]
    fn fingerprint_matches_the_openssh_spelling() {
        // Byte-for-byte what `ssh-keygen -lf` prints for these two keys: the
        // fingerprint is what every guard-rail message quotes back, so a
        // maintainer must be able to match it against their own `ssh-keygen`
        // and `ssh-add -l` output without translation.
        assert_eq!(fingerprint(KEY_A).as_deref(), Some(FP_A));
        assert_eq!(fingerprint(KEY_B).as_deref(), Some(FP_B));
        // Unpadded base64 — a trailing `=` would be a different string from
        // the one OpenSSH shows, and the comparison a user makes is textual.
        assert!(!FP_A.ends_with('='));
        // The comment is not part of the identity: the same key under a
        // different comment must fingerprint identically, or a key would stop
        // matching its anchor line the moment someone re-exported it.
        assert_eq!(
            fingerprint(&format!("{KEY_A} someone@elsewhere")).as_deref(),
            Some(FP_A)
        );
    }

    #[test]
    fn fingerprint_rejects_material_that_is_not_a_key() {
        assert_eq!(fingerprint("ssh-ed25519"), None);
        assert_eq!(fingerprint("ssh-ed25519 not!base64!"), None);
    }

    #[test]
    fn tracked_changes_ignores_untracked_and_keeps_status_and_path() {
        let changes = tracked_changes(
            " M src/lib.rs\n\
             A  src/new.rs\n\
             ?? target/junk\n\
             !! ignored.txt\n\
             D  gone.rs\n",
        );
        assert_eq!(
            changes,
            vec![
                TrackedChange {
                    status: "M".into(),
                    path: "src/lib.rs".into()
                },
                TrackedChange {
                    status: "A".into(),
                    path: "src/new.rs".into()
                },
                TrackedChange {
                    status: "D".into(),
                    path: "gone.rs".into()
                },
            ]
        );
    }

    #[test]
    fn an_unstaged_modification_keeps_its_leading_dot() {
        // The first porcelain line of an unstaged modification starts with a
        // space. Trim the output and every field shifts left by one: the path
        // loses its first character, which for this tool's own files is the
        // leading dot of `.sscsb/…`. Caught by running the real command.
        let changes = tracked_changes(" M .sscsb/policy/allowed_signers\n M README.md\n");
        assert_eq!(
            changes,
            vec![
                TrackedChange {
                    status: "M".into(),
                    path: ".sscsb/policy/allowed_signers".into()
                },
                TrackedChange {
                    status: "M".into(),
                    path: "README.md".into()
                },
            ]
        );
    }

    #[test]
    fn a_line_missing_the_separator_is_kept_whole_rather_than_dropped() {
        // Fail-safe direction: an unparseable row must still block the record.
        // Dropping it is how a dirty tree would slip past this guard entirely.
        let changes = tracked_changes("M .sscsb/policy/allowed_signers\n");
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].status, "");
        assert_eq!(changes[0].path, "M .sscsb/policy/allowed_signers");
        assert!(require_clean_worktree(&changes).is_err());
    }

    #[test]
    fn a_clean_tree_passes_and_a_dirty_one_refuses_naming_the_paths() {
        require_clean_worktree(&[]).unwrap();
        let err = require_clean_worktree(&tracked_changes(" M src/lib.rs\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("src/lib.rs"), "{err}");
        assert!(err.contains("git stash"), "{err}");
        assert!(err.contains("Untracked files are ignored"), "{err}");
    }

    #[test]
    fn the_dirty_tree_message_truncates_a_long_list_and_says_how_many_remain() {
        let porcelain: String = (0..25).map(|i| format!(" M f{i}.rs\n")).collect();
        let err = require_clean_worktree(&tracked_changes(&porcelain))
            .unwrap_err()
            .to_string();
        assert!(err.contains("25 tracked changes"), "{err}");
        assert!(err.contains("and 5 more"), "{err}");
    }

    #[test]
    fn body_size_guard_accepts_a_normal_record_and_refuses_an_oversized_one() {
        check_body_size("small").unwrap();
        let err = check_body_size(&"x".repeat(MAX_ISSUE_BODY + 1))
            .unwrap_err()
            .to_string();
        assert!(err.contains("over the"), "{err}");
        assert!(err.contains(RECORD_PATH), "{err}");
    }

    #[test]
    fn submission_title_and_args_target_the_local_lane() {
        assert_eq!(submission_title("o/r"), "[local-scan] o/r");
        let args = submit_args("[local-scan] o/r", "body.md");
        assert!(args.contains(&SUBMISSION_LABEL));
        assert!(args.contains(&DIRECTORY_REPO));
        assert!(args.contains(&"--body-file"));
    }

    // ─────────────────── end-to-end against real git + ssh ───────────────────
    //
    // These drive the real `git` and `ssh-keygen` binaries, because the thing
    // under test IS the interoperability: a record this tool signs must verify
    // under the same `ssh-keygen -Y verify` the directory runs, against the
    // anchor this repository generates. A mocked signer would prove nothing
    // about that, which is the only claim the lane makes.
    //
    // Each fixture makes git hermetic itself (`GIT_CONFIG_COUNT=0`, no global
    // or system config) rather than relying on the caller's invocation, so an
    // agent harness that injects a signing key at command-line scope cannot
    // sign the fixture's commits with the human's key and make these read as
    // regressions.

    use crate::controls::Outcome;
    use crate::testutil::EnvLock;

    struct Fixture {
        _repo: tempfile::TempDir,
        _home: tempfile::TempDir,
        ctx: Ctx,
        cfg: Config,
        home: PathBuf,
        /// Public-key path of the signer the repo approves.
        approved_pub: PathBuf,
        /// `"<keytype> <base64>"` of that key.
        approved_material: String,
    }

    /// Generate a throwaway ed25519 keypair; returns (private path, material).
    fn keypair(dir: &Path, name: &str) -> (PathBuf, String) {
        let path = dir.join(name);
        let out = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                &format!("{name}@example.test"),
                "-f",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("ssh-keygen must be installed to test the signing lane");
        assert!(out.status.success(), "ssh-keygen: {out:?}");
        let pub_text = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        let material = signing_setup::ssh_public_key_material(&pub_text).unwrap();
        (path, material)
    }

    fn git(root: &Path, args: &[&str]) {
        exec::git(args, root).unwrap_or_else(|e| panic!("git {args:?}: {e}"));
    }

    /// A bootstrapped repo whose committed anchor approves one generated key,
    /// with git configured to sign with it. HEAD is a real commit; the tree is
    /// clean.
    fn signing_repo(lock: &EnvLock) -> Fixture {
        lock.set(&[
            ("GIT_CONFIG_COUNT", Some("0")),
            ("GIT_CONFIG_GLOBAL", Some("/dev/null")),
            ("GIT_CONFIG_SYSTEM", Some("/dev/null")),
        ]);
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let root = repo.path().to_path_buf();
        git(&root, &["init", "-b", "main"]);
        git(&root, &["config", "user.name", "SSCSB Test"]);
        git(&root, &["config", "user.email", "signer@example.test"]);
        git(&root, &["config", "commit.gpgsign", "false"]);
        git(
            &root,
            &["remote", "add", "origin", "https://github.com/o/r.git"],
        );
        crate::init::bootstrap(&root).expect("bootstrap");

        // The key lives outside the repo — a signing key committed alongside
        // the thing it signs is not a fixture, it is a finding.
        let (priv_path, material) = keypair(home.path(), "signer");
        std::fs::write(
            root.join(".sscsb/policy/signers.toml"),
            format!(
                "[[signer]]\nprincipal = \"signer@example.test\"\nclass = \"human\"\n\
                 ssh_public_key = \"{material} signer@example.test\"\n"
            ),
        )
        .unwrap();
        let ctx = Ctx::discover(&root).unwrap();
        crate::hooks::regenerate_allowed_signers(&ctx, false).unwrap();

        let approved_pub = priv_path.with_extension("pub");
        git(&root, &["config", "gpg.format", "ssh"]);
        git(
            &root,
            &["config", "user.signingkey", approved_pub.to_str().unwrap()],
        );
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-m", "bootstrap"]);

        let ctx = Ctx::discover(&root).unwrap();
        let cfg = Config::load(&root)
            .unwrap()
            .expect("bootstrap writes a config");
        let home_path = home.path().to_path_buf();
        Fixture {
            _repo: repo,
            cfg,
            _home: home,
            ctx,
            home: home_path,
            approved_pub,
            approved_material: material,
        }
    }

    fn sample_results() -> Vec<VerifyResult> {
        vec![
            VerifyResult::new("secrets", Outcome::Pass, vec!["trufflehog: ok".into()]),
            VerifyResult::new(
                "commit-signing",
                Outcome::Pass,
                vec!["signing policy satisfied".into()],
            ),
        ]
    }

    #[test]
    fn a_signed_record_verifies_under_the_same_check_the_directory_runs() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let prepared = prepare(&f.ctx, &f.home).expect("prepare");
            let signed =
                sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home).expect("sign");
            verify_signature(&f.ctx, &prepared, &signed).expect("verify");

            assert!(signed.record_path.exists());
            assert!(signed.signature_path.exists());
            assert!(
                signed
                    .signature
                    .starts_with("-----BEGIN SSH SIGNATURE-----"),
                "detached SSHSIG expected: {}",
                signed.signature
            );

            let doc: serde_json::Value = serde_json::from_str(&signed.record).unwrap();
            // The signed bytes are a directory ScanRecord — contract line
            // `record-shape`. If this drifts, the directory's validator
            // rejects everything this lane produces.
            assert_eq!(doc["schema_version"], SCHEMA_VERSION);
            assert_eq!(doc["methodology_version"], METHODOLOGY_VERSION);
            assert_eq!(doc["controls"][0]["id"], "secrets");
            assert_eq!(doc["controls"][0]["scan_outcome"], "pass");
            assert_eq!(doc["repo"]["owner"], "o");
            assert_eq!(doc["score"]["phases"].as_array().unwrap().len(), 5);
            // The record and its signature are COMMITTED paths, not gitignored
            // output — contract lines `record-path` / `signature-path`.
            assert_eq!(signed.record_path, f.ctx.root.join(RECORD_PATH));
            assert_eq!(signed.signature_path, f.ctx.root.join(SIGNATURE_PATH));
            for path in [RECORD_PATH, SIGNATURE_PATH] {
                let out = exec::git_raw(&["check-ignore", "-q", "--no-index", path], &f.ctx.root)
                    .unwrap();
                assert_eq!(
                    out.status, 1,
                    "{path} must NOT be gitignored — the submission is a pointer to it"
                );
            }
            let local = &doc["local"];
            assert_eq!(local["lane"], "local");
            assert_eq!(local["namespace"], NAMESPACE);
            assert_eq!(local["record_version"], RECORD_VERSION);
            assert_eq!(local["repo"]["owner"], "o");
            assert_eq!(local["repo"]["name"], "r");
            assert_eq!(local["repo"]["url"], "https://github.com/o/r");
            assert_eq!(local["signer"]["principal"], "signer@example.test");
            assert_eq!(
                local["signer"]["fingerprint"],
                fingerprint(&f.approved_material).unwrap()
            );
            assert_eq!(local["worktree"]["clean"], true);
            assert_eq!(
                local["allowed_signers"]["path"],
                ".sscsb/policy/allowed_signers"
            );
            let commit = local["repo"]["commit"].as_str().unwrap();
            assert_eq!(commit.len(), 40);
            assert!(commit.chars().all(|c| c.is_ascii_hexdigit()));
        });
    }

    #[test]
    fn a_tree_that_goes_dirty_while_the_controls_run_is_caught_before_signing() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let prepared = prepare(&f.ctx, &f.home).expect("clean at prepare time");
            // Stand-in for what really happens: a control regenerating a policy
            // file, or an editor saving, between the check and the signature.
            std::fs::write(f.ctx.root.join(".sscsb/policy/signers.toml"), "# touched\n").unwrap();

            let err = sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home)
                .unwrap_err()
                .to_string();
            assert!(err.contains("changed while the controls ran"), "{err}");
            assert!(
                !f.ctx.root.join(SIGNATURE_PATH).exists(),
                "no signature may exist for a record that was refused"
            );
        });
    }

    #[test]
    fn one_flipped_byte_in_the_record_breaks_the_signature() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let mut signed =
                sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home).unwrap();
            verify_signature(&f.ctx, &prepared, &signed).expect("baseline must verify");

            // Substituting a PASS for a FAIL is the tamper that matters: it is
            // the only edit worth making to someone else's published posture.
            signed.record = signed.record.replace("\"pass\"", "\"fail\"");
            let err = verify_signature(&f.ctx, &prepared, &signed)
                .unwrap_err()
                .to_string();
            assert!(err.contains("does NOT verify"), "{err}");
        });
    }

    #[test]
    fn the_signature_is_bound_to_the_scan_namespace_and_not_to_git() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let signed =
                sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home).unwrap();

            // Same key, same anchor, same bytes — only the namespace differs.
            // If this passed, a commit signature and a scan record would be
            // interchangeable, which is exactly what namespacing prevents.
            let out = exec::run_with_stdin(
                "ssh-keygen",
                &[
                    "-Y",
                    "verify",
                    "-f",
                    prepared.anchor_path.to_str().unwrap(),
                    "-I",
                    &prepared.block.signer.principal,
                    "-n",
                    "git",
                    "-s",
                    signed.signature_path.to_str().unwrap(),
                ],
                Some(&f.ctx.root),
                Some(signed.record.as_bytes()),
            )
            .unwrap();
            assert!(
                !out.success(),
                "a scan-record signature must not verify as a git signature"
            );
        });
    }

    #[test]
    fn a_key_the_repository_does_not_approve_is_refused_before_anything_is_signed() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let (other_priv, _material) = keypair(&f.home, "intruder");
            let other_pub = other_priv.with_extension("pub");
            git(
                &f.ctx.root,
                &["config", "user.signingkey", other_pub.to_str().unwrap()],
            );
            let err = prepare(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("NOT an approved signer"), "{err}");
            assert!(err.contains("signers.toml"), "{err}");
            assert!(
                !f.ctx.root.join(RECORD_PATH).exists(),
                "nothing may be written when the guard rail refuses"
            );
        });
    }

    #[test]
    fn an_anchor_without_the_scan_namespace_is_refused_with_the_regenerate_instruction() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            // The shape every repository anchored before this lane existed has.
            let anchor = f.ctx.sscsb_dir().join("policy").join("allowed_signers");
            std::fs::write(
                &anchor,
                format!(
                    "signer@example.test namespaces=\"git\" {} c\n",
                    f.approved_material
                ),
            )
            .unwrap();
            let err = prepare(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("restricts it to namespaces"), "{err}");
            assert!(err.contains("sscsb init"), "{err}");
        });
    }

    #[test]
    fn a_dirty_tracked_file_refuses_the_record_but_an_untracked_one_does_not() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            // Untracked: ignored, the record is still produced.
            std::fs::write(f.ctx.root.join("scratch.txt"), "junk").unwrap();
            prepare(&f.ctx, &f.home).expect("an untracked file must not block");

            // Tracked and modified: refused, naming the path IN FULL. The
            // dot-prefixed path is the case that regressed when git's output
            // was read through a trimming helper, so it is the one asserted.
            std::fs::write(f.ctx.root.join(".sscsb/policy/signers.toml"), "# edited\n").unwrap();
            let err = prepare(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains(".sscsb/policy/signers.toml"), "{err}");
            assert!(err.contains("tracked change"), "{err}");
        });
    }

    #[test]
    fn a_missing_anchor_names_the_files_to_generate_and_commit() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            std::fs::remove_file(f.ctx.sscsb_dir().join("policy").join("allowed_signers")).unwrap();
            let err = prepare(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("trust anchor"), "{err}");
            assert!(err.contains("sscsb init"), "{err}");
            assert!(err.contains("docs/signing.md"), "{err}");
        });
    }

    #[test]
    fn a_repository_with_no_origin_remote_is_refused_with_the_command_to_add_one() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            git(&f.ctx.root, &["remote", "remove", "origin"]);
            let err = prepare(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("no `origin` remote"), "{err}");
            assert!(err.contains("git remote add origin"), "{err}");
        });
    }

    #[test]
    fn an_openpgp_or_unset_gpg_format_names_the_exact_git_config_keys() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            git(&f.ctx.root, &["config", "gpg.format", "openpgp"]);
            let err = resolve_signing(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("`openpgp`"), "{err}");
            assert!(err.contains("git config --global gpg.format ssh"), "{err}");
            assert!(err.contains("docs/signing.md"), "{err}");

            git(&f.ctx.root, &["config", "--unset", "gpg.format"]);
            let err = resolve_signing(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("unset (git defaults to `openpgp`)"), "{err}");
        });
    }

    #[test]
    fn a_config_git_cannot_read_is_reported_as_unreadable_not_as_unset() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            // A malformed config file: `git config --get` exits 128 rather
            // than 1. Reported as "unset", this would tell someone whose key
            // is configured perfectly well to go configure a key.
            let broken = f.home.join("broken.gitconfig");
            std::fs::write(&broken, "[user\nsigningkey = nope\n").unwrap();
            lock.set(&[("GIT_CONFIG_GLOBAL", Some(broken.to_str().unwrap()))]);

            let err = resolve_signing(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("could not read git's"), "{err}");
            assert!(err.contains("not a missing setting"), "{err}");
            assert!(!err.contains("unset"), "{err}");
        });
    }

    #[test]
    fn an_unset_signing_key_names_both_config_keys_and_the_policy_file() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            git(&f.ctx.root, &["config", "--unset", "user.signingkey"]);
            let err = resolve_signing(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("`user.signingkey` is unset"), "{err}");
            assert!(err.contains("git config --global user.signingkey"), "{err}");
            assert!(err.contains("signers.toml"), "{err}");
        });
    }

    #[test]
    fn a_signing_key_that_resolves_to_no_public_key_is_reported_as_unreadable() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let bogus = f.ctx.root.join("not-a-key");
            std::fs::write(&bogus, "definitely not a key\n").unwrap();
            git(
                &f.ctx.root,
                &["config", "user.signingkey", bogus.to_str().unwrap()],
            );
            let err = resolve_signing(&f.ctx, &f.home).unwrap_err().to_string();
            assert!(err.contains("could not read a public key"), "{err}");
            assert!(err.contains("docs/signing.md"), "{err}");
        });
    }

    #[test]
    fn the_inline_key_spelling_git_accepts_is_materialised_and_then_removed() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            // git accepts the key material itself under `key::`; it is not a
            // path, so the signer needs a file made for it.
            git(
                &f.ctx.root,
                &[
                    "config",
                    "user.signingkey",
                    &format!("key::{}", f.approved_material),
                ],
            );
            let prepared = prepare(&f.ctx, &f.home).expect("inline key must resolve");
            assert_eq!(prepared.block.signer.principal, "signer@example.test");

            let out_dir = f.ctx.root.join(OUT_DIR);
            std::fs::create_dir_all(&out_dir).unwrap();
            let (path, temporary) = key_file_for(&prepared.signing, &f.home, &out_dir).unwrap();
            assert!(temporary);
            assert_eq!(
                signing_setup::ssh_public_key_material(&std::fs::read_to_string(&path).unwrap()),
                Some(f.approved_material.clone())
            );

            // A path-valued key is used where it stands, never copied.
            git(
                &f.ctx.root,
                &[
                    "config",
                    "user.signingkey",
                    f.approved_pub.to_str().unwrap(),
                ],
            );
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let (path, temporary) = key_file_for(&prepared.signing, &f.home, &out_dir).unwrap();
            assert!(!temporary);
            assert_eq!(path, f.approved_pub);
        });
    }

    #[test]
    fn both_signature_filename_conventions_are_accepted_and_normalised() {
        // `ssh-keygen -Y sign` appends `.sig`; `op-ssh-sign` replaces the
        // extension. Both are named here so a reader can see the divergence
        // without owning a 1Password licence.
        let candidates = signature_candidates(Path::new("/o/scan-local.json"));
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/o/scan-local.json.sig"),
                PathBuf::from("/o/scan-local.sig"),
            ]
        );
        // A record name with no extension collapses to one candidate rather
        // than listing the same path twice.
        assert_eq!(
            signature_candidates(Path::new("/o/buffer")),
            vec![PathBuf::from("/o/buffer.sig")]
        );
    }

    #[test]
    fn a_signer_that_replaces_the_extension_still_lands_at_the_published_name() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            // A stand-in for `op-ssh-sign`: real ssh-keygen, then the rename
            // that shim performs. Without normalisation the command reports
            // "the signer wrote no signature" on a signer that worked.
            let shim = f.home.join("extension-replacing-signer");
            std::fs::write(
                &shim,
                "#!/bin/sh\nset -e\nssh-keygen \"$@\"\nf=$(eval echo \\${$#})\n\
                 mv \"$f.sig\" \"${f%.*}.sig\"\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            git(
                &f.ctx.root,
                &["config", "gpg.ssh.program", shim.to_str().unwrap()],
            );

            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let signed = sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home)
                .expect("a signer that replaces the extension must still work");
            assert!(
                signed.signature_path.ends_with(SIGNATURE_PATH),
                "the published signature name is canonical: {}",
                signed.signature_path.display()
            );
            assert!(
                !f.ctx.root.join(OUT_DIR).join("scan-local.sig").exists(),
                "the signer's own spelling must not be left behind as a second copy"
            );
            verify_signature(&f.ctx, &prepared, &signed).expect("and it must verify");
        });
    }

    #[test]
    fn a_signer_that_exits_zero_without_writing_a_signature_is_not_treated_as_success() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            // Exactly the shape the first live run hit: the configured signer
            // returned 0 and produced nothing at the name we expected. "It
            // exited 0" is not a signature, and the message has to name where
            // it looked or the failure is unactionable.
            let shim = f.home.join("silent-signer");
            std::fs::write(&shim, "#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            git(
                &f.ctx.root,
                &["config", "gpg.ssh.program", shim.to_str().unwrap()],
            );
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let err = sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home)
                .unwrap_err()
                .to_string();
            assert!(err.contains("wrote no signature"), "{err}");
            assert!(err.contains("silent-signer"), "{err}");
            // Both conventions are named, so a maintainer can see we looked
            // for the 1Password spelling too.
            assert!(err.contains("scan-record.local.json.sig"), "{err}");
            assert!(err.contains("scan-record.local.sig"), "{err}");
        });
    }

    #[test]
    fn a_signer_program_that_fails_reports_it_and_leaves_no_stale_signature() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let good = sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home).unwrap();
            assert!(good.signature_path.exists());

            // A signer shim that cannot sign — an agent that is locked, a
            // missing 1Password helper. The previous run's signature must not
            // survive to be submitted as if it covered this record.
            git(
                &f.ctx.root,
                &["config", "gpg.ssh.program", "/usr/bin/false"],
            );
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let err = sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home)
                .unwrap_err()
                .to_string();
            assert!(err.contains("signing the record failed"), "{err}");
            assert!(err.contains("docs/signing.md"), "{err}");
            assert!(
                !good.signature_path.exists(),
                "a stale signature must be removed before a new signing attempt"
            );
        });
    }

    #[test]
    fn the_submission_body_carries_the_record_the_signature_and_how_to_check_them() {
        crate::testutil::with_env(|lock| {
            let f = signing_repo(lock);
            let prepared = prepare(&f.ctx, &f.home).unwrap();
            let signed =
                sign_record(&f.ctx, &f.cfg, &prepared, &sample_results(), &f.home).unwrap();
            let body = submission_body(&prepared, &signed);
            check_body_size(&body).unwrap();

            assert!(body.contains("https://github.com/o/r"));
            assert!(body.contains(&prepared.block.repo.commit));
            assert!(body.contains("signer@example.test"));
            assert!(body.contains(&prepared.block.signer.fingerprint));
            assert!(body.contains(NAMESPACE));
            // A POINTER, not a payload: the record and signature are committed
            // files the directory reads from the public repository, so the body
            // must NOT carry a second copy of the signed bytes for anyone to
            // mistake for them.
            assert!(body.contains(RECORD_PATH));
            assert!(body.contains(SIGNATURE_PATH));
            assert!(
                !body.contains(&signed.record),
                "the submission must not inline the record"
            );
            assert!(
                !body.contains(&signed.signature),
                "the submission must not inline the signature"
            );
            assert!(body.contains(&sha256_hex(signed.record.as_bytes())));
            // `parse-request.ts` extracts the slug from this body; if it stops
            // finding one, every submission is rejected at intake.
            assert!(body.contains("### Repository URL"));
            // The recipe a reader can run without trusting us — and it has to
            // actually run. `gh api` returns the file's raw bytes only with the
            // raw Accept header, and `?ref=` is the query parameter a GET
            // takes; `-f ref=…` builds a POST body and `--jq .content` would
            // try to index into content that is no longer JSON. Both were in
            // the first draft, and a recipe that errors is worse than none.
            assert!(body.contains("ssh-keygen -Y verify"));
            assert!(body.contains(".sscsb/policy/allowed_signers"));
            assert!(body.contains("Accept: application/vnd.github.raw"));
            assert!(body.contains(&format!("?ref={}", prepared.block.repo.commit)));
            assert!(!body.contains("--jq .content"));
            assert!(!body.contains("-f ref="));
            // The claim, stated at its real strength and no higher.
            assert!(body.contains("does **not** prove the repository's own CI"));
            assert!(body.contains("requires an independent record to agree"));
        });
    }
}
