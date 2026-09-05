//! The bundled agent skill — `sscsb skill install | print | check`.
//!
//! `sscsb` ships an agent skill describing how to drive `sscsb`. The canonical
//! copy is `templates/skills/sscsb/SKILL.md`; it is compiled into the binary
//! with `include_str!`, and this repository's own installed copy at
//! [`SKILL_PATH`] is asserted byte-identical to it by `tests/skill_docs.rs`.
//! The tool that audits you is the tool that generated your workflows — and now
//! the tool that wrote the instructions your agent reads.
//!
//! # What the embedded comparison proves, and what it does not
//!
//! [`check`] compares the file on disk against the bundled bytes. That detects
//! **modification of the extracted copy by something that is not this binary**:
//! `SKILL_PATH` sits in a repository writable by every other agent, hook,
//! postinstall script and prompt-injected tool call on the machine. It also
//! catches a stale copy left by an older `sscsb` and a partial write.
//!
//! How much that is worth depends on a fact this module refuses to assume:
//! whether the same unprivileged process could ALSO have rewritten this binary.
//! On an install into a root-owned prefix it could not, and the narrow claim
//! stands at full strength. On a Homebrew install it usually could —
//! `/opt/homebrew/bin` is owned by the installing user and needs no `sudo` —
//! and then the binary is exactly as writable as the file it is checking, so a
//! clean result is evidence of no *casual* edit and nothing stronger.
//! [`binary_guarantee`] answers that question at run time, per machine, by
//! asking the kernel; every `check` result carries the answer.
//!
//! It answers it over the WHOLE resolution chain — every ancestor directory up
//! to the filesystem root and every symlink hop individually — because a
//! four-point probe (the executable, its directory, the canonicalized file, its
//! directory) reports `not-user-writable` for two layouts an unprivileged user
//! can take over: a writable grandparent above a read-only `bin`, and a
//! repointed intermediate symlink, which is precisely Homebrew's
//! `opt/<formula> -> ../Cellar/<formula>/<version>` shape. Both were proven by
//! replacing a binary that had just printed the strong verdict. A green verdict
//! that is checkable and wrong is worse than a vague sentence, because it is
//! trusted.
//!
//! # Why the strong verdict is the exception and not the default
//!
//! Each round of that hardening closed one door and found another open. Mode
//! bits missed a writable grandparent. Four points missed an intermediate
//! symlink. `faccessat(W_OK)` — "may I write this right now" — missed
//! OWNERSHIP, and POSIX lets an owner `chmod`: a real release binary,
//! user-owned at `0555` in a user-owned `0555` directory under a root-owned
//! prefix, answered every probe "not writable", printed the strong verdict, and
//! was then replaced by an unprivileged `chmod u+w`. [`owned_by_this_user`]
//! closes that specific hole.
//!
//! The pattern is the finding. This probe is trying to prove a NEGATIVE about a
//! filesystem, and it cannot do that portably: [`UNCHECKED_MECHANISMS`] lists
//! what still remains — ACLs, BSD file flags, mount options, container image
//! layering, process capabilities — and that list is not itself provably
//! complete. So the DEFAULT is inverted. [`BinaryTrust::NotUserWritable`] is
//! now issued only when the chain is fully walked, every link answers both
//! questions "no", and the platform's [`std::env::current_exe`] is known to
//! report the invocation path rather than a resolved one
//! ([`CHAIN_STARTS_AT_INVOCATION_PATH`]). Every other outcome — one unreadable
//! link, one unanswered probe, one abandoned walk, one platform that resolves
//! before the process starts — is [`BinaryTrust::Unknown`], read as the weak
//! case.
//!
//! That last condition is the platform limit, stated rather than guessed at.
//! std documents `current_exe` as platform-dependent: "if the executable was
//! invoked through a symbolic link, some platforms will return the path of the
//! symbolic link and other platforms will return the path of the symbolic
//! link's target". macOS returns the link, measured rather than assumed: a real
//! `bin/sscsb -> ../opt/sscsb/bin/sscsb` install puts both the middle link and
//! the directory holding it on the chain. Linux reads the already-resolved
//! `/proc/self/exe`, so a link the kernel traversed before the process started
//! cannot appear on the chain at all — and rather than let that layout earn the
//! strong verdict there, the strong verdict is simply unavailable on such a
//! platform. A process cannot portably recover the path it was invoked by
//! (`argv[0]` is caller-supplied, so seeding from it would let a caller choose
//! this verdict), which is why the gap disqualifies instead of being closed
//! with a guess. `--format json` carries the disqualification as
//! `binary.chain_start` and `binary.strong_verdict_available`, so a machine
//! consumer gets the caveat too.
//!
//! Either way it proves nothing about a tampered binary. The check, the bytes
//! and any digest of them all live in the same artifact, so a modified `sscsb`
//! could be modified to lie here too. That is not a gap to be closed
//! in-process — it is why `docs/skill.md` sends a verifier to the release asset
//! and its Sigstore identity, using tools obtained independently of `sscsb`.
//! Claiming otherwise would contradict this repository's own doctrine that a
//! digest a record supplies about itself authorizes nothing
//! (`docs/local-scan.md`).

use anyhow::{Context as _, Result};
use sha2::Digest as _;
use std::collections::{BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};

/// The canonical skill, compiled in from the template it is generated from.
pub const SKILL_MD: &str = include_str!("../templates/skills/sscsb/SKILL.md");

/// Where `sscsb skill install` writes by default, relative to the repo root.
pub const SKILL_PATH: &str = ".claude/skills/sscsb/SKILL.md";

/// The skill's name — the directory under `.claude/skills/` and the `name:`
/// field of the frontmatter. Pinned in both directions by `tests/skill_docs.rs`.
pub const SKILL_NAME: &str = "sscsb";

/// The document carrying the release-asset verification recipe, as an absolute
/// HTTPS URL. Named in refusals and in every `check` result so a reader is
/// never left to guess where the real proof lives.
///
/// Absolute ON PURPOSE. This binary's stdout is the one surface an on-machine
/// attacker cannot rewrite — that is the entire premise of [`check`] — so it is
/// the worst possible place to print a pointer that only resolves inside a
/// checkout. Someone who installed `sscsb` from a release, or from Homebrew,
/// has no `docs/` directory; a relative path would dead-end exactly where the
/// tool is refusing to reassure them, while the far more tamperable
/// `SKILL.md` correctly links the URL.
///
/// Built from `CARGO_PKG_REPOSITORY` like [`CERTIFICATE_IDENTITY`], so the host
/// and slug cannot drift from `Cargo.toml`.
pub const VERIFY_DOC: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/skill.md");

/// The same document as a repository-relative path — for Markdown links inside
/// this repository, where a URL would send a reader out to the web to read a
/// file already next to them. Never printed by the binary: see [`VERIFY_DOC`].
pub const VERIFY_DOC_PATH: &str = "docs/skill.md";

/// The exact scope of what [`check`] can establish. One sentence, one place:
/// the CLI prints it, `docs/skill.md` publishes it, and the doc test asserts
/// they are the same string.
pub const EMBEDDED_CHECK_SCOPE: &str =
    "detects modification of the installed file by anything other than this binary; \
     cannot detect a tampered sscsb";

/// The one invocation that installs the skill. Written down once, here, and
/// asserted against `docs/skill.md` and against `--help` by the doc test.
pub const COMMAND: &str = "sscsb skill install";

/// The canonical source of [`SKILL_MD`], relative to the repository root.
pub const TEMPLATE_PATH: &str = "templates/skills/sscsb/SKILL.md";

/// The release asset's name. `release.yml` stages [`TEMPLATE_PATH`] into
/// `dist/` under this name, where the all-files Cosign loop signs it.
pub const ASSET_NAME: &str = "SKILL.md";

/// The disclosure every surface showing the release-asset recipe must carry
/// until a published release actually contains [`ASSET_NAME`].
///
/// `release.yml` stages the skill and the signing loop covers it — the pipeline
/// is real — but no tag published so far was cut from a tree that did that.
/// A reader who runs the recipe's worked example verbatim today gets "no such
/// file or directory" from step 3, with every step around it working, and reads
/// that as their own mistake. Naming the gap is the fix; deleting the step
/// would remove the one trust root in the document that does not depend on this
/// binary.
///
/// `tests/skill_docs.rs` asserts this sentence onto every such surface, and its
/// failure message says when it may be removed.
pub const ASSET_PENDING_NOTICE: &str = "`SKILL.md` is not a release asset yet";

/// When it becomes one. Pinned beside [`ASSET_PENDING_NOTICE`] so a surface
/// cannot state the gap without stating its end.
pub const ASSET_PENDING_FIRST_TAG: &str = "the first tag cut after this change lands";

/// What `cosign sign-blob --bundle` appends to each signed file's name. The
/// deploy gate requires one of these per asset, and refuses an orphan.
pub const BUNDLE_SUFFIX: &str = ".sigstore.json";

/// The workflow that signs every release asset, as the certificate identity
/// spells it. `deploy-gate.yml` assembles the same string from
/// `${GITHUB_REPOSITORY}` and its `SIGNER_WORKFLOW` input.
pub const SIGNER_WORKFLOW: &str = ".github/workflows/release.yml";

/// The full `--certificate-identity` to pass to `cosign verify-blob`, with the
/// tag left as a placeholder ON PURPOSE.
///
/// The tag has to come from the version you MEANT to install, learned out of
/// band — a changelog, a release announcement, a pinned dependency. Reading it
/// off the artifact you just downloaded and then verifying the artifact against
/// itself proves only that the file is internally consistent.
///
/// Built from `CARGO_PKG_REPOSITORY` so the host and slug cannot drift from
/// `Cargo.toml`.
pub const CERTIFICATE_IDENTITY: &str = concat!(
    env!("CARGO_PKG_REPOSITORY"),
    "/.github/workflows/release.yml@refs/tags/vX.Y.Z"
);

/// The OIDC issuer that minted the signing certificate. Pinned alongside the
/// identity: an identity string without an issuer can be matched by a
/// certificate from an issuer you never trusted.
pub const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The predicate type of the release's build-provenance attestation, which
/// `gh attestation verify` needs stated explicitly — it defaults to this one,
/// but the SBOM attestation over the same subjects does not.
pub const ATTESTATION_PREDICATE: &str = "https://slsa.dev/provenance/v1";

/// Lowercase hex SHA-256, the digest form every other record in this tool uses.
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

// ───────────────────── how strong this binary's own claim is ─────────────────

/// Whether `path` can be modified by the user this process runs as, with no
/// elevation and no further syscall. `None` means the question could not be
/// answered.
///
/// This asks the KERNEL — `faccessat(…, W_OK, AT_EACCESS)` — rather than
/// reading mode bits. Mode bits alone would miss supplementary groups and
/// ACLs, and would miss them in the direction that overstates the guarantee: a
/// directory owned by `root`, group `admin`, mode `0775` is writable by an
/// admin user and would read as unwritable.
///
/// It answers a NARROWER question than the verdict needs, and the difference
/// shipped a false assurance: `W_OK` is "may I write this right now", not "may
/// I make myself able to write it". See [`owned_by_this_user`].
///
/// `EACCES`, `EPERM` and `EROFS` are answers ("no"). Anything else — the path
/// vanished, a component is not a directory, the call is unsupported — is not
/// an answer, and is reported as one rather than being rounded to "no".
#[cfg(unix)]
pub fn writable_by_this_user(path: &Path) -> Option<bool> {
    use rustix::fs::{Access, AtFlags, CWD};
    use rustix::io::Errno;
    match rustix::fs::accessat(CWD, path, Access::WRITE_OK, AtFlags::EACCESS) {
        Ok(()) => Some(true),
        Err(Errno::ACCESS | Errno::PERM | Errno::ROFS) => Some(false),
        Err(_) => None,
    }
}

/// Non-Unix hosts: `sscsb` ships no such target, and guessing would be the one
/// thing this function exists to avoid.
#[cfg(not(unix))]
pub fn writable_by_this_user(_path: &Path) -> Option<bool> {
    None
}

/// Whether the effective uid OWNS `path` — which is to say, whether it can
/// make itself able to write it. `None` means the question could not be
/// answered.
///
/// **Ownership is capability.** POSIX gives a file's owner `chmod`, so a path
/// at mode `0555` owned by the current user is a path the current user writes
/// the moment it decides to: `chmod u+w` on the file, or `chmod u+w` on the
/// directory followed by unlink-and-recreate. `faccessat(W_OK)` answers "no" to
/// both, because both are one syscall away rather than zero.
///
/// This was not a hypothetical. A real `sscsb` release binary, user-owned at
/// `0555` inside a user-owned `0555` directory under a root-owned prefix,
/// probed `writable: false` on every link of its chain and printed
/// `not-user-writable` with `narrow_claim_holds: true` — and was then replaced
/// twice, through both doors, by an unprivileged `chmod`.
///
/// Uses `lstat`, not `stat`: the question is who owns the entry that is ON the
/// chain. A symlink's own ownership is reported for the symlink; the target is
/// a separate row, already walked and probed in its own right.
///
/// Root (uid 0) owns everything, and is reported as owning everything.
#[cfg(unix)]
pub fn owned_by_this_user(path: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let euid = rustix::process::geteuid();
    if euid.is_root() {
        return Some(true);
    }
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| m.uid() == euid.as_raw())
}

/// Non-Unix hosts: see [`writable_by_this_user`].
#[cfg(not(unix))]
pub fn owned_by_this_user(_path: &Path) -> Option<bool> {
    None
}

/// What this verdict CANNOT see, even in its strongest form, named so a machine
/// consumer gets the caveat and not only a prose reader.
///
/// The probe is trying to prove a negative about a filesystem, and four rounds
/// of hardening each closed one door and found another: mode bits, an
/// intermediate symlink, a pre-resolved chain start, ownership. These are the
/// mechanisms known to remain. The list is not a promise of completeness — it
/// is the reason the strong verdict is deliberately hard to earn and the
/// release-asset path in `docs/skill.md` is the trust root that does not depend
/// on this binary.
/// Each entry is `<name> — <why it matters>`, and `docs/skill.md` is asserted
/// to name every one of them: the list a machine reads and the list a human
/// reads cannot drift apart.
pub const UNCHECKED_MECHANISMS: &[&str] = &[
    "POSIX ACLs — an entry granting another principal, or a default ACL on a parent, \
     can change who may write after this answer was taken",
    "BSD file flags — chflags uchg/schg can mask a path this answer calls shut",
    "mount options — a read-only mount can be remounted read-write by whoever may mount it",
    "container image layering — a copy-on-write layer can present different bytes to a \
     different process",
    "process capabilities — CAP_DAC_OVERRIDE and CAP_FOWNER let a non-root process write \
     regardless of mode or owner",
];

/// Whether [`std::env::current_exe`] on THIS platform reports the path the
/// executable was invoked by, or one the kernel resolved before the process
/// started.
///
/// std documents the answer as platform-dependent: "if the executable was
/// invoked through a symbolic link, some platforms will return the path of the
/// symbolic link and other platforms will return the path of the symbolic
/// link's target". macOS returns the link — measured, not assumed. Linux reads
/// `/proc/self/exe`, which the kernel already resolved, so an intermediate
/// symlink cannot appear on the chain at all there, and a layout whose only
/// open door IS such a link would look shut.
///
/// A process cannot portably recover the path it was invoked by — `argv[0]` is
/// caller-supplied, so seeding from it would let a caller choose the verdict.
/// So the gap is not closed; it DISQUALIFIES the strong verdict, and this
/// constant is what disqualifies it.
pub const CHAIN_STARTS_AT_INVOCATION_PATH: bool = cfg!(target_os = "macos");

/// The wire word for [`CHAIN_STARTS_AT_INVOCATION_PATH`], carried in
/// `--format json` so an agent branching on `trust` can see why the strong
/// verdict was or was not on the table.
pub const CHAIN_START: &str = if CHAIN_STARTS_AT_INVOCATION_PATH {
    "invocation-path"
} else {
    "pre-resolved"
};

/// One location that could be used to replace this binary, and the answers for
/// it. A writable *directory* is as good as a writable file: the entry can be
/// unlinked and re-created, or a symlink repointed. So is an OWNED one, at any
/// mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteProbe {
    /// Machine-readable role. One of `executable`, `executable-symlink`,
    /// `executable-directory`, `resolved-executable`,
    /// `resolved-executable-directory`, `symlink`, `ancestor-directory`,
    /// `path-component`, `unresolved-chain`.
    pub role: &'static str,
    pub path: PathBuf,
    /// `faccessat(W_OK)`. `None` when the question could not be answered.
    pub writable: Option<bool>,
    /// Whether the effective uid owns this path, and so can `chmod` it into
    /// writability. `None` when the question could not be answered.
    pub owned: Option<bool>,
}

impl WriteProbe {
    /// Whether this path hands the current user the binary — by being writable
    /// now, or by being owned and therefore one `chmod` from writable.
    pub fn user_can_replace(&self) -> bool {
        self.writable == Some(true) || self.owned == Some(true)
    }

    /// Whether BOTH questions were answered, and both answered "no". Anything
    /// less is not a shut door; it is an unanswered one.
    pub fn shut(&self) -> bool {
        self.writable == Some(false) && self.owned == Some(false)
    }

    /// Why this path is a door, for the sentence that has to name it. Empty
    /// when it is not one.
    pub fn open_because(&self) -> &'static str {
        match (self.writable, self.owned) {
            (Some(true), Some(true)) => "writable and owned",
            (Some(true), _) => "writable",
            (_, Some(true)) => "owned — an owner may chmod it",
            _ => "",
        }
    }
}

/// How many paths the resolver expands before it stops and says so.
///
/// A symlink cycle (`a -> b`, `b -> a`) and a chain too deep to be honest about
/// both end here. Stopping is reported rather than swallowed: a walk that did
/// not finish cannot claim every door is shut.
const MAX_RESOLUTION_STEPS: usize = 64;

/// What a path on the chain turned out to be. Drives both the probe's role and
/// whether resolution continues through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Directory,
    Symlink,
    File,
    /// The walk could not answer for this path — it vanished, a component is
    /// not a directory, or the resolver gave up here.
    Unresolvable,
}

/// Walk `start` the way the kernel does — prefix by prefix, substituting at
/// every symlink — and record every path touched on the way.
///
/// This is the whole correction. Probing four points (the exe, its parent, the
/// canonicalized file, that file's parent) misses two shapes that hand an
/// unprivileged user the binary:
///
/// 1. **A writable ancestor further up.** `prefix/bin` can be mode `0555` while
///    `prefix` is yours: `mv bin bin.orig && mkdir bin` replaces the binary
///    without touching a single probed path.
/// 2. **A repointed intermediate symlink.** Homebrew's own shape —
///    `bin/sscsb -> ../opt/sscsb/bin/sscsb` and `opt/sscsb -> ../Cellar/…` —
///    canonicalizes straight past the middle link, so a writable `opt/`
///    directory never appears in a four-point probe at all.
///
/// Both were demonstrated by taking over a binary that had just printed
/// `not-user-writable`. A verdict that is checkable and wrong is worse than the
/// vague sentence it replaced, because it gets trusted.
///
/// Returns the chain in walk order (deduplicated by path, first kind wins) and
/// whether the walk finished. One walk per seed: sharing state between seeds
/// makes a second seed that the first walk also reaches look like a symlink
/// loop, which is how `/tmp -> private/tmp` briefly reported an incomplete
/// chain for an ordinary path.
fn resolution_chain(seed: &Path) -> (Vec<(PathBuf, Kind)>, bool) {
    let mut chain: Vec<(PathBuf, Kind)> = Vec::new();
    // Every path this walk has ever queued. A symlink whose target is already
    // in here is going back somewhere the walk has been: that is the loop.
    let mut queued: BTreeSet<PathBuf> = BTreeSet::new();
    let mut pending: VecDeque<PathBuf> = VecDeque::new();
    queued.insert(seed.to_path_buf());
    pending.push_back(seed.to_path_buf());
    let mut steps = 0usize;
    let mut complete = true;

    let record = |path: &Path, kind: Kind, chain: &mut Vec<(PathBuf, Kind)>| {
        if !chain.iter().any(|(p, _)| p == path) {
            chain.push((path.to_path_buf(), kind));
        }
    };

    while let Some(path) = pending.pop_front() {
        if path.as_os_str().is_empty() {
            continue;
        }
        steps += 1;
        // A chain too deep to be honest about. Stopping here is reported, not
        // rounded down to "nothing was writable".
        if steps > MAX_RESOLUTION_STEPS {
            record(&path, Kind::Unresolvable, &mut chain);
            complete = false;
            break;
        }

        let comps: Vec<Component> = path.components().collect();
        let mut cur = PathBuf::new();
        for (i, c) in comps.iter().enumerate() {
            match c {
                // `.` is a no-op, and `..` is applied to what resolution has
                // already produced — every symlink before this point is
                // already substituted, so popping is the correct move.
                Component::CurDir => continue,
                Component::ParentDir => {
                    cur.pop();
                    continue;
                }
                other => cur.push(other.as_os_str()),
            }

            let kind = match std::fs::symlink_metadata(&cur) {
                Ok(m) if m.is_symlink() => Kind::Symlink,
                Ok(m) if m.is_dir() => Kind::Directory,
                Ok(_) => Kind::File,
                Err(_) => Kind::Unresolvable,
            };
            record(&cur, kind, &mut chain);

            match kind {
                Kind::Symlink => {
                    // The rest of this path lives under whatever the link
                    // points at, so resolution continues there rather than
                    // here. Probing only the far end is exactly how the
                    // Homebrew middle link stayed invisible.
                    match std::fs::read_link(&cur) {
                        Ok(target) => {
                            let base = if target.is_absolute() {
                                target
                            } else {
                                cur.parent().unwrap_or(Path::new("/")).join(target)
                            };
                            let rest: PathBuf = comps[i + 1..].iter().collect();
                            let next = if rest.as_os_str().is_empty() {
                                base
                            } else {
                                base.join(rest)
                            };
                            // `a -> b`, `b -> a`. The kernel answers ELOOP; we
                            // say so instead of walking forever, and an
                            // unfinished walk cannot earn the strong verdict.
                            if queued.insert(next.clone()) {
                                pending.push_back(next);
                            } else {
                                complete = false;
                            }
                        }
                        Err(_) => complete = false,
                    }
                    break;
                }
                Kind::Unresolvable => {
                    complete = false;
                    break;
                }
                Kind::Directory | Kind::File => {}
            }
        }
    }
    (chain, complete)
}

/// How strong `check`'s result is on THIS machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryTrust {
    /// Some path that can replace this binary is writable by the user running
    /// it, or owned by them, with no elevation. The check and the file it
    /// checks share one attacker.
    UserWritable,
    /// The narrow, hard-to-earn case. Every link of a fully-walked chain is
    /// both unwritable AND unowned, on a platform whose chain start is the
    /// invocation path. The narrow claim stands, within
    /// [`UNCHECKED_MECHANISMS`].
    NotUserWritable,
    /// The question could not be answered — an unreadable link, an unanswered
    /// probe, an abandoned walk, or a platform where the chain may begin after
    /// a symlink the kernel already resolved. This is the DEFAULT, not the
    /// exception: treated as the weak case everywhere, because assuming the
    /// strong one is how a false assurance gets printed.
    Unknown,
}

impl BinaryTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            BinaryTrust::UserWritable => "user-writable",
            BinaryTrust::NotUserWritable => "not-user-writable",
            BinaryTrust::Unknown => "unknown",
        }
    }

    /// True when a clean `check` may be read as the narrow claim at full
    /// strength. `Unknown` is deliberately not one of them.
    pub fn narrow_claim_holds(self) -> bool {
        self == BinaryTrust::NotUserWritable
    }
}

/// What this binary can honestly say about its own integrity, resolved at run
/// time on the machine it is running on.
#[derive(Debug, Clone)]
pub struct BinaryGuarantee {
    /// `current_exe()` as reported — possibly a symlink.
    pub exe: Option<PathBuf>,
    /// The same path with symlinks resolved, when it is not already that and
    /// resolution succeeded. Homebrew's `/opt/homebrew/bin/sscsb` is a symlink
    /// into `../Cellar/...`, and both ends are attack surface.
    pub resolved: Option<PathBuf>,
    /// Every path on the resolution chain, in walk order, with the kernel's
    /// answer for each. This IS the chain — a reader can see *which* link is
    /// writable instead of having to trust the verdict over it.
    pub probes: Vec<WriteProbe>,
    /// False when the walk stopped early (a symlink cycle, an unreadable
    /// component, or [`MAX_RESOLUTION_STEPS`]). An unfinished walk can never
    /// earn [`BinaryTrust::NotUserWritable`].
    pub chain_complete: bool,
    pub trust: BinaryTrust,
}

/// Build the guarantee for an arbitrary executable path.
///
/// Split out from [`binary_guarantee`] so every verdict can be exercised
/// against real fixtures — a writable grandparent, a repointed intermediate
/// symlink, a root-owned prefix — rather than against whatever the test
/// runner's own path happens to be.
pub fn guarantee_for(exe: &Path) -> BinaryGuarantee {
    let canonical = std::fs::canonicalize(exe).ok();
    let resolved = canonical.clone().filter(|r| r.as_path() != exe);

    // Seed with the path as given AND with its canonical form. The walk below
    // reaches the canonical path on its own in every ordinary case; seeding it
    // too means the requirement "every ancestor of the canonicalized path is
    // probed" holds even where the walk gave up part way.
    //
    // A RELATIVE path is made absolute first (lexically — `absolute` does not
    // touch the filesystem), or the walk would stop at the current directory
    // and silently miss every ancestor above it. `current_exe()` is absolute
    // on every platform this ships to, but this function is public.
    let mut seeds = vec![std::path::absolute(exe).unwrap_or_else(|_| exe.to_path_buf())];
    if let Some(c) = canonical.as_ref() {
        if !seeds.iter().any(|s| s == c) {
            seeds.push(c.clone());
        }
    }
    let mut chain: Vec<(PathBuf, Kind)> = Vec::new();
    let mut chain_complete = true;
    for seed in &seeds {
        let (walked, complete) = resolution_chain(seed);
        chain_complete &= complete;
        for (path, kind) in walked {
            if !chain.iter().any(|(p, _)| *p == path) {
                chain.push((path, kind));
            }
        }
    }

    // The exe as the WALK spells it: its directory resolved, its own last
    // component left alone. Without this, an install whose *ancestors* happen
    // to run through a symlink — `/var -> private/var` on macOS, `/bin ->
    // usr/bin` on Linux — loses the `executable` and `executable-directory`
    // roles entirely, because the path as typed never appears on the chain.
    let exe_abs = seeds[0].as_path();
    let exe_parent = exe_abs.parent().filter(|p| !p.as_os_str().is_empty());
    let exe_parent_resolved = exe_parent.and_then(|p| std::fs::canonicalize(p).ok());
    let exe_as_walked = match (exe_parent_resolved.as_deref(), exe_abs.file_name()) {
        (Some(d), Some(n)) => Some(d.join(n)),
        _ => None,
    };
    let canonical_parent = canonical
        .as_deref()
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty());

    let probes: Vec<WriteProbe> = chain
        .iter()
        .map(|(path, kind)| {
            let p = path.as_path();
            // An unresolvable entry is always labelled as such, checked BEFORE
            // any positional match. Positional labels (`executable-directory`
            // and friends) claim the path was actually walked and resolved;
            // an entry the walk gave up on has no business claiming that, even
            // when it lexically happens to equal `exe_parent` — which is
            // exactly the shape of a nonexistent immediate parent directory.
            // This was previously an `else` arm reached only when every
            // positional check failed, which is what a lexical/canonical
            // mismatch (macOS's `/var` -> `/private/var`) accidentally
            // guaranteed; on a platform with no such symlink in the temp path
            // (Linux's `/tmp`), the positional check matched first and an
            // unresolvable parent was mislabelled `executable-directory`. The
            // security-relevant fields are unaffected either way — `writable`
            // and `owned` are already gated on `kind`, not on `role` — this is
            // a diagnostic-accuracy fix for the label a reader sees.
            let role = if matches!(kind, Kind::Unresolvable) {
                "unresolved-chain"
            } else if p == exe || p == exe_abs || Some(p) == exe_as_walked.as_deref() {
                match kind {
                    Kind::Symlink => "executable-symlink",
                    _ => "executable",
                }
            } else if Some(p) == canonical.as_deref() {
                "resolved-executable"
            } else if Some(p) == exe_parent || Some(p) == exe_parent_resolved.as_deref() {
                "executable-directory"
            } else if Some(p) == canonical_parent {
                "resolved-executable-directory"
            } else {
                match kind {
                    Kind::Symlink => "symlink",
                    Kind::Directory => "ancestor-directory",
                    Kind::File => "path-component",
                    Kind::Unresolvable => unreachable!("handled above"),
                }
            };
            WriteProbe {
                role,
                path: path.clone(),
                // A path the walk could not resolve gets no verdict at all,
                // rather than a syscall answer about something that is not
                // there. `None` is what keeps it out of the strong case.
                writable: match kind {
                    Kind::Unresolvable => None,
                    _ => writable_by_this_user(p),
                },
                owned: match kind {
                    Kind::Unresolvable => None,
                    _ => owned_by_this_user(p),
                },
            }
        })
        .collect();

    // THE DEFAULT IS INVERTED, and this is the whole of the strategic fix.
    //
    // Rounds of hardening each closed one door and found another open: mode
    // bits missed a writable grandparent, a four-point probe missed an
    // intermediate symlink, the chain start is pre-resolved on Linux, and
    // `W_OK` missed ownership. Each correction was right and none of them
    // finished the job, because the probe is trying to prove a NEGATIVE about a
    // filesystem and cannot do that portably — ACLs, chflags, mount options,
    // container layering and capabilities all remain (see
    // [`UNCHECKED_MECHANISMS`]).
    //
    // So the strong verdict is now the narrow, hard-to-earn case rather than
    // the fallback. It requires FOUR things at once, and anything else — one
    // unreadable link, one unanswered question, one platform where the chain
    // may start after a symlink — is the weak verdict.
    let any_open = probes.iter().any(WriteProbe::user_can_replace);
    let every_door_shut = !probes.is_empty() && probes.iter().all(WriteProbe::shut);
    let trust = if any_open {
        BinaryTrust::UserWritable
    } else if chain_complete && every_door_shut && CHAIN_STARTS_AT_INVOCATION_PATH {
        BinaryTrust::NotUserWritable
    } else {
        BinaryTrust::Unknown
    };

    BinaryGuarantee {
        exe: Some(exe.to_path_buf()),
        resolved,
        probes,
        chain_complete,
        trust,
    }
}

/// The guarantee for the binary that is running right now.
pub fn binary_guarantee() -> BinaryGuarantee {
    match std::env::current_exe() {
        Ok(exe) => guarantee_for(&exe),
        Err(_) => BinaryGuarantee {
            exe: None,
            resolved: None,
            probes: Vec::new(),
            chain_complete: false,
            trust: BinaryTrust::Unknown,
        },
    }
}

impl BinaryGuarantee {
    /// Whether every link of the chain answered both questions "no". Says
    /// nothing about whether the chain was complete or the platform qualifies —
    /// [`statement`](Self::statement) needs those apart, so that a chain that
    /// is shut but on a disqualified platform explains ITSELF rather than
    /// reading as an unreadable link.
    pub fn every_door_shut(&self) -> bool {
        !self.probes.is_empty() && self.probes.iter().all(WriteProbe::shut)
    }

    /// The paths this user can replace the binary through, with the reason for
    /// each. Empty in the two non-`UserWritable` cases.
    fn writable_paths(&self) -> Vec<String> {
        self.probes
            .iter()
            .filter(|p| p.user_can_replace())
            .map(|p| format!("{} ({})", p.path.display(), p.open_because()))
            .collect()
    }

    /// The writable paths, capped so one deep chain cannot flood a terminal.
    /// The full list is always in `--format json`.
    fn writable_summary(&self) -> String {
        const SHOWN: usize = 6;
        let all = self.writable_paths();
        if all.len() <= SHOWN {
            return all.join(", ");
        }
        format!(
            "{}, … (+{} more, see `--format json`)",
            all[..SHOWN].join(", "),
            all.len() - SHOWN
        )
    }

    /// Whether any path on the chain is inside a Homebrew prefix.
    ///
    /// The Homebrew sentence is true and useful for a `brew`-installed binary
    /// and pure noise anywhere else — it was printed, unconditionally, for a
    /// binary sitting in `/tmp`. Deciding from the chain rather than from
    /// `HOMEBREW_PREFIX` keeps an environment variable out of a security
    /// sentence. Intel Homebrew (`/usr/local`) carries no marker in its `bin`
    /// path, but its Cellar target does, and the chain now reaches that.
    fn looks_like_homebrew(&self) -> bool {
        self.probes.iter().any(|p| {
            let s = p.path.to_string_lossy();
            s.contains("/Cellar/") || s.contains("/homebrew/") || s.contains("/linuxbrew/")
        })
    }

    /// What the chain ends at, for the sentence that has to name something.
    fn target(&self) -> String {
        self.resolved
            .as_ref()
            .or(self.exe.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "an unknown path".to_string())
    }

    /// Say — in the tool's own output, not only in a document — exactly how
    /// much a clean `check` is worth on this machine.
    ///
    /// The doc used to assert that nothing which can write the installed skill
    /// "can write `/usr/local/bin/sscsb`". That is true of a root-owned prefix
    /// and false of the install path the docs recommend first: `brew install`
    /// lands the binary under a prefix the installing user owns. Printing the
    /// strong sentence unconditionally would be the tool asserting an asymmetry
    /// that does not exist for most of its readers, so the sentence is chosen
    /// from what the kernel just said.
    pub fn statement(&self) -> Vec<String> {
        // Only where the binary really is a Homebrew one. Printed for every
        // user-writable verdict, it told a reader with a binary in `/tmp`
        // about a package manager that had nothing to do with it.
        let homebrew = if self.looks_like_homebrew() {
            " A `brew`-installed sscsb is the common case, and this chain is one: Homebrew's \
             prefix is owned by the installing user."
        } else {
            ""
        };
        let independent = format!(
            "The claim that does not depend on this binary is the release asset's Sigstore \
             identity — see {VERIFY_DOC}."
        );
        // Named on the strong verdict, where a reader is most likely to stop
        // reading. The list is the honest boundary of a negative this probe
        // cannot prove portably.
        let unchecked = format!(
            "Not checked even here, and each of them can flip that answer: {}. \
             This verdict is the floor of what an attacker must beat, not a proof.",
            UNCHECKED_MECHANISMS.join("; ")
        );
        match self.trust {
            BinaryTrust::NotUserWritable => vec![
                format!(
                    "No path on this binary's resolution chain is writable by the user running \
                     it, and none is owned by that user — all {} probed, ending at {}.",
                    self.probes.len(),
                    self.target()
                ),
                "The chain is every ancestor directory and every symlink hop, not just the \
                 binary and its own directory, and OWNERSHIP counts as write access: POSIX lets \
                 an owner chmod, so a user-owned path at mode 0555 is one command from open."
                    .to_string(),
                "So an unprivileged process that edited the installed skill could not also have \
                 edited this check — the comparison above is that narrow claim at full strength. \
                 It still says nothing about a binary replaced with elevation."
                    .to_string(),
                unchecked,
                independent,
            ],
            BinaryTrust::UserWritable => vec![
                format!(
                    "This binary can be replaced by the user running it, with no elevation — \
                     {} of the {} paths on its resolution chain {} writable by that user or \
                     owned by them: {}.",
                    self.writable_paths().len(),
                    self.probes.len(),
                    if self.writable_paths().len() == 1 {
                        "is"
                    } else {
                        "are"
                    },
                    self.writable_summary()
                ),
                format!(
                    "A process running as this user could have modified this check as well as \
                     the file it checks, so a clean result is evidence of no CASUAL edit and \
                     nothing stronger.{homebrew}"
                ),
                independent,
            ],
            BinaryTrust::Unknown => vec![
                if !self.chain_complete {
                    format!(
                        "Could not follow this binary's resolution chain to the end ({} paths \
                         walked), so it cannot be said that every path on it is shut.",
                        self.probes.len()
                    )
                } else if self.every_door_shut() && !CHAIN_STARTS_AT_INVOCATION_PATH {
                    // The chain IS shut. The platform is what disqualifies it,
                    // and saying "could not determine" here would read as a
                    // broken probe rather than a stated limit.
                    format!(
                        "Every one of the {} paths on this binary's resolution chain is \
                         unwritable and unowned by the user running it — but on this platform \
                         `current_exe()` reports an already-resolved path, so a symlink the \
                         kernel traversed before the process started cannot appear on that chain \
                         at all, and a layout whose only open door is such a link would look \
                         exactly like this one.",
                        self.probes.len()
                    )
                } else {
                    "Could not determine whether this binary is writable or owned by the user \
                     running it."
                        .to_string()
                },
                "Read the result as the weaker claim: evidence of no CASUAL edit to the installed \
                 file, and nothing stronger."
                    .to_string(),
                independent,
            ],
        }
    }
}

/// What `check` found. `Missing` and `Differs` are both exit 1 — an absent
/// skill and a rewritten one are the same answer to "is the agent reading what
/// this binary shipped?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// On-disk bytes equal the bundled bytes.
    Identical,
    /// The file exists and differs.
    Differs,
    /// No file at the resolved path.
    Missing,
}

impl CheckState {
    /// The wire/word form. `identical` is what a consumer matches on.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckState::Identical => "identical",
            CheckState::Differs => "differs",
            CheckState::Missing => "missing",
        }
    }

    /// Exit 0 only when the installed copy is the bundled copy.
    pub fn exit_code(self) -> u8 {
        match self {
            CheckState::Identical => 0,
            CheckState::Differs | CheckState::Missing => 1,
        }
    }
}

/// The result of comparing the installed skill against the bundled one.
#[derive(Debug)]
pub struct CheckReport {
    /// The path examined, as the user would type it.
    pub path: PathBuf,
    pub state: CheckState,
    /// Digest of the bytes this binary carries.
    pub bundled_sha256: String,
    /// Digest of the bytes on disk, when there were any.
    pub on_disk_sha256: Option<String>,
    /// Human-readable specifics: what differs, and where.
    pub messages: Vec<String>,
    /// How much this binary's own word is worth on this machine, measured
    /// rather than assumed. Carried on every result, including a clean one —
    /// a passing check is exactly where an overstated guarantee does harm.
    pub binary: BinaryGuarantee,
}

/// Truncate a line for display so one pathological long line cannot flood a
/// terminal or an issue body.
fn clip(line: &str) -> String {
    const MAX: usize = 120;
    if line.chars().count() <= MAX {
        return line.to_string();
    }
    let head: String = line.chars().take(MAX).collect();
    format!("{head}… (+{} more chars)", line.chars().count() - MAX)
}

/// Name the differences a line-by-line comparison structurally cannot show:
/// the line terminator and the final newline.
///
/// Both are real mutations — a Windows editor rewriting `\n` to `\r\n`, a
/// script stripping the last newline — and both leave every line comparing
/// equal while the digests differ. Saying "the files differ" and stopping
/// there would send a maintainer hunting for a content edit that is not
/// present.
fn invisible_difference(bundled: &str, on_disk: &str) -> Vec<String> {
    let mut out = Vec::new();
    let crlf = |s: &str| s.matches("\r\n").count();
    let (b_crlf, d_crlf) = (crlf(bundled), crlf(on_disk));
    if b_crlf != d_crlf {
        out.push(format!(
            "line endings: bundled has {b_crlf} CRLF line ending(s), on disk {d_crlf} — \
             the file was rewritten with different line endings."
        ));
    }
    let (b_nl, d_nl) = (bundled.ends_with('\n'), on_disk.ends_with('\n'));
    if b_nl != d_nl {
        let state = |present: bool| if present { "present" } else { "absent" };
        out.push(format!(
            "trailing newline: bundled {}, on disk {}.",
            state(b_nl),
            state(d_nl)
        ));
    }
    // Neither of the two named causes fits — e.g. line endings that differ
    // per line while their totals happen to match. Say so rather than
    // inventing an explanation.
    if out.is_empty() {
        out.push(
            "the line endings differ somewhere without changing their totals; compare the raw \
             bytes with `sscsb skill print | cmp - <file>`."
                .to_string(),
        );
    }
    out
}

/// Say what differs, concretely enough to act on: the first line that changed,
/// with both sides, plus the size and line-count deltas.
///
/// A bare "files differ" makes a maintainer diff by hand against bytes they do
/// not have — the bundled copy is inside the binary. `sscsb skill print` emits
/// it, and this function names that as the way to get a full diff.
fn describe_difference(bundled: &str, on_disk: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b_lines: Vec<&str> = bundled.lines().collect();
    let d_lines: Vec<&str> = on_disk.lines().collect();

    out.push(format!(
        "size: bundled {} bytes / {} lines, on disk {} bytes / {} lines",
        bundled.len(),
        b_lines.len(),
        on_disk.len(),
        d_lines.len()
    ));

    match b_lines.iter().zip(d_lines.iter()).position(|(b, d)| b != d) {
        Some(i) => {
            out.push(format!("first difference at line {}:", i + 1));
            out.push(format!("  bundled: {}", clip(b_lines[i])));
            out.push(format!("  on disk: {}", clip(d_lines[i])));
        }
        // Same lines, same NUMBER of lines, different bytes: the edit is in
        // what sits BETWEEN and AFTER the lines. `str::lines()` splits on `\n`
        // and strips a trailing `\r`, so it is blind to exactly the two most
        // common accidental mutations a file suffers in transit — a CRLF
        // conversion and a stripped final newline. Reporting a prefix/suffix
        // delta here would print "0 line(s) missing, starting at line N+1"
        // and quote nothing, which reads as a bug in the tool rather than a
        // description of the file.
        None if b_lines.len() == d_lines.len() => {
            out.push(format!(
                "all {} line(s) are identical; the difference is not visible line by line.",
                b_lines.len()
            ));
            out.extend(invisible_difference(bundled, on_disk));
        }
        None => {
            // Every shared line matches: one side is a prefix of the other.
            let (label, extra, from) = if d_lines.len() > b_lines.len() {
                (
                    "appended to the installed copy",
                    &d_lines[b_lines.len()..],
                    b_lines.len(),
                )
            } else {
                (
                    "missing from the installed copy",
                    &b_lines[d_lines.len()..],
                    d_lines.len(),
                )
            };
            out.push(format!(
                "the first {from} line(s) are identical; {} line(s) {label}, starting at line {}:",
                extra.len(),
                from + 1
            ));
            // The first line of an appended block is very often blank —
            // injected text is usually separated from the document above it.
            // Quoting that blank line would print nothing useful, so quote the
            // first line that has content, and say where it is.
            let quoted = extra
                .iter()
                .position(|l| !l.trim().is_empty())
                .or(if extra.is_empty() { None } else { Some(0) });
            if let Some(offset) = quoted {
                out.push(format!(
                    "  line {}: {}",
                    from + offset + 1,
                    clip(extra[offset])
                ));
            }
        }
    }
    out.push(
        "`sscsb skill print` emits the bundled copy — diff against that for the full change set."
            .to_string(),
    );
    out
}

/// Compare the skill at `path` against the bundled copy.
///
/// An unreadable existing file is an operational error (`Err`, exit 2), not a
/// `Differs` verdict: "we could not look" and "it was changed" are different
/// claims, and collapsing them would report a permissions problem as tampering.
///
/// The same distinction governs ABSENCE, and `Path::exists()` cannot express
/// it: it returns `false` for every `stat` error, so a directory this user may
/// not traverse reads as "no skill installed here" — a confident negative
/// produced by a failure to look. Only `ErrorKind::NotFound` is
/// [`CheckState::Missing`]; every other error is an error.
pub fn check(path: &Path) -> Result<CheckReport> {
    let bundled_sha256 = digest(SKILL_MD.as_bytes());
    let binary = binary_guarantee();
    // `symlink_metadata` rather than `metadata`: a dangling symlink at the
    // skill's path is something rather than nothing, and reporting it as
    // "missing" would hand `install` a path it would then write THROUGH.
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CheckReport {
                path: path.to_path_buf(),
                state: CheckState::Missing,
                bundled_sha256,
                on_disk_sha256: None,
                messages: vec![
                    format!("no skill at {}", path.display()),
                    "install it with `sscsb skill install`".to_string(),
                ],
                binary,
            });
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "could not look for the installed skill at {} — this is \"we could not look\", \
                 not \"nothing is installed there\"",
                path.display()
            )));
        }
    }
    let on_disk = std::fs::read_to_string(path)
        .with_context(|| format!("could not read the installed skill at {}", path.display()))?;
    let on_disk_sha256 = digest(on_disk.as_bytes());
    if on_disk == SKILL_MD {
        return Ok(CheckReport {
            path: path.to_path_buf(),
            state: CheckState::Identical,
            bundled_sha256,
            on_disk_sha256: Some(on_disk_sha256),
            messages: vec![format!(
                "{} is byte-identical to the copy compiled into this binary",
                path.display()
            )],
            binary,
        });
    }
    let mut messages = vec![format!(
        "{} DIFFERS from the copy compiled into this binary",
        path.display()
    )];
    messages.extend(describe_difference(SKILL_MD, &on_disk));
    Ok(CheckReport {
        path: path.to_path_buf(),
        state: CheckState::Differs,
        bundled_sha256,
        on_disk_sha256: Some(on_disk_sha256),
        messages,
        binary,
    })
}

/// What an install did, or would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAction {
    /// No file was there; the skill was written.
    Created,
    /// A file was there and differed; `--force` replaced it.
    Overwritten,
    /// The installed copy already equals the bundled one. Nothing was written.
    AlreadyCurrent,
    /// A file is there and differs, and `--force` was not passed. Reachable
    /// ONLY under `--dry-run`: a real run raises this as an error (exit 2). It
    /// exists so a dry run can describe the refusal instead of performing it —
    /// `--dry-run` is documented to print the plan, and "the plan" for this
    /// state is "it would refuse".
    WouldRefuse,
}

impl InstallAction {
    pub fn as_str(self) -> &'static str {
        match self {
            InstallAction::Created => "created",
            InstallAction::Overwritten => "overwritten",
            InstallAction::AlreadyCurrent => "already-current",
            InstallAction::WouldRefuse => "would-refuse",
        }
    }

    /// The same action as a bare infinitive, for the `would …` line a dry run
    /// prints. [`as_str`](Self::as_str) is the past-tense wire word a machine
    /// consumer reads back — splicing it into a plan yielded "would created".
    pub fn verb(self) -> &'static str {
        match self {
            InstallAction::Created => "create",
            InstallAction::Overwritten => "overwrite",
            InstallAction::AlreadyCurrent => "leave alone",
            InstallAction::WouldRefuse => "refuse",
        }
    }
}

/// The outcome of an install (or of the plan a `--dry-run` printed).
#[derive(Debug)]
pub struct InstallOutcome {
    pub path: PathBuf,
    pub action: InstallAction,
    /// False when `--dry-run` was passed: nothing touched the filesystem.
    pub written: bool,
    pub messages: Vec<String>,
}

/// Write the bundled skill to `path`.
///
/// Refuses — `Err`, so exit 2 — when a DIFFERENT file already sits there and
/// `force` is false. Clobbering a maintainer's edited skill silently is the one
/// failure mode this command could plausibly have, and the refusal names both
/// the escape hatch and the command that shows what would change.
///
/// `dry_run` prints the plan for ALL FOUR states and touches nothing —
/// including the refusal, which it describes rather than performs. Refusing
/// inside a dry run would be the wet-run behaviour: the one state a reader most
/// needs a plan for is the one where a real run is about to stop.
pub fn install(path: &Path, dry_run: bool, force: bool) -> Result<InstallOutcome> {
    let report = check(path)?;
    let action = match report.state {
        CheckState::Identical => InstallAction::AlreadyCurrent,
        CheckState::Missing => InstallAction::Created,
        CheckState::Differs if force => InstallAction::Overwritten,
        CheckState::Differs if dry_run => InstallAction::WouldRefuse,
        CheckState::Differs => {
            anyhow::bail!(
                "{} exists and differs from the bundled skill — refusing to overwrite it.\n\
                 Inspect the difference with `sscsb skill check`, keep your version, or replace \
                 it deliberately with `sscsb skill install --force`.",
                path.display()
            );
        }
    };

    let mut messages = Vec::new();
    if dry_run {
        match action {
            InstallAction::AlreadyCurrent => messages.push(format!(
                "{} is already the bundled skill — nothing would be written",
                path.display()
            )),
            InstallAction::WouldRefuse => {
                messages.push(format!(
                    "would refuse: {} exists and differs from the bundled skill",
                    path.display()
                ));
                messages.push(
                    "`sscsb skill install` would exit 2 and write nothing. `--force` would \
                     replace it; `sscsb skill check` shows what would change."
                        .to_string(),
                );
            }
            InstallAction::Created | InstallAction::Overwritten => {
                messages.push(format!(
                    "would {} {} ({} bytes, sha256 {})",
                    action.verb(),
                    path.display(),
                    SKILL_MD.len(),
                    report.bundled_sha256
                ));
                if action == InstallAction::Overwritten {
                    messages.push("the existing file differs and would be replaced".to_string());
                }
            }
        }
        return Ok(InstallOutcome {
            path: path.to_path_buf(),
            action,
            written: false,
            messages,
        });
    }

    if action == InstallAction::AlreadyCurrent {
        messages.push(format!(
            "{} is already the bundled skill — nothing written",
            path.display()
        ));
        return Ok(InstallOutcome {
            path: path.to_path_buf(),
            action,
            written: false,
            messages,
        });
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("could not create the skill directory {}", parent.display())
            })?;
        }
    }
    std::fs::write(path, SKILL_MD)
        .with_context(|| format!("could not write the skill to {}", path.display()))?;
    messages.push(format!(
        "{} {} ({} bytes, sha256 {})",
        action.as_str(),
        path.display(),
        SKILL_MD.len(),
        report.bundled_sha256
    ));
    messages.push(format!(
        "`sscsb skill check` re-compares it later. Scope: {EMBEDDED_CHECK_SCOPE}. \
         For the binary itself, see {VERIFY_DOC}."
    ));
    Ok(InstallOutcome {
        path: path.to_path_buf(),
        action,
        written: true,
        messages,
    })
}

/// The YAML frontmatter block, without its `---` fences.
///
/// Returned as text rather than parsed: the repository carries no YAML
/// deserializer, and the assertions that matter (which keys exist, which do
/// not) are key-level. `None` when the document does not open with a fence.
pub fn frontmatter(doc: &str) -> Option<&str> {
    let rest = doc.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    Some(&rest[..end])
}

/// Top-level keys of the frontmatter, in order.
///
/// A top-level key is one at column zero followed by `:`. Nested keys (which
/// are indented) belong to their parent and are not reported.
pub fn frontmatter_keys(front: &str) -> Vec<&str> {
    front
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace) && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, _)| k.trim())
        .filter(|k| !k.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn the_bundled_skill_is_the_template_and_carries_frontmatter() {
        assert!(SKILL_MD.starts_with("---\n"), "the skill must open a fence");
        let front = frontmatter(SKILL_MD).expect("frontmatter parses");
        assert!(front.contains(&format!("name: {SKILL_NAME}")));
        assert_eq!(digest(SKILL_MD.as_bytes()).len(), 64);
    }

    #[test]
    fn frontmatter_returns_none_without_a_fence() {
        assert!(frontmatter("# no frontmatter\n").is_none());
        // An opening fence that never closes is not frontmatter either.
        assert!(frontmatter("---\nname: x\n").is_none());
    }

    #[test]
    fn frontmatter_keys_reports_only_top_level_keys() {
        let keys =
            frontmatter_keys("name: x\nmetadata:\n  requires:\n    bins:\n# c: 1\nhomepage: y\n");
        assert_eq!(keys, vec!["name", "metadata", "homepage"]);
    }

    #[test]
    fn check_reports_missing_when_nothing_is_installed() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        let report = check(&path).expect("check runs");
        assert_eq!(report.state, CheckState::Missing);
        assert_eq!(report.state.exit_code(), 1);
        assert_eq!(report.state.as_str(), "missing");
        assert!(report.on_disk_sha256.is_none());
        assert!(report.messages.iter().any(|m| m.contains("no skill at")));
    }

    #[test]
    fn check_reports_identical_for_a_freshly_installed_copy() {
        let dir = tmp();
        let path = dir.path().join("nested").join("SKILL.md");
        let out = install(&path, false, false).expect("install runs");
        assert_eq!(out.action, InstallAction::Created);
        assert!(out.written);
        let report = check(&path).expect("check runs");
        assert_eq!(report.state, CheckState::Identical);
        assert_eq!(report.state.exit_code(), 0);
        assert_eq!(report.state.as_str(), "identical");
        assert_eq!(
            report.on_disk_sha256.as_deref(),
            Some(report.bundled_sha256.as_str())
        );
    }

    #[test]
    fn check_names_the_line_that_a_third_party_edit_changed() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        install(&path, false, false).expect("install runs");
        // The realistic threat: another agent rewrites one line in place.
        let mut lines: Vec<String> = SKILL_MD.lines().map(str::to_string).collect();
        lines[3] = "  ATTACKER CONTROLLED".to_string();
        std::fs::write(&path, lines.join("\n")).unwrap();

        let report = check(&path).expect("check runs");
        assert_eq!(report.state, CheckState::Differs);
        assert_eq!(report.state.exit_code(), 1);
        assert_eq!(report.state.as_str(), "differs");
        assert_ne!(
            report.on_disk_sha256.as_deref(),
            Some(report.bundled_sha256.as_str())
        );
        let joined = report.messages.join("\n");
        assert!(joined.contains("DIFFERS"), "{joined}");
        assert!(joined.contains("first difference at line 4"), "{joined}");
        assert!(joined.contains("ATTACKER CONTROLLED"), "{joined}");
        assert!(joined.contains("sscsb skill print"), "{joined}");
    }

    #[test]
    fn check_describes_a_pure_append_and_a_pure_truncation() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");

        std::fs::write(&path, format!("{SKILL_MD}\nInjected instruction.\n")).unwrap();
        let appended = check(&path).expect("check runs").messages.join("\n");
        assert!(
            appended.contains("appended to the installed copy"),
            "{appended}"
        );
        assert!(appended.contains("Injected instruction."), "{appended}");

        let head: String = SKILL_MD.lines().take(10).collect::<Vec<_>>().join("\n");
        std::fs::write(&path, head).unwrap();
        let truncated = check(&path).expect("check runs").messages.join("\n");
        assert!(
            truncated.contains("missing from the installed copy"),
            "{truncated}"
        );
    }

    #[test]
    fn a_stripped_trailing_newline_is_named_not_reported_as_a_phantom_line() {
        // The commonest accidental mutation there is, and the one the earlier
        // report handled worst: it printed "0 line(s) missing … starting at
        // line N+1" and then quoted nothing at all.
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        let stripped = SKILL_MD.strip_suffix('\n').expect("the skill ends in \\n");
        std::fs::write(&path, stripped).unwrap();

        let report = check(&path).expect("check runs");
        assert_eq!(report.state, CheckState::Differs);
        let joined = report.messages.join("\n");
        assert!(joined.contains("trailing newline: bundled present, on disk absent"));
        assert!(joined.contains("not visible line by line"), "{joined}");
        // The old, wrong shape must be gone.
        // The old shape's tell — a prefix/suffix delta with nothing to quote.
        assert!(!joined.contains("starting at line"), "{joined}");
        assert!(
            !joined.contains("missing from the installed copy"),
            "{joined}"
        );
        assert!(
            !joined.contains("appended to the installed copy"),
            "{joined}"
        );
        // …and the counts it does print are still the real ones.
        assert!(
            joined.contains(&format!(
                "size: bundled {} bytes / {} lines, on disk {} bytes / {} lines",
                SKILL_MD.len(),
                SKILL_MD.lines().count(),
                stripped.len(),
                stripped.lines().count()
            )),
            "{joined}"
        );
    }

    #[test]
    fn a_crlf_conversion_is_named_as_line_endings_not_as_a_content_edit() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        let crlf = SKILL_MD.replace('\n', "\r\n");
        std::fs::write(&path, &crlf).unwrap();

        let report = check(&path).expect("check runs");
        assert_eq!(report.state, CheckState::Differs);
        let joined = report.messages.join("\n");
        // `str::lines()` strips the `\r`, so every line still compares equal.
        assert_eq!(SKILL_MD.lines().count(), crlf.lines().count());
        assert!(
            joined.contains("line endings: bundled has 0 CRLF"),
            "{joined}"
        );
        assert!(
            joined.contains(&format!("on disk {}", SKILL_MD.lines().count())),
            "{joined}"
        );
        assert!(!joined.contains("first difference at line"), "{joined}");
        // The old shape's tell — a prefix/suffix delta with nothing to quote.
        assert!(!joined.contains("starting at line"), "{joined}");
    }

    #[test]
    fn an_equal_line_count_difference_with_no_named_cause_says_so() {
        // Line endings that differ per line while their TOTALS match: two CRLF
        // each, in different places. Neither named cause fits, and the report
        // must say that rather than inventing one.
        let bundled = "a\r\nb\r\nc\nd\n";
        let on_disk = "a\nb\nc\r\nd\r\n";
        assert_eq!(bundled.lines().count(), on_disk.lines().count());
        assert_eq!(
            bundled.matches("\r\n").count(),
            on_disk.matches("\r\n").count()
        );
        let out = describe_difference(bundled, on_disk).join("\n");
        assert!(out.contains("without changing their totals"), "{out}");
        assert!(out.contains("cmp -"), "{out}");
    }

    #[test]
    fn the_verify_doc_is_an_absolute_url_the_stdout_reader_can_actually_open() {
        // `skill check`'s stdout is read by someone who may have no checkout at
        // all — a relative path is unresolvable exactly there.
        assert!(VERIFY_DOC.starts_with("https://"), "{VERIFY_DOC}");
        assert!(VERIFY_DOC.ends_with(VERIFY_DOC_PATH), "{VERIFY_DOC}");
        assert_eq!(VERIFY_DOC_PATH, "docs/skill.md");
        // Same origin as the identity a verifier pins, from the same source.
        let host_and_slug = env!("CARGO_PKG_REPOSITORY");
        assert!(VERIFY_DOC.starts_with(host_and_slug));
        assert!(CERTIFICATE_IDENTITY.starts_with(host_and_slug));
    }

    #[test]
    fn a_pathological_long_line_is_clipped_rather_than_dumped() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        let long = "x".repeat(5000);
        std::fs::write(&path, format!("---\n{long}\n")).unwrap();
        let joined = check(&path).expect("check runs").messages.join("\n");
        assert!(joined.contains("more chars)"), "{joined}");
        assert!(joined.len() < 2000, "the report must not dump 5000 chars");
    }

    #[test]
    fn install_is_idempotent_and_says_it_wrote_nothing() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        install(&path, false, false).expect("first install");
        let again = install(&path, false, false).expect("second install");
        assert_eq!(again.action, InstallAction::AlreadyCurrent);
        assert_eq!(again.action.as_str(), "already-current");
        assert!(!again.written);
        assert!(again.messages.iter().any(|m| m.contains("nothing written")));
    }

    #[test]
    fn install_refuses_to_clobber_a_modified_skill_without_force() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        std::fs::write(&path, "---\nname: sscsb\n---\nlocally edited\n").unwrap();
        let err = install(&path, false, false).expect_err("must refuse");
        let msg = format!("{err}");
        assert!(msg.contains("refusing to overwrite"), "{msg}");
        assert!(msg.contains("--force"), "{msg}");
        // The refusal must not have written anything.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "---\nname: sscsb\n---\nlocally edited\n"
        );
    }

    #[test]
    fn force_replaces_a_modified_skill() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        std::fs::write(&path, "locally edited\n").unwrap();
        let out = install(&path, false, true).expect("force installs");
        assert_eq!(out.action, InstallAction::Overwritten);
        assert_eq!(out.action.as_str(), "overwritten");
        assert!(out.written);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SKILL_MD);
        assert_eq!(InstallAction::Created.as_str(), "created");
    }

    #[test]
    fn dry_run_writes_nothing_on_either_path() {
        let dir = tmp();
        let fresh = dir.path().join("a").join("SKILL.md");
        let plan = install(&fresh, true, false).expect("plan");
        assert_eq!(plan.action, InstallAction::Created);
        assert!(!plan.written);
        assert!(!fresh.exists(), "a dry run must not create the directory");
        assert!(plan.messages.iter().any(|m| m.starts_with("would create")));

        let edited = dir.path().join("b.md");
        std::fs::write(&edited, "locally edited\n").unwrap();
        let replace = install(&edited, true, true).expect("plan");
        assert_eq!(replace.action, InstallAction::Overwritten);
        assert!(!replace.written);
        assert_eq!(
            std::fs::read_to_string(&edited).unwrap(),
            "locally edited\n"
        );
        assert!(replace
            .messages
            .iter()
            .any(|m| m.contains("would be replaced")));
    }

    #[test]
    fn an_unreadable_existing_file_is_an_error_not_a_difference() {
        // A directory at the skill's path reads as "exists" but cannot be read
        // as a string. That must surface as an operational error, never as a
        // tampering verdict.
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        std::fs::create_dir(&path).unwrap();
        let err = check(&path).expect_err("must error");
        assert!(format!("{err}").contains("could not read"));
    }

    #[test]
    fn the_scope_sentence_states_both_halves_of_the_claim() {
        assert!(EMBEDDED_CHECK_SCOPE.contains("cannot detect a tampered sscsb"));
        assert!(EMBEDDED_CHECK_SCOPE.contains("modification of the installed file"));
    }

    // ───────────────── the guarantee this binary can actually make ──────────

    /// The effective uid, without a syscall wrapper: a file this process
    /// creates is owned by it. `root` satisfies `W_OK` against every mode, so
    /// the read-only fixtures below prove nothing when the suite runs as root.
    #[cfg(unix)]
    fn running_as_root() -> bool {
        use std::os::unix::fs::MetadataExt as _;
        tempfile::NamedTempFile::new()
            .ok()
            .and_then(|f| f.as_file().metadata().ok())
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// Look up one probe by exact path.
    #[cfg(unix)]
    fn probe<'a>(g: &'a BinaryGuarantee, path: &Path) -> &'a WriteProbe {
        // Every fixture below lives under a tempdir, and on macOS `/var` is a
        // symlink to `/private/var` — the chain therefore carries the resolved
        // spelling. Resolve the PARENT and keep the final component as written:
        // canonicalizing the whole path would follow a symlink fixture through
        // to its target and look up the wrong probe.
        let want = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                .map(|p| p.join(name))
                .unwrap_or_else(|_| path.to_path_buf()),
            _ => std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
        };
        g.probes
            .iter()
            .find(|p| p.path == want || p.path == path)
            .unwrap_or_else(|| panic!("no probe for {} in {:#?}", path.display(), g.probes))
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_in_a_user_writable_directory_reports_the_weaker_guarantee() {
        // The Homebrew case, and the one the docs used to deny existed:
        // `/opt/homebrew/bin` is owned by the installing user, mode 0775, no
        // sudo anywhere. The binary is then exactly as writable as the file it
        // is checking, and saying otherwise is a false assurance.
        let dir = tmp();
        let exe = dir.path().join("sscsb");
        std::fs::write(&exe, b"not really a binary").unwrap();
        chmod(&exe, 0o755);

        let g = guarantee_for(&exe);
        assert_eq!(g.trust, BinaryTrust::UserWritable);
        assert_eq!(g.trust.as_str(), "user-writable");
        assert!(!g.trust.narrow_claim_holds());
        assert!(g.chain_complete, "{:#?}", g.probes);
        assert_eq!(probe(&g, &exe).writable, Some(true));
        assert_eq!(probe(&g, dir.path()).writable, Some(true));
        assert_eq!(probe(&g, dir.path()).role, "executable-directory");

        let said = g.statement().join(" ");
        assert!(
            said.contains("can be replaced by the user running it"),
            "{said}"
        );
        assert!(
            said.contains("no CASUAL edit and nothing stronger"),
            "{said}"
        );
        assert!(said.contains(VERIFY_DOC), "{said}");
        // …and it must NOT be the strong sentence.
        assert!(!said.contains("at full strength"), "{said}");
    }

    /// A path whose entire chain is root-owned, or `None` on a host that has
    /// none. `/bin/sh` is root-owned on macOS (and read-only under SIP) and on
    /// every Linux distribution; `/bin` there is often a symlink to
    /// `/usr/bin`, which the walk follows and probes too.
    #[cfg(unix)]
    fn root_owned_control() -> Option<PathBuf> {
        ["/bin/sh", "/usr/bin/true", "/bin/ls"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
    }

    #[cfg(unix)]
    #[test]
    fn a_root_owned_prefix_is_the_only_shape_that_can_still_earn_the_strong_claim() {
        // The control for the takeover fixtures below. Making the strong
        // verdict hard to earn must not make it unreachable-in-principle — it
        // must make it rare and correct. No fixture a TEST can build reaches it
        // any more, and that is the point rather than a limitation: a test can
        // only create files it owns, and ownership is now capability. So this
        // is measured against a real root-owned prefix.
        if running_as_root() {
            eprintln!("skipped: running as root, which satisfies W_OK against any mode");
            return;
        }
        let Some(exe) = root_owned_control() else {
            eprintln!("skipped: this host has no root-owned control binary");
            return;
        };

        let g = guarantee_for(&exe);
        assert!(g.chain_complete, "{:#?}", g.probes);
        // Both questions, answered "no", on every link. This is the condition
        // `W_OK` alone could not express: a chain can be unwritable and still
        // be one `chmod` from open.
        assert!(g.every_door_shut(), "{:#?}", g.probes);
        assert!(
            g.probes
                .iter()
                .all(|p| p.writable == Some(false) && p.owned == Some(false)),
            "{:#?}",
            g.probes
        );
        // The root directory is on the chain, which is the shape the
        // four-point probe never reached.
        assert!(
            g.probes.iter().any(|p| p.path == Path::new("/")),
            "{:#?}",
            g.probes
        );

        let said = g.statement().join(" ");
        if CHAIN_STARTS_AT_INVOCATION_PATH {
            assert_eq!(g.trust, BinaryTrust::NotUserWritable, "{:#?}", g.probes);
            assert_eq!(g.trust.as_str(), "not-user-writable");
            assert!(g.trust.narrow_claim_holds());
            assert!(
                said.contains("No path on this binary's resolution chain"),
                "{said}"
            );
            assert!(said.contains("at full strength"), "{said}");
            assert!(!said.contains("CASUAL"), "{said}");
            // Even at full strength the sentence has to name what it did not
            // check. A strong verdict that reads as a proof is the failure
            // mode this whole module keeps rediscovering.
            for m in UNCHECKED_MECHANISMS {
                let head = m.split(" — ").next().expect("a name before the dash");
                assert!(
                    said.contains(head),
                    "the strong verdict must name {head}: {said}"
                );
            }
        } else {
            // A shut chain on a platform whose `current_exe()` is already
            // resolved is NOT the strong case: a symlink the kernel traversed
            // before the process started cannot appear on the chain at all, so
            // "every door is shut" is a statement about a chain that may be
            // missing a door. The verdict must say so in its own words rather
            // than claim the probe failed.
            assert_eq!(g.trust, BinaryTrust::Unknown, "{:#?}", g.probes);
            assert!(!g.trust.narrow_claim_holds());
            assert!(said.contains("already-resolved path"), "{said}");
            assert!(said.contains("unwritable and unowned"), "{said}");
            assert!(said.contains("CASUAL"), "{said}");
        }
        // A root-owned prefix is not Homebrew, so the Homebrew sentence stays
        // out of it.
        assert!(!said.contains("brew"), "{said}");
    }

    /// The hole item 1 closes, at the level of the rule.
    ///
    /// `faccessat(W_OK)` answers "may I write this right now". POSIX lets a
    /// file's OWNER `chmod` it, so "no" to that question is not "no" to "may I
    /// make myself able to write it" — and the verdict needs the second.
    #[cfg(unix)]
    #[test]
    fn ownership_alone_opens_a_door_that_mode_bits_report_shut() {
        let owned_but_read_only = WriteProbe {
            role: "executable",
            path: PathBuf::from("/anywhere"),
            writable: Some(false),
            owned: Some(true),
        };
        assert!(owned_but_read_only.user_can_replace());
        assert!(!owned_but_read_only.shut());
        assert!(owned_but_read_only.open_because().contains("chmod"));

        // …and a door is only shut when BOTH questions were answered "no".
        // An unanswered one is not a "no".
        for unanswered in [
            WriteProbe {
                role: "executable",
                path: PathBuf::from("/anywhere"),
                writable: None,
                owned: Some(false),
            },
            WriteProbe {
                role: "executable",
                path: PathBuf::from("/anywhere"),
                writable: Some(false),
                owned: None,
            },
        ] {
            assert!(!unanswered.shut(), "{unanswered:?}");
            assert!(!unanswered.user_can_replace(), "{unanswered:?}");
            assert_eq!(unanswered.open_because(), "");
        }

        let both = WriteProbe {
            role: "executable",
            path: PathBuf::from("/anywhere"),
            writable: Some(true),
            owned: Some(true),
        };
        assert_eq!(both.open_because(), "writable and owned");
    }

    #[cfg(unix)]
    #[test]
    fn a_user_owned_binary_at_mode_0555_is_replaceable_and_says_so() {
        // PROVEN takeover, not an argument, and the THIRD consecutive round in
        // which this feature produced a checkable-but-wrong "not-user-writable".
        // A real `sscsb` release binary, user-owned at 0555 inside a user-owned
        // 0555 directory under a root-owned prefix (a mounted image, whose
        // `/Volumes` parent is root:wheel 0755), probed `writable: false` on
        // ALL FIVE links and printed `not-user-writable` with
        // `narrow_claim_holds: true`. It was then replaced twice with no
        // elevation: `chmod u+w` on the file, and `chmod u+w` on the directory
        // followed by unlink-and-recreate.
        //
        // The fixture here is the same shape minus the root-owned prefix, which
        // a test cannot build without `sudo`. What it asserts is the part that
        // matters: every mode-bit door in the fixture reads SHUT, and the
        // verdict is nevertheless the weak one, because the paths are owned.
        if running_as_root() {
            eprintln!("skipped: running as root, which owns every path by definition");
            return;
        }
        let dir = tmp();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("sscsb");
        std::fs::write(&exe, b"not really a binary").unwrap();
        chmod(&exe, 0o555);
        chmod(&bin, 0o555);

        let g = guarantee_for(&exe);
        let verdict = g.trust;
        let probes = g.probes.clone();
        let file = probe(&g, &exe).clone();
        let parent = probe(&g, &bin).clone();
        chmod(&bin, 0o755);

        assert_eq!(verdict, BinaryTrust::UserWritable, "{probes:#?}");
        assert!(!verdict.narrow_claim_holds());

        // Every path the fixture controls answers the OLD question "no" …
        //
        // Scoped to exactly the two paths this fixture chmod'd (`file` and
        // `parent`, both already resolved via `probe()`), not a `starts_with`
        // sweep of everything under the tempdir. The tempdir ROOT itself is
        // never restricted and is legitimately `writable: true` — on macOS
        // that entry silently never matched `starts_with(dir.path())` because
        // `/var` resolves to `/private/var` and the probe stores the resolved
        // form while `dir.path()` is lexical, so the mismatch masked the bug
        // there; on Linux, where `/tmp` has no such indirection, the sweep
        // included the tempdir root and failed on its legitimately-writable
        // entry. The fixture's intent was always "the two paths we chmod'd",
        // so that is what it now asserts, on every platform.
        let fixture: Vec<&WriteProbe> = probes
            .iter()
            .filter(|p| p.path == file.path || p.path == parent.path)
            .collect();
        assert!(!fixture.is_empty(), "{probes:#?}");
        assert!(
            fixture.iter().all(|p| p.writable == Some(false)),
            "the old rule saw every one of these as shut: {fixture:#?}"
        );
        // … and the NEW question "yes", which is the whole correction.
        assert!(
            fixture.iter().all(|p| p.owned == Some(true)),
            "{fixture:#?}"
        );
        assert!(fixture.iter().all(|p| p.user_can_replace()));
        assert_eq!(file.writable, Some(false));
        assert_eq!(file.owned, Some(true));
        assert_eq!(parent.writable, Some(false));
        assert_eq!(parent.owned, Some(true));

        let said = g.statement().join(" ");
        assert!(said.contains("owned by them"), "{said}");
        assert!(said.contains("an owner may chmod it"), "{said}");
        assert!(!said.contains("at full strength"), "{said}");
    }

    /// The strategic half: the strong verdict is gated on the platform, not
    /// only on the probes, and the gate is reported rather than assumed.
    #[test]
    fn the_strong_verdict_is_disqualified_where_the_chain_may_start_after_a_symlink() {
        // macOS reports the invocation path; everything else this could ship to
        // may report an already-resolved one, and Linux demonstrably does.
        assert_eq!(CHAIN_STARTS_AT_INVOCATION_PATH, cfg!(target_os = "macos"));
        assert_eq!(
            CHAIN_START,
            if CHAIN_STARTS_AT_INVOCATION_PATH {
                "invocation-path"
            } else {
                "pre-resolved"
            }
        );
        // The list a strong verdict must publish is never empty — a verdict
        // that claimed to check everything would be the false assurance in a
        // new costume.
        assert!(!UNCHECKED_MECHANISMS.is_empty());
        for m in UNCHECKED_MECHANISMS {
            assert!(
                m.contains(" — "),
                "each entry names a mechanism AND why: {m}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_writable_grandparent_is_a_replaceable_binary() {
        // PROVEN takeover, not an argument: with `prefix/bin` and the binary
        // both mode 0555, `mv bin bin.orig && mkdir bin` replaces the binary
        // using only `prefix`, which the four-point probe never looked at. It
        // printed `not-user-writable` for this exact layout.
        if running_as_root() {
            eprintln!("skipped: running as root, which satisfies W_OK against any mode");
            return;
        }
        let dir = tmp();
        let prefix = dir.path().join("prefix");
        let bin = prefix.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("sscsb");
        std::fs::write(&exe, b"not really a binary").unwrap();
        chmod(&exe, 0o555);
        chmod(&bin, 0o555);

        let g = guarantee_for(&exe);
        let verdict = g.trust;
        let probes = g.probes.clone();
        let grandparent = probe(&g, &prefix).clone();
        let parent = probe(&g, &bin).clone();
        let file = probe(&g, &exe).clone();
        chmod(&bin, 0o755);

        assert_eq!(verdict, BinaryTrust::UserWritable, "{probes:#?}");
        assert!(!verdict.narrow_claim_holds());
        // The four the old probe looked at are all shut…
        assert_eq!(parent.writable, Some(false), "{parent:?}");
        assert_eq!(file.writable, Some(false), "{file:?}");
        // …and the one it never looked at is the open door.
        assert_eq!(grandparent.writable, Some(true), "{grandparent:?}");
        assert_eq!(grandparent.role, "ancestor-directory");
    }

    #[cfg(unix)]
    #[test]
    fn a_repointed_intermediate_symlink_is_a_replaceable_binary() {
        // Homebrew's own shape: `bin/<f> -> ../opt/<f>/bin/<f>` and
        // `opt/<f> -> ../Cellar/<f>/<version>`. `canonicalize` resolves
        // straight past the middle link, so a four-point probe never sees
        // `opt/`, and repointing `opt/<f>` swaps the binary with nothing
        // elevated. PROVEN: the binary that printed `not-user-writable` for
        // this layout was replaced through exactly that link.
        if running_as_root() {
            eprintln!("skipped: running as root, which satisfies W_OK against any mode");
            return;
        }
        let dir = tmp();
        let prefix = dir.path().join("prefix");
        let versioned = prefix.join("Cellar").join("sscsb").join("0.3.1");
        std::fs::create_dir_all(versioned.join("bin")).unwrap();
        let real = versioned.join("bin").join("sscsb");
        std::fs::write(&real, b"not really a binary").unwrap();

        let opt = prefix.join("opt");
        let bin = prefix.join("bin");
        std::fs::create_dir_all(&opt).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let middle = opt.join("sscsb");
        std::os::unix::fs::symlink("../Cellar/sscsb/0.3.1", &middle).unwrap();
        let exe = bin.join("sscsb");
        std::os::unix::fs::symlink("../opt/sscsb/bin/sscsb", &exe).unwrap();

        // Everything read-only EXCEPT `opt/`, the directory holding the link.
        chmod(&real, 0o555);
        for d in [
            versioned.join("bin"),
            versioned.clone(),
            prefix.join("Cellar").join("sscsb"),
            prefix.join("Cellar"),
            bin.clone(),
        ] {
            chmod(&d, 0o555);
        }

        let g = guarantee_for(&exe);
        let verdict = g.trust;
        let probes = g.probes.clone();
        let opt_probe = probe(&g, &opt).clone();
        let middle_probe = probe(&g, &middle).clone();
        let bin_probe = probe(&g, &bin).clone();
        let resolved = g.resolved.clone();
        for d in [
            versioned.join("bin"),
            versioned.clone(),
            prefix.join("Cellar").join("sscsb"),
            prefix.join("Cellar"),
            bin.clone(),
        ] {
            chmod(&d, 0o755);
        }

        assert_eq!(verdict, BinaryTrust::UserWritable, "{probes:#?}");
        assert!(!verdict.narrow_claim_holds());
        assert!(resolved.is_some(), "the symlink chain must resolve");
        // The four the old probe looked at were all shut: the link follows to
        // the read-only Cellar file, and its own directory is 0555.
        assert_eq!(bin_probe.writable, Some(false), "{bin_probe:?}");
        // The middle link is ON the chain — it was invisible before — and the
        // directory holding it is the open door.
        assert_eq!(middle_probe.role, "symlink", "{middle_probe:?}");
        assert_eq!(opt_probe.writable, Some(true), "{opt_probe:?}");
        // …and a Cellar path on the chain earns the Homebrew sentence, which
        // must NOT be printed for chains that have nothing to do with brew.
        assert!(
            g.statement().join(" ").contains("brew"),
            "{:?}",
            g.statement()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_is_reported_rather_than_walked_forever() {
        let dir = tmp();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();

        let g = guarantee_for(&a);
        assert!(!g.chain_complete, "{:#?}", g.probes);
        assert!(!g.trust.narrow_claim_holds());
        // Both links are on the chain; the walk stopped, it did not hang.
        assert_eq!(probe(&g, &a).role, "executable-symlink");
        assert_eq!(probe(&g, &b).role, "symlink");
    }

    #[test]
    fn an_unresolvable_chain_never_earns_the_strong_claim() {
        // A path that is not there cannot be walked to the end, so the verdict
        // may never be the strong one — whatever the ancestors say.
        let dir = tmp();
        let g = guarantee_for(&dir.path().join("nope").join("sscsb"));
        assert!(!g.trust.narrow_claim_holds());
        assert!(!g.chain_complete, "{:#?}", g.probes);
        assert!(g.probes.iter().any(|p| p.role == "unresolved-chain"));

        // Nothing to walk at all — the shape a failing `current_exe()`
        // produces — is Unknown, never the strong claim by default.
        let none = guarantee_for(Path::new(""));
        assert_eq!(none.trust, BinaryTrust::Unknown);
        assert_eq!(none.trust.as_str(), "unknown");
        assert!(none.probes.is_empty());
        let said = none.statement().join(" ");
        assert!(said.contains("Could not determine"), "{said}");
        assert!(said.contains("no CASUAL edit"), "{said}");
    }

    #[cfg(unix)]
    #[test]
    fn the_homebrew_sentence_is_only_printed_for_a_homebrew_chain() {
        // It used to be appended to EVERY user-writable verdict. A binary in
        // `/tmp` printed a sentence about a package manager that had nothing
        // to do with it.
        let dir = tmp();
        let exe = dir.path().join("sscsb");
        std::fs::write(&exe, b"not really a binary").unwrap();
        let plain = guarantee_for(&exe);
        assert_eq!(plain.trust, BinaryTrust::UserWritable);
        assert!(
            !plain.statement().join(" ").contains("brew"),
            "{:?}",
            plain.statement()
        );

        let cellar = dir.path().join("Cellar").join("sscsb").join("0.3.1");
        std::fs::create_dir_all(&cellar).unwrap();
        let brewed = cellar.join("sscsb");
        std::fs::write(&brewed, b"not really a binary").unwrap();
        assert!(guarantee_for(&brewed)
            .statement()
            .join(" ")
            .contains("brew"));
    }

    #[test]
    fn every_check_result_carries_the_binarys_own_guarantee() {
        let dir = tmp();
        let path = dir.path().join("SKILL.md");
        // Missing, identical and differs alike — a PASSING check is exactly
        // where an overstated guarantee does harm.
        assert!(!check(&path).unwrap().binary.probes.is_empty());
        install(&path, false, false).unwrap();
        let ok = check(&path).unwrap();
        assert!(!ok.binary.statement().is_empty());
        std::fs::write(&path, "locally edited\n").unwrap();
        assert!(!check(&path).unwrap().binary.statement().is_empty());
        // The test binary lives under target/, which the user running the suite
        // owns — so this run must report the weaker reading, not the stronger.
        let running = binary_guarantee();
        assert_eq!(running.trust, BinaryTrust::UserWritable);
        // …and the guarantee it carries is a CHAIN, not four points: the
        // filesystem root is on it.
        assert!(
            running.probes.iter().any(|p| p.path == Path::new("/")),
            "{:#?}",
            running.probes
        );
        assert!(running.probes.len() > 4, "{:#?}", running.probes);
    }

    // ──────────── "could not look" is not "definitely not there" ────────────

    #[cfg(unix)]
    #[test]
    fn an_unstattable_path_is_an_error_not_a_confident_missing() {
        // `Path::exists()` returns false on ANY stat error, so a parent
        // directory this user cannot traverse used to print "no skill at …" —
        // a confident negative produced by a failure to look, in the one
        // command whose whole point is keeping those apart.
        if running_as_root() {
            eprintln!("skipped: running as root, which can traverse a 0o000 directory");
            return;
        }
        let dir = tmp();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let path = locked.join("SKILL.md");
        std::fs::write(&path, SKILL_MD).unwrap();
        chmod(&locked, 0o000);

        let result = check(&path);
        chmod(&locked, 0o755);

        let err = result.expect_err("an unreadable parent must not report `missing`");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not look for the installed skill"),
            "{msg}"
        );
        assert!(msg.contains("not \"nothing is installed there\""), "{msg}");
    }

    #[test]
    fn a_truly_absent_file_is_still_missing() {
        let dir = tmp();
        let report = check(&dir.path().join("gone").join("SKILL.md")).expect("check runs");
        assert_eq!(report.state, CheckState::Missing);
    }

    // ─────────────────── --dry-run prints a plan, always ────────────────────

    #[test]
    fn dry_run_prints_a_plan_in_all_four_states() {
        let dir = tmp();

        // 1. missing
        let fresh = dir.path().join("a").join("SKILL.md");
        let plan = install(&fresh, true, false).expect("plan");
        assert_eq!(plan.action, InstallAction::Created);
        assert!(!plan.written && !fresh.exists());
        // The exact verb: `as_str()` is the past-tense WIRE word, and splicing
        // that into the plan printed "would created" for a whole round.
        assert!(
            plan.messages
                .iter()
                .any(|m| m.starts_with(&format!("would create {}", fresh.display()))),
            "{:?}",
            plan.messages
        );

        // 2. identical
        let same = dir.path().join("b.md");
        install(&same, false, false).expect("install");
        let plan = install(&same, true, false).expect("plan");
        assert_eq!(plan.action, InstallAction::AlreadyCurrent);
        assert!(!plan.written);
        assert!(
            plan.messages
                .iter()
                .any(|m| m.contains("nothing would be written")),
            "{:?}",
            plan.messages
        );

        // 3. differs, --force
        let edited = dir.path().join("c.md");
        std::fs::write(&edited, "locally edited\n").unwrap();
        let plan = install(&edited, true, true).expect("plan");
        assert_eq!(plan.action, InstallAction::Overwritten);
        assert!(!plan.written);
        assert!(
            plan.messages
                .iter()
                .any(|m| m.starts_with(&format!("would overwrite {}", edited.display()))),
            "{:?}",
            plan.messages
        );
        assert!(plan
            .messages
            .iter()
            .any(|m| m.contains("would be replaced")));
        // No message may splice a past-tense wire word into a future plan.
        for m in &plan.messages {
            assert!(
                !m.contains("would created") && !m.contains("would overwritten"),
                "{m}"
            );
        }

        // 4. differs, NO --force — the state that used to take the refusal
        //    path and print no plan at all. Refusing is the wet-run behaviour.
        let plan = install(&edited, true, false).expect("a dry run must not refuse");
        assert_eq!(plan.action, InstallAction::WouldRefuse);
        assert_eq!(plan.action.as_str(), "would-refuse");
        assert!(!plan.written);
        let said = plan.messages.join("\n");
        assert!(said.contains("would refuse"), "{said}");
        assert!(said.contains("would exit 2 and write nothing"), "{said}");
        assert!(said.contains("--force"), "{said}");
        assert_eq!(
            std::fs::read_to_string(&edited).unwrap(),
            "locally edited\n",
            "every dry run must leave the file untouched"
        );

        // …and the real run still refuses, loudly.
        let err = install(&edited, false, false).expect_err("a real run must refuse");
        assert!(format!("{err}").contains("refusing to overwrite"));
    }
}
