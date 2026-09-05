//! The bundled agent skill's contract, asserted rather than described.
//!
//! `docs/skill.md` carries a fenced ```contract block that is the ONLY
//! normative statement of the skill surface: the command, the four paths a copy
//! of the file lives at, the Sigstore identity a release asset is verified
//! against, and the exact scope of what the in-binary comparison establishes.
//!
//! Three classes of claim are pinned, the same three the local lane pins in
//! `tests/local_scan_docs.rs`:
//!
//! - **Contract**: every line of the block equals the constant the binary
//!   actually uses, and the block's digest is pinned so an unreviewed edit to
//!   either side fails here.
//! - **Strength**: the doc must state both claims at their real strength — the
//!   in-binary check cannot detect a tampered binary, and a verified release
//!   asset proves origin, not benignity. Dropping either turns an honest narrow
//!   claim into a false one, which is worse than no claim at all.
//! - **It runs**: the commands the contract names are EXECUTED here — install,
//!   print, check, a corrupted check — against real bytes on a real filesystem,
//!   rather than being asserted to exist.
//!
//! Plus the two drift guards: the installed copy in this repository is the
//! template byte-for-byte, and every `sscsb` command the skill names is a
//! command the binary actually has (in both directions).

use assert_cmd::Command;
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::path::Path;

const SKILL_DOC_MD: &str = include_str!("../docs/skill.md");
const TEMPLATE_SKILL_MD: &str = include_str!("../templates/skills/sscsb/SKILL.md");
const INSTALLED_SKILL_MD: &str = include_str!("../.claude/skills/sscsb/SKILL.md");
const README_MD: &str = include_str!("../README.md");
const CHANGELOG_MD: &str = include_str!("../CHANGELOG.md");
const AGENTS_MD: &str = include_str!("../AGENTS.md");
const SKILL_RS: &str = include_str!("../src/skill.rs");

/// The digest pinned over the normalized contract block.
///
/// Computed as `sha256("<key>=<value>\n" …)` over the block's lines sorted by
/// key, header excluded — the same normalization `tests/local_scan_docs.rs`
/// uses, so the two contract guards are read the same way.
const CONTRACT_DIGEST: &str = "38feceb5187b75e74a2596330084d090e72de6a8275dc98fe43fd690cb97ff8f";

const CONTRACT_HEADER: &str = "sscsb skill contract v1";

/// Parse the fenced ```contract block: `key`, two-or-more spaces, `value`.
fn contract() -> BTreeMap<String, String> {
    let body = SKILL_DOC_MD
        .split("```contract\n")
        .nth(1)
        .expect("docs/skill.md must carry a fenced ```contract block")
        .split("\n```")
        .next()
        .expect("the contract block must be closed");
    let mut lines = body.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(
        lines.next(),
        Some(CONTRACT_HEADER),
        "the contract block must open with its version header"
    );
    let mut out = BTreeMap::new();
    for line in lines {
        let mut parts = line.trim_end().splitn(2, "  ");
        let key = parts.next().unwrap().trim().to_string();
        let value = parts
            .next()
            .unwrap_or_else(|| panic!("contract line `{line}` has no value"))
            .trim()
            .to_string();
        assert!(
            out.insert(key.clone(), value).is_none(),
            "contract key `{key}` is declared twice"
        );
    }
    out
}

fn contract_value(key: &str) -> String {
    contract()
        .get(key)
        .unwrap_or_else(|| panic!("the contract has no `{key}` line"))
        .clone()
}

/// The document with every run of whitespace collapsed to one space, so a claim
/// can be asserted as the sentence it is rather than as the lines the author
/// happened to wrap it into. Blockquote markers are stripped first: both claims
/// are published as pull-quotes.
fn unwrapped(doc: &str) -> String {
    doc.lines()
        .map(|l| l.trim_start().strip_prefix('>').unwrap_or(l))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn assert_states(doc_name: &str, doc: &str, claim: &str) {
    assert!(
        unwrapped(doc).contains(&unwrapped(claim)),
        "{doc_name} must state: {claim}"
    );
}

// ────────────────────────── the release, replayed ───────────────────────────
//
// Three separate statements in `docs/skill.md`, one in `README.md` and one in
// the skill itself are statements about COUNTS — how many files carry a Cosign
// bundle, how many carry none, how many are signed but not attested. Every one
// of them said "two", which was a count of SHAPES read as a count of FILES: a
// release publishes eight bundles, not one, and three `.sha256` sidecars, not
// one. A heading contradicted its own body.
//
// Counts cannot be asserted from memory, so they are not asserted at all here:
// the release is REPLAYED from `release.yml`'s own rules — the build matrix,
// the exact-count guard, the checksum loop, the literal files staged into
// `dist/`, the signing loop's skip pattern and the subject-set exclusion — and
// every documented number is checked against what that yields. Change the
// fan-out and this test fails the documents rather than letting them rot.

fn workflow(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("{path} is readable: {e}"))
}

/// The patterns of the first `case "$f" in …)` under the step named `after`.
fn case_patterns(text: &str, after: &str) -> Vec<String> {
    let at = text
        .find(after)
        .unwrap_or_else(|| panic!("the workflow must contain the step named `{after}`"));
    text[at..]
        .lines()
        .find(|l| l.trim_start().starts_with("case \"$f\" in"))
        .unwrap_or_else(|| panic!("`{after}` must classify files with a `case`"))
        .split_once(" in ")
        .expect("a `case … in …` line")
        .1
        .split(')')
        .next()
        .expect("a `case` pattern")
        .split('|')
        .map(|p| p.trim().to_string())
        .collect()
}

/// The only two shapes these workflows use: `*.suffix`, or a literal name.
fn matches(name: &str, pattern: &str) -> bool {
    match pattern.strip_prefix('*') {
        Some(suffix) => name.ends_with(suffix),
        None => name == pattern,
    }
}

/// Every literal `dist/<file>` the release job stages — the extra assets. The
/// tarball template (`dist/sscsb-${GITHUB_REF_NAME}-…`) and the globs are not
/// literals and are excluded by shape, not by name.
fn literal_dist_files(yml: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (i, _) in yml.match_indices("dist/") {
        let rest = &yml[i + "dist/".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || "._-*".contains(*c))
            .collect();
        let next = rest[name.len()..].chars().next().unwrap_or(' ');
        if name.is_empty() || name.contains('*') || !name.contains('.') || next == '$' {
            continue;
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// What a release publishes, and which trail covers each file.
struct Replay {
    /// One per build-matrix target.
    tarballs: usize,
    /// Everything the published release holds.
    assets: Vec<String>,
    /// The files the Cosign loop signs — one `*.sigstore.json` bundle each.
    signed: Vec<String>,
    /// The files the single subject list covers.
    attested: Vec<String>,
}

impl Replay {
    fn total(&self) -> usize {
        self.assets.len()
    }
    fn with_bundle(&self) -> usize {
        self.signed.len()
    }
    fn without_bundle(&self) -> usize {
        self.total() - self.signed.len()
    }
    fn attested(&self) -> usize {
        self.attested.len()
    }
    fn signed_not_attested(&self) -> usize {
        self.signed
            .iter()
            .filter(|f| !self.attested.contains(f))
            .count()
    }
}

fn replay() -> Replay {
    let yml = workflow(".github/workflows/release.yml");

    // 1. the build fan-out — one tarball per matrix target, and the release job
    //    refuses to continue unless it collected exactly that many.
    let targets: Vec<String> = yml
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- target: "))
        .map(|t| t.trim().to_string())
        .collect();
    assert!(
        !targets.is_empty(),
        "release.yml must declare build-matrix targets"
    );
    let required: usize = yml
        .lines()
        .find_map(|l| l.trim().strip_prefix("if [ ${#artifacts[@]} -ne "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("release.yml must assert an EXACT tarball count");
    assert_eq!(
        targets.len(),
        required,
        "the matrix builds {} tarballs and the guard demands {required}",
        targets.len()
    );

    // The tag is irrelevant to every count; only the shape of the names is.
    let tag = "v0.0.0";
    let mut assets: Vec<String> = targets
        .iter()
        .map(|t| format!("sscsb-{tag}-{t}.tar.gz"))
        .collect();

    // 2. one `.sha256` sidecar per tarball.
    assert!(
        yml.contains(r#"for f in *.tar.gz; do sha256sum "$f" > "$f.sha256"; done"#),
        "release.yml must checksum every tarball into a sidecar"
    );
    let sidecars: Vec<String> = assets.iter().map(|t| format!("{t}.sha256")).collect();
    assets.extend(sidecars);

    // 3. every literal file staged into dist/ — SKILL.md and the SBOM.
    let extras = literal_dist_files(&yml);
    assert!(
        extras.contains(&sscsb::skill::ASSET_NAME.to_string()),
        "the replay lost the skill asset: {extras:?}"
    );
    assets.extend(extras);

    // 4. the signing loop signs everything in dist/ but its own bundles.
    let skip = case_patterns(&yml, "Keyless sign all artifacts");
    let signed: Vec<String> = assets
        .iter()
        .filter(|f| !skip.iter().any(|p| matches(f, p)))
        .cloned()
        .collect();
    assets.extend(
        signed
            .iter()
            .map(|f| format!("{f}{}", sscsb::skill::BUNDLE_SUFFIX)),
    );

    // 5. the SLSA generator's envelope, collected by `publish`. Exactly one —
    //    the gate refuses any other number.
    let gate = workflow(".github/workflows/deploy-gate.yml");
    assert!(
        gate.contains("if [ ${#provenance[@]} -ne 1 ]; then"),
        "the gate must require exactly one provenance envelope"
    );
    assets.push("sscsb.intoto.jsonl".to_string());

    // 6. the ONE subject set, by the name rule the publisher and the gate share.
    let excluded = case_patterns(&yml, "Compute the release subject set");
    let attested: Vec<String> = assets
        .iter()
        .filter(|f| !excluded.iter().any(|p| matches(f, p)))
        .cloned()
        .collect();

    Replay {
        tarballs: targets.len(),
        assets,
        signed,
        attested,
    }
}

#[test]
fn the_replay_reproduces_the_release_this_repository_actually_ships() {
    // The replay is the measuring stick for every count below, so its own
    // shape is asserted first — a broken replay would silently agree with a
    // broken document.
    let r = replay();
    assert_eq!(r.tarballs, 3, "the build fan-out changed: {:?}", r.assets);
    assert_eq!(r.total(), 17, "{:#?}", r.assets);
    assert_eq!(r.with_bundle(), 8);
    assert_eq!(r.without_bundle(), 9);
    assert_eq!(r.attested(), 4);
    assert_eq!(r.signed_not_attested(), 4);
    // …and the names, so a rename cannot keep the arithmetic while changing
    // which files it is about.
    let mut attested = r.attested.clone();
    attested.sort();
    assert_eq!(
        attested,
        vec![
            "SKILL.md",
            "sscsb-v0.0.0-aarch64-apple-darwin.tar.gz",
            "sscsb-v0.0.0-x86_64-apple-darwin.tar.gz",
            "sscsb-v0.0.0-x86_64-unknown-linux-gnu.tar.gz",
        ]
    );
    let mut unattested: Vec<&String> = r
        .signed
        .iter()
        .filter(|f| !r.attested.contains(f))
        .collect();
    unattested.sort();
    assert_eq!(
        unattested,
        vec![
            "sbom.cdx.json",
            "sscsb-v0.0.0-aarch64-apple-darwin.tar.gz.sha256",
            "sscsb-v0.0.0-x86_64-apple-darwin.tar.gz.sha256",
            "sscsb-v0.0.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
        ]
    );
}

#[test]
fn every_counting_claim_is_the_count_the_release_actually_produces() {
    let r = replay();
    let (total, bundled, bare) = (r.total(), r.with_bundle(), r.without_bundle());
    let (attested, unattested, tarballs) = (r.attested(), r.signed_not_attested(), r.tarballs);

    // docs/skill.md — the long-form claim, the breakdown table and the two
    // headings that used to say "two" over bodies that listed more than two.
    for claim in [
        format!("A release of this repository's current shape publishes {total} files."),
        format!("a release publishes **{total}** assets"),
        format!(
            "So **{bundled}** files carry a Cosign bundle, **{bare}** carry none, **{attested}** \
             are signed *and* attested, and **{unattested}** are signed but not attested."
        ),
        format!("That accounts for {bundled} of the {bare}."),
        format!(
            "Exactly {unattested} files in a release are signed but **not** attested: the \
             {tarballs} `.sha256` sidecars and `sbom.cdx.json`."
        ),
        format!("{total} files for a release of this repository's current shape"),
    ] {
        assert_states("docs/skill.md", SKILL_DOC_MD, &claim);
    }
    for exact in [
        format!("### The {bare} files that carry no Cosign bundle"),
        format!("### The {unattested} files that are signed but not attested"),
        // the in-page link has to follow the heading it points at
        format!("(#the-{bare}-files-that-carry-no-cosign-bundle)"),
        // the breakdown table's own rows
        format!("| platform tarballs (`*.tar.gz`) | {tarballs} | yes | yes |"),
        format!("| checksum sidecars (`*.sha256`) | {tarballs} | yes | no |"),
        format!("| Cosign bundles (`*.sigstore.json`) | {bundled} | it **is** one | no |"),
    ] {
        assert!(
            SKILL_DOC_MD.contains(&exact),
            "docs/skill.md must contain `{exact}`"
        );
    }

    // …and the two shorter surfaces a reader meets first.
    for (name, doc) in [("README.md", README_MD), ("the skill", TEMPLATE_SKILL_MD)] {
        assert_states(name, doc, &format!("A release publishes {total} files."));
    }

    // The old miscount must not survive anywhere.
    for (name, doc) in [
        ("docs/skill.md", SKILL_DOC_MD),
        ("README.md", README_MD),
        ("the skill", TEMPLATE_SKILL_MD),
    ] {
        for stale in ["all but two are keyless-signed", "The two files that"] {
            assert!(
                !unwrapped(doc).contains(stale),
                "{name} still carries the miscount `{stale}`"
            );
        }
    }
}

/// The `*.intoto.jsonl` envelope is signed by the SLSA generator's own workflow
/// at the generator's own tag — not by `release.yml` at ours.
///
/// "Every file in an `sscsb` release carries a signature minted at its tag"
/// attributed one signer to all 17 assets, which is wrong for exactly the one
/// asset a reader is most likely to mis-verify: pinning our
/// `--certificate-identity` against the envelope pins the wrong signer, and the
/// failure looks like tampering rather than like a mistake in the recipe.
#[test]
fn every_surface_names_both_signers_not_one() {
    let r = replay();
    let (total, bundled) = (r.total(), r.with_bundle());
    // Derived, not restated: everything but the single SLSA envelope.
    let ours = total - 1;

    let split = format!(
        "{ours} of the {total} are signed at *our* tag by `.github/workflows/release.yml` — \
         {bundled} keyless-signed into a `*.sigstore.json` bundle, plus those {bundled} bundles, \
         each of which *is* such a signature."
    );
    let other = "The 17th, the `*.intoto.jsonl` envelope, is signed by the SLSA generator's own \
                 workflow at the generator's own tag, not by ours — `slsa-verifier --builder-id` \
                 is what checks that signature, and pinning our `release.yml` identity against it \
                 would be pinning the wrong signer.";
    // The literal "17th" above is the only place a count is spelled rather than
    // derived, so hold it to the replay.
    assert!(
        other.contains(&format!("The {total}th")),
        "the second-signer sentence names a file number the replay does not produce"
    );

    for (name, doc) in [
        ("docs/skill.md", SKILL_DOC_MD),
        ("README.md", README_MD),
        ("the skill", TEMPLATE_SKILL_MD),
    ] {
        assert_states(name, doc, &split);
        assert_states(name, doc, other);
        // …and the false absolute must be gone.
        assert!(
            !unwrapped(doc).contains(
                "Every file in an `sscsb` release carries a signature minted \
                                      at its tag"
            ),
            "{name} still attributes one signer to every asset"
        );
    }
}

/// `SKILL.md` is staged and signed by `release.yml`, but no PUBLISHED tag
/// carries it: the recipe's own worked example (`TAG=v0.3.1`) returns "no such
/// file or directory" from step 3 while every step around it works, which reads
/// as the reader's mistake rather than as a gap.
///
/// This test exists to keep the disclosure in place until the asset is real. It
/// is deliberately a presence check, not a network call — a doc test that
/// queried GitHub would be flaky and would not run offline.
#[test]
fn every_surface_showing_the_recipe_discloses_that_the_asset_is_not_published_yet() {
    const WHEN_TO_DELETE: &str =
        "delete this hedge only once a release contains SKILL.md — check with \
         `gh release view <tag> --json assets`, and remove it from EVERY surface at once \
         (docs/skill.md, README.md, templates/skills/sscsb/SKILL.md, AGENTS.md) together with \
         this test and the sscsb::skill constants it reads";

    for (name, doc) in [
        ("docs/skill.md", SKILL_DOC_MD),
        ("README.md", README_MD),
        ("the skill", TEMPLATE_SKILL_MD),
        ("AGENTS.md", AGENTS_MD),
    ] {
        assert!(
            unwrapped(doc).contains(sscsb::skill::ASSET_PENDING_NOTICE),
            "{name} must state `{}` — {WHEN_TO_DELETE}",
            sscsb::skill::ASSET_PENDING_NOTICE
        );
        assert!(
            unwrapped(doc).contains(sscsb::skill::ASSET_PENDING_FIRST_TAG),
            "{name} states the gap without stating when it ends; it must also say `{}` — \
             {WHEN_TO_DELETE}",
            sscsb::skill::ASSET_PENDING_FIRST_TAG
        );
    }

    // The document must also tell the reader what they CAN run today, or the
    // disclosure is a dead end.
    for claim in [
        "3 — `cosign verify-blob` | yes, with a platform tarball substituted for `SKILL.md`",
        "4 — the closure loop | yes, over the whole published set",
    ] {
        assert!(
            SKILL_DOC_MD.contains(claim),
            "docs/skill.md must say which steps are runnable against a published tag: `{claim}`"
        );
    }

    // A hedge that arrives after the claim it qualifies has already been read
    // is not a hedge. `docs/skill.md` asserted twice that a release publishes
    // 17 assets — flatly, in reading order, hundreds of lines BEFORE the
    // section explaining that `SKILL.md` is not among them yet — so a reader
    // going front-to-back learned the count as fact and only later learned it
    // was aspirational. Every count claim must be qualified at or before its
    // FIRST use.
    let flat = unwrapped(SKILL_DOC_MD);
    let first_notice = flat
        .find(sscsb::skill::ASSET_PENDING_NOTICE)
        .expect("the notice is asserted above");
    let first_count = ["publishes 17 ", "publishes **17** "]
        .iter()
        .filter_map(|n| flat.find(n))
        .min()
        .expect("docs/skill.md states the asset count");
    assert!(
        first_notice < first_count,
        "docs/skill.md states the release asset count at byte {first_count} but does not \
         disclose that `SKILL.md` is not a release asset yet until byte {first_notice} — \
         qualify the count at first use, or move the disclosure above it. {WHEN_TO_DELETE}"
    );

    // …and the release.yml staging that makes the promise true is still there,
    // so the hedge cannot outlive a pipeline that stopped shipping the asset.
    let yml = workflow(".github/workflows/release.yml");
    assert!(
        literal_dist_files(&yml).contains(&sscsb::skill::ASSET_NAME.to_string()),
        "release.yml no longer stages {} — the hedge promises a release that will never come",
        sscsb::skill::ASSET_NAME
    );
}

// ─────────────────────────────── the contract ───────────────────────────────

#[test]
fn the_contract_blocks_digest_is_the_one_this_tree_pins() {
    let normalized: String = contract()
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    let got = hex::encode(sha2::Sha256::digest(normalized.as_bytes()));
    assert_eq!(
        got, CONTRACT_DIGEST,
        "the contract block changed. Review the change, then update \
         CONTRACT_DIGEST.\nnormalized block:\n{normalized}"
    );
}

#[test]
fn every_contract_line_is_the_value_the_binary_actually_uses() {
    let c = contract();
    let expect = |key: &str, want: String| {
        assert_eq!(
            c.get(key).map(String::as_str),
            Some(want.as_str()),
            "contract line `{key}` disagrees with the binary"
        );
    };
    expect("command", sscsb::skill::COMMAND.to_string());
    expect("template-path", sscsb::skill::TEMPLATE_PATH.to_string());
    expect("installed-path", sscsb::skill::SKILL_PATH.to_string());
    expect("asset-path", sscsb::skill::ASSET_NAME.to_string());
    expect(
        "bundle-path",
        format!(
            "{}{}",
            sscsb::skill::ASSET_NAME,
            sscsb::skill::BUNDLE_SUFFIX
        ),
    );
    expect(
        "certificate-identity",
        sscsb::skill::CERTIFICATE_IDENTITY.to_string(),
    );
    expect(
        "certificate-oidc-issuer",
        sscsb::skill::OIDC_ISSUER.to_string(),
    );
    expect(
        "attestation-predicate",
        sscsb::skill::ATTESTATION_PREDICATE.to_string(),
    );
    expect(
        "embedded-check-scope",
        sscsb::skill::EMBEDDED_CHECK_SCOPE.to_string(),
    );
    assert_eq!(c.len(), 9, "the contract gained or lost a line: {c:?}");
}

#[test]
fn the_certificate_identity_names_the_workflow_that_actually_signs() {
    // The identity is only as good as the workflow it names. `release.yml` is
    // where the all-files `cosign sign-blob` loop lives, and `deploy-gate.yml`
    // assembles the same identity from its `SIGNER_WORKFLOW` input.
    let identity = contract_value("certificate-identity");
    assert!(
        identity.contains(sscsb::skill::SIGNER_WORKFLOW),
        "the identity must name {}: {identity}",
        sscsb::skill::SIGNER_WORKFLOW
    );
    assert!(
        identity.ends_with("@refs/tags/vX.Y.Z"),
        "the tag must stay a placeholder — it comes from out of band: {identity}"
    );
    let gate = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/deploy-gate.yml"),
    )
    .expect("deploy-gate.yml is readable");
    assert!(
        gate.contains(&format!("'{}'", sscsb::skill::SIGNER_WORKFLOW)),
        "deploy-gate.yml's SIGNER_WORKFLOW default drifted from the documented identity"
    );
    assert!(
        gate.contains(sscsb::skill::OIDC_ISSUER),
        "deploy-gate.yml must pin the same OIDC issuer the doc tells a verifier to pass"
    );
}

// ──────────────────────────── the claims, at strength ───────────────────────

#[test]
fn the_doc_states_the_limit_of_what_the_in_binary_check_proves() {
    for claim in [
        "It detects an edit made to the installed file after installation — by another agent, \
         a hook, or anything else on this machine.",
        "It cannot detect a tampered `sscsb`: a binary that was modified could have been \
         modified to lie here too.",
        "To check the binary itself, verify the release artifact against its Sigstore identity",
    ] {
        assert_states("docs/skill.md", SKILL_DOC_MD, claim);
    }
    // The same limit must be stated in the skill itself, where an agent reads it.
    assert_states(
        "the skill",
        TEMPLATE_SKILL_MD,
        "It cannot detect a tampered `sscsb`",
    );
}

#[test]
fn the_doc_states_the_release_claim_and_refuses_to_overstate_it() {
    for claim in [
        // Narrowed in round 3 to what the pipeline actually does — the signing
        // loop skips `*.sigstore.json`, and the `*.intoto.jsonl` is added by
        // `publish` AFTER that loop and carries the SLSA generator's own DSSE
        // signature instead — and RECOUNTED in round 4, because "all but two"
        // counted shapes and presented them as files: a release publishes eight
        // bundles, not one. The exact numbers are held by
        // `every_counting_claim_is_the_count_the_release_actually_produces`.
        // …and RE-ATTRIBUTED in round 5: "a signature minted at its tag" gave
        // one signer to all 17, which is false for the `*.intoto.jsonl`
        // envelope. Its certificate identity is the SLSA generator's OWN
        // workflow at ITS tag, so pinning our `--certificate-identity` against
        // it pins the wrong signer and the failure looks like tampering. Both
        // identities are now stated; the split is held by
        // `every_surface_names_both_signers_not_one`.
        "Every file in an `sscsb` release carries a signature, `SKILL.md` included — but not \
         all of them are signed by the same identity, and the difference is the whole point of \
         `--certificate-identity`.",
        // The half the release pipeline had to be REWIRED to make true: for a
        // while the wording asserted attestation coverage while every
        // subject-path and subject-hash glob in release.yml was scoped
        // `dist/*.tar.gz`, so SKILL.md was signed and nothing else.
        "`SKILL.md` and the platform tarballs are also subjects of that release's \
         build-provenance attestation, of its CycloneDX SBOM attestation, and of its SLSA \
         Build L3 provenance.",
        "Using tools you obtained independently of `sscsb`, you can verify that a copy is \
         byte-for-byte what that workflow published at that tag, and that no asset was altered \
         or added afterwards.",
        "That is a proof of origin, not a judgement of content: it establishes which pipeline \
         produced these bytes, not that the instructions in them are safe to follow.",
        // …and the part that is NOT covered is named, rather than left for a
        // reader to discover by checking.
        "Exactly 4 files in a release are signed but **not** attested: the 3 `.sha256` sidecars \
         and `sbom.cdx.json`.",
        // The same, for the two that carry no Cosign bundle. A reader running
        // the closure check needs to know which absences are legitimate, or
        // they will read a correct result as a finding.
        "The signing loop in `release.yml` runs over everything staged in `dist/` and skips \
         exactly one shape — `*.sigstore.json`, the bundles it is writing as it goes.",
    ] {
        assert_states("docs/skill.md", SKILL_DOC_MD, claim);
    }
    // The same two exceptions have to be stated where an agent reads them, not
    // only in the long-form doc. The exact wording is held by
    // `every_surface_names_both_signers_not_one`; this is the presence check.
    for doc in [("the skill", TEMPLATE_SKILL_MD), ("README.md", README_MD)] {
        assert_states(
            doc.0,
            doc.1,
            "Every file in an `sscsb` release carries a signature — but not all of them from \
             the same signer.",
        );
    }
    // Risk 1, named outright. A reader must not be able to infer safety from a
    // green cosign, and the doc has to say so in its own words.
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "Provenance is not benignity.",
    );
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "A compromised repository cutting a release produces a perfectly verifiable malicious \
         skill",
    );
}

#[test]
fn the_doc_states_the_writability_boundary_conditionally_and_names_homebrew() {
    // The sentence that justified this whole feature used to be an absolute:
    // the installed skill is writable by every agent on the machine, "none of
    // which can write `/usr/local/bin/sscsb`". That is true of a root-owned
    // prefix and FALSE of `brew install`, which the README recommends first —
    // `/opt/homebrew/bin` is owned by the installing user, mode 0775, and the
    // binary there is a symlink anyone can repoint without sudo. For most
    // readers the binary was exactly as writable as the file it checks, and the
    // asymmetry the feature rests on did not exist.
    for claim in [
        "Nothing running as you replaces that binary without `sudo`, and the narrow claim holds \
         exactly as stated",
        "**By Homebrew** — the install this repository's README recommends *first* — it does not \
         hold.",
        "There the binary is *exactly* as writable as the file it checks, one attacker holds \
         both, and a clean result is evidence of no **casual** edit and nothing stronger.",
        // …and the reader is pointed at the trust root that is not this binary.
        "For that there is exactly one trust root in this document that is not this binary — the \
         release asset's Sigstore identity",
    ] {
        assert_states("docs/skill.md", SKILL_DOC_MD, claim);
    }
    // The agent-facing copy and the changelog carry the conditional too — an
    // agent reads the skill, not this document.
    assert_states(
        "the skill",
        TEMPLATE_SKILL_MD,
        "On a `brew`-installed `sscsb` the answer is usually `user-writable`",
    );
    assert_states(
        "CHANGELOG.md",
        CHANGELOG_MD,
        "By Homebrew — the install path the README recommends first — it usually could",
    );

    // The false absolute must be gone from every surface that carried it,
    // including the source.
    for (name, doc) in [
        ("docs/skill.md", SKILL_DOC_MD),
        ("README.md", README_MD),
        ("the skill", TEMPLATE_SKILL_MD),
        ("CHANGELOG.md", CHANGELOG_MD),
        ("src/skill.rs", SKILL_RS),
    ] {
        assert!(
            !unwrapped(doc).contains("none of which can write `/usr/local/bin/sscsb`"),
            "{name} still claims nothing that can write the skill can write the binary"
        );
        assert!(
            !unwrapped(doc).contains("`/usr/local/bin/sscsb` is not"),
            "{name} still states the writability asymmetry as an absolute"
        );
    }
}

#[test]
fn check_measures_its_own_binarys_writability_and_reports_it_in_both_formats() {
    // Prose alone would have been a fix to the wording of a false sentence.
    // The tool has to tell the truth at run time, on the machine it is on.
    let dir = repo();
    let root = dir.path();
    assert_eq!(
        sscsb_bin(root, &["skill", "install"]).status.code(),
        Some(0)
    );

    let text = sscsb_bin(root, &["skill", "check"]);
    assert_eq!(text.status.code(), Some(0));
    let out = String::from_utf8_lossy(&text.stdout);
    assert!(out.contains("binary trust"), "{out}");

    let json = sscsb_bin(root, &["skill", "check", "--format", "json"]);
    let doc: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    let binary = &doc["binary"];
    let trust = binary["trust"].as_str().expect("a trust verdict");

    // The three verdicts the binary can emit are the three the document's table
    // explains — neither side may gain one silently.
    let verdicts = ["not-user-writable", "user-writable", "unknown"];
    assert!(verdicts.contains(&trust), "{binary}");
    for v in verdicts {
        assert!(
            SKILL_DOC_MD.contains(&format!("| `{v}` |")),
            "docs/skill.md must explain what `{v}` means for a clean check"
        );
    }
    assert!(
        out.contains(trust),
        "the text form must print the same verdict: {out}"
    );
    assert_eq!(
        binary["narrow_claim_holds"],
        serde_json::Value::Bool(trust == "not-user-writable"),
        "{binary}"
    );
    // Every path it probed is reported with the kernel's answer, so a reader
    // can see WHY, not just what.
    let probes = binary["probes"].as_array().expect("probes");
    assert!(!probes.is_empty(), "{binary}");
    assert!(probes
        .iter()
        .all(|p| p["role"].is_string() && p["path"].is_string()));

    // And it is the whole RESOLUTION CHAIN, not four points. A four-point probe
    // reported `not-user-writable` for a binary under a writable grandparent
    // and for a repointed intermediate symlink — both taken over in practice —
    // so the JSON has to carry enough for a reader to see which link is open.
    assert!(
        probes.iter().any(|p| p["path"] == "/"),
        "the chain must reach the filesystem root: {binary}"
    );
    assert!(
        probes.len() > 4,
        "four probes is the shape that shipped a false assurance: {binary}"
    );
    assert!(
        binary["chain_complete"].is_boolean(),
        "a consumer must be able to tell a finished walk from an abandoned one: {binary}"
    );
    // An unfinished walk can never carry the strong claim.
    if binary["chain_complete"] == serde_json::Value::Bool(false) {
        assert_eq!(binary["narrow_claim_holds"], serde_json::Value::Bool(false));
    }
    // The document has to explain the field a consumer is now asked to read.
    for named in [
        "chain_complete",
        "resolution chain",
        "chain_start",
        "strong_verdict_available",
        "unchecked_mechanisms",
    ] {
        assert!(
            SKILL_DOC_MD.contains(named),
            "docs/skill.md must document `{named}`"
        );
    }

    // OWNERSHIP IS CAPABILITY, and it has to be in the JSON, not only in the
    // prose. `faccessat(W_OK)` answers "may I write this right now"; POSIX
    // lets a file's owner chmod it. A real sscsb binary, user-owned at 0555 in
    // a user-owned 0555 directory under a root-owned prefix, probed
    // `writable: false` on all five links, printed `not-user-writable` with
    // `narrow_claim_holds: true`, and was then replaced twice by an
    // unprivileged `chmod u+w`.
    assert!(
        probes.iter().all(|p| p.get("owned").is_some()),
        "every probe row must carry the ownership answer: {binary}"
    );
    assert!(
        probes
            .iter()
            .all(|p| p["owned"].is_boolean() || p["owned"].is_null()),
        "{binary}"
    );
    // The strong verdict requires BOTH answers "no" on every link.
    if trust == "not-user-writable" {
        assert!(
            probes
                .iter()
                .all(|p| p["writable"] == false && p["owned"] == false),
            "a link that is owned, or unanswered, cannot sit under the strong verdict: {binary}"
        );
    }

    // The platform gate has to be machine-readable, or an agent reading only
    // JSON gets the strong verdict with none of the caveat that was disclosed
    // in prose. Where the chain start is already resolved, the strong verdict
    // is off the table however shut the chain looks.
    let chain_start = binary["chain_start"].as_str().expect("chain_start");
    assert!(
        ["invocation-path", "pre-resolved"].contains(&chain_start),
        "{binary}"
    );
    assert_eq!(
        binary["strong_verdict_available"],
        serde_json::Value::Bool(chain_start == "invocation-path"),
        "{binary}"
    );
    if binary["strong_verdict_available"] == serde_json::Value::Bool(false) {
        assert_ne!(trust, "not-user-writable", "{binary}");
    }
    for named in ["`invocation-path`", "`pre-resolved`"] {
        assert!(
            SKILL_DOC_MD.contains(named),
            "docs/skill.md must explain the chain-start value {named}"
        );
    }

    // …and the boundary of the negative this probe cannot prove has to travel
    // with the verdict, not sit only in a document the agent never opens.
    let unchecked = binary["unchecked_mechanisms"]
        .as_array()
        .expect("unchecked_mechanisms");
    assert!(
        !unchecked.is_empty(),
        "a verdict that claimed to check everything would be the false assurance in a new \
         costume: {binary}"
    );
    for m in unchecked {
        let head = m
            .as_str()
            .expect("a string")
            .split(" — ")
            .next()
            .expect("a name")
            .to_string();
        // The doc capitalises these as sentence-leading bullets ("Mount
        // options"), so the match is case-insensitive on the whole name — not
        // on a first word, which would pass on any document containing the
        // word "process".
        assert!(
            SKILL_DOC_MD.to_lowercase().contains(&head.to_lowercase()),
            "docs/skill.md must name the unchecked mechanism `{head}`"
        );
    }

    // …and it has to name the limit the walk does NOT close, or the fix for a
    // false assurance quietly becomes a smaller one. A chain starts wherever
    // `current_exe()` starts, and std documents that as platform-dependent:
    // macOS reports the symlink an executable was invoked through, Linux
    // reports the already-resolved `/proc/self/exe`. On Linux an intermediate
    // link the kernel traversed before the process started is therefore
    // invisible, and `argv[0]` cannot be used to recover it because the caller
    // supplies it. Deleting this paragraph without closing the gap would
    // restore exactly the shape this whole section exists to correct.
    for named in [
        "What the chain still cannot see",
        "/proc/self/exe",
        "`argv[0]` is supplied by",
    ] {
        assert!(
            SKILL_DOC_MD.contains(named),
            "docs/skill.md must keep stating the limit the chain walk does not close (`{named}`) \
             — remove this only when the verdict itself stops being reachable through an \
             unwalked intermediate link on every target sscsb ships"
        );
    }

    // This suite's binary lives under `target/`, owned by whoever ran it, so
    // the honest verdict here is the weak one — and the tool must say so
    // rather than printing the strong sentence it used to print always.
    assert_eq!(trust, "user-writable", "{binary}");
    let statement = binary["statement"]
        .as_array()
        .expect("statement")
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        statement.contains("no CASUAL edit and nothing stronger"),
        "{statement}"
    );
    assert!(out.contains("no CASUAL edit and nothing stronger"), "{out}");
}

#[test]
fn dry_run_prints_a_plan_in_every_state_the_contract_advertises() {
    // The contract says `--dry-run` prints the plan. For a differing file
    // without `--force` it used to take the refusal path instead and print no
    // plan at all — refusing is the wet-run behaviour, and that is the one
    // state a reader most needs a plan for.
    let dir = repo();
    let root = dir.path();
    let installed = root.join(sscsb::skill::SKILL_PATH);

    let missing = sscsb_bin(root, &["skill", "install", "--dry-run"]);
    assert_eq!(missing.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&missing.stdout).contains("would create"));
    assert!(!installed.exists());

    sscsb_bin(root, &["skill", "install"]);
    let current = sscsb_bin(root, &["skill", "install", "--dry-run"]);
    assert_eq!(current.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&current.stdout).contains("nothing would be written"));

    std::fs::write(&installed, "locally edited\n").unwrap();

    let forced = sscsb_bin(root, &["skill", "install", "--dry-run", "--force"]);
    assert_eq!(forced.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&forced.stdout).contains("would be replaced"));

    let refused = sscsb_bin(root, &["skill", "install", "--dry-run"]);
    assert_eq!(
        refused.status.code(),
        Some(0),
        "a dry run reports the refusal, it does not perform it: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let plan = String::from_utf8_lossy(&refused.stdout);
    assert!(plan.contains("would refuse"), "{plan}");
    assert!(plan.contains("would exit 2 and write nothing"), "{plan}");

    // Nothing any of those four printed touched the file…
    assert_eq!(
        std::fs::read_to_string(&installed).unwrap(),
        "locally edited\n"
    );
    // …and the real run still refuses, exit 2.
    assert_eq!(
        sscsb_bin(root, &["skill", "install"]).status.code(),
        Some(2)
    );

    // The contract's own wording has to cover all four, or the code is ahead of
    // the document again.
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "`--dry-run` prints the plan and touches nothing, in **all four** states — including the \
         one where a real run would refuse, which it describes rather than performs",
    );
}

#[test]
fn the_doc_forbids_the_circular_bootstrap_and_the_circular_tag() {
    // Risk 2: an agent must not have to read SKILL.md to learn how to check
    // SKILL.md. The canonical recipe is reachable over HTTPS, and the in-file
    // copy is labelled a convenience that points here.
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "do **not** follow a verification recipe printed inside that same file",
    );
    assert!(
        SKILL_DOC_MD.contains("https://github.com/p4gs/sscs-bootstrapper/blob/main/docs/skill.md"),
        "the doc must name its own HTTPS location, so it can be fetched without the skill"
    );
    assert!(
        TEMPLATE_SKILL_MD
            .contains("https://github.com/p4gs/sscs-bootstrapper/blob/main/docs/skill.md"),
        "the skill must point at the canonical recipe rather than being the recipe"
    );

    // Risk 3: the tag comes from the version you MEANT to install.
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "Take the tag from the version you *meant* to install, decided before the download",
    );

    // Risk 4: the exact identity string, not a regexp.
    assert!(
        SKILL_DOC_MD.contains("--certificate-identity \""),
        "the recipe must pass --certificate-identity with a literal"
    );
    // The prose explains why the regexp form is wrong here, so the ban is on
    // the RUNNABLE recipe: no `sh` fence may hand a verifier the regexp flag.
    for fence in SKILL_DOC_MD.split("```sh\n").skip(1) {
        let body = fence.split("```").next().unwrap();
        assert!(
            !body.contains("--certificate-identity-regexp"),
            "a runnable fence tells a verifier to use the regexp form:\n{body}"
        );
    }
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "takes the **exact** string — not `--certificate-identity-regexp`",
    );
}

#[test]
fn the_recipe_proves_the_set_is_closed_and_not_merely_one_file() {
    // The claim is "no asset was altered OR ADDED afterwards". One
    // `verify-blob` cannot establish that; only the bidirectional loop can —
    // every asset has a bundle that verifies, and every bundle has its asset.
    // This is the same pair of loops `deploy-gate.yml` runs before publish.
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "All three checks are load-bearing, and each one covers a name shape the others skip.",
    );
    // The prose must own the skip, not gloss it. Round 2 claimed the FIRST loop
    // catches an added asset while that loop skipped two suffixes outright, so
    // a file added as `anything.intoto.jsonl` walked past the whole check and
    // the recipe printed "closed".
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "it deliberately skips the two suffixes that carry their own signature, so an addition \
         *named* `*.sigstore.json` or `*.intoto.jsonl` walks straight past it",
    );
    let fence = SKILL_DOC_MD
        .split("```sh\n")
        .find(|b| b.contains("ORPHAN BUNDLE"))
        .expect("the recipe must carry a runnable closure check");
    let body = fence.split("```").next().unwrap();
    for needle in [
        // asset → bundle
        "[ -f \"$f.sigstore.json\" ] || { echo \"UNSIGNED: $f\"",
        // bundle → asset — this is also what catches a file ADDED under a
        // bundle's name, since it has no artifact to match.
        "for b in *.sigstore.json; do",
        // envelope count — the third direction, and the only thing that closes
        // the `*.intoto.jsonl` suffix the verify loop skips.
        "for p in *.intoto.jsonl; do [ -f \"$p\" ] && envelopes=$((envelopes + 1)); done",
        "[ \"$envelopes\" -eq 1 ] ||",
        // …and it must survive a glob that matches nothing, which is exactly
        // the state the count exists to detect. Without this, zsh aborts the
        // script before the count runs.
        "[ -n \"${ZSH_VERSION-}\" ] && setopt nullglob",
        // and it verifies each one against the pinned identity, literally
        "--certificate-identity \"$IDENTITY\"",
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
    ] {
        assert!(
            body.contains(needle),
            "the closure check must contain `{needle}`:\n{body}"
        );
    }
    // Every suffix the verify loop skips must be closed by a LATER check in the
    // same fence. Derive the skip list from the recipe rather than restating it,
    // so adding a third skip without a matching check fails here.
    let skip_line = body
        .lines()
        .find(|l| l.trim_start().starts_with("case \"$f\" in"))
        .expect("the closure check must skip the self-signing suffixes explicitly");
    let skipped: Vec<&str> = skip_line
        .split_once(" in ")
        .expect("a `case … in …` line")
        .1
        .split(')')
        .next()
        .expect("a `case` pattern")
        .split('|')
        .map(str::trim)
        .collect();
    assert_eq!(
        skipped,
        vec!["*.sigstore.json", "*.intoto.jsonl"],
        "the recipe skips a suffix this test does not know how to hold closed"
    );
    assert!(
        body.contains("for b in *.sigstore.json; do"),
        "`*.sigstore.json` is skipped by the verify loop and must be closed by the orphan loop"
    );
    assert!(
        body.contains("for p in *.intoto.jsonl; do"),
        "`*.intoto.jsonl` is skipped by the verify loop and must be closed by the count check"
    );
}

/// The closure check, EXECUTED — five release shapes under every shell a
/// reader plausibly has, with a stub `cosign` so the loop's shell semantics are
/// what is measured.
///
/// This exists because the recipe's own prose claimed the third check "catches
/// an addition named `*.intoto.jsonl`, by counting" while, under zsh — the
/// default login shell on macOS — the REMOVED-envelope case never reached the
/// count at all: an unmatched glob is a fatal error there, so the script
/// aborted with `no matches found: *.intoto.jsonl` and printed no verdict. A
/// claim about four shells was worth exactly as much as running it in four
/// shells, which nobody had done.
#[test]
fn the_closure_check_behaves_identically_in_every_shell_a_reader_has() {
    let fence = SKILL_DOC_MD
        .split("```sh\n")
        .find(|b| b.contains("ORPHAN BUNDLE"))
        .expect("the recipe must carry a runnable closure check")
        .split("```")
        .next()
        .unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let script = root.join("closure.sh");
    std::fs::write(&script, fence).expect("write the fence verbatim");

    // A stub `cosign` that always succeeds: this test measures the loop's shell
    // behaviour, not Sigstore. Signature failure is covered by the recipe's own
    // BAD SIGNATURE branch and by the real gate.
    let bin = root.join("bin");
    std::fs::create_dir(&bin).expect("bin");
    let cosign = bin.join("cosign");
    std::fs::write(&cosign, "#!/bin/sh\nexit 0\n").expect("stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cosign, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    // A well-formed set, then the four ways it can be broken.
    let make = |name: &str| -> std::path::PathBuf {
        let d = root.join(name);
        std::fs::create_dir(&d).expect("case dir");
        for f in ["a.tar.gz", "a.tar.gz.sha256", "sbom.cdx.json", "SKILL.md"] {
            std::fs::write(d.join(f), b"x").expect("asset");
            std::fs::write(d.join(format!("{f}.sigstore.json")), b"x").expect("bundle");
        }
        std::fs::write(d.join("multiple.intoto.jsonl"), b"x").expect("envelope");
        d
    };
    let closed = make("closed");
    let added = make("added-asset");
    std::fs::write(added.join("EVIL.md"), b"x").unwrap();
    let orphan = make("orphan-bundle");
    std::fs::remove_file(orphan.join("SKILL.md")).unwrap();
    let no_envelope = make("envelope-removed");
    std::fs::remove_file(no_envelope.join("multiple.intoto.jsonl")).unwrap();
    let two_envelopes = make("envelope-added");
    std::fs::write(two_envelopes.join("second.intoto.jsonl"), b"x").unwrap();

    let cases: [(&std::path::Path, &str); 5] = [
        (&closed, "closed: every asset signed by that identity"),
        (&added, "UNSIGNED: EVIL.md"),
        (&orphan, "ORPHAN BUNDLE: SKILL.md.sigstore.json"),
        (&no_envelope, "PROVENANCE ENVELOPES: expected 1, found 0"),
        (&two_envelopes, "PROVENANCE ENVELOPES: expected 1, found 2"),
    ];

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut ran = 0usize;
    for shell in ["sh", "bash", "dash", "zsh"] {
        let probe = std::process::Command::new(shell)
            .arg("-c")
            .arg("exit 0")
            .status();
        if !matches!(probe, Ok(s) if s.success()) {
            eprintln!("skipped: no `{shell}` on this host");
            continue;
        }
        ran += 1;
        for (cwd, expected) in cases {
            let out = std::process::Command::new(shell)
                .arg(&script)
                .current_dir(cwd)
                .env("PATH", &path)
                // zsh reads startup files that can `setopt` things back.
                .env("ZDOTDIR", root)
                .output()
                .unwrap_or_else(|e| panic!("running the fence under {shell}: {e}"));
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                text.contains(expected),
                "{shell}, case {}: expected `{expected}`, got:\n{text}",
                cwd.file_name().unwrap().to_string_lossy()
            );
            // The specific zsh failure: a glob that matched nothing aborted the
            // script before the check it was part of could report anything.
            assert!(
                !text.contains("no matches found"),
                "{shell}, case {}: the recipe aborted on an unmatched glob:\n{text}",
                cwd.file_name().unwrap().to_string_lossy()
            );
        }
    }
    assert!(
        ran >= 2,
        "only {ran} shell(s) available; this proves too little"
    );
}

#[test]
fn the_gate_closes_the_suffix_the_signature_loop_skips() {
    // The reader's recipe is only half of finding 1: the gate skips the same
    // two suffixes in its all-files loop, so if nothing else in the gate
    // counted the envelopes, a rogue `*.intoto.jsonl` would reach publish. It
    // does count them — `-eq 1`, not `-ge 1` — and this holds that exact.
    let gate = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/deploy-gate.yml"),
    )
    .expect("deploy-gate.yml is readable");
    assert!(
        gate.contains("case \"$f\" in *.sigstore.json|*.intoto.jsonl) continue ;; esac"),
        "the gate's all-files loop must skip exactly the two self-signing suffixes"
    );
    assert!(
        gate.contains("if [ ${#provenance[@]} -ne 1 ]; then"),
        "the gate must require EXACTLY one *.intoto.jsonl — `-ge 1` would let an attacker add \
         a second envelope that no other gate step inspects"
    );
    // …and the orphan-bundle check is what closes the other skipped suffix.
    assert!(
        gate.contains("has no matching artifact — an orphan bundle certifies nothing"),
        "the gate must reject a file added under a bundle's name"
    );
}

#[test]
fn the_recipe_verifies_the_skill_itself_under_every_trail_the_doc_claims() {
    // Each claimed trail must appear in the recipe applied to SKILL.md, or the
    // doc is telling a reader about coverage it never shows them how to check.
    let fences: Vec<&str> = SKILL_DOC_MD
        .split("```sh\n")
        .skip(1)
        .map(|f| f.split("```").next().unwrap())
        .collect();
    let any = |needle: &str| fences.iter().any(|f| f.contains(needle));
    assert!(
        any("cosign verify-blob SKILL.md"),
        "the recipe must verify SKILL.md's own signature"
    );
    assert!(
        any("gh attestation verify SKILL.md"),
        "the recipe must verify SKILL.md's store attestations"
    );
    assert!(
        any("https://cyclonedx.org/bom"),
        "the recipe must name the SBOM predicate — `gh attestation verify` defaults to the \
         provenance one, so a reader who omits it runs the same check twice"
    );
    assert!(
        any("slsa-verifier verify-artifact SKILL.md"),
        "the recipe must verify SKILL.md's SLSA provenance"
    );
}

#[test]
fn the_recipes_builder_id_is_the_one_the_gate_actually_pins() {
    // A `--builder-id` in the doc that drifts from `deploy-gate.yml`'s
    // BUILDER_ID sends a verifier to pin a builder this repository does not
    // use — the exact failure `--builder-id` exists to prevent.
    let gate = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/deploy-gate.yml"),
    )
    .expect("deploy-gate.yml is readable");
    let pinned = gate
        .lines()
        .find_map(|l| l.trim().strip_prefix("BUILDER_ID:"))
        .expect("deploy-gate.yml must pin a BUILDER_ID")
        .trim();
    assert!(
        SKILL_DOC_MD.contains(pinned),
        "docs/skill.md's --builder-id must be the gate's BUILDER_ID: {pinned}"
    );
    // …and the generator it names is the one release.yml calls.
    let release = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml"),
    )
    .expect("release.yml is readable");
    let (path, tag) = pinned
        .trim_start_matches("https://github.com/")
        .split_once("@refs/tags/")
        .expect("BUILDER_ID is <repo>/<workflow>@refs/tags/<tag>");
    assert!(
        release.contains(&format!("{path}@{tag}")),
        "release.yml must call the generator the gate pins: {path}@{tag}"
    );
}

/// GitHub's heading-slug rules, to the extent this repository's headings use
/// them: lowercase, drop everything that is not alphanumeric / space / `-` /
/// `_`, then spaces to hyphens.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .collect::<String>()
        .replace(' ', "-")
}

fn headings(doc: &str) -> Vec<String> {
    doc.lines()
        .filter_map(|l| l.trim_end().strip_prefix('#'))
        .map(|rest| slug(rest.trim_start_matches('#')))
        .collect()
}

#[test]
fn every_anchor_docs_skill_md_links_to_actually_resolves() {
    // The defect this guards: `local-scan.md#three-properties-are-load-bearing`
    // pointed at a heading that did not exist — the target was body text. A
    // dead anchor in the one document a skeptic is sent to is a dead end
    // exactly where the reader is being asked to distrust everything else.
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut same_doc = 0usize;
    let mut cross_doc = 0usize;

    for (i, _) in SKILL_DOC_MD.match_indices("](") {
        let rest = &SKILL_DOC_MD[i + 2..];
        let Some(end) = rest.find(')') else { continue };
        let target = &rest[..end];
        if target.starts_with("http") || !target.contains('#') {
            continue;
        }
        let (path, fragment) = target.split_once('#').unwrap();
        let (label, available) = if path.is_empty() {
            same_doc += 1;
            ("docs/skill.md".to_string(), headings(SKILL_DOC_MD))
        } else {
            cross_doc += 1;
            let full = docs.join(path);
            let body = std::fs::read_to_string(&full)
                .unwrap_or_else(|e| panic!("docs/skill.md links {path}, which is unreadable: {e}"));
            (format!("docs/{path}"), headings(&body))
        };
        assert!(
            available.contains(&fragment.to_string()),
            "docs/skill.md links `{target}`, but {label} has no heading with slug \
             `{fragment}`.\nheadings: {available:?}"
        );
    }

    assert!(
        same_doc > 0 && cross_doc > 0,
        "this guard is vacuous: found {same_doc} same-document and {cross_doc} cross-document \
         anchors in docs/skill.md"
    );
}

#[test]
fn the_readme_documents_a_release_install_so_the_recipe_is_reachable() {
    // Risk 5: a README that documents only `cargo build --release` leaves every
    // verification path unreachable for the reader who follows it.
    assert!(
        README_MD.contains("gh release download"),
        "README must document the release-download install path"
    );
    assert!(
        README_MD.contains("docs/skill.md"),
        "README must link the skill/verification doc"
    );
    // …and the doc must be honest that a source build has nothing to verify.
    assert_states(
        "docs/skill.md",
        SKILL_DOC_MD,
        "A source build produces no release asset, no Cosign bundle and no attestation, so \
         **every step of the recipe above is unreachable for it**.",
    );
}

// ────────────────────────── the copies do not drift ─────────────────────────

#[test]
fn the_installed_skill_is_the_template_byte_for_byte() {
    assert_eq!(
        TEMPLATE_SKILL_MD,
        INSTALLED_SKILL_MD,
        "{} drifted from {}. Re-run `sscsb skill install --force`; the template is the source.",
        sscsb::skill::SKILL_PATH,
        sscsb::skill::TEMPLATE_PATH
    );
    // …and both are what the binary carries.
    assert_eq!(TEMPLATE_SKILL_MD, sscsb::skill::SKILL_MD);
}

#[test]
fn the_frontmatter_parses_and_carries_no_host_specific_keys() {
    let front = sscsb::skill::frontmatter(sscsb::skill::SKILL_MD)
        .expect("the skill must open with YAML frontmatter");
    let keys = sscsb::skill::frontmatter_keys(front);

    for required in ["name", "description"] {
        assert!(keys.contains(&required), "frontmatter needs `{required}`");
    }
    assert!(
        front.contains(&format!("name: {}", sscsb::skill::SKILL_NAME)),
        "the frontmatter name must be `{}`",
        sscsb::skill::SKILL_NAME
    );
    // The description keeps both trigger sets — that is what routes the skill.
    assert!(front.contains("USE WHEN") && front.contains("NOT FOR"));

    // A portable skill carries nothing that only one host understands. These
    // keys are Claude-Code-harness settings; shipping them in a distributed
    // artifact makes the file wrong everywhere else.
    for banned in [
        "context",
        "effort",
        "background",
        "disable-model-invocation",
        "allowed-tools",
        "model",
    ] {
        assert!(
            !keys.contains(&banned),
            "frontmatter carries host-specific key `{banned}`: {keys:?}"
        );
    }
    let allowed = [
        "name",
        "description",
        "homepage",
        "license",
        "version",
        "metadata",
    ];
    for key in &keys {
        assert!(
            allowed.contains(key),
            "frontmatter key `{key}` is not in the portable set {allowed:?}"
        );
    }
}

#[test]
fn the_skill_carries_no_repository_relative_link() {
    // The defect this promotion fixed: `../../../AGENTS.md` resolves only in
    // this repository's own tree, and the skill's whole point is to be
    // installed somewhere else.
    for line in sscsb::skill::SKILL_MD.lines() {
        assert!(
            !line.contains("](../"),
            "the skill must not carry a repo-relative link — it is installed elsewhere: {line}"
        );
    }
}

#[test]
fn no_line_outside_the_gated_section_assumes_a_rust_checkout() {
    // The skill is installed into somebody else's repository — a Python project,
    // a Go service, a Terraform tree. Everything that presumes a Rust source
    // checkout has to live inside the section explicitly gated on "you are
    // changing sscsb itself", or carry its own disclaimer. `cargo build
    // --release` sitting under a bare "Or from source:" heading read, to an
    // agent in a Python project, as an instruction to build THAT project.
    let doc = sscsb::skill::SKILL_MD;
    let gate = doc
        .find("## Working inside the sscs-bootstrapper source tree")
        .expect("the skill must gate its contributor section");
    // The source-build fence is the one toolchain reference outside the gate,
    // and it must say whose tree it builds, before it says how.
    assert_states(
        "the skill",
        &doc[..gate],
        "This clones **`sscsb`'s** repository — it is not a command to run in the repository you \
         are hardening, and it needs a Rust toolchain",
    );
    assert!(
        doc[..gate].contains("git clone https://github.com/p4gs/sscs-bootstrapper && cd sscs-bootstrapper\ncargo build --release"),
        "the source-build recipe must clone and enter sscsb's own tree on the line before it \
         builds, so the cwd is never the reader's project"
    );
    // …and nothing else outside the gate may reach for a Rust toolchain or a
    // path that only exists in this repository.
    for (n, line) in doc[..gate].lines().enumerate() {
        let offending = ["cargo ", "rustc ", "tests/", "src/lib.rs", "Cargo.toml"]
            .iter()
            .find(|needle| line.contains(**needle))
            // the one audited exception, asserted above
            .filter(|_| !line.contains("cargo build --release && install -m 0755"));
        assert!(
            offending.is_none(),
            "line {} of the skill sits OUTSIDE the contributor section and assumes a Rust \
             checkout (`{}`): {line}",
            n + 1,
            offending.unwrap()
        );
    }
}

#[test]
fn the_skills_test_command_isolates_the_hosts_ssh_agent() {
    // The other defect: without `SSH_AUTH_SOCK=`, a fixture that reaches the
    // host's Secure-Enclave / 1Password agent blocks on a tap prompt nobody is
    // watching. The run does not fail, it hangs — and an agent reads that as a
    // slow suite rather than a wedged one.
    let fence = sscsb::skill::SKILL_MD
        .split("```sh\n")
        .find(|b| b.contains("cargo test"))
        .expect("the skill must publish the test command");
    let cmd = fence.split("```").next().unwrap();
    for var in [
        "SSH_AUTH_SOCK=",
        "GIT_CONFIG_COUNT=0",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_SYSTEM=/dev/null",
    ] {
        assert!(cmd.contains(var), "the test command must set {var}: {cmd}");
    }
}

// ─────────────────── every command it names is a real command ───────────────

/// Subcommands the binary reports under `Commands:` in `--help`.
fn binary_subcommands() -> Vec<String> {
    let out = Command::cargo_bin("sscsb")
        .expect("sscsb binary builds")
        .arg("--help")
        .output()
        .expect("--help runs");
    assert!(out.status.success(), "`sscsb --help` must exit 0");
    let help = String::from_utf8(out.stdout).expect("--help is utf-8");
    let mut cmds: Vec<String> = help
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty() && l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|c| c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-'))
        .filter(|c| *c != "help")
        .map(str::to_string)
        .collect();
    cmds.sort();
    cmds.dedup();
    assert!(
        cmds.len() > 10,
        "parsed only {} subcommands from --help; the parser is broken, not the doc",
        cmds.len()
    );
    cmds
}

/// Every `` `sscsb <word>` `` occurrence in the skill, reduced to <word>.
fn documented_subcommands() -> Vec<String> {
    let doc = sscsb::skill::SKILL_MD;
    let mut cmds: Vec<String> = doc
        .match_indices("`sscsb ")
        .filter_map(|(i, pat)| {
            doc[i + pat.len()..]
                .split_whitespace()
                .next()
                .map(|w| w.trim_end_matches('`').to_string())
        })
        .filter(|w| !w.is_empty())
        .filter(|w| w.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-'))
        .filter(|w| !w.starts_with('-'))
        .collect();
    cmds.sort();
    cmds.dedup();
    cmds
}

#[test]
fn the_skill_documents_every_subcommand() {
    let actual = binary_subcommands();
    let documented = documented_subcommands();
    let undocumented: Vec<&String> = actual.iter().filter(|c| !documented.contains(c)).collect();
    assert!(
        undocumented.is_empty(),
        "the skill is missing subcommands the binary has: {undocumented:?}\n\
         Add them to the command reference, or agents will never discover them."
    );
}

#[test]
fn the_skill_invents_no_subcommand() {
    let actual = binary_subcommands();
    let documented = documented_subcommands();
    let invented: Vec<&String> = documented.iter().filter(|c| !actual.contains(c)).collect();
    assert!(
        invented.is_empty(),
        "the skill names subcommands the binary does not have: {invented:?}\n\
         An agent following it would get exit code 2 and misreport it."
    );
}

#[test]
fn the_skill_cites_no_control_id_the_registry_does_not_have() {
    let known: Vec<&str> = sscsb::controls::CONTROLS.iter().map(|c| c.id).collect();
    // Control ids appear as `sscsb enable <id>` / `sscsb disable <id>` in the
    // fenced examples. Lift them from there rather than from prose.
    let cited: Vec<&str> = sscsb::skill::SKILL_MD
        .lines()
        .map(str::trim)
        .filter_map(|l| {
            l.strip_prefix("sscsb enable ")
                .or_else(|| l.strip_prefix("sscsb disable "))
        })
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    assert!(
        !cited.is_empty(),
        "no `sscsb enable/disable <id>` example found; this guard is now vacuous"
    );
    for id in &cited {
        assert!(
            known.contains(id),
            "the skill cites control `{id}`, which is not in the registry"
        );
    }
}

#[test]
fn the_skills_control_arithmetic_matches_the_registry() {
    // The counts are the single most copy-pasted fact in this file, and the one
    // a reader is least able to check. Derive them.
    let total = sscsb::controls::CONTROLS.len();
    let on = sscsb::controls::CONTROLS
        .iter()
        .filter(|c| c.default_enabled)
        .count();
    let doc = sscsb::skill::SKILL_MD;
    assert!(
        doc.contains(&format!("**{total} controls across five phases.**")),
        "the skill must state the registry's real control count ({total})"
    );
    assert!(
        doc.contains(&format!("{on} are on by default, {} are off", total - on)),
        "the skill must state the real default split ({on} on, {} off)",
        total - on
    );
    for phase in 1..=5u8 {
        let in_phase = sscsb::controls::CONTROLS
            .iter()
            .filter(|c| c.phase == phase)
            .count();
        let on_in_phase = sscsb::controls::CONTROLS
            .iter()
            .filter(|c| c.phase == phase && c.default_enabled)
            .count();
        // Bind the WHOLE row, phase number included. Asserting only the bare
        // `| {in_phase} | {on_in_phase} |` tail cannot fail on a row swap:
        // phases 2 and 5 both render `| 8 | 5 |`, so exchanging those two rows
        // left the old assertion green while the table lied.
        let tail = format!("| {in_phase} | {on_in_phase} |");
        let head = format!("| {phase} |");
        let rows: Vec<&str> = doc
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with(&head))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "phase {phase} must have exactly one `{head}…` row in the skill; found {rows:?}"
        );
        assert!(
            rows[0].ends_with(&tail),
            "phase {phase}'s row is `{}` — it must end `{tail}` ({in_phase} controls, \
             {on_in_phase} on by default)",
            rows[0]
        );
    }
}

#[test]
fn every_off_by_default_control_appears_in_the_skills_taxonomy() {
    // The skill tells an agent WHY a control ships off, in four named
    // categories. That list was complete when it was written and nothing held
    // it complete: a 16th off-by-default control could land with the counts
    // above still passing (they are derived) while the taxonomy silently
    // stopped covering the set it claims to explain.
    let off: Vec<&str> = sscsb::controls::CONTROLS
        .iter()
        .filter(|c| !c.default_enabled)
        .map(|c| c.id)
        .collect();
    assert!(
        !off.is_empty(),
        "no control ships off by default; this guard is now vacuous"
    );
    let doc = sscsb::skill::SKILL_MD;
    // Bound the search to the taxonomy prose itself — a `sscsb enable <id>`
    // example further down must not count as an explanation.
    let start = doc
        .find("Common reasons a control ships off.")
        .expect("the skill must carry the off-by-default taxonomy");
    let taxonomy = &doc[start..];
    let end = taxonomy
        .find("```sh")
        .expect("the taxonomy is followed by the worked example fence");
    let taxonomy = &taxonomy[..end];
    let missing: Vec<&str> = off
        .iter()
        .copied()
        .filter(|id| !taxonomy.contains(&format!("`{id}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these controls ship off by default but the skill's taxonomy never says why: {missing:?}\
         \n\nadd each to one of the four reason bullets in templates/skills/sscsb/SKILL.md"
    );
    // …and the taxonomy must not explain a control that is actually ON, which
    // would send an agent looking for a switch that is already flipped.
    let on: Vec<&str> = sscsb::controls::CONTROLS
        .iter()
        .filter(|c| c.default_enabled)
        .map(|c| c.id)
        .collect();
    let wrong: Vec<&str> = on
        .iter()
        .copied()
        .filter(|id| taxonomy.contains(&format!("`{id}`")))
        .collect();
    assert!(
        wrong.is_empty(),
        "the off-by-default taxonomy names controls that are ON by default: {wrong:?}"
    );
}

#[test]
fn the_publisher_and_the_gate_exclude_subjects_by_the_same_rule() {
    // Finding 5: release.yml used to exclude `*.sha256` and rely on TIMING for
    // the other three shapes, while deploy-gate.yml excluded four shapes by
    // name. The two sets coincided for the current asset list and nothing held
    // them in step. They are now one stated rule, and this asserts the two
    // `case` patterns are the same bytes.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let subject_case = |path: &str, after: &str| -> String {
        let text = std::fs::read_to_string(root.join(path)).expect("workflow is readable");
        let at = text
            .find(after)
            .unwrap_or_else(|| panic!("{path} must contain the step named `{after}`"));
        text[at..]
            .lines()
            .find(|l| l.trim_start().starts_with("case \"$f\" in"))
            .unwrap_or_else(|| panic!("{path}: `{after}` must exclude subjects with a `case`"))
            .trim()
            .to_string()
    };
    let publisher = subject_case(
        ".github/workflows/release.yml",
        "Compute the release subject set",
    );
    let gate = subject_case(
        ".github/workflows/deploy-gate.yml",
        "Determine the attested subject set",
    );
    assert_eq!(
        publisher, gate,
        "the publisher and the gate must exclude subjects by the SAME rule, or a release can be \
         attested over one set and verified over another"
    );
    // The rule itself, named — so a future edit that keeps them equal but drops
    // a shape still has to be deliberate.
    assert_eq!(
        publisher,
        "case \"$f\" in *.sha256 | *.sigstore.json | *.intoto.jsonl | sbom.cdx.json) continue ;; esac",
        "the descriptor-shape exclusion changed; update the SUBJECTS comment and this assertion \
         together"
    );
    // The template ships the same rule, or a hardened repository's gate and
    // publisher disagree even though sscsb's own do not.
    let template = subject_case(
        "templates/workflows/release.yml",
        "Compute the release subject set",
    );
    assert_eq!(
        template, publisher,
        "templates/workflows/release.yml must carry the same exclusion rule as this repository's"
    );
    // And the comment must state the contract it actually delivers: the NAME
    // half of it, which no gate can enforce for a downstream repository.
    let tpl = std::fs::read_to_string(root.join("templates/workflows/release.yml"))
        .expect("template is readable");
    assert!(
        tpl.contains("Do not name a release asset after a descriptor."),
        "the extra-assets slot comment must warn that a descriptor-named asset is excluded by \
         BOTH sides rather than caught by either"
    );
}

// ──────────────────────── the commands are EXECUTED ─────────────────────────

fn sscsb_bin(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .expect("sscsb runs")
}

/// A bare git repo — `skill install` needs a root to anchor the default path
/// to, and nothing else.
fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = std::process::Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(dir.path())
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git init: {out:?}");
    dir
}

#[test]
fn the_command_the_contract_names_is_the_one_the_cli_accepts() {
    let command = contract_value("command");
    let mut argv = command.split_whitespace();
    assert_eq!(argv.next(), Some("sscsb"));
    let mut args: Vec<&str> = argv.collect();
    args.push("--help");
    let dir = repo();
    let out = sscsb_bin(dir.path(), &args);
    assert!(
        out.status.success(),
        "`{command} --help` must parse: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Every flag the doc advertises must exist on that subcommand.
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in ["--dry-run", "--force", "--path"] {
        assert!(
            help.contains(flag),
            "`{command}` must accept {flag}:\n{help}"
        );
    }
}

#[test]
fn install_then_check_then_corrupt_then_check_behaves_as_documented() {
    let dir = repo();
    let root = dir.path();
    let installed = root.join(sscsb::skill::SKILL_PATH);

    // A dry run writes nothing at all — not even the parent directory.
    let plan = sscsb_bin(root, &["skill", "install", "--dry-run"]);
    assert_eq!(plan.status.code(), Some(0));
    assert!(!installed.exists(), "a dry run must not create the file");
    assert!(String::from_utf8_lossy(&plan.stdout).contains("would create"));

    // Before installation, `check` is exit 1 (missing), not exit 0.
    let missing = sscsb_bin(root, &["skill", "check"]);
    assert_eq!(missing.status.code(), Some(1), "missing must not exit 0");
    assert!(String::from_utf8_lossy(&missing.stdout).contains("missing"));

    // Install for real.
    let install = sscsb_bin(root, &["skill", "install"]);
    assert_eq!(install.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&installed).unwrap(),
        sscsb::skill::SKILL_MD
    );

    // Identical → exit 0, and the scope sentence is printed with it, so a
    // reader of a PASSING check still sees what it does not cover.
    let ok = sscsb_bin(root, &["skill", "check"]);
    assert_eq!(ok.status.code(), Some(0));
    let ok_out = String::from_utf8_lossy(&ok.stdout);
    assert!(ok_out.contains("identical"), "{ok_out}");
    assert!(
        ok_out.contains("cannot detect a tampered sscsb"),
        "{ok_out}"
    );
    assert!(ok_out.contains(sscsb::skill::VERIFY_DOC), "{ok_out}");

    // Corrupt exactly one byte, the way a hostile in-place edit would.
    let mut bytes = std::fs::read(&installed).unwrap();
    let target = bytes.len() / 2;
    bytes[target] = if bytes[target] == b'x' { b'y' } else { b'x' };
    std::fs::write(&installed, &bytes).unwrap();

    let differs = sscsb_bin(root, &["skill", "check"]);
    assert_eq!(differs.status.code(), Some(1), "a corrupted copy exits 1");
    let out = String::from_utf8_lossy(&differs.stdout);
    assert!(out.contains("differs"), "{out}");
    assert!(out.contains("first difference at line"), "{out}");
    assert!(out.contains("bundled sha256"), "{out}");
    assert!(out.contains("on-disk sha256"), "{out}");

    // …and `install` refuses to silently clobber it. Exit 2: this is an
    // operational refusal, not a security verdict about the repository.
    let refused = sscsb_bin(root, &["skill", "install"]);
    assert_eq!(refused.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("--force"), "{stderr}");
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        bytes,
        "a refused install must leave the file untouched"
    );

    // --force is the deliberate escape hatch, and it restores the bundled copy.
    let forced = sscsb_bin(root, &["skill", "install", "--force"]);
    assert_eq!(forced.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&installed).unwrap(),
        sscsb::skill::SKILL_MD
    );
    assert_eq!(sscsb_bin(root, &["skill", "check"]).status.code(), Some(0));
}

#[test]
fn print_emits_the_bundled_bytes_and_nothing_else() {
    let dir = repo();
    let out = sscsb_bin(dir.path(), &["skill", "print"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf-8"),
        sscsb::skill::SKILL_MD,
        "`skill print` must emit the bundled copy verbatim — it is piped into files and digests"
    );
    assert!(out.stderr.is_empty(), "print must not write to stderr");
}

#[test]
fn checks_json_form_carries_the_same_verdict_and_exit_code() {
    let dir = repo();
    let root = dir.path();
    sscsb_bin(root, &["skill", "install"]);
    let out = sscsb_bin(root, &["skill", "check", "--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--format json emits JSON");
    assert_eq!(doc["state"], "identical");
    assert_eq!(doc["command"], "skill check");
    assert_eq!(doc["scope"], sscsb::skill::EMBEDDED_CHECK_SCOPE);
    assert_eq!(
        doc["bundled_sha256"],
        sscsb::skill::digest(sscsb::skill::SKILL_MD.as_bytes())
    );

    // An unknown format is a usage error before anything is read.
    let bad = sscsb_bin(root, &["skill", "check", "--format", "yaml"]);
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn a_path_override_needs_no_repository() {
    // An operator staging the skill into some other agent's directory must not
    // need a git repo for the privilege.
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("elsewhere").join("SKILL.md");
    let out = sscsb_bin(
        dir.path(),
        &["skill", "install", "--path", target.to_str().unwrap()],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "install --path must work outside a repo: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        sscsb::skill::SKILL_MD
    );
    let checked = sscsb_bin(
        dir.path(),
        &["skill", "check", "--path", target.to_str().unwrap()],
    );
    assert_eq!(checked.status.code(), Some(0));
}

#[test]
fn the_default_path_is_anchored_to_the_repo_root_not_the_cwd() {
    // Running the command from a subdirectory must install to the same place.
    let dir = repo();
    let root = dir.path();
    let sub = root.join("deep").join("nested");
    std::fs::create_dir_all(&sub).unwrap();
    let out = sscsb_bin(&sub, &["skill", "install"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        root.join(sscsb::skill::SKILL_PATH).is_file(),
        "install from a subdirectory must still write to the repo root's skill path"
    );
    assert!(!sub.join(sscsb::skill::SKILL_PATH).exists());
}

#[test]
fn the_release_workflow_ships_the_skill_as_a_signed_and_attested_asset() {
    // Ordering IS the contract, and the earlier cut of this test only pinned
    // half of it. Staging after the signer yields an unsigned asset (loud: the
    // gate refuses). Staging after the SUBJECT SET yields a signed asset with
    // no build provenance, no SBOM attestation and no SLSA subject — silent,
    // and precisely the shape that shipped while the docs claimed otherwise.
    // Both edges are asserted here.
    let release = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml"),
    )
    .expect("release.yml is readable");
    let stage = release
        .find(sscsb::skill::TEMPLATE_PATH)
        .expect("release.yml must stage the skill template into dist/");
    let subjects = release
        .find("Compute the release subject set")
        .expect("release.yml must compute one subject set");
    let sign = release
        .find("cosign sign-blob")
        .expect("release.yml must sign every asset");
    assert!(
        stage < subjects,
        "the skill must be staged BEFORE the subject set, or it is signed but unattested"
    );
    assert!(
        stage < sign,
        "the skill must be staged into dist/ before the signing loop runs"
    );
    assert!(
        release.contains(&format!("dist/{}", sscsb::skill::ASSET_NAME)),
        "the asset must be staged as dist/{}",
        sscsb::skill::ASSET_NAME
    );
    // Every attestation reads that one list, so nothing can be attested that
    // the SLSA generator was not also given.
    assert_eq!(
        release
            .matches("subject-checksums: subjects.sha256")
            .count(),
        2,
        "both attest steps must read the single computed subject list"
    );
    assert!(
        !release.contains("subject-path: dist/*.tar.gz"),
        "a `*.tar.gz`-scoped subject glob is back — it silently drops every extra asset"
    );

    // …and the gate has to CHECK the thing that is now attested, or an
    // attestation nothing verifies is decoration.
    let gate = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/deploy-gate.yml"),
    )
    .expect("deploy-gate.yml is readable");
    assert!(
        gate.contains("Determine the attested subject set"),
        "the gate must derive the attested subject set from the published assets"
    );
    assert_eq!(
        gate.matches("while IFS= read -r subject; do artifacts+=(\"$subject\"); done")
            .count(),
        3,
        "all three attestation gates (provenance, SBOM, SLSA) must read that derived set"
    );
    assert!(
        !gate.contains("artifacts=(*.tar.gz)"),
        "a gate loop is back to globbing tarballs — extra assets would go unverified"
    );
}
