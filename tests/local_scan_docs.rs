//! The local lane's contract, asserted rather than described.
//!
//! `docs/local-scan.md` carries a fenced ```contract block that is the ONLY
//! normative statement of the lane. The directory mirrors that block verbatim
//! in `site/src/local-contract.ts` and asserts the same digest, so the two
//! trees cannot drift into the state the last round shipped: a tool signing
//! `sscsb-local-scan` over a `verify --format json` document at
//! `.sscsb/out/scan-local.json`, and a directory verifying `sscsb-scan-record`
//! over a `ScanRecord` at `.sscsb/scan-record.local.json`. Every one of those
//! four mismatches is now one assertion here.
//!
//! Three classes of claim are pinned:
//!
//! - **Contract**: every line of the block equals the constant the binary
//!   actually uses, and the block's digest equals the one the site pins.
//! - **Strength**: the doc must say the record does NOT prove CI ran the scan,
//!   and must state the observability requirement. Dropping either turns an
//!   honest weaker lane into a false equivalence.
//! - **It runs**: `sscsb scan --local` produces a record, and the "verify it
//!   yourself" recipe printed in the doc is EXECUTED here against those exact
//!   bytes rather than being asserted to exist.

use assert_cmd::Command;
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::path::Path;

const LOCAL_SCAN_MD: &str = include_str!("../docs/local-scan.md");
const README_MD: &str = include_str!("../README.md");
const SIGNING_MD: &str = include_str!("../docs/signing.md");
const PHASE_1_MD: &str = include_str!("../docs/phase-1.md");
const PHASE_2_MD: &str = include_str!("../docs/phase-2.md");

/// The digest both trees pin over the normalized contract block.
///
/// Computed as `sha256("<key>=<value>\n" …)` over the block's lines in order,
/// header excluded. The site computes the same digest over its verbatim mirror
/// and asserts the same hex, so an edit on one side that is not mirrored on
/// the other fails a test in whichever tree was edited.
const CONTRACT_DIGEST: &str = "6f7f55db83c16865499db2230ef7aed46982cc84e16bdd550e44b6754d991227";

const CONTRACT_HEADER: &str = "sscsb local-lane contract v1";

/// Parse the fenced ```contract block: `key`, two-or-more spaces, `value`.
fn contract() -> BTreeMap<String, String> {
    let body = LOCAL_SCAN_MD
        .split("```contract\n")
        .nth(1)
        .expect("docs/local-scan.md must carry a fenced ```contract block")
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
/// happened to wrap it into.
///
/// Blockquote markers are stripped first. The claims that matter most here are
/// written as pull-quotes, and a `>` at each wrap point would otherwise land
/// mid-sentence and make a correctly-stated claim read as missing.
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

#[test]
fn the_contract_blocks_digest_is_the_one_both_trees_pin() {
    // The cross-repository drift guard. The site computes this same digest
    // over its verbatim mirror of the block; if either copy is edited without
    // the other, one of the two tests fails instead of a broken lane shipping.
    let normalized: String = contract()
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    let got = hex::encode(sha2::Sha256::digest(normalized.as_bytes()));
    assert_eq!(
        got, CONTRACT_DIGEST,
        "the contract block changed. Mirror it verbatim into \
         site/src/local-contract.ts and update CONTRACT_DIGEST in BOTH trees.\n\
         normalized block:\n{normalized}"
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
    expect("command", sscsb::local_scan::COMMAND.to_string());
    expect("sshsig-namespace", sscsb::local_scan::NAMESPACE.to_string());
    expect("record-path", sscsb::local_scan::RECORD_PATH.to_string());
    expect(
        "signature-path",
        sscsb::local_scan::SIGNATURE_PATH.to_string(),
    );
    expect("anchor-path", sscsb::local_scan::ANCHOR_PATH.to_string());
    expect(
        "anchor-namespaces",
        format!("git,{}", sscsb::local_scan::NAMESPACE),
    );
    expect(
        "schema-version",
        sscsb::local_scan::SCHEMA_VERSION.to_string(),
    );
    expect(
        "methodology-version",
        sscsb::local_scan::METHODOLOGY_VERSION.to_string(),
    );
    expect(
        "submission-label",
        sscsb::local_scan::SUBMISSION_LABEL.to_string(),
    );
    expect(
        "signed-bytes",
        format!("the bytes of {}, verbatim", sscsb::local_scan::RECORD_PATH),
    );
    expect("record-shape", "ScanRecord".to_string());
}

#[test]
fn the_command_the_contract_names_is_the_one_the_cli_accepts() {
    // The blocker this test exists for: the directory rendered
    // `sscsb scan --local --submit` on every provisional listing while the CLI
    // implemented `verify --local`, so the lane was unreachable by the only
    // string a maintainer was ever shown.
    let command = contract_value("command");
    let mut argv = command.split_whitespace();
    assert_eq!(argv.next(), Some("sscsb"));
    let args: Vec<&str> = argv.collect();

    // `--help` on the subcommand proves the flags parse without running a scan.
    let mut help = args.clone();
    help.push("--help");
    let out = Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(&help)
        .output()
        .expect("sscsb runs");
    assert!(
        out.status.success(),
        "`{command} --help` must parse: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // …and the spelling the lane REJECTED must not silently work.
    let rejected = Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(["verify", "--local", "--help"])
        .output()
        .expect("sscsb runs");
    assert!(
        !rejected.status.success(),
        "`sscsb verify --local` must not exist — the contract names exactly one command"
    );
}

#[test]
fn every_doc_spells_the_command_the_contract_names() {
    let command = contract_value("command");
    let base = command
        .strip_suffix(" --submit")
        .expect("the contract command ends in --submit");
    for (name, doc) in [
        ("docs/local-scan.md", LOCAL_SCAN_MD),
        ("README.md", README_MD),
        ("docs/phase-1.md", PHASE_1_MD),
        ("docs/phase-2.md", PHASE_2_MD),
    ] {
        assert!(doc.contains(base), "{name} must spell the command `{base}`");
        assert!(
            !doc.contains("sscsb verify --local"),
            "{name} names `sscsb verify --local`, which the CLI does not accept"
        );
    }
}

#[test]
fn the_documented_namespace_is_the_one_the_binary_signs_in() {
    // A doc that names a different namespace tells a maintainer to commit a
    // grant that permits nothing, and the refusal they get back will quote a
    // string their anchor does not contain.
    for (name, doc) in [
        ("docs/local-scan.md", LOCAL_SCAN_MD),
        ("docs/signing.md", SIGNING_MD),
    ] {
        assert!(
            doc.contains(sscsb::local_scan::NAMESPACE),
            "{name} must name the SSHSIG namespace `{}`",
            sscsb::local_scan::NAMESPACE
        );
        assert!(
            !doc.contains("sscsb-local-scan"),
            "{name} still names the retired namespace `sscsb-local-scan`"
        );
    }
}

#[test]
fn the_documented_paths_are_committed_paths_that_init_does_not_ignore() {
    let record = contract_value("record-path");
    let signature = contract_value("signature-path");
    assert!(LOCAL_SCAN_MD.contains(&record));
    assert!(LOCAL_SCAN_MD.contains(&signature));
    assert!(README_MD.contains(&record));
    // The transport blocker: the tool wrote into `.sscsb/out/`, which `init`
    // gitignores, while ingest fetched a committed path. A record nobody can
    // commit is a record nobody can submit.
    assert!(
        !record.starts_with(sscsb::local_scan::OUT_DIR),
        "the record must NOT live under the gitignored {} — ingest reads a committed path",
        sscsb::local_scan::OUT_DIR
    );
    assert!(!signature.starts_with(sscsb::local_scan::OUT_DIR));
}

#[test]
fn the_docs_state_the_limit_of_what_a_local_record_proves() {
    assert_states(
        "docs/local-scan.md",
        LOCAL_SCAN_MD,
        "It does not prove your CI produced the result.",
    );
    assert_states(
        "docs/local-scan.md",
        LOCAL_SCAN_MD,
        "Where someone else could have checked, we require that someone else.",
    );
    assert_states(
        "docs/local-scan.md",
        LOCAL_SCAN_MD,
        "a maintainer's self-report **alone** is not countable",
    );
    assert_states(
        "docs/local-scan.md",
        LOCAL_SCAN_MD,
        "A contradiction therefore **costs** the repository",
    );
    assert_states(
        "README.md",
        README_MD,
        "It does **not** prove your CI produced it",
    );
}

#[test]
fn the_docs_state_what_a_verified_local_record_does_prove() {
    // The positive claim has to be pinned too: a doc that only lists what the
    // lane cannot do gives a maintainer no reason to use it, and the wording is
    // the exact scope the signature supports.
    let claim = "a holder of a key this repository commits as an approved signer";
    assert!(unwrapped(LOCAL_SCAN_MD).contains(claim));
    assert!(unwrapped(README_MD).contains(claim));
}

// ───────────────────────── end-to-end: the lane runs ────────────────────────

fn git(repo: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A bootstrapped repo whose committed anchor approves one generated key, with
/// git configured to sign with it. Returns (repo dir, home dir, principal).
fn signing_repo() -> (tempfile::TempDir, tempfile::TempDir, String) {
    signing_repo_of_class("human")
}

/// As [`signing_repo`], but registers the generated key under an arbitrary
/// signer `class`. The class is what decides whether the generated anchor
/// grants the scan-record namespace, so it has to be a parameter for the
/// refusal path to be testable at all.
fn signing_repo_of_class(class: &str) -> (tempfile::TempDir, tempfile::TempDir, String) {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let home_dir = tempfile::tempdir().expect("tempdir");
    let repo = repo_dir.path();
    let principal = "doc-guard@example.com".to_string();

    git(repo, &["init", "-b", "main"]);
    git(repo, &["config", "user.name", "SSCSB Doc Guard"]);
    git(repo, &["config", "user.email", &principal]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    git(
        repo,
        &["remote", "add", "origin", "https://github.com/o/r.git"],
    );

    let key = home_dir.path().join("signer");
    let out = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &principal,
            "-f",
            key.to_str().unwrap(),
        ])
        .output()
        .expect("ssh-keygen must be installed to test the signing lane");
    assert!(out.status.success(), "ssh-keygen: {out:?}");
    let pub_text = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let material = pub_text
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");

    sscsb_bin(repo, &["init"]);
    std::fs::write(
        repo.join(".sscsb/policy/signers.toml"),
        format!(
            "[[signer]]\nprincipal = \"{principal}\"\nclass = \"{class}\"\n\
             ssh_public_key = \"{material} {principal}\"\n"
        ),
    )
    .unwrap();
    sscsb_bin(repo, &["init"]);

    git(repo, &["config", "gpg.format", "ssh"]);
    git(
        repo,
        &[
            "config",
            "user.signingkey",
            key.with_extension("pub").to_str().unwrap(),
        ],
    );
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-m", "bootstrap"]);
    (repo_dir, home_dir, principal)
}

fn sscsb_bin(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .expect("sscsb runs")
}

#[test]
fn the_generated_anchor_grants_the_namespace_the_docs_tell_people_to_commit() {
    // The end-to-end claim: `sscsb init` must produce an allowed_signers file
    // that permits the scan namespace. If the generator ever drops the grant,
    // every documented instruction ("run sscsb init, then commit it") becomes a
    // dead end, and the failure only shows up at signature-verification time.
    let (repo_dir, home_dir, principal) = signing_repo();
    drop(home_dir);
    let anchor =
        std::fs::read_to_string(repo_dir.path().join(sscsb::local_scan::ANCHOR_PATH)).unwrap();
    let parsed = sscsb::local_scan::parse_allowed_signers(&anchor);
    let line = parsed
        .iter()
        .find(|a| a.principals.contains(&principal))
        .unwrap_or_else(|| panic!("generated anchor has no line for the signer:\n{anchor}"));
    assert!(
        line.permits(sscsb::local_scan::NAMESPACE),
        "the generated anchor must permit `{}`:\n{anchor}",
        sscsb::local_scan::NAMESPACE
    );
    // The grant is additive — commit signing must keep working.
    assert!(
        line.permits("git"),
        "the generated anchor must still permit `git`:\n{anchor}"
    );
    // …and it is exactly the `anchor-namespaces` line of the contract.
    assert!(
        anchor.contains(&format!(
            "namespaces=\"{}\"",
            contract_value("anchor-namespaces")
        )),
        "the generated anchor must carry the contract's namespaces= grant:\n{anchor}"
    );
}

/// The generated anchor grants the scan namespace to `class = "human"` ONLY,
/// and the refusal for every other class is enforced by the VERIFIER, not by a
/// message.
///
/// A local record is a maintainer's attested word about a machine nobody else
/// can inspect, and it is the one lane whose class-C verdicts count with no
/// independent corroboration. CI does not need it (it has the action lane,
/// which proves strictly more), and an `ai`-class signer asserting one would
/// contradict `src/signers.rs`'s own load-bearing invariant that an ai-class
/// signer never signs.
///
/// So this test does not assert on the generated string. It drives the real
/// path twice: the tool refuses to produce a record at all, and the exact
/// `ssh-keygen -Y verify` invocation the directory's ingest runs REJECTS a
/// record signed by the non-human key — while the same signature verifies fine
/// under `git`, proving the refusal is the namespace grant and not a broken
/// fixture.
#[test]
fn a_local_record_signed_by_a_non_human_principal_is_refused_end_to_end() {
    // ── class = "ci": the key IS an approved signer, but only for `git`. ──
    let (repo_dir, home_dir, principal) = signing_repo_of_class("ci");
    let repo = repo_dir.path();

    let out = sscsb_bin(repo, &["scan", "--local"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(2),
        "a ci-class signer must be an OPERATIONAL refusal, not a control failure:\n{stderr}"
    );
    assert!(
        stderr.contains(sscsb::local_scan::NAMESPACE) && stderr.contains("class = \"human\""),
        "the refusal must name the namespace and the human-only rule:\n{stderr}"
    );
    assert!(
        !repo.join(sscsb::local_scan::RECORD_PATH).exists(),
        "a refused run must not leave a record behind"
    );

    // Now the verifier itself, on bytes the ci key really signed. This is the
    // command directory-ingest.yml runs, argument for argument.
    let record = repo.join("forged-record.json");
    std::fs::write(&record, b"{\"schema_version\":1}\n").unwrap();
    let key = home_dir.path().join("signer");
    let sign = |namespace: &str| {
        // `ssh-keygen -Y sign` PROMPTS before overwriting an existing `.sig`
        // and would hang the test forever; the tool's own `sign_record` clears
        // the same file for the same reason.
        let _ = std::fs::remove_file(record.with_extension("json.sig"));
        let out = std::process::Command::new("ssh-keygen")
            .args([
                "-Y",
                "sign",
                "-n",
                namespace,
                "-f",
                key.to_str().unwrap(),
                record.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ssh-keygen runs");
        assert!(
            out.status.success(),
            "signing must succeed — the key is real; only the GRANT is in question: {out:?}"
        );
        std::fs::read(record.with_extension("json.sig")).unwrap()
    };
    let verify = |namespace: &str, sig: &[u8]| -> std::process::Output {
        let sig_path = repo.join("forged.sig");
        std::fs::write(&sig_path, sig).unwrap();
        let mut child = std::process::Command::new("ssh-keygen")
            .args([
                "-Y",
                "verify",
                "-f",
                sscsb::local_scan::ANCHOR_PATH,
                "-I",
                &principal,
                "-n",
                namespace,
                "-s",
                sig_path.to_str().unwrap(),
            ])
            .current_dir(repo)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("ssh-keygen runs");
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&std::fs::read(&record).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let scan_sig = sign(sscsb::local_scan::NAMESPACE);
    let refused = verify(sscsb::local_scan::NAMESPACE, &scan_sig);
    assert!(
        !refused.status.success(),
        "the directory's own verify must REJECT a scan record signed by a ci-class key:\n{}\n{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );

    // The control: the same key, the same anchor, the namespace it IS granted.
    // Without this the test would pass just as well against a broken fixture.
    let git_sig = sign("git");
    let accepted = verify("git", &git_sig);
    assert!(
        accepted.status.success(),
        "the ci key must still verify under `git` — otherwise this test proves nothing:\n{}\n{}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );

    // ── class = "ai": the key is never emitted into the anchor at all. ──
    let (ai_repo_dir, _ai_home, _p) = signing_repo_of_class("ai");
    let ai_out = sscsb_bin(ai_repo_dir.path(), &["scan", "--local"]);
    let ai_stderr = String::from_utf8_lossy(&ai_out.stderr).to_string();
    assert_eq!(
        ai_out.status.code(),
        Some(2),
        "an ai-class signer must be refused too:\n{ai_stderr}"
    );
    assert!(
        ai_stderr.contains("NOT an approved signer"),
        "with agent-signing off the ai key is not in the anchor at all:\n{ai_stderr}"
    );
    assert!(!ai_repo_dir
        .path()
        .join(sscsb::local_scan::RECORD_PATH)
        .exists());
}

/// The whole lane, run: `sscsb scan --local` produces a record and a signature
/// at the contracted paths, and the "verify it yourself" recipe printed in
/// `docs/local-scan.md` is EXTRACTED FROM THE DOC and executed against those
/// exact bytes.
///
/// The `gh api` half of the published recipe fetches the committed anchor from
/// GitHub; offline, the local committed file IS that content, so the fetch is
/// substituted and the `ssh-keygen -Y verify` half — the part that can be
/// wrong — runs verbatim, argument for argument, out of the document.
#[test]
fn the_published_verify_it_yourself_recipe_actually_runs() {
    let (repo_dir, _home, principal) = signing_repo();
    let repo = repo_dir.path();

    let out = sscsb_bin(repo, &["scan", "--local"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Exit 1 is legitimate here (a fresh repo FAILs controls); exit 2 is not.
    assert!(
        matches!(out.status.code(), Some(0 | 1)),
        "`sscsb scan --local` failed operationally:\n{stdout}\n{stderr}"
    );

    let record_path = repo.join(contract_value("record-path"));
    let sig_path = repo.join(contract_value("signature-path"));
    assert!(record_path.is_file(), "no record at {record_path:?}");
    assert!(sig_path.is_file(), "no signature at {sig_path:?}");

    // Neither output may be gitignored: the submission is a pointer to them.
    for path in [
        contract_value("record-path"),
        contract_value("signature-path"),
    ] {
        let out = std::process::Command::new("git")
            .args(["check-ignore", "-q", "--no-index", &path])
            .current_dir(repo)
            .output()
            .expect("git runs");
        assert_eq!(
            out.status.code(),
            Some(1),
            "{path} is gitignored — it must be committable"
        );
    }

    // The record is a directory ScanRecord (contract line `record-shape`).
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    for field in contract_value("record-fields").split_whitespace() {
        assert!(record.get(field).is_some(), "record is missing `{field}`");
    }
    assert_eq!(record["repo"]["owner"], "o");
    assert_eq!(
        record["local"]["signer"]["principal"].as_str(),
        Some(principal.as_str())
    );

    // ── the recipe, lifted out of the document and executed ──
    // Lift the recipe out of the ```sh fence that publishes it — not out of
    // prose that merely mentions the command — and run it argument for
    // argument. A recipe that is asserted to EXIST is how the last one rotted.
    let fence = LOCAL_SCAN_MD
        .split("```sh\n")
        .find(|b| b.contains("ssh-keygen -Y verify -f"))
        .expect("docs/local-scan.md must publish a runnable ssh-keygen -Y verify recipe")
        .split("```")
        .next()
        .unwrap();
    let joined = fence.replace("\\\n", " ");
    let line = joined
        .lines()
        .find(|l| l.contains("ssh-keygen -Y verify -f"))
        .expect("the fence must hold the verify invocation on one logical line");
    let start = line.find("ssh-keygen").unwrap();
    let argv: Vec<String> = line[start..]
        .split_whitespace()
        .skip(1) // the program name
        .take_while(|t| *t != "<")
        .map(|t| {
            t.replace("PRINCIPAL", &principal)
                // `gh api … > allowed_signers` writes the repository's own
                // committed anchor; offline, that file IS the anchor.
                .replace("allowed_signers", sscsb::local_scan::ANCHOR_PATH)
        })
        .collect();
    // The doc's `-f allowed_signers` names the file the gh-api step writes;
    // offline that content is the repository's own committed anchor.
    assert!(argv.contains(&"-n".to_string()) && argv.contains(&"-s".to_string()));
    assert!(
        argv.contains(&sscsb::local_scan::NAMESPACE.to_string()),
        "the recipe must verify under the contract namespace: {argv:?}"
    );

    let record_bytes = std::fs::read(&record_path).unwrap();
    let mut child = std::process::Command::new("ssh-keygen")
        .args(&argv)
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("ssh-keygen runs");
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&record_bytes)
        .unwrap();
    let verified = child.wait_with_output().unwrap();
    assert!(
        verified.status.success(),
        "the PUBLISHED recipe did not verify the record it describes.\n\
         argv: {argv:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        String::from_utf8_lossy(&verified.stdout).contains("Good"),
        "ssh-keygen must report a good signature: {}",
        String::from_utf8_lossy(&verified.stdout)
    );
}
