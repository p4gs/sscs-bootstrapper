//! AGENTS.md must never describe a `sscsb` that does not exist.
//!
//! Documentation that lies to an agent is worse than no documentation: the
//! agent will confidently invoke a command that was renamed three commits ago
//! and report the resulting exit code 2 as a security finding. These tests pin
//! the doc to the binary in both directions, so a renamed subcommand or a
//! retired control breaks the build instead of rotting silently.

use assert_cmd::Command;
use sscsb::controls;

const AGENTS_MD: &str = include_str!("../AGENTS.md");

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
        // clap generates `help` itself; it is not part of the tool's surface.
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

/// Every `` `sscsb <word>` `` occurrence in AGENTS.md, reduced to <word>.
fn documented_subcommands() -> Vec<String> {
    let mut cmds: Vec<String> = AGENTS_MD
        .match_indices("`sscsb ")
        .filter_map(|(i, pat)| {
            AGENTS_MD[i + pat.len()..]
                .split_whitespace()
                .next()
                .map(|w| w.trim_end_matches('`').to_string())
        })
        // Drop placeholders (`<command>`) and flags (`--version`); keep real names.
        .filter(|w| !w.is_empty())
        .filter(|w| w.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-'))
        .filter(|w| !w.starts_with('-'))
        .collect();
    cmds.sort();
    cmds.dedup();
    cmds
}

#[test]
fn agents_md_documents_every_subcommand() {
    let actual = binary_subcommands();
    let documented = documented_subcommands();

    let undocumented: Vec<&String> = actual.iter().filter(|c| !documented.contains(c)).collect();

    assert!(
        undocumented.is_empty(),
        "AGENTS.md is missing subcommands that exist in the binary: {undocumented:?}\n\
         Add them to the command reference, or agents will never discover them."
    );
}

#[test]
fn agents_md_invents_no_subcommand() {
    let actual = binary_subcommands();
    let documented = documented_subcommands();

    let invented: Vec<&String> = documented.iter().filter(|c| !actual.contains(c)).collect();

    assert!(
        invented.is_empty(),
        "AGENTS.md documents subcommands the binary does not have: {invented:?}\n\
         An agent following this doc would get exit code 2 and misreport it."
    );
}

#[test]
fn agents_md_invents_no_control_id() {
    // Control ids appear in prose as `sscsb enable <id>` / `sscsb disable <id>`
    // and inside the `[controls.<id>]` config example.
    let known: Vec<&str> = controls::CONTROLS.iter().map(|c| c.id).collect();

    // Anchor to real TOML table headers at the start of a line. Matching the
    // bare substring anywhere would also catch the CLI usage string
    // `sscsb verify [controls...]`, whose "id" parses as "..".
    let cited: Vec<String> = AGENTS_MD
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("[controls."))
        .filter_map(|rest| rest.strip_suffix(']'))
        .map(str::to_string)
        .collect();

    assert!(
        !cited.is_empty(),
        "no `[controls.<id>]` example found in AGENTS.md; the config section was removed \
         or reworded, and this guard is now vacuous"
    );

    for id in &cited {
        assert!(
            known.contains(&id.as_str()),
            "AGENTS.md cites control `{id}`, which is not in the registry. \
             Known ids: {known:?}"
        );
    }
}

#[test]
fn agents_md_exit_code_table_matches_reality() {
    // The doc promises 0 / 1 / 2 and tells agents to branch on them. Prove the
    // two unambiguous ends: a usage error is 2, and `--help` is 0. The `1` case
    // (a real gate failure) is covered by the integration suite, which builds a
    // repo that genuinely fails a control.
    for code in ["`0`", "`1`", "`2`"] {
        assert!(
            AGENTS_MD.contains(code),
            "exit code {code} vanished from AGENTS.md's contract table"
        );
    }

    let usage_err = Command::cargo_bin("sscsb")
        .expect("binary builds")
        .arg("definitely-not-a-subcommand")
        .output()
        .expect("runs");
    assert_eq!(
        usage_err.status.code(),
        Some(2),
        "AGENTS.md tells agents exit 2 means `sscsb` itself errored; \
         an unknown subcommand must produce it"
    );

    let help_ok = Command::cargo_bin("sscsb")
        .expect("binary builds")
        .arg("--help")
        .output()
        .expect("runs");
    assert_eq!(
        help_ok.status.code(),
        Some(0),
        "AGENTS.md documents 0 as success"
    );
}

/// The verdict table is the part of this doc an agent parses most literally,
/// so its spellings must be the binary's own. `Outcome::Disabled` renders as
/// lowercase `disabled` while every other symbol is uppercase, and the doc
/// carried `DISABLED` until an evidence pass caught it — an agent
/// string-matching the table would simply never match that row.
#[test]
fn agents_md_verdict_table_uses_the_binary_symbols() {
    for outcome in [
        controls::Outcome::Pass,
        controls::Outcome::Fail,
        controls::Outcome::Degraded,
        controls::Outcome::Disabled,
        controls::Outcome::Info,
    ] {
        let symbol = outcome.symbol();
        assert!(
            AGENTS_MD.contains(&format!("`{symbol}`")),
            "AGENTS.md's verdict table is missing the exact symbol `{symbol}` \
             that the binary prints — an agent matching on the doc's spelling \
             would never match this outcome"
        );
    }
}

/// The subcommand tests above only compare the FIRST token after `sscsb`, so a
/// wrong nested command or argument shape sails through. That is not
/// hypothetical: AGENTS.md documented `sscsb agent-key setup <backend>` for
/// weeks, while the binary takes `--backend` as a flag — an agent following the
/// doc got exit 2 and, per this file's own contract, would report that as a
/// tool error rather than its own bad invocation.
///
/// Rather than reimplement clap's grammar, this asks the binary: every fully
/// specified invocation the doc shows must at least PARSE. `--help` short-
/// circuits execution, so this checks argument shape without running anything.
#[test]
fn agents_md_nested_invocations_actually_parse() {
    // Read the invocations out of the DOC, so the guard tests whatever the doc
    // currently claims. An earlier version of this test held a hardcoded list
    // gated on `AGENTS_MD.contains(shape)`, which made it vacuous in exactly
    // the case that matters: change the doc to a wrong shape and the check
    // silently skipped itself.
    let documented: Vec<Vec<String>> = AGENTS_MD
        .match_indices("`sscsb ")
        .filter_map(|(i, pat)| {
            let rest = &AGENTS_MD[i + pat.len()..];
            let invocation = rest.split('`').next()?;
            // Everything from the first `[` on is optional-argument syntax.
            // Truncate rather than filter token-by-token: a bracketed group can
            // span several tokens (`[--vex <file>]`), and markdown table cells
            // escape the alternation pipe (`[--format text\|json]`), so partial
            // removal leaves fragments that are not arguments at all.
            let required = invocation.split('[').next()?;
            let mut argv: Vec<String> = Vec::new();
            for token in required.split_whitespace() {
                if token == "..." {
                    continue;
                }
                // Substitute a placeholder with something type-plausible so
                // clap validates shape rather than rejecting the literal.
                argv.push(if token.starts_with('<') {
                    "PLACEHOLDER".to_string()
                } else {
                    token.to_string()
                });
            }
            // Skip the generic `sscsb <command> --help` form — its first token
            // is a stand-in for any subcommand, not an invocation to check.
            if argv.first().is_some_and(|t| t == "PLACEHOLDER") {
                return None;
            }
            // Only multi-word invocations; single subcommands are already
            // covered by the two set-difference tests above.
            (argv.len() >= 2).then_some(argv)
        })
        .collect();

    assert!(
        documented.len() >= 10,
        "parsed only {} multi-word invocations from AGENTS.md; the extractor is \
         broken, not the doc",
        documented.len()
    );

    let mut broken = Vec::new();
    for argv in &documented {
        // Hooks are invoked by git with real operands and have side effects;
        // shape-check them without executing.
        let mut probe: Vec<String> = argv.clone();
        probe.push("--help".to_string());

        let out = Command::cargo_bin("sscsb")
            .expect("binary builds")
            .args(&probe)
            .output()
            .expect("runs");

        // Exit 2 is clap's usage error: the doc described a shape the CLI does
        // not accept. A trailing --help does NOT rescue a bad positional, so a
        // clean parse really is a clean parse.
        if out.status.code() == Some(2) {
            broken.push(format!(
                "`sscsb {}` → {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("?")
            ));
        }
    }

    assert!(
        broken.is_empty(),
        "AGENTS.md documents invocations the binary rejects as usage errors:\n  {}\n\n\
         An agent following the doc gets exit 2 and, per this file's own contract, \
         reports it as a tool error rather than its own bad invocation.",
        broken.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Behavioural guards.
//
// Everything above pins the doc's *vocabulary* to the binary — command names,
// symbols, argument shapes. That caught renames but not lies: a documented
// sentence about what a command DOES could be flatly false and every test
// above still passed. An agent given only AGENTS.md and the binary found four
// such sentences in one bootstrap run. The tests below run the binary and
// compare its behaviour to what the doc claims about it.
// ---------------------------------------------------------------------------

/// A throwaway repo with `sscsb init` already run in it.
fn bootstrapped_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path();
    for args in [
        vec!["init", "-b", "main"],
        vec!["config", "user.name", "SSCSB Doc Guard"],
        vec!["config", "user.email", "doc-guard@example.com"],
        vec!["config", "commit.gpgsign", "false"],
    ] {
        let out = std::process::Command::new("git")
            .args(&args)
            .current_dir(repo)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?} failed");
    }
    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .arg("init")
        .current_dir(repo)
        .assert()
        .success();
    dir
}

fn sscsb_in(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("runs")
}

/// Every file under `.sscsb/`, plus the repo's `.gitignore`, relative to root.
fn generated_files(root: &std::path::Path) -> Vec<String> {
    fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join(".sscsb"), root, &mut out);
    if root.join(".gitignore").is_file() {
        out.push(".gitignore".to_string());
    }
    out.sort();
    out
}

/// The paths AGENTS.md lists as rewritten on every `init`.
fn documented_as_rewritten() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_list = false;
    for line in AGENTS_MD.lines() {
        let t = line.trim();
        if !in_list {
            in_list = t.contains("Rewritten every run");
            continue;
        }
        if t.is_empty() {
            if out.is_empty() {
                continue; // blank line between the lead-in and the list
            }
            break;
        }
        let Some(path) = t.strip_prefix("- `").and_then(|r| r.split('`').next()) else {
            break;
        };
        out.push(path.to_string());
    }
    out.sort();
    out
}

/// AGENTS.md said `init` "will not clobber edits". It preserves config and CI
/// templates, but unconditionally rewrites the three hook shims and
/// `allowed_signers` — so an agent that put local logic in a shim lost it
/// silently on the next `init`. `src/init.rs`'s own module doc had the truth
/// all along; only the agent-facing file was wrong.
///
/// This pins the doc's list to what init MEASURABLY rewrites, in both
/// directions: a file that starts being regenerated, or stops, fails here.
#[test]
fn agents_md_lists_exactly_what_init_rewrites() {
    const MARKER: &str = "# SSCSB-DOC-GUARD-MARKER";
    let dir = bootstrapped_repo();
    let repo = dir.path();

    let files = generated_files(repo);
    assert!(
        files.len() > 5,
        "expected init to generate several files, found {files:?}"
    );
    for rel in &files {
        let p = repo.join(rel);
        let mut body = std::fs::read_to_string(&p).unwrap_or_default();
        body.push('\n');
        body.push_str(MARKER);
        body.push('\n');
        std::fs::write(&p, body).expect("marker written");
    }

    Command::cargo_bin("sscsb")
        .expect("binary builds")
        .arg("init")
        .current_dir(repo)
        .assert()
        .success();

    let mut clobbered: Vec<String> = files
        .into_iter()
        .filter(|rel| {
            !std::fs::read_to_string(repo.join(rel))
                .unwrap_or_default()
                .contains(MARKER)
        })
        .collect();
    clobbered.sort();

    assert!(
        !clobbered.is_empty(),
        "no file was regenerated — this guard has gone vacuous, or init changed"
    );
    assert_eq!(
        clobbered,
        documented_as_rewritten(),
        "AGENTS.md's `Rewritten every run` list does not match what `sscsb init` \
         actually overwrites.\n  actually clobbered: {clobbered:?}\n  documented:         {:?}\n\n\
         An agent trusting the doc either loses an edit it was told would survive, \
         or is warned off editing a file that is in fact preserved.",
        documented_as_rewritten()
    );
}

/// AGENTS.md called `.sscsb/out/` "gitignored" while `init` wrote no
/// `.gitignore` at all, so `git add .` after `sscsb sbom` committed a
/// regenerated SBOM into policy history. Ask git, not the file text.
#[test]
fn agents_md_generated_output_really_is_ignored() {
    let dir = bootstrapped_repo();
    let repo = dir.path();

    let ignored = |rel: &str| {
        std::process::Command::new("git")
            .args(["check-ignore", "-q", "--no-index", rel])
            .current_dir(repo)
            .output()
            .expect("git runs")
            .status
            .code()
            == Some(0)
    };

    assert!(
        ignored(".sscsb/out/sbom.cdx.json"),
        "AGENTS.md tells agents `.sscsb/out/` is ignored; git disagrees, so an \
         agent running `git add .` commits generated SBOMs as policy"
    );
    assert!(
        !ignored(".sscsb/policy/signers.toml"),
        "policy must stay committable — AGENTS.md says everything outside \
         `.sscsb/out/` IS committed"
    );
    assert!(
        AGENTS_MD.contains(sscsb::init::OUT_IGNORE_RULE),
        "AGENTS.md must name the ignore rule `{}` that init installs",
        sscsb::init::OUT_IGNORE_RULE
    );
}

/// The doc defined `DEGRADED` as "a required tool is missing" and told agents
/// to "install the named tool". In a real bootstrap, all four DEGRADED
/// controls were missing config, a remote, or a policy — no tool was missing
/// and none was named, sending the agent hunting for installed binaries.
///
/// This proves the tool-independent DEGRADED state is real, so the doc's
/// broader definition is not editorial preference.
#[test]
fn agents_md_degraded_does_not_require_a_missing_tool() {
    let dir = bootstrapped_repo();
    let out = sscsb_in(dir.path(), &["verify", "commit-signing"]);
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("[DEGRADED]"),
        "fixture drifted: a freshly bootstrapped repo with no signers should \
         degrade `commit-signing`. Got:\n{text}"
    );
    // `tools::degrade_message` is the only thing that emits this phrase, so its
    // absence proves nothing was missing from PATH.
    assert!(
        !text.contains("not found on PATH"),
        "this control degraded because of a MISSING TOOL, which would make the \
         doc's old definition correct and this guard meaningless:\n{text}"
    );
    assert!(
        AGENTS_MD.contains("could not be performed"),
        "AGENTS.md's DEGRADED row must define the outcome as the check not \
         happening, not narrowly as a missing tool"
    );
}

/// `init` takes no flags — no `--force`, no `--dry-run`. The doc never said
/// so, and an agent that wanted to regenerate a CI template had no way to
/// learn that deleting the file is the only route.
#[test]
fn agents_md_init_flag_claim_matches_the_binary() {
    let out = Command::cargo_bin("sscsb")
        .expect("binary builds")
        .args(["init", "--help"])
        .output()
        .expect("runs");
    let help = String::from_utf8(out.stdout).expect("utf-8");

    let flags: Vec<String> = help
        .lines()
        .skip_while(|l| !l.starts_with("Options:"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().find(|w| w.starts_with("--")))
        .map(str::to_string)
        .collect();

    assert_eq!(
        flags,
        vec!["--help".to_string()],
        "`sscsb init` grew a flag. That is fine — but AGENTS.md states it takes \
         none, so update the doc's init section and this guard together."
    );
    assert!(
        AGENTS_MD.contains("takes no flags"),
        "AGENTS.md must say `init` takes no flags, and that deleting a file is \
         the only way to regenerate it"
    );
}

/// `harden` is not a gate and does not fit the exit-code table: its documented
/// dry-run exits 1 when it cannot find a GitHub repo, which against that table
/// reads as "a gate failed". The doc must describe harden's own codes.
#[test]
fn agents_md_documents_harden_exit_codes() {
    let dir = bootstrapped_repo();
    let repo = dir.path();

    // No origin remote and no `github_repo` in config: harden cannot inspect
    // anything. This is the invocation the doc shows.
    assert_eq!(
        sscsb_in(repo, &["harden"]).status.code(),
        Some(1),
        "a harden dry-run that cannot resolve a repo must exit 1 — the fact the \
         doc has to explain, because the exit-code table reads it as a failed gate"
    );
    assert_eq!(
        sscsb_in(repo, &["harden", "definitely-not-a-control"])
            .status
            .code(),
        Some(2),
        "harden rejects an unsupported control with 2"
    );

    let section = AGENTS_MD
        .split("## `sscsb harden`")
        .nth(1)
        .expect("AGENTS.md needs a `sscsb harden` section documenting its codes");
    for code in ["`0`", "`1`", "`2`"] {
        assert!(
            section.contains(code),
            "harden's section must document exit {code}; agents branch on it"
        );
    }
}

/// `init` prints its own next steps, and step 2 is `sscsb deps baseline` — a
/// command the doc's core loop omitted entirely. An agent following only
/// AGENTS.md declared a repo bootstrapped without ever running it.
///
/// Reads the steps from `init::NEXT_STEPS`, so changing the guidance without
/// changing the doc fails here.
#[test]
fn agents_md_core_loop_covers_the_bootstrap_next_steps() {
    let commands: Vec<String> = sscsb::init::NEXT_STEPS
        .iter()
        .flat_map(|step| {
            step.match_indices("sscsb ").map(|(i, _)| {
                step[i..]
                    .split("&&")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(['.', ')'])
                    .to_string()
            })
        })
        .collect();

    assert!(
        commands.iter().any(|c| c == "sscsb deps baseline"),
        "fixture drifted: NEXT_STEPS no longer names `sscsb deps baseline`; got {commands:?}"
    );

    let loop_block = AGENTS_MD
        .split("## The core loop")
        .nth(1)
        .and_then(|s| s.split("## ").next())
        .expect("AGENTS.md needs a `The core loop` section");

    let missing: Vec<&String> = commands
        .iter()
        .filter(|c| !loop_block.contains(c.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "`sscsb init` tells the user to run {missing:?}, but AGENTS.md's core loop \
         never mentions them. An agent following only the doc reports the repo \
         bootstrapped with a step skipped."
    );
}

#[test]
fn agents_md_states_the_ai_cannot_sign_invariant() {
    // This is the single load-bearing safety claim in the file. If a future
    // edit softens it into "prefer not to", an agent may reasonably try.
    let lowered = AGENTS_MD.to_lowercase();
    assert!(
        lowered.contains("you cannot sign"),
        "AGENTS.md must state the AI-cannot-sign invariant in unhedged terms"
    );
    assert!(
        lowered.contains("--no-gpg-sign"),
        "AGENTS.md must name --no-gpg-sign as a prohibited route around signing"
    );
}

/// AGENTS.md's `skill check` row must document the surface the command
/// actually has.
///
/// The skill file calls AGENTS.md the "full machine contract", so an agent that
/// reads only AGENTS.md is the intended reader. The row documented exit codes
/// and the tamper caveat and said nothing about `binary trust`,
/// `narrow_claim_holds` or the `binary` block — a whole verdict the command
/// prints on every result, and the one that decides what a clean check is
/// worth. Pinned to the binary the way the rest of the file is: the fields are
/// read out of a real `--format json` run, not restated.
#[test]
fn agents_md_documents_the_binary_trust_surface_skill_check_actually_emits() {
    let dir = bootstrapped_repo();
    assert!(sscsb_in(dir.path(), &["skill", "install"]).status.success());

    let run = |exe: &std::path::Path| -> serde_json::Map<String, serde_json::Value> {
        let out = std::process::Command::new(exe)
            .args(["skill", "check", "--format", "json"])
            .current_dir(dir.path())
            .output()
            .expect("runs");
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("json from {}: {e}", exe.display()));
        doc["binary"].as_object().expect("a `binary` block").clone()
    };

    let real = assert_cmd::cargo::cargo_bin("sscsb");
    let mut binary = run(&real);

    // …and again THROUGH A SYMLINK, because `resolved_path` is omitted when
    // there is nothing to resolve. Without this the test only documents the
    // keys that this host's layout happens to produce, and a field would go
    // undocumented on every machine where the binary is not behind a link —
    // which is how `resolved_path` was missed until a coverage run under
    // `/tmp` (a symlink to `/private/tmp` on macOS) emitted it.
    let link_dir = tempfile::tempdir().expect("tempdir");
    let link = link_dir.path().join("sscsb");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    #[cfg(unix)]
    {
        let through_link = run(&link);
        assert!(
            through_link.contains_key("resolved_path"),
            "invoking through a symlink must report the path it resolves to: {through_link:?}"
        );
        for (k, v) in through_link {
            binary.entry(k).or_insert(v);
        }
    }

    // Every key the block emits has to be findable in the doc, and so does the
    // verdict vocabulary an agent would branch on.
    let mut expected: Vec<String> = binary.keys().cloned().collect();
    expected.extend(
        [
            "user-writable",
            "not-user-writable",
            "unknown",
            "binary trust",
        ]
        .into_iter()
        .map(str::to_string),
    );
    // Probe rows are what let an agent name WHICH link is writable.
    expected.extend(
        binary["probes"]
            .as_array()
            .expect("probes")
            .first()
            .expect("at least one probe")
            .as_object()
            .expect("a probe object")
            .keys()
            .cloned(),
    );
    expected.sort();
    expected.dedup();

    let missing: Vec<&String> = expected
        .iter()
        .filter(|k| !AGENTS_MD.contains(k.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "`sscsb skill check --format json` emits {missing:?}, and AGENTS.md — which the skill \
         calls the full machine contract — never mentions them"
    );

    // …and the row must state the rule, not merely list the words: `unknown`
    // is read as the weak case, and only `not-user-writable` earns the strong
    // one. An agent that branches the other way has been told wrong.
    for claim in [
        "Only `not-user-writable`",
        "read `unknown`, and `binary.chain_complete: false`, as `user-writable`",
    ] {
        assert!(
            AGENTS_MD.contains(claim),
            "AGENTS.md must state how to read the verdict: `{claim}`"
        );
    }
}
