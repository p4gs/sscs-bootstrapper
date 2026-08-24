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
