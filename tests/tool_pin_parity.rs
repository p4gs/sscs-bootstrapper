//! `src/tools.rs` claims to be "the SINGLE place versions are pinned".
//!
//! It very nearly is — except `.github/actions/setup-sscsb-tools/action.yml`
//! re-declares eleven of those versions as job-level `env:` so CI can download
//! the binaries before the suite runs. That is a second copy of the same facts,
//! in a different language, and until this test existed nothing reconciled them.
//!
//! A silent divergence is the bad outcome: CI would test against one version
//! while `tools::degrade_message` tells users to install a different one, and
//! both would look correct in isolation. This test makes the registry normative
//! and the CI action a derived copy that must agree.

use sscsb::tools;

const ACTION_YML: &str = include_str!("../.github/actions/setup-sscsb-tools/action.yml");

/// `NAME_VERSION: "1.2.3"` (or unquoted) → ("name", "1.2.3"), for the `env:`
/// block only. Parsed textually rather than with a YAML crate because the shape
/// is fixed and a parser dependency would be a heavier promise than the data.
fn action_pins() -> Vec<(String, String)> {
    ACTION_YML
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let key = key.trim();
            let tool = key.strip_suffix("_VERSION")?;
            if !tool.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                return None;
            }
            let value = value.trim().trim_matches(['"', '\'']).trim();
            if value.is_empty() {
                return None;
            }
            let id = tool.to_ascii_lowercase().replace('_', "-");
            // Two env names are shortened from their registry ids. Mapped
            // explicitly rather than fuzzily, so a genuinely unknown tool still
            // fails loudly instead of being quietly matched to something else.
            let id = match id.as_str() {
                "osv" => "osv-scanner".to_string(),
                _ => id,
            };
            Some((id, value.to_string()))
        })
        .collect()
}

#[test]
fn ci_action_pins_agree_with_the_tool_registry() {
    let pins = action_pins();
    assert!(
        pins.len() >= 8,
        "parsed only {} *_VERSION entries from action.yml; the parser is broken, \
         not the action ({pins:?})",
        pins.len()
    );

    let mut unknown = Vec::new();
    let mut mismatched = Vec::new();

    for (tool_id, ci_version) in &pins {
        match tools::spec(tool_id) {
            None => unknown.push(tool_id.clone()),
            Some(spec) if spec.pinned_version != ci_version => {
                mismatched.push(format!(
                    "{tool_id}: CI pins {ci_version}, src/tools.rs pins {}",
                    spec.pinned_version
                ));
            }
            Some(_) => {}
        }
    }

    assert!(
        unknown.is_empty(),
        "action.yml pins tools absent from the registry: {unknown:?}\n\
         Either add them to src/tools.rs or stop installing them in CI."
    );
    assert!(
        mismatched.is_empty(),
        "CI and the tool registry disagree on pinned versions:\n  {}\n\n\
         src/tools.rs is the normative source. Update \
         .github/actions/setup-sscsb-tools/action.yml to match, or the suite \
         will test against a version the degrade message does not name.",
        mismatched.join("\n  ")
    );
}

/// The action deliberately does NOT install `guacone`, `vexctl`, `witness`, or
/// `sighthound` — their absence is what keeps the degrade branches live in CI.
/// If someone "helpfully" adds them, the degrade paths stop being exercised and
/// the coverage rationale in ci.yml quietly stops being true.
#[test]
fn ci_action_still_omits_the_tools_that_exercise_degrade_paths() {
    let installed: Vec<String> = action_pins().into_iter().map(|(id, _)| id).collect();

    for deliberately_absent in ["guacone", "vexctl", "witness", "sighthound"] {
        assert!(
            !installed.contains(&deliberately_absent.to_string()),
            "action.yml now installs `{deliberately_absent}`, which CI omits on \
             purpose so the missing-tool degrade branch runs. If this is \
             intentional, update the rationale in \
             .github/actions/setup-sscsb-tools/action.yml and in ci.yml's \
             coverage comment, which both cite these tools by name."
        );
    }
}
