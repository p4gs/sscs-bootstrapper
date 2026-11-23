//! Verify rule coverage and exact matches on inert fixtures. No fixture code runs.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

type Case = (PathBuf, usize, String);

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            found.extend(files(&entry.path()));
        } else {
            assert!(kind.is_file(), "expected plain file: {:?}", entry.path());
            found.push(entry.path());
        }
    }
    found.sort();
    found
}

fn declared_ids(config: &Path) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for file in files(config) {
        let text = fs::read_to_string(&file).unwrap();
        let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
        for doc in &docs {
            let rules = doc["rules"].as_vec().expect("rule list");
            for rule in rules {
                let id = rule["id"].as_str().expect("rule ID");
                assert!(ids.insert(id.to_owned()), "duplicate rule ID: {id}");
            }
        }
    }
    assert!(!ids.is_empty());
    ids
}

fn annotation(line: &str) -> Option<(bool, &str)> {
    let line = line.trim_start();
    let comment = line
        .strip_prefix("//")
        .or_else(|| line.strip_prefix('#'))?
        .trim();
    if let Some(ids) = comment.strip_prefix("ruleid:") {
        Some((true, ids))
    } else {
        comment.strip_prefix("ok:").map(|ids| (false, ids))
    }
}

fn fixture_cases(
    path: &Path,
    text: &str,
    positive: &mut BTreeSet<Case>,
    negative: &mut BTreeSet<Case>,
) {
    let lines: Vec<_> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some((must_match, ids)) = annotation(line) else {
            continue;
        };
        assert!(
            lines
                .get(i + 1)
                .is_some_and(|next| !next.trim().is_empty() && annotation(next).is_none()),
            "{path:?}:{}: place the annotation directly above its subject",
            i + 1
        );
        for raw in ids.split(',') {
            let id = raw.trim();
            assert!(!id.is_empty(), "{path:?}:{}: empty rule ID", i + 1);
            let case = (path.to_path_buf(), i + 2, id.to_owned());
            let matrix = if must_match {
                &mut *positive
            } else {
                &mut *negative
            };
            assert!(matrix.insert(case), "{path:?}:{}: duplicate {id}", i + 1);
        }
    }
}

#[derive(Deserialize)]
struct Position {
    line: usize,
}

#[derive(Deserialize)]
struct Match {
    path: PathBuf,
    check_id: String,
    start: Position,
    end: Position,
}

#[derive(Deserialize)]
struct Paths {
    scanned: BTreeSet<PathBuf>,
}

#[derive(Deserialize)]
struct Scan {
    results: Vec<Match>,
    errors: Vec<serde_json::Value>,
    paths: Paths,
    skipped_rules: Vec<serde_json::Value>,
}

#[test]
fn expanded_sast_fixtures_match_their_positive_and_negative_annotations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let config = root.join("rules-expanded");
    let fixtures = root.join("rule-fixtures");
    let ids = declared_ids(&config);
    let temp = tempfile::tempdir().unwrap();

    let mut scanned_files = BTreeSet::new();
    let mut positive = BTreeSet::new();
    let mut negative = BTreeSet::new();
    for source in files(&fixtures) {
        let rel = source.strip_prefix(&fixtures).unwrap();
        let restored = rel
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".fixture"))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| panic!("fixture must have a .fixture suffix: {source:?}"));
        let target = Path::new("fixtures").join(rel.with_file_name(restored));
        assert!(scanned_files.insert(target.clone()), "duplicate {target:?}");
        let text = fs::read_to_string(&source).unwrap();
        fixture_cases(&target, &text, &mut positive, &mut negative);
        let file = temp.path().join(&target);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    assert!(positive.is_disjoint(&negative));
    let annotated_ids = |cases: &BTreeSet<Case>| {
        cases
            .iter()
            .map(|(_, _, id)| id.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(annotated_ids(&positive), ids, "positive rule coverage");
    assert_eq!(annotated_ids(&negative), ids, "negative rule coverage");

    // The production checkout ignores scan-only sources; the scanner instead
    // receives the reconstructed, non-executable files in an empty directory.
    let scan = match Command::new("opengrep")
        .current_dir(temp.path())
        .args([
            "scan",
            "--json",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--config",
        ])
        .arg(config)
        .arg("fixtures")
        .output()
    {
        Ok(output) => output,
        Err(err)
            if err.kind() == ErrorKind::NotFound
                && std::env::var_os("GITHUB_ACTIONS").is_none() =>
        {
            eprintln!("OpenGrep unavailable: checked annotation coverage but did not run expanded SAST fixtures (CI requires OpenGrep)");
            return;
        }
        Err(err) => panic!("could not run OpenGrep fixture scan: {err}"),
    };
    assert!(
        scan.status.success(),
        "OpenGrep fixture scan failed: {}\n{}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
    let result: Scan = serde_json::from_slice(&scan.stdout)
        .unwrap_or_else(|err| panic!("invalid OpenGrep JSON: {err}"));
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(
        result.skipped_rules.is_empty(),
        "{:?}",
        result.skipped_rules
    );
    assert_eq!(result.paths.scanned, scanned_files, "scan coverage");

    let mut actual = BTreeMap::<Case, usize>::new();
    for hit in result.results {
        for (path, line, id) in &negative {
            assert!(
                *path != hit.path
                    || *id != hit.check_id
                    || !(hit.start.line..=hit.end.line).contains(line),
                "unexpected {} in {path:?}:{line}",
                hit.check_id
            );
        }
        *actual
            .entry((hit.path, hit.start.line, hit.check_id))
            .or_default() += 1;
    }
    let expected: BTreeMap<Case, usize> = positive.into_iter().map(|case| (case, 1)).collect();
    assert_eq!(actual, expected, "unexpected or missing rule matches");
}
