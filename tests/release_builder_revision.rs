//! Execute the real assertion against inert workflow-run metadata. The fake gh
//! command never connects to GitHub and cannot launch a workflow or publish.

#![cfg(unix)]

use serde_json::{json, Value};
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
};
use yaml_rust2::{Yaml, YamlLoader};

const RUN_ID: &str = "12345";
const RUN_ATTEMPT: &str = "2";
const REPO: &str = "example/project";
const SOURCE_TAG: &str = "v1.2.3";
const SOURCE_SHA: &str = "1111111111111111111111111111111111111111";

fn workflow() -> Yaml {
    YamlLoader::load_from_str(include_str!("../.github/workflows/release.yml"))
        .unwrap()
        .remove(0)
}

fn step(doc: &Yaml) -> &Yaml {
    doc["jobs"]["builder"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["id"].as_str() == Some("builder-revision"))
        .unwrap()
}

fn mock_response(doc: &Yaml) -> Value {
    let env = &step(doc)["env"];
    let path = env["BUILDER_PATH"].as_str().unwrap();
    let tag = env["BUILDER_TAG"].as_str().unwrap();
    let sha = env["BUILDER_SHA"].as_str().unwrap();
    json!({
        "id": 12345,
        "run_attempt": 2,
        "repository": {"full_name": REPO},
        "event": "push",
        "path": ".github/workflows/release.yml",
        "head_branch": SOURCE_TAG,
        "head_sha": SOURCE_SHA,
        "referenced_workflows": [
            {"path": format!("{path}@{tag}"), "ref": format!("refs/tags/{tag}"), "sha": sha},
            {"path": format!("{REPO}/.github/workflows/deploy-gate.yml@{SOURCE_SHA}"), "sha": SOURCE_SHA},
        ],
    })
}

fn run(doc: &Yaml, data: &str, api_fails: bool) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let helper = dir.path().join("gh");
    std::fs::write(
        &helper,
        r#"#!/bin/bash
if [[ "$#" != 6 || "$1" != "api" || "$2" != "--method" || "$3" != "GET" || "$4" != "-H" ||
      "$5" != "X-GitHub-Api-Version: 2022-11-28" ||
      "$6" != "repos/example/project/actions/runs/12345/attempts/2" ]]; then
  exit 99
fi
cat "$MOCK_JSON"
[[ "$MOCK_FAIL" == false ]]
"#,
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let data_path = dir.path().join("attempt.json");
    std::fs::write(&data_path, data).unwrap();
    let step = step(doc);
    Command::new("bash")
        .current_dir(dir.path())
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .env("MOCK_JSON", data_path)
        .env("MOCK_FAIL", api_fails.to_string())
        .env("GITHUB_REPOSITORY", REPO)
        .env("GITHUB_RUN_ID", RUN_ID)
        .env("GITHUB_RUN_ATTEMPT", RUN_ATTEMPT)
        .env("GITHUB_REF_NAME", SOURCE_TAG)
        .env("GITHUB_SHA", SOURCE_SHA)
        .env(
            "BUILDER_PATH",
            step["env"]["BUILDER_PATH"].as_str().unwrap(),
        )
        .env("BUILDER_TAG", step["env"]["BUILDER_TAG"].as_str().unwrap())
        .env("BUILDER_SHA", step["env"]["BUILDER_SHA"].as_str().unwrap())
        .args(["-c", step["run"].as_str().unwrap()])
        .output()
        .unwrap()
}

#[test]
fn checks_exact_run_attempt_before_publication() {
    let doc = workflow();
    let jobs = &doc["jobs"];
    let builder = &jobs["builder"];
    assert_eq!(builder["needs"].as_str(), Some("provenance"));
    assert!(builder["if"].is_badvalue());
    assert!(builder["continue-on-error"].is_badvalue());
    assert_eq!(builder["permissions"].as_hash().unwrap().len(), 1);
    assert_eq!(builder["permissions"]["actions"].as_str(), Some("read"));
    for (job, prerequisite) in [("gate", "builder"), ("publish", "gate")] {
        assert!(jobs[job]["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|name| name.as_str() == Some(prerequisite)));
        assert!(jobs[job]["if"].is_badvalue());
    }

    let out = run(&doc, &mock_response(&doc).to_string(), false);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn missing_duplicate_mismatch_or_api_failure_blocks() {
    let doc = workflow();
    let expected = mock_response(&doc);
    let candidate = &expected["referenced_workflows"][0];
    let mut missing = expected.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("referenced_workflows");
    let mut duplicate = expected.clone();
    duplicate["referenced_workflows"]
        .as_array_mut()
        .unwrap()
        .push(candidate.clone());
    let mut cases = vec![missing, duplicate];
    for (field, changed) in [
        (
            "path",
            json!("example/project/.github/workflows/other.yml@v2.1.0"),
        ),
        ("ref", json!("refs/heads/v2.1.0")),
        ("sha", json!("2222222222222222222222222222222222222222")),
    ] {
        let mut data = expected.clone();
        data["referenced_workflows"][0][field] = changed;
        cases.push(data);
    }
    for (field, changed) in [
        ("id", json!(12346)),
        ("run_attempt", json!(1)),
        ("repository", json!({"full_name": "example/other"})),
        ("event", json!("workflow_dispatch")),
        ("path", json!(".github/workflows/other.yml")),
        ("head_branch", json!("v1.2.2")),
        (
            "head_sha",
            json!("2222222222222222222222222222222222222222"),
        ),
    ] {
        let mut data = expected.clone();
        data[field] = changed;
        cases.push(data);
    }
    let mut failures: Vec<_> = cases
        .into_iter()
        .map(|value| (value.to_string(), false))
        .collect();
    failures.push(("{not json".into(), false));
    failures.push((format!("{{}} {expected}"), false));
    failures.push((expected.to_string(), true));
    for (data, api_fails) in failures {
        let out = run(&doc, &data, api_fails);
        assert_eq!(out.status.code(), Some(1), "wrong decision on {data}");
        assert!(String::from_utf8_lossy(&out.stdout)
            .contains("did not confirm the approved SLSA builder revision"));
    }
}
