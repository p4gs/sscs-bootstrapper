//! The package rehearsal must exercise the production build without acquiring
//! production release, signing, or attestation permissions.

use yaml_rust2::{Yaml, YamlLoader};

const BUILD: &str = "./.github/workflows/release-build.yml";

fn workflow(source: &str) -> Yaml {
    YamlLoader::load_from_str(source).unwrap().remove(0)
}

fn only_contents_read(doc: &Yaml) {
    let permissions = &doc["permissions"];
    assert_eq!(permissions.as_hash().unwrap().len(), 1);
    assert_eq!(permissions["contents"].as_str(), Some("read"));
}

#[test]
fn rehearsal_can_only_build_and_collect() {
    let rehearsal = workflow(include_str!("../.github/workflows/release-rehearsal.yml"));
    let release = workflow(include_str!("../.github/workflows/release.yml"));
    let build = workflow(include_str!("../.github/workflows/release-build.yml"));
    assert_eq!(rehearsal["on"].as_hash().unwrap().len(), 1);
    assert!(!rehearsal["on"]["workflow_dispatch"].is_badvalue());
    assert!(release["on"]["workflow_dispatch"].is_badvalue());
    assert!(release["jobs"]["publish"]["needs"]
        .as_vec()
        .unwrap()
        .iter()
        .any(|job| job.as_str() == Some("gate")));
    assert_eq!(build["on"].as_hash().unwrap().len(), 1);
    assert!(!build["on"]["workflow_call"].is_badvalue());
    for doc in [&rehearsal, &build] {
        only_contents_read(doc);
        for (_, job) in doc["jobs"].as_hash().unwrap() {
            only_contents_read(job);
        }
    }
    assert_eq!(rehearsal["jobs"].as_hash().unwrap().len(), 2);
    assert_eq!(build["jobs"].as_hash().unwrap().len(), 1);
    assert_eq!(rehearsal["jobs"]["build"]["uses"].as_str(), Some(BUILD));
    assert_eq!(release["jobs"]["build"]["uses"].as_str(), Some(BUILD));
    assert_eq!(
        rehearsal["jobs"]["build"]["with"]["production-release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        release["jobs"]["build"]["with"]["production-release"].as_bool(),
        Some(true)
    );
    assert_eq!(
        rehearsal["jobs"]["checksums"]["needs"].as_str(),
        Some("build")
    );
}

#[test]
fn each_platform_uses_a_native_smoke_runner() {
    let build = workflow(include_str!("../.github/workflows/release-build.yml"));
    let matrix = build["jobs"]["build"]["strategy"]["matrix"]["include"]
        .as_vec()
        .unwrap();
    assert_eq!(matrix.len(), 3);
    for (target, runner) in [
        ("aarch64-apple-darwin", "macos-latest"),
        ("x86_64-apple-darwin", "macos-15-intel"),
        ("x86_64-unknown-linux-gnu", "ubuntu-latest"),
    ] {
        assert!(matrix.iter().any(|entry| {
            entry["target"].as_str() == Some(target) && entry["os"].as_str() == Some(runner)
        }));
    }
}
