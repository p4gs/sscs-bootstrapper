//! The standalone SBOM job generates under read-only permissions, and only a
//! published release may attach the exact artifact produced by that workflow run.

use yaml_rust2::YamlLoader;

#[test]
fn sbom_workflow_separates_generation_from_release_publication() {
    let workflow = include_str!("../.github/workflows/sbom.yml");
    let template = include_str!("../templates/workflows/sbom.yml");
    assert_eq!(template.replace("{{default_branch}}", "main"), workflow);

    let yaml = YamlLoader::load_from_str(workflow).unwrap();
    let root = &yaml[0];
    assert!(root["permissions"].as_hash().unwrap().is_empty());
    assert_eq!(root["on"]["push"]["branches"][0].as_str(), Some("main"));
    assert_eq!(
        root["on"]["release"]["types"][0].as_str(),
        Some("published")
    );

    let jobs = root["jobs"].as_hash().unwrap();
    assert_eq!(jobs.len(), 2);
    let generation = &root["jobs"]["sbom"];
    assert_eq!(generation["permissions"].as_hash().unwrap().len(), 1);
    assert_eq!(generation["permissions"]["contents"].as_str(), Some("read"));

    let generate_steps = generation["steps"].as_vec().unwrap();
    let syft = generate_steps
        .iter()
        .find(|step| step["name"].as_str() == Some("Generate CycloneDX SBOM"))
        .unwrap();
    assert_eq!(syft["with"]["upload-release-assets"].as_bool(), Some(false));
    assert_eq!(
        syft["with"]["artifact-name"].as_str(),
        Some("sbom.cdx.json")
    );
    assert_eq!(syft["with"]["output-file"].as_str(), Some("sbom.cdx.json"));

    let upload = generate_steps
        .iter()
        .find(|step| step["id"].as_str() == Some("upload"))
        .unwrap();
    assert_eq!(upload["with"]["name"].as_str(), Some("sbom-cyclonedx"));
    assert_eq!(upload["with"]["path"].as_str(), Some("sbom.cdx.json"));
    assert_eq!(upload["with"]["if-no-files-found"].as_str(), Some("error"));

    let publish = &root["jobs"]["attach-sbom"];
    assert_eq!(publish["permissions"].as_hash().unwrap().len(), 1);
    assert_eq!(publish["permissions"]["contents"].as_str(), Some("write"));
    assert_eq!(publish["needs"].as_str(), Some("sbom"));
    assert_eq!(
        publish["if"].as_str(),
        Some("github.event_name == 'release' && github.event.action == 'published'")
    );

    let publish_steps = publish["steps"].as_vec().unwrap();
    assert_eq!(publish_steps.len(), 4);
    let actions: Vec<_> = publish_steps
        .iter()
        .filter_map(|step| step["uses"].as_str())
        .map(|uses| uses.split_once('@').unwrap().0)
        .collect();
    assert_eq!(
        actions,
        ["step-security/harden-runner", "actions/download-artifact"]
    );
    let download = &publish_steps[2]["with"];
    assert_eq!(
        download["artifact-ids"].as_str(),
        Some("${{ needs.sbom.outputs.artifact-id }}")
    );
    assert!(download["run-id"].is_badvalue());
    assert!(download["repository"].is_badvalue());
    assert!(download["github-token"].is_badvalue());
    assert_eq!(download["path"].as_str(), Some("release-sbom"));
}
