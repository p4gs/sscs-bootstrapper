//! The slsa-github-generator tag is one fact pinned in several places: the
//! `builder_id` under `[controls.provenance-verify]` in `.sscsb/config.toml`,
//! the generator `uses:` in the release workflow this repository runs and in
//! the two templates that call the generator, and the `BUILDER_ID` the
//! deploy gate (dogfood and template) verifies against. `slsa-verifier`
//! identifies the trusted builder by that tag, so a bump applied to one site
//! and not the others is a release whose provenance the gate refuses — or,
//! worse, a gate that verifies against a builder the release never used.
//! `.sscsb/config.toml` says "change one, change all three"; this test is
//! what makes that sentence true.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The `vX.Y.Z` a `…@refs/tags/vX.Y.Z` builder id ends in.
fn builder_id_tag(id: &str, rel: &str) -> String {
    id.rsplit_once("@refs/tags/")
        .map(|(_, tag)| tag.to_string())
        .unwrap_or_else(|| panic!("{rel}: builder id {id:?} does not end in `@refs/tags/<tag>`"))
}

/// The `@vX.Y.Z` on the file's generator `uses:` line.
fn generator_uses_tag(rel: &str) -> String {
    let content = read(rel);
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("uses: slsa-framework/slsa-github-generator/"))
        .unwrap_or_else(|| panic!("{rel}: no slsa-github-generator `uses:` line"));
    let (_, rest) = line.rsplit_once('@').unwrap();
    rest.split_whitespace().next().unwrap().to_string()
}

/// The tag in the file's `BUILDER_ID:` env entry.
fn builder_id_env_tag(rel: &str) -> String {
    let content = read(rel);
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("BUILDER_ID:"))
        .unwrap_or_else(|| panic!("{rel}: no `BUILDER_ID:` env entry"));
    let (_, value) = line.split_once(':').unwrap();
    builder_id_tag(value.trim().trim_matches(['"', '\'']), rel)
}

/// How one file states the tag.
type TagOf = fn(&str) -> String;

#[test]
fn the_generator_tag_is_one_value_everywhere() {
    let config: toml::Value = read(".sscsb/config.toml")
        .parse()
        .expect(".sscsb/config.toml parses");
    let builder_id = config["controls"]["provenance-verify"]["builder_id"]
        .as_str()
        .expect("[controls.provenance-verify].builder_id is set");
    let expected = builder_id_tag(builder_id, ".sscsb/config.toml");
    assert!(
        expected.starts_with('v') && expected.split('.').count() == 3,
        "builder_id must name a vX.Y.Z tag, got {expected:?}"
    );

    let sites: [(&str, TagOf); 5] = [
        (".github/workflows/release.yml", generator_uses_tag),
        ("templates/workflows/release.yml", generator_uses_tag),
        ("templates/workflows/release-slsa.yml", generator_uses_tag),
        (".github/workflows/deploy-gate.yml", builder_id_env_tag),
        ("templates/workflows/deploy-gate.yml", builder_id_env_tag),
    ];
    for (rel, tag_of) in sites {
        assert_eq!(
            tag_of(rel),
            expected,
            "{rel} pins a different generator tag than .sscsb/config.toml's builder_id"
        );
    }

    // The documented `--builder-id` example must not lag the pin either.
    let docs = read("docs/phase-3.md");
    let examples: Vec<&str> = docs
        .lines()
        .filter(|l| l.contains("generator_generic_slsa3.yml@refs/tags/"))
        .collect();
    assert!(
        !examples.is_empty(),
        "docs/phase-3.md documents a --builder-id example"
    );
    for line in examples {
        assert!(
            line.contains(&format!("@refs/tags/{expected}")),
            "docs/phase-3.md example carries a tag other than {expected}: {line}"
        );
    }
}
