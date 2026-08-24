//! Verifiers for the OpenSSF controls layered on top of the core registry:
//! Security Insights (`security-insights.yml`), OpenSSF Model Signing
//! (`sign-models.yml`), and gittuf (`gittuf-verify.yml`). Each follows sscsb's
//! scan-for / implement pattern — `sscsb init` installs the artifact, these
//! functions report the real, on-disk state (and, for model-signing, whether the
//! control even applies to this repo). The Best-Practices-Badge worksheet is a
//! plain generated artifact and uses the generic template verifier.

use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use std::path::Path;
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::Yaml;

// ─────────────────────────── Security Insights ──────────────────────────────

/// Security Insights schema MAJOR versions this verifier understands. Minor and
/// patch releases inside a known major are accepted — that is what the version
/// scheme promises — so a spec point release does not turn a good file red. A
/// major sscsb has never heard of is a different matter: every structural check
/// below is written against v1/v2 field names, so on `9.9.9` those checks are
/// not evidence of anything and PASS would be a claim sscsb cannot support.
const KNOWN_SI_SCHEMA_MAJORS: &[u64] = &[1, 2];

/// The generator's own placeholder markers. A field still carrying one is an
/// unfinished starter, which the Info branch below already reports; it is not a
/// separate malformed-value complaint.
fn is_placeholder(text: &str) -> bool {
    text.contains("REPLACE-ME") || text.contains("TODO:")
}

/// The literal text of a YAML scalar, whatever type it resolved to. `9.9.9` is
/// a string to YAML and `2.0` is a float; both are answers to "what version did
/// this file claim", so both are worth reading.
fn scalar_text(node: &Yaml) -> Option<String> {
    match node {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// MAJOR of a `MAJOR.MINOR.PATCH` version, or `None` when the text is not one.
fn schema_major(text: &str) -> Option<u64> {
    let mut parts = text.trim().split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    parts.next().is_none().then_some(major)
}

/// Fields whose name says outright that the value is a URL. Kept to the
/// unambiguous set — `url`, `<something>-url`, `<something>_url` — because this
/// is a structural verifier, not a schema: `si validate` is what knows that
/// `documentation.detailed-guide` is a URI too.
fn is_url_key(key: &str) -> bool {
    key == "url" || key.ends_with("-url") || key.ends_with("_url")
}

/// Shape-only URL check: a scheme, `://`, and something after it. sscsb is not
/// resolving these — it is declining to call `not-a-url` a URL.
fn looks_like_url(value: &str) -> bool {
    let Some((scheme, rest)) = value.trim().split_once("://") else {
        return false;
    };
    !rest.is_empty()
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Every `url`-shaped field in the document whose value is not a URL.
///
/// Iterative on purpose: the walk runs over a document sscsb did not write, and
/// a recursive one would be a second way to knock `verify` over.
fn url_field_problems(doc: &Yaml) -> Vec<String> {
    let mut problems = Vec::new();
    let mut stack = vec![(String::new(), doc)];
    while let Some((path, node)) = stack.pop() {
        match node {
            Yaml::Hash(map) => {
                for (k, v) in map {
                    let key = k.as_str().unwrap_or("?");
                    let child = if path.is_empty() {
                        key.to_string()
                    } else {
                        format!("{path}.{key}")
                    };
                    if is_url_key(key) {
                        match scalar_text(v) {
                            Some(text) if is_placeholder(&text) => {}
                            Some(text) if !looks_like_url(&text) => {
                                problems.push(format!("{child} is not a URL: `{text}`"));
                            }
                            Some(_) => {}
                            None => problems.push(format!("{child} must be a URL string")),
                        }
                    }
                    stack.push((child, v));
                }
            }
            Yaml::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    stack.push((format!("{path}[{i}]"), v));
                }
            }
            _ => {}
        }
    }
    problems.sort();
    problems
}

/// Ceiling on the bytes sscsb reads from `security-insights.yml`. It is project
/// metadata — the OpenSSF spec's own examples are a couple of kilobytes — and a
/// repository sscsb is pointed at is not a repository sscsb trusts.
const MAX_SI_BYTES: usize = 1024 * 1024;

/// Ceiling on the number of YAML nodes the document may expand to once anchors
/// and aliases are resolved.
///
/// yaml-rust2 resolves an alias by CLONING the node it points at (`yaml.rs`:
/// `anchor_map.insert(node.1, node.0.clone())`), and exposes no limit on that —
/// its only "recursion limit" is a `u8` overflow on flow nesting depth. So a few
/// hundred bytes of nested anchors expand geometrically: a 439-byte file of
/// eight 9-way alias levels drove `sscsb verify` past 4.5 GB RSS before it was
/// killed, still growing. That is a denial of service reachable by anyone who
/// can add a file to a repository, and `verify` is what people wire into CI.
///
/// The expansion is counted on the parser's EVENT stream, which is linear in
/// the input (an alias is one event, not a subtree), and the document is
/// refused before it ever reaches the loader. 500 000 nodes is roughly the most
/// an alias-free document of `MAX_SI_BYTES` could contain, so nothing that
/// would have parsed on its own text is turned away.
const MAX_SI_NODES: u64 = 500_000;

/// Read at most `max` bytes of `path`, so an oversized (or endless) file is a
/// reported refusal rather than an unbounded read.
fn read_bounded(path: &Path, max: usize) -> Result<String, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|e| format!("unreadable: {e}"))?;
    let mut buf = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("unreadable: {e}"))?;
    if buf.len() > max {
        return Err(format!(
            "is larger than the {max}-byte ceiling sscsb reads — Security Insights is a \
             metadata file, not a data file"
        ));
    }
    String::from_utf8(buf).map_err(|_| "is not valid UTF-8".to_string())
}

/// Counts the nodes a YAML document would expand to *without* expanding it, by
/// walking the parser's event stream. Anchored node sizes are remembered, and an
/// alias is charged the size of the node it points at — exactly the clone the
/// loader would make.
#[derive(Default)]
struct NodeBudget {
    /// Expanded size of each anchored node, by anchor id.
    anchors: std::collections::HashMap<usize, u64>,
    /// (anchor id, accumulated child cost) per still-open collection.
    open: Vec<(usize, u64)>,
    /// Expanded size of every completed top-level node.
    total: u64,
}

impl NodeBudget {
    fn finish(&mut self, anchor: usize, cost: u64) {
        if anchor > 0 {
            self.anchors.insert(anchor, cost);
        }
        match self.open.last_mut() {
            Some((_, acc)) => *acc = acc.saturating_add(cost),
            None => self.total = self.total.saturating_add(cost),
        }
    }
}

impl EventReceiver for NodeBudget {
    fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Scalar(_, _, anchor, _) => self.finish(anchor, 1),
            // An alias that resolves to nothing is stored as BadValue by the
            // loader — one node, not a subtree.
            Event::Alias(id) => {
                let cost = self.anchors.get(&id).copied().unwrap_or(1);
                self.finish(0, cost);
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                self.open.push((anchor, 0));
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((anchor, children)) = self.open.pop() {
                    self.finish(anchor, children.saturating_add(1));
                }
            }
            _ => {}
        }
    }
}

/// How many YAML nodes `content` expands to. `None` when the document does not
/// parse — the loader reports that with its own message and marker.
fn expanded_node_count(content: &str) -> Option<u64> {
    let mut budget = NodeBudget::default();
    Parser::new_from_str(content).load(&mut budget, true).ok()?;
    Some(budget.total)
}

/// `security-insights.yml` must exist, parse as YAML, carry a `header` with a
/// `schema-version`, and describe the `project` or `repository`. Full schema
/// conformance is si-tooling's job (`si validate`); sscsb does the structural
/// sanity check and says where deeper validation lives.
pub fn verify_security_insights(ctx: &Ctx) -> VerifyResult {
    let path = ctx.root.join("security-insights.yml");
    if !path.is_file() {
        return VerifyResult::new(
            "security-insights",
            Outcome::Fail,
            vec!["security-insights.yml missing — run `sscsb init`".into()],
        );
    }
    let content = match read_bounded(&path, MAX_SI_BYTES) {
        Ok(c) => c,
        Err(e) => {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec![format!("security-insights.yml {e}")],
            )
        }
    };
    // Count the alias expansion on the event stream and refuse the document
    // before the loader can materialize it. See `MAX_SI_NODES`.
    if let Some(nodes) = expanded_node_count(&content) {
        if nodes > MAX_SI_NODES {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec![
                    format!(
                        "security-insights.yml expands to {nodes} YAML nodes from {} bytes \
                         (ceiling {MAX_SI_NODES}) — REFUSED, not parsed",
                        content.len()
                    ),
                    "its anchors/aliases amplify a small document into a huge one (a \
                     \"billion laughs\" denial of service); remove the nested aliases"
                        .into(),
                ],
            );
        }
    }
    let docs = match yaml_rust2::YamlLoader::load_from_str(&content) {
        Ok(d) => d,
        Err(e) => {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec![format!("security-insights.yml is not valid YAML: {e}")],
            )
        }
    };
    let doc = match docs.first() {
        Some(d) => d,
        None => {
            return VerifyResult::new(
                "security-insights",
                Outcome::Fail,
                vec!["security-insights.yml is empty".into()],
            )
        }
    };
    // Structural checks mirroring the v2-required fields `si validate` enforces
    // (not the full CUE evaluation — that's si-tooling's job).
    let mut problems: Vec<String> = Vec::new();
    let declared = &doc["header"]["schema-version"];
    if declared.is_badvalue() {
        problems.push("MISSING header.schema-version".into());
    } else {
        // A version this tool has never heard of is cheap to catch and makes
        // every check below meaningless — it must not read as PASS.
        match scalar_text(declared) {
            None => problems
                .push("header.schema-version must be a version string like \"2.0.0\"".into()),
            Some(text) => match schema_major(&text) {
                None => problems.push(format!(
                    "header.schema-version `{text}` is not a MAJOR.MINOR.PATCH version"
                )),
                Some(major) if !KNOWN_SI_SCHEMA_MAJORS.contains(&major) => problems.push(format!(
                    "header.schema-version `{text}` declares Security Insights v{major}; sscsb's \
                     structural checks only know v1 and v2 — upgrade sscsb or fix the version"
                )),
                Some(_) => {}
            },
        }
    }
    let has_project = !doc["project"].is_badvalue();
    let has_repository = !doc["repository"].is_badvalue();
    if !has_project && !has_repository {
        problems.push("MISSING project or repository block".into());
    }
    if has_project
        && doc["project"]["administrators"]
            .as_vec()
            .is_none_or(|v| v.is_empty())
    {
        problems.push("project.administrators must list at least one contact".into());
    }
    if has_repository {
        if doc["repository"]["core-team"]
            .as_vec()
            .is_none_or(|v| v.is_empty())
        {
            problems.push("repository.core-team must list at least one contact".into());
        }
        // license must be a {expression, url} object, never a bare URL string.
        if doc["repository"]["license"].as_str().is_some()
            || doc["repository"]["license"]["expression"].is_badvalue()
        {
            problems.push("repository.license must be an object with `expression` + `url`".into());
        }
    }
    // A field the file itself names `url` and fills with `not-a-url` is not a
    // schema question — it is wrong on its face, wherever in the document it is.
    problems.extend(url_field_problems(doc));
    if !problems.is_empty() {
        return VerifyResult::new("security-insights", Outcome::Fail, problems);
    }

    // Structurally valid. If generator placeholders remain, it's an unfinished
    // starter — report Info (not a false Pass) so `sscsb verify` stays honest.
    if content.contains("REPLACE-ME") || content.contains("TODO:") {
        return VerifyResult::new(
            "security-insights",
            Outcome::Info,
            vec![
                "structurally valid starter installed".into(),
                "replace the REPLACE-ME/TODO placeholders, then run `si validate`".into(),
            ],
        );
    }
    VerifyResult::new(
        "security-insights",
        Outcome::Pass,
        vec!["structurally valid — run `si validate` for full schema conformance".into()],
    )
}

// ─────────────────────────── Model Signing ──────────────────────────────────

/// File extensions that unambiguously indicate an ML model artifact. Deliberately
/// excludes generic containers (`.bin`, `.pkl`) to avoid false positives.
const MODEL_EXTS: &[&str] = &[
    "safetensors",
    "onnx",
    "gguf",
    "ggml",
    "tflite",
    "h5",
    "ckpt",
    "pt",
    "pth",
    "npz",
];

/// Bounded recursive scan for model files under `root`, skipping VCS/build dirs.
/// Capped so a large repo can't stall `verify`.
fn find_model_files(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    // Bound on DIRECTORIES traversed (not just matches) so a match-free tree
    // can't stall verify, independent of the 50-match cap below.
    let mut dirs_visited = 0usize;
    while let Some(dir) = stack.pop() {
        if found.len() >= 50 || dirs_visited >= 4000 {
            break;
        }
        dirs_visited += 1;
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            // Never follow symlinks: a symlinked directory could form a cycle or
            // point outside the repo (e.g. `models -> ~/models`, `link -> /`),
            // which would let `sscsb verify` escape the repo and stall — the exact
            // thing the cap above promises against. file_type() does not traverse
            // the link, so is_symlink() is true for a symlink to a directory.
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if matches!(
                    name.as_str(),
                    ".git" | "target" | "node_modules" | ".venv" | "venv" | "dist"
                ) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if MODEL_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
                        if let Ok(rel) = path.strip_prefix(root) {
                            found.push(rel.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }
    found.sort();
    found
}

/// Model signing applies only when the repo ships models. If it does, the
/// signing workflow must be installed; if it doesn't, the control is honestly
/// reported as N/A (Info) rather than a false pass or fail.
pub fn verify_model_signing(ctx: &Ctx) -> VerifyResult {
    let workflow_ok = ctx.root.join(".github/workflows/sign-models.yml").is_file();
    let models = find_model_files(&ctx.root);
    if models.is_empty() {
        let installed = if workflow_ok {
            "sign-models.yml installed (ready if models are added)"
        } else {
            "sign-models.yml not installed — run `sscsb init`"
        };
        return VerifyResult::new(
            "model-signing",
            Outcome::Info,
            vec![
                "no ML model files detected (*.safetensors/*.onnx/*.gguf/*.pt …) — N/A for this repo"
                    .into(),
                installed.into(),
            ],
        );
    }
    let mut messages = vec![format!(
        "{} model file(s) detected (e.g. {})",
        models.len(),
        models[0]
    )];
    if !workflow_ok {
        messages.push(".github/workflows/sign-models.yml MISSING — run `sscsb init`".into());
        return VerifyResult::new("model-signing", Outcome::Fail, messages);
    }
    messages.push(".github/workflows/sign-models.yml installed".into());
    // The repo ships models and the workflow is installed — but an installed
    // workflow is a YAML file, not a signature. Whether these models are signed
    // and verifiable is only answerable with the model-signing CLI this control
    // declares, so without it the honest verdict is "not checked", not PASS.
    // (`sscsb status` already reports `model-signing:missing` here; PASS made
    // the two commands contradict each other in the same session.)
    if !crate::tools::is_available("model-signing") {
        messages.push(crate::tools::degrade_message("model-signing", ctx.platform));
        messages.push(
            "model signatures NOT verified locally — the workflow's own verify step is the \
             only evidence, and it runs in CI"
                .into(),
        );
        return VerifyResult::new("model-signing", Outcome::Degraded, messages);
    }
    messages.push("model-signing CLI available for local `sign`/`verify`".into());
    VerifyResult::new("model-signing", Outcome::Pass, messages)
}

// ─────────────────────────── gittuf ─────────────────────────────────────────

/// gittuf policy lives in `refs/gittuf/*`, not the working tree. Detect it via
/// git rather than a directory probe (robust to worktrees). Absent git or refs
/// → not initialized.
fn gittuf_policy_present(root: &Path) -> bool {
    crate::exec::git_raw(&["show-ref"], root)
        .map(|o| o.stdout.contains("refs/gittuf/"))
        .unwrap_or(false)
}

/// The verify workflow must be installed; gittuf policy is an advanced,
/// locally-initialized step, so its absence is Info (guidance), not Fail.
pub fn verify_gittuf(ctx: &Ctx) -> VerifyResult {
    let workflow_ok = ctx
        .root
        .join(".github/workflows/gittuf-verify.yml")
        .is_file();
    if !workflow_ok {
        return VerifyResult::new(
            "gittuf",
            Outcome::Fail,
            vec![".github/workflows/gittuf-verify.yml MISSING — run `sscsb init`".into()],
        );
    }
    if gittuf_policy_present(&ctx.root) {
        let mut messages = vec![
            "gittuf policy (refs/gittuf/*) present".into(),
            "gittuf-verify.yml installed".into(),
        ];
        // A ref under refs/gittuf/ is just a ref name — anyone can create one
        // with `git update-ref`. Only gittuf itself can say whether the RSL and
        // policy actually verify, so without the binary this control has
        // checked a name, not a guarantee.
        if !crate::tools::is_available("gittuf") {
            messages.push(crate::tools::degrade_message("gittuf", ctx.platform));
            messages.push(
                "the refs are present but NOT verified — `gittuf verify-ref` is the only \
                 thing that proves the policy holds"
                    .into(),
            );
            return VerifyResult::new("gittuf", Outcome::Degraded, messages);
        }
        messages
            .push("gittuf CLI available — run `gittuf verify-ref <ref>` to check the RSL".into());
        VerifyResult::new("gittuf", Outcome::Pass, messages)
    } else {
        VerifyResult::new(
            "gittuf",
            Outcome::Info,
            vec![
                "gittuf-verify.yml installed; no gittuf policy yet".into(),
                "initialize locally: `gittuf trust init` + policy, then push refs/gittuf/* — https://github.com/gittuf/gittuf".into(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Ctx;
    use crate::testutil::{env_lock, path_without, EnvGuard};

    /// Make tool presence deterministic in both directions without disturbing
    /// any other tool the concurrently-running suite needs: the real PATH minus
    /// `hidden`, with a scratch dir of stub executables prepended.
    fn path_fixture(stubs: &[&str], hidden: &[&str]) -> (Vec<tempfile::TempDir>, String) {
        let stub_dir = tempfile::tempdir().unwrap();
        for name in stubs {
            let path = stub_dir.path().join(name);
            std::fs::write(&path, format!("#!/bin/sh\necho '{name} 9.9.9'\nexit 0\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let (mut keep, rest) = path_without(hidden);
        let joined = format!("{}:{}", stub_dir.path().display(), rest.to_string_lossy());
        keep.push(stub_dir);
        (keep, joined)
    }

    fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    #[test]
    fn security_insights_starter_is_info_filled_is_pass_missing_is_fail() {
        let (_d, ctx) = repo();
        // Bootstrap installs a structurally-VALID starter that still carries
        // REPLACE-ME placeholders → Info (not a false Pass).
        let starter = verify_security_insights(&ctx);
        assert_eq!(starter.outcome, Outcome::Info, "{:?}", starter.messages);
        assert!(starter.messages.iter().any(|m| m.contains("placeholder")));
        // Placeholders replaced + valid structure → Pass.
        let filled = "header:\n  schema-version: \"2.0.0\"\n  url: \"https://example.com/si.yml\"\nproject:\n  name: \"acme/widget\"\n  administrators:\n    - name: \"Real Maintainer\"\n      primary: true\n  repositories:\n    - name: \"acme/widget\"\n      comment: \"primary\"\n      url: \"https://github.com/acme/widget\"\n  vulnerability-reporting:\n    reports-accepted: true\n    bug-bounty-available: false\n";
        std::fs::write(ctx.root.join("security-insights.yml"), filled).unwrap();
        assert_eq!(verify_security_insights(&ctx).outcome, Outcome::Pass);
        // Missing → Fail with the init hint.
        std::fs::remove_file(ctx.root.join("security-insights.yml")).unwrap();
        let missing = verify_security_insights(&ctx);
        assert_eq!(missing.outcome, Outcome::Fail);
        assert!(missing.messages[0].contains("missing"));
    }

    #[test]
    fn security_insights_rejects_missing_required_fields_and_string_license() {
        let (_d, ctx) = repo();
        let p = ctx.root.join("security-insights.yml");
        // project present but no administrators → Fail.
        std::fs::write(
            &p,
            "header:\n  schema-version: \"2.0.0\"\n  url: \"x\"\nproject:\n  name: \"x\"\n",
        )
        .unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("administrators")));
        // repository with a bare-string license → Fail (must be an object).
        std::fs::write(&p, "header:\n  schema-version: \"2.0.0\"\n  url: \"x\"\nrepository:\n  core-team:\n    - name: \"m\"\n      primary: true\n  license: \"https://x/LICENSE\"\n").unwrap();
        let r2 = verify_security_insights(&ctx);
        assert_eq!(r2.outcome, Outcome::Fail);
        assert!(r2.messages.iter().any(|m| m.contains("license")));
    }

    #[test]
    fn security_insights_fails_on_invalid_yaml_and_on_missing_keys() {
        let (_d, ctx) = repo();
        let path = ctx.root.join("security-insights.yml");
        std::fs::write(&path, "header: [this is: not: valid").unwrap();
        assert_eq!(verify_security_insights(&ctx).outcome, Outcome::Fail);
        // Valid YAML but missing the required structure.
        std::fs::write(&path, "something: else\n").unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("schema-version")));
    }

    #[test]
    fn model_signing_is_info_without_models_and_pass_with_a_model() {
        let _g = env_lock();
        let (_d, ctx) = repo();
        // The declared CLI must be present, or the Pass assertion below is
        // testing the new degrade path instead.
        let (_stubs, path) = path_fixture(&["model_signing"], &[]);
        let _env = EnvGuard::new(&[("PATH", Some(&path))]);

        // Fresh repo has no models → Info, N/A, workflow present.
        let na = verify_model_signing(&ctx);
        assert_eq!(na.outcome, Outcome::Info);
        assert!(na.messages.iter().any(|m| m.contains("N/A")));
        // model-signing is default-OFF, so bootstrap did NOT install the
        // workflow. Enable the scenario by hand: add a model + install the
        // workflow → Pass.
        std::fs::write(ctx.root.join("model.safetensors"), b"\x00\x01").unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/sign-models.yml"),
            "name: Sign ML Models\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        let ok = verify_model_signing(&ctx);
        assert_eq!(ok.outcome, Outcome::Pass, "{:?}", ok.messages);
        assert!(ok.messages[0].contains("model.safetensors"));
        // Remove the workflow → Fail (models present, no signing).
        std::fs::remove_file(ctx.root.join(".github/workflows/sign-models.yml")).unwrap();
        assert_eq!(verify_model_signing(&ctx).outcome, Outcome::Fail);
    }

    /// Regression (H11): with models in the tree and the workflow installed the
    /// control reported PASS while `sscsb status` said `model-signing:missing`
    /// in the same session. An installed YAML file is not a signature — without
    /// the declared CLI nothing about these models was verified.
    #[test]
    fn model_signing_degrades_when_the_declared_cli_is_absent() {
        let _g = env_lock();
        let (_d, ctx) = repo();
        let (_stubs, path) = path_fixture(&[], &["model_signing"]);
        let _env = EnvGuard::new(&[("PATH", Some(&path))]);
        assert!(
            !crate::tools::is_available("model-signing"),
            "fixture must hide the model-signing CLI"
        );

        std::fs::write(ctx.root.join("weights.safetensors"), b"\x00\x01").unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/sign-models.yml"),
            "name: Sign ML Models\non:\n  workflow_dispatch:\n",
        )
        .unwrap();

        let r = verify_model_signing(&ctx);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("model-signing not found on PATH")),
            "{:?}",
            r.messages
        );
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("NOT verified locally")));
    }

    #[test]
    fn model_scan_skips_git_and_build_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join(".git/x.onnx"), b"x").unwrap();
        std::fs::write(root.join("target/y.pt"), b"y").unwrap();
        std::fs::write(root.join("real.gguf"), b"z").unwrap();
        let found = find_model_files(root);
        assert_eq!(found, vec!["real.gguf".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn model_scan_never_follows_symlinks() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        // A real model living OUTSIDE the scanned repo.
        std::fs::write(outside.path().join("external.onnx"), b"x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("in-repo.safetensors"), b"y").unwrap();
        // A symlinked directory pointing outside the repo, and a self-cycle.
        symlink(outside.path(), root.join("models")).unwrap();
        symlink(root, root.join("loop")).unwrap();
        // A symlinked model file.
        symlink(
            outside.path().join("external.onnx"),
            root.join("linked.onnx"),
        )
        .unwrap();
        let found = find_model_files(root);
        // Only the real in-repo file — the scan neither follows the dir symlink
        // (escaping the repo), the cycle (stalling), nor the file symlink.
        assert_eq!(found, vec!["in-repo.safetensors".to_string()]);
    }

    #[test]
    fn gittuf_is_info_when_installed_without_policy_and_fail_when_missing() {
        let (_d, ctx) = repo();
        // Bootstrap does not enable gittuf (default-off), so the workflow is
        // absent → Fail. Install it, then re-check → Info (no policy yet).
        assert_eq!(verify_gittuf(&ctx).outcome, Outcome::Fail);
        std::fs::write(
            ctx.root.join(".github/workflows/gittuf-verify.yml"),
            "name: gittuf verify\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        let info = verify_gittuf(&ctx);
        assert_eq!(info.outcome, Outcome::Info, "{:?}", info.messages);
        assert!(info.messages.iter().any(|m| m.contains("no gittuf policy")));
        assert!(!gittuf_policy_present(&ctx.root));
    }

    #[test]
    fn gittuf_passes_once_a_policy_ref_exists() {
        let _g = env_lock();
        let (_d, ctx) = repo();
        // The Pass path is gated on the declared CLI being present; stub it so
        // this test still exercises Pass and not the degrade path.
        let (_stubs, path) = path_fixture(&["gittuf"], &[]);
        let _env = EnvGuard::new(&[("PATH", Some(&path))]);
        std::fs::write(
            ctx.root.join(".github/workflows/gittuf-verify.yml"),
            "name: gittuf verify\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        // Simulate an initialized gittuf policy by creating a refs/gittuf ref.
        let head = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root)
            .or_else(|_| {
                // Ensure at least one commit exists to point the ref at.
                std::fs::write(ctx.root.join("f.txt"), "x").unwrap();
                crate::exec::git(&["add", "-A"], &ctx.root).unwrap();
                crate::exec::git(&["commit", "-m", "c", "--no-verify"], &ctx.root).unwrap();
                crate::exec::git(&["rev-parse", "HEAD"], &ctx.root)
            })
            .unwrap();
        crate::exec::git(
            &["update-ref", "refs/gittuf/reference-state-log", &head],
            &ctx.root,
        )
        .unwrap();
        assert!(gittuf_policy_present(&ctx.root));
        let pass = verify_gittuf(&ctx);
        assert_eq!(pass.outcome, Outcome::Pass, "{:?}", pass.messages);
        assert!(pass.messages.iter().any(|m| m.contains("refs/gittuf/*")));
    }

    /// Regression (H11): `refs/gittuf/…` is a ref NAME — the test above creates
    /// one with a plain `git update-ref`, and so can anyone. Only gittuf can say
    /// whether the RSL and policy actually verify, so with the declared CLI
    /// absent this control has checked a name, not a guarantee, and PASS was a
    /// claim it could not support.
    #[test]
    fn gittuf_degrades_when_the_declared_cli_is_absent() {
        let _g = env_lock();
        let (_d, ctx) = repo();
        let (_stubs, path) = path_fixture(&[], &["gittuf"]);
        let _env = EnvGuard::new(&[("PATH", Some(&path))]);
        assert!(
            !crate::tools::is_available("gittuf"),
            "fixture must hide the gittuf CLI"
        );

        std::fs::write(
            ctx.root.join(".github/workflows/gittuf-verify.yml"),
            "name: gittuf verify\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        std::fs::write(ctx.root.join("f.txt"), "x").unwrap();
        crate::exec::git(&["add", "-A"], &ctx.root).unwrap();
        crate::exec::git(&["commit", "-m", "c", "--no-verify"], &ctx.root).unwrap();
        let head = crate::exec::git(&["rev-parse", "HEAD"], &ctx.root).unwrap();
        crate::exec::git(
            &["update-ref", "refs/gittuf/reference-state-log", &head],
            &ctx.root,
        )
        .unwrap();
        assert!(gittuf_policy_present(&ctx.root));

        let r = verify_gittuf(&ctx);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("gittuf not found on PATH")),
            "{:?}",
            r.messages
        );
        assert!(r.messages.iter().any(|m| m.contains("NOT verified")));
    }

    /// Regression (M22): this exact document — a schema version that does not
    /// exist, a `url` that is not a URL, and a second `url` that is a number —
    /// reported `[PASS] structurally valid`. The verifier is deliberately
    /// structural rather than a schema check (`si validate` owns conformance),
    /// but "structural" was never a licence to pass things that are wrong on
    /// their face.
    #[test]
    fn security_insights_rejects_an_unknown_schema_version_and_non_urls() {
        let (_d, ctx) = repo();
        let path = ctx.root.join("security-insights.yml");
        std::fs::write(
            &path,
            "header:\n  schema-version: 9.9.9\n  url: not-a-url\nproject:\n  name: \"acme/widget\"\n  administrators:\n    - name: \"Real Maintainer\"\n      primary: true\n  repositories:\n    - name: \"acme/widget\"\n      url: 42\n",
        )
        .unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("9.9.9") && m.contains("v9")),
            "{:?}",
            r.messages
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m == "header.url is not a URL: `not-a-url`"),
            "{:?}",
            r.messages
        );
        // A numeric `url` is reported by path, wherever it is nested.
        assert!(
            r.messages
                .iter()
                .any(|m| m == "project.repositories[0].url is not a URL: `42`"),
            "{:?}",
            r.messages
        );
    }

    /// A malformed version is as unusable as an unknown one, and a `url:` with
    /// no scalar value at all is its own kind of wrong.
    #[test]
    fn security_insights_rejects_a_malformed_version_and_a_non_scalar_url() {
        let (_d, ctx) = repo();
        let path = ctx.root.join("security-insights.yml");
        std::fs::write(
            &path,
            "header:\n  schema-version: \"two\"\n  url:\n    - \"https://example.com\"\nproject:\n  name: \"x\"\n  administrators:\n    - name: \"m\"\n      primary: true\n",
        )
        .unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("not a MAJOR.MINOR.PATCH")),
            "{:?}",
            r.messages
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m == "header.url must be a URL string"),
            "{:?}",
            r.messages
        );
        // A non-string schema-version (a plain YAML mapping) is caught too.
        std::fs::write(
            &path,
            "header:\n  schema-version:\n    major: 2\n  url: \"https://example.com\"\nproject:\n  name: \"x\"\n  administrators:\n    - name: \"m\"\n      primary: true\n",
        )
        .unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("must be a version string")),
            "{:?}",
            r.messages
        );
    }

    /// The version gate is on the MAJOR, not the exact string: a spec point
    /// release inside a known major must not turn a good file red, and v1 files
    /// still verify. Nor may the URL check flinch at real-world URL shapes.
    #[test]
    fn security_insights_accepts_known_majors_and_real_url_shapes() {
        let (_d, ctx) = repo();
        let path = ctx.root.join("security-insights.yml");
        for version in ["1.0.0", "2.0.0", "2.7.13"] {
            std::fs::write(
                &path,
                format!("header:\n  schema-version: \"{version}\"\n  url: \"https://example.com/si.yml\"\nproject:\n  name: \"x\"\n  administrators:\n    - name: \"m\"\n      primary: true\n"),
            )
            .unwrap();
            let r = verify_security_insights(&ctx);
            assert_eq!(r.outcome, Outcome::Pass, "{version}: {:?}", r.messages);
        }
        // Schemes other than https, ports, and query strings are all URLs.
        for url in [
            "https://example.com/a?b=c#d",
            "http://127.0.0.1:8080/x",
            "git://example.com/r.git",
            "ssh://git@example.com/r.git",
        ] {
            assert!(looks_like_url(url), "{url} should read as a URL");
        }
        for not_url in [
            "not-a-url",
            "",
            "://nohost",
            "1https://x.com",
            "example.com",
        ] {
            assert!(
                !looks_like_url(not_url),
                "{not_url} should not read as a URL"
            );
        }
    }

    /// A structurally COMPLETE Security Insights document — it would PASS every
    /// check below — whose five nested 9-way anchor levels expand to ~672 000
    /// YAML nodes from 434 bytes. Deliberately sized just over `MAX_SI_NODES`
    /// rather than as large as it could be: pre-fix this costs ~125 MB and ~1 s,
    /// so a future regression of the guard is caught without the test itself
    /// allocating gigabytes.
    const ALIAS_BOMB: &str = concat!(
        "header:\n",
        "  schema-version: \"2.0.0\"\n",
        "  url: \"https://example.com/si.yml\"\n",
        "project:\n",
        "  name: \"acme/widget\"\n",
        "  administrators:\n",
        "    - name: \"Real Maintainer\"\n",
        "      primary: true\n",
        "  a0: &a0 [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n",
        "  a1: &a1 [*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0]\n",
        "  a2: &a2 [*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1]\n",
        "  a3: &a3 [*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2]\n",
        "  a4: &a4 [*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3]\n",
        "  a5: &a5 [*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4]\n",
    );

    /// Regression (M23): `verify` is what people wire into CI, and sscsb is
    /// pointed at repositories it does not trust. A few hundred bytes of nested
    /// YAML anchors made yaml-rust2 clone its way past 4.5 GB RSS with no end
    /// in sight — a denial of service reachable by anyone who can add a file to
    /// the repository. The document must be REFUSED, not expanded.
    #[test]
    fn security_insights_refuses_an_alias_bomb_instead_of_expanding_it() {
        let (_d, ctx) = repo();
        assert!(
            ALIAS_BOMB.len() < 1000,
            "the bomb must stay small — the point is that the FILE is tiny"
        );
        std::fs::write(ctx.root.join("security-insights.yml"), ALIAS_BOMB).unwrap();

        let started = std::time::Instant::now();
        let r = verify_security_insights(&ctx);
        let elapsed = started.elapsed();

        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages.iter().any(|m| m.contains("REFUSED, not parsed")),
            "{:?}",
            r.messages
        );
        assert!(
            r.messages.iter().any(|m| m.contains("billion laughs")),
            "{:?}",
            r.messages
        );
        // Refusing is cheap; expanding is not. Pre-fix this same document took
        // ~1s and ~125MB before answering (and grows geometrically with one
        // more line), so the bound is the regression signal, not decoration.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "refusing the bomb took {elapsed:?} — the guard is not short-circuiting"
        );
    }

    /// The guard must catch amplification, not anchors. A file that reuses an
    /// anchor the way a human would still parses and still passes.
    #[test]
    fn security_insights_still_accepts_ordinary_anchor_reuse() {
        let (_d, ctx) = repo();
        let legit = "header:\n  schema-version: \"2.0.0\"\n  url: \"https://example.com/si.yml\"\nproject:\n  name: \"acme/widget\"\n  administrators: &admins\n    - name: \"Real Maintainer\"\n      primary: true\n  responsible-disclosure: *admins\n  security-contacts: *admins\n";
        std::fs::write(ctx.root.join("security-insights.yml"), legit).unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
    }

    /// The bounded read is the other half of M23: sscsb must not slurp an
    /// arbitrarily large file just because it is named `security-insights.yml`.
    #[test]
    fn security_insights_refuses_a_file_past_the_byte_ceiling() {
        let (_d, ctx) = repo();
        let mut huge = String::from("header:\n  schema-version: \"2.0.0\"\n");
        while huge.len() <= MAX_SI_BYTES {
            huge.push_str("# padding padding padding padding padding padding padding\n");
        }
        std::fs::write(ctx.root.join("security-insights.yml"), &huge).unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(
            r.messages.iter().any(|m| m.contains("byte ceiling")),
            "{:?}",
            r.messages
        );
    }

    /// The node counter models the loader's own cost: a scalar is one node, a
    /// collection is one plus its children, and an alias costs what it clones.
    #[test]
    fn node_budget_charges_an_alias_what_the_loader_would_clone() {
        // 3 scalars + 1 seq node = 4; the root map is 1 + key + value.
        assert_eq!(expanded_node_count("a: [1, 2, 3]\n"), Some(6));
        // The alias costs the whole 4-node sequence again, not one token.
        assert_eq!(expanded_node_count("a: &s [1, 2, 3]\nb: *s\n"), Some(11));
        // An alias to an anchor that never resolves is the loader's BadValue:
        // one node, so a dangling reference cannot be inflated either.
        assert_eq!(expanded_node_count("a: *nope\n"), None);
        // Not YAML at all: the caller falls through to the loader's own error.
        assert_eq!(expanded_node_count("header: [this is: not: valid"), None);
    }

    #[test]
    fn security_insights_reports_empty_file() {
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join("security-insights.yml"), "").unwrap();
        let r = verify_security_insights(&ctx);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages.iter().any(|m| m.contains("empty")));
    }

    #[test]
    fn model_signing_info_notes_when_workflow_is_already_installed() {
        let (_d, ctx) = repo();
        // No models, but the workflow is present → Info that says it's ready.
        std::fs::write(
            ctx.root.join(".github/workflows/sign-models.yml"),
            "name: Sign ML Models\non:\n  workflow_dispatch:\n",
        )
        .unwrap();
        let r = verify_model_signing(&ctx);
        assert_eq!(r.outcome, Outcome::Info);
        assert!(r
            .messages
            .iter()
            .any(|m| m.contains("ready if models are added")));
    }
}
