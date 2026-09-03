//! Template registry: CI workflows, policy files, and sample configs that
//! `sscsb init` installs. Templates are embedded at compile time and rendered
//! with repo-specific values. Invariants enforced by tests in this module:
//! every workflow template passes sscsb's OWN actions audit (SHA-pinned,
//! least-privilege, Harden-Runner first) — the tool that audits you is the
//! tool that generated your workflows.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use anyhow::Result;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Clone, Copy)]
pub struct Artifact {
    /// Control that owns this artifact (installed only when enabled).
    pub control: &'static str,
    /// Destination path relative to the repo root.
    pub dest: &'static str,
    pub content: &'static str,
}

pub const ARTIFACTS: &[Artifact] = &[
    Artifact {
        control: "secrets",
        dest: ".github/workflows/secrets-scan.yml",
        content: include_str!("../templates/workflows/secrets-scan.yml"),
    },
    Artifact {
        control: "secrets",
        dest: ".gitleaks.toml",
        content: include_str!("../templates/configs/gitleaks.toml"),
    },
    Artifact {
        control: "secrets",
        dest: ".trufflehog.yaml",
        content: include_str!("../templates/configs/trufflehog.yaml"),
    },
    Artifact {
        control: "agent-signing",
        dest: ".github/workflows/agent-signing-verify.yml",
        content: include_str!("../templates/workflows/agent-signing-verify.yml"),
    },
    Artifact {
        control: "pr-template",
        dest: ".github/PULL_REQUEST_TEMPLATE.md",
        content: include_str!("../templates/configs/pull_request_template.md"),
    },
    Artifact {
        control: "sbom",
        dest: ".github/workflows/sbom.yml",
        content: include_str!("../templates/workflows/sbom.yml"),
    },
    Artifact {
        control: "vuln-scan",
        dest: ".github/workflows/vuln-scan.yml",
        content: include_str!("../templates/workflows/vuln-scan.yml"),
    },
    Artifact {
        control: "scorecard",
        dest: ".github/workflows/scorecard.yml",
        content: include_str!("../templates/workflows/scorecard.yml"),
    },
    Artifact {
        control: "renovate",
        dest: "renovate.json5",
        content: include_str!("../templates/configs/renovate.json5"),
    },
    Artifact {
        control: "sigstore-signing",
        dest: ".github/workflows/release-sign.yml",
        content: include_str!("../templates/workflows/release-sign.yml"),
    },
    Artifact {
        control: "slsa-provenance",
        dest: ".github/workflows/release-slsa.yml",
        content: include_str!("../templates/workflows/release-slsa.yml"),
    },
    Artifact {
        control: "github-attestations",
        dest: ".github/workflows/release-attest.yml",
        content: include_str!("../templates/workflows/release-attest.yml"),
    },
    Artifact {
        control: "sbom-attestation",
        dest: ".github/workflows/release-attest-sbom.yml",
        content: include_str!("../templates/workflows/release-attest-sbom.yml"),
    },
    Artifact {
        control: "provenance-verify",
        dest: ".github/workflows/deploy-gate.yml",
        content: include_str!("../templates/workflows/deploy-gate.yml"),
    },
    Artifact {
        control: "release-immutability",
        dest: ".github/workflows/release.yml",
        content: include_str!("../templates/workflows/release.yml"),
    },
    Artifact {
        control: "octo-sts",
        dest: ".github/workflows/octo-sts-example.yml",
        content: include_str!("../templates/workflows/octo-sts-example.yml"),
    },
    Artifact {
        control: "octo-sts",
        dest: ".github/chainguard/sscsb-automation.sts.yaml",
        content: include_str!("../templates/configs/octo-sts-policy.sts.yaml"),
    },
    Artifact {
        control: "sast",
        dest: ".github/workflows/sast-opengrep.yml",
        content: include_str!("../templates/workflows/sast-opengrep.yml"),
    },
    Artifact {
        control: "sast",
        dest: ".sscsb/rules/sscsb-default.yaml",
        content: include_str!("../templates/rules/sscsb-default.yaml"),
    },
    Artifact {
        control: "codeql",
        dest: ".github/workflows/codeql.yml",
        content: include_str!("../templates/workflows/codeql.yml"),
    },
    Artifact {
        control: "fuzzing",
        dest: ".github/workflows/cflite-pr.yml",
        content: include_str!("../templates/workflows/cflite-pr.yml"),
    },
    // The ClusterFuzzLite scaffold the workflow needs: a hardened, Trivy-clean
    // build container + build script + the documented `.trivyignore` waiver, so
    // enabling `fuzzing` on any repo yields a Scorecard-detectable, scanner-clean
    // fuzzing setup — not a workflow that references a Dockerfile you must invent.
    // The `fuzz/` cargo-fuzz targets stay yours to write (project-specific).
    Artifact {
        control: "fuzzing",
        dest: ".clusterfuzzlite/Dockerfile",
        content: include_str!("../templates/clusterfuzzlite/Dockerfile"),
    },
    Artifact {
        control: "fuzzing",
        dest: ".clusterfuzzlite/build.sh",
        content: include_str!("../templates/clusterfuzzlite/build.sh"),
    },
    Artifact {
        control: "fuzzing",
        dest: ".trivyignore",
        content: include_str!("../templates/trivyignore"),
    },
    Artifact {
        control: "wait-for-secrets",
        dest: ".github/workflows/wait-for-secrets-example.yml",
        content: include_str!("../templates/workflows/wait-for-secrets-snippet.yml"),
    },
    Artifact {
        control: "dependency-track",
        dest: ".sscsb/templates/dependency-track-compose.yml",
        content: include_str!("../templates/configs/dependency-track-compose.yml"),
    },
    // ── OpenSSF controls ────────────────────────────────────────────────────
    Artifact {
        control: "security-insights",
        dest: "security-insights.yml",
        content: include_str!("../templates/configs/security-insights.yml"),
    },
    Artifact {
        control: "best-practices-badge",
        dest: ".sscsb/best-practices-badge.md",
        content: include_str!("../templates/configs/best-practices-badge.md"),
    },
    Artifact {
        control: "osps-baseline",
        dest: ".sscsb/osps-baseline.md",
        content: include_str!("../templates/configs/osps-baseline.md"),
    },
    Artifact {
        control: "model-signing",
        dest: ".github/workflows/sign-models.yml",
        content: include_str!("../templates/workflows/sign-models.yml"),
    },
    Artifact {
        control: "gittuf",
        dest: ".github/workflows/gittuf-verify.yml",
        content: include_str!("../templates/workflows/gittuf-verify.yml"),
    },
];

/// The numeric GitHub ids a trust policy pins its subject to. GitHub's OIDC
/// `sub` claim decorates the owner and the repository with their ids —
/// `repo:OWNER@<owner_id>/REPO@<repo_id>:ref:refs/heads/main` — so a pattern
/// spelled from names alone never matches what Octo STS is handed; the ids
/// are also what survives a rename and what a re-created repository of the
/// same name does NOT share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoIds {
    pub owner_id: String,
    pub repo_id: String,
}

/// The slug `install_all` renders with when the repository has no GitHub
/// remote and no `github_repo` in its config.
const PLACEHOLDER_SLUG: &str = "OWNER/REPO";

/// Resolve the owner and repository ids for `slug` through `gh api`
/// (`repos/<slug>` and `users/<owner>`, each `--jq .id`). `None` when `gh`
/// is absent, unauthenticated, or the slug is not on GitHub — the caller
/// then renders the tolerant form and says so.
pub fn repo_ids(slug: &str, cwd: &Path) -> Option<RepoIds> {
    let (owner, _) = slug.split_once('/')?;
    crate::exec::find_in_path("gh")?;
    let id = |path: &str| -> Option<String> {
        let out = crate::exec::run("gh", &["api", path, "--jq", ".id"], Some(cwd)).ok()?;
        let id = out.stdout.trim();
        (out.success() && !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()))
            .then(|| id.to_string())
    };
    Some(RepoIds {
        repo_id: id(&format!("repos/{slug}"))?,
        owner_id: id(&format!("users/{owner}"))?,
    })
}

/// Render template placeholders with repo-specific values — the tolerant
/// form: `{{owner_id}}` / `{{repo_id}}` become `[0-9]+`. See
/// [`render_with_ids`].
pub fn render(content: &str, repo_slug: &str, default_branch: &str) -> String {
    render_with_ids(content, repo_slug, default_branch, None)
}

/// Render template placeholders with repo-specific values.
///
/// `{{repo_slug}}`, `{{default_branch}}`; `{{project}}` = the repo name (slug
/// tail — the ClusterFuzzLite scaffold's OSS-Fuzz `$SRC/<project>` path);
/// `{{owner}}` = the slug head; `{{repo_escaped}}` = the repo name with `.`
/// escaped for a regular expression (`p4gs\.github\.io`); `{{owner_id}}` /
/// `{{repo_id}}` = the GitHub ids when `ids` is known, else `[0-9]+`, so an
/// Octo STS `subject_pattern` built as `repo:{{owner}}(@{{owner_id}})?/…`
/// matches GitHub's id-decorated `sub` either way — pinned when the ids are
/// known, tolerant of any id when they are not.
pub fn render_with_ids(
    content: &str,
    repo_slug: &str,
    default_branch: &str,
    ids: Option<&RepoIds>,
) -> String {
    let project = repo_slug.rsplit('/').next().unwrap_or(repo_slug);
    let owner = repo_slug.split('/').next().unwrap_or(repo_slug);
    let any_id = "[0-9]+";
    let (owner_id, repo_id) = ids
        .map(|i| (i.owner_id.as_str(), i.repo_id.as_str()))
        .unwrap_or((any_id, any_id));
    content
        .replace("{{repo_slug}}", repo_slug)
        .replace("{{default_branch}}", default_branch)
        .replace("{{project}}", project)
        .replace("{{owner}}", owner)
        .replace("{{repo_escaped}}", &project.replace('.', "\\."))
        .replace("{{owner_id}}", owner_id)
        .replace("{{repo_id}}", repo_id)
}

/// Whether a template needs the GitHub ids to render pinned.
fn wants_ids(content: &str) -> bool {
    content.contains("{{owner_id}}") || content.contains("{{repo_id}}")
}

pub fn artifacts_for(control: &str) -> Vec<&'static Artifact> {
    ARTIFACTS.iter().filter(|a| a.control == control).collect()
}

/// Install all artifacts whose control is enabled. Existing files are never
/// overwritten (delete to regenerate). Returns human-readable report lines.
///
/// `init` and `verify` must agree on what "implemented" means: a control in
/// the consolidated set ([`Consolidated`]) whose real step already lives in a
/// committed workflow is NOT installed a second time as its modular template.
/// The scan pipeline runs `init` before `verify`; writing `release-sign.yml`
/// here would hand `verify` an init-created file to grade and bury the
/// committed evidence in `release.yml`. The decision is made by the SAME
/// recognizer `verify` uses, so the two cannot disagree.
pub fn install_all(ctx: &Ctx, cfg: &Config) -> Result<Vec<String>> {
    let slug = cfg
        .github_repo()
        .or_else(|| ctx.origin_slug())
        .unwrap_or_else(|| PLACEHOLDER_SLUG.to_string());
    let branch = ctx.default_branch();
    let mut lines = Vec::new();
    // The GitHub ids are asked for once, and only when a template about to be
    // written needs them — never for the placeholder slug, which names no
    // repository.
    let mut ids: Option<Option<RepoIds>> = None;
    for artifact in ARTIFACTS {
        // Every artifact must name a registered control; the lookup is the
        // assertion, and `control_enabled_or_default` reads that same registry
        // entry for the fallback rather than repeating its default here.
        crate::controls::control(artifact.control).expect("registry");
        if !cfg.control_enabled_or_default(artifact.control) {
            lines.push(format!(
                "skip {} (control {} disabled)",
                artifact.dest, artifact.control
            ));
            continue;
        }
        let dest = ctx.root.join(artifact.dest);
        if dest.exists() {
            lines.push(format!(
                "keep {} (exists — delete to regenerate)",
                artifact.dest
            ));
            continue;
        }
        if let Some(kind) = Consolidated::for_control(artifact.control) {
            if let ConsolidatedVerdict::Proven { files, .. } =
                consolidated_evidence(ctx, kind, artifact.dest)
            {
                lines.push(format!(
                    "skip {} ({} proven by {})",
                    artifact.dest,
                    artifact.control,
                    files.join(", ")
                ));
                continue;
            }
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let resolved = if wants_ids(artifact.content) {
            ids.get_or_insert_with(|| {
                (slug != PLACEHOLDER_SLUG)
                    .then(|| repo_ids(&slug, &ctx.root))
                    .flatten()
            })
            .as_ref()
        } else {
            None
        };
        std::fs::write(
            &dest,
            render_with_ids(artifact.content, &slug, &branch, resolved),
        )?;
        lines.push(format!("write {}", artifact.dest));
        if wants_ids(artifact.content) && resolved.is_none() {
            let owner = slug.split('/').next().unwrap_or(&slug);
            lines.push(format!(
                "note {}: owner/repo ids not resolved from the GitHub API — `subject_pattern` \
                 accepts any `@<id>` decoration until you pin them: `gh api repos/{slug} --jq \
                 .id` (repo id), `gh api users/{owner} --jq .id` (owner id)",
                artifact.dest
            ));
        }
    }
    Ok(lines)
}

// ───────────────────────── artifact shape checks ────────────────────────────

/// What sscsb can honestly assert about an installed artifact BEYOND the fact
/// that a file exists at the path.
///
/// Existence is not function. `install_all` never overwrites, so a pre-existing
/// file at a destination is kept and then reported — and a file gutted to
/// `# gutted` is still a file. Each artifact kind therefore gets the strongest
/// structural claim sscsb can make from the bytes alone, and no stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// GitHub Actions workflow: must parse as YAML and declare at least one
    /// job that actually runs something.
    Workflow,
    /// Any other YAML document: must parse into a non-empty mapping.
    Yaml,
    /// JSON / JSON5 config: sscsb parses the comment-stripped JSON subset.
    Json,
    /// TOML config: must parse into a non-empty table.
    Toml,
    /// Prose, shell, Dockerfile, ignore-lists. There is no machine-checkable
    /// structure here that sscsb could assert without inventing one — the
    /// substance of a filled-in worksheet is a human judgement. sscsb proves
    /// only that the file is present and not empty, and says so.
    Opaque,
}

fn shape_of(dest: &str) -> Shape {
    let is_yamlish = dest.ends_with(".yml") || dest.ends_with(".yaml");
    if is_yamlish && dest.starts_with(".github/workflows/") {
        Shape::Workflow
    } else if is_yamlish {
        Shape::Yaml
    } else if dest.ends_with(".json") || dest.ends_with(".json5") {
        Shape::Json
    } else if dest.ends_with(".toml") {
        Shape::Toml
    } else {
        Shape::Opaque
    }
}

/// The verdict on one installed artifact's contents.
enum ShapeVerdict {
    /// Structurally sound as far as this artifact kind can be checked.
    Sound(String),
    /// Present and non-empty, but sscsb's parser cannot confirm it — reported
    /// honestly rather than claimed as verified.
    Unprovable(String),
    /// Provably not a working artifact: empty, unparseable, or inert.
    Broken(String),
}

/// Strip whole-line `//` comments so a JSON5 config can be handed to a strict
/// JSON parser. Deliberately conservative: it does not attempt to be a JSON5
/// implementation, and anything it cannot parse is reported as UNPROVABLE, not
/// as broken.
fn strip_line_comments(content: &str) -> String {
    strip_lines_starting_with(content, "//")
}

/// Drop every line whose first non-blank characters are `marker`. (The
/// `run:` body reader does not use this: shell is tokenised properly by
/// [`shell_commands`], where a `#` comment can also trail a command.)
fn strip_lines_starting_with(content: &str, marker: &str) -> String {
    content
        .lines()
        .filter(|l| !l.trim_start().starts_with(marker))
        .collect::<Vec<_>>()
        .join("\n")
}

fn check_workflow(dest: &str, content: &str) -> ShapeVerdict {
    let docs = match YamlLoader::load_from_str(content) {
        Ok(d) => d,
        Err(err) => {
            return ShapeVerdict::Broken(format!(
                "{dest} is NOT valid YAML ({err}) — GitHub Actions cannot run it"
            ))
        }
    };
    // A trailing `---` yields a blank document, which is not a second
    // workflow; two documents with content are, and GitHub reads exactly one
    // workflow per file — so whichever half the author thinks is running, the
    // file is not the workflow anyone can rely on.
    let live: Vec<&Yaml> = docs
        .iter()
        .filter(|d| !matches!(d, Yaml::Null | Yaml::BadValue))
        .collect();
    let Some(doc) = live.first() else {
        return ShapeVerdict::Broken(format!(
            "{dest} contains no YAML document — a gutted or comment-only workflow runs NOTHING"
        ));
    };
    if live.len() > 1 {
        return ShapeVerdict::Broken(format!(
            "{dest} holds {} YAML documents — a GitHub Actions workflow file is exactly one \
             document, so GitHub cannot run it",
            live.len()
        ));
    }
    let Some(jobs) = doc["jobs"].as_hash().filter(|j| !j.is_empty()) else {
        return ShapeVerdict::Broken(format!(
            "{dest} declares no `jobs:` — the workflow runs NOTHING"
        ));
    };
    // A job with neither `steps:` nor `uses:` is not a runnable job; GitHub
    // rejects it and, until it does, the control it is supposed to enforce is
    // not being enforced.
    let inert: Vec<String> = jobs
        .iter()
        .filter(|(_, job)| {
            let has_steps = job["steps"].as_vec().is_some_and(|s| !s.is_empty());
            let has_uses = job["uses"].as_str().is_some_and(|u| !u.trim().is_empty());
            !(has_steps || has_uses)
        })
        .map(|(id, _)| id.as_str().unwrap_or("<non-string job id>").to_string())
        .collect();
    if !inert.is_empty() {
        return ShapeVerdict::Broken(format!(
            "{dest}: job(s) {} declare neither `steps:` nor `uses:` — they run NOTHING",
            inert.join(", ")
        ));
    }
    // `needs:` naming a job that does not exist is a hard error on GitHub:
    // the whole workflow is rejected at parse time, every job included.
    for (id, job) in jobs {
        let job_id = id.as_str().unwrap_or("<non-string job id>");
        for needed in job_needs(job) {
            if !jobs.contains_key(&Yaml::String(needed.to_string())) {
                return ShapeVerdict::Broken(format!(
                    "{dest}: job `{job_id}` needs `{needed}`, which is not a job in this \
                     workflow — GitHub rejects the whole workflow"
                ));
            }
        }
    }
    ShapeVerdict::Sound(format!("{dest} installed ({} job(s))", jobs.len()))
}

/// The job ids a job's `needs:` names, whatever form the author used
/// (`needs: build` or `needs: [build, test]`).
fn job_needs(job: &Yaml) -> Vec<&str> {
    match &job["needs"] {
        Yaml::String(s) => vec![s.as_str()],
        Yaml::Array(a) => a.iter().filter_map(Yaml::as_str).collect(),
        _ => Vec::new(),
    }
}

fn check_yaml(dest: &str, content: &str) -> ShapeVerdict {
    match YamlLoader::load_from_str(content) {
        Err(err) => ShapeVerdict::Broken(format!("{dest} is NOT valid YAML ({err})")),
        Ok(docs) => match docs.first().and_then(|d| d.as_hash()) {
            Some(h) if !h.is_empty() => {
                ShapeVerdict::Sound(format!("{dest} installed ({} key(s))", h.len()))
            }
            _ => ShapeVerdict::Broken(format!(
                "{dest} holds no YAML mapping — an empty or comment-only config configures NOTHING"
            )),
        },
    }
}

fn check_json(dest: &str, content: &str) -> ShapeVerdict {
    let stripped = strip_line_comments(content);
    if stripped.trim().is_empty() {
        return ShapeVerdict::Broken(format!(
            "{dest} is empty once comments are stripped — it configures NOTHING"
        ));
    }
    match serde_json::from_str::<serde_json::Value>(&stripped) {
        Ok(serde_json::Value::Object(map)) if !map.is_empty() => {
            ShapeVerdict::Sound(format!("{dest} installed ({} key(s))", map.len()))
        }
        Ok(serde_json::Value::Object(_)) => {
            ShapeVerdict::Broken(format!("{dest} is an empty object — it configures NOTHING"))
        }
        Ok(_) => ShapeVerdict::Broken(format!("{dest} is not a JSON object")),
        // JSON5 is a superset (trailing commas, unquoted keys, single quotes);
        // sscsb's stripper only handles the subset its own template uses, so a
        // parse failure here is sscsb's limitation, NOT proof the file is
        // broken. Say that instead of failing a legitimate hand-written config.
        Err(err) => ShapeVerdict::Unprovable(format!(
            "{dest} present and non-empty, but sscsb could not parse it as comment-stripped JSON \
             ({err}) — JSON5 features beyond that subset are outside what it can check"
        )),
    }
}

fn check_toml(dest: &str, content: &str) -> ShapeVerdict {
    match content.parse::<toml::Value>() {
        Err(err) => ShapeVerdict::Broken(format!("{dest} is NOT valid TOML ({err})")),
        Ok(toml::Value::Table(t)) if !t.is_empty() => {
            ShapeVerdict::Sound(format!("{dest} installed ({} key(s))", t.len()))
        }
        Ok(_) => ShapeVerdict::Broken(format!(
            "{dest} holds no TOML table — an empty or comment-only config configures NOTHING"
        )),
    }
}

/// Assert whatever this artifact kind permits. The floor, applied to every
/// kind, is that a zero-byte or whitespace-only artifact is never sound.
fn check_shape(dest: &str, content: &str) -> ShapeVerdict {
    if content.trim().is_empty() {
        return ShapeVerdict::Broken(format!("{dest} is EMPTY — it enforces nothing"));
    }
    match shape_of(dest) {
        Shape::Workflow => check_workflow(dest, content),
        Shape::Yaml => check_yaml(dest, content),
        Shape::Json => check_json(dest, content),
        Shape::Toml => check_toml(dest, content),
        // Deliberately weak, and labelled as such. See `Shape::Opaque`.
        Shape::Opaque => ShapeVerdict::Sound(format!(
            "{dest} installed (present and non-empty; no machine-checkable structure — its \
             substance is a human judgement sscsb does not assert)"
        )),
    }
}

// ───────────────────── consolidated provenance evidence ─────────────────────

/// The release-provenance controls whose deliverable can legitimately live
/// INSIDE another committed workflow instead of in the modular template
/// `sscsb init` installs.
///
/// The draft-then-publish `release.yml` (`release-immutability`) performs the
/// Cosign signing, the build-provenance attestation, the SBOM attestation and
/// the slsa-github-generator call itself, over the exact artifact it ships,
/// because GitHub's release immutability forbids the modular workflows'
/// write-after-publish. Grading those controls by whether `release-sign.yml`
/// exists would fail a repository for doing the right thing — and disabling
/// them to silence that FAIL reads as "not implemented" to every downstream
/// consumer. So, when — and ONLY when — the modular artifact is absent, sscsb
/// looks for the control's real step in every **committed** workflow under
/// `.github/workflows/`, parsed as YAML, and holds it to a bar the template
/// itself meets. Exactly what is checked, and nothing more:
///
/// 1. **Committed (HEAD).** Candidates come from `git ls-tree -r HEAD --
///    .github/workflows` and each is read with `git show HEAD:<path>` — the
///    content a fresh clone would carry. A file that is merely on disk, or
///    only `git add`ed to the index, or edited in the working tree, is never
///    evidence, and is named as such. (Only outside a git repository does
///    sscsb fall back to reading the directory, and it says so.)
/// 2. **Shape-sound.** The file passes [`check_workflow`] — one YAML
///    document, at least one job, no inert job, every `needs:` resolvable —
///    or GitHub would not run it.
/// 3. **Fires unattended.** `on:` includes an automatic trigger (`push`,
///    `release`, `schedule`, `pull_request`, `workflow_run`), or is
///    `workflow_call` and a committed workflow WITH such a trigger calls it
///    via `uses: ./<path>` from a job that is not switched off, in a file
///    that is itself shape-sound, whose effective `permissions:` already
///    grant every scope the called job needs (GitHub refuses a called
///    workflow that asks for more than its caller holds). A
///    `workflow_dispatch`-only or `on:`-less workflow is a manual step, not
///    a control. A trigger's `branches` / `tags` / `paths` / `types` /
///    `workflows` filters are NOT evaluated — the message says so — except
///    that an EMPTY list under any of `branches`, `tags`, `types`,
///    `workflows` or `schedule` matches nothing and fails.
/// 4. **Not switched off.** Neither the proving job nor the proving step
///    carries a constant-false `if:` (`false`, `'false'`, `"false"`,
///    `${{ false }}`) or `continue-on-error: true`; a signing command is not
///    negated with `!`, not followed by `|| true` / `|| :`, and not preceded
///    by a function or alias named `cosign`; and a `run:` body is judged
///    only under a POSIX shell (no `shell:`, `bash`, `sh`, or a `bash … {0}`
///    / `sh … {0}` template). Any other expression is not evaluated.
/// 5. **Pinned.** The action is pinned to a 40-hex commit SHA — except the
///    slsa-github-generator, which must be at a `vX.Y.Z` tag and ONLY a tag,
///    because slsa-verifier identifies the builder by its tag ref and a SHA
///    pin breaks verification (the same helpers `actions-audit` uses, so the
///    two cannot drift on what a SHA or a tag is). Only the generic
///    generator (`generator_generic_slsa3.yml`) is judged.
/// 6. **Bound to an artifact.** The step names what it attests or signs
///    (`subject-*`, `sbom-path`, `base64-subjects` for the generator,
///    `--bundle` as an argument of the same `cosign sign-blob` command — the
///    `run:` body is tokenised as shell, so an `echo`, a `#` comment or a
///    heredoc body that mentions cosign is not a signing command), and for
///    Cosign the installer step precedes the signing step.
/// 7. **Granted.** The job's EFFECTIVE `permissions:` (job level, else
///    workflow level, as GitHub resolves them; an empty job-level block is
///    an explicit grant of nothing) include the scopes the step needs.
///
/// A modular file that is present but Broken is never rescued this way; the
/// file that was examined is reported as the control's evidence so a
/// reclassifier sees the committed file, not the template that was never
/// installed. None of this proves the workflow has RUN — that is what the
/// release itself, and `provenance-verify`, are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consolidated {
    SigstoreSigning,
    GithubAttestations,
    SbomAttestation,
    SlsaProvenance,
}

/// The access a required token scope must grant. `contents: write` is a
/// write; `actions: read` (workflow-run metadata for the SLSA generator) is
/// satisfied by `read` OR `write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
}

impl Access {
    fn word(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl Consolidated {
    fn for_control(control: &str) -> Option<Self> {
        match control {
            "sigstore-signing" => Some(Self::SigstoreSigning),
            "github-attestations" => Some(Self::GithubAttestations),
            "sbom-attestation" => Some(Self::SbomAttestation),
            "slsa-provenance" => Some(Self::SlsaProvenance),
            _ => None,
        }
    }

    /// The evidence looked for, named the way the failure message names it.
    fn wanted(self) -> &'static str {
        match self {
            Self::SigstoreSigning => {
                "a `cosign sign-blob --bundle` step (installed by a preceding SHA-pinned \
                 `sigstore/cosign-installer`) in a job granted `id-token: write`"
            }
            Self::GithubAttestations => {
                "a SHA-pinned `actions/attest-build-provenance` step with a subject \
                 in a job granted `attestations: write` + `id-token: write`"
            }
            Self::SbomAttestation => {
                "a SHA-pinned `actions/attest` step with `sbom-path` and a subject in a job \
                 granted `attestations: write` + `id-token: write`"
            }
            Self::SlsaProvenance => {
                "a job calling the `slsa-framework/slsa-github-generator` \
                 `generator_generic_slsa3.yml` reusable workflow (the generic generator only, \
                 at a `vX.Y.Z` tag) granted `actions: read` + `id-token: write` + \
                 `contents: write`"
            }
        }
    }

    /// Whether this step (or job-level `uses:`) is the control's deliverable.
    /// Matched on the parsed `uses:` value, never on raw text.
    fn is_candidate_action(self, uses: &str) -> bool {
        let (action, _) = split_uses(uses);
        match self {
            Self::GithubAttestations => action == "actions/attest-build-provenance",
            Self::SbomAttestation => action == "actions/attest" || action == "actions/attest-sbom",
            // The generic generator only: it is the one every template calls,
            // and the one `provenance-verify`'s builder id names. The
            // container generator and the language builders are different
            // trusted builders with different subjects and are not judged.
            Self::SlsaProvenance => action == SLSA_GENERIC_GENERATOR,
            // Signing is a `run:` command, not an action — see `cosign_sign_in_run`.
            Self::SigstoreSigning => false,
        }
    }

    fn required_scopes(self) -> &'static [(&'static str, Access)] {
        match self {
            Self::SigstoreSigning => &[("id-token", Access::Write)],
            Self::GithubAttestations | Self::SbomAttestation => {
                &[("attestations", Access::Write), ("id-token", Access::Write)]
            }
            Self::SlsaProvenance => &[
                ("actions", Access::Read),
                ("id-token", Access::Write),
                ("contents", Access::Write),
            ],
        }
    }
}

/// `owner/repo[/path]@ref` → (`owner/repo[/path]`, `ref`); no `@` → empty ref.
fn split_uses(uses: &str) -> (&str, &str) {
    uses.rsplit_once('@').unwrap_or((uses, ""))
}

/// The one generator workflow the `slsa-provenance` control recognizes.
const SLSA_GENERIC_GENERATOR: &str =
    "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml";

/// The pinning bar every consolidated step must meet — the same helpers
/// `actions-audit` uses, so the two cannot drift on what a SHA or a tag is:
/// a 40-hex commit SHA for every action, and a `vX.Y.Z` tag — a tag ONLY —
/// for the slsa-github-generator, whose trust model identifies the builder
/// by its tag ref: slsa-verifier validates that ref, so a SHA pin there
/// produces provenance that cannot be verified (the shipped `release.yml`
/// header says the same).
fn pin_defect(uses: &str) -> Option<String> {
    let (action, r) = split_uses(uses);
    if r.is_empty() {
        return Some(format!(
            "`{uses}` has no ref at all — the step is present but its action is unpinned"
        ));
    }
    if crate::audit::is_tag_pin_exception(action) {
        if crate::audit::is_semver_tag(r) {
            return None;
        }
        if crate::audit::is_full_sha(r) {
            return Some(format!(
                "`{uses}` is pinned to the commit SHA `@{r}` — slsa-verifier identifies the \
                 trusted builder by its `vX.Y.Z` tag ref and refuses a SHA-pinned generator, \
                 so the provenance it produces cannot be verified; pin it to a `vX.Y.Z` tag"
            ));
        }
        return Some(format!(
            "`{uses}` ref `@{r}` is not a `vX.Y.Z` tag — the generator's documented trust \
             model, which slsa-verifier checks, identifies the builder by its tag"
        ));
    }
    if crate::audit::is_full_sha(r) {
        return None;
    }
    Some(format!(
        "`{uses}` is pinned to `@{r}`, not a 40-hex commit SHA — the step is present but \
         its action is mutable"
    ))
}

/// GitHub semantics: a job-level `permissions:` block REPLACES the workflow
/// level wholesale; only a job that declares none inherits the top level. An
/// EMPTY job-level block — `permissions: {}` or a bare `permissions:` — is a
/// declaration: it grants nothing, and inherits nothing.
fn effective_permissions<'a>(doc: &'a Yaml, job: &'a Yaml) -> &'a Yaml {
    let own = &job["permissions"];
    if matches!(own, Yaml::BadValue) {
        &doc["permissions"]
    } else {
        own
    }
}

/// `write-all` grants every scope at every level; `read-all` grants every
/// scope read-only; otherwise the scope must read `write`, or `read` when
/// read access is all that is required.
fn grants(perms: &Yaml, scope: &str, access: Access) -> bool {
    match perms.as_str() {
        Some("write-all") => return true,
        Some("read-all") => return access == Access::Read,
        _ => {}
    }
    matches!(
        (perms[scope].as_str(), access),
        (Some("write"), _) | (Some("read"), Access::Read)
    )
}

fn missing_scopes(perms: &Yaml, required: &[(&str, Access)]) -> Vec<String> {
    required
        .iter()
        .filter(|(scope, access)| !grants(perms, scope, *access))
        .map(|(scope, access)| format!("`{scope}: {}`", access.word()))
        .collect()
}

fn scopes_defect(perms: &Yaml, required: &[(&str, Access)], what: &str) -> Option<String> {
    let missing = missing_scopes(perms, required);
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "{what} runs in a job not granted {} — the effective `permissions:` (job level, \
         else workflow level) do not include it",
        missing.join(" + ")
    ))
}

/// A `with:` input that is set to something — a non-empty string, or any
/// non-scalar the action will receive.
fn with_input_set(step: &Yaml, key: &str) -> bool {
    match &step["with"][key] {
        Yaml::String(s) => !s.trim().is_empty(),
        Yaml::BadValue | Yaml::Null => false,
        _ => true,
    }
}

/// The `subject-*` input that binds an attestation to an artifact digest.
fn subject_input_set(step: &Yaml) -> bool {
    ["subject-path", "subject-digest", "subject-checksums"]
        .iter()
        .any(|k| with_input_set(step, k))
}

/// A job- or step-level `if:` that can never be true, returned as the literal
/// the author wrote so the message can quote it. Recognized: YAML `false`,
/// the quoted strings `'false'` / `"false"` (an expression that evaluates to
/// `false`), and `${{ false }}` in any spacing, with or without quotes
/// inside the braces. Anything else — including an expression sscsb cannot
/// evaluate — is NOT treated as false: this gate exists to catch the switch
/// left off, not to model the expression language.
fn constant_false(cond: &Yaml) -> Option<String> {
    match cond {
        Yaml::Boolean(false) => Some("false".to_string()),
        Yaml::String(s) => {
            let text = s.trim();
            let inner = text
                .strip_prefix("${{")
                .and_then(|r| r.strip_suffix("}}"))
                .map(str::trim)
                .unwrap_or(text);
            let bare = inner
                .strip_prefix('\'')
                .and_then(|r| r.strip_suffix('\''))
                .or_else(|| inner.strip_prefix('"').and_then(|r| r.strip_suffix('"')))
                .unwrap_or(inner);
            (bare == "false").then(|| text.to_string())
        }
        _ => None,
    }
}

/// What followed a simple command — the two operators that change what the
/// command's exit status means for the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sep {
    /// Newline, `;`, `&`, `&&` or end of input.
    Other,
    /// `||` — the next command runs only when this one fails.
    Or,
    /// `|` — this command's output feeds the next one, and without
    /// `pipefail` the pipeline's exit status is the LAST command's, not
    /// this one's.
    Pipe,
}

/// One simple command of a `run:` body: its shell words and what ended it.
#[derive(Debug, PartialEq, Eq)]
struct ShellCommand {
    words: Vec<String>,
    sep: Sep,
}

/// The state of [`shell_commands`] while it walks a script.
#[derive(Default)]
struct Tokeniser {
    commands: Vec<ShellCommand>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    /// Heredoc bodies to skip once the current line ends, in order:
    /// `(delimiter, strip leading tabs)` — the second for `<<-`.
    heredocs: Vec<(String, bool)>,
    /// A `<<` / `<<-` was just read: the next word is its delimiter.
    delimiter_next: bool,
}

impl Tokeniser {
    fn end_word(&mut self) {
        if !self.in_word {
            return;
        }
        let word = std::mem::take(&mut self.word);
        if self.delimiter_next {
            self.delimiter_next = false;
            if let Some(last) = self.heredocs.last_mut() {
                last.0.clone_from(&word);
            }
        }
        self.words.push(word);
        self.in_word = false;
    }

    fn end_command(&mut self, sep: Sep) {
        self.end_word();
        if !self.words.is_empty() {
            self.commands.push(ShellCommand {
                words: std::mem::take(&mut self.words),
                sep,
            });
        }
    }

    /// The line has ended: every heredoc opened on it now has its body,
    /// which runs up to a line equal to the delimiter (leading tabs
    /// stripped for `<<-`). Those lines are data, never commands.
    fn skip_heredoc_bodies(&mut self, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
        // A `<<` with no delimiter before the newline is a syntax error the
        // shell would reject; it opens no body.
        self.delimiter_next = false;
        self.heredocs.retain(|(delimiter, _)| !delimiter.is_empty());
        for (delimiter, strip_tabs) in std::mem::take(&mut self.heredocs) {
            while chars.peek().is_some() {
                let mut line = String::new();
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                    line.push(c);
                }
                let line = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if line == delimiter {
                    break;
                }
            }
        }
    }
}

/// Split a `run:` body into simple commands, each as its shell words plus
/// the operator that ended it.
///
/// Enough of the shell to tell a command from a mention of one, and no more:
/// single and double quotes group words and hide everything inside them;
/// backslash escapes the next character and backslash-newline continues the
/// line; an unquoted `#` at the start of a word begins a comment that runs
/// to the end of the line; newline, `;`, `&`, `&&`, `|` and `||` end a
/// command, but the `&` of a redirection (`2>&1`, `>&2`, `&>log`) is part
/// of its word; `(` and `)` are words of their own; a heredoc (`<<WORD`,
/// `<< 'WORD'`, `<<-WORD`, bare or glued, quotes stripped) makes every line
/// after the current one data up to the line equal to `WORD`, so a signing
/// line inside a `cat <<EOF` or the `: <<'COMMENT'` idiom is not a command.
/// `<<<` is a here-string, not a heredoc. Nothing is expanded — `$f` stays
/// `$f` — because the question is what the author wrote, not what it would
/// evaluate to.
fn shell_commands(script: &str) -> Vec<ShellCommand> {
    let mut t = Tokeniser::default();
    let mut chars = script.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                t.in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    t.word.push(q);
                }
            }
            '"' => {
                t.in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                t.word.push(e);
                            }
                        }
                        _ => t.word.push(q),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') | None => {}
                Some(e) => {
                    t.in_word = true;
                    t.word.push(e);
                }
            },
            '#' if !t.in_word => {
                while chars.peek().is_some_and(|n| *n != '\n') {
                    chars.next();
                }
            }
            '<' if chars.peek() == Some(&'<') => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    // `<<<` is a here-string: a word, not a heredoc.
                    chars.next();
                    t.in_word = true;
                    t.word.push_str("<<<");
                } else {
                    t.end_word();
                    let strip_tabs = chars.next_if_eq(&'-').is_some();
                    t.words
                        .push(if strip_tabs { "<<-" } else { "<<" }.to_string());
                    t.heredocs.push((String::new(), strip_tabs));
                    t.delimiter_next = true;
                }
            }
            '\n' => {
                t.end_command(Sep::Other);
                t.skip_heredoc_bodies(&mut chars);
            }
            ';' => t.end_command(Sep::Other),
            // `2>&1`, `>&2`, `<&0`: the `&` belongs to the redirection, and
            // so does bash's `&>file` — neither ends the command, so a `||`
            // or `|` after them still attaches to this command.
            '&' if t.in_word && t.word.ends_with(['>', '<']) => t.word.push('&'),
            '&' if chars.peek() == Some(&'>') => {
                t.end_word();
                t.in_word = true;
                t.word.push('&');
            }
            '&' | '|' => {
                let doubled = chars.next_if_eq(&c).is_some();
                t.end_command(match (c, doubled) {
                    ('|', true) => Sep::Or,
                    ('|', false) => Sep::Pipe,
                    _ => Sep::Other,
                });
            }
            '(' | ')' => {
                t.end_word();
                t.words.push(c.to_string());
            }
            c if c.is_whitespace() => t.end_word(),
            c => {
                t.in_word = true;
                t.word.push(c);
            }
        }
    }
    t.end_command(Sep::Other);
    t.commands
}

/// Words that may precede the command word without changing which program
/// runs: shell reserved words that open a compound command, and the wrappers
/// that exec their argument.
const COMMAND_PREFIX_WORDS: &[&str] = &[
    "do", "then", "else", "if", "elif", "while", "until", "!", "{", "(", "time", "sudo", "env",
    "command", "exec",
];

/// A leading `VAR=value` assignment (a shell name, then `=`).
fn is_shell_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The program a simple command runs, with everything after it: leading
/// `VAR=…` assignments, `sudo` / `env` / `time` (and their own `-flags`) and
/// compound-command openers (`do`, `then`, `{`, …) are skipped, so
/// `for f in dist/*; do cosign sign-blob …` and `env COSIGN_YES=1 cosign …`
/// both name `cosign`.
fn command_word(words: &[String]) -> Option<(&str, &[String])> {
    command_index(words).map(|i| (words[i].as_str(), &words[i + 1..]))
}

/// The index of the command word in `words` — see [`command_word`].
fn command_index(words: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        if is_shell_assignment(w) {
            i += 1;
        } else if COMMAND_PREFIX_WORDS.contains(&w) {
            i += 1;
            // A wrapper's own options belong to the wrapper, not the command.
            if matches!(w, "sudo" | "env" | "time" | "command") {
                while i < words.len() && words[i].starts_with('-') {
                    i += 1;
                }
            }
        } else {
            return Some(i);
        }
    }
    None
}

/// Whether a `!` precedes the command word: the pipeline's exit status is
/// inverted, so a signing that fails reads as success.
fn negated(words: &[String]) -> bool {
    command_index(words).is_some_and(|i| words[..i].iter().any(|w| w == "!"))
}

/// Whether this command defines a shell function or alias named `cosign`
/// (`cosign() {`, `function cosign`, `alias cosign=…`), so that a later
/// `cosign sign-blob` in the same body runs the author's code, not the
/// installed binary.
fn redefines_cosign(words: &[String]) -> bool {
    let word = |i: usize| words.get(i).map(String::as_str);
    match word(0) {
        Some("cosign") => word(1) == Some("(") && word(2) == Some(")"),
        Some("function") => word(1) == Some("cosign"),
        Some("alias") => words[1..].iter().any(|w| w.starts_with("cosign=")),
        _ => false,
    }
}

/// How a `run:` body that signs falls short — every field `false`/`None`
/// is a body whose signing commands all meet the bar.
#[derive(Debug, Default, PartialEq, Eq)]
struct SigningShortfalls {
    /// A `cosign sign`/`sign-blob` without `--bundle` on its own command line.
    unbundled: bool,
    /// A signing command word preceded by `!` — its exit status is inverted.
    negated: bool,
    /// A signing command followed by `|| <word>` where the word does not
    /// fail the step — the word that swallows the failure.
    failure_ignored: Option<String>,
    /// A signing command followed by `|` with no `set -o pipefail` earlier
    /// in the body — its exit status is the pipeline's last command's.
    piped: bool,
    /// The body defines a function or alias named `cosign`.
    redefined: bool,
}

/// After `||`, the command words that propagate a failure rather than
/// swallow it — `exit` / `return` leave the script or function with a
/// status the author chose, `false` fails outright, `kill` ends the process
/// — plus the two openers of a compound command (`{ …; }` / `( … )`), whose
/// inside sscsb does not follow.
const FAILURE_PROPAGATING_WORDS: &[&str] = &["exit", "return", "false", "kill", "{", "("];

/// Whether this command is a `set` that turns `pipefail` on.
fn sets_pipefail(command: &ShellCommand) -> bool {
    matches!(
        command_word(&command.words),
        Some(("set", args)) if options_set_pipefail(args.iter().map(String::as_str))
    )
}

/// What the `cosign sign` invocations in a step's `run:` body amount to:
/// `Some(shortfalls)` when the body signs, `None` when it does not sign at
/// all.
///
/// The body is tokenised as shell ([`shell_commands`]): a signing command is
/// one whose command word ([`command_word`]) is `cosign` and whose next word
/// is `sign-blob` or `sign`, and it is bundled when `--bundle` (or
/// `--bundle=…`) is one of THAT command's words. So `echo "cosign sign-blob
/// … --bundle"`, a `# cosign sign-blob --bundle` comment, a heredoc body,
/// and a `--bundle` on the next command of a `;`/`&&`/`|` chain are none of
/// them signing with a bundle. `cosign verify-blob` (the deploy-gate side)
/// is not a signing invocation and does not match. A signing command that
/// is negated with `!`, followed by `||` and anything other than `exit` /
/// `return` / `false` / `kill` / `{` / `(` (so `|| true`, `|| :`, `|| echo
/// warn`, `|| continue` all swallow), piped into another command with no
/// `set -o pipefail` before it, or preceded in the same body by a function
/// or alias named `cosign`, is reported as such.
fn cosign_sign_in_run(run: &str) -> Option<SigningShortfalls> {
    let commands = shell_commands(run);
    let mut signs = false;
    let mut shortfalls = SigningShortfalls::default();
    for (i, command) in commands.iter().enumerate() {
        if redefines_cosign(&command.words) {
            shortfalls.redefined = true;
            continue;
        }
        let Some(("cosign", args)) = command_word(&command.words) else {
            continue;
        };
        if !matches!(args.first().map(String::as_str), Some("sign-blob" | "sign")) {
            continue;
        }
        signs = true;
        if !args
            .iter()
            .any(|a| a == "--bundle" || a.starts_with("--bundle="))
        {
            shortfalls.unbundled = true;
        }
        if negated(&command.words) {
            shortfalls.negated = true;
        }
        match command.sep {
            Sep::Or => {
                if let Some(next) = commands.get(i + 1) {
                    // `{` and `(` are compound openers the command-word walk
                    // steps over; here they are the answer.
                    let first = next.words.first().map(String::as_str);
                    let word = if matches!(first, Some("{" | "(")) {
                        first
                    } else {
                        command_word(&next.words).map(|(w, _)| w)
                    };
                    if let Some(word) = word.filter(|w| !FAILURE_PROPAGATING_WORDS.contains(w)) {
                        shortfalls.failure_ignored = Some(word.to_string());
                    }
                }
            }
            Sep::Pipe => {
                if !commands[..i].iter().any(sets_pipefail) {
                    shortfalls.piped = true;
                }
            }
            Sep::Other => {}
        }
    }
    signs.then_some(shortfalls)
}

/// The shell a `run:` step executes under, as GitHub resolves it: the step's
/// `shell:`, else the job's `defaults.run.shell`, else the workflow's. `None`
/// is the runner default.
fn effective_shell<'a>(doc: &'a Yaml, job: &'a Yaml, step: &'a Yaml) -> Option<&'a str> {
    [
        &step["shell"],
        &job["defaults"]["run"]["shell"],
        &doc["defaults"]["run"]["shell"],
    ]
    .into_iter()
    .find_map(|s| s.as_str().map(str::trim).filter(|s| !s.is_empty()))
}

/// Whether a `run:` body under this shell is judged as POSIX shell: no
/// `shell:` at all, the built-in `bash` or `sh`, or GitHub's documented
/// custom-shell shape — `bash`/`sh`, then options (each starting with `-`;
/// a short cluster ending in `o` takes the next word as its `set -o` option
/// name, as in `-eo pipefail`), and exactly one bare `{0}` placeholder for
/// the script (`bash -e {0}`, `bash --noprofile --norc -eo pipefail {0}`).
/// Anything else runs something other than the body as written, and the
/// tokeniser has no opinion about it: `pwsh`, `python`, `cmd`, a custom
/// template such as `true {0}`, a template that smuggles a command in front
/// of the script (`bash -c 'exit 0; {0}'`), an extra bare word beside the
/// placeholder, or options with no `{0}` at all (the runner then starts
/// `bash -e` with no script and the body never runs).
fn is_posix_shell(shell: Option<&str>) -> bool {
    let Some(shell) = shell else {
        return true;
    };
    let mut words = shell.split_whitespace();
    let Some(program) = words.next() else {
        return true;
    };
    if !matches!(program, "bash" | "sh") {
        return false;
    }
    let mut placeholders = 0usize;
    let mut options = 0usize;
    let mut option_name_next = false;
    for word in words {
        if word.trim_matches(['"', '\'']) == "{0}" {
            placeholders += 1;
            option_name_next = false;
        } else if word.starts_with('-') {
            options += 1;
            option_name_next = !word.starts_with("--") && word.ends_with('o');
        } else if option_name_next {
            option_name_next = false;
        } else {
            return false;
        }
    }
    placeholders == 1 || (placeholders == 0 && options == 0)
}

/// Whether an option list turns `pipefail` on: `-o pipefail`, or a short
/// cluster containing `o` (`-eo`, `-euo`) immediately followed by
/// `pipefail`.
fn options_set_pipefail<'a>(words: impl IntoIterator<Item = &'a str>) -> bool {
    let words: Vec<&str> = words.into_iter().collect();
    words.windows(2).any(|pair| {
        pair[0].starts_with('-')
            && !pair[0].starts_with("--")
            && pair[0].contains('o')
            && pair[1] == "pipefail"
    })
}

/// Whether the shell itself runs the body with `pipefail` on: the built-in
/// `bash` (GitHub runs it as `bash --noprofile --norc -eo pipefail {0}`),
/// or a custom template whose own options set it. The built-in `sh` and no
/// `shell:` at all (`bash -e {0}`) do not.
fn shell_sets_pipefail(shell: Option<&str>) -> bool {
    match shell {
        Some("bash") => true,
        Some(template) => options_set_pipefail(template.split_whitespace()),
        None => false,
    }
}

/// `continue-on-error: true` on a job or a step, as YAML `true` or the
/// string `'true'`. Any expression is left alone.
fn continues_on_error(node: &Yaml) -> bool {
    match &node["continue-on-error"] {
        Yaml::Boolean(b) => *b,
        Yaml::String(s) => s.trim() == "true",
        _ => false,
    }
}

/// What one job proves about a consolidated control.
enum JobEvidence {
    /// No trace of the control's step in this job.
    Absent,
    /// The step is here and meets the bar; carries the proof message.
    Proven(String),
    /// The step is here but falls short; carries every precise defect.
    Defective(Vec<String>),
}

fn job_steps(job: &Yaml) -> Vec<&Yaml> {
    job["steps"]
        .as_vec()
        .map(|v| v.iter().collect())
        .unwrap_or_default()
}

fn step_uses(step: &Yaml) -> Option<&str> {
    step["uses"]
        .as_str()
        .map(str::trim)
        .filter(|u| !u.is_empty())
}

/// How a step is named in a message: its `name:` if it has one, else its
/// 1-based position in the job.
fn step_label(index: usize, step: &Yaml) -> String {
    match step["name"].as_str() {
        Some(n) if !n.trim().is_empty() => format!("step `{}`", n.trim()),
        _ => format!("step #{}", index + 1),
    }
}

/// A job whose `if:` is constant-false runs none of its steps, and a job
/// whose `continue-on-error: true` fails nothing when its steps fail.
fn job_switched_off(job: &Yaml, at: &str) -> Vec<String> {
    let mut defects = Vec::new();
    if let Some(v) = constant_false(&job["if"]) {
        defects.push(format!(
            "{at}: job `if: {v}` is constant-false — the job never runs"
        ));
    }
    if continues_on_error(job) {
        defects.push(format!(
            "{at}: job `continue-on-error: true` — a failed job does not fail the run, so the \
             release proceeds without what this job was to produce"
        ));
    }
    defects
}

fn sigstore_job_evidence(doc: &Yaml, job_id: &str, job: &Yaml, at: &str) -> JobEvidence {
    let steps = job_steps(job);
    let signing: Vec<(usize, &Yaml, SigningShortfalls)> = steps
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            s["run"]
                .as_str()
                .and_then(cosign_sign_in_run)
                .map(|shortfalls| (i, *s, shortfalls))
        })
        .collect();
    if signing.is_empty() {
        return JobEvidence::Absent;
    }
    let mut defects = job_switched_off(job, at);
    let installer = steps.iter().enumerate().find_map(|(i, s)| {
        step_uses(s)
            .filter(|u| split_uses(u).0 == "sigstore/cosign-installer")
            .map(|u| (i, u, *s))
    });
    match installer {
        None => defects.push(format!(
            "{at}: invokes cosign but no `sigstore/cosign-installer` step installs it in job \
             `{job_id}` — the binary's provenance is whatever the runner happened to have"
        )),
        Some((i, u, s)) => {
            if let Some(d) = pin_defect(u) {
                defects.push(format!("{at}: {d}"));
            }
            if let Some(v) = constant_false(&s["if"]) {
                defects.push(format!(
                    "{at} {}: `if: {v}` is constant-false — cosign is never installed",
                    step_label(i, s)
                ));
            }
            if continues_on_error(s) {
                defects.push(format!(
                    "{at} {}: `continue-on-error: true` on the installer — a failed install is \
                     ignored and signing runs against whatever the runner happened to have",
                    step_label(i, s)
                ));
            }
        }
    }
    // Every cosign-bearing step is judged; one that falls short is reported
    // even when a sibling step in the same job is sound.
    for (i, step, shortfalls) in &signing {
        let step_at = format!("{at} {}", step_label(*i, step));
        let shell = effective_shell(doc, job, step);
        if !is_posix_shell(shell) {
            defects.push(format!(
                "{step_at}: step runs under shell `{}` — not judged as a POSIX signing command",
                shell.unwrap_or_default()
            ));
        }
        if shortfalls.unbundled {
            defects.push(format!(
                "{step_at}: `cosign sign` runs without `--bundle` on the same command line — \
                 no Sigstore bundle (certificate + signature + Rekor proof) is produced for \
                 consumers to verify"
            ));
        }
        if shortfalls.negated {
            defects.push(format!(
                "{step_at}: the signing command is negated with `!` — its exit status is \
                 inverted, so a failed signing reads as success"
            ));
        }
        if let Some(word) = &shortfalls.failure_ignored {
            defects.push(format!(
                "{step_at}: the signing command is followed by `|| {word}` — a failed signing \
                 is swallowed and the step succeeds with an unsigned artifact"
            ));
        }
        if shortfalls.piped && !shell_sets_pipefail(shell) {
            defects.push(format!(
                "{step_at}: the signing command's output is piped — its exit status is not \
                 the step's (no `set -o pipefail` precedes it in the body, and the shell \
                 does not set it)"
            ));
        }
        if shortfalls.redefined {
            defects.push(format!(
                "{step_at}: the `run:` body defines a function or alias named `cosign` — the \
                 signing command is not the installed cosign"
            ));
        }
        if let Some(v) = constant_false(&step["if"]) {
            defects.push(format!(
                "{step_at}: `if: {v}` is constant-false — the signing step never runs"
            ));
        }
        if continues_on_error(step) {
            defects.push(format!(
                "{step_at}: `continue-on-error: true` — a failed signing does not fail the job"
            ));
        }
        if let Some((ii, _, _)) = installer {
            if ii > *i {
                defects.push(format!(
                    "{step_at}: signs at step #{} but `sigstore/cosign-installer` is step #{} \
                     — cosign is installed AFTER the signing step, so signing runs against \
                     whatever the runner happened to have",
                    i + 1,
                    ii + 1
                ));
            }
        }
    }
    if let Some(d) = scopes_defect(
        effective_permissions(doc, job),
        Consolidated::SigstoreSigning.required_scopes(),
        "`cosign sign-blob`",
    ) {
        defects.push(format!(
            "{at}: {d}; keyless signing cannot obtain a Fulcio certificate without it"
        ));
    }
    if !defects.is_empty() {
        return JobEvidence::Defective(defects);
    }
    JobEvidence::Proven(format!(
        "{at}: keyless-signs with `cosign sign-blob --bundle` via `{}` under `id-token: write`",
        installer.map(|(_, u, _)| u).unwrap_or_default()
    ))
}

fn attest_job_evidence(kind: Consolidated, doc: &Yaml, job: &Yaml, at: &str) -> JobEvidence {
    let candidates: Vec<(usize, &str, &Yaml)> = job_steps(job)
        .into_iter()
        .enumerate()
        .filter_map(|(i, s)| step_uses(s).map(|u| (i, u, s)))
        .filter(|(_, u, _)| kind.is_candidate_action(u))
        .collect();
    if candidates.is_empty() {
        return JobEvidence::Absent;
    }
    let mut defects = job_switched_off(job, at);
    let mut proven = Vec::new();
    for (i, uses, step) in candidates {
        if let Some(d) = pin_defect(uses) {
            defects.push(format!("{at}: {d}"));
        }
        if let Some(v) = constant_false(&step["if"]) {
            defects.push(format!(
                "{at} {}: `if: {v}` is constant-false — the attestation step never runs",
                step_label(i, step)
            ));
        }
        if continues_on_error(step) {
            defects.push(format!(
                "{at} {}: `continue-on-error: true` — a failed attestation does not fail the job",
                step_label(i, step)
            ));
        }
        if !subject_input_set(step) {
            defects.push(format!(
                "{at}: `{uses}` names no subject (`subject-path`, `subject-digest` or \
                 `subject-checksums`) — {} not bound to any artifact digest",
                match kind {
                    Consolidated::GithubAttestations => "provenance",
                    _ => "the SBOM attestation",
                }
            ));
        }
        if kind == Consolidated::SbomAttestation && !with_input_set(step, "sbom-path") {
            defects.push(format!(
                "{at}: `{uses}` has no `sbom-path` — nothing binds an SBOM to the artifact \
                 digest"
            ));
        }
        proven.push(format!("`{uses}`"));
    }
    if let Some(d) = scopes_defect(
        effective_permissions(doc, job),
        kind.required_scopes(),
        &proven.join(", "),
    ) {
        defects.push(format!("{at}: {d}"));
    }
    if !defects.is_empty() {
        return JobEvidence::Defective(defects);
    }
    JobEvidence::Proven(match kind {
        Consolidated::GithubAttestations => format!(
            "{at}: attests build provenance to GitHub's attestation store with {} under \
             `attestations: write` + `id-token: write`",
            proven.join(", ")
        ),
        _ => format!(
            "{at}: attests the SBOM (`sbom-path`) to the artifact digest with {} under \
             `attestations: write` + `id-token: write`",
            proven.join(", ")
        ),
    })
}

fn slsa_job_evidence(doc: &Yaml, job: &Yaml, at: &str) -> JobEvidence {
    let Some(uses) = job["uses"]
        .as_str()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    else {
        return JobEvidence::Absent;
    };
    if !Consolidated::SlsaProvenance.is_candidate_action(uses) {
        // Another workflow of the generator's repository — the container
        // generator, a language builder — is the generator's step in name,
        // but not the one this recognizer judges.
        if crate::audit::is_tag_pin_exception(split_uses(uses).0) {
            return JobEvidence::Defective(vec![format!(
                "{at}: `{uses}` is not `{SLSA_GENERIC_GENERATOR}` — only the generic \
                 generator, the one the templates call, is judged; the container and \
                 language-builder workflows of slsa-github-generator are out of scope and \
                 are not evidence"
            )]);
        }
        return JobEvidence::Absent;
    }
    let mut defects = job_switched_off(job, at);
    if let Some(d) = pin_defect(uses) {
        defects.push(format!("{at}: {d}"));
    }
    // The generator attests whatever subjects it is handed. A call that hands
    // it none produces provenance describing nothing.
    if !(with_input_set(job, "base64-subjects") || with_input_set(job, "base64-subjects-as-file")) {
        defects.push(format!(
            "{at}: `{uses}` names no subjects (`base64-subjects` or `base64-subjects-as-file` \
             in `with:`) — provenance is bound to nothing"
        ));
    }
    if let Some(d) = scopes_defect(
        effective_permissions(doc, job),
        Consolidated::SlsaProvenance.required_scopes(),
        &format!("`{uses}`"),
    ) {
        defects.push(format!(
            "{at}: {d}; the generator cannot read the run (actions), sign (id-token) or \
             attach provenance (contents) without them"
        ));
    }
    if !defects.is_empty() {
        return JobEvidence::Defective(defects);
    }
    JobEvidence::Proven(format!(
        "{at}: generates SLSA L3 provenance via `{uses}` under `actions: read` + \
         `id-token: write` + `contents: write`"
    ))
}

fn consolidated_job_evidence(
    kind: Consolidated,
    doc: &Yaml,
    job_id: &str,
    job: &Yaml,
    at: &str,
) -> JobEvidence {
    match kind {
        Consolidated::SigstoreSigning => sigstore_job_evidence(doc, job_id, job, at),
        Consolidated::GithubAttestations | Consolidated::SbomAttestation => {
            attest_job_evidence(kind, doc, job, at)
        }
        Consolidated::SlsaProvenance => slsa_job_evidence(doc, job, at),
    }
}

// ─────────────────────────── candidate workflows ────────────────────────────

/// Triggers that run a workflow without a human pressing a button. A workflow
/// reachable only through `workflow_dispatch` is a procedure, not a control.
const AUTOMATIC_TRIGGERS: &[&str] = &[
    "push",
    "release",
    "schedule",
    "pull_request",
    "workflow_run",
];

/// Every trigger name under `on:`, whatever shape the author used
/// (`on: push`, `on: [push, release]`, or the mapping form).
fn trigger_names(doc: &Yaml) -> Vec<String> {
    match &doc["on"] {
        Yaml::String(s) => vec![s.clone()],
        Yaml::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Yaml::Hash(h) => h
            .keys()
            .filter_map(|k| k.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// The filters GitHub applies to a trigger before running the workflow.
/// sscsb does not evaluate them (no glob engine, no ref to match against);
/// their presence is named in the message instead, so "fires on `push`" is
/// never claimed of a workflow whose `push` is filtered.
const TRIGGER_FILTERS: &[&str] = &[
    "branches",
    "branches-ignore",
    "tags",
    "tags-ignore",
    "paths",
    "paths-ignore",
    "types",
    "workflows",
];

/// The filter keys the author put under `on: <trigger>:`.
fn trigger_filters(doc: &Yaml, trigger: &str) -> Vec<&'static str> {
    let cfg = &doc["on"][trigger];
    TRIGGER_FILTERS
        .iter()
        .copied()
        .filter(|k| !matches!(cfg[*k], Yaml::BadValue))
        .collect()
}

/// A YAML node that is a list with nothing in it — `[]`, or a bare key.
fn empty_list(node: &Yaml) -> bool {
    matches!(node, Yaml::Null) || matches!(node, Yaml::Array(a) if a.is_empty())
}

/// The one filter shape that can be judged without evaluating a glob or a
/// cron: a list with nothing in it matches nothing, so the trigger never
/// fires. An empty `branches:` / `tags:` matches no ref, an empty `types:`
/// no activity, an empty `workflows:` no upstream workflow, and a
/// `schedule:` with no cron entries schedules nothing. Returns the reason,
/// phrased to follow "`on: <trigger>`".
fn dead_trigger(doc: &Yaml, trigger: &str) -> Option<String> {
    let cfg = &doc["on"][trigger];
    if trigger == "schedule" && !matches!(cfg, Yaml::Array(a) if !a.is_empty()) {
        return Some("lists no cron entries — nothing is scheduled".to_string());
    }
    [
        ("branches", "it matches no ref"),
        ("tags", "it matches no ref"),
        ("types", "it matches no activity type"),
        ("workflows", "it names no workflow to run after"),
    ]
    .into_iter()
    .find(|(key, _)| empty_list(&cfg[*key]))
    .map(|(key, why)| format!("has an empty `{key}:` filter — {why}"))
}

/// `push`, or `push (tags filter not evaluated)` — the trigger named
/// together with what sscsb did NOT check about it.
fn describe_trigger(doc: &Yaml, trigger: &str) -> String {
    let filters = trigger_filters(doc, trigger);
    if filters.is_empty() {
        return format!("`{trigger}`");
    }
    format!(
        "`{trigger}` ({} filter{} not evaluated)",
        filters.join(", "),
        if filters.len() > 1 { "s" } else { "" }
    )
}

/// The first automatic trigger that is not filtered down to nothing.
fn automatic_trigger(doc: &Yaml) -> Option<String> {
    trigger_names(doc)
        .into_iter()
        .filter(|t| AUTOMATIC_TRIGGERS.contains(&t.as_str()))
        .find(|t| dead_trigger(doc, t).is_none())
}

/// One workflow file as the recognizer sees it: committed, readable, parsed.
struct WorkflowFile {
    rel: String,
    content: String,
    docs: Vec<Yaml>,
}

/// The candidate set plus every reason a file under `.github/workflows/`
/// was NOT a candidate, so "absent" is never quietly "unexamined".
struct WorkflowSet {
    files: Vec<WorkflowFile>,
    notes: Vec<String>,
}

/// Where a candidate's bytes come from.
enum Source {
    /// `git show HEAD:<rel>` — the committed content, whatever the working
    /// tree or the index currently hold.
    Head,
    /// The working tree, because there is no git repository to ask. Only
    /// ever used with a note saying committed-ness was not established.
    Disk,
}

const WORKFLOWS_DIR: &str = ".github/workflows";

/// The workflow files git has committed at HEAD under `.github/workflows/`,
/// as `(name, source)`, plus the notes explaining every on-disk file that is
/// NOT in that set. "Committed" is literal: the index (`git add`) is not a
/// commit, and a working-tree edit is not the content a clone carries.
fn committed_workflow_names(ctx: &Ctx, on_disk: &[String]) -> (Vec<(String, Source)>, Vec<String>) {
    let mut notes = Vec::new();
    let listing = crate::exec::git_raw(
        &[
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            "HEAD",
            "--",
            WORKFLOWS_DIR,
        ],
        &ctx.root,
    );
    let uncommitted_note = |names: Vec<&String>, notes: &mut Vec<String>| {
        if !names.is_empty() {
            notes.push(format!(
                "uncommitted workflow file(s) were not examined — only content committed at \
                 HEAD is evidence: {}",
                names
                    .iter()
                    .map(|n| format!("{WORKFLOWS_DIR}/{n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    };
    match listing {
        Ok(out) if out.success() => {
            let committed: Vec<String> = out
                .stdout
                .split('\0')
                .filter_map(|p| p.strip_prefix(&format!("{WORKFLOWS_DIR}/")))
                .filter(|n| !n.is_empty() && !n.contains('/') && is_workflow_name(n))
                .map(str::to_string)
                .collect();
            uncommitted_note(
                on_disk.iter().filter(|n| !committed.contains(n)).collect(),
                &mut notes,
            );
            (
                committed.into_iter().map(|n| (n, Source::Head)).collect(),
                notes,
            )
        }
        other => {
            let in_repo = crate::exec::git_raw(&["rev-parse", "--git-dir"], &ctx.root)
                .is_ok_and(|o| o.success());
            if in_repo {
                // A repository with no commits yet, or a HEAD git cannot
                // read: nothing is committed, so nothing is evidence.
                let why = match other {
                    Ok(o) => o.stderr.trim().to_string(),
                    Err(e) => format!("{e:#}"),
                };
                notes.push(format!(
                    "HEAD could not be read ({why}) — no content is committed, so no workflow \
                     under {WORKFLOWS_DIR}/ can be evidence"
                ));
                uncommitted_note(on_disk.iter().collect(), &mut notes);
                (Vec::new(), notes)
            } else {
                notes.push(format!(
                    "not inside a git repository — {WORKFLOWS_DIR}/ was read from disk and \
                     committed-ness (tracked-ness) could NOT be established; every file there \
                     was examined"
                ));
                (
                    on_disk.iter().map(|n| (n.clone(), Source::Disk)).collect(),
                    notes,
                )
            }
        }
    }
}

fn is_workflow_name(name: &str) -> bool {
    name.ends_with(".yml") || name.ends_with(".yaml")
}

/// The workflow files present on disk under `.github/workflows/` (top level
/// only — the only place GitHub reads).
fn on_disk_workflows(ctx: &Ctx) -> Vec<String> {
    let dir = ctx.root.join(".github").join("workflows");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| is_workflow_name(n))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The workflows committed at HEAD under `.github/workflows/`, read from HEAD
/// (`git show HEAD:<path>`), so that neither an index-only `git add` nor a
/// working-tree edit can be evidence — what is examined is what a fresh clone
/// would carry. Only when there is no git repository to ask does this fall
/// back to the directory listing, and it says so.
fn committed_workflows(ctx: &Ctx) -> WorkflowSet {
    let on_disk = on_disk_workflows(ctx);
    let (mut candidates, mut notes) = committed_workflow_names(ctx, &on_disk);
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates.dedup_by(|a, b| a.0 == b.0);
    let mut files = Vec::new();
    for (name, source) in candidates {
        let rel = format!("{WORKFLOWS_DIR}/{name}");
        let path = ctx.root.join(&rel);
        let bytes = match source {
            Source::Head => {
                let shown = crate::exec::git_bytes(&["show", &format!("HEAD:{rel}")], &ctx.root);
                match shown {
                    Ok(out) if out.success() => out.stdout,
                    other => {
                        let why = match other {
                            Ok(o) => o.stderr.trim().to_string(),
                            Err(e) => format!("{e:#}"),
                        };
                        notes.push(format!(
                            "{rel} is committed but could not be read from HEAD ({why}) and \
                             was not examined"
                        ));
                        continue;
                    }
                }
            }
            Source::Disk => match std::fs::read(&path) {
                Ok(b) => b,
                Err(err) => {
                    notes.push(format!(
                        "{rel} could not be read ({err}) and was not examined"
                    ));
                    continue;
                }
            },
        };
        // The working tree is NOT what was examined. Say so whenever it
        // differs, so a developer looking at their editor is not misled
        // about which version the verdict rests on.
        if matches!(source, Source::Head) {
            match std::fs::read(&path) {
                Ok(disk) if disk == bytes => {}
                Ok(_) => notes.push(format!(
                    "{rel} differs from HEAD in the working tree — only the committed (HEAD) \
                     content was examined"
                )),
                Err(_) => notes.push(format!(
                    "{rel} is committed at HEAD but absent from the working tree — the \
                     committed content was examined"
                )),
            }
        }
        let Ok(content) = String::from_utf8(bytes) else {
            notes.push(format!("{rel} is unreadable as text and was not examined"));
            continue;
        };
        let Ok(docs) = YamlLoader::load_from_str(&content) else {
            notes.push(format!("{rel} is not valid YAML and was not examined"));
            continue;
        };
        files.push(WorkflowFile { rel, content, docs });
    }
    WorkflowSet { files, notes }
}

/// What the search for a `workflow_call` workflow's caller found.
struct CallerSearch {
    /// How it fires, when a sound, automatically triggered, live caller
    /// whose grant covers the called job exists.
    via: Option<String>,
    /// Callers that call it but cannot run it: the calling job's effective
    /// grant is short of what the called proving job requires.
    defects: Vec<String>,
}

/// Whether any document of `wf` has a job that calls `local`.
fn calls(wf: &WorkflowFile, local: &str) -> bool {
    wf.docs.iter().any(|doc| {
        doc["jobs"].as_hash().is_some_and(|jobs| {
            jobs.values()
                .any(|job| job["uses"].as_str().map(str::trim) == Some(local))
        })
    })
}

/// How a `workflow_call`-only workflow fires: the first committed,
/// shape-sound workflow with an automatic trigger whose (not switched-off)
/// job calls it as `uses: ./<rel>` and whose effective `permissions:`
/// already grant every scope the called proving job needs — GitHub refuses a
/// called workflow's job that asks for more than its caller holds, so a
/// caller short of a scope runs nothing. One level only — a caller that is
/// itself call-only does not count. A caller that is not a sound workflow
/// is skipped, and the reason lands in `notes`.
fn automatic_caller(
    files: &[WorkflowFile],
    rel: &str,
    kind: Consolidated,
    notes: &mut Vec<String>,
) -> CallerSearch {
    let local = format!("./{rel}");
    let mut defects = Vec::new();
    for wf in files.iter().filter(|w| w.rel != rel && calls(w, &local)) {
        if let ShapeVerdict::Broken(m) = check_workflow(&wf.rel, &wf.content) {
            notes.push(format!("{m} — not counted as a caller of {rel}"));
            continue;
        }
        for doc in &wf.docs {
            let Some(trigger) = automatic_trigger(doc) else {
                continue;
            };
            let Some(jobs) = doc["jobs"].as_hash() else {
                continue;
            };
            for (id, job) in jobs {
                if job["uses"].as_str().map(str::trim) != Some(local.as_str())
                    || constant_false(&job["if"]).is_some()
                {
                    continue;
                }
                let job_id = id.as_str().unwrap_or("<non-string job id>");
                // The calling job is the proving job's outer shell: if ITS
                // failure does not fail the run, neither does the called
                // job's, however sound that job is.
                if continues_on_error(job) {
                    defects.push(format!(
                        "{rel}: called from `{}` job `{job_id}` (on {}), whose \
                         `continue-on-error: true` means a failed call does not fail the run \
                         — the release proceeds without what this workflow was to produce",
                        wf.rel,
                        describe_trigger(doc, &trigger)
                    ));
                    continue;
                }
                let missing =
                    missing_scopes(effective_permissions(doc, job), kind.required_scopes());
                if missing.is_empty() {
                    return CallerSearch {
                        via: Some(format!(
                            "fires via `{}` job `{job_id}` (on {}), which calls it as a \
                             reusable workflow",
                            wf.rel,
                            describe_trigger(doc, &trigger)
                        )),
                        defects,
                    };
                }
                defects.push(format!(
                    "{rel}: called from `{}` job `{job_id}` (on {}), whose effective \
                     `permissions:` (job level, else workflow level) do not grant {} — GitHub \
                     refuses a called workflow's job that asks for more than its caller \
                     holds, so the call runs nothing",
                    wf.rel,
                    describe_trigger(doc, &trigger),
                    missing.join(" + ")
                ));
            }
        }
    }
    CallerSearch { via: None, defects }
}

/// Gate 3: `Ok(how it fires)` or `Err(the defects that keep it from firing)`.
fn trigger_verdict(
    doc: &Yaml,
    rel: &str,
    files: &[WorkflowFile],
    kind: Consolidated,
    notes: &mut Vec<String>,
) -> Result<String, Vec<String>> {
    if let Some(t) = automatic_trigger(doc) {
        return Ok(format!("fires on {}", describe_trigger(doc, &t)));
    }
    let names = trigger_names(doc);
    // An automatic trigger whose filter is an empty list is present in name
    // only — GitHub has nothing to match it against.
    if let Some((t, why)) = names
        .iter()
        .filter(|t| AUTOMATIC_TRIGGERS.contains(&t.as_str()))
        .find_map(|t| dead_trigger(doc, t).map(|why| (t, why)))
    {
        return Err(vec![format!(
            "{rel}: `on: {t}` {why}, so the trigger never fires — it carries {} but nothing \
             runs it unattended",
            kind.wanted()
        )]);
    }
    if names.iter().any(|t| t == "workflow_call") {
        let found = automatic_caller(files, rel, kind, notes);
        if let Some(via) = found.via {
            return Ok(via);
        }
        if !found.defects.is_empty() {
            return Err(found.defects);
        }
        return Err(vec![format!(
            "{rel}: manual-only trigger — `on:` has `workflow_call` but no committed workflow \
             with an automatic trigger (push/release/schedule/pull_request/workflow_run) calls \
             it via `uses: ./{rel}` — it carries {} but nothing runs it unattended",
            kind.wanted()
        )]);
    }
    let listed = if names.is_empty() {
        "`on:` is absent".to_string()
    } else {
        format!(
            "`on:` lists only {}",
            names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(vec![format!(
        "{rel}: manual-only trigger — {listed}, none of \
         push/release/schedule/pull_request/workflow_run — it carries {} but nothing runs it \
         unattended",
        kind.wanted()
    )])
}

/// The repository-wide verdict on one consolidated control.
enum ConsolidatedVerdict {
    /// At least one job somewhere meets the bar. Carries the files those jobs
    /// live in (the control's evidence) and every message, including defects
    /// found in OTHER candidate jobs so they are not hidden by the pass.
    Proven {
        files: Vec<String>,
        messages: Vec<String>,
    },
    /// The step exists somewhere but no job meets the bar.
    Defective(Vec<String>),
    /// No committed workflow carries the step. Carries notes on files that
    /// could not be examined, so "absent" is never quietly "unparsed".
    Absent(Vec<String>),
}

/// Search every committed workflow (except the modular artifact's own path,
/// which the caller has already established is missing) for the control's
/// real step, and judge each job that carries it against every gate listed
/// on [`Consolidated`].
fn consolidated_evidence(ctx: &Ctx, kind: Consolidated, modular: &str) -> ConsolidatedVerdict {
    let set = committed_workflows(ctx);
    let mut files = Vec::new();
    let mut proven = Vec::new();
    let mut defects = Vec::new();
    let mut notes = set.notes;
    for wf in set.files.iter().filter(|w| w.rel != modular) {
        let rel = &wf.rel;
        let per_doc: Vec<(&Yaml, Vec<JobEvidence>)> = wf
            .docs
            .iter()
            .filter_map(|doc| {
                let jobs = doc["jobs"].as_hash()?;
                let evidence = jobs
                    .iter()
                    .map(|(id, job)| {
                        let job_id = id.as_str().unwrap_or("<non-string job id>");
                        let at = format!("{rel} job `{job_id}`");
                        consolidated_job_evidence(kind, doc, job_id, job, &at)
                    })
                    .collect();
                Some((doc, evidence))
            })
            .collect();
        let carries = per_doc
            .iter()
            .flat_map(|(_, e)| e.iter())
            .any(|e| !matches!(e, JobEvidence::Absent));
        if !carries {
            continue;
        }
        // The step is here. A file that is not a sound workflow cannot be
        // evidence no matter what its steps say — GitHub will not run it.
        if let ShapeVerdict::Broken(m) = check_workflow(rel, &wf.content) {
            defects.push(format!(
                "{m} — it carries {} but cannot serve as evidence",
                kind.wanted()
            ));
            continue;
        }
        let mut file_proven = false;
        for (doc, evidence) in per_doc {
            if evidence.iter().all(|e| matches!(e, JobEvidence::Absent)) {
                continue;
            }
            // A workflow nothing runs unattended proves nothing, however
            // sound its steps.
            let fires = match trigger_verdict(doc, rel, &set.files, kind, &mut notes) {
                Ok(fires) => fires,
                Err(d) => {
                    defects.extend(d);
                    continue;
                }
            };
            for e in evidence {
                match e {
                    JobEvidence::Absent => {}
                    JobEvidence::Proven(m) => {
                        file_proven = true;
                        proven.push(format!("{m}; {fires}"));
                    }
                    JobEvidence::Defective(d) => defects.extend(d),
                }
            }
        }
        if file_proven {
            files.push(rel.clone());
        }
    }
    if !files.is_empty() {
        let mut messages = proven;
        messages.extend(defects);
        messages.extend(notes);
        return ConsolidatedVerdict::Proven { files, messages };
    }
    if !defects.is_empty() {
        defects.append(&mut notes);
        return ConsolidatedVerdict::Defective(defects);
    }
    ConsolidatedVerdict::Absent(notes)
}

/// Generic verifier for controls whose deliverable is installed artifacts.
///
/// Checks the artifact's CONTENT, not just its inode: `install_all` never
/// overwrites, so the file sitting at a destination may be a gutted stub or
/// something else entirely that happens to share the name.
///
/// For the four release-provenance controls, a MISSING modular artifact is not
/// the end of the question: see [`Consolidated`]. The file that proved the
/// control is returned as the result's `evidence`.
pub fn verify_template_control(ctx: &Ctx, control: &'static str) -> VerifyResult {
    if control == "harden-runner" {
        return verify_harden_runner(ctx);
    }
    let artifacts = artifacts_for(control);
    if artifacts.is_empty() {
        return VerifyResult::new(
            control,
            Outcome::Fail,
            vec![format!("no artifacts registered for `{control}` — bug")],
        );
    }
    let mut messages = Vec::new();
    let mut evidence: Vec<String> = Vec::new();
    let mut broken = 0;
    let mut unprovable = 0;
    for a in artifacts {
        let path = ctx.root.join(a.dest);
        if !path.is_file() {
            let Some(kind) = Consolidated::for_control(control) else {
                broken += 1;
                messages.push(format!("{} MISSING — run `sscsb init`", a.dest));
                continue;
            };
            match consolidated_evidence(ctx, kind, a.dest) {
                ConsolidatedVerdict::Proven { files, messages: m } => {
                    messages.push(format!(
                        "{} not installed — verified by consolidated evidence in {} instead",
                        a.dest,
                        files.join(", ")
                    ));
                    messages.extend(m);
                    evidence.extend(files);
                }
                ConsolidatedVerdict::Defective(m) => {
                    broken += 1;
                    messages.push(format!(
                        "{} MISSING, and the consolidated implementation found in its place \
                         does not meet the bar — fix it, or run `sscsb init` to install the \
                         modular workflow",
                        a.dest
                    ));
                    messages.extend(m);
                }
                ConsolidatedVerdict::Absent(notes) => {
                    broken += 1;
                    messages.push(format!(
                        "{} MISSING — run `sscsb init`; no committed (HEAD) workflow under \
                         .github/workflows/ carries {} in its place",
                        a.dest,
                        kind.wanted()
                    ));
                    messages.extend(notes);
                }
            }
            continue;
        }
        // A non-UTF-8 blob at a template destination is not the artifact.
        let Ok(content) = std::fs::read_to_string(&path) else {
            broken += 1;
            messages.push(format!(
                "{} is unreadable as text — this is not the installed artifact",
                a.dest
            ));
            continue;
        };
        match check_shape(a.dest, &content) {
            ShapeVerdict::Sound(m) => messages.push(m),
            ShapeVerdict::Unprovable(m) => {
                unprovable += 1;
                messages.push(m);
            }
            ShapeVerdict::Broken(m) => {
                broken += 1;
                messages.push(format!(
                    "{m} — run `sscsb init` after deleting it to regenerate"
                ));
            }
        }
    }
    let outcome = if broken > 0 {
        Outcome::Fail
    } else if unprovable > 0 {
        Outcome::Degraded
    } else {
        Outcome::Pass
    };
    // Evidence is reported only for a verdict that rests on it: a FAIL points
    // the consumer at the registered artifact that is missing, never at a
    // file that did not prove the control.
    let evidence = if outcome == Outcome::Fail {
        Vec::new()
    } else {
        evidence
    };
    VerifyResult::new(control, outcome, messages).with_evidence(evidence)
}

/// Harden-Runner is verified across EVERY installed workflow, one JOB at a time.
///
/// The predecessor asked `content.contains("step-security/harden-runner@")` of
/// each file's raw text, which answered a different question than the one the
/// control claims. Three ways that passed a repo that was not protected:
/// a `#`-commented-out reference still matched; one hardened job vouched for
/// every OTHER job in the same file; and an existing-but-empty
/// `.github/workflows/` directory examined nothing and reported Pass. The check
/// now parses each workflow and asks [`crate::audit::harden_runner_status`] the
/// per-job question, and anything it could not read, parse, or find jobs in is
/// reported as unverified rather than silently counted either way.
fn verify_harden_runner(ctx: &Ctx) -> VerifyResult {
    let dir = ctx.root.join(".github").join("workflows");
    if !dir.is_dir() {
        return VerifyResult::new(
            "harden-runner",
            Outcome::Degraded,
            vec!["no workflows installed yet — run `sscsb init`".into()],
        );
    }
    let mut messages = Vec::new();
    let mut missing = 0usize;
    let mut workflows = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        workflows += 1;
        let Ok(content) = std::fs::read_to_string(&path) else {
            missing += 1;
            messages.push(format!(
                "{name}: unreadable as text — harden-runner could not be verified"
            ));
            continue;
        };
        let jobs = match crate::audit::harden_runner_status(&content) {
            Ok(jobs) => jobs,
            Err(err) => {
                missing += 1;
                messages.push(format!(
                    "{name}: could not be parsed ({err:#}) — harden-runner is unverified, \
                     not confirmed"
                ));
                continue;
            }
        };
        if jobs.is_empty() {
            missing += 1;
            messages.push(format!(
                "{name}: declares no jobs — nothing runs here and nothing was verified"
            ));
            continue;
        }
        for (job, status) in jobs {
            match status {
                crate::audit::HardenRunner::Present => {
                    messages.push(format!("{name}: harden-runner present in job `{job}`"))
                }
                // Kept deliberately: a job that only calls a reusable workflow
                // has no step list to head, so hardening belongs to the callee
                // (for slsa-github-generator, the trusted builder does it).
                crate::audit::HardenRunner::Reusable(calls) => messages.push(format!(
                    "{name}: reusable-workflow only — job `{job}` calls `{calls}`, where \
                     harden-runner is the called workflow's concern"
                )),
                crate::audit::HardenRunner::Absent => {
                    missing += 1;
                    messages.push(format!(
                        "{name}: MISSING harden-runner in job `{job}` — that job's egress and \
                         file tampering are unmonitored"
                    ));
                }
            }
        }
    }
    if workflows == 0 {
        messages.push(
            ".github/workflows/ holds no workflow files — zero jobs were examined, so \
             harden-runner coverage is unverified, not confirmed"
                .into(),
        );
        return VerifyResult::new("harden-runner", Outcome::Degraded, messages);
    }
    let outcome = if missing == 0 {
        Outcome::Pass
    } else {
        Outcome::Fail
    };
    VerifyResult::new("harden-runner", outcome, messages)
}

pub fn verify_pr_template(ctx: &Ctx) -> VerifyResult {
    let path = ctx.root.join(".github").join("PULL_REQUEST_TEMPLATE.md");
    if !path.is_file() {
        return VerifyResult::new(
            "pr-template",
            Outcome::Fail,
            vec![".github/PULL_REQUEST_TEMPLATE.md missing — run `sscsb init`".into()],
        );
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let has_ai_questions = content.contains("AI generated or assisted with **code**")
        && content.contains("new dependencies");
    if has_ai_questions {
        VerifyResult::new(
            "pr-template",
            Outcome::Pass,
            vec!["AI-provenance PR template installed (code/tests/deps/docs questions)".into()],
        )
    } else {
        VerifyResult::new(
            "pr-template",
            Outcome::Fail,
            vec!["PR template exists but lacks the AI-provenance questions".into()],
        )
    }
}

/// Also expose the templates dir installer for non-artifact extras.
pub fn write_if_absent(root: &Path, rel: &str, content: &str) -> Result<bool> {
    let dest = root.join(rel);
    if dest.exists() {
        return Ok(false);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&dest, content)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{audit_workflow, Severity};
    use crate::context::Ctx;

    /// Throwaway repo bootstrapped through the real `sscsb init` path —
    /// mirrors the pattern in `tests/library.rs` so template-control tests
    /// run against the same layout a user gets.
    fn repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        crate::exec::git(&["init", "-b", "main"], root).unwrap();
        crate::exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        crate::exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).expect("discover");
        (dir, ctx)
    }

    fn rendered_workflows() -> Vec<(&'static str, String)> {
        ARTIFACTS
            .iter()
            .filter(|a| a.dest.starts_with(".github/workflows/"))
            .map(|a| (a.dest, render(a.content, "owner/repo", "main")))
            .collect()
    }

    /// ∀ workflow templates: zero audit ERRORS (SHA-pinning + permissions) —
    /// including the extended checks. The one sanctioned tag pin
    /// (slsa-github-generator) surfaces as Info, not Error.
    #[test]
    fn every_workflow_template_passes_own_audit() {
        for (dest, content) in rendered_workflows() {
            let findings = audit_workflow(dest, &content, true)
                .unwrap_or_else(|e| panic!("{dest} failed to parse: {e:#}"));
            let bad: Vec<_> = findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .collect();
            assert!(bad.is_empty(), "{dest} fails sscsb's own audit: {bad:?}");
        }
    }

    /// ∀ workflow templates: every job with its own steps starts with
    /// Harden-Runner (reusable-workflow jobs are the trusted builder's concern).
    #[test]
    fn every_workflow_template_embeds_harden_runner() {
        for (dest, content) in rendered_workflows() {
            assert!(
                content.contains(
                    "step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920"
                ),
                "{dest} lacks the pinned harden-runner step"
            );
        }
    }

    /// ∀ templates: no unrendered placeholders survive rendering.
    #[test]
    fn rendering_leaves_no_placeholders() {
        for a in ARTIFACTS {
            let rendered = render(a.content, "owner/repo", "main");
            assert!(
                !rendered.contains("{{repo_slug}}") && !rendered.contains("{{default_branch}}"),
                "{} has unrendered placeholders",
                a.dest
            );
        }
    }

    /// ∀ templates: no real identities/secrets baked in — placeholders only.
    #[test]
    fn templates_carry_no_baked_in_identities() {
        for a in ARTIFACTS {
            assert!(
                !a.content.contains("/Users/") && !a.content.contains("/home/"),
                "{} contains a hardcoded home path",
                a.dest
            );
        }
    }

    #[test]
    fn every_artifact_control_is_registered() {
        for a in ARTIFACTS {
            assert!(
                crate::controls::control(a.control).is_some(),
                "artifact {} references unknown control {}",
                a.dest,
                a.control
            );
        }
    }

    #[test]
    fn renovate_template_is_valid_json_after_comment_strip() {
        let a = ARTIFACTS
            .iter()
            .find(|a| a.dest == "renovate.json5")
            .unwrap();
        let stripped: String = a
            .content
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let v: serde_json::Value = serde_json::from_str(&stripped).expect("renovate config parses");
        assert!(v["extends"].as_array().is_some());
        assert_eq!(v["osvVulnerabilityAlerts"], serde_json::Value::Bool(true));
    }

    #[test]
    fn verify_template_control_reports_bug_for_control_with_no_artifacts() {
        let (_d, ctx) = repo();
        // "witness" is a real control but owns no ARTIFACTS entries — calling
        // the generic template verifier for it is the defensive "this is a
        // bug" branch, not a real dispatch (controls.rs routes witness
        // elsewhere), but the function must still handle it safely.
        let result = verify_template_control(&ctx, "witness");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("no artifacts registered for `witness`"));
    }

    #[test]
    fn verify_template_control_reports_missing_artifacts_and_fails() {
        let (_d, ctx) = repo();
        // Every enabled control's artifacts are installed by bootstrap;
        // delete one to simulate an incomplete/corrupted install.
        std::fs::remove_file(ctx.root.join(".github/workflows/scorecard.yml")).unwrap();
        let result = verify_template_control(&ctx, "scorecard");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains(".github/workflows/scorecard.yml MISSING")));
    }

    // ─────────────────── artifact shape checks (H1) ────────────────────────

    /// ∀ registered artifacts: the template sscsb SHIPS satisfies the
    /// structural check sscsb APPLIES. This is the guard against the fix's own
    /// worst failure mode — a check strict enough to fail every real repo the
    /// moment `sscsb init` writes the file.
    #[test]
    fn every_artifact_template_satisfies_its_own_shape_check() {
        for a in ARTIFACTS {
            let rendered = render(a.content, "owner/repo", "main");
            match check_shape(a.dest, &rendered) {
                ShapeVerdict::Sound(_) => {}
                ShapeVerdict::Unprovable(m) => {
                    panic!("shipped template {} is not verifiable: {m}", a.dest)
                }
                ShapeVerdict::Broken(m) => panic!("shipped template {} is broken: {m}", a.dest),
            }
        }
    }

    /// Every control routed through `verify_template_control` must be green on
    /// a freshly bootstrapped repo. A false FAIL here lands on every user.
    #[test]
    fn every_template_control_passes_on_a_freshly_bootstrapped_repo() {
        let (_d, ctx) = repo();
        let cfg = ctx.require_config().unwrap();
        let mut checked = 0;
        for a in ARTIFACTS {
            let def = crate::controls::control(a.control).expect("registry");
            if !cfg
                .control_enabled(a.control)
                .unwrap_or(def.default_enabled)
            {
                continue;
            }
            if a.control == "harden-runner" {
                continue;
            }
            let result = verify_template_control(&ctx, def.id);
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "control `{}` regressed on a clean install: {:?}",
                def.id,
                result.messages
            );
            checked += 1;
        }
        assert!(checked > 10, "expected to cover the template controls");
    }

    /// H1: gutting a workflow to a single comment left the control PASSing,
    /// because the verifier only asked whether a file existed at the path.
    #[test]
    fn a_gutted_workflow_fails_its_template_control() {
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(".github/workflows/codeql.yml"), "# gutted\n").unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(
            result.outcome,
            Outcome::Fail,
            "a workflow that runs nothing must not verify: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("contains no YAML document")),
            "{:?}",
            result.messages
        );
    }

    /// The floor that applies to every artifact kind, checked on the one kind
    /// that has no structure beyond it: a prose worksheet.
    #[test]
    fn a_zero_byte_artifact_fails_its_template_control() {
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(".sscsb/osps-baseline.md"), "").unwrap();
        let result = verify_template_control(&ctx, "osps-baseline");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.messages[0].contains("is EMPTY"));

        // Whitespace-only is the same emptiness wearing a disguise.
        std::fs::write(ctx.root.join(".sscsb/osps-baseline.md"), "  \n\n\t\n").unwrap();
        assert_eq!(
            verify_template_control(&ctx, "osps-baseline").outcome,
            Outcome::Fail
        );
    }

    /// A workflow can parse, declare jobs, and still run nothing.
    #[test]
    fn a_workflow_whose_jobs_run_nothing_fails() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            "name: codeql\non: push\njobs:\n  analyze:\n    runs-on: ubuntu-latest\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("declare neither `steps:` nor `uses:`")));

        // ...and an empty `jobs:` mapping.
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            "name: codeql\non: push\njobs:\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("declares no `jobs:`")));
    }

    #[test]
    fn an_unparseable_workflow_fails_its_template_control() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            "name: codeql\n  bad: [unclosed\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.messages[0].contains("NOT valid YAML"));
    }

    /// A non-UTF-8 blob at a template destination is not the artifact.
    #[test]
    fn a_binary_blob_at_an_artifact_path_fails() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/codeql.yml"),
            [0xff_u8, 0xfe, 0x00, 0x01],
        )
        .unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("unreadable as text"));
    }

    /// Non-workflow YAML (octo-sts trust policy) gets the mapping check.
    #[test]
    fn a_gutted_yaml_config_fails_its_template_control() {
        let (_d, ctx) = repo();
        let dest = ctx
            .root
            .join(".github/chainguard/sscsb-automation.sts.yaml");
        std::fs::write(&dest, "# gutted\n").unwrap();
        let result = verify_template_control(&ctx, "octo-sts");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("holds no YAML mapping")));

        std::fs::write(&dest, "- just\n- a\n- list\n").unwrap();
        assert_eq!(
            verify_template_control(&ctx, "octo-sts").outcome,
            Outcome::Fail
        );
    }

    #[test]
    fn a_gutted_json_config_fails_its_template_control() {
        let (_d, ctx) = repo();
        let dest = ctx.root.join("renovate.json5");
        std::fs::write(&dest, "// gutted\n").unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.messages[0].contains("empty once comments are stripped"));

        std::fs::write(&dest, "{}\n").unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("empty object"));

        std::fs::write(&dest, "[1, 2]\n").unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("not a JSON object"));
    }

    /// JSON5 is a superset of JSON. A file sscsb's stripper cannot parse is
    /// sscsb's limitation, not proof the config is broken — so it degrades
    /// (which `verify --strict` still refuses) instead of failing a
    /// legitimate hand-written renovate config.
    #[test]
    fn json5_beyond_the_parseable_subset_degrades_rather_than_failing() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join("renovate.json5"),
            "{\n  extends: ['config:recommended'],\n}\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "renovate");
        assert_eq!(result.outcome, Outcome::Degraded, "{:?}", result.messages);
        assert!(result.messages[0].contains("could not parse it as comment-stripped JSON"));
    }

    #[test]
    fn shape_of_routes_each_artifact_kind() {
        assert_eq!(
            shape_of(".github/workflows/codeql.yml"),
            Shape::Workflow,
            "workflows are the strongest-checked kind"
        );
        assert_eq!(shape_of("security-insights.yml"), Shape::Yaml);
        assert_eq!(
            shape_of(".github/chainguard/sscsb-automation.sts.yaml"),
            Shape::Yaml
        );
        assert_eq!(shape_of("renovate.json5"), Shape::Json);
        assert_eq!(shape_of("deps.json"), Shape::Json);
        assert_eq!(shape_of(".gitleaks.toml"), Shape::Toml);
        assert_eq!(shape_of(".sscsb/osps-baseline.md"), Shape::Opaque);
        assert_eq!(shape_of(".clusterfuzzlite/Dockerfile"), Shape::Opaque);
        assert_eq!(shape_of(".trivyignore"), Shape::Opaque);
    }

    #[test]
    fn toml_configs_are_checked_for_a_non_empty_table() {
        match check_shape(".gitleaks.toml", "[extend]\nuseDefault = true\n") {
            ShapeVerdict::Sound(m) => assert!(m.contains("1 key(s)")),
            other => panic!("expected sound: {}", verdict_text(&other)),
        }
        match check_shape(".gitleaks.toml", "# only a comment\n") {
            ShapeVerdict::Broken(m) => assert!(m.contains("holds no TOML table")),
            other => panic!("expected broken: {}", verdict_text(&other)),
        }
        match check_shape(".gitleaks.toml", "not = [valid toml\n") {
            ShapeVerdict::Broken(m) => assert!(m.contains("NOT valid TOML")),
            other => panic!("expected broken: {}", verdict_text(&other)),
        }
    }

    /// An opaque artifact that survives the emptiness floor is reported as
    /// checked-for-presence-only, never as verified.
    #[test]
    fn opaque_artifacts_report_the_limit_of_what_was_checked() {
        match check_shape(".sscsb/osps-baseline.md", "# filled in by a human\n") {
            ShapeVerdict::Sound(m) => {
                assert!(m.contains("no machine-checkable structure"), "{m}");
                assert!(m.contains("human judgement"), "{m}");
            }
            other => panic!("expected sound: {}", verdict_text(&other)),
        }
    }

    fn verdict_text(v: &ShapeVerdict) -> &str {
        match v {
            ShapeVerdict::Sound(m) | ShapeVerdict::Unprovable(m) | ShapeVerdict::Broken(m) => m,
        }
    }

    #[test]
    fn harden_runner_check_covers_present_missing_and_reusable_workflow_cases() {
        let (_d, ctx) = repo();
        // A non-workflow file in the directory must be skipped, not misread.
        std::fs::write(
            ctx.root.join(".github/workflows/README.md"),
            "not a workflow\n",
        )
        .unwrap();
        // A workflow that never adopted harden-runner.
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        )
        .unwrap();
        // A reusable-workflow-only caller: harden-runner runs inside the
        // trusted builder, not in this file, so it must not be flagged.
        std::fs::write(
            ctx.root.join(".github/workflows/reusable-only.yml"),
            "name: reusable-only\non: push\npermissions:\n  contents: read\njobs:\n  provenance:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0\n    with:\n      base64-subjects: \"abc\"\n",
        )
        .unwrap();

        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("custom.yml: MISSING harden-runner")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("reusable-only.yml: reusable-workflow only")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("harden-runner present")));
        assert!(
            !result.messages.iter().any(|m| m.contains("README.md")),
            "non-workflow files must be skipped entirely: {:?}",
            result.messages
        );
    }

    /// M1: the check was a substring search over the file's TEXT, so a
    /// commented-out reference — the exact thing a developer leaves behind when
    /// they rip harden-runner out — satisfied it.
    #[test]
    fn a_commented_out_harden_runner_reference_does_not_satisfy_the_control() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\non: push\npermissions:\n  contents: read\njobs:\n  b:\n    \
             runs-on: ubuntu-latest\n    steps:\n      \
             # - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n      \
             - run: echo hi\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(
            result.outcome,
            Outcome::Fail,
            "a comment monitors no egress: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("custom.yml: MISSING harden-runner")),
            "{:?}",
            result.messages
        );
    }

    /// M1: harden-runner protects the JOB it starts, not the file it appears
    /// in. One hardened job used to vouch for every other job in the workflow.
    #[test]
    fn harden_runner_is_checked_per_job_not_per_file() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\non: push\npermissions:\n  contents: read\njobs:\n  \
             hardened:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920\n        \
             with:\n          egress-policy: audit\n      - run: echo hi\n  \
             unhardened:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl evil.example\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(
            result.outcome,
            Outcome::Fail,
            "the second job runs unmonitored: {:?}",
            result.messages
        );
        assert!(
            result.messages.iter().any(
                |m| m.contains("custom.yml: MISSING harden-runner") && m.contains("unhardened")
            ),
            "the unprotected job must be named: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("custom.yml: harden-runner present") && m.contains("hardened")),
            "{:?}",
            result.messages
        );
    }

    /// M1: an existing-but-empty workflow directory verified NOTHING, and
    /// reported that as a pass with no messages at all.
    #[test]
    fn harden_runner_degrades_when_the_workflow_directory_holds_no_workflows() {
        let (_d, ctx) = repo();
        let dir = ctx.root.join(".github/workflows");
        for entry in std::fs::read_dir(&dir).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        // A non-workflow file in the directory is not a workflow either.
        std::fs::write(dir.join("README.md"), "not a workflow\n").unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(
            result.outcome,
            Outcome::Degraded,
            "zero workflows examined is not a pass: {:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("no workflow files")),
            "{:?}",
            result.messages
        );
    }

    /// A non-UTF-8 blob sitting at a `.yml` path in the workflow directory is
    /// not a workflow sscsb read — so it is unverified, not protected.
    #[test]
    fn harden_runner_reports_a_workflow_it_could_not_read_as_text() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/blob.yml"),
            [0xff_u8, 0xfe, 0x00, 0x01],
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("blob.yml") && m.contains("unreadable as text")),
            "{:?}",
            result.messages
        );
    }

    /// A workflow sscsb cannot parse, or one that declares no jobs, proves
    /// nothing about harden-runner — and must not be reported as protected.
    #[test]
    fn harden_runner_reports_workflows_it_could_not_check() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/broken.yml"),
            "name: broken\n  bad: [unclosed\n",
        )
        .unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/jobless.yml"),
            "name: jobless\non: push\npermissions:\n  contents: read\n",
        )
        .unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("broken.yml") && m.contains("could not be parsed")),
            "{:?}",
            result.messages
        );
        assert!(
            result
                .messages
                .iter()
                .any(|m| m.contains("jobless.yml") && m.contains("declares no jobs")),
            "{:?}",
            result.messages
        );
    }

    #[test]
    fn harden_runner_check_degrades_when_no_workflows_installed() {
        let (_d, ctx) = repo();
        std::fs::remove_dir_all(ctx.root.join(".github/workflows")).unwrap();
        let result = verify_template_control(&ctx, "harden-runner");
        assert_eq!(result.outcome, Outcome::Degraded);
        assert!(result.messages[0].contains("no workflows installed yet"));
    }

    #[test]
    fn pr_template_check_reports_missing_file() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/PULL_REQUEST_TEMPLATE.md")).unwrap();
        let result = verify_pr_template(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("missing — run `sscsb init`"));
    }

    #[test]
    fn pr_template_check_flags_template_missing_ai_provenance_questions() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/PULL_REQUEST_TEMPLATE.md"),
            "# Pull Request\n\nDescribe your change.\n",
        )
        .unwrap();
        let result = verify_pr_template(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result.messages[0].contains("lacks the AI-provenance questions"));
    }

    #[test]
    fn write_if_absent_creates_parent_dirs_and_skips_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let created = write_if_absent(dir.path(), "nested/dir/file.txt", "hello\n").unwrap();
        assert!(created);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("nested/dir/file.txt")).unwrap(),
            "hello\n"
        );

        let skipped = write_if_absent(dir.path(), "nested/dir/file.txt", "changed\n").unwrap();
        assert!(!skipped);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("nested/dir/file.txt")).unwrap(),
            "hello\n",
            "existing file must never be overwritten"
        );
    }

    #[test]
    fn install_all_skips_disabled_controls_and_keeps_existing_files() {
        let (_d, ctx) = repo();
        // Bootstrap already installed everything once; re-running install_all
        // must "keep" every existing artifact rather than overwrite it.
        let cfg = ctx.require_config().unwrap();
        let second = install_all(&ctx, cfg).unwrap();
        assert!(second
            .iter()
            .all(|l| l.starts_with("keep") || l.starts_with("skip")));
        assert!(second
            .iter()
            .any(|l| l.contains("keep .github/workflows/scorecard.yml")));

        // Disable a control and delete its artifact, then confirm install_all
        // skips reinstalling it — the modularity contract.
        crate::config::set_control_enabled(&ctx.config_path(), "renovate", false).unwrap();
        std::fs::remove_file(ctx.root.join("renovate.json5")).unwrap();
        let ctx2 = Ctx::discover(&ctx.root).unwrap();
        let cfg2 = ctx2.require_config().unwrap();
        let third = install_all(&ctx2, cfg2).unwrap();
        assert!(third
            .iter()
            .any(|l| l.contains("skip renovate.json5 (control renovate disabled)")));
        assert!(!ctx2.root.join("renovate.json5").exists());
    }

    #[test]
    fn slsa_template_is_tag_pinned_and_documented() {
        let a = ARTIFACTS
            .iter()
            .find(|a| a.dest == ".github/workflows/release-slsa.yml")
            .unwrap();
        assert!(a.content.contains(
            "slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
        ));
        assert!(a.content.contains("PINNING EXCEPTION"));
    }

    // ───────────────── consolidated provenance evidence ────────────────────

    use crate::testutil::{
        cosign_sign_steps, release_workflow, signed_release_workflow, ATTEST_BUILD_PROVENANCE_SHA,
        ATTEST_SHA, COSIGN_INSTALLER_SHA, COSIGN_SIGN_BUNDLED, RELEASE_JOB_PERMISSIONS,
    };

    const RELEASE: &str = ".github/workflows/release.yml";

    /// Commit `rel` as it is on disk: only content at HEAD is evidence, so a
    /// fixture that merely writes (or `git add`s) the file has not put it in
    /// the repository the recognizer reads.
    fn commit(ctx: &Ctx, rel: &str) {
        crate::exec::git(&["add", "--", rel], &ctx.root).unwrap();
        crate::exec::git(
            &["commit", "-q", "-m", &format!("test: {rel}"), "--no-verify"],
            &ctx.root,
        )
        .unwrap();
    }

    /// A bootstrapped repo with `control`'s modular artifact deleted and a
    /// COMMITTED `release.yml` written from `body` — the consolidated shape.
    fn consolidated_repo(control: &str, body: &str) -> (tempfile::TempDir, Ctx) {
        let (d, ctx) = repo();
        for a in artifacts_for(control) {
            std::fs::remove_file(ctx.root.join(a.dest)).unwrap();
        }
        std::fs::write(ctx.root.join(RELEASE), body).unwrap();
        commit(&ctx, RELEASE);
        (d, ctx)
    }

    fn assert_message(result: &VerifyResult, needle: &str) {
        assert!(
            result.messages.iter().any(|m| m.contains(needle)),
            "expected a message containing {needle:?}, got {:?}",
            result.messages
        );
    }

    fn assert_no_message(result: &VerifyResult, needle: &str) {
        assert!(
            !result.messages.iter().any(|m| m.contains(needle)),
            "did not expect a message containing {needle:?}, got {:?}",
            result.messages
        );
    }

    /// The claim this whole feature exists for: a repository that signs inside
    /// its immutable-release workflow, with no `release-sign.yml`, is doing the
    /// control — and the verdict names the file it actually examined.
    #[test]
    fn sigstore_signing_is_proven_by_a_consolidated_release_workflow() {
        let (_d, ctx) = consolidated_repo("sigstore-signing", &signed_release_workflow());
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_message(
            &result,
            "release-sign.yml not installed — verified by consolidated evidence in \
             .github/workflows/release.yml",
        );
        assert_message(
            &result,
            "release.yml job `release`: keyless-signs with `cosign sign-blob --bundle` via \
             `sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6` under \
             `id-token: write`",
        );
    }

    /// The bootstrapped repo already carries `deploy-gate.yml`, which installs
    /// cosign and runs `cosign verify-blob`. Verification is not signing: with
    /// no workflow that SIGNS, the control is missing and says so.
    #[test]
    fn sigstore_signing_fails_when_no_committed_workflow_signs() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        assert!(
            std::fs::read_to_string(ctx.root.join(".github/workflows/deploy-gate.yml"))
                .unwrap()
                .contains("cosign verify-blob"),
            "fixture premise: deploy-gate verifies with cosign"
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release-sign.yml MISSING — run `sscsb init`; no committed (HEAD) workflow under \
             .github/workflows/ carries a `cosign sign-blob --bundle` step",
        );
    }

    #[test]
    fn an_unpinned_cosign_installer_fails_and_names_the_ref() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &cosign_sign_steps("v4", COSIGN_SIGN_BUNDLED),
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(
            result.evidence.is_empty(),
            "a FAIL rests on no evidence file"
        );
        assert_message(
            &result,
            "release.yml job `release`: `sigstore/cosign-installer@v4` is pinned to `@v4`, \
             not a 40-hex commit SHA — the step is present but its action is mutable",
        );
        assert_message(
            &result,
            "release-sign.yml MISSING, and the consolidated implementation found in its \
             place does not meet the bar",
        );
    }

    #[test]
    fn signing_in_a_job_without_id_token_write_fails() {
        // Job-level `permissions:` REPLACES the workflow level, so a job that
        // declares only `contents: write` has no id-token even if the top
        // level had granted one.
        let body = release_workflow(
            "      contents: write",
            &cosign_sign_steps(COSIGN_INSTALLER_SHA, COSIGN_SIGN_BUNDLED),
        )
        .replace(
            "permissions:\n  contents: read",
            "permissions:\n  id-token: write",
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "`cosign sign-blob` runs in a job not granted `id-token: write` — the effective \
             `permissions:` (job level, else workflow level) do not include it; keyless \
             signing cannot obtain a Fulcio certificate without it",
        );
    }

    #[test]
    fn signing_without_a_bundle_fails() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &cosign_sign_steps(COSIGN_INSTALLER_SHA, "cosign sign-blob \"$f\" --yes"),
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "`cosign sign` runs without `--bundle` on the same command line — no Sigstore \
             bundle (certificate + signature + Rekor proof) is produced",
        );
    }

    #[test]
    fn signing_without_a_pinned_installer_step_fails() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            "      - run: |\n          for f in dist/*; do\n            cosign sign-blob \"$f\" \
             --bundle \"$f.sigstore.json\" --yes\n          done",
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "invokes cosign but no `sigstore/cosign-installer` step installs it in job \
             `release`",
        );
    }

    /// The `run:` body is shell; a commented-out signing command signs nothing.
    #[test]
    fn a_commented_out_cosign_invocation_is_not_signing() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &format!(
                "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
                 \x20     - run: |\n\
                 \x20         # cosign sign-blob \"$f\" --bundle \"$f.sigstore.json\" --yes\n\
                 \x20         echo signing disabled"
            ),
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "no committed (HEAD) workflow under .github/workflows/ carries",
        );
    }

    /// Consolidated evidence exists to answer "the modular file is ABSENT";
    /// it must never excuse a modular file that is present and broken, even
    /// when a perfectly good `release.yml` sits beside it.
    #[test]
    fn a_broken_modular_artifact_is_never_rescued_by_consolidated_evidence() {
        let (_d, ctx) = repo();
        std::fs::write(
            ctx.root.join(".github/workflows/release-sign.yml"),
            "# gutted\n",
        )
        .unwrap();
        std::fs::write(ctx.root.join(RELEASE), signed_release_workflow()).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, "release-sign.yml contains no YAML document");
        assert_no_message(&result, "consolidated evidence");
    }

    /// A file that is not a sound workflow cannot be evidence, whatever its
    /// steps say — GitHub will refuse to run it.
    #[test]
    fn a_consolidated_workflow_that_is_not_sound_cannot_serve_as_evidence() {
        let body = format!(
            "{}  inert:\n    runs-on: ubuntu-latest\n",
            signed_release_workflow()
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml: job(s) inert declare neither `steps:` nor `uses:` — they run \
             NOTHING — it carries a `cosign sign-blob --bundle` step",
        );
        assert_message(&result, "but cannot serve as evidence");
    }

    /// One job that meets the bar proves the control; a defective sibling is
    /// still reported so the pass does not hide it.
    #[test]
    fn a_proven_job_passes_and_a_defective_sibling_job_is_still_reported() {
        let body = format!(
            "{}  legacy:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n\
             \x20   steps:\n{}\n",
            signed_release_workflow(),
            cosign_sign_steps("v4", COSIGN_SIGN_BUNDLED)
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_message(&result, "job `release`: keyless-signs");
        assert_message(
            &result,
            "job `legacy`: `sigstore/cosign-installer@v4` is pinned to `@v4`",
        );
    }

    /// "Absent" must never quietly mean "unparsed": a workflow sscsb could not
    /// read is named in the failure.
    #[test]
    fn workflows_that_could_not_be_examined_are_named_when_evidence_is_absent() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/custom.yml"),
            "name: custom\n  bad: [unclosed\n",
        )
        .unwrap();
        std::fs::write(
            ctx.root.join(".github/workflows/blob.yml"),
            [0xff_u8, 0xfe, 0x00, 0x01],
        )
        .unwrap();
        commit(&ctx, ".github/workflows/custom.yml");
        commit(&ctx, ".github/workflows/blob.yml");
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            ".github/workflows/custom.yml is not valid YAML and was not examined",
        );
        assert_message(
            &result,
            ".github/workflows/blob.yml is unreadable as text and was not examined",
        );
    }

    fn attest_build_provenance_step(r: &str, with: &str) -> String {
        format!("      - uses: actions/attest-build-provenance@{r}\n        with:\n{with}")
    }

    #[test]
    fn github_attestations_are_proven_by_a_consolidated_release_workflow() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &attest_build_provenance_step(
                ATTEST_BUILD_PROVENANCE_SHA,
                "          subject-path: dist/*.tar.gz",
            ),
        );
        let (_d, ctx) = consolidated_repo("github-attestations", &body);
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_message(
            &result,
            "release.yml job `release`: attests build provenance to GitHub's attestation \
             store with `actions/attest-build-provenance@\
             0f67c3f4856b2e3261c31976d6725780e5e4c373` under `attestations: write` + \
             `id-token: write`",
        );
    }

    #[test]
    fn github_attestations_fail_without_a_subject_an_unpinned_ref_or_attestations_write() {
        // No subject: provenance bound to nothing.
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &attest_build_provenance_step(
                ATTEST_BUILD_PROVENANCE_SHA,
                "          push-to-registry: false",
            ),
        );
        let (_d, ctx) = consolidated_repo("github-attestations", &body);
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "names no subject (`subject-path`, `subject-digest` or `subject-checksums`) — \
             provenance not bound to any artifact digest",
        );

        // Unpinned: the ref is named.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &attest_build_provenance_step("v4", "          subject-path: dist/*.tar.gz"),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "`actions/attest-build-provenance@v4` is pinned to `@v4`, not a 40-hex commit SHA",
        );

        // id-token without attestations: the store write is refused.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                "      id-token: write",
                &attest_build_provenance_step(
                    ATTEST_BUILD_PROVENANCE_SHA,
                    "          subject-path: dist/*.tar.gz",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "runs in a job not granted `attestations: write` — the effective `permissions:`",
        );
        assert_no_message(&result, "`attestations: write` + `id-token: write` —");
    }

    /// `write-all` is over-broad (actions-audit says so) but it does grant the
    /// scopes; a repo using it has implemented the control, not skipped it.
    #[test]
    fn workflow_level_write_all_is_inherited_by_a_job_that_declares_no_permissions() {
        let body = release_workflow(
            "",
            &attest_build_provenance_step(
                ATTEST_BUILD_PROVENANCE_SHA,
                "          subject-digest: sha256:abc",
            ),
        )
        .replace("permissions:\n  contents: read", "permissions: write-all")
        .replace("    permissions:\n\n", "");
        let (_d, ctx) = consolidated_repo("github-attestations", &body);
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    fn attest_step(action: &str, r: &str, with: &str) -> String {
        format!("      - uses: {action}@{r}\n        with:\n{with}")
    }

    #[test]
    fn sbom_attestation_is_proven_by_actions_attest_with_sbom_path() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &attest_step(
                "actions/attest",
                ATTEST_SHA,
                "          subject-path: dist/*.tar.gz\n          sbom-path: dist/sbom.cdx.json",
            ),
        );
        let (_d, ctx) = consolidated_repo("sbom-attestation", &body);
        let result = verify_template_control(&ctx, "sbom-attestation");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_message(
            &result,
            "attests the SBOM (`sbom-path`) to the artifact digest with \
             `actions/attest@a1948c3f048ba23858d222213b7c278aabede763` under \
             `attestations: write` + `id-token: write`",
        );

        // The deprecated-but-real `actions/attest-sbom` counts too.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &attest_step(
                    "actions/attest-sbom",
                    ATTEST_SHA,
                    "          subject-path: dist/*.tar.gz\n          sbom-path: dist/sbom.cdx.json",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sbom-attestation");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(&result, "`actions/attest-sbom@");
    }

    /// `actions/attest` without `sbom-path` is a generic attestation, and
    /// `actions/attest-build-provenance` is a different control entirely.
    #[test]
    fn sbom_attestation_fails_without_sbom_path_and_is_not_satisfied_by_build_provenance() {
        let body = release_workflow(
            RELEASE_JOB_PERMISSIONS,
            &attest_step(
                "actions/attest",
                ATTEST_SHA,
                "          subject-path: dist/*.tar.gz\n          predicate-type: https://example.test/p",
            ),
        );
        let (_d, ctx) = consolidated_repo("sbom-attestation", &body);
        let result = verify_template_control(&ctx, "sbom-attestation");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "has no `sbom-path` — nothing binds an SBOM to the artifact digest",
        );

        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &attest_build_provenance_step(
                    ATTEST_BUILD_PROVENANCE_SHA,
                    "          subject-path: dist/*.tar.gz",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sbom-attestation");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release-attest-sbom.yml MISSING — run `sscsb init`; no committed (HEAD) workflow",
        );

        // Unpinned attest: the ref is named.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &attest_step(
                    "actions/attest",
                    "v4",
                    "          sbom-path: dist/sbom.cdx.json",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sbom-attestation");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "`actions/attest@v4` is pinned to `@v4`, not a 40-hex commit SHA",
        );
    }

    fn slsa_workflow(r: &str, job_permissions: &str) -> String {
        format!(
            "name: Release\non:\n  release:\n    types: [published]\npermissions:\n  \
             contents: read\njobs:\n  provenance:\n    permissions:\n{job_permissions}\n\
             \x20   uses: slsa-framework/slsa-github-generator/.github/workflows/\
             generator_generic_slsa3.yml@{r}\n    with:\n      base64-subjects: \"abc\"\n"
        )
    }

    const SLSA_JOB_PERMISSIONS: &str =
        "      actions: read\n      id-token: write\n      contents: write";

    #[test]
    fn slsa_provenance_is_proven_by_a_tag_pinned_generic_generator_job() {
        let (_d, ctx) = consolidated_repo(
            "slsa-provenance",
            &slsa_workflow("v2.1.0", SLSA_JOB_PERMISSIONS),
        );
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_message(
            &result,
            "release.yml job `provenance`: generates SLSA L3 provenance via \
             `slsa-framework/slsa-github-generator/.github/workflows/\
             generator_generic_slsa3.yml@v2.1.0` under `actions: read` + `id-token: write` + \
             `contents: write`; fires on `release` (types filter not evaluated)",
        );
    }

    /// Gate (e): the generator's trust model identifies the builder by its
    /// tag ref — slsa-verifier validates that ref — so a SHA pin, the right
    /// answer for every other action, is the wrong one here and produces
    /// provenance nothing can verify. The shipped workflow headers say so;
    /// the recognizer now agrees with them.
    #[test]
    fn a_sha_pinned_generator_fails_naming_the_tag_requirement() {
        let sha = "5a775b367a56d5bd118a224a811bba288150a563";
        let (_d, ctx) =
            consolidated_repo("slsa-provenance", &slsa_workflow(sha, SLSA_JOB_PERMISSIONS));
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            &format!(
                "release.yml job `provenance`: `slsa-framework/slsa-github-generator/.github/\
                 workflows/generator_generic_slsa3.yml@{sha}` is pinned to the commit SHA \
                 `@{sha}` — slsa-verifier identifies the trusted builder by its `vX.Y.Z` tag \
                 ref and refuses a SHA-pinned generator, so the provenance it produces cannot \
                 be verified; pin it to a `vX.Y.Z` tag"
            ),
        );
        // Every other action still wants the SHA, and the helper says so.
        assert_eq!(
            pin_defect(&format!("actions/attest@{sha}")),
            None,
            "a SHA is the bar for every other action"
        );
    }

    /// Gate (e): only the generic generator is judged. The container
    /// generator (and the language builders) are different trusted builders
    /// with different subjects; a job calling one is named as out of scope,
    /// never quietly accepted as the control.
    #[test]
    fn a_container_generator_fails_with_the_narrowing_message() {
        let container = slsa_workflow("v2.1.0", SLSA_JOB_PERMISSIONS).replace(
            "generator_generic_slsa3.yml",
            "generator_container_slsa3.yml",
        );
        assert!(
            container.contains("generator_container_slsa3.yml"),
            "fixture premise"
        );
        let (_d, ctx) = consolidated_repo("slsa-provenance", &container);
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release.yml job `provenance`: `slsa-framework/slsa-github-generator/.github/\
             workflows/generator_container_slsa3.yml@v2.1.0` is not \
             `slsa-framework/slsa-github-generator/.github/workflows/\
             generator_generic_slsa3.yml` — only the generic generator, the one the templates \
             call, is judged; the container and language-builder workflows of \
             slsa-github-generator are out of scope and are not evidence",
        );
        assert_message(&result, "does not meet the bar");
        // The missing-evidence message names the same narrowing.
        assert!(
            Consolidated::SlsaProvenance.wanted().contains(
                "`generator_generic_slsa3.yml` reusable workflow (the generic generator only"
            ),
            "{}",
            Consolidated::SlsaProvenance.wanted()
        );
        // A job calling some unrelated reusable workflow is simply absent.
        assert!(!Consolidated::SlsaProvenance.is_candidate_action(
            "slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@v2.1.0"
        ));
        assert!(matches!(
            slsa_job_evidence(
                &Yaml::Null,
                &YamlLoader::load_from_str("uses: ./.github/workflows/deploy-gate.yml").unwrap()[0],
                "x"
            ),
            JobEvidence::Absent
        ));
    }

    #[test]
    fn slsa_provenance_fails_on_a_branch_ref_or_missing_contents_write() {
        let (_d, ctx) = consolidated_repo(
            "slsa-provenance",
            &slsa_workflow("main", SLSA_JOB_PERMISSIONS),
        );
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "generator_generic_slsa3.yml@main` ref `@main` is not a `vX.Y.Z` tag — the \
             generator's documented trust model, which slsa-verifier checks, identifies the \
             builder by its tag",
        );

        std::fs::write(
            ctx.root.join(RELEASE),
            slsa_workflow("v2.1.0", "      actions: read\n      id-token: write"),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "runs in a job not granted `contents: write` — the effective `permissions:` \
             (job level, else workflow level) do not include it; the generator cannot read \
             the run (actions), sign (id-token) or attach provenance (contents) without them",
        );
    }

    /// Gate (f): the generator reads the calling run's metadata, so
    /// `actions: read` is required; `read` OR `write` satisfies it, and so
    /// does a workflow-level `read-all` inherited by a job with no block.
    #[test]
    fn slsa_provenance_requires_actions_read_with_read_semantics() {
        let (_d, ctx) = consolidated_repo(
            "slsa-provenance",
            &slsa_workflow("v2.1.0", "      id-token: write\n      contents: write"),
        );
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(&result, "runs in a job not granted `actions: read`");

        // `actions: write` is a superset of read.
        std::fs::write(
            ctx.root.join(RELEASE),
            slsa_workflow(
                "v2.1.0",
                "      actions: write\n      id-token: write\n      contents: write",
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    // ───────────────────────── gaming probes ─────────────────────────────

    /// Gate (a): "committed" means committed at HEAD, not tracked. A
    /// `release.yml` that exists on disk, or was only `git add`ed to the
    /// index, or carries the signing step only as a working-tree edit, is
    /// not what a clone of the repository contains — so it proves nothing,
    /// and the verdict says which file was skipped and why.
    #[test]
    fn an_uncommitted_release_workflow_is_never_evidence() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        std::fs::write(ctx.root.join(RELEASE), signed_release_workflow()).unwrap();

        // On disk only: nothing is committed at all.
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, "release-sign.yml MISSING — run `sscsb init`");
        assert_message(
            &result,
            "HEAD could not be read (fatal: Not a valid object name HEAD) — no content is \
             committed, so no workflow under .github/workflows/ can be evidence",
        );
        assert_message(
            &result,
            "uncommitted workflow file(s) were not examined — only content committed at HEAD \
             is evidence: ",
        );
        assert_message(&result, ".github/workflows/release.yml");

        // Index only (`git add`, no commit): still not evidence.
        crate::exec::git(&["add", "--", RELEASE], &ctx.root).unwrap();
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, "no content is committed");

        // Committed WITHOUT the signing step, then the step added as a
        // working-tree edit: HEAD is what is examined, and the verdict says
        // the working tree differs from it.
        let unsigned = release_workflow("      contents: read", "      - run: echo build");
        std::fs::write(ctx.root.join(RELEASE), &unsigned).unwrap();
        commit(&ctx, RELEASE);
        std::fs::write(ctx.root.join(RELEASE), signed_release_workflow()).unwrap();
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, "release-sign.yml MISSING — run `sscsb init`");
        assert_message(
            &result,
            ".github/workflows/release.yml differs from HEAD in the working tree — only the \
             committed (HEAD) content was examined",
        );
        // ...and `git add` of that edit changes nothing.
        crate::exec::git(&["add", "--", RELEASE], &ctx.root).unwrap();
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);

        // Committing it — and nothing else — flips the verdict.
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_no_message(&result, "differs from HEAD");

        // A committed file deleted from the working tree is still what a
        // clone carries: examined, with the absence noted.
        std::fs::remove_file(ctx.root.join(RELEASE)).unwrap();
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(
            &result,
            ".github/workflows/release.yml is committed at HEAD but absent from the working \
             tree — the committed content was examined",
        );
    }

    /// Gate (a), the fallback: with no git repository to ask, the directory
    /// is read from disk and the verdict SAYS tracked-ness was not checked.
    #[test]
    fn outside_a_git_repository_the_directory_is_read_and_the_limit_is_stated() {
        let dir = tempfile::tempdir().unwrap();
        let wf = dir.path().join(".github/workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("release.yml"), signed_release_workflow()).unwrap();
        let ctx = Ctx {
            root: dir.path().to_path_buf(),
            platform: crate::platform::Platform::detect(),
            config: None,
        };
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(
            &result,
            "not inside a git repository — .github/workflows/ was read from disk and \
             committed-ness (tracked-ness) could NOT be established",
        );
    }

    /// Gate (b): a workflow only a human can start is a procedure, not a
    /// control. `workflow_dispatch`-only and `on:`-less both fail, naming
    /// what `on:` actually lists.
    #[test]
    fn a_manual_only_release_workflow_is_defective() {
        let dispatch_only = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on:\n  workflow_dispatch:\n",
        );
        assert!(
            dispatch_only.contains("workflow_dispatch"),
            "fixture premise"
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &dispatch_only);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release.yml: manual-only trigger — `on:` lists only `workflow_dispatch`, none of \
             push/release/schedule/pull_request/workflow_run — it carries a `cosign sign-blob \
             --bundle` step",
        );
        assert_message(&result, "but nothing runs it unattended");

        let no_on = signed_release_workflow().replace("on:\n  push:\n    tags: [\"v*\"]\n", "");
        assert!(!no_on.contains("\non:"), "fixture premise");
        std::fs::write(ctx.root.join(RELEASE), no_on).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml: manual-only trigger — `on:` is absent, none of",
        );

        // `on: [workflow_dispatch, push]` in list form is automatic again.
        let list_form = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on: [workflow_dispatch, push]\n",
        );
        std::fs::write(ctx.root.join(RELEASE), list_form).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(&result, "; fires on `push`");
        assert_no_message(&result, "not evaluated");
    }

    /// Gate (b), filters: sscsb has no glob engine and no ref to match, so a
    /// `push` carrying `branches:`/`tags:`/`paths:` filters is reported as
    /// "on `push` (… filter not evaluated)", never as "fires on push". The
    /// one filter it CAN judge is an empty `branches:`/`tags:` list, which
    /// matches nothing: that is a defect, named as such.
    #[test]
    fn trigger_filters_are_named_as_unevaluated_and_an_empty_ref_list_is_defective() {
        let (_d, ctx) = consolidated_repo("sigstore-signing", &signed_release_workflow());
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(&result, "; fires on `push` (tags filter not evaluated)");
        assert_no_message(&result, "fires on `push`;");

        // Several filters: all named, plural.
        let filtered = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on:\n  push:\n    branches: [main]\n    paths-ignore: [\"docs/**\"]\n",
        );
        std::fs::write(ctx.root.join(RELEASE), filtered).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(
            &result,
            "; fires on `push` (branches, paths-ignore filters not evaluated)",
        );

        // An empty `tags:` list matches no ref: the trigger never fires.
        for empty in ["tags: []", "tags:"] {
            let dead = signed_release_workflow().replace(
                "on:\n  push:\n    tags: [\"v*\"]\n",
                &format!("on:\n  push:\n    {empty}\n"),
            );
            assert!(dead.contains(empty), "fixture premise");
            std::fs::write(ctx.root.join(RELEASE), dead).unwrap();
            commit(&ctx, RELEASE);
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "`{empty}` must fail: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(
                &result,
                "release.yml: `on: push` has an empty `tags:` filter — it matches no ref, so \
                 the trigger never fires — it carries a `cosign sign-blob --bundle` step",
            );
        }

        // An empty `branches:` list, same verdict.
        let dead = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on:\n  push:\n    branches: []\n",
        );
        std::fs::write(ctx.root.join(RELEASE), dead).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(&result, "has an empty `branches:` filter");

        // A second, live automatic trigger beside the dead one still fires.
        let mixed = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on:\n  push:\n    tags: []\n  release:\n    types: [published]\n",
        );
        std::fs::write(ctx.root.join(RELEASE), mixed).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(&result, "; fires on `release`");
    }

    /// Gate (b), the reusable case: a `workflow_call` workflow fires only
    /// through its callers. It is evidence when a TRACKED, automatically
    /// triggered workflow calls it — not when nothing does, not when the
    /// caller is untracked, and not when the calling job is switched off.
    #[test]
    fn a_workflow_call_only_workflow_needs_an_automatic_tracked_caller() {
        let callee = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on:\n  workflow_call:\n",
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &callee);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml: manual-only trigger — `on:` has `workflow_call` but no committed \
             workflow with an automatic trigger (push/release/schedule/pull_request/\
             workflow_run) calls it via `uses: ./.github/workflows/release.yml`",
        );

        // An uncommitted caller does not count.
        let caller = ".github/workflows/tag.yml";
        // The calling job holds the scope the called signing job needs —
        // the short-caller case is its own test.
        let caller_body = |cond: &str| {
            format!(
                "name: Tag\non:\n  push:\n    tags: [\"v*\"]\npermissions:\n  contents: read\n\
                 jobs:\n  release:\n{cond}    permissions:\n      contents: read\n      \
                 id-token: write\n    uses: ./.github/workflows/release.yml\n"
            )
        };
        std::fs::write(ctx.root.join(caller), caller_body("")).unwrap();
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);

        // A committed caller whose calling job is `if: false` does not count.
        std::fs::write(ctx.root.join(caller), caller_body("    if: false\n")).unwrap();
        commit(&ctx, caller);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);

        // A committed, live, automatically triggered caller does — and its
        // `tags:` filter is named as unevaluated, never claimed as matched.
        std::fs::write(ctx.root.join(caller), caller_body("")).unwrap();
        commit(&ctx, caller);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
        assert_message(
            &result,
            "; fires via `.github/workflows/tag.yml` job `release` (on `push` (tags filter not \
             evaluated)), which calls it as a reusable workflow",
        );
    }

    fn call_only_release_workflow() -> String {
        let callee = signed_release_workflow().replace(
            "on:\n  push:\n    tags: [\"v*\"]\n",
            "on:\n  workflow_call:\n",
        );
        assert!(callee.contains("workflow_call"), "fixture premise");
        callee
    }

    const CALLER: &str = ".github/workflows/tag.yml";

    /// A sound, automatically triggered caller of `release.yml` whose job
    /// carries `job_permissions` (six-space-indented scopes, or empty for
    /// no block at all).
    fn caller_workflow(job_permissions: &str) -> String {
        let block = if job_permissions.is_empty() {
            String::new()
        } else {
            format!("    permissions:\n{job_permissions}\n")
        };
        format!(
            "name: Tag\non:\n  push:\n    tags: [\"v*\"]\npermissions:\n  contents: read\n\
             jobs:\n  release:\n{block}    uses: ./.github/workflows/release.yml\n"
        )
    }

    const CALLER_JOB_PERMISSIONS: &str = "      contents: read\n      id-token: write";

    /// Gate (b), the caller's own soundness: a caller GitHub would reject —
    /// a ghost `needs:`, two YAML documents — calls nothing, so it is not
    /// counted as a caller, and the verdict's notes say why it was skipped.
    #[test]
    fn a_broken_caller_is_not_counted_and_the_reason_is_noted() {
        let (_d, ctx) = consolidated_repo("sigstore-signing", &call_only_release_workflow());
        let sound = caller_workflow(CALLER_JOB_PERMISSIONS);

        // A ghost `needs:` in the caller.
        let ghost = sound.replace("  release:\n", "  release:\n    needs: build\n");
        assert!(ghost.contains("needs: build"), "fixture premise");
        std::fs::write(ctx.root.join(CALLER), ghost).unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            ".github/workflows/tag.yml: job `release` needs `build`, which is not a job in \
             this workflow — GitHub rejects the whole workflow — not counted as a caller of \
             .github/workflows/release.yml",
        );
        assert_message(
            &result,
            "release.yml: manual-only trigger — `on:` has `workflow_call` but no committed \
             workflow with an automatic trigger",
        );

        // Two YAML documents in the caller.
        std::fs::write(ctx.root.join(CALLER), format!("{sound}---\n{sound}")).unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            ".github/workflows/tag.yml holds 2 YAML documents — a GitHub Actions workflow \
             file is exactly one document, so GitHub cannot run it — not counted as a caller \
             of .github/workflows/release.yml",
        );

        // The sound caller, unchanged otherwise, is counted.
        std::fs::write(ctx.root.join(CALLER), &sound).unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_no_message(&result, "not counted as a caller");
    }

    /// Gate (b), the caller's `continue-on-error`: the calling job is the
    /// proving job's outer shell — when ITS failure does not fail the run,
    /// the called job's cannot either, however sound that job is. Treated
    /// exactly like `continue-on-error: true` on the proving job, and the
    /// defect names the caller and its job.
    #[test]
    fn a_caller_job_with_continue_on_error_is_defective() {
        let (_d, ctx) = consolidated_repo("sigstore-signing", &call_only_release_workflow());
        let sound = caller_workflow(CALLER_JOB_PERMISSIONS);
        let lenient = sound.replace("  release:\n", "  release:\n    continue-on-error: true\n");
        assert!(
            lenient.contains("continue-on-error: true"),
            "fixture premise"
        );
        std::fs::write(ctx.root.join(CALLER), lenient).unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release.yml: called from `.github/workflows/tag.yml` job `release` (on `push` \
             (tags filter not evaluated)), whose `continue-on-error: true` means a failed \
             call does not fail the run — the release proceeds without what this workflow \
             was to produce",
        );
        assert_no_message(&result, "manual-only trigger");

        // `continue-on-error: false` (and an expression, which is not
        // evaluated) leave the caller counted.
        for literal in ["false", "${{ github.event_name == 'push' }}"] {
            let strict = sound.replace(
                "  release:\n",
                &format!("  release:\n    continue-on-error: {literal}\n"),
            );
            std::fs::write(ctx.root.join(CALLER), strict).unwrap();
            commit(&ctx, CALLER);
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "`continue-on-error: {literal}` on the caller: {:?}",
                result.messages
            );
            assert_no_message(&result, "continue-on-error");
        }
    }

    /// Gate (b), the caller's grant: GitHub refuses a called workflow's job
    /// that asks for more than the calling job holds, so a caller whose
    /// effective `permissions:` lack a scope the proving job needs runs
    /// nothing — and the defect names the caller, its job, and the scope.
    #[test]
    fn a_caller_whose_grant_is_short_of_the_called_job_is_defective() {
        let (_d, ctx) = consolidated_repo("sigstore-signing", &call_only_release_workflow());
        let short = "release.yml: called from `.github/workflows/tag.yml` job `release` (on \
                     `push` (tags filter not evaluated)), whose effective `permissions:` (job \
                     level, else workflow level) do not grant `id-token: write` — GitHub \
                     refuses a called workflow's job that asks for more than its caller \
                     holds, so the call runs nothing";

        // A job-level block without `id-token: write`.
        std::fs::write(
            ctx.root.join(CALLER),
            caller_workflow("      contents: read"),
        )
        .unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, short);
        assert_no_message(&result, "manual-only trigger");

        // No job-level block: the caller's workflow-level `contents: read`
        // is what the job holds, and it is short too.
        std::fs::write(ctx.root.join(CALLER), caller_workflow("")).unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(&result, short);

        // The scope granted at the job level: counted.
        std::fs::write(
            ctx.root.join(CALLER),
            caller_workflow(CALLER_JOB_PERMISSIONS),
        )
        .unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(
            &result,
            "; fires via `.github/workflows/tag.yml` job `release` (on `push` (tags filter \
             not evaluated)), which calls it as a reusable workflow",
        );

        // `write-all` at the caller's workflow level, inherited: counted.
        std::fs::write(
            ctx.root.join(CALLER),
            caller_workflow("").replace(
                "permissions:\n  contents: read\n",
                "permissions: write-all\n",
            ),
        )
        .unwrap();
        commit(&ctx, CALLER);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    /// Gate (b), the other sub-keys: `types` and `workflows` are named as
    /// not evaluated like the ref and path filters; an empty `types:`, an
    /// empty `workflow_run.workflows:`, or a `schedule:` with no cron
    /// entries matches nothing, and fails.
    #[test]
    fn types_workflows_and_schedule_are_judged_only_when_empty() {
        let on = |trigger: &str| {
            let body =
                signed_release_workflow().replace("on:\n  push:\n    tags: [\"v*\"]\n", trigger);
            assert!(body.contains(trigger), "fixture premise");
            body
        };
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &on("on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n"),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(
            &result,
            "; fires on `workflow_run` (types, workflows filters not evaluated)",
        );

        for (trigger, defect) in [
            (
                "on:\n  release:\n    types: []\n",
                "release.yml: `on: release` has an empty `types:` filter — it matches no \
                 activity type, so the trigger never fires",
            ),
            (
                "on:\n  workflow_run:\n    workflows: []\n    types: [completed]\n",
                "release.yml: `on: workflow_run` has an empty `workflows:` filter — it names \
                 no workflow to run after, so the trigger never fires",
            ),
            (
                "on:\n  schedule: []\n",
                "release.yml: `on: schedule` lists no cron entries — nothing is scheduled, so \
                 the trigger never fires",
            ),
            (
                "on:\n  schedule:\n",
                "release.yml: `on: schedule` lists no cron entries — nothing is scheduled",
            ),
        ] {
            std::fs::write(ctx.root.join(RELEASE), on(trigger)).unwrap();
            commit(&ctx, RELEASE);
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "{trigger:?} must fail: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(&result, defect);
            assert_message(&result, "but nothing runs it unattended");
        }

        // A real cron entry fires.
        std::fs::write(
            ctx.root.join(RELEASE),
            on("on:\n  schedule:\n    - cron: \"0 4 * * 1\"\n"),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_message(&result, "; fires on `schedule`");
        assert_no_message(&result, "not evaluated");
    }

    /// Gate (g): a job-level `permissions: {}` — or a bare `permissions:` —
    /// is a declaration that grants nothing, not an omission that inherits
    /// the workflow level. A workflow-level `write-all` above it changes
    /// nothing.
    #[test]
    fn an_empty_job_level_permissions_block_grants_nothing() {
        for block in ["    permissions: {}\n", "    permissions:\n"] {
            let body = signed_release_workflow()
                .replace(
                    "permissions:\n  contents: read\n",
                    "permissions: write-all\n",
                )
                .replace(
                    &format!("    permissions:\n{RELEASE_JOB_PERMISSIONS}\n"),
                    block,
                );
            assert!(
                body.contains("permissions: write-all") && body.contains(block),
                "fixture premise: {body}"
            );
            let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "{block:?} must grant nothing: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(
                &result,
                "release.yml job `release`: `cosign sign-blob` runs in a job not granted \
                 `id-token: write` — the effective `permissions:` (job level, else workflow \
                 level) do not include it",
            );
        }
    }

    /// Gate (c): a constant-false `if:` on the proving job is the switch left
    /// off. Every spelling GitHub accepts for "never" is rejected.
    #[test]
    fn a_job_switched_off_with_a_constant_false_if_is_defective() {
        for literal in [
            "false",
            "'false'",
            "\"false\"",
            "${{ false }}",
            "${{false}}",
        ] {
            let body = signed_release_workflow().replace(
                "  release:\n    runs-on: ubuntu-latest\n",
                &format!("  release:\n    if: {literal}\n    runs-on: ubuntu-latest\n"),
            );
            assert!(body.contains(&format!("if: {literal}")), "fixture premise");
            let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "`if: {literal}` must fail: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(&result, "release.yml job `release`: job `if: ");
            assert_message(&result, "` is constant-false — the job never runs");
        }

        // A non-constant condition is NOT treated as false: the gate models
        // the switch left off, not the expression language.
        let body = signed_release_workflow().replace(
            "  release:\n    runs-on: ubuntu-latest\n",
            "  release:\n    if: startsWith(github.ref, 'refs/tags/')\n    runs-on: ubuntu-latest\n",
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    /// Gate (c) at step level: a signing step, an installer step or an
    /// attestation step that is `if: false` never runs, whatever the job does.
    #[test]
    fn a_proving_step_switched_off_with_a_constant_false_if_is_defective() {
        // The signing step.
        let steps = format!(
            "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
             \x20     - name: Sign\n\
             \x20       if: ${{{{ false }}}}\n\
             \x20       run: |\n\
             \x20         for f in dist/*; do\n\
             \x20           {COSIGN_SIGN_BUNDLED}\n\
             \x20         done"
        );
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(RELEASE_JOB_PERMISSIONS, &steps),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml job `release` step `Sign`: `if: ${{ false }}` is constant-false — \
             the signing step never runs",
        );

        // The installer step.
        let steps = format!(
            "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
             \x20       if: 'false'\n\
             \x20     - run: |\n\
             \x20         for f in dist/*; do\n\
             \x20           {COSIGN_SIGN_BUNDLED}\n\
             \x20         done"
        );
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(RELEASE_JOB_PERMISSIONS, &steps),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        // YAML strips the quotes: `'false'` reaches the parser as the string
        // `false`, and that is the literal the message quotes.
        assert_message(
            &result,
            "release.yml job `release` step #1: `if: false` is constant-false — cosign is \
             never installed",
        );

        // The attestation step.
        let (_d, ctx) = consolidated_repo(
            "github-attestations",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &format!(
                    "      - uses: actions/attest-build-provenance@{ATTEST_BUILD_PROVENANCE_SHA}\n\
                     \x20       if: false\n\
                     \x20       with:\n\
                     \x20         subject-path: dist/*.tar.gz"
                ),
            ),
        );
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml job `release` step #1: `if: false` is constant-false — the \
             attestation step never runs",
        );
    }

    /// Gate (d): the installer must PRECEDE the signing step — cosign installed
    /// afterwards signs nothing, and the step signed with whatever binary the
    /// runner happened to have.
    #[test]
    fn a_cosign_installer_after_the_signing_step_is_defective() {
        let steps = format!(
            "      - name: Sign\n\
             \x20       run: |\n\
             \x20         for f in dist/*; do\n\
             \x20           {COSIGN_SIGN_BUNDLED}\n\
             \x20         done\n\
             \x20     - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}"
        );
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(RELEASE_JOB_PERMISSIONS, &steps),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml job `release` step `Sign`: signs at step #1 but \
             `sigstore/cosign-installer` is step #2 — cosign is installed AFTER the signing \
             step",
        );
    }

    /// Gate (d): `--bundle` must be on the SAME command line as the signing
    /// invocation. A `--bundle` elsewhere in the step (another command, an
    /// echo) does not make the signature a bundle. Backslash-continued lines
    /// are one command; `&&`, `;`, `|` and newlines separate commands.
    #[test]
    fn a_bundle_flag_on_a_different_command_line_is_not_bundling() {
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &cosign_sign_steps(
                    COSIGN_INSTALLER_SHA,
                    "cosign sign-blob \"$f\" --yes; echo \"--bundle written\"",
                ),
            ),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "`cosign sign` runs without `--bundle` on the same command line",
        );

        // `&&`-chained: the bundle belongs to the other command.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &cosign_sign_steps(
                    COSIGN_INSTALLER_SHA,
                    "cosign sign-blob \"$f\" --yes && cosign verify-blob \"$f\" --bundle x",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);

        // A backslash continuation is the same command line: this is fine.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &cosign_sign_steps(
                    COSIGN_INSTALLER_SHA,
                    "cosign sign-blob \"$f\" \\\n              --bundle \"$f.sigstore.json\" --yes",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    /// Gate (d): every cosign-bearing step in the job is judged. One sound
    /// signing step does not excuse a second one that signs without a bundle
    /// — the artifact set it signs ships unverifiable.
    #[test]
    fn every_cosign_bearing_step_is_judged_and_a_defective_one_fails_the_job() {
        let steps = format!(
            "{}\n\
             \x20     - name: Sign checksums\n\
             \x20       run: cosign sign-blob dist/SHA256SUMS --yes",
            cosign_sign_steps(COSIGN_INSTALLER_SHA, COSIGN_SIGN_BUNDLED)
        );
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(RELEASE_JOB_PERMISSIONS, &steps),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release.yml job `release` step `Sign checksums`: `cosign sign` runs without \
             `--bundle`",
        );
    }

    /// Gate (e): an SBOM attestation with `sbom-path` but no subject binds the
    /// SBOM to nothing.
    #[test]
    fn sbom_attestation_without_a_subject_is_defective() {
        let (_d, ctx) = consolidated_repo(
            "sbom-attestation",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &attest_step(
                    "actions/attest",
                    ATTEST_SHA,
                    "          sbom-path: dist/sbom.cdx.json",
                ),
            ),
        );
        let result = verify_template_control(&ctx, "sbom-attestation");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "names no subject (`subject-path`, `subject-digest` or `subject-checksums`) — the \
             SBOM attestation not bound to any artifact digest",
        );
    }

    #[test]
    fn constant_false_recognizes_every_spelling_and_nothing_else() {
        let doc = &YamlLoader::load_from_str(
            "a: false\nb: 'false'\nc: \"false\"\nd: ${{ false }}\ne: ${{false}}\n\
             f: ${{ 'false' }}\ng: true\nh: ${{ github.event_name == 'push' }}\ni: 0\nj: \"\"\n",
        )
        .unwrap()[0];
        for k in ["a", "b", "c", "d", "e", "f"] {
            assert!(
                constant_false(&doc[k]).is_some(),
                "{k} must be constant-false"
            );
        }
        for k in ["g", "h", "i", "j", "missing"] {
            assert!(
                constant_false(&doc[k]).is_none(),
                "{k} must NOT be constant-false"
            );
        }
        assert_eq!(constant_false(&doc["d"]).as_deref(), Some("${{ false }}"));
    }

    #[test]
    fn trigger_names_cover_string_list_and_map_forms() {
        let s = &YamlLoader::load_from_str("on: push\n").unwrap()[0];
        assert_eq!(trigger_names(s), vec!["push"]);
        let l = &YamlLoader::load_from_str("on: [workflow_dispatch, release]\n").unwrap()[0];
        assert_eq!(automatic_trigger(l).as_deref(), Some("release"));
        let m =
            &YamlLoader::load_from_str("on:\n  schedule:\n    - cron: '0 0 * * *'\n").unwrap()[0];
        assert_eq!(automatic_trigger(m).as_deref(), Some("schedule"));
        let none = &YamlLoader::load_from_str("name: x\n").unwrap()[0];
        assert!(trigger_names(none).is_empty());
        assert!(automatic_trigger(none).is_none());
    }

    #[test]
    fn grants_applies_read_all_and_write_all_with_read_semantics() {
        let p = &YamlLoader::load_from_str("actions: read\ncontents: write\n").unwrap()[0];
        assert!(grants(p, "actions", Access::Read));
        assert!(!grants(p, "actions", Access::Write));
        assert!(grants(p, "contents", Access::Read));
        assert!(grants(p, "contents", Access::Write));
        assert!(!grants(p, "id-token", Access::Read));
        let ra = &YamlLoader::load_from_str("read-all").unwrap()[0];
        assert!(grants(ra, "actions", Access::Read));
        assert!(!grants(ra, "contents", Access::Write));
        let wa = &YamlLoader::load_from_str("write-all").unwrap()[0];
        assert!(grants(wa, "contents", Access::Write));
    }

    // ───────────────────── init / verify agreement ─────────────────────────

    /// The scan pipeline runs `init` BEFORE `verify`. A control proven by
    /// tracked consolidated evidence must NOT have its modular template
    /// written by `init` — otherwise `verify` grades an init-created file and
    /// the committed evidence is never reached. Same recognizer, same answer.
    #[test]
    fn install_all_skips_a_modular_artifact_whose_control_is_proven_by_consolidated_evidence() {
        let (_d, ctx) = consolidated_repo("sigstore-signing", &signed_release_workflow());
        let cfg = ctx.require_config().unwrap();
        assert!(
            cfg.control_enabled_or_default("sigstore-signing"),
            "premise"
        );
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(
            lines.contains(
                &"skip .github/workflows/release-sign.yml (sigstore-signing proven by \
                  .github/workflows/release.yml)"
                    .to_string()
            ),
            "{lines:?}"
        );
        assert!(
            !ctx.root.join(".github/workflows/release-sign.yml").exists(),
            "init must not write the modular template over proven evidence"
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert_eq!(result.evidence, vec![RELEASE.to_string()]);
    }

    /// Without evidence — no tracked workflow signs — `init` still installs
    /// the template, exactly as before.
    #[test]
    fn install_all_still_writes_the_modular_template_when_nothing_proves_the_control() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        // An UNTRACKED signing workflow is not evidence either.
        std::fs::write(ctx.root.join(RELEASE), signed_release_workflow()).unwrap();
        let cfg = ctx.require_config().unwrap();
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(
            lines.contains(&"write .github/workflows/release-sign.yml".to_string()),
            "{lines:?}"
        );
        assert!(ctx
            .root
            .join(".github/workflows/release-sign.yml")
            .is_file());
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert!(
            result.evidence.is_empty(),
            "the installed template, not release.yml, is the evidence"
        );
    }

    /// Controls outside the consolidated set keep the plain MISSING verdict:
    /// nothing is searched for on their behalf.
    #[test]
    fn controls_without_a_consolidated_form_report_plain_missing() {
        let (_d, ctx) = repo();
        std::fs::remove_file(ctx.root.join(".github/workflows/deploy-gate.yml")).unwrap();
        let result = verify_template_control(&ctx, "provenance-verify");
        assert_eq!(result.outcome, Outcome::Fail);
        assert_eq!(
            result.messages,
            vec![".github/workflows/deploy-gate.yml MISSING — run `sscsb init`".to_string()]
        );
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn a_uses_ref_with_no_at_is_reported_as_unpinned() {
        assert_eq!(
            pin_defect("actions/attest").as_deref(),
            Some("`actions/attest` has no ref at all — the step is present but its action is unpinned")
        );
        assert_eq!(pin_defect(&format!("actions/attest@{ATTEST_SHA}")), None);
    }

    #[test]
    fn with_input_set_requires_a_real_value() {
        let doc =
            &YamlLoader::load_from_str("with:\n  a: dist/x\n  b: \"\"\n  c:\n  d: [x]\n  e: 3\n")
                .unwrap()[0];
        assert!(with_input_set(doc, "a"));
        assert!(!with_input_set(doc, "b"), "empty string is not a subject");
        assert!(!with_input_set(doc, "c"), "null is not a subject");
        assert!(!with_input_set(doc, "missing"));
        assert!(
            with_input_set(doc, "d"),
            "a list is passed through to the action"
        );
        assert!(
            with_input_set(doc, "e"),
            "a number is passed through to the action"
        );
    }

    // ───────────────── shell tokenisation of `run:` bodies ─────────────────

    /// The recognizer used to ask `contains("cosign sign-blob")` of a command
    /// line, so a `run:` that merely PRINTED the command satisfied it. A
    /// signing command is one whose command word is `cosign`; a mention of
    /// cosign inside an `echo`'s argument is not one.
    #[test]
    fn an_echo_that_mentions_cosign_is_not_signing() {
        for decoy in [
            "echo \"would: cosign sign-blob $f --bundle $f.sigstore.json\"",
            "echo 'cosign sign-blob --bundle x'",
            "printf '%s\\n' \"cosign sign-blob $f --bundle $f.sigstore.json\"",
            "echo skipping cosign sign-blob --bundle for \"$f\"",
        ] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(
                    RELEASE_JOB_PERMISSIONS,
                    &cosign_sign_steps(COSIGN_INSTALLER_SHA, decoy),
                ),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "{decoy:?} must not read as signing: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            // Absent, not defective: nothing in the job signs at all.
            assert_message(
                &result,
                "release-sign.yml MISSING — run `sscsb init`; no committed (HEAD) workflow",
            );
            assert_no_message(&result, "does not meet the bar");
        }
    }

    /// A `#` comment can trail a command. `--bundle` inside that comment is
    /// not an argument of the command; the command signs without a bundle.
    #[test]
    fn a_bundle_flag_inside_a_trailing_comment_is_not_bundling() {
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &cosign_sign_steps(
                    COSIGN_INSTALLER_SHA,
                    "cosign sign-blob \"$f\" --yes # cosign sign-blob --bundle later",
                ),
            ),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "`cosign sign` runs without `--bundle` on the same command line",
        );

        // A `#` inside quotes, or glued to a word, is data — the real
        // `--bundle` after it still counts.
        std::fs::write(
            ctx.root.join(RELEASE),
            release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &cosign_sign_steps(
                    COSIGN_INSTALLER_SHA,
                    "cosign sign-blob \"$f\" --output-signature \"$f#1.sig\" --bundle \"#$f\" --yes",
                ),
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    /// The shapes a real `run:` body puts in front of the program without
    /// changing which program runs — and the `--bundle=` spelling.
    #[test]
    fn signing_is_recognized_through_assignments_wrappers_and_compound_openers() {
        for cmd in [
            "COSIGN_YES=true cosign sign-blob \"$f\" --bundle \"$f.sigstore.json\"",
            "env COSIGN_YES=true cosign sign-blob \"$f\" --bundle \"$f.sigstore.json\"",
            "sudo -E cosign sign-blob \"$f\" --bundle=\"$f.sigstore.json\" --yes",
            "time cosign sign \"$IMAGE\" --bundle out.json --yes",
            "[ -f \"$f\" ] && cosign sign-blob \"$f\" --bundle \"$f.sigstore.json\" --yes",
        ] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(
                    RELEASE_JOB_PERMISSIONS,
                    &cosign_sign_steps(COSIGN_INSTALLER_SHA, cmd),
                ),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "{cmd:?} must read as bundled signing: {:?}",
                result.messages
            );
        }
        // A one-line `for … do cosign …; done` as well.
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &format!(
                    "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
                     \x20     - run: for f in dist/*; do cosign sign-blob \"$f\" --bundle \
                     \"$f.sigstore.json\" --yes || exit 1; done"
                ),
            ),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    #[test]
    fn shell_commands_tokenises_quotes_comments_continuations_and_separators() {
        let script = "A=1 cosign sign-blob \"$f\" \\\n  --bundle '$f.sigstore.json' # done\n\
                      echo \"a; b && c\" | grep x; (exit 1) && true\n\
                      x=\"un#quoted\" y=z\\ w";
        let cmds = shell_commands(script);
        let words: Vec<Vec<&str>> = cmds
            .iter()
            .map(|c| c.words.iter().map(String::as_str).collect())
            .collect();
        assert_eq!(
            words,
            vec![
                vec![
                    "A=1",
                    "cosign",
                    "sign-blob",
                    "$f",
                    "--bundle",
                    "$f.sigstore.json"
                ],
                vec!["echo", "a; b && c"],
                vec!["grep", "x"],
                vec!["(", "exit", "1", ")"],
                vec!["true"],
                vec!["x=un#quoted", "y=z w"],
            ]
        );
        assert_eq!(
            command_word(&cmds[0].words).map(|(w, _)| w),
            Some("cosign"),
            "leading assignments are skipped"
        );
        assert_eq!(
            cmds.iter().map(|c| c.sep).collect::<Vec<_>>(),
            vec![
                Sep::Other,
                Sep::Pipe,
                Sep::Other,
                Sep::Other,
                Sep::Other,
                Sep::Other
            ],
            "one `|` (echo into grep) and no `||` anywhere in this script"
        );
        assert_eq!(
            cosign_sign_in_run(script),
            Some(SigningShortfalls::default())
        );
        // The `&` of a redirection does not end the command: the `|| true`
        // after `2>&1` still swallows THIS command's failure, and `&>log`
        // is one word.
        let redirected = shell_commands("cosign sign-blob x --bundle b 2>&1 || true\ncmd &>log");
        assert_eq!(
            redirected[0].words,
            vec!["cosign", "sign-blob", "x", "--bundle", "b", "2>&1"]
        );
        assert_eq!(redirected[0].sep, Sep::Or);
        assert_eq!(redirected[2].words, vec!["cmd", "&>log"]);
        assert_eq!(
            cosign_sign_in_run("cosign sign-blob x --bundle b 2>&1 || true")
                .unwrap()
                .failure_ignored
                .as_deref(),
            Some("true")
        );
        assert_eq!(cosign_sign_in_run("echo cosign sign-blob --bundle"), None);
        assert_eq!(
            cosign_sign_in_run("cosign verify-blob x --bundle y"),
            None,
            "verification is not signing"
        );
        assert_eq!(
            cosign_sign_in_run("cosign sign-blob x --yes\ncosign sign-blob y --bundle b")
                .map(|s| s.unbundled),
            Some(true),
            "one unbundled command fails the step"
        );
    }

    /// Gate (d), heredocs: everything between `<<WORD` and the line equal to
    /// `WORD` is data. A signing line inside a heredoc body is not a
    /// command, whichever spelling opened the heredoc; `<<-` strips leading
    /// tabs from the closing line; `<<<` is a here-string and opens nothing.
    #[test]
    fn a_signing_line_inside_a_heredoc_body_is_not_a_command() {
        for opener in ["<<EOF", "<< EOF", "<<'EOF'", "<< \"EOF\"", "<<-EOF"] {
            let script = format!(
                "cat {opener} > notes.txt\n\tcosign sign-blob \"$f\" --bundle \"$f.sigstore.json\" \
                 --yes\n\tEOF\n"
            );
            let cmds = shell_commands(&script);
            assert_eq!(
                cmds.len(),
                1,
                "{opener}: the body must not tokenise into commands: {cmds:?}"
            );
            assert_eq!(cmds[0].words[0], "cat");
            assert_eq!(
                cosign_sign_in_run(&script),
                None,
                "{opener}: a heredoc body does not sign"
            );
        }
        // A plain `<<EOF` closes only on a line EXACTLY `EOF`; the tab-indented
        // closer above therefore leaves the body open to the end of input for
        // `<<EOF`, and that is still not signing — only `<<-` strips tabs.
        let closed =
            "cat <<EOF\ncosign sign-blob x --bundle b\nEOF\ncosign sign-blob y --bundle b\n";
        assert_eq!(
            cosign_sign_in_run(closed),
            Some(SigningShortfalls::default()),
            "the command AFTER the closing delimiter is real"
        );
        assert_eq!(shell_commands(closed).len(), 2, "cat, then the real cosign");
        assert_eq!(
            cosign_sign_in_run("cosign sign-blob x --bundle b <<< data"),
            Some(SigningShortfalls::default()),
            "a here-string is a word of the command, not a heredoc"
        );

        // The `: <<'COMMENT'` block-comment idiom.
        let commented = ": <<'COMMENT'\ncosign sign-blob \"$f\" --bundle \"$f.sigstore.json\" \
                         --yes\nCOMMENT\necho done\n";
        assert_eq!(cosign_sign_in_run(commented), None);

        // In a workflow: the signing step's body is one heredoc — Absent,
        // and the control fails as missing, not as defective.
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &format!(
                    "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
                     \x20     - run: |\n\
                     \x20         cat <<'SIGN' > /dev/null\n\
                     \x20         for f in dist/*; do\n\
                     \x20           {COSIGN_SIGN_BUNDLED}\n\
                     \x20         done\n\
                     \x20         SIGN"
                ),
            ),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release-sign.yml MISSING — run `sscsb init`; no committed (HEAD) workflow",
        );
        assert_no_message(&result, "does not meet the bar");
    }

    /// Gate (c), suppression: a signing command whose failure cannot fail
    /// the step — negated with `!`, followed by `|| true` / `|| :`, or run
    /// as the author's own `cosign` function or alias — is named as such.
    #[test]
    fn a_signing_command_whose_failure_is_suppressed_is_defective() {
        for (cmd, needle) in [
            (
                format!("! {COSIGN_SIGN_BUNDLED}"),
                "the signing command is negated with `!` — its exit status is inverted, so a \
                 failed signing reads as success",
            ),
            (
                format!("{COSIGN_SIGN_BUNDLED} || true"),
                "the signing command is followed by `|| true` — a failed signing is swallowed \
                 and the step succeeds with an unsigned artifact",
            ),
            (
                format!("{COSIGN_SIGN_BUNDLED} || :"),
                "the signing command is followed by `|| :` — a failed signing is swallowed",
            ),
            // Any word after `||` that does not fail the step swallows the
            // failure just as `true` does — the message names the word.
            (
                format!("{COSIGN_SIGN_BUNDLED} || echo \"::warning::signing failed for $f\""),
                "the signing command is followed by `|| echo` — a failed signing is swallowed",
            ),
            (
                format!("{COSIGN_SIGN_BUNDLED} || continue"),
                "the signing command is followed by `|| continue` — a failed signing is \
                 swallowed",
            ),
            (
                format!("{COSIGN_SIGN_BUNDLED} || FAILED=1 true"),
                "the signing command is followed by `|| true`",
            ),
            // A pipe hands the step the LAST command's exit status: without
            // `pipefail` a failed signing whose output `tee` copied is a
            // success.
            (
                format!("{COSIGN_SIGN_BUNDLED} | tee -a sign.log"),
                "the signing command's output is piped — its exit status is not the step's",
            ),
            (
                format!("{COSIGN_SIGN_BUNDLED} 2>&1 | grep -v noise || exit 1"),
                "output is piped — its exit status is not the step's",
            ),
            // `set -o pipefail` counts only when it PRECEDES the pipe.
            (
                format!("{COSIGN_SIGN_BUNDLED} | tee -a sign.log\n            set -o pipefail"),
                "output is piped — its exit status is not the step's",
            ),
            (
                format!("cosign() {{ echo fake; }}\n            {COSIGN_SIGN_BUNDLED}"),
                "the `run:` body defines a function or alias named `cosign` — the signing \
                 command is not the installed cosign",
            ),
            (
                format!("function cosign {{ :; }}\n            {COSIGN_SIGN_BUNDLED}"),
                "defines a function or alias named `cosign`",
            ),
            (
                format!("alias cosign='true'\n            shopt -s expand_aliases\n            {COSIGN_SIGN_BUNDLED}"),
                "defines a function or alias named `cosign`",
            ),
        ] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(
                    RELEASE_JOB_PERMISSIONS,
                    &cosign_sign_steps(COSIGN_INSTALLER_SHA, &cmd),
                ),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "{cmd:?} must fail: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(&result, "release.yml job `release` step #2: ");
            assert_message(&result, needle);
        }

        // `|| exit 1` and `|| { …; exit 1; }` — the shipped template's own
        // shape — fail the step on a signing failure and are NOT suppression;
        // neither are `return`, `false`, `kill` and a `( … )` group. A pipe
        // with `set -o pipefail` before it keeps the signing status, and a
        // signing command that is the LAST in a pipeline owns the status.
        for cmd in [
            format!("{COSIGN_SIGN_BUNDLED} || exit 1"),
            format!("{COSIGN_SIGN_BUNDLED} \\\n              || {{ echo \"::error::failed\"; exit 1; }}"),
            format!("{COSIGN_SIGN_BUNDLED} || return 1"),
            format!("{COSIGN_SIGN_BUNDLED} || false"),
            format!("{COSIGN_SIGN_BUNDLED} || kill -TERM $$"),
            format!("{COSIGN_SIGN_BUNDLED} || ( echo failed; exit 1 )"),
            format!("set -o pipefail\n            {COSIGN_SIGN_BUNDLED} | tee -a sign.log"),
            format!("set -euo pipefail\n            {COSIGN_SIGN_BUNDLED} | tee -a sign.log"),
            format!("printf '%s\\n' \"$f\" | {COSIGN_SIGN_BUNDLED}"),
        ] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(
                    RELEASE_JOB_PERMISSIONS,
                    &cosign_sign_steps(COSIGN_INSTALLER_SHA, &cmd),
                ),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "{cmd:?} must pass: {:?}",
                result.messages
            );
        }
    }

    /// Gate (c), the pipe under a shell that sets `pipefail` itself: the
    /// built-in `shell: bash` runs as `bash --noprofile --norc -eo pipefail
    /// {0}`, so the pipeline's status is the signing command's and the body
    /// needs no `set -o pipefail` of its own. `shell: sh` (`sh -e {0}`) and
    /// no `shell:` at all (`bash -e {0}`) set nothing, and the same body
    /// fails under them.
    #[test]
    fn a_piped_signing_command_is_sound_only_when_pipefail_is_on() {
        let piped_under = |shell: &str| {
            let shell_line = if shell.is_empty() {
                String::new()
            } else {
                format!("        shell: {shell}\n")
            };
            format!(
                "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
                 \x20     - name: Sign\n\
                 {shell_line}\
                 \x20       run: {COSIGN_SIGN_BUNDLED} | tee -a sign.log"
            )
        };
        let piped_needle = "the signing command's output is piped — its exit status is not \
                            the step's (no `set -o pipefail` precedes it in the body, and the \
                            shell does not set it)";
        for shell in ["", "sh", "bash -e {0}"] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(RELEASE_JOB_PERMISSIONS, &piped_under(shell)),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "shell {shell:?} sets no pipefail: {:?}",
                result.messages
            );
            assert_message(&result, "release.yml job `release` step `Sign`: ");
            assert_message(&result, piped_needle);
        }
        for shell in ["bash", "bash --noprofile --norc -eo pipefail {0}"] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(RELEASE_JOB_PERMISSIONS, &piped_under(shell)),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "shell {shell:?} sets pipefail: {:?}",
                result.messages
            );
            assert_no_message(&result, "output is piped");
        }

        // The tokeniser's own view: `|` is its own separator, the pipe is a
        // shortfall only without a preceding `set … pipefail`, and `||` is
        // swallowing for any word outside the propagating set.
        let piped = cosign_sign_in_run(&format!("{COSIGN_SIGN_BUNDLED} | tee log")).unwrap();
        assert!(piped.piped);
        assert_eq!(piped.failure_ignored, None);
        let guarded = cosign_sign_in_run(&format!(
            "set -eo pipefail\n{COSIGN_SIGN_BUNDLED} | tee log"
        ))
        .unwrap();
        assert!(!guarded.piped);
        assert_eq!(
            cosign_sign_in_run(&format!("{COSIGN_SIGN_BUNDLED} || echo warn"))
                .unwrap()
                .failure_ignored
                .as_deref(),
            Some("echo")
        );
        for propagating in [
            "exit 1",
            "return 1",
            "false",
            "kill $$",
            "{ exit 1; }",
            "( exit 1 )",
        ] {
            assert_eq!(
                cosign_sign_in_run(&format!("{COSIGN_SIGN_BUNDLED} || {propagating}"))
                    .unwrap()
                    .failure_ignored,
                None,
                "`|| {propagating}` propagates the failure"
            );
        }
    }

    /// Gate (c), `continue-on-error`: on the proving job, the proving step,
    /// or the installer step, a failure fails nothing — `true` as YAML or as
    /// the string `'true'`; any expression is left alone.
    #[test]
    fn continue_on_error_on_the_proving_job_or_step_is_defective() {
        // The signing job.
        for literal in ["true", "'true'"] {
            let body = signed_release_workflow().replace(
                "  release:\n    runs-on: ubuntu-latest\n",
                &format!(
                    "  release:\n    continue-on-error: {literal}\n    runs-on: ubuntu-latest\n"
                ),
            );
            assert!(body.contains("continue-on-error"), "fixture premise");
            let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "`continue-on-error: {literal}` must fail: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(
                &result,
                "release.yml job `release`: job `continue-on-error: true` — a failed job does \
                 not fail the run",
            );
        }

        // The signing step, and the installer step.
        let steps = format!(
            "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
             \x20       continue-on-error: true\n\
             \x20     - name: Sign\n\
             \x20       continue-on-error: 'true'\n\
             \x20       run: {COSIGN_SIGN_BUNDLED}"
        );
        let (_d, ctx) = consolidated_repo(
            "sigstore-signing",
            &release_workflow(RELEASE_JOB_PERMISSIONS, &steps),
        );
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml job `release` step `Sign`: `continue-on-error: true` — a failed \
             signing does not fail the job",
        );
        assert_message(
            &result,
            "release.yml job `release` step #1: `continue-on-error: true` on the installer — \
             a failed install is ignored and signing runs against whatever the runner \
             happened to have",
        );

        // The attestation step.
        let (_d, ctx) = consolidated_repo(
            "github-attestations",
            &release_workflow(
                RELEASE_JOB_PERMISSIONS,
                &format!(
                    "      - uses: actions/attest-build-provenance@{ATTEST_BUILD_PROVENANCE_SHA}\n\
                     \x20       continue-on-error: true\n\
                     \x20       with:\n\
                     \x20         subject-path: dist/*.tar.gz"
                ),
            ),
        );
        let result = verify_template_control(&ctx, "github-attestations");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "release.yml job `release` step #1: `continue-on-error: true` — a failed \
             attestation does not fail the job",
        );

        // An expression is not evaluated: neither `true` nor suppression.
        let body = signed_release_workflow().replace(
            "  release:\n    runs-on: ubuntu-latest\n",
            "  release:\n    continue-on-error: ${{ github.event_name == 'push' }}\n    \
             runs-on: ubuntu-latest\n",
        );
        let (_d, ctx) = consolidated_repo("sigstore-signing", &body);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
        assert!(!continues_on_error(
            &YamlLoader::load_from_str("continue-on-error: false").unwrap()[0]
        ));
    }

    /// Gate (d), the effective shell: a `run:` body is judged as a POSIX
    /// signing command only under `bash` / `sh` (bare, or as GitHub's
    /// `bash … {0}` template) or with no `shell:` at all. Under `pwsh`,
    /// `python`, `cmd` or a custom template such as `true {0}` the body is
    /// whatever that program makes of it, and sscsb says it did not judge
    /// it. The step's `shell:` wins over the job's `defaults.run.shell`,
    /// which wins over the workflow's.
    #[test]
    fn a_signing_step_under_a_non_posix_shell_is_not_judged() {
        let step_shell = |shell: &str| {
            format!(
                "      - uses: sigstore/cosign-installer@{COSIGN_INSTALLER_SHA}\n\
                 \x20     - name: Sign\n\
                 \x20       shell: {shell}\n\
                 \x20       run: {COSIGN_SIGN_BUNDLED}"
            )
        };
        // GitHub's custom-shell shape is `program`, options, one `{0}` — and
        // nothing else: a template that runs a command of its own before the
        // script (`bash -c 'exit 0; {0}'`), carries an extra bare word, has
        // two placeholders, or has options but no placeholder (the runner
        // starts `bash -e` with no script) is not that shape.
        for shell in [
            "pwsh",
            "true {0}",
            "python",
            "cmd",
            "bash -c 'exit 0; {0}'",
            "bash {0} extra",
            "sh {0} {0}",
            "bash -e",
        ] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(RELEASE_JOB_PERMISSIONS, &step_shell(shell)),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Fail,
                "shell `{shell}` must not be judged: {:?}",
                result.messages
            );
            assert!(result.evidence.is_empty());
            assert_message(
                &result,
                &format!(
                    "release.yml job `release` step `Sign`: step runs under shell `{shell}` — \
                     not judged as a POSIX signing command"
                ),
            );
        }
        for shell in [
            "bash",
            "sh",
            "bash -e {0}",
            "bash --noprofile --norc -eo pipefail {0}",
            "sh -e {0}",
        ] {
            let (_d, ctx) = consolidated_repo(
                "sigstore-signing",
                &release_workflow(RELEASE_JOB_PERMISSIONS, &step_shell(shell)),
            );
            let result = verify_template_control(&ctx, "sigstore-signing");
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "shell `{shell}` is POSIX: {:?}",
                result.messages
            );
        }

        // Job-level and workflow-level `defaults.run.shell` apply when the
        // step names none; the step's own `shell:` overrides both.
        let job_default = signed_release_workflow().replace(
            "  release:\n    runs-on: ubuntu-latest\n",
            "  release:\n    defaults:\n      run:\n        shell: pwsh\n    runs-on: ubuntu-latest\n",
        );
        assert!(job_default.contains("shell: pwsh"), "fixture premise");
        let (_d, ctx) = consolidated_repo("sigstore-signing", &job_default);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(&result, "step runs under shell `pwsh`");

        let workflow_default = signed_release_workflow().replace(
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\ndefaults:\n  run:\n    shell: python\n",
        );
        assert!(
            workflow_default.contains("shell: python"),
            "fixture premise"
        );
        std::fs::write(ctx.root.join(RELEASE), workflow_default).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(&result, "step runs under shell `python`");

        let step_overrides = signed_release_workflow()
            .replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: read\ndefaults:\n  run:\n    shell: python\n",
            )
            .replace("      - run: |\n", "      - shell: bash\n        run: |\n");
        assert!(step_overrides.contains("- shell: bash"), "fixture premise");
        std::fs::write(ctx.root.join(RELEASE), step_overrides).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);

        assert!(is_posix_shell(None));
        assert!(is_posix_shell(Some("bash -c '{0}'")));
        assert!(is_posix_shell(Some("sh -e {0}")));
        assert!(!is_posix_shell(Some("bash -c script.sh")));
        assert!(!is_posix_shell(Some("zsh {0}")));
        assert!(!is_posix_shell(Some("bash -c 'exit 0; {0}'")));
        assert!(!is_posix_shell(Some("bash {0} extra")));
        assert!(!is_posix_shell(Some("sh {0} {0}")));
        assert!(!is_posix_shell(Some("bash -e")));

        // Which shells run the body with `pipefail` already on.
        assert!(shell_sets_pipefail(Some("bash")));
        assert!(shell_sets_pipefail(Some(
            "bash --noprofile --norc -eo pipefail {0}"
        )));
        assert!(shell_sets_pipefail(Some("sh -o pipefail {0}")));
        assert!(!shell_sets_pipefail(Some("sh")));
        assert!(!shell_sets_pipefail(Some("bash -e {0}")));
        assert!(!shell_sets_pipefail(Some("bash --pipefail {0}")));
        assert!(!shell_sets_pipefail(None));
    }

    // ───────────────── generator subjects ─────────────────

    /// The generator attests the subjects it is handed. A call that hands it
    /// none — no `base64-subjects`, no `base64-subjects-as-file` — produces
    /// provenance bound to nothing, and the previous recognizer accepted it.
    #[test]
    fn a_generator_job_that_names_no_subjects_is_defective() {
        let no_subjects = slsa_workflow("v2.1.0", SLSA_JOB_PERMISSIONS)
            .replace("    with:\n      base64-subjects: \"abc\"\n", "");
        assert!(!no_subjects.contains("base64-subjects"), "fixture premise");
        let (_d, ctx) = consolidated_repo("slsa-provenance", &no_subjects);
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(
            &result,
            "release.yml job `provenance`: `slsa-framework/slsa-github-generator/.github/\
             workflows/generator_generic_slsa3.yml@v2.1.0` names no subjects \
             (`base64-subjects` or `base64-subjects-as-file` in `with:`) — provenance is \
             bound to nothing",
        );

        // An empty value is no subject either.
        std::fs::write(
            ctx.root.join(RELEASE),
            slsa_workflow("v2.1.0", SLSA_JOB_PERMISSIONS)
                .replace("base64-subjects: \"abc\"", "base64-subjects: \"\""),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(&result, "names no subjects");

        // `base64-subjects-as-file` is the other documented input.
        std::fs::write(
            ctx.root.join(RELEASE),
            slsa_workflow("v2.1.0", SLSA_JOB_PERMISSIONS).replace(
                "base64-subjects: \"abc\"",
                "base64-subjects-as-file: subjects.b64",
            ),
        )
        .unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "slsa-provenance");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    // ───────────────── workflow shape: hard errors GitHub raises ─────────

    /// Two YAML documents in one file: GitHub reads exactly one workflow per
    /// file, so the file cannot be the workflow anyone relies on.
    #[test]
    fn a_multi_document_workflow_file_is_broken() {
        let (_d, ctx) = repo();
        let two = format!(
            "{}---\n{}",
            signed_release_workflow(),
            signed_release_workflow()
        );
        std::fs::write(ctx.root.join(".github/workflows/codeql.yml"), &two).unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "codeql.yml holds 2 YAML documents — a GitHub Actions workflow file is exactly \
             one document, so GitHub cannot run it",
        );

        // A trailing `---` is a blank document, not a second workflow.
        let trailing = format!("{}---\n", signed_release_workflow());
        match check_workflow(".github/workflows/x.yml", &trailing) {
            ShapeVerdict::Sound(_) => {}
            other => panic!("a trailing separator is fine: {}", verdict_text(&other)),
        }

        // And as consolidated evidence the same file cannot serve.
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        std::fs::write(ctx.root.join(RELEASE), &two).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, "release.yml holds 2 YAML documents");
        assert_message(&result, "but cannot serve as evidence");
    }

    /// `needs:` naming a job that does not exist is rejected by GitHub at
    /// parse time — every job in the file, the proving one included.
    #[test]
    fn a_job_that_needs_a_nonexistent_job_is_broken() {
        let ghost = signed_release_workflow().replace(
            "  release:\n    runs-on: ubuntu-latest\n",
            "  release:\n    needs: [build, package]\n    runs-on: ubuntu-latest\n",
        );
        assert!(ghost.contains("needs: [build, package]"), "fixture premise");
        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(".github/workflows/codeql.yml"), &ghost).unwrap();
        let result = verify_template_control(&ctx, "codeql");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert_message(
            &result,
            "codeql.yml: job `release` needs `build`, which is not a job in this workflow — \
             GitHub rejects the whole workflow",
        );

        // The string form too.
        let ghost_str = signed_release_workflow().replace(
            "  release:\n    runs-on: ubuntu-latest\n",
            "  release:\n    needs: build\n    runs-on: ubuntu-latest\n",
        );
        match check_workflow(".github/workflows/x.yml", &ghost_str) {
            ShapeVerdict::Broken(m) => assert!(m.contains("needs `build`"), "{m}"),
            other => panic!("expected broken: {}", verdict_text(&other)),
        }

        // As consolidated evidence: the signing job is sound, the file is not.
        std::fs::remove_file(ctx.root.join(".github/workflows/release-sign.yml")).unwrap();
        std::fs::write(ctx.root.join(RELEASE), &ghost).unwrap();
        commit(&ctx, RELEASE);
        let result = verify_template_control(&ctx, "sigstore-signing");
        assert_eq!(result.outcome, Outcome::Fail, "{:?}", result.messages);
        assert!(result.evidence.is_empty());
        assert_message(&result, "release.yml: job `release` needs `build`");
        assert_message(&result, "but cannot serve as evidence");
    }

    // ───────────────── Octo STS subject pinning ─────────────────

    const STS: &str = ".github/chainguard/sscsb-automation.sts.yaml";

    fn sts_template() -> &'static str {
        ARTIFACTS.iter().find(|a| a.dest == STS).unwrap().content
    }

    /// The `subject_pattern` a rendered policy declares.
    fn subject_pattern(rendered: &str) -> String {
        let doc = YamlLoader::load_from_str(rendered).unwrap().remove(0);
        doc["subject_pattern"]
            .as_str()
            .unwrap_or_else(|| panic!("no string subject_pattern in {rendered}"))
            .to_string()
    }

    /// GitHub's OIDC `sub` is id-decorated (`repo:p4gs@10093271/
    /// p4gs.github.io@1354031532:ref:refs/heads/main` — the live refusal
    /// this was observed in), so the policy pins the ids when they are
    /// known: each as an optional `(@<id>)?` group, with the repository
    /// name's `.` escaped, because the pattern is a regular expression. The
    /// shape checker accepts the rendered file.
    #[test]
    fn the_sts_policy_renders_an_id_pinned_subject_when_the_ids_are_known() {
        let ids = RepoIds {
            owner_id: "10093271".into(),
            repo_id: "1354031532".into(),
        };
        let rendered = render_with_ids(sts_template(), "p4gs/p4gs.github.io", "main", Some(&ids));
        assert_eq!(
            subject_pattern(&rendered),
            r"repo:p4gs(@10093271)?/p4gs\.github\.io(@1354031532)?:ref:refs/heads/main"
        );
        assert!(
            !rendered.contains("{{"),
            "every placeholder rendered: {rendered}"
        );
        assert!(
            rendered.contains("gh api repos/p4gs/p4gs.github.io --jq .id")
                && rendered.contains("gh api users/p4gs --jq .id"),
            "the comment names the two pin commands: {rendered}"
        );

        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(STS), &rendered).unwrap();
        let result = verify_template_control(&ctx, "octo-sts");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    /// Without the ids the policy is TOLERANT, not blind: `[0-9]+` accepts
    /// whatever id GitHub decorates the subject with, so the exchange works
    /// — and the operator is told to pin. `render` (no ids) is that form.
    #[test]
    fn the_sts_policy_renders_a_tolerant_subject_when_the_ids_are_unknown() {
        let rendered = render(sts_template(), "p4gs/p4gs.github.io", "release");
        assert_eq!(
            subject_pattern(&rendered),
            r"repo:p4gs(@[0-9]+)?/p4gs\.github\.io(@[0-9]+)?:ref:refs/heads/release"
        );
        assert_eq!(
            render_with_ids(sts_template(), "p4gs/p4gs.github.io", "release", None),
            rendered
        );
        assert!(!rendered.contains("{{"), "{rendered}");

        let (_d, ctx) = repo();
        std::fs::write(ctx.root.join(STS), &rendered).unwrap();
        let result = verify_template_control(&ctx, "octo-sts");
        assert_eq!(result.outcome, Outcome::Pass, "{:?}", result.messages);
    }

    /// `init` resolves the ids through `gh api repos/<slug>` and `gh api
    /// users/<owner>` when `gh` answers; when it refuses or is absent, the
    /// tolerant form is written and a `note` line names the two commands
    /// that pin it. The placeholder slug (no remote, no `github_repo`) never
    /// calls the API at all.
    #[test]
    fn install_all_pins_the_sts_subject_ids_from_the_github_api_when_it_can() {
        let lock = crate::testutil::env_lock();
        let (_d, ctx) = repo();
        let sts = ctx.root.join(STS);
        let cfg = ctx.require_config().unwrap();
        let note = format!(
            "note {STS}: owner/repo ids not resolved from the GitHub API — `subject_pattern` \
             accepts any `@<id>` decoration until you pin them: `gh api \
             repos/p4gs/sscs-bootstrapper --jq .id` (repo id), `gh api users/p4gs --jq .id` \
             (owner id)"
        );

        // Placeholder slug: no remote, so no API call — a `gh` that would
        // blow up proves it was never run. The note still fires, spelled
        // with the same placeholders the rest of the file carries.
        lock.fake_tool(
            "gh",
            "#!/bin/sh\necho 'gh must not run for OWNER/REPO' >&2\nexit 99\n",
        );
        std::fs::remove_file(&sts).unwrap();
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(lines.contains(&format!("write {STS}")), "{lines:?}");
        assert!(
            lines.contains(
                &note
                    .replace("p4gs/sscs-bootstrapper", "OWNER/REPO")
                    .replace("users/p4gs", "users/OWNER")
            ),
            "{lines:?}"
        );
        assert_eq!(
            subject_pattern(&std::fs::read_to_string(&sts).unwrap()),
            "repo:OWNER(@[0-9]+)?/REPO(@[0-9]+)?:ref:refs/heads/main"
        );

        crate::exec::git(
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/p4gs/sscs-bootstrapper.git",
            ],
            &ctx.root,
        )
        .unwrap();

        // `gh` answers: pinned, no note.
        lock.fake_tool(
            "gh",
            "#!/bin/sh\n\
             [ \"$1\" = api ] && [ \"$3\" = --jq ] && [ \"$4\" = .id ] || { echo \"unexpected: $*\" >&2; exit 2; }\n\
             case \"$2\" in\n\
             \x20 repos/p4gs/sscs-bootstrapper) echo 1156341487 ;;\n\
             \x20 users/p4gs) echo 10093271 ;;\n\
             \x20 *) echo \"unexpected path: $2\" >&2; exit 1 ;;\n\
             esac\n",
        );
        std::fs::remove_file(&sts).unwrap();
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(lines.contains(&format!("write {STS}")), "{lines:?}");
        assert!(!lines.iter().any(|l| l.starts_with("note ")), "{lines:?}");
        assert_eq!(
            subject_pattern(&std::fs::read_to_string(&sts).unwrap()),
            "repo:p4gs(@10093271)?/sscs-bootstrapper(@1156341487)?:ref:refs/heads/main"
        );

        // `gh` present but refusing (unauthenticated, offline): tolerant + note.
        lock.fake_tool(
            "gh",
            "#!/bin/sh\necho 'gh: HTTP 401: Bad credentials' >&2\nexit 1\n",
        );
        std::fs::remove_file(&sts).unwrap();
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(lines.contains(&note), "{lines:?}");
        assert_eq!(
            subject_pattern(&std::fs::read_to_string(&sts).unwrap()),
            "repo:p4gs(@[0-9]+)?/sscs-bootstrapper(@[0-9]+)?:ref:refs/heads/main"
        );

        // A `gh` that answers with something other than a number is not an id.
        lock.fake_tool("gh", "#!/bin/sh\necho 'null'\n");
        std::fs::remove_file(&sts).unwrap();
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(lines.contains(&note), "{lines:?}");

        // `gh` absent: tolerant + note.
        lock.hide_from_path(&["gh"]);
        assert!(
            crate::exec::find_in_path("gh").is_none(),
            "fixture must hide gh"
        );
        std::fs::remove_file(&sts).unwrap();
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(lines.contains(&note), "{lines:?}");
        assert_eq!(
            subject_pattern(&std::fs::read_to_string(&sts).unwrap()),
            "repo:p4gs(@[0-9]+)?/sscs-bootstrapper(@[0-9]+)?:ref:refs/heads/main"
        );

        // An existing file is kept, and nothing is asked of the API for it.
        let lines = install_all(&ctx, cfg).unwrap();
        assert!(lines.contains(&format!("keep {STS} (exists — delete to regenerate)")));
        assert!(!lines.iter().any(|l| l.starts_with("note ")), "{lines:?}");
    }

    /// This repository's own policy is the template rendered with its ids.
    #[test]
    fn the_dogfood_sts_policy_is_the_template_rendered_with_this_repositorys_ids() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let ids = RepoIds {
            owner_id: "10093271".into(),
            repo_id: "1156341487".into(),
        };
        let rendered =
            render_with_ids(sts_template(), "p4gs/sscs-bootstrapper", "main", Some(&ids));
        let dogfood = std::fs::read_to_string(root.join(STS)).unwrap();
        assert_eq!(
            rendered, dogfood,
            "{STS}: dogfood policy drifted from the rendered template"
        );
    }

    // ───────────────── template ⇄ dogfood parity ─────────────────

    /// Remove every region between a `sscsb:customize-begin` line and its
    /// `sscsb:customize-end` line (both inclusive), returning what is left
    /// and how many regions there were. Unbalanced markers panic.
    fn excise_customized(content: &str) -> (String, usize) {
        let mut kept = String::new();
        let mut regions = 0;
        let mut inside = false;
        for line in content.lines() {
            if line.contains("sscsb:customize-begin") {
                assert!(!inside, "nested customize-begin");
                inside = true;
                regions += 1;
                continue;
            }
            if line.contains("sscsb:customize-end") {
                assert!(inside, "customize-end without begin");
                inside = false;
                continue;
            }
            if !inside {
                kept.push_str(line);
                kept.push('\n');
            }
        }
        assert!(!inside, "customize-begin without end");
        (kept, regions)
    }

    /// The release pipeline this repository RUNS is the one the templates
    /// SHIP: `.github/workflows/release.yml` and `deploy-gate.yml` are the
    /// rendered templates, byte for byte, outside the marked
    /// repository-specific regions — the build fan-out (a Rust matrix here,
    /// `git archive` in the template) and the artifact-count assertion that
    /// depends on it. `deploy-gate.yml` has no such region: it is identical.
    /// Either file drifting from the other fails here.
    #[test]
    fn dogfood_release_workflows_are_the_rendered_templates() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for (dest, regions) in [
            (".github/workflows/release.yml", 2),
            (".github/workflows/deploy-gate.yml", 0),
        ] {
            let template = ARTIFACTS.iter().find(|a| a.dest == dest).unwrap();
            let rendered = render(template.content, "p4gs/sscs-bootstrapper", "main");
            let dogfood = std::fs::read_to_string(root.join(dest)).unwrap();
            let (rendered_kept, rendered_regions) = excise_customized(&rendered);
            let (dogfood_kept, dogfood_regions) = excise_customized(&dogfood);
            assert_eq!(rendered_regions, regions, "{dest}: template regions");
            assert_eq!(dogfood_regions, regions, "{dest}: dogfood regions");
            if regions == 0 {
                assert_eq!(
                    rendered, dogfood,
                    "{dest}: dogfood file is not the template"
                );
            }
            assert_eq!(
                rendered_kept, dogfood_kept,
                "{dest}: dogfood file drifted from the template outside its customize regions"
            );
        }
    }
}
