//! `dependency-pinning`: the dependency surfaces OpenSSF Scorecard's
//! Pinned-Dependencies check reads that `actions-audit` was never scoped for —
//! Dockerfile base images, shell downloads and package installs in workflow
//! `run:` steps, composite-action steps, Dockerfile `RUN` lines and committed
//! scripts — plus the surface neither tool reads: a package manifest with no
//! committed lockfile.
//!
//! Subjects are tracked in the Git index. Inspect their index blobs and guarded
//! working copies, without mistaking unavailable evidence for a clean check.
//!
//! Severity policy. A floating base image, a download piped into a shell or
//! executed without verification, and an install with no version at all are
//! `Error` — the repository is telling a future build to fetch whatever is
//! there that day. A `pip` or `npm` install pinned to an exact version but
//! not to a hash is `Warn`: it names one release, which is a real decision,
//! and hash pinning is the stricter form the message asks for. Only `Error`
//! fails the control.

use crate::audit::{jobs, steps, Finding, Severity};
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::index_file::{self, Entries};
use anyhow::Result;
use std::path::Path;

/// Verification steps that, appearing anywhere in the same script as a
/// download, mean the download is checked before it is executed. Any one
/// suffices: the point is that a verification exists, not which tool.
const VERIFICATION_MARKERS: &[&str] = &[
    "sha256sum -c",
    "sha256sum --check",
    "sha512sum -c",
    "sha512sum --check",
    "shasum -a 256 -c",
    "shasum -c",
    "cosign verify-blob",
    "cosign verify",
    "gh attestation verify",
    "slsa-verifier",
    "gpg --verify",
    "minisign -V",
    "--hash=",
    "--require-hashes",
    // Computing a digest of what was downloaded and comparing it to a pinned
    // constant is the verification most workflows actually write
    // (`actual="$(sha256sum f | cut -d' ' -f1)"; [ "$actual" = "$PINNED" ]`).
    // The digest call is the marker; a script that computes one and ignores
    // it is not a shape worth modelling.
    "sha256sum",
    "sha512sum",
    "shasum ",
    "openssl dgst",
];

/// Filenames that are Dockerfiles.
fn is_dockerfile(name: &str) -> bool {
    name == "Dockerfile"
        || name == "Containerfile"
        || name.starts_with("Dockerfile.")
        || name.ends_with(".Dockerfile")
}

fn is_workflow(path: &str) -> bool {
    path.starts_with(".github/workflows/") && (path.ends_with(".yml") || path.ends_with(".yaml"))
}

/// A composite action: one vendored under `.github/actions/`, or the
/// repository's own root `action.yml` when the repository IS an action.
fn is_composite_action(path: &str) -> bool {
    path == "action.yml"
        || path == "action.yaml"
        || (path.starts_with(".github/actions/")
            && (path.ends_with("/action.yml") || path.ends_with("/action.yaml")))
}

fn is_shell_script(name: &str) -> bool {
    name.ends_with(".sh") || name.ends_with(".bash")
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `FROM [--platform=…] <image> [AS <name>]` → the image reference.
fn from_image(line: &str) -> Option<&str> {
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("FROM ")
        .or_else(|| rest.strip_prefix("from "))?;
    let mut parts = rest.split_whitespace().filter(|p| !p.starts_with("--"));
    parts.next()
}

/// Audit a Dockerfile's `FROM` lines. A stage alias defined earlier by
/// `AS <name>` is a reference into the same file, not an image; `scratch` is
/// the empty image; a variable is resolved at build time from a pinned
/// `ARG`, which is the same file's concern.
pub fn audit_dockerfile(file: &str, text: &str, findings: &mut Vec<Finding>) {
    let mut stages: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        let Some(image) = from_image(line) else {
            continue;
        };
        let upper = line.to_ascii_uppercase();
        if let Some(idx) = upper.find(" AS ") {
            if let Some(alias) = line[idx + 4..].split_whitespace().next() {
                stages.push(alias.to_string());
            }
        }
        if image == "scratch"
            || image.starts_with('$')
            || image.contains("${")
            || stages.iter().any(|s| s == image)
            || image.contains("@sha256:")
        {
            continue;
        }
        findings.push(Finding::new(
            Severity::Error,
            file,
            format!(
                "`FROM {image}` is not digest-pinned — a tag can move; pin \
                 `{image}@sha256:<digest>` (docker buildx imagetools inspect prints it)"
            ),
        ));
    }
}

/// A shell text is any `run:` body, `RUN` line or committed script.
pub fn audit_shell(file: &str, context: &str, text: &str, findings: &mut Vec<Finding>) {
    let verified = VERIFICATION_MARKERS.iter().any(|m| text.contains(m));
    let mut has_download = false;
    let mut has_chmod_exec = false;

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        // A download whose output is a shell: nothing on disk to verify.
        if piped_to_shell(line) {
            findings.push(Finding::new(
                Severity::Error,
                file,
                format!(
                    "{context}: a download is piped straight into a shell (`{}`) — nothing is \
                     verified before it runs; download to a file, check its digest or signature, \
                     then execute",
                    abbreviate(line)
                ),
            ));
        }
        if is_download(line) {
            has_download = true;
        }
        if line.contains("chmod +x") || line.contains("chmod 0755") || line.contains("chmod 755") {
            has_chmod_exec = true;
        }
        audit_install(file, context, line, findings);
    }

    if has_download && has_chmod_exec && !verified {
        findings.push(Finding::new(
            Severity::Error,
            file,
            format!(
                "{context}: a downloaded file is made executable with no verification step in \
                 between — check a pinned sha256 (`sha256sum --check`), a signature \
                 (`cosign verify-blob`, `gh attestation verify`, `slsa-verifier`) before it runs"
            ),
        ));
    }
}

fn is_download(line: &str) -> bool {
    (line.contains("curl ")
        && (line.contains(" -o ") || line.contains(" -O") || line.contains("--output")))
        || (line.contains("wget ") && !line.contains(" -O-") && !line.contains(" -O -"))
}

/// `curl … | sh`, `wget … | bash`, with or without `sudo`, any of the
/// common shells — the same shape the shipped SAST ruleset flags, checked here
/// so the finding exists without an engine on the machine.
fn piped_to_shell(line: &str) -> bool {
    if !(line.contains("curl ") || line.contains("wget ")) {
        return false;
    }
    let Some(pipe) = line.rfind('|') else {
        return false;
    };
    let after = line[pipe + 1..].trim();
    let after = after.strip_prefix("sudo ").unwrap_or(after);
    let cmd = after.split_whitespace().next().unwrap_or("");
    matches!(
        cmd,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "/bin/sh" | "/bin/bash"
    )
}

fn abbreviate(line: &str) -> String {
    let mut out: String = line.chars().take(80).collect();
    if line.chars().count() > 80 {
        out.push('…');
    }
    out
}

/// Package installs by name in a script. A bare `npm install` (the project's
/// own manifest) is `actions-audit`'s lockfile-exact concern and is NOT
/// counted here, so one line never yields two findings.
fn audit_install(file: &str, context: &str, line: &str, findings: &mut Vec<Finding>) {
    for cmd in line.split("&&").flat_map(|s| s.split(';')) {
        let cmd = cmd.trim();
        let words: Vec<&str> = cmd.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        // pip / pip3 / python -m pip
        let pip_at = words.iter().position(|w| *w == "pip" || *w == "pip3");
        if let Some(i) = pip_at {
            if words.get(i + 1) == Some(&"install") {
                let args: Vec<&str> = words[i + 2..].to_vec();
                if args.contains(&"--require-hashes") {
                    continue;
                }
                if args.iter().any(|a| *a == "-r" || *a == "--requirement") {
                    // The requirements file is the subject; `audit_requirements`
                    // covers committed ones.
                    continue;
                }
                for pkg in args
                    .iter()
                    .filter(|a| !a.starts_with('-') && **a != "." && !a.starts_with("./"))
                {
                    let pkg = pkg.trim_matches('"').trim_matches('\'');
                    if pkg.contains("==") {
                        findings.push(Finding::new(
                            Severity::Warn,
                            file,
                            format!(
                                "{context}: `pip install {pkg}` pins a version, not a hash — \
                                 `--require-hashes` with `--hash=sha256:…` pins the bytes"
                            ),
                        ));
                    } else {
                        findings.push(Finding::new(
                            Severity::Error,
                            file,
                            format!(
                                "{context}: `pip install {pkg}` installs whatever is current — pin \
                                 a version, or better a hash (`--require-hashes`)"
                            ),
                        ));
                    }
                }
            }
            continue;
        }
        // go get / go install
        if words.first() == Some(&"go") && matches!(words.get(1), Some(&"get") | Some(&"install")) {
            for pkg in words[2..]
                .iter()
                .filter(|a| !a.starts_with('-') && !a.starts_with("./") && **a != ".")
            {
                let pinned = pkg
                    .rsplit_once('@')
                    .is_some_and(|(_, v)| v != "latest" && v != "master" && v != "main");
                if !pinned {
                    findings.push(Finding::new(
                        Severity::Error,
                        file,
                        format!(
                            "{context}: `go {} {pkg}` resolves to whatever is current — pin \
                             `{pkg}@v<x.y.z>`",
                            words[1]
                        ),
                    ));
                }
            }
            continue;
        }
        // npm install <pkg> / npm i <pkg>
        if words.first() == Some(&"npm")
            && matches!(words.get(1), Some(&"install") | Some(&"i") | Some(&"add"))
        {
            for pkg in words[2..]
                .iter()
                .filter(|a| !a.starts_with('-') && !a.starts_with('.'))
            {
                // `@scope/name@1.2.3` — the version is after the LAST `@`
                // that is not the leading scope marker.
                let version = pkg[1..].rsplit_once('@').map(|(_, v)| v);
                match version {
                    Some(v) if v.chars().next().is_some_and(|c| c.is_ascii_digit()) => {}
                    Some(v) => findings.push(Finding::new(
                        Severity::Error,
                        file,
                        format!(
                            "{context}: `npm install {pkg}` — `@{v}` is a range or tag, not a \
                             version; pin `name@<x.y.z>`"
                        ),
                    )),
                    None => findings.push(Finding::new(
                        Severity::Error,
                        file,
                        format!(
                            "{context}: `npm install {pkg}` installs whatever is current — pin \
                             `{pkg}@<x.y.z>`"
                        ),
                    )),
                }
            }
        }
    }
}

/// Workflow and composite-action `run:` bodies.
fn audit_yaml_runs(file: &str, text: &str, composite: bool, findings: &mut Vec<Finding>) {
    let Ok(docs) = crate::audit::parse_workflow_yaml(text) else {
        findings.push(Finding::new(
            Severity::Error,
            file,
            "workflow/action YAML unavailable or invalid; run steps were not assessed".into(),
        ));
        return;
    };
    for doc in &docs {
        if composite {
            if let Some(list) = doc["runs"]["steps"].as_vec() {
                for (i, step) in list.iter().enumerate() {
                    if let Some(run) = step["run"].as_str() {
                        audit_shell(file, &format!("step {}", step_name(step, i)), run, findings);
                    }
                }
            }
        } else {
            for (job, jdoc) in jobs(doc) {
                for (i, step) in steps(jdoc).into_iter().enumerate() {
                    if let Some(run) = step["run"].as_str() {
                        audit_shell(
                            file,
                            &format!("job `{job}` step {}", step_name(step, i)),
                            run,
                            findings,
                        );
                    }
                }
            }
        }
    }
}

fn step_name(step: &yaml_rust2::Yaml, i: usize) -> String {
    step["name"]
        .as_str()
        .map(|n| format!("`{n}`"))
        .unwrap_or_else(|| format!("#{}", i + 1))
}

/// Dockerfile `RUN` lines. A backslash-newline is a continuation, so the
/// physical lines are one logical command line — which is how the shell
/// reads them, and how a download on one line and its shell on the next
/// must be read. Commands chained with `&&` or `;` are then split back into
/// their own lines so each is judged on its own, matching a workflow `run:`.
fn audit_dockerfile_runs(file: &str, text: &str, findings: &mut Vec<Finding>) {
    let mut buf = String::new();
    let mut in_run = false;
    for raw in text.lines() {
        let line = raw.trim_end();
        if !in_run {
            let t = line.trim_start();
            if let Some(cmd) = t.strip_prefix("RUN ") {
                in_run = true;
                buf.clear();
                buf.push_str(cmd);
            } else {
                continue;
            }
        } else {
            buf.push(' ');
            buf.push_str(line.trim_start());
        }
        if let Some(stripped) = buf.strip_suffix('\\') {
            buf = stripped.trim_end().to_string();
            continue;
        }
        in_run = false;
        let joined = buf.replace(" && ", "\n").replace("; ", "\n");
        audit_shell(file, "RUN", &joined, findings);
    }
}

/// A committed `requirements*.txt` that pins nothing by hash.
fn audit_requirements(file: &str, text: &str, findings: &mut Vec<Finding>) {
    let specs: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .collect();
    if specs.is_empty() {
        return;
    }
    if text.contains("--hash=") {
        return;
    }
    let unversioned = specs.iter().filter(|s| !s.contains("==")).count();
    if unversioned > 0 {
        findings.push(Finding::new(
            Severity::Error,
            file,
            format!(
                "{unversioned} of {} requirement(s) carry no `==` version and none carry a \
                 `--hash=` — `pip-compile --generate-hashes` pins both",
                specs.len()
            ),
        ));
    } else {
        findings.push(Finding::new(
            Severity::Warn,
            file,
            format!(
                "{} requirement(s) pin versions but no hashes — `pip-compile \
                 --generate-hashes` pins the bytes",
                specs.len()
            ),
        ));
    }
}

/// A manifest and the lockfiles that would pin it. The tuple is (manifest
/// basename, candidate lockfile basenames in the same directory).
const MANIFEST_LOCKS: &[(&str, &[&str])] = &[
    (
        "package.json",
        &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
            "bun.lockb",
        ],
    ),
    ("Cargo.toml", &["Cargo.lock"]),
    (
        "pyproject.toml",
        &[
            "poetry.lock",
            "uv.lock",
            "pdm.lock",
            "Pipfile.lock",
            "requirements.txt",
        ],
    ),
    ("go.mod", &["go.sum"]),
];

/// Root manifests, and nested manifests that are their own root (a nested
/// `Cargo.toml` declaring `[workspace]`), must have a committed lockfile.
/// A crate declaring `[package.metadata] cargo-fuzz = true` is exempt by the
/// tool's own convention: cargo-fuzz ignores `Cargo.lock`, and the crate is
/// never built for release.
fn require_lockfile(
    ctx: &Ctx,
    tracked: &Entries,
    path: &str,
    manifest: &str,
    locks: &[&str],
    content: &str,
    report: &mut PinningReport,
) {
    let dir = path.strip_suffix(manifest).unwrap_or("");
    if manifest == "Cargo.toml" {
        let Some(table) = content.parse::<toml::Table>().ok() else {
            report.findings.push(Finding::new(
                Severity::Error,
                path,
                "invalid Cargo manifest; applicable lockfiles could not be determined".into(),
            ));
            return;
        };
        if table
            .get("package")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("cargo-fuzz"))
            .and_then(toml::Value::as_bool)
            == Some(true)
        {
            report.info.push(format!(
                "{path}: cargo-fuzz crate — no lockfile by the fuzzer's own convention"
            ));
            return;
        }
        if !dir.is_empty() && !table.contains_key("workspace") {
            return; // a workspace member pins through the root lockfile
        }
    } else if !dir.is_empty() {
        return; // v1 scopes non-Cargo manifests to the repository root
    }
    let missing = !locks
        .iter()
        .any(|lock| tracked.contains_key(&format!("{dir}{lock}")));
    let pinned = !missing
        && locks.iter().any(|lock| {
            let relative = format!("{dir}{lock}");
            tracked.get(&relative).is_some_and(|entry| {
                entry.may_open_worktree_path()
                    && entry.blob(&ctx.root).is_ok()
                    && crate::repo_file::read(&ctx.root, Path::new(&relative))
                        .is_ok_and(|bytes| bytes.is_some())
            })
        });
    if !pinned {
        let detail = if missing {
            "has no committed lockfile"
        } else {
            "has no readable regular lockfile in both the Git index and worktree"
        };
        report.findings.push(Finding::new(
            Severity::Error,
            path,
            format!(
                "`{path}` {detail} ({}) — stage a regular lockfile for review",
                locks.join(" / ")
            ),
        ));
    }
}

#[derive(Default)]
struct PinningReport {
    findings: Vec<Finding>,
    info: Vec<String>,
}

impl PinningReport {
    fn unavailable(&mut self, path: &str, layer: &str) {
        self.findings.push(Finding::new(
            Severity::Error,
            path,
            format!(
                "could not read regular tracked evidence from {layer}; this input was not assessed"
            ),
        ));
    }
}

fn audit_file(ctx: &Ctx, tracked: &Entries, path: &str, text: &str, report: &mut PinningReport) {
    let name = basename(path);
    if is_dockerfile(name) {
        audit_dockerfile(path, text, &mut report.findings);
        audit_dockerfile_runs(path, text, &mut report.findings);
    } else if is_workflow(path) {
        audit_yaml_runs(path, text, false, &mut report.findings);
    } else if is_composite_action(path) {
        audit_yaml_runs(path, text, true, &mut report.findings);
    } else if is_shell_script(name) {
        audit_shell(path, "script", text, &mut report.findings);
    } else if name.starts_with("requirements") && name.ends_with(".txt") {
        audit_requirements(path, text, &mut report.findings);
    }
    if let Some((manifest, locks)) = MANIFEST_LOCKS.iter().find(|(m, _)| name == *m) {
        require_lockfile(ctx, tracked, path, manifest, locks, text, report);
    }
}

/// Audit both the exact stage-0 snapshot and corresponding current files.
/// An unreadable blob/checkout is a finding, but does not hide other results.
pub fn audit_repo(ctx: &Ctx) -> Result<(Vec<Finding>, Vec<String>)> {
    let tracked = index_file::index(&ctx.root)?;
    let mut report = PinningReport::default();
    for (path, entry) in &tracked {
        let name = basename(path);
        let manifest = MANIFEST_LOCKS
            .iter()
            .any(|(m, _)| name == *m && (*m == "Cargo.toml" || path == *m));
        if !(is_dockerfile(name)
            || is_workflow(path)
            || is_composite_action(path)
            || is_shell_script(name)
            || (name.starts_with("requirements") && name.ends_with(".txt"))
            || manifest)
        {
            continue;
        }
        let indexed = entry.text(&ctx.root);
        let local = entry
            .may_open_worktree_path()
            .then(|| crate::repo_file::read_text(&ctx.root, Path::new(path)))
            .transpose()
            .map(Option::flatten);
        match &indexed {
            Ok(text) => audit_file(ctx, &tracked, path, text, &mut report),
            Err(_) => report.unavailable(path, "the Git index"),
        }
        match local {
            Ok(Some(text)) if indexed.as_ref().is_ok_and(|other| other == &text) => {}
            Ok(Some(text)) => {
                report.info.push(format!(
                    "{path}: also assessed current worktree bytes (not the indexed snapshot)"
                ));
                let start = report.findings.len();
                audit_file(ctx, &tracked, path, &text, &mut report);
                for finding in &mut report.findings[start..] {
                    finding.message = format!("worktree: {}", finding.message);
                }
            }
            _ => report.unavailable(path, "the worktree"),
        }
    }
    Ok((report.findings, report.info))
}

/// `verify dependency-pinning`.
pub fn verify_dependency_pinning(ctx: &Ctx) -> VerifyResult {
    let id = "dependency-pinning";
    let (findings, info) = match audit_repo(ctx) {
        Ok(r) => r,
        Err(err) => {
            return VerifyResult::degraded(
                id,
                "scan-error",
                vec![format!("could not list tracked files: {err:#}")],
            );
        }
    };
    let mut messages: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "[{}] {}: {}",
                severity_label(&f.severity),
                f.file,
                f.message
            )
        })
        .collect();
    messages.extend(info.iter().map(|i| format!("[info] {i}")));
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    if errors > 0 {
        return VerifyResult::new(id, Outcome::Fail, messages);
    }
    if messages.is_empty() {
        messages.push(
            "base images digest-pinned, downloads checked, installs pinned, lockfiles committed or staged (Git index and worktree)"
                .into(),
        );
    }
    VerifyResult::new(id, Outcome::Pass, messages)
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warn => "warn",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec;

    fn findings_of(f: impl FnOnce(&mut Vec<Finding>)) -> Vec<Finding> {
        let mut v = Vec::new();
        f(&mut v);
        v
    }

    fn errors(v: &[Finding]) -> usize {
        v.iter().filter(|f| f.severity == Severity::Error).count()
    }

    /// ISC-21: a floating tag is a finding.
    #[test]
    fn dockerfile_from_with_a_tag_is_not_pinned() {
        let f =
            findings_of(|v| audit_dockerfile("Dockerfile", "FROM alpine:3.19\nRUN echo hi\n", v));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Error);
        assert!(f[0]
            .message
            .contains("`FROM alpine:3.19` is not digest-pinned"));
        let bare = findings_of(|v| audit_dockerfile("Dockerfile", "FROM ubuntu\n", v));
        assert_eq!(bare.len(), 1);
    }

    /// ISC-22: a digest, a variable, `scratch`, and a stage alias are clean.
    #[test]
    fn dockerfile_from_digest_variable_scratch_and_stage_alias_are_clean() {
        let text = "ARG BASE=alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000\n\
                    FROM --platform=linux/amd64 alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS builder\n\
                    FROM ${BASE}\nFROM $BASE\nFROM scratch\nFROM builder AS final\n";
        let f = findings_of(|v| audit_dockerfile("Dockerfile", text, v));
        assert!(f.is_empty(), "{f:?}");
    }

    /// ISC-24 (a): piped downloads and download-chmod-execute are findings, in
    /// a workflow `run:`, a Dockerfile `RUN`, and a script alike.
    #[test]
    fn piped_and_unverified_downloads_are_findings_everywhere() {
        for (ctx, text) in [
            ("script", "curl -fsSL https://example.com/i | sh\n"),
            ("script", "wget -qO- https://example.com/i | sudo bash\n"),
            (
                "script",
                "curl -fsSL -o tool https://example.com/tool\nchmod +x tool\n./tool\n",
            ),
        ] {
            let f = findings_of(|v| audit_shell("f", ctx, text, v));
            assert!(errors(&f) >= 1, "{text:?} → {f:?}");
        }
        let wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - name: get\n        run: curl -fsSL https://example.com/i | bash\n";
        let f = findings_of(|v| audit_yaml_runs("w.yml", wf, false, v));
        assert_eq!(errors(&f), 1, "{f:?}");
        assert!(f[0].message.contains("job `b` step `get`"));
        let df = "FROM alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111\nRUN curl -fsSL https://example.com/i \\\n    | sh\n";
        let f = findings_of(|v| audit_dockerfile_runs("Dockerfile", df, v));
        assert_eq!(errors(&f), 1, "{f:?}");
    }

    /// ISC-25: a verification step between download and execution — any of
    /// the recognised ones — makes the sequence clean.
    #[test]
    fn verified_downloads_are_clean() {
        for marker in [
            "sha256sum -c SHA256SUMS",
            "echo \"$SUM  tool\" | sha256sum --check --status",
            "cosign verify-blob tool --bundle tool.sigstore.json --certificate-identity x --certificate-oidc-issuer y",
            "gh attestation verify tool --owner acme",
            "slsa-verifier verify-artifact tool --provenance-path p.intoto.jsonl --source-uri github.com/acme/tool",
        ] {
            let text = format!("curl -fsSL -o tool https://example.com/tool\n{marker}\nchmod +x tool\n./tool\n");
            let f = findings_of(|v| audit_shell("f", "script", &text, v));
            assert!(f.is_empty(), "{marker}: {f:?}");
        }
    }

    /// ISC-24 (b): Scorecard's unpinned-install class.
    #[test]
    fn unpinned_installs_are_findings_and_exact_pins_are_not() {
        let text = "pip install requests\npip3 install --require-hashes -r req.txt\n\
                    python3 -m pip install \"semgrep==1.169.0\"\n\
                    go install golang.org/x/tools/cmd/goimports\ngo install golang.org/x/tools/cmd/goimports@latest\n\
                    go install golang.org/x/tools/cmd/goimports@v0.25.0\n\
                    npm install lodash\nnpm install lodash@^4\nnpm install lodash@4.17.21\nnpm install @scope/pkg@1.0.0\n";
        let f = findings_of(|v| audit_shell("f", "script", text, v));
        let msgs: Vec<&str> = f.iter().map(|x| x.message.as_str()).collect();
        assert_eq!(errors(&f), 5, "{msgs:#?}");
        assert!(msgs.iter().any(|m| m.contains("pip install requests")));
        assert!(msgs.iter().any(|m| m.contains("goimports` resolves")));
        assert!(msgs.iter().any(|m| m.contains("goimports@latest")));
        assert!(msgs.iter().any(|m| m.contains("npm install lodash`")));
        assert!(msgs.iter().any(|m| m.contains("lodash@^4")));
        let warns: Vec<&&str> = msgs
            .iter()
            .filter(|m| m.contains("semgrep==1.169.0"))
            .collect();
        assert_eq!(warns.len(), 1, "a version pin is a warning, not a failure");
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::Warn && x.message.contains("semgrep")));
    }

    /// ISC-48: a bare `npm install` is `actions-audit`'s lockfile-exact
    /// finding; this control does not count it again.
    #[test]
    fn bare_npm_install_is_not_counted_here() {
        let f = findings_of(|v| {
            audit_shell(
                "f",
                "script",
                "npm install\nnpm ci\nyarn install --frozen-lockfile\n",
                v,
            )
        });
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn requirements_without_hashes_warn_and_without_versions_fail() {
        let f = findings_of(|v| {
            audit_requirements("requirements.txt", "requests==2.32.3\nurllib3==2.2.2\n", v)
        });
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warn);
        let f = findings_of(|v| {
            audit_requirements("requirements.txt", "requests\nurllib3==2.2.2\n", v)
        });
        assert_eq!(errors(&f), 1);
        let f = findings_of(|v| {
            audit_requirements(
                "requirements.txt",
                "requests==2.32.3 \\\n    --hash=sha256:aaaa\n",
                v,
            )
        });
        assert!(f.is_empty(), "{f:?}");
        assert!(findings_of(|v| audit_requirements("requirements.txt", "# empty\n", v)).is_empty());
    }

    fn repo_with(files: &[(&str, &str)]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        for (path, text) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        exec::git(&["add", "-A"], root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    /// ISC-26: four root manifests with no lockfile → four findings; a
    /// nested workspace `Cargo.toml` counts; a cargo-fuzz crate is Info.
    #[test]
    fn manifests_without_lockfiles_are_findings_and_fuzz_crates_are_info() {
        let (_d, ctx) = repo_with(&[
            ("package.json", "{}"),
            ("Cargo.toml", "[package]\nname = \"x\"\n"),
            ("pyproject.toml", "[project]\nname = \"x\"\n"),
            ("go.mod", "module x\n"),
            ("nested/Cargo.toml", "[workspace]\nmembers = []\n"),
            ("member/Cargo.toml", "[package]\nname = \"m\"\n"),
            (
                "fuzz/Cargo.toml",
                "[package]\nname = \"x-fuzz\"\n\n[package.metadata]\ncargo-fuzz = true\n",
            ),
        ]);
        let (f, info) = audit_repo(&ctx).unwrap();
        let named: Vec<&str> = f.iter().map(|x| x.file.as_str()).collect();
        assert_eq!(errors(&f), 5, "{named:?}");
        for m in [
            "package.json",
            "Cargo.toml",
            "pyproject.toml",
            "go.mod",
            "nested/Cargo.toml",
        ] {
            assert!(named.contains(&m), "missing {m}: {named:?}");
        }
        assert!(
            !named.contains(&"member/Cargo.toml"),
            "a workspace member pins through the root"
        );
        assert_eq!(info.len(), 1);
        assert!(info[0].contains("fuzz/Cargo.toml") && info[0].contains("cargo-fuzz"));

        let (_d, ctx) = repo_with(&[
            ("package.json", "{}"),
            ("bun.lock", "{}"),
            ("Cargo.toml", "[package]\nname = \"x\"\n"),
            ("Cargo.lock", "version = 3\n"),
            ("go.mod", "module x\n"),
            ("go.sum", ""),
            ("pyproject.toml", "[project]\n"),
            ("uv.lock", ""),
        ]);
        let (f, info) = audit_repo(&ctx).unwrap();
        assert!(f.is_empty() && info.is_empty(), "{f:?}");
    }

    /// The control's own verdict shape, end to end on a small repo.
    #[test]
    fn verify_dependency_pinning_fails_on_errors_and_passes_clean() {
        let (_d, ctx) = repo_with(&[
            ("Dockerfile", "FROM alpine:3.19\n"),
            ("Cargo.toml", "[package]\nname = \"x\"\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let r = verify_dependency_pinning(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(r.messages[0].starts_with("[error] Dockerfile:"));

        let (_d, ctx) = repo_with(&[
            ("Dockerfile", "FROM alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"),
            ("scripts/get.sh", "#!/bin/sh\ncurl -fsSL -o t https://example.com/t\nsha256sum --check t.sha256\nchmod +x t\n"),
            ("Cargo.toml", "[package]\nname = \"x\"\n"),
            ("Cargo.lock", "version = 3\n"),
            ("fuzz/Cargo.toml", "[package]\nname = \"f\"\n[package.metadata]\ncargo-fuzz = true\n"),
        ]);
        let r = verify_dependency_pinning(&ctx);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert_eq!(r.messages.len(), 1);
        assert!(r.messages[0].contains("[info] fuzz/Cargo.toml"));
    }

    #[test]
    fn tracked_evidence_checks_both_layers_and_keeps_other_findings() {
        let (_dir, ctx) = repo_with(&[
            ("Dockerfile", "FROM alpine:3.19\n"),
            ("Cargo.toml", "[package]\nname = \"demo\"\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        std::fs::write(ctx.root.join("Dockerfile"), "FROM scratch\n").unwrap();
        std::fs::remove_file(ctx.root.join("Cargo.lock")).unwrap();
        let result = verify_dependency_pinning(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("not digest-pinned")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("no readable regular lockfile")));
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("also assessed current worktree")));
    }

    #[test]
    fn malformed_yaml_is_not_a_clean_pinning_result() {
        let (_dir, ctx) = repo_with(&[(".github/workflows/ci.yml", "jobs: [\n")]);
        let result = verify_dependency_pinning(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("YAML unavailable or invalid")));
    }

    #[test]
    #[cfg(unix)]
    fn linked_tracked_inputs_cannot_stand_in_for_regular_evidence() {
        let (_dir, ctx) = repo_with(&[
            ("Dockerfile", "FROM scratch\n"),
            ("Cargo.toml", "[package]\nname = \"demo\"\n"),
            ("Cargo.lock", "version = 3\n"),
            ("inert.txt", "FROM scratch\n"),
        ]);
        std::fs::remove_file(ctx.root.join("Dockerfile")).unwrap();
        std::os::unix::fs::symlink("inert.txt", ctx.root.join("Dockerfile")).unwrap();
        exec::git(&["add", "Dockerfile"], &ctx.root).unwrap();
        let result = verify_dependency_pinning(&ctx);
        assert_eq!(result.outcome, Outcome::Fail);
        assert!(result
            .messages
            .iter()
            .any(|m| m.contains("Dockerfile") && m.contains("Git index")));
    }

    /// The verification most workflows actually write — compute the digest,
    /// compare it to a pinned constant — counts, in every spelling.
    #[test]
    fn an_explicit_digest_comparison_is_a_verification() {
        for check in [
            "actual=\"$(sha256sum tool | cut -d' ' -f1)\"; [ \"$actual\" = \"$PINNED\" ] || exit 1",
            "test \"$(shasum -a 256 tool | awk '{print $1}')\" = \"$PINNED\"",
            "openssl dgst -sha256 tool | grep -q \"$PINNED\"",
        ] {
            let text =
                format!("curl -fsSL -o tool https://example.com/tool\n{check}\nchmod 0755 tool\n");
            let f = findings_of(|v| audit_shell("f", "script", &text, v));
            assert!(f.is_empty(), "{check}: {f:?}");
        }
    }

    /// A repository that IS an action carries its steps in a root
    /// `action.yml`; those `run:` bodies are subjects too.
    #[test]
    fn a_root_action_yml_is_scanned_as_a_composite_action() {
        let (_d, ctx) = repo_with(&[(
            "action.yml",
            "name: x\nruns:\n  using: composite\n  steps:\n    - name: fetch\n      shell: bash\n      run: |\n        curl -fsSL -o tool https://example.com/tool\n        chmod +x tool\n",
        )]);
        let r = verify_dependency_pinning(&ctx);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        assert!(r.messages[0].contains("action.yml: step `fetch`"));
    }

    #[test]
    fn a_repo_with_nothing_to_pin_passes_with_the_summary_line() {
        let (_d, ctx) = repo_with(&[("README.md", "hi\n")]);
        let r = verify_dependency_pinning(&ctx);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(r.messages[0].contains("lockfiles committed"));
    }
}
