//! Bumblebee — developer-endpoint exposure scanning.
//!
//! Every other phase-2 control asks a question about the *repository*: what does
//! it depend on, is that dependency vulnerable, does that package even exist.
//! Bumblebee asks a question about the *machine the work happens on*: is anything
//! installed here — an npm package, a Python dist, an MCP server, an editor
//! extension, a browser extension, an agent skill — that appears in a catalog of
//! known-compromised releases.
//!
//! That surface is where the 2024-2026 worm campaigns actually land, and nothing
//! else in the registry looks at it.
//!
//! ## Tool contract (established empirically against bumblebee v0.1.2, not from docs)
//!
//! Four behaviours drive this implementation and none of them are guessable:
//!
//! 1. **Findings do not change the exit code.** A scan that matches a compromised
//!    package exits `0`, exactly like a clean one; `2` means the scan itself
//!    errored (bad catalog, unreadable root). Gating on `$?` would produce a
//!    control that passes through every compromise it detects — the same trap
//!    `sast.rs` documents for opengrep. We parse the record stream instead.
//! 2. **The shipped binary accepts exposure-catalog `schema_version` `"0.1.0"`
//!    only.** The project README documents `"0.2.0"`; feeding that to v0.1.2
//!    fails with `unsupported exposure catalog schema_version`. We surface the
//!    tool's own stderr rather than translating it, so the user sees the truth.
//! 3. **`versions: ["*"]` does not match in v0.1.2.** Wildcards are a documented
//!    `0.2.0`-schema feature; the shipped matcher is exact
//!    `(ecosystem, normalized_name, version)`. A catalog written from the README
//!    therefore matches nothing — a gate that always passes. `sscsb` cannot fix
//!    the matcher, so `count_catalog_entries` refuses to count a wildcard-only
//!    entry as criteria and the run fails before it can report a false clean.
//! 4. **What the scan could not read is reported ONLY on stderr, and only there.**
//!    stdout carries `finding` and `scan_summary` records; `record_type=diagnostic`
//!    rows go to stderr as NDJSON with a `level`, an optional `path`, and a
//!    `message`. A config bumblebee cannot parse produces
//!    `{"level":"warn","path":"…/mcp_config.json","message":"parse MCP config:
//!    unexpected end of JSON input"}` there — while the run still exits `0` and
//!    emits a `status:"complete"` summary. Reading stdout alone therefore turns a
//!    dropped subject into silence inside a PASS, so `parse_diagnostics` reads
//!    stderr on every run, not just failed ones. Fatal errors arrive on the same
//!    stream as bare non-JSON text (`unsupported exposure catalog
//!    schema_version …`), so the parser keeps unrecognised lines rather than
//!    dropping them.
//!
//! ## Four ways a bumblebee run can be empty, none of which mean "clean"
//!
//! Every one of these produces zero findings and, in three cases, exit 0 and a
//! well-formed summary. Each is refused explicitly rather than passed:
//!
//! - **No criteria.** The catalog is an empty directory, has `entries: []`, or
//!   contains only unmatchable wildcard entries. Verified: an empty catalog
//!   directory scanned 364,119 files and reported `findings=0`, exit 0.
//! - **No subjects.** The scan inventoried zero artifacts — what `profile =
//!   "project"` does to a repository with no npm/pypi/go/gem/composer manifests,
//!   which includes every Rust repository. `package_records_emitted +
//!   package_records_suppressed == 0` is the signal.
//! - **No subjects OF THE RIGHT CLASS.** `inventoried` is a single aggregate, so
//!   a machine whose only populated root is the Homebrew Cellar clears the guard
//!   above with 16,912 receipts while every class this control exists for — MCP
//!   configs, editor extensions, browser extensions, agent skills — went
//!   unexamined. `--findings-only` suppresses the per-package records, so the
//!   summary's `roots[].kind` list is the only per-class signal there is.
//! - **No completion.** The run timed out or ended with a non-`complete`
//!   `status`. A summary record alone is not proof of a finished scan; the
//!   summary's own `status` and `timed_out` fields are.
//!
//! A scanner that reports clean without having scanned is worse than no scanner,
//! so `Outcome::Pass` requires criteria, subjects of the classes this control is
//! for, and completion together.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::tools;

const CONTROL: &str = "bumblebee";

/// A `record_type=finding` row: one installed artifact matching one catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    pub catalog_id: String,
    pub severity: String,
    pub package: String,
    pub version: String,
    pub ecosystem: String,
}

/// Outcome of reading a bumblebee NDJSON record stream.
#[derive(Debug, Default)]
pub struct ScanRecords {
    pub exposures: Vec<Exposure>,
    /// Did the run finish? Not merely "was a summary emitted" — the summary
    /// itself reports `status` and `timed_out`, and a run that hit its
    /// `--max-duration` still emits a well-formed summary. Only
    /// `status == "complete"` with `timed_out == false` licenses a clean report.
    pub completed: bool,
    /// Verbatim `status` from the summary, for the message when it is not
    /// `complete`.
    pub status: Option<String>,
    pub timed_out: bool,
    /// How many artifacts the scan actually inventoried
    /// (`package_records_emitted + package_records_suppressed`). Under
    /// `--findings-only` — which this control always passes — packages are
    /// suppressed rather than emitted, so the suppressed counter is the real
    /// one. NOTE: the summary's `counts.package` reads 0 even when 148 packages
    /// were inventoried, so it must not be used here.
    ///
    /// Zero means the scan matched the catalog against nothing at all.
    pub inventoried: u64,
    /// The `kind` of every root the scan actually reached, deduplicated in
    /// first-seen order — `mcp_config_root`, `editor_extension_root`,
    /// `browser_extension_root`, `agent_skill_root`, `homebrew_root`,
    /// `user_package_root`, or `project_root`.
    ///
    /// This is the ONLY per-class signal bumblebee emits. Under `--findings-only`
    /// package records are suppressed rather than printed, so nothing in the
    /// stream says which ecosystem the inventory came from, and the summary's own
    /// `counts` are aggregates. `inventoried` is therefore one number that 16,912
    /// Homebrew receipts satisfy on their own — which is why a guard built on it
    /// alone cannot tell "scanned the endpoint" from "counted the Cellar".
    pub root_kinds: Vec<String>,
    /// Lines in the parsed stream that were not valid JSON. bumblebee writes its
    /// diagnostics to **stderr**, not into this stream, so a malformed line here
    /// is genuinely unexpected rather than routine — it is counted and surfaced.
    pub unparsable_lines: usize,
}

/// Parse a bumblebee NDJSON stream.
///
/// Lenient per line, strict in aggregate. An individual unreadable line is
/// counted rather than aborting the parse, so one malformed record cannot hide
/// the findings around it — but leniency never becomes permission: `completed`
/// is driven by the summary's own `status`/`timed_out`, and the caller refuses
/// `Pass` unless the run finished AND inventoried something.
///
/// Note that bumblebee writes its diagnostics to **stderr**, not into this
/// stream, so unparsable lines here are genuinely unexpected rather than routine.
pub fn parse_records(ndjson: &str) -> ScanRecords {
    let mut out = ScanRecords::default();
    for line in ndjson.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            out.unparsable_lines += 1;
            continue;
        };
        match v.get("record_type").and_then(|x| x.as_str()) {
            Some("finding") => out.exposures.push(Exposure {
                catalog_id: str_field(&v, "catalog_id"),
                severity: str_field(&v, "severity"),
                package: str_field(&v, "package_name"),
                version: str_field(&v, "version"),
                ecosystem: str_field(&v, "ecosystem"),
            }),
            Some("scan_summary") => {
                let status = v.get("status").and_then(|x| x.as_str()).map(str::to_string);
                out.timed_out = v
                    .get("timed_out")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                // A summary exists for timed-out and partial runs too; only an
                // explicitly complete, non-truncated run counts as finished.
                out.completed = status.as_deref() == Some("complete") && !out.timed_out;
                out.status = status;
                let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
                out.inventoried = n("package_records_emitted") + n("package_records_suppressed");
                for kind in v
                    .get("roots")
                    .and_then(|x| x.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.get("kind").and_then(|k| k.as_str()))
                {
                    if !out.root_kinds.iter().any(|k| k == kind) {
                        out.root_kinds.push(kind.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string()
}

/// A `record_type=diagnostic` row. bumblebee writes these to **stderr**, one
/// NDJSON object per line, and they are the only place it says what it could
/// NOT read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: String,
    /// The file the diagnostic is about, when it names one.
    pub path: Option<String>,
    pub message: String,
}

impl Diagnostic {
    /// Does this diagnostic report something the scan could not do?
    ///
    /// `info` is bookkeeping — "default roots: 19 present, 85 candidate paths
    /// absent", "scan complete: …", "no MCP servers parsed" — and appears on
    /// every run. Anything above it is bumblebee reporting that a subject it was
    /// asked to examine was dropped. Measured on a real v0.1.2 `baseline` run
    /// over 464,986 files and 19 roots: 3 diagnostics, of which exactly one was
    /// `warn`, and it named a genuinely malformed file. Non-`info` is rare, and
    /// when it fires it means something.
    fn is_problem(&self) -> bool {
        !matches!(self.level.as_str(), "info" | "debug" | "trace" | "")
    }

    fn render(&self) -> String {
        match &self.path {
            Some(p) => format!("{}: {p} — {}", self.level, self.message),
            None => format!("{}: {}", self.level, self.message),
        }
    }
}

/// What bumblebee said on stderr.
#[derive(Debug, Default)]
pub struct Diagnostics {
    pub entries: Vec<Diagnostic>,
    /// stderr lines that are not diagnostic records. bumblebee's fatal errors
    /// arrive this way — a `schema_version` rejection is the bare line
    /// `unsupported exposure catalog schema_version "0.2.0" (supported: "0.1.0")`
    /// with no JSON around it — as would a runtime panic. Kept verbatim so the
    /// tool's own words reach the user rather than our paraphrase of them.
    pub plain: Vec<String>,
}

impl Diagnostics {
    fn problems(&self) -> Vec<&Diagnostic> {
        self.entries.iter().filter(|d| d.is_problem()).collect()
    }

    fn informational(&self) -> usize {
        self.entries.iter().filter(|d| !d.is_problem()).count()
    }
}

/// Parse bumblebee's stderr stream.
///
/// Exists because the exit code and the stdout record stream together do not
/// carry everything the tool established: a config it could not parse is
/// reported ONLY here, at `warn`, and the run still exits 0 with a well-formed
/// `complete` summary. Reading stdout alone therefore turns "I could not read
/// this MCP config" into silence inside a PASS.
///
/// Tolerant by construction: a line that is not a diagnostic record — valid JSON
/// or not — is kept as `plain` rather than dropped, because the one thing this
/// function must never do is lose output.
pub fn parse_diagnostics(stderr: &str) -> Diagnostics {
    let mut out = Diagnostics::default();
    for line in stderr.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .filter(|v| v.get("record_type").and_then(|x| x.as_str()) == Some("diagnostic"));
        match record {
            Some(v) => out.entries.push(Diagnostic {
                level: v
                    .get("level")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                path: v.get("path").and_then(|x| x.as_str()).map(str::to_string),
                message: v
                    .get("message")
                    .and_then(|x| x.as_str())
                    .unwrap_or("(no message)")
                    .to_string(),
            }),
            None => out.plain.push(line.to_string()),
        }
    }
    out
}

/// How many exposure entries does this catalog path actually resolve to?
///
/// This exists because of a failure mode that is invisible from the outside: an
/// exposure catalog that is an **empty directory** — or a directory whose
/// `*.json` files declare no entries — makes bumblebee exit `0` and emit a
/// perfectly well-formed `scan_summary` with `findings=0`. Verified against
/// v0.1.2: an empty catalog directory scanned 364,119 files and reported
/// `records=0 findings=0`, exit 0.
///
/// Nothing in the record stream distinguishes "checked 40,000 packages against
/// 900 known compromises and found none" from "checked them against nothing at
/// all". Both are zero findings and a clean summary. Reporting the second as
/// PASS would be the control asserting safety it never established, so the
/// entry count is established here, before the scan result is trusted.
///
/// Mirrors bumblebee's own resolution: a file is read directly; a directory is
/// merged **non-recursively** over its `*.json` children.
fn count_catalog_entries(path: &std::path::Path) -> std::io::Result<usize> {
    /// v0.1.2 matches versions by exact string equality, so `"*"` is a literal
    /// that can never equal an installed version. An entry whose versions are
    /// all wildcards therefore carries no matching criteria — and since the
    /// upstream README documents `["*"]` as "match all versions", it is the
    /// *default authoring mistake*, not an exotic one. Counting it as a usable
    /// entry would let a README-written catalog clear the zero-entry guard and
    /// report a confident PASS having matched nothing.
    ///
    /// Only the literal `*` is rejected. Broader "looks non-exact" detection
    /// (`^1.0`, `1.x`, `>=1.0`) would produce false failures on valid catalogs:
    /// real installed versions include `0.1.2_1` (homebrew), `v1.2.3` (go) and
    /// `1.0.0-beta.1` (npm).
    fn has_matchable_version(entry: &serde_json::Value) -> bool {
        match entry.get("versions").and_then(|v| v.as_array()) {
            // Absent or empty `versions` is rejected by bumblebee itself with
            // exit 2 and a precise message. Keep counting those as usable so the
            // tool's own error surfaces through the exit-status branch rather
            // than being masked by our "0 usable entries" message.
            None => true,
            Some(vs) if vs.is_empty() => true,
            Some(vs) => vs
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.trim() != "*")),
        }
    }

    fn entries_in(file: &std::path::Path) -> usize {
        let Ok(text) = std::fs::read_to_string(file) else {
            return 0;
        };
        serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("entries")
                    .and_then(|e| e.as_array())
                    .map(|es| es.iter().filter(|e| has_matchable_version(e)).count())
            })
            .unwrap_or(0)
    }

    if path.is_dir() {
        let mut total = 0;
        for entry in std::fs::read_dir(path)? {
            let p = entry?.path();
            if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("json") {
                total += entries_in(&p);
            }
        }
        Ok(total)
    } else {
        Ok(entries_in(path))
    }
}

/// The registry's declared default for `[controls.bumblebee] profile` — the
/// value `sscsb init` actually writes into `.sscsb/config.toml`.
///
/// Read from the registry rather than repeated as a literal because a hard-coded
/// second copy is exactly how the two drifted apart: the registry said
/// `"baseline"` while the code fell back to `"project"`, so the same control
/// scanned two different things depending on whether the config key happened to
/// be present. One source, one default.
///
/// The match arm is not redundant with `trim_matches`: it keeps an unrecognised
/// registry value from becoming a profile bumblebee would reject, and preserves
/// the never-widen rule below as the failure mode.
fn registry_default_profile() -> &'static str {
    crate::controls::control(CONTROL)
        .and_then(|d| d.default_options.iter().find(|(k, _)| *k == "profile"))
        .map(|(_, v)| v.trim_matches('"'))
        .and_then(|v| match v {
            "baseline" => Some("baseline"),
            "project" => Some("project"),
            _ => None,
        })
        .unwrap_or("project")
}

/// Scan profile, validated against what v0.1.2 actually accepts.
///
/// `deep` is deliberately NOT reachable from config: it requires explicit
/// `--root` paths and is the mode that walks `$HOME`. Scanning a developer's
/// entire home directory is a decision for the developer at a shell prompt, not
/// something a repository bootstrapper turns on from a config file it generated.
/// Anything *named* but unrecognised — including an attempt to name `deep` —
/// narrows to the repo-scoped profile, so config can never widen the blast
/// radius.
///
/// An ABSENT (or blank) option is not an unrecognised one: nobody chose
/// anything, so the registry default applies — the same value the generated
/// config carries. Conflating the two is what made the default disagree with
/// itself.
///
/// Takes the raw option rather than a `Config` so the allow-list is testable
/// without materialising a config file.
fn profile_from(opt: Option<&str>) -> &'static str {
    match opt.map(str::trim) {
        None | Some("") => registry_default_profile(),
        Some("baseline") => "baseline",
        _ => "project",
    }
}

/// No catalog means no exposure criteria, which means no gate is possible.
/// Report that plainly as Info: an inventory with nothing to match against is
/// useful context, but it is not a passing security control and must not be
/// dressed up as one.
///
/// Pure, so the hint it prints is testable without a `bumblebee` on PATH — the
/// hint named the wrong profile for as long as nothing could check it.
fn no_catalog_result(version: &str) -> VerifyResult {
    VerifyResult::new(
        CONTROL,
        Outcome::Info,
        vec![
            format!("bumblebee {version} available; no exposure catalog configured"),
            // `sscsb init` will not backfill options into a config that already
            // exists, and `sscsb enable` writes only `enabled`. So a user who
            // turns this control on may have no `catalog` key to edit — spell
            // the whole block out rather than naming a key that isn't there.
            //
            // The profile printed here is read from the registry, not typed in:
            // this hint used to say `project`, the opposite of what the generated
            // config says and of what this control needs.
            format!(
                "add to .sscsb/config.toml:  [controls.bumblebee]  profile = \"{}\"  \
                 catalog = \"path/to/catalog.json\"",
                registry_default_profile()
            ),
            "catalogs must use schema_version \"0.1.0\" and exact versions \
             (wildcards do not match in v0.1.2) — upstream publishes them under threat_intel/"
                .into(),
            "inventory-only: nothing to match against, so no exposure gate is applied".into(),
        ],
    )
}

pub fn verify_bumblebee_control(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let version = match tools::detect(tools::spec(CONTROL).expect("registry")) {
        tools::ToolStatus::Found { version, .. } => {
            version.unwrap_or_else(|| "version unknown".into())
        }
        tools::ToolStatus::Missing => {
            return VerifyResult::new(
                CONTROL,
                Outcome::Degraded,
                vec![tools::degrade_message(CONTROL, ctx.platform)],
            )
        }
    };

    let catalog = cfg
        .control_opt_str(CONTROL, "catalog")
        .unwrap_or_default()
        .trim()
        .to_string();

    if catalog.is_empty() {
        return no_catalog_result(&version);
    }

    match plan_scan(
        &ctx.root,
        &catalog,
        cfg.control_opt_str(CONTROL, "profile").as_deref(),
    ) {
        Err(refusal) => refusal,
        Ok(plan) => {
            let mut args: Vec<&str> = vec![
                "scan",
                "--profile",
                plan.profile,
                "--exposure-catalog",
                &plan.catalog_arg,
                "--findings-only",
            ];
            // NOTE: --root REPLACES the profile's roots, it does not narrow them
            // (bumblebee's own help: "use --root to override"). For `project` that
            // is the intent — scope the scan to this repository. For `baseline` it
            // would destroy the very roots the control exists to read (MCP configs,
            // editor and browser extensions, agent skills, Homebrew receipts), so
            // --root is never passed there.
            if plan.profile == "project" {
                args.push("--root");
                args.push(&plan.root);
            }

            match exec::run(CONTROL, &args, Some(&ctx.root)) {
                Err(e) => VerifyResult::new(
                    CONTROL,
                    Outcome::Fail,
                    vec![format!("bumblebee scan could not be executed: {e:#}")],
                ),
                Ok(out) => evaluate_scan(
                    &version,
                    plan.profile,
                    &catalog,
                    plan.coerced.as_deref(),
                    &out,
                ),
            }
        }
    }
}

/// Everything decided before the scan runs.
#[derive(Debug)]
pub struct ScanPlan {
    pub profile: &'static str,
    pub catalog_arg: String,
    pub root: String,
    /// Set when config named a profile we did not recognise and narrowed it.
    pub coerced: Option<String>,
}

/// Decide whether a scan should run at all, and with what arguments.
///
/// `Err(VerifyResult)` is a refusal: a reason the scan must not be trusted even
/// though bumblebee would happily exit 0. Reads the filesystem (catalog
/// existence and entry count) but touches no PATH and spawns no subprocess, so
/// every refusal is reachable in a test with nothing but a tempdir.
pub fn plan_scan(
    root: &std::path::Path,
    catalog: &str,
    profile_opt: Option<&str>,
) -> std::result::Result<ScanPlan, VerifyResult> {
    let refuse = |messages: Vec<String>| VerifyResult::new(CONTROL, Outcome::Fail, messages);

    let catalog_path = root.join(catalog);
    let catalog_arg = if catalog_path.exists() {
        catalog_path.display().to_string()
    } else {
        catalog.to_string()
    };

    // A catalog that resolves to zero usable entries makes every scan
    // tautologically clean. Refuse before running rather than reporting the empty
    // result as a pass. (A path that does not exist at all is caught by the tool
    // itself with exit 2 and handled in `evaluate_scan`.)
    let resolved = std::path::Path::new(&catalog_arg);
    if resolved.exists() {
        match count_catalog_entries(resolved) {
            Ok(0) => {
                return Err(refuse(vec![
                    format!("exposure catalog `{catalog}` resolved to 0 usable entries"),
                    "bumblebee exits 0 and reports a clean scan against a catalog with no \
                     criteria — that is a scan that checked nothing, not a clean endpoint"
                        .into(),
                    "entries whose only versions are \"*\" match nothing: v0.1.2 matches \
                     exact (ecosystem, name, version), so the README's wildcard syntax \
                     silently never fires"
                        .into(),
                    "check the catalog has a non-empty `entries` array with concrete \
                     versions and schema_version \"0.1.0\"; a directory is merged \
                     non-recursively over its *.json children"
                        .into(),
                ]));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(refuse(vec![format!(
                    "exposure catalog `{catalog}` could not be read: {e}"
                )]));
            }
        }
    }

    let profile = profile_from(profile_opt);
    // Silently coercing an unrecognised profile would hide a config typo behind a
    // narrower scan that then reports clean. Name it instead.
    let coerced = profile_opt
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != profile)
        .map(str::to_string);

    let root_str = root.display().to_string();
    // bumblebee declares --root as "repeatable or comma-separated", so a comma
    // anywhere in the repository path is parsed as a root separator and the scan
    // silently targets paths that do not exist. There is no escaping syntax, so
    // refuse rather than scan the wrong thing and call it clean.
    if profile == "project" && root_str.contains(',') {
        return Err(refuse(vec![
            format!("repository path contains a comma and cannot be passed as --root: {root_str}"),
            "bumblebee treats commas in --root as separators, so this path would be split \
             into roots that do not exist and the scan would examine nothing"
                .into(),
            "set profile = \"baseline\" in [controls.bumblebee] (which needs no --root), \
             or move the repository to a path without a comma"
                .into(),
        ]));
    }

    Ok(ScanPlan {
        profile,
        catalog_arg,
        root: root_str,
        coerced,
    })
}

/// The root classes this control exists for — the surface nothing else in the
/// registry looks at. Keys are bumblebee's own `roots[].kind` values, read off a
/// real v0.1.2 `baseline` summary; values are what to call them in a report.
///
/// Deliberately excludes `homebrew_root`, `user_package_root` and `project_root`:
/// those are package inventories, which `vuln-scan`, `package-trust` and the SBOM
/// controls already cover from the repository side. A scan that reached only
/// those has not looked at the endpoint.
const ENDPOINT_ROOT_KINDS: &[(&str, &str)] = &[
    ("mcp_config_root", "MCP server configs"),
    ("editor_extension_root", "editor extensions"),
    ("browser_extension_root", "browser extensions"),
    ("agent_skill_root", "agent skills"),
];

/// Which of the endpoint classes did this scan actually reach?
fn endpoint_classes_reached(root_kinds: &[String]) -> Vec<&'static str> {
    ENDPOINT_ROOT_KINDS
        .iter()
        .filter(|(kind, _)| root_kinds.iter().any(|k| k == kind))
        .map(|(_, label)| *label)
        .collect()
}

/// Turn a finished bumblebee invocation into an outcome.
///
/// Split out from `verify_bumblebee_control` deliberately: every decision that
/// matters lives here and none of it touches the filesystem, PATH, or a
/// subprocess, so it is testable by construction. The repo's `with_fake_tool`
/// harness mutates the process-global `PATH` under a mutex, which races against
/// any sibling test that reads PATH without taking that mutex — and on a machine
/// where the real `bumblebee` is installed, losing that race silently swaps the
/// fake for the real binary. Rather than ship tests that flake, the policy is
/// exercised directly and only the thin detect-and-exec wrapper above is left to
/// the end-to-end checks against the real binary.
fn evaluate_scan(
    version: &str,
    prof: &str,
    catalog: &str,
    coerced: Option<&str>,
    out: &exec::CmdOutput,
) -> VerifyResult {
    // Exit 2 is a scan error (unsupported catalog schema, unreadable root). The
    // tool's own stderr is more precise than anything we could synthesise, so it
    // is passed through rather than summarised.
    if !out.success() {
        let detail = out.stderr.trim();
        return VerifyResult::new(
            CONTROL,
            Outcome::Fail,
            vec![
                format!("bumblebee scan failed (exit {})", out.status),
                if detail.is_empty() {
                    "no stderr output".into()
                } else {
                    detail.lines().take(3).collect::<Vec<_>>().join(" / ")
                },
            ],
        );
    }

    let mut result = evaluate_records(version, prof, catalog, coerced, out);
    apply_diagnostics(&mut result, &parse_diagnostics(&out.stderr));
    result
}

/// The stdout half of the verdict: everything decidable from the record stream.
fn evaluate_records(
    version: &str,
    prof: &str,
    catalog: &str,
    coerced: Option<&str>,
    out: &exec::CmdOutput,
) -> VerifyResult {
    let records = parse_records(&out.stdout);

    // A run that did not finish did not establish anything. Empty findings from a
    // truncated or timed-out scan look identical to a clean machine.
    if !records.completed {
        let mut messages = vec![
            match (&records.status, records.timed_out) {
                (_, true) => {
                    "bumblebee scan TIMED OUT — partial results cannot be called clean".to_string()
                }
                (Some(s), _) => format!("bumblebee scan ended with status `{s}`, not `complete`"),
                (None, _) => {
                    "bumblebee produced no scan_summary record — the scan did not demonstrably \
                     complete"
                        .to_string()
                }
            },
            "refusing to report clean on a scan that cannot be shown to have finished".to_string(),
        ];
        if records.unparsable_lines > 0 {
            messages.push(format!(
                "{} unparsable output line(s)",
                records.unparsable_lines
            ));
        }
        return VerifyResult::new(CONTROL, Outcome::Fail, messages);
    }

    // The symmetric twin of the empty-catalog case: a scan that inventoried
    // nothing matched the catalog against nothing. This is what the `project`
    // profile does to a repository with no npm/pypi/go/gem/composer manifests —
    // including every Rust repository, since bumblebee has no cargo ecosystem —
    // and it would otherwise assert endpoint cleanliness having examined zero
    // artifacts.
    if records.inventoried == 0 {
        return VerifyResult::new(
            CONTROL,
            Outcome::Fail,
            vec![
                format!(
                    "bumblebee inventoried 0 artifacts under profile `{prof}` — the catalog was \
                     matched against nothing"
                ),
                "a scan with no subjects is not a clean endpoint, the same way an empty catalog \
                 is not a clean scan"
                    .into(),
                "set profile = \"baseline\" in [controls.bumblebee] to reach the endpoint roots \
                 this control covers (MCP configs, editor and browser extensions, agent skills, \
                 Homebrew receipts)"
                    .into(),
            ],
        );
    }

    if records.exposures.is_empty() {
        // The class-aware half of the "did this scan actually look?" question.
        // `inventoried` is one aggregate number, so a machine whose only populated
        // root was the Homebrew Cellar satisfied the zero-subject guard above and
        // then reported a clean ENDPOINT — having never opened an MCP config, an
        // editor or browser extension, or an agent skill. Those four classes are
        // the entire reason this control exists; nothing else in the registry
        // looks at them, so a clean verdict that never reached one of them is
        // claiming more than it checked.
        let reached = endpoint_classes_reached(&records.root_kinds);
        let mut messages = vec![format!(
            "bumblebee {version}: {} artifact(s) inventoried, no known-compromised packages found \
             (profile {prof}, catalog {catalog})",
            records.inventoried
        )];
        let outcome = if reached.is_empty() {
            let missing: Vec<&str> = ENDPOINT_ROOT_KINDS.iter().map(|(_, l)| *l).collect();
            messages.push(format!(
                "scan reached no {} — nothing was established about the artifact classes this \
                 control exists to check; the inventory above is packages only",
                missing.join(", ")
            ));
            messages.push(format!(
                "roots reached: {}",
                if records.root_kinds.is_empty() {
                    "none reported".to_string()
                } else {
                    records.root_kinds.join(", ")
                }
            ));
            if prof == "project" {
                // Fixable from config, so it degrades rather than merely
                // informing: `--strict` should catch a control pointed at the
                // wrong surface.
                messages.push(
                    "profile `project` scopes the scan to this repository, where none of those \
                     roots live — set profile = \"baseline\" in [controls.bumblebee]"
                        .into(),
                );
                Outcome::Degraded
            } else {
                // Nothing to fix: this endpoint genuinely has none of those roots.
                // Say so plainly instead of failing a build over it.
                messages.push(
                    "none of those roots are present on this endpoint, so this run verified \
                     installed packages only"
                        .into(),
                );
                Outcome::Info
            }
        } else {
            messages.push(format!("endpoint classes covered: {}", reached.join(", ")));
            Outcome::Pass
        };
        if let Some(c) = &coerced {
            messages.push(format!(
                "note: unrecognised profile `{c}` was treated as `{prof}`"
            ));
        }
        if records.unparsable_lines > 0 {
            messages.push(format!(
                "note: {} unparsable output line(s)",
                records.unparsable_lines
            ));
        }
        return VerifyResult::new(CONTROL, outcome, messages);
    }

    let mut messages = vec![format!(
        "{} known-compromised artifact(s) present on this endpoint",
        records.exposures.len()
    )];
    for e in records.exposures.iter().take(20) {
        messages.push(format!(
            "{}: {} {} ({}) — catalog {}",
            e.severity, e.package, e.version, e.ecosystem, e.catalog_id
        ));
    }
    if records.exposures.len() > 20 {
        messages.push(format!("… and {} more", records.exposures.len() - 20));
    }
    VerifyResult::new(CONTROL, Outcome::Fail, messages)
}

/// How many problem diagnostics are spelled out before the rest are counted.
const DIAGNOSTIC_LIMIT: usize = 10;

/// Fold what bumblebee said on stderr into the verdict the record stream
/// produced.
///
/// The stderr stream was previously read only when the exit code was non-zero,
/// which discarded it on every successful run — and a successful run is exactly
/// where it matters, because a subject bumblebee could not read is reported
/// there at `warn` while the run still exits 0 and emits a `complete` summary.
/// Observed on a real machine: a malformed MCP config was dropped from the scan
/// and the control reported PASS.
///
/// A dropped subject weakens a clean verdict rather than invalidating it — the
/// artifacts that WERE read were genuinely matched — so a would-be `Pass`
/// becomes `Degraded`, the same rung `package-trust` uses when its approved
/// baseline cannot be read. `--strict` catches it; a plain `verify` reports it
/// without failing the build. Outcomes that are already weaker are left alone:
/// `weakest` never promotes.
fn apply_diagnostics(result: &mut VerifyResult, diags: &Diagnostics) {
    let problems = diags.problems();
    if !problems.is_empty() {
        result.messages.push(format!(
            "bumblebee could not read {} subject(s) it was asked to examine — those artifacts \
             were NOT matched against the catalog",
            problems.len()
        ));
        for d in problems.iter().take(DIAGNOSTIC_LIMIT) {
            result.messages.push(d.render());
        }
        if problems.len() > DIAGNOSTIC_LIMIT {
            result.messages.push(format!(
                "… and {} more diagnostic(s)",
                problems.len() - DIAGNOSTIC_LIMIT
            ));
        }
        result.outcome = result.outcome.clone().weakest(Outcome::Degraded);
    }
    // Routine per-run bookkeeping ("default roots: 19 present…", "scan complete:
    // …"). Counted rather than reprinted: the point is that the user knows the
    // stream exists and is not being hidden, not that four lines of provenance
    // are pasted into every report.
    let informational = diags.informational();
    if informational > 0 {
        result.messages.push(format!(
            "note: {informational} informational diagnostic(s) from the scan"
        ));
    }
    // Anything bumblebee wrote that was not a diagnostic record. On a successful
    // run this should be empty; if it is not, it is the tool saying something we
    // have no schema for, and dropping it is how the schema stays unknown.
    for line in diags.plain.iter().take(3) {
        result.messages.push(format!("stderr: {line}"));
    }
    if diags.plain.len() > 3 {
        result.messages.push(format!(
            "… and {} more stderr line(s)",
            diags.plain.len() - 3
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Build a finished invocation without touching PATH or a subprocess.
    fn out(stdout: &str, stderr: &str, status: i32) -> exec::CmdOutput {
        exec::CmdOutput {
            status,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    /// The root set a real `baseline` run reports on a developer machine, so the
    /// default fixture is a scan that actually reached the endpoint classes.
    const ENDPOINT_ROOTS: &str = r#"[{"path":"/h/.claude","kind":"mcp_config_root"},{"path":"/h/.vscode/extensions","kind":"editor_extension_root"},{"path":"/h/Library/.../Extensions","kind":"browser_extension_root"},{"path":"/h/.agents","kind":"agent_skill_root"},{"path":"/opt/homebrew/Cellar","kind":"homebrew_root"}]"#;
    /// What a machine with nothing but Homebrew reports — the M20 case.
    const HOMEBREW_ONLY_ROOTS: &str = r#"[{"path":"/opt/homebrew/Cellar","kind":"homebrew_root"},{"path":"/h/go","kind":"user_package_root"}]"#;
    /// What `--profile project --root <repo>` reports, verbatim from a real run.
    const PROJECT_ROOTS: &str = r#"[{"path":"/repo","kind":"project_root"}]"#;

    fn summary(status: &str, timed_out: bool, inventoried: u64) -> String {
        summary_with_roots(status, timed_out, inventoried, ENDPOINT_ROOTS)
    }

    fn summary_with_roots(status: &str, timed_out: bool, inventoried: u64, roots: &str) -> String {
        format!(
            r#"{{"record_type":"scan_summary","status":"{status}","timed_out":{timed_out},"package_records_emitted":0,"package_records_suppressed":{inventoried},"roots":{roots}}}"#
        )
    }

    fn eval(stdout: &str, stderr: &str, status: i32) -> VerifyResult {
        evaluate_scan(
            "0.1.2",
            "baseline",
            "catalog.json",
            None,
            &out(stdout, stderr, status),
        )
    }

    // ── plan_scan: the refusals that happen BEFORE bumblebee is ever invoked ──

    fn cat(dir: &std::path::Path, name: &str, entries: &str) {
        std::fs::write(
            dir.join(name),
            format!(r#"{{"schema_version":"0.1.0","entries":[{entries}]}}"#),
        )
        .unwrap();
    }

    const USABLE: &str = r#"{"id":"E1","ecosystem":"npm","package":"p","versions":["1.0.0"]}"#;

    #[test]
    fn plan_resolves_a_repo_relative_catalog_to_an_absolute_path() {
        let d = tempfile::tempdir().unwrap();
        cat(d.path(), "catalog.json", USABLE);
        let plan = plan_scan(d.path(), "catalog.json", Some("baseline")).expect("should proceed");
        assert_eq!(plan.profile, "baseline");
        assert!(
            plan.catalog_arg.ends_with("catalog.json") && plan.catalog_arg.starts_with('/'),
            "a repo-relative catalog must be passed absolute: {}",
            plan.catalog_arg
        );
        assert!(plan.coerced.is_none());
    }

    #[test]
    fn plan_passes_an_unresolvable_catalog_through_for_the_tool_to_reject() {
        let d = tempfile::tempdir().unwrap();
        // Nonexistent: bumblebee itself errors with exit 2 and a precise message,
        // which is better than anything we could synthesise.
        let plan = plan_scan(d.path(), "/nope/missing.json", Some("baseline")).expect("proceeds");
        assert_eq!(plan.catalog_arg, "/nope/missing.json");
    }

    #[test]
    fn plan_refuses_a_wildcard_only_catalog() {
        let d = tempfile::tempdir().unwrap();
        cat(d.path(), "catalog.json", r#"{"id":"W","versions":["*"]}"#);
        let r = plan_scan(d.path(), "catalog.json", Some("baseline")).expect_err("must refuse");
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages[0].contains("0 usable entries"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn plan_refuses_an_empty_catalog_directory() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("catalogs")).unwrap();
        let r = plan_scan(d.path(), "catalogs", Some("baseline")).expect_err("must refuse");
        assert!(
            r.messages[0].contains("0 usable entries"),
            "{:?}",
            r.messages
        );
    }

    /// The comma case: bumblebee splits --root on commas with no escaping syntax,
    /// so a comma in the repo path would silently scan nothing.
    #[test]
    fn plan_refuses_a_comma_in_the_repo_path_under_the_project_profile() {
        let d = tempfile::tempdir().unwrap();
        let odd = d.path().join("has,comma");
        std::fs::create_dir(&odd).unwrap();
        cat(&odd, "catalog.json", USABLE);
        let r = plan_scan(&odd, "catalog.json", Some("project")).expect_err("must refuse");
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages[0].contains("comma"), "{:?}", r.messages);
    }

    /// ...but `baseline` never passes --root, so the same path is fine there.
    #[test]
    fn plan_allows_a_comma_in_the_repo_path_under_baseline() {
        let d = tempfile::tempdir().unwrap();
        let odd = d.path().join("has,comma");
        std::fs::create_dir(&odd).unwrap();
        cat(&odd, "catalog.json", USABLE);
        let plan = plan_scan(&odd, "catalog.json", Some("baseline"))
            .expect("baseline needs no --root, so a comma is harmless");
        assert_eq!(plan.profile, "baseline");
    }

    #[test]
    fn plan_records_a_coerced_profile_so_a_typo_is_not_silent() {
        let d = tempfile::tempdir().unwrap();
        cat(d.path(), "catalog.json", USABLE);
        let plan = plan_scan(d.path(), "catalog.json", Some("deep")).expect("proceeds");
        assert_eq!(plan.profile, "project", "deep must never widen scope");
        assert_eq!(plan.coerced.as_deref(), Some("deep"));
    }

    #[test]
    fn plan_does_not_report_coercion_when_the_profile_was_absent_or_exact() {
        let d = tempfile::tempdir().unwrap();
        cat(d.path(), "catalog.json", USABLE);
        for opt in [
            None,
            Some("project"),
            Some("baseline"),
            Some("  baseline  "),
        ] {
            let plan = plan_scan(d.path(), "catalog.json", opt).expect("proceeds");
            assert!(
                plan.coerced.is_none(),
                "{opt:?} is not a coercion worth reporting"
            );
        }
    }

    #[test]
    fn nonzero_exit_fails_and_passes_the_tools_own_stderr_through() {
        let r = eval(
            "",
            "unsupported exposure catalog schema_version \"0.2.0\"",
            2,
        );
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages[0].contains("exit 2"), "{:?}", r.messages);
        assert!(
            r.messages[1].contains("schema_version"),
            "the tool's own message must survive verbatim: {:?}",
            r.messages
        );
    }

    #[test]
    fn nonzero_exit_with_no_stderr_still_fails_and_says_so() {
        let r = eval("", "", 2);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages[1].contains("no stderr"), "{:?}", r.messages);
    }

    #[test]
    fn a_timed_out_scan_fails_rather_than_reporting_clean() {
        let r = eval(&summary("complete", true, 400), "", 0);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages[0].contains("TIMED OUT"), "{:?}", r.messages);
    }

    #[test]
    fn a_non_complete_status_fails_and_names_the_status() {
        let r = eval(&summary("partial", false, 400), "", 0);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages[0].contains("partial"), "{:?}", r.messages);
    }

    #[test]
    fn a_stream_with_no_summary_at_all_fails() {
        let r = eval("", "", 0);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages[0].contains("no scan_summary"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn an_incomplete_scan_reports_unparsable_line_count_too() {
        let r = eval("not json\n", "", 0);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages.iter().any(|m| m.contains("1 unparsable")),
            "{:?}",
            r.messages
        );
    }

    /// The regression the review caught: a completed scan that inventoried
    /// nothing is not a clean endpoint.
    #[test]
    fn a_scan_that_inventoried_nothing_fails_instead_of_passing() {
        let r = evaluate_scan(
            "0.1.2",
            "project",
            "catalog.json",
            None,
            &out(&summary("complete", false, 0), "", 0),
        );
        assert_eq!(
            r.outcome,
            Outcome::Fail,
            "zero subjects must never read as clean"
        );
        assert!(r.messages[0].contains("inventoried 0"), "{:?}", r.messages);
        assert!(
            r.messages.iter().any(|m| m.contains("baseline")),
            "must point at the fix: {:?}",
            r.messages
        );
    }

    #[test]
    fn a_completed_scan_with_subjects_and_no_findings_passes_and_reports_the_count() {
        let r = eval(&summary("complete", false, 148), "", 0);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(
            r.messages[0].contains("148"),
            "a pass must say how much it looked at: {:?}",
            r.messages
        );
    }

    // ── M20: the inventory guard must be per-class, not one aggregate number ──

    /// The finding. 16,912 Homebrew receipts satisfied "did the scan look at
    /// anything?" while every class this control exists for went unopened, and
    /// the report said the ENDPOINT was clean.
    #[test]
    fn a_homebrew_only_scan_is_not_a_clean_endpoint() {
        let r = evaluate_scan(
            "0.1.2",
            "baseline",
            "catalog.json",
            None,
            &out(
                &summary_with_roots("complete", false, 16912, HOMEBREW_ONLY_ROOTS),
                "",
                0,
            ),
        );
        assert_ne!(
            r.outcome,
            Outcome::Pass,
            "a single populated class must not satisfy a guard meant to prove the scan \
             looked at the endpoint: {:?}",
            r.messages
        );
        assert_eq!(r.outcome, Outcome::Info);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("MCP server configs") && m.contains("agent skills")),
            "the unexamined classes must be named: {:?}",
            r.messages
        );
        assert!(
            r.messages.iter().any(|m| m.contains("homebrew_root")),
            "what WAS reached must be named too: {:?}",
            r.messages
        );
    }

    /// Same blindness, the version a user can fix: `project` cannot reach those
    /// roots by construction, so it degrades and names the config change. An npm
    /// repo inventories plenty under `project` and sailed past the aggregate
    /// guard.
    #[test]
    fn a_project_scoped_scan_degrades_and_points_at_the_profile() {
        let r = evaluate_scan(
            "0.1.2",
            "project",
            "catalog.json",
            None,
            &out(
                &summary_with_roots("complete", false, 431, PROJECT_ROOTS),
                "",
                0,
            ),
        );
        assert_eq!(
            r.outcome,
            Outcome::Degraded,
            "a control pointed at the wrong surface is fixable, so --strict should see it: {:?}",
            r.messages
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("profile = \"baseline\"")),
            "must name the fix: {:?}",
            r.messages
        );
    }

    /// The other direction: reaching even one endpoint class is a real endpoint
    /// scan, and it passes — with the covered classes stated, so the verdict is
    /// no longer a class-blind number.
    #[test]
    fn a_scan_that_reached_endpoint_roots_passes_and_names_the_classes_covered() {
        let r = eval(&summary("complete", false, 148), "", 0);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("endpoint classes covered") && m.contains("MCP server configs")),
            "a pass must say WHICH classes it covered: {:?}",
            r.messages
        );
    }

    #[test]
    fn one_endpoint_class_is_enough_to_be_an_endpoint_scan() {
        let only_skills = r#"[{"path":"/h/.agents","kind":"agent_skill_root"},{"path":"/opt/homebrew/Cellar","kind":"homebrew_root"}]"#;
        let r = evaluate_scan(
            "0.1.2",
            "baseline",
            "catalog.json",
            None,
            &out(
                &summary_with_roots("complete", false, 9, only_skills),
                "",
                0,
            ),
        );
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("endpoint classes covered: agent skills")),
            "{:?}",
            r.messages
        );
    }

    /// A summary with no `roots` at all is not evidence of coverage either.
    #[test]
    fn a_summary_with_no_roots_array_is_not_a_covered_endpoint() {
        let no_roots = r#"{"record_type":"scan_summary","status":"complete","timed_out":false,"package_records_suppressed":50}"#;
        let r = eval(no_roots, "", 0);
        assert_ne!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert!(
            r.messages.iter().any(|m| m.contains("none reported")),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn root_kinds_are_parsed_and_deduplicated_in_first_seen_order() {
        let dup = r#"{"record_type":"scan_summary","status":"complete","timed_out":false,"package_records_suppressed":1,"roots":[{"path":"/a","kind":"mcp_config_root"},{"path":"/b","kind":"mcp_config_root"},{"path":"/c","kind":"homebrew_root"}]}"#;
        let r = parse_records(dup);
        assert_eq!(r.root_kinds, vec!["mcp_config_root", "homebrew_root"]);
        assert_eq!(
            endpoint_classes_reached(&r.root_kinds),
            vec!["MCP server configs"]
        );
    }

    // ── M19: stderr diagnostics, which a successful run is the ONLY place for ──

    /// Captured verbatim from a real v0.1.2 `baseline` run. bumblebee reached
    /// this MCP config, could not parse it, dropped it from the inventory, and
    /// still exited 0 with a `status:"complete"` summary.
    const WARN_DIAG: &str = r#"{"record_type":"diagnostic","run_id":"08dd","time":"2026-08-24T20:43:03.635305Z","level":"warn","path":"/Users/p4gs/.gemini/config/mcp_config.json","message":"parse MCP config: unexpected end of JSON input"}"#;
    /// Routine bookkeeping from the same run.
    const INFO_DIAG: &str = r#"{"record_type":"diagnostic","run_id":"08dd","level":"info","message":"default roots: 19 present, 85 candidate paths absent (use --root to override)"}"#;

    /// The finding, in one test: bumblebee reports what it could not read ONLY
    /// on stderr, and the exit code stays 0. Reading stdout alone reported a
    /// dropped MCP config as a clean endpoint.
    #[test]
    fn a_subject_the_scan_could_not_read_is_surfaced_and_weakens_a_clean_verdict() {
        let r = eval(&summary("complete", false, 148), WARN_DIAG, 0);
        assert_eq!(
            r.outcome,
            Outcome::Degraded,
            "a scan that dropped a subject has not established that subject is clean: {:?}",
            r.messages
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("mcp_config.json") && m.contains("unexpected end of JSON")),
            "the tool's own diagnostic must survive verbatim: {:?}",
            r.messages
        );
        assert!(
            r.messages.iter().any(|m| m.contains("could not read 1")),
            "the count of dropped subjects must be stated: {:?}",
            r.messages
        );
    }

    /// The other half: routine `info` chatter must NOT weaken a clean run, or
    /// every scan degrades and the signal is worthless.
    #[test]
    fn informational_diagnostics_are_counted_without_weakening_a_pass() {
        let r = eval(&summary("complete", false, 148), INFO_DIAG, 0);
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("1 informational diagnostic")),
            "the stream must be acknowledged rather than hidden: {:?}",
            r.messages
        );
    }

    #[test]
    fn diagnostics_are_reported_on_a_findings_fail_too_and_never_promote_it() {
        let r = eval(
            &format!("{FINDING}\n{}", summary("complete", false, 148)),
            &format!("{INFO_DIAG}\n{WARN_DIAG}"),
            0,
        );
        assert_eq!(
            r.outcome,
            Outcome::Fail,
            "Degraded must never promote a Fail"
        );
        assert!(
            r.messages.iter().any(|m| m.contains("mcp_config.json")),
            "{:?}",
            r.messages
        );
    }

    /// Many dropped subjects are truncated in the listing, but the COUNT stays
    /// truthful — the same rule the findings list follows.
    #[test]
    fn many_diagnostics_are_truncated_but_the_count_is_not() {
        let stderr = (0..14)
            .map(|i| {
                format!(
                    r#"{{"record_type":"diagnostic","level":"warn","path":"/p/{i}","message":"unreadable"}}"#
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let r = eval(&summary("complete", false, 148), &stderr, 0);
        assert_eq!(r.outcome, Outcome::Degraded);
        assert!(
            r.messages.iter().any(|m| m.contains("could not read 14")),
            "{:?}",
            r.messages
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("and 4 more diagnostic")),
            "truncation must be declared: {:?}",
            r.messages
        );
    }

    /// stderr that is not a diagnostic record is still output, and still reaches
    /// the user. bumblebee's own fatal errors are bare text on this stream.
    #[test]
    fn non_record_stderr_lines_are_surfaced_verbatim_rather_than_dropped() {
        let r = eval(
            &summary("complete", false, 148),
            "runtime: out of memory\n",
            0,
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("runtime: out of memory")),
            "unrecognised stderr must not be swallowed: {:?}",
            r.messages
        );
    }

    #[test]
    fn diagnostics_parse_levels_paths_and_plain_lines_apart() {
        let d = parse_diagnostics(&format!("{INFO_DIAG}\n{WARN_DIAG}\nnot a record\n\n"));
        assert_eq!(d.entries.len(), 2);
        assert_eq!(d.informational(), 1);
        let problems = d.problems();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].level, "warn");
        assert_eq!(
            problems[0].path.as_deref(),
            Some("/Users/p4gs/.gemini/config/mcp_config.json")
        );
        assert_eq!(d.plain, vec!["not a record".to_string()]);
    }

    /// A diagnostic with no `level` and no `message` must not panic or silently
    /// vanish — an unknown level is not a safe level.
    #[test]
    fn a_diagnostic_missing_its_fields_is_treated_as_a_problem_not_as_noise() {
        let d = parse_diagnostics(r#"{"record_type":"diagnostic"}"#);
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].level, "unknown");
        assert_eq!(d.entries[0].message, "(no message)");
        assert_eq!(
            d.problems().len(),
            1,
            "an unrecognised level must not be assumed benign"
        );
    }

    #[test]
    fn a_pass_still_reports_unparsable_lines_as_a_note() {
        let r = eval(
            &format!("garbage\n{}", summary("complete", false, 5)),
            "",
            0,
        );
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(
            r.messages.iter().any(|m| m.contains("unparsable")),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn findings_fail_and_name_each_artifact_with_its_catalog_id() {
        let r = eval(
            &format!("{FINDING}\n{}", summary("complete", false, 148)),
            "",
            0,
        );
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(
            r.messages[0].contains("1 known-compromised"),
            "{:?}",
            r.messages
        );
        assert!(
            r.messages[1].contains("bumblebee") && r.messages[1].contains("TEST-EXACT"),
            "artifact and catalog id must both appear: {:?}",
            r.messages
        );
    }

    /// Findings are truncated in the message list, but the COUNT must stay
    /// truthful or a reader concludes there were only 20.
    #[test]
    fn more_than_twenty_findings_are_truncated_but_the_count_is_not() {
        let mut stream = String::new();
        for i in 0..25 {
            stream.push_str(&format!(
                r#"{{"record_type":"finding","severity":"high","catalog_id":"C{i}","package_name":"p{i}","version":"1.0.0","ecosystem":"npm"}}"#
            ));
            stream.push('\n');
        }
        stream.push_str(&summary("complete", false, 900));
        let r = eval(&stream, "", 0);
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.messages[0].contains("25"), "{:?}", r.messages[0]);
        assert!(
            r.messages.iter().any(|m| m.contains("and 5 more")),
            "truncation must be declared: {:?}",
            r.messages
        );
    }

    #[test]
    fn a_coerced_profile_is_surfaced_on_an_otherwise_clean_pass() {
        let r = evaluate_scan(
            "0.1.2",
            "project",
            "catalog.json",
            Some("deep"),
            &out(&summary("complete", false, 10), "", 0),
        );
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(
            r.messages.iter().any(|m| m.contains("`deep`")),
            "a silently-narrowed scope must be surfaced: {:?}",
            r.messages
        );
    }

    /// A real v0.1.2 finding record, captured from an actual scan rather than
    /// hand-written, so the field names are the tool's and not our guess.
    const FINDING: &str = r#"{"record_type":"finding","finding_type":"package_exposure","severity":"critical","catalog_id":"TEST-EXACT","package_name":"bumblebee","version":"0.1.2","ecosystem":"homebrew"}"#;
    /// A successful-run summary shaped like the real one: `status: "complete"`,
    /// not timed out, with the package counters that prove subjects existed.
    /// A bare `{"record_type":"scan_summary"}` is deliberately NOT this — the
    /// dedicated tests below cover partial, timed-out and zero-inventory runs.
    const SUMMARY: &str = r#"{"record_type":"scan_summary","run_id":"abc","status":"complete","timed_out":false,"package_records_emitted":0,"package_records_suppressed":148}"#;

    #[test]
    fn finding_and_summary_are_both_recognised() {
        let r = parse_records(&format!("{FINDING}\n{SUMMARY}\n"));
        assert!(r.completed, "scan_summary must set completed");
        assert_eq!(r.exposures.len(), 1);
        let e = &r.exposures[0];
        assert_eq!(e.package, "bumblebee");
        assert_eq!(e.version, "0.1.2");
        assert_eq!(e.ecosystem, "homebrew");
        assert_eq!(e.severity, "critical");
        assert_eq!(e.catalog_id, "TEST-EXACT");
    }

    #[test]
    fn clean_scan_is_complete_with_no_exposures() {
        let r = parse_records(&format!("{SUMMARY}\n"));
        assert!(r.completed);
        assert!(r.exposures.is_empty());
    }

    /// The load-bearing distinction: an empty stream is NOT a clean scan.
    #[test]
    fn empty_stream_is_not_a_completed_scan() {
        let r = parse_records("");
        assert!(
            !r.completed,
            "an empty stream must never look like a finished scan"
        );
        assert!(r.exposures.is_empty());
    }

    #[test]
    fn truncated_stream_of_findings_without_summary_is_incomplete() {
        // Findings present but the run died before emitting its summary: we know
        // about exposures AND we know we cannot trust the count.
        let r = parse_records(&format!("{FINDING}\n"));
        assert!(!r.completed);
        assert_eq!(r.exposures.len(), 1);
    }

    #[test]
    fn unparsable_lines_are_counted_not_swallowed() {
        let r = parse_records(&format!("not json at all\n{FINDING}\n{SUMMARY}\n"));
        assert_eq!(r.unparsable_lines, 1);
        assert_eq!(r.exposures.len(), 1);
        assert!(r.completed);
    }

    #[test]
    fn package_records_are_ignored_only_findings_count() {
        let pkg = r#"{"record_type":"package","package_name":"bash","version":"5.3.9","ecosystem":"homebrew"}"#;
        let r = parse_records(&format!("{pkg}\n{SUMMARY}\n"));
        assert!(r.completed);
        assert!(
            r.exposures.is_empty(),
            "an inventory record is not an exposure"
        );
    }

    #[test]
    fn missing_fields_degrade_to_unknown_rather_than_panicking() {
        let sparse = r#"{"record_type":"finding"}"#;
        let r = parse_records(&format!("{sparse}\n{SUMMARY}\n"));
        assert_eq!(r.exposures.len(), 1);
        assert_eq!(r.exposures[0].package, "unknown");
        assert_eq!(r.exposures[0].severity, "unknown");
    }

    /// The whole point of `count_catalog_entries`: an empty catalog directory
    /// produces a clean bumblebee run (exit 0, scan_summary, findings=0), so the
    /// entry count is the only thing that distinguishes "nothing compromised"
    /// from "nothing checked".
    #[test]
    fn empty_catalog_directory_counts_zero_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(count_catalog_entries(dir.path()).unwrap(), 0);
    }

    #[test]
    fn catalog_entries_are_counted_from_a_file_and_across_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let one = dir.path().join("a.json");
        std::fs::write(
            &one,
            r#"{"schema_version":"0.1.0","entries":[{"id":"A"},{"id":"B"}]}"#,
        )
        .unwrap();
        assert_eq!(count_catalog_entries(&one).unwrap(), 2);

        std::fs::write(
            dir.path().join("b.json"),
            r#"{"schema_version":"0.1.0","entries":[{"id":"C"}]}"#,
        )
        .unwrap();
        // Non-JSON siblings are ignored, matching bumblebee's own resolution.
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        assert_eq!(count_catalog_entries(dir.path()).unwrap(), 3);
    }

    #[test]
    fn a_catalog_with_an_empty_entries_array_counts_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("empty.json");
        std::fs::write(&f, r#"{"schema_version":"0.1.0","entries":[]}"#).unwrap();
        assert_eq!(
            count_catalog_entries(&f).unwrap(),
            0,
            "a syntactically valid catalog with no entries is still no criteria"
        );
    }

    #[test]
    fn unparseable_catalog_counts_zero_rather_than_pretending_to_have_criteria() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("broken.json");
        std::fs::write(&f, "{ this is not json").unwrap();
        assert_eq!(count_catalog_entries(&f).unwrap(), 0);
    }

    /// The README tells users to write `["*"]`, and v0.1.2 matches it as a
    /// literal — so a wildcard-only catalog is criteria-free and must not clear
    /// the zero-entry guard.
    #[test]
    fn wildcard_only_entries_are_not_usable_criteria() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("wild.json");
        std::fs::write(
            &f,
            r#"{"schema_version":"0.1.0","entries":[{"id":"A","versions":["*"]}]}"#,
        )
        .unwrap();
        assert_eq!(
            count_catalog_entries(&f).unwrap(),
            0,
            "a wildcard-only entry matches nothing in v0.1.2 and is not criteria"
        );
    }

    #[test]
    fn an_entry_with_a_concrete_version_alongside_a_wildcard_is_usable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("mixed.json");
        std::fs::write(
            &f,
            r#"{"schema_version":"0.1.0","entries":[{"id":"A","versions":["*","0.1.2"]}]}"#,
        )
        .unwrap();
        assert_eq!(count_catalog_entries(&f).unwrap(), 1);
    }

    /// Absent/empty `versions` is bumblebee's own exit-2 error; counting those as
    /// usable lets the tool's precise message surface instead of ours.
    #[test]
    fn entries_without_a_versions_array_stay_countable_so_the_tool_reports_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("noversions.json");
        std::fs::write(
            &f,
            r#"{"schema_version":"0.1.0","entries":[{"id":"A"},{"id":"B","versions":[]}]}"#,
        )
        .unwrap();
        assert_eq!(count_catalog_entries(&f).unwrap(), 2);
    }

    /// A real v0.1.2 summary. `inventoried` must come from the package-record
    /// counters, NOT `counts.package` — which reads 0 even here.
    #[test]
    fn summary_yields_inventory_count_completion_and_timeout_state() {
        let summary = r#"{"record_type":"scan_summary","status":"complete","package_records_emitted":0,"package_records_suppressed":148,"findings_emitted":1,"timed_out":false,"counts":{"finding":1,"package":0}}"#;
        let r = parse_records(summary);
        assert!(r.completed);
        assert!(!r.timed_out);
        assert_eq!(
            r.inventoried, 148,
            "must sum the package-record counters, not read counts.package"
        );
    }

    /// A timed-out run still emits a well-formed summary. It is not clean.
    #[test]
    fn timed_out_summary_is_not_a_completed_scan() {
        let s = r#"{"record_type":"scan_summary","status":"complete","timed_out":true,"package_records_suppressed":10}"#;
        let r = parse_records(s);
        assert!(r.timed_out);
        assert!(!r.completed, "a timed-out scan must never read as complete");
    }

    #[test]
    fn non_complete_status_is_not_a_completed_scan() {
        let s = r#"{"record_type":"scan_summary","status":"partial","timed_out":false,"package_records_suppressed":10}"#;
        let r = parse_records(s);
        assert!(!r.completed);
        assert_eq!(r.status.as_deref(), Some("partial"));
    }

    /// The `project`-profile-on-a-Rust-repo case: scan completes, finds nothing,
    /// because it inventoried nothing.
    #[test]
    fn a_completed_scan_that_inventoried_nothing_reports_zero() {
        let s = r#"{"record_type":"scan_summary","status":"complete","timed_out":false,"package_records_emitted":0,"package_records_suppressed":0}"#;
        let r = parse_records(s);
        assert!(r.completed);
        assert_eq!(
            r.inventoried, 0,
            "zero subjects is what the caller must refuse to call clean"
        );
    }

    #[test]
    fn an_unrecognised_profile_never_widens_the_scan() {
        // Anything NAMED but not an explicit `baseline` — including an attempt to
        // select the $HOME-walking `deep` mode — resolves to the repo-scoped
        // profile. Config cannot escalate scan scope beyond the repository.
        for attempted in ["deep", "DEEP", "nonsense", "  deep  "] {
            assert_eq!(
                profile_from(Some(attempted)),
                "project",
                "`{attempted}` must not select a broader scope"
            );
        }
        assert_eq!(profile_from(Some("baseline")), "baseline");
        assert_eq!(profile_from(Some("  baseline  ")), "baseline");
        assert_eq!(profile_from(Some("project")), "project");
    }

    /// The registry literal, unquoted — the value `sscsb init` writes into
    /// `.sscsb/config.toml` for `[controls.bumblebee] profile`.
    fn registry_profile_literal() -> &'static str {
        crate::controls::control(CONTROL)
            .expect("bumblebee is in the registry")
            .default_options
            .iter()
            .find(|(k, _)| *k == "profile")
            .map(|(_, v)| v.trim_matches('"'))
            .expect("bumblebee declares a default profile")
    }

    /// M25. The registry said `"baseline"` and the code fell back to `"project"`,
    /// so the SAME control scanned a different surface depending on whether the
    /// config key happened to be present — a hand-written or trimmed config got
    /// the repo-scoped scan while a generated one got the endpoint scan. An
    /// absent key must mean the registry default, not a second opinion.
    #[test]
    fn the_runtime_profile_default_is_the_registry_default() {
        assert_eq!(
            profile_from(None),
            registry_profile_literal(),
            "the fallback used when `profile` is absent must equal the value the \
             generated config carries"
        );
        assert_eq!(
            profile_from(Some("")),
            registry_profile_literal(),
            "a blank value is nobody choosing anything, not an unrecognised choice"
        );
    }

    /// M25, second half: the Info hint printed when no catalog is configured told
    /// the user to set the profile the module's own doc says inventories nothing
    /// on a Rust repo — advice that produced the zero-subject FAIL below.
    #[test]
    fn the_no_catalog_hint_names_the_registry_default_profile() {
        let r = no_catalog_result("0.1.2");
        assert_eq!(r.outcome, Outcome::Info);
        let hint = r
            .messages
            .iter()
            .find(|m| m.contains("[controls.bumblebee]"))
            .expect("the hint must spell out the config block");
        assert!(
            hint.contains(&format!("profile = \"{}\"", registry_profile_literal())),
            "the hint must not tell the user to set a different profile than the \
             registry default: {hint}"
        );
    }
}
