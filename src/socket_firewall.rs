//! `socket-firewall-ci`: do this repository's COMMITTED workflows put their
//! package-manager installs behind Socket Firewall?
//!
//! The existing `socket-firewall` control asks whether `sfw` is on the
//! developer's PATH — a fact about a machine, which nobody but that developer
//! can observe. This one asks a different question with different evidence, and
//! leaves that control alone: every subject here is a file committed at HEAD
//! under `.github/workflows/`, so the verdict is a property of the repository
//! and anyone cloning it reaches the same answer.
//!
//! # Tiers, and why only one of them can fail
//!
//! Socket Firewall **Free** proxies exactly npm, yarn, pnpm, pip, uv and cargo
//! ([`Tier::Free`]). Go, Maven, Gradle, Bundler, gem, dotnet and NuGet are
//! Enterprise-only; bun, composer, apt, brew and rustup are not supported at
//! any tier. Failing a maintainer for an ecosystem the free tool **cannot**
//! protect is a false positive by construction, so Enterprise and unsupported
//! acquisitions are reported as information and never as findings. Only a
//! free-tier acquisition can fail this control.
//!
//! # The first-acquisition rule
//!
//! The unit of judgement is (job, ecosystem), where a local composite action
//! (`uses: ./…`) is spliced into the calling job at the position of the step
//! that uses it. For each pair, the **first** acquisition in step order must
//! carry the `sfw` prefix. `sfw cargo fetch --locked` followed by a bare
//! `cargo build --locked` is a PASS: the crates came through the firewall and
//! the build reads the filtered cache. That gives a one-step remedy per job and
//! avoids demanding a prefix on every matrix `cargo test`.
//!
//! # Acquiring subcommands are an allowlist
//!
//! `npm run build`, `npm test` and `cargo fmt` acquire nothing, and an
//! unrecognised subcommand is NOT an acquisition. Detection fails open on
//! purpose: a missed install is a gap this control discloses, while an invented
//! one is a maintainer told to fix something that is not broken.
//!
//! # What is deliberately NOT a shortfall here
//!
//! [`crate::workflows`] gates cosign signing on `!`, condition position,
//! `set +e`, `||`, `|` and `&` — a signature that "ran" while its failure was
//! swallowed proves nothing. None of those gates apply here, and importing them
//! would be a bug rather than an omission: `sfw npm ci || true` still ran the
//! install **through the firewall**, and that is the whole and only question
//! this control asks. The packages went through the proxy whether or not the
//! step's exit status survived.

use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;
use crate::workflows::{
    automatic_trigger, check_workflow, command_word, committed_workflows, constant_false,
    continues_on_error, describe_trigger, effective_shell, is_posix_shell, shell_commands,
    step_label, ShapeVerdict,
};
use std::collections::BTreeSet;
use yaml_rust2::{Yaml, YamlLoader};

const ID: &str = "socket-firewall-ci";

/// The prefix that puts an acquisition behind the firewall.
const SFW: &str = "sfw";

/// Which Socket Firewall tier can proxy an ecosystem — the core
/// false-positive defence. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// Proxied by Socket Firewall Free: no account, no key, no payment.
    Free,
    /// Proxied only by Socket Firewall Enterprise.
    Enterprise,
    /// Not proxied at any tier.
    Unsupported,
}

impl Tier {
    fn why(self) -> &'static str {
        match self {
            Tier::Free => "Socket Firewall Free proxies this ecosystem",
            Tier::Enterprise => {
                "Socket Firewall proxies this ecosystem only on the Enterprise tier, so its \
                 absence is not a finding"
            }
            Tier::Unsupported => {
                "Socket Firewall does not proxy this ecosystem at any tier, so its absence is \
                 not a finding"
            }
        }
    }
}

/// One package-manager acquisition found in a committed `run:` body.
#[derive(Debug)]
struct Acquisition {
    /// The canonical ecosystem id — the half of the (unit, ecosystem) key that
    /// is not the job. One id per manager: `pip`, `pip3` and `python -m pip`
    /// are all `pip`, `gradlew` is `gradle`, but `npm`, `yarn` and `pnpm` stay
    /// distinct. Three managers that share a registry still each open their own
    /// connection, so a prefix on one says nothing about the others.
    ecosystem: &'static str,
    tier: Tier,
    /// The `sfw` prefix was present on this command.
    prefixed: bool,
    /// `<workflow> job `<id>`` — the unit half of the key.
    unit: String,
    /// Where the command is, down to the step (and the composite action, when
    /// the step was one).
    at: String,
    /// The command as written, abbreviated.
    command: String,
    /// The program the command runs (`cargo`, `python3`, `npm`), for a remedy
    /// that can be read as a whole — abbreviating the full command into the
    /// suggestion would hand the reader a truncated line to paste.
    program: String,
    /// The step (or its job) carries `continue-on-error: true`.
    continue_on_error: bool,
}

/// The non-flag words of an argument list, in order. `-m`, `--quiet` and
/// cargo's `+nightly` toolchain selector are all skipped, so
/// `python3 -m pip install`, `npm install --save-dev x` and
/// `cargo +nightly build` yield `pip install`, `install x` and `build`.
fn positional(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-') && !a.starts_with('+'))
        .collect()
}

/// Drop the leading options of a wrapper, so `sfw --verbose npm ci` names
/// `npm`. An option that takes a separate value (`sfw --config x npm ci`)
/// leaves `x` in the command-word position, which classifies as nothing and is
/// therefore silent — the fail-open direction.
fn skip_flags(args: &[String]) -> &[String] {
    let start = args
        .iter()
        .position(|a| !a.starts_with('-'))
        .unwrap_or(args.len());
    &args[start..]
}

/// The ecosystem and tier a command acquires for, or `None` when it acquires
/// nothing. Every subcommand list is an ALLOWLIST: an unrecognised subcommand
/// is not an acquisition.
fn classify(program: &str, args: &[String]) -> Option<(&'static str, Tier)> {
    let w = positional(args);
    let first = w.first().copied();
    let second = w.get(1).copied();
    let is = |set: &[&str]| first.is_some_and(|f| set.contains(&f));
    match program {
        // ── Socket Firewall Free ────────────────────────────────────────────
        "npm" => is(&["ci", "install", "i", "add"]).then_some(("npm", Tier::Free)),
        // A bare `yarn` IS `yarn install`.
        "yarn" => (first.is_none() || is(&["install", "add"])).then_some(("yarn", Tier::Free)),
        "pnpm" => is(&["install", "i", "add", "fetch"]).then_some(("pnpm", Tier::Free)),
        "pip" | "pip3" => is(&["install", "download"]).then_some(("pip", Tier::Free)),
        "python" | "python3" => (first == Some("pip")
            && matches!(second, Some("install" | "download")))
        .then_some(("pip", Tier::Free)),
        "uv" => (is(&["sync", "add"])
            || (first == Some("pip") && second == Some("install"))
            || (first == Some("tool") && second == Some("install")))
        .then_some(("uv", Tier::Free)),
        // `cargo build`/`test`/`check`/`clippy`/`doc`/`run`/`bench`/`publish`
        // and the two common third-party runners all resolve and download
        // crates when the cache is cold, which is every fresh CI runner.
        "cargo" => is(&[
            "fetch", "add", "install", "update", "build", "test", "check", "clippy", "bench",
            "doc", "run", "publish", "llvm-cov", "nextest",
        ])
        .then_some(("cargo", Tier::Free)),

        // ── Enterprise only ─────────────────────────────────────────────────
        "go" => (is(&["get", "install", "build", "test", "run"])
            || (first == Some("mod") && matches!(second, Some("download" | "tidy"))))
        .then_some(("go", Tier::Enterprise)),
        "mvn" => is(&["install", "package", "verify", "compile", "test"])
            .then_some(("maven", Tier::Enterprise)),
        "gradle" | "gradlew" | "./gradlew" => {
            is(&["build", "assemble", "test", "check", "dependencies"])
                .then_some(("gradle", Tier::Enterprise))
        }
        "bundle" => is(&["install", "update", "add"]).then_some(("bundler", Tier::Enterprise)),
        "gem" => is(&["install", "update", "fetch"]).then_some(("gem", Tier::Enterprise)),
        "dotnet" => (is(&["restore", "add", "build", "publish", "test"])
            || (first == Some("tool") && second == Some("install")))
        .then_some(("dotnet", Tier::Enterprise)),
        "nuget" => is(&["install", "restore", "add"]).then_some(("nuget", Tier::Enterprise)),

        // ── Unsupported at any tier ─────────────────────────────────────────
        "bun" => is(&["install", "i", "add", "ci"]).then_some(("bun", Tier::Unsupported)),
        "composer" => {
            is(&["install", "update", "require"]).then_some(("composer", Tier::Unsupported))
        }
        "apt" | "apt-get" => is(&["install"]).then_some(("apt", Tier::Unsupported)),
        "brew" => is(&["install", "bundle"]).then_some(("brew", Tier::Unsupported)),
        "rustup" => (is(&["install"])
            || (first == Some("toolchain") && second == Some("install"))
            || (matches!(first, Some("component" | "target")) && second == Some("add")))
        .then_some(("rustup", Tier::Unsupported)),

        _ => None,
    }
}

fn abbreviate(words: &[String]) -> String {
    let joined = words.join(" ");
    let mut out: String = joined.chars().take(80).collect();
    if joined.chars().count() > 80 {
        out.push('…');
    }
    out
}

/// Every acquisition in one `run:` body, in command order.
fn scan_run(run: &str, unit: &str, at: &str, continue_on_error: bool, out: &mut Vec<Acquisition>) {
    for command in shell_commands(run) {
        let Some((word, args)) = command_word(&command.words) else {
            continue;
        };
        let (prefixed, program, args) = if word == SFW {
            let rest = skip_flags(args);
            match rest.split_first() {
                Some((program, rest)) => (true, program.as_str(), rest),
                None => continue,
            }
        } else {
            (false, word, args)
        };
        if let Some((ecosystem, tier)) = classify(program, args) {
            out.push(Acquisition {
                ecosystem,
                tier,
                prefixed,
                unit: unit.to_string(),
                at: at.to_string(),
                command: abbreviate(&command.words),
                program: program.to_string(),
                continue_on_error,
            });
        }
    }
}

/// The `runs.steps` of a local composite action referenced as `uses: ./<path>`,
/// read from HEAD. `Err` carries the note explaining why nothing was spliced.
fn composite_steps(ctx: &Ctx, path: &str) -> Result<(String, Vec<Yaml>), String> {
    let dir = path.trim_end_matches('/');
    for name in ["action.yml", "action.yaml"] {
        let rel = format!("{dir}/{name}");
        let Ok(out) = exec::git_bytes(&["show", &format!("HEAD:{rel}")], &ctx.root) else {
            continue;
        };
        if !out.success() {
            continue;
        }
        let Ok(text) = String::from_utf8(out.stdout) else {
            return Err(format!("{rel} is unreadable as text"));
        };
        let Ok(docs) = YamlLoader::load_from_str(&text) else {
            return Err(format!("{rel} is not valid YAML"));
        };
        let Some(doc) = docs.first() else {
            return Err(format!("{rel} holds no YAML document"));
        };
        if doc["runs"]["using"].as_str().map(str::trim) != Some("composite") {
            return Err(format!(
                "{rel} is not a composite action — only a composite's `run:` steps execute in \
                 the calling job"
            ));
        }
        let steps = doc["runs"]["steps"].as_vec().cloned().unwrap_or_default();
        return Ok((rel, steps));
    }
    Err(format!(
        "neither {dir}/action.yml nor {dir}/action.yaml is committed at HEAD — the referenced \
         local action was not examined"
    ))
}

/// Everything found in one job, composite steps spliced in at the position of
/// the step that uses them, depth 1 only.
fn scan_job(
    ctx: &Ctx,
    doc: &Yaml,
    job: &Yaml,
    unit: &str,
    out: &mut Vec<Acquisition>,
    notes: &mut Vec<String>,
) {
    let job_off = continues_on_error(job);
    let steps = job["steps"].as_vec().cloned().unwrap_or_default();
    for (index, step) in steps.iter().enumerate() {
        let label = step_label(index, step);
        if let Some(v) = constant_false(&step["if"]) {
            notes.push(format!(
                "{unit} {label}: `if: {v}` is constant-false — the step never runs, so it was \
                 not examined"
            ));
            continue;
        }
        let coe = job_off || continues_on_error(step);
        if let Some(run) = step["run"].as_str() {
            let shell = effective_shell(doc, job, step);
            if !is_posix_shell(shell) {
                notes.push(format!(
                    "{unit} {label}: `shell: {}` is not a POSIX shell — its body was not \
                     tokenised and was not examined",
                    shell.unwrap_or("")
                ));
                continue;
            }
            scan_run(run, unit, &format!("{unit} {label}"), coe, out);
            continue;
        }
        let Some(uses) = step["uses"]
            .as_str()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        else {
            continue;
        };
        let Some(path) = uses.strip_prefix("./") else {
            continue;
        };
        match composite_steps(ctx, path) {
            Err(why) => notes.push(format!("{unit} {label}: {why}")),
            Ok((rel, inner)) => {
                for (i, inner_step) in inner.iter().enumerate() {
                    if constant_false(&inner_step["if"]).is_some() {
                        continue;
                    }
                    let Some(run) = inner_step["run"].as_str() else {
                        continue;
                    };
                    // A composite `run:` step declares its own `shell:`;
                    // workflow-level `defaults` do not reach it.
                    let shell = inner_step["shell"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    if !is_posix_shell(shell) {
                        notes.push(format!(
                            "{unit} {label} → {rel} {}: `shell: {}` is not a POSIX shell — its \
                             body was not examined",
                            step_label(i, inner_step),
                            shell.unwrap_or("")
                        ));
                        continue;
                    }
                    let at = format!("{unit} {label} → {rel} {}", step_label(i, inner_step));
                    let coe = coe || continues_on_error(inner_step);
                    scan_run(run, unit, &at, coe, out);
                }
                // Depth 1 only, stated out loud: a composite step that uses
                // ANOTHER local action is not followed.
                if inner
                    .iter()
                    .any(|s| s["uses"].as_str().is_some_and(|u| u.starts_with("./")))
                {
                    notes.push(format!(
                        "{unit} {label} → {rel} itself uses another local action — composites are \
                         spliced one level deep, so that one was not examined"
                    ));
                }
            }
        }
    }
}

/// Walk every committed workflow and collect the acquisitions plus every
/// reason something was not examined.
fn audit(ctx: &Ctx) -> (Vec<Acquisition>, Vec<String>) {
    let set = committed_workflows(ctx);
    let mut notes = set.notes;
    let mut out = Vec::new();
    for wf in &set.files {
        if let ShapeVerdict::Broken(why) = check_workflow(&wf.rel, &wf.content) {
            notes.push(format!(
                "{why} — GitHub would not run it, so it was not examined"
            ));
            continue;
        }
        for doc in &wf.docs {
            if matches!(doc, Yaml::Null | Yaml::BadValue) {
                continue;
            }
            let Some(trigger) = automatic_trigger(doc) else {
                notes.push(format!(
                    "{}: no automatic trigger — a workflow reachable only by hand \
                     (`workflow_dispatch`, `workflow_call`) is a procedure, not a control, and \
                     was not examined",
                    wf.rel
                ));
                continue;
            };
            let fires = describe_trigger(doc, &trigger);
            let Some(jobs) = doc["jobs"].as_hash() else {
                continue;
            };
            for (id, job) in jobs {
                let job_id = id.as_str().unwrap_or("<non-string job id>");
                let unit = format!("{} job `{job_id}`", wf.rel);
                if let Some(v) = constant_false(&job["if"]) {
                    notes.push(format!(
                        "{unit}: `if: {v}` is constant-false — the job never runs, so it was not \
                         examined"
                    ));
                    continue;
                }
                let before = out.len();
                scan_job(ctx, doc, job, &unit, &mut out, &mut notes);
                if out.len() > before {
                    notes.push(format!("{unit} fires on {fires}"));
                }
            }
        }
    }
    (out, notes)
}

/// The first acquisition of each (unit, ecosystem) pair, in discovery order —
/// the only one the rule judges.
fn firsts(acquisitions: &[Acquisition]) -> Vec<&Acquisition> {
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    acquisitions
        .iter()
        .filter(|a| seen.insert((a.unit.as_str(), a.ecosystem)))
        .collect()
}

pub fn verify_socket_firewall_ci(ctx: &Ctx) -> VerifyResult {
    // Every subject is committed content. A HEAD nobody can read is not an
    // empty repository — it is a scan that did not happen.
    match exec::git_raw(&["rev-parse", "--verify", "HEAD"], &ctx.root) {
        Ok(out) if out.success() => {}
        other => {
            let why = match other {
                Ok(o) => o.stderr.trim().to_string(),
                Err(e) => format!("{e:#}"),
            };
            return VerifyResult::degraded(
                ID,
                "scan-error",
                vec![format!(
                    "HEAD could not be read ({why}) — this control reads only committed \
                     workflows, so nothing was verified"
                )],
            );
        }
    }

    let (acquisitions, notes) = audit(ctx);
    let firsts = firsts(&acquisitions);
    let mut messages: Vec<String> = Vec::new();

    let findings: Vec<&&Acquisition> = firsts
        .iter()
        .filter(|a| a.tier == Tier::Free && !a.prefixed)
        .collect();
    for a in &findings {
        messages.push(format!(
            "[error] {}: `{}` is the first {} acquisition in this job and does not go through \
             Socket Firewall — put `{SFW}` in front of it (`{SFW} {} …`), or add an \
             `{SFW}`-prefixed {} step before it; the rest of the job then reads the filtered \
             cache",
            a.at, a.command, a.ecosystem, a.program, a.ecosystem
        ));
    }
    for a in firsts.iter().filter(|a| a.tier == Tier::Free && a.prefixed) {
        messages.push(format!(
            "[info] {}: `{}` — first {} acquisition in this job, behind Socket Firewall ({})",
            a.at,
            a.command,
            a.ecosystem,
            a.tier.why()
        ));
        if a.continue_on_error {
            messages.push(format!(
                "[note] {}: this step carries `continue-on-error: true`, so a blocked install \
                 does not stop the job and any later {} step in it fetches unfiltered",
                a.at, a.ecosystem
            ));
        }
    }
    for a in firsts.iter().filter(|a| a.tier != Tier::Free) {
        messages.push(format!(
            "[info] {}: `{}` acquires for {} — {}",
            a.at,
            a.command,
            a.ecosystem,
            a.tier.why()
        ));
    }
    let later = acquisitions.len() - firsts.len();
    if later > 0 {
        messages.push(format!(
            "[info] {later} later acquisition(s) in an already-judged (job, ecosystem) were not \
             judged — the first one in each decides"
        ));
    }
    messages.extend(notes.into_iter().map(|n| format!("[note] {n}")));

    if acquisitions.is_empty() {
        messages.insert(
            0,
            "no package-manager acquisition was found in any committed workflow — nothing was \
             verified, so this is not a pass"
                .to_string(),
        );
        return VerifyResult::degraded(ID, "no-inventory", messages);
    }
    if firsts.iter().all(|a| a.tier != Tier::Free) {
        messages.insert(
            0,
            "committed workflows acquire packages, but none through an ecosystem Socket Firewall \
             Free can proxy — there is nothing here for this control to require"
                .to_string(),
        );
        return VerifyResult::new(ID, Outcome::Info, messages);
    }
    if !findings.is_empty() {
        messages.insert(
            0,
            format!(
                "{} (job, ecosystem) unit(s) acquire packages outside Socket Firewall",
                findings.len()
            ),
        );
        return VerifyResult::new(ID, Outcome::Fail, messages);
    }
    messages.insert(
        0,
        format!(
            "every first free-tier acquisition in a committed workflow job goes through Socket \
             Firewall ({} unit(s))",
            firsts.iter().filter(|a| a.tier == Tier::Free).count()
        ),
    );
    VerifyResult::new(ID, Outcome::Pass, messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repo whose files are COMMITTED — this control reads HEAD, so
    /// `git add` alone would leave it with nothing to examine.
    fn repo_with(files: &[(&str, &str)]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        exec::git(&["config", "commit.gpgsign", "false"], root).unwrap();
        for (path, text) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        exec::git(&["add", "-A"], root).unwrap();
        exec::git(&["commit", "-q", "-m", "fixture", "--no-verify"], root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    /// A one-job workflow on `push` whose steps are `steps` (already indented
    /// six spaces, starting with `- `).
    fn wf(steps: &str) -> String {
        format!(
            "name: T\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"
        )
    }

    fn run_step(name: &str, body: &str) -> String {
        format!("      - name: {name}\n        run: {body}\n")
    }

    fn verdict(files: &[(&str, &str)]) -> VerifyResult {
        let (_d, ctx) = repo_with(files);
        verify_socket_firewall_ci(&ctx)
    }

    fn joined(r: &VerifyResult) -> String {
        r.messages.join("\n")
    }

    fn errors(r: &VerifyResult) -> Vec<&String> {
        r.messages
            .iter()
            .filter(|m| m.starts_with("[error]"))
            .collect()
    }

    // ───────────────────── the rule ─────────────────────────────────────────

    /// ISC: the first acquisition of a (job, ecosystem) decides, and a bare
    /// one fails naming the file, the job, the step and the command.
    #[test]
    fn a_bare_first_acquisition_in_a_job_is_a_finding() {
        let r = verdict(&[(
            ".github/workflows/ci.yml",
            &wf(&run_step("build", "cargo build --release --locked")),
        )]);
        assert_eq!(r.outcome, Outcome::Fail, "{}", joined(&r));
        let e = errors(&r);
        assert_eq!(e.len(), 1, "{}", joined(&r));
        assert!(e[0].contains(".github/workflows/ci.yml"), "{}", e[0]);
        assert!(e[0].contains("job `build`"), "{}", e[0]);
        assert!(e[0].contains("step `build`"), "{}", e[0]);
        assert!(e[0].contains("cargo build --release --locked"), "{}", e[0]);
        assert!(e[0].contains("put `sfw` in front of it"), "{}", e[0]);
        assert!(e[0].contains("`sfw cargo …`"), "{}", e[0]);
    }

    /// ISC: `sfw cargo fetch` then a bare `cargo build` is a PASS — the crates
    /// came through the firewall and the build reads the filtered cache. This
    /// is the rule that gives a one-step remedy per job.
    #[test]
    fn an_sfw_prefix_on_the_first_acquisition_licenses_the_rest_of_the_job() {
        let steps = format!(
            "{}{}",
            run_step("fetch", "sfw cargo fetch --locked"),
            run_step("build", "cargo build --release --locked")
        );
        let r = verdict(&[(".github/workflows/ci.yml", &wf(&steps))]);
        assert_eq!(r.outcome, Outcome::Pass, "{}", joined(&r));
        assert!(errors(&r).is_empty(), "{}", joined(&r));
        assert!(
            joined(&r).contains("1 later acquisition(s)"),
            "the later bare build must be reported as not judged: {}",
            joined(&r)
        );
    }

    /// ISC: nothing acquired is NOT a pass. Nothing was verified, and the
    /// reason is machine-readable.
    #[test]
    fn a_workflow_with_no_acquisition_at_all_degrades_no_inventory() {
        let r = verdict(&[(
            ".github/workflows/ci.yml",
            &wf(&run_step("say", "echo hello")),
        )]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert_eq!(r.degraded_reason, Some("no-inventory"));
    }

    /// ISC: failing a maintainer for an ecosystem Socket Firewall Free cannot
    /// proxy is the false positive this control exists to avoid. Enterprise and
    /// unsupported acquisitions are information, and the verdict is `Info`
    /// rather than a pass.
    #[test]
    fn enterprise_and_unsupported_ecosystems_are_information_never_findings() {
        for (body, ecosystem) in [
            ("go build ./...", "go"),
            ("go mod download", "go"),
            ("mvn -B package", "maven"),
            ("./gradlew build", "gradle"),
            ("bundle install", "bundler"),
            ("gem install rake", "gem"),
            ("dotnet restore", "dotnet"),
            ("dotnet tool install dotnet-format", "dotnet"),
            ("nuget restore", "nuget"),
            ("bun install", "bun"),
            ("composer install", "composer"),
            ("sudo apt-get install -y jq", "apt"),
            ("brew install jq", "brew"),
            ("rustup toolchain install stable", "rustup"),
            ("rustup component add clippy", "rustup"),
        ] {
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&run_step("acquire", body)))]);
            assert_eq!(r.outcome, Outcome::Info, "{body}: {}", joined(&r));
            assert!(errors(&r).is_empty(), "{body}: {}", joined(&r));
            assert!(
                joined(&r).contains(ecosystem),
                "{body} should be named as `{ecosystem}`: {}",
                joined(&r)
            );
        }
    }

    // ─────────────── the tokeniser is what makes these silent ───────────────

    /// ISC: a real tokeniser, not string matching. An install inside a
    /// heredoc, a comment or a quoted string is text, not a command.
    #[test]
    fn installs_inside_heredocs_comments_and_quotes_are_not_acquisitions() {
        for body in [
            "|\n          cat <<'EOF' > note.txt\n          cargo build --release\n          npm ci\n          EOF\n",
            "|\n          # cargo build --release\n          echo done\n",
            "|\n          echo \"cargo build --release\"\n          echo 'npm ci'\n",
            "|\n          : <<'COMMENT'\n          pip install evil\n          COMMENT\n",
        ] {
            let steps = format!("      - name: s\n        run: {body}");
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&steps))]);
            assert_eq!(
                r.outcome,
                Outcome::Degraded,
                "mentioned, not run: {body} → {}",
                joined(&r)
            );
            assert_eq!(r.degraded_reason, Some("no-inventory"), "{body}");
        }
    }

    /// ISC: wrapper words do not hide the manager, and do not hide the
    /// firewall either.
    #[test]
    fn wrapper_prefixes_hide_neither_the_manager_nor_the_firewall() {
        for bare in [
            "sudo npm ci",
            "env CI=1 npm ci",
            "CI=1 npm ci",
            "time npm ci",
            "command npm ci",
        ] {
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&run_step("s", bare)))]);
            assert_eq!(r.outcome, Outcome::Fail, "{bare}: {}", joined(&r));
        }
        for protected in [
            "sudo sfw npm ci",
            "sfw --verbose npm ci",
            "env CI=1 sfw npm ci",
            "sfw npm ci",
        ] {
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&run_step("s", protected)))]);
            assert_eq!(r.outcome, Outcome::Pass, "{protected}: {}", joined(&r));
        }
    }

    /// ISC: the operator gates `workflows` applies to cosign are deliberately
    /// NOT applied here. `sfw npm ci || true` still ran the install through the
    /// firewall, which is the only question this control asks.
    #[test]
    fn failure_swallowing_operators_do_not_revoke_the_prefix() {
        for body in [
            "sfw npm ci || true",
            "sfw npm ci | tee install.log",
            "! sfw npm ci",
            "set +e\n          sfw npm ci\n",
        ] {
            let steps = format!("      - name: s\n        run: |\n          {body}\n");
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&steps))]);
            assert_eq!(r.outcome, Outcome::Pass, "{body}: {}", joined(&r));
        }
    }

    /// ISC: an unrecognised subcommand is not an acquisition. Detection fails
    /// open — a missed install is a disclosed gap, an invented one is a
    /// maintainer sent to fix nothing.
    #[test]
    fn unrecognised_subcommands_acquire_nothing() {
        for body in [
            "cargo fmt --check",
            "npm run build",
            "npm test",
            "yarn run lint",
            "pip --version",
            "uv version",
            "cargo",
            // `sfw` with nothing after it wraps nothing.
            "sfw",
            "sfw --verbose",
            // A leading redirection names no program at all.
            "> out.txt",
        ] {
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&run_step("s", body)))]);
            assert_eq!(
                r.outcome,
                Outcome::Degraded,
                "{body} acquires nothing: {}",
                joined(&r)
            );
        }
    }

    /// ISC: the python and uv spellings of a pip install are the same
    /// ecosystem, and a bare `yarn` IS `yarn install`.
    #[test]
    fn alternate_spellings_of_an_acquisition_are_recognised() {
        for (body, ecosystem) in [
            ("python3 -m pip install --quiet semgrep==1.0.0", "pip"),
            ("python -m pip download x", "pip"),
            ("pip3 install x", "pip"),
            ("uv pip install x", "uv"),
            ("uv sync --locked", "uv"),
            ("uv tool install ruff", "uv"),
            ("yarn", "yarn"),
            ("cargo +nightly build", "cargo"),
        ] {
            let r = verdict(&[(".github/workflows/ci.yml", &wf(&run_step("s", body)))]);
            assert_eq!(r.outcome, Outcome::Fail, "{body}: {}", joined(&r));
            assert!(
                errors(&r)[0].contains(ecosystem),
                "{body} should be `{ecosystem}`: {}",
                errors(&r)[0]
            );
        }
    }

    /// ISC: a long command is abbreviated in the finding, so one over-long
    /// `run:` line cannot make the whole verdict unreadable — and the remedy
    /// names the program rather than a truncated line to paste.
    #[test]
    fn a_long_command_is_abbreviated_and_the_remedy_is_not() {
        let long = format!("cargo build --release --locked {}", "--verbose ".repeat(20));
        let r = verdict(&[(".github/workflows/ci.yml", &wf(&run_step("s", &long)))]);
        assert_eq!(r.outcome, Outcome::Fail, "{}", joined(&r));
        let e = errors(&r);
        assert!(e[0].contains('…'), "{}", e[0]);
        assert!(!e[0].contains(&long), "the full command must not appear");
        assert!(e[0].contains("`sfw cargo …`"), "{}", e[0]);
    }

    /// ISC: a step that runs nothing, and a marketplace action, acquire
    /// nothing — only a local composite's `run:` bodies execute in this job.
    #[test]
    fn marketplace_actions_and_runless_steps_acquire_nothing() {
        let steps = "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n      - name: bare\n        env:\n          X: '1'\n";
        let r = verdict(&[(".github/workflows/ci.yml", &wf(steps))]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert_eq!(r.degraded_reason, Some("no-inventory"));
    }

    // ───────────────── what is not examined, and says so ────────────────────

    /// ISC: a workflow reachable only by hand is a procedure, not a control.
    #[test]
    fn a_workflow_dispatch_only_workflow_is_not_examined() {
        let text = "name: T\non:\n  workflow_dispatch:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo build\n";
        let r = verdict(&[(".github/workflows/manual.yml", text)]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert_eq!(r.degraded_reason, Some("no-inventory"));
        assert!(
            joined(&r).contains("no automatic trigger"),
            "{}",
            joined(&r)
        );
    }

    /// ISC: a workflow GitHub would refuse to run proves nothing either way.
    #[test]
    fn a_workflow_github_would_refuse_to_run_is_not_examined() {
        let text = "name: T\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    needs: nope\n    steps:\n      - run: cargo build\n";
        let r = verdict(&[(".github/workflows/ci.yml", text)]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert!(
            joined(&r).contains("GitHub would not run it"),
            "{}",
            joined(&r)
        );
    }

    /// ISC: a job or step switched off with a constant-false `if:` runs
    /// nothing, so it acquires nothing.
    #[test]
    fn a_constant_false_job_or_step_acquires_nothing() {
        let job_off = "name: T\non: push\njobs:\n  build:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo build\n";
        let r = verdict(&[(".github/workflows/ci.yml", job_off)]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert!(joined(&r).contains("constant-false"), "{}", joined(&r));

        let step_off = "name: T\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: ${{ false }}\n        run: cargo build\n";
        let r = verdict(&[(".github/workflows/ci.yml", step_off)]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
    }

    /// ISC: the tokeniser has no opinion about a body the runner hands to
    /// something other than a POSIX shell.
    #[test]
    fn a_non_posix_shell_body_is_not_examined() {
        let text = "name: T\non: push\njobs:\n  build:\n    runs-on: windows-latest\n    steps:\n      - shell: pwsh\n        run: cargo build\n";
        let r = verdict(&[(".github/workflows/ci.yml", text)]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert!(joined(&r).contains("not a POSIX shell"), "{}", joined(&r));
    }

    /// ISC: HEAD unreadable is a scan that did not happen, not an empty
    /// repository.
    #[test]
    fn an_unreadable_head_degrades_scan_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        let r = verify_socket_firewall_ci(&ctx);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert_eq!(r.degraded_reason, Some("scan-error"));
    }

    /// ISC: only committed content is evidence — an uncommitted edit is not
    /// what a clone carries, and the control says so rather than reading it.
    #[test]
    fn only_committed_workflow_content_is_examined() {
        let (dir, ctx) = repo_with(&[(
            ".github/workflows/ci.yml",
            &wf(&run_step("s", "sfw cargo build")),
        )]);
        std::fs::write(
            dir.path().join(".github/workflows/ci.yml"),
            wf(&run_step("s", "cargo build")),
        )
        .unwrap();
        let r = verify_socket_firewall_ci(&ctx);
        assert_eq!(r.outcome, Outcome::Pass, "{}", joined(&r));
        assert!(joined(&r).contains("differs from HEAD"), "{}", joined(&r));
    }

    // ───────────────────────── composites ───────────────────────────────────

    /// ISC: a local composite action's `run:` steps execute in the calling
    /// job, so they are spliced in at the position of the step that uses them —
    /// and they can therefore be the job's FIRST acquisition.
    #[test]
    fn a_composite_action_is_spliced_into_the_calling_job() {
        let action = "name: setup\ndescription: d\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: python3 -m pip install --quiet semgrep==1.0.0\n";
        let steps = format!(
            "      - uses: ./.github/actions/setup\n{}",
            run_step("build", "sfw cargo build --locked")
        );
        let r = verdict(&[
            (".github/actions/setup/action.yml", action),
            (".github/workflows/ci.yml", &wf(&steps)),
        ]);
        assert_eq!(r.outcome, Outcome::Fail, "{}", joined(&r));
        let e = errors(&r);
        assert_eq!(e.len(), 1, "{}", joined(&r));
        assert!(
            e[0].contains(".github/actions/setup/action.yml"),
            "the finding must name the composite that carries it: {}",
            e[0]
        );
        assert!(e[0].contains("job `build`"), "{}", e[0]);
        assert!(e[0].contains("pip"), "{}", e[0]);
    }

    /// ISC: a composite no committed workflow uses is not evidence about
    /// anything — nothing runs it.
    #[test]
    fn a_composite_no_committed_workflow_uses_is_not_examined() {
        let action = "name: setup\ndescription: d\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: npm ci\n";
        let r = verdict(&[
            (".github/actions/setup/action.yml", action),
            (
                ".github/workflows/ci.yml",
                &wf(&run_step("s", "echo hello")),
            ),
        ]);
        assert_eq!(r.outcome, Outcome::Degraded, "{}", joined(&r));
        assert_eq!(r.degraded_reason, Some("no-inventory"));
    }

    /// ISC: a `uses: ./…` that is not a committed composite is a note, not a
    /// silent skip.
    #[test]
    fn an_unresolvable_local_action_is_noted() {
        let steps = format!(
            "      - uses: ./.github/actions/missing\n{}",
            run_step("build", "sfw cargo build")
        );
        let r = verdict(&[(".github/workflows/ci.yml", &wf(&steps))]);
        assert_eq!(r.outcome, Outcome::Pass, "{}", joined(&r));
        assert!(
            joined(&r).contains(
                "neither .github/actions/missing/action.yml nor \
                 .github/actions/missing/action.yaml is committed at HEAD"
            ),
            "{}",
            joined(&r)
        );
    }

    /// ISC: a `continue-on-error: true` step does not revoke the prefix — the
    /// install still went through the proxy — but it does mean a blocked
    /// install cannot stop the job, so any later step in it fetches
    /// unfiltered. Disclosed as a note rather than invented as a finding.
    #[test]
    fn a_prefixed_first_acquisition_that_cannot_fail_the_job_is_noted() {
        let steps = "      - name: fetch\n        continue-on-error: true\n        run: sfw cargo fetch --locked\n      - name: build\n        run: cargo build\n";
        let r = verdict(&[(".github/workflows/ci.yml", &wf(steps))]);
        assert_eq!(r.outcome, Outcome::Pass, "{}", joined(&r));
        assert!(
            joined(&r).contains("`continue-on-error: true`"),
            "{}",
            joined(&r)
        );
        assert!(joined(&r).contains("fetches unfiltered"), "{}", joined(&r));
    }

    /// ISC: `uses: ./…` that does not resolve to a COMPOSITE action executes
    /// nothing in the calling job, and the reason is named.
    #[test]
    fn a_local_action_that_is_not_composite_is_noted_not_spliced() {
        let action = "name: node\ndescription: d\nruns:\n  using: node20\n  main: index.js\n";
        let steps = format!(
            "      - uses: ./.github/actions/setup\n{}",
            run_step("build", "sfw cargo build")
        );
        let r = verdict(&[
            (".github/actions/setup/action.yml", action),
            (".github/workflows/ci.yml", &wf(&steps)),
        ]);
        assert_eq!(r.outcome, Outcome::Pass, "{}", joined(&r));
        assert!(
            joined(&r).contains("is not a composite action"),
            "{}",
            joined(&r)
        );
    }

    /// ISC: composites are spliced ONE level deep, and the second level is
    /// named as not examined rather than passed over in silence.
    #[test]
    fn a_composite_that_uses_another_local_action_says_so() {
        let outer = "name: outer\ndescription: d\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n    - shell: bash\n      run: sfw npm ci\n";
        let inner = "name: inner\ndescription: d\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: cargo build\n";
        let steps = "      - uses: ./.github/actions/outer\n";
        let r = verdict(&[
            (".github/actions/outer/action.yml", outer),
            (".github/actions/inner/action.yml", inner),
            (".github/workflows/ci.yml", &wf(steps)),
        ]);
        assert_eq!(r.outcome, Outcome::Pass, "{}", joined(&r));
        assert!(
            joined(&r).contains("spliced one level deep"),
            "{}",
            joined(&r)
        );
        assert!(
            !joined(&r).contains("cargo"),
            "the inner action's cargo build must not be counted: {}",
            joined(&r)
        );
    }

    // ──────────────────────── units and landmines ───────────────────────────

    /// ISC: the unit is (job, ecosystem) — a second job gets its own verdict,
    /// and a second ecosystem in the same job gets its own too.
    #[test]
    fn each_job_and_each_ecosystem_is_judged_separately() {
        let text = "name: T\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: sfw cargo build\n      - run: npm ci\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo build\n";
        let r = verdict(&[(".github/workflows/ci.yml", text)]);
        assert_eq!(r.outcome, Outcome::Fail, "{}", joined(&r));
        let e = errors(&r);
        assert_eq!(e.len(), 2, "{}", joined(&r));
        assert!(
            e.iter().any(|m| m.contains("job `a`") && m.contains("npm")),
            "{}",
            joined(&r)
        );
        assert!(
            e.iter()
                .any(|m| m.contains("job `b`") && m.contains("cargo")),
            "{}",
            joined(&r)
        );
    }

    /// M: `machine.rs` asserts every verify row's `artifacts` equals
    /// `workflows::artifacts_for(id)`, which is empty for this control. Setting
    /// `evidence` here would turn an unrelated test red, so the proving files
    /// are named in the messages instead.
    #[test]
    fn the_control_never_populates_evidence() {
        let r = verdict(&[(
            ".github/workflows/ci.yml",
            &wf(&run_step("s", "cargo build")),
        )]);
        assert!(r.evidence.is_empty());
        assert!(crate::workflows::artifacts_for(ID).is_empty());
        assert!(joined(&r).contains(".github/workflows/ci.yml"));
    }

    /// M: the existing `socket-firewall` control is untouched — it still asks
    /// about PATH, and this one never reads PATH.
    #[test]
    fn the_path_control_and_this_one_ask_different_questions() {
        let sources = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/socket_firewall.rs"),
        )
        .unwrap();
        let production = &sources[..sources.find("#[cfg(test)]").unwrap()];
        assert!(
            !production.contains("find_in_path"),
            "this control must not read PATH — that is `socket-firewall`'s question"
        );
    }
}
