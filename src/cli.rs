//! Command surface for `sscsb`. Thin: parses args, builds a `Ctx`, and
//! delegates to the modules. Exit codes: 0 success, 1 policy/verification
//! failure, 2 operational error.

use crate::config;
use crate::context::Ctx;
use crate::controls::{self, Outcome};
use crate::{
    compliance, deps, hooks, init, observability, provenance, sast, sbom, scan, signers, tools,
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sscsb",
    version,
    about = "SSCS Bootstrapper — opinionated, modular software supply chain security \
             for solo developers and small teams in AI-heavy workflows",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap the current repo: config, hooks, policies, CI templates
    Init,
    /// Show every control with enabled state and tool availability
    Status,
    /// Enable a control in .sscsb/config.toml
    Enable { control: String },
    /// Disable a control in .sscsb/config.toml
    Disable { control: String },
    /// Verify controls (all enabled ones, or the ones named)
    Verify {
        /// Specific control ids to verify
        controls: Vec<String>,
        /// Exit non-zero on DEGRADED as well as FAIL
        #[arg(long)]
        strict: bool,
    },
    /// Render control → framework coverage (SLSA/SSDF/CRA/Badge)
    Report {
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Git hook entry points (invoked by the installed shims)
    Hook {
        #[command(subcommand)]
        event: HookEvent,
    },
    /// Generate an SBOM with Syft
    Sbom {
        /// cyclonedx-json (default) or spdx-json
        #[arg(long)]
        format: Option<String>,
    },
    /// Vulnerability scan (Trivy + OSV-Scanner; optional VEX suppression)
    Scan {
        /// OpenVEX document whose not_affected/fixed statements suppress findings
        #[arg(long)]
        vex: Option<PathBuf>,
        /// Also run Grype against a fresh SBOM (requires grype)
        #[arg(long)]
        grype: bool,
    },
    /// Run SAST (OpenGrep default; engine configurable)
    Sast,
    /// Package-trust operations
    Deps {
        #[command(subcommand)]
        action: DepsAction,
    },
    /// AI provenance receipts
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },
    /// Provenance operations (slsa-verifier / DSSE inspection)
    Provenance {
        #[command(subcommand)]
        action: ProvenanceAction,
    },
    /// Dependency-Track integration
    Dtrack {
        #[command(subcommand)]
        action: DtrackAction,
    },
    /// GUAC supply-chain graph ingestion
    Guac {
        #[command(subcommand)]
        action: GuacAction,
    },
    /// OpenVEX document generation
    Vex {
        #[command(subcommand)]
        action: VexAction,
    },
    /// Push SBOM/attestation files to an OCI registry via ORAS
    Oras {
        #[command(subcommand)]
        action: OrasAction,
    },
    /// Inspect and manage the signer policy (human / ci / ai identities)
    Signers {
        #[command(subcommand)]
        action: SignersAction,
    },
    /// Guidance for provisioning a hardware-backed / remote agent signing key
    AgentKey {
        #[command(subcommand)]
        action: AgentKeyAction,
    },
    /// Show the pinned external-tool registry and detection status
    Tools,
}

#[derive(Subcommand)]
enum SignersAction {
    /// List configured signers with class, backend, expiry, attestation state
    List,
    /// Add a signer to .sscsb/policy/signers.toml (validated before writing)
    Add {
        #[arg(long)]
        principal: String,
        /// human | ci | ai
        #[arg(long)]
        class: String,
        /// SSH public key line (ssh-ed25519 AAAA... comment)
        #[arg(long = "ssh-key")]
        ssh_key: Option<String>,
        /// GPG fingerprint (for gpg.format=openpgp signers)
        #[arg(long)]
        gpg_fingerprint: Option<String>,
        /// tpm | fido2 | kms | github-app | piv | software
        #[arg(long)]
        backend: Option<String>,
        /// Assert the key is hardware-backed / non-exportable
        #[arg(long)]
        hardware_backed: bool,
        /// Rotation date, YYYY-MM-DD
        #[arg(long)]
        expires: Option<String>,
    },
    /// Classify recent commits as human / ci / agent / unsigned
    Check {
        /// Commit range (e.g. origin/main..HEAD); default: last 20 commits
        range: Option<String>,
        /// Instead of local signature classification, verify commits are
        /// GitHub-'Verified' and committed by this login (server-side signing)
        #[arg(long = "github-app")]
        github_app: Option<String>,
    },
    /// Server-side gate: reject policy changes in base..head not made by a
    /// human trusted BEFORE the push (reads trusted policy from `base`)
    VerifyPolicy {
        /// Trusted pre-push tip (e.g. github.event.before)
        #[arg(long)]
        base: String,
        /// Pushed tip (e.g. github.sha)
        #[arg(long)]
        head: String,
    },
}

#[derive(Subcommand)]
enum AgentKeyAction {
    /// Print setup guidance for a signing backend (github-app | tpm | ...)
    Setup {
        #[arg(long)]
        backend: String,
    },
}

#[derive(Subcommand)]
enum HookEvent {
    PreCommit,
    CommitMsg { message_file: PathBuf },
    PrePush { remote: String, url: String },
}

#[derive(Subcommand)]
enum DepsAction {
    /// Validate packages: registry existence + typosquat heuristics
    Check {
        /// Skip network registry lookups
        #[arg(long)]
        offline: bool,
    },
    /// Approve a package into the baseline (e.g. cargo:serde)
    Approve {
        package: String,
        /// Approve despite a typosquat or nonexistent-on-registry warning
        #[arg(long)]
        force: bool,
        /// Skip the network existence check (typosquat check still runs)
        #[arg(long)]
        offline: bool,
    },
    /// Approve everything currently in the manifests
    Baseline {
        /// Skip network existence checks (typosquat check still runs)
        #[arg(long)]
        offline: bool,
    },
    /// List the approved baseline
    List,
}

#[derive(Subcommand)]
enum ReceiptAction {
    /// Create a receipt for a commit (default HEAD)
    Create {
        #[arg(default_value = "HEAD")]
        commit: String,
        /// Also sign the receipt with cosign keyless (needs OIDC)
        #[arg(long)]
        sign: bool,
    },
    /// Verify a receipt against the repository
    Verify { receipt: PathBuf },
}

#[derive(Subcommand)]
enum ProvenanceAction {
    /// Verify an artifact against SLSA provenance (wraps slsa-verifier)
    Verify {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        source_uri: String,
        #[arg(long)]
        source_tag: Option<String>,
    },
    /// Inspect a DSSE/in-toto provenance file (subjects, builder)
    Inspect { file: PathBuf },
    /// Verify a cosign keyless blob signature bundle
    VerifyBlob {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        /// Expected certificate identity (e.g. the workflow URL)
        #[arg(long)]
        identity: String,
        #[arg(long, default_value = "https://token.actions.githubusercontent.com")]
        issuer: String,
    },
}

#[derive(Subcommand)]
enum DtrackAction {
    /// Upload the generated SBOM (PUT /api/v1/bom)
    Upload {
        /// SBOM path (default: .sscsb/out/sbom.cdx.json)
        #[arg(long)]
        bom: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum GuacAction {
    /// Ingest .sscsb/out (or a directory) via `guacone collect files`
    Ingest {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum VexAction {
    /// Create an OpenVEX document
    Create {
        #[arg(long)]
        vuln: String,
        /// Product identifier (purl preferred, e.g. pkg:cargo/foo@1.0.0)
        #[arg(long)]
        product: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        justification: Option<String>,
    },
}

#[derive(Subcommand)]
enum OrasAction {
    Push { reference: String, file: PathBuf },
}

pub fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let cwd = std::env::current_dir()?;
    match cli.command {
        Command::Init => cmd_init(&cwd),
        Command::Status => cmd_status(&cwd),
        Command::Enable { control } => cmd_toggle(&cwd, &control, true),
        Command::Disable { control } => cmd_toggle(&cwd, &control, false),
        Command::Verify { controls, strict } => cmd_verify(&cwd, &controls, strict),
        Command::Report { format } => cmd_report(&cwd, &format),
        Command::Hook { event } => cmd_hook(&cwd, event),
        Command::Sbom { format } => cmd_sbom(&cwd, format.as_deref()),
        Command::Scan { vex, grype } => cmd_scan(&cwd, vex.as_deref(), grype),
        Command::Sast => cmd_sast(&cwd),
        Command::Deps { action } => cmd_deps(&cwd, action),
        Command::Receipt { action } => cmd_receipt(&cwd, action),
        Command::Provenance { action } => cmd_provenance(&cwd, action),
        Command::Dtrack { action } => cmd_dtrack(&cwd, action),
        Command::Guac { action } => cmd_guac(&cwd, action),
        Command::Vex { action } => cmd_vex(&cwd, action),
        Command::Oras { action } => cmd_oras(&cwd, action),
        Command::Signers { action } => cmd_signers(&cwd, action),
        Command::AgentKey { action } => cmd_agent_key(action),
        Command::Tools => cmd_tools(),
    }
}

fn ok() -> Result<ExitCode> {
    Ok(ExitCode::SUCCESS)
}

fn fail(code: u8) -> Result<ExitCode> {
    Ok(ExitCode::from(code))
}

fn cmd_init(cwd: &std::path::Path) -> Result<ExitCode> {
    for line in init::bootstrap(cwd)? {
        println!("{line}");
    }
    println!();
    println!("Bootstrap complete. Next steps:");
    for step in init::NEXT_STEPS {
        println!("{step}");
    }
    ok()
}

fn cmd_status(cwd: &std::path::Path) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.config.as_ref();
    println!(
        "sscsb status — repo: {} (branch: {}, platform: {})",
        ctx.root.display(),
        ctx.current_branch().unwrap_or_else(|_| "?".into()),
        ctx.platform
    );
    println!(
        "config: {}",
        if cfg.is_some() {
            ".sscsb/config.toml"
        } else {
            "MISSING — run `sscsb init`"
        }
    );
    println!("hooks installed: {}", hooks::hooks_installed(&ctx));
    println!();
    for phase in 1..=5u8 {
        println!("Phase {phase}");
        for def in controls::phase_controls(phase) {
            let enabled = cfg
                .and_then(|c| c.control_enabled(def.id))
                .unwrap_or(def.default_enabled);
            let tools_state: Vec<String> = def
                .tools
                .iter()
                .map(|t| {
                    let present = tools::is_available(t);
                    format!("{t}:{}", if present { "ok" } else { "missing" })
                })
                .collect();
            println!(
                "  [{}] {:<24} {}{}",
                if enabled { "on " } else { "off" },
                def.id,
                def.name,
                if tools_state.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", tools_state.join(", "))
                }
            );
        }
    }
    ok()
}

fn cmd_toggle(cwd: &std::path::Path, control: &str, enabled: bool) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let config_path = ctx.require_config()?.path.clone();
    config::set_control_enabled(&config_path, control, enabled)?;
    println!(
        "{} `{}` — verify with `sscsb status`",
        if enabled { "enabled" } else { "disabled" },
        control
    );
    ok()
}

fn cmd_verify(cwd: &std::path::Path, only: &[String], strict: bool) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.require_config()?;
    let mut failed = 0u32;
    let mut degraded = 0u32;
    for def in controls::CONTROLS {
        if !only.is_empty() && !only.iter().any(|o| o == def.id) {
            continue;
        }
        let result = controls::verify_control(&ctx, cfg, def);
        println!("[{:8}] {}", result.outcome.symbol(), result.control);
        for m in &result.messages {
            println!("           {m}");
        }
        match result.outcome {
            Outcome::Fail => failed += 1,
            Outcome::Degraded => degraded += 1,
            _ => {}
        }
    }
    println!();
    println!("verify: {failed} failed, {degraded} degraded");
    if failed > 0 || (strict && degraded > 0) {
        fail(1)
    } else {
        ok()
    }
}

fn cmd_report(cwd: &std::path::Path, format: &str) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match format {
        "json" => println!("{}", compliance::render_report_json(&ctx)?),
        _ => println!("{}", compliance::render_report(&ctx)?),
    }
    ok()
}

fn cmd_hook(cwd: &std::path::Path, event: HookEvent) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let code = match event {
        HookEvent::PreCommit => hooks::hook_pre_commit(&ctx)?,
        HookEvent::CommitMsg { message_file } => hooks::hook_commit_msg(&ctx, &message_file)?,
        HookEvent::PrePush { remote, url: _ } => {
            let mut stdin = String::new();
            use std::io::Read;
            std::io::stdin().read_to_string(&mut stdin)?;
            hooks::hook_pre_push(&ctx, &remote, &stdin)?
        }
    };
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}

fn cmd_sbom(cwd: &std::path::Path, format: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.require_config()?;
    let path = sbom::generate(&ctx, cfg, format)?;
    println!("SBOM written: {}", path.display());
    ok()
}

fn cmd_scan(cwd: &std::path::Path, vex: Option<&std::path::Path>, grype: bool) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.require_config()?;
    let report = scan::run_scan(&ctx, cfg, vex)?;
    for note in &report.notes {
        println!("note: {note}");
    }
    for s in &report.suppressed {
        println!("suppressed: {s}");
    }
    println!("{} finding(s):", report.findings.len());
    for f in report.findings.iter().take(50) {
        println!("  [{}] {} {} ({})", f.severity, f.id, f.package, f.source);
    }
    if grype {
        let cfg_enabled = cfg.control_enabled("grype").unwrap_or(false);
        if !cfg_enabled {
            println!("grype: control disabled — `sscsb enable grype` first");
        } else {
            let sbom_path = sbom::generate(&ctx, cfg, None)?;
            let (n, summaries) = sbom::grype_scan(&ctx, &sbom_path)?;
            println!("grype: {n} match(es)");
            for s in summaries {
                println!("  {s}");
            }
        }
    }
    let fail_on = cfg
        .control_opt_str("vuln-scan", "fail_on")
        .unwrap_or_else(|| "high".to_string());
    if scan::breaches_threshold(&report, &fail_on) {
        println!("threshold breached (fail_on = {fail_on})");
        return fail(1);
    }
    ok()
}

fn cmd_sast(cwd: &std::path::Path) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.require_config()?;
    let findings = sast::run_sast(&ctx, cfg, &ctx.root)?;
    println!("{} finding(s)", findings.len());
    for f in findings.iter().take(50) {
        println!("  {}", f.render());
    }
    if findings
        .iter()
        .any(|f| f.severity.eq_ignore_ascii_case("ERROR"))
    {
        return fail(1);
    }
    ok()
}

fn cmd_deps(cwd: &std::path::Path, action: DepsAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        DepsAction::Check { offline } => {
            let (problems, notes) = deps::deps_check(&ctx, offline)?;
            for n in &notes {
                println!("note: {n}");
            }
            for p in &problems {
                println!("PROBLEM: {p}");
            }
            if problems.is_empty() {
                println!("deps check: clean");
                ok()
            } else {
                fail(1)
            }
        }
        DepsAction::Approve {
            package,
            force,
            offline,
        } => {
            let warnings = deps::approval_warnings(&package, offline);
            if !warnings.is_empty() {
                for w in &warnings {
                    eprintln!("  ✗ {w}");
                }
                if !force {
                    eprintln!(
                        "sscsb: refusing to approve {package} — re-run with --force if this is \
                         genuinely the package you intend."
                    );
                    return fail(1);
                }
                eprintln!("sscsb: --force given; approving {package} despite the warning(s).");
            }
            deps::approve_package(&ctx, &package)?;
            println!("approved {package} → .sscsb/policy/packages.toml");
            ok()
        }
        DepsAction::Baseline { offline } => {
            // Baseline blesses what's already present, but it must not silently
            // bless a typosquat/hallucinated name. Clean packages are approved;
            // suspect ones are reported and SKIPPED for a deliberate
            // `sscsb deps approve <pkg> --force`.
            let current = deps::current_deps(&ctx)?;
            let mut approved = 0usize;
            let mut skipped = Vec::new();
            for pkg in current {
                let warnings = deps::approval_warnings(&pkg, offline);
                if warnings.is_empty() {
                    deps::approve_package(&ctx, &pkg)?;
                    approved += 1;
                } else {
                    skipped.push((pkg, warnings));
                }
            }
            println!("baselined {approved} package(s) into .sscsb/policy/packages.toml");
            if !skipped.is_empty() {
                eprintln!(
                    "sscsb: {} package(s) NOT baselined (suspect):",
                    skipped.len()
                );
                for (pkg, warnings) in &skipped {
                    for w in warnings {
                        eprintln!("  ✗ {w}");
                    }
                    eprintln!("    approve deliberately with: sscsb deps approve {pkg} --force");
                }
                return fail(1);
            }
            ok()
        }
        DepsAction::List => {
            for pkg in deps::load_approved(&ctx)? {
                println!("{pkg}");
            }
            ok()
        }
    }
}

fn cmd_receipt(cwd: &std::path::Path, action: ReceiptAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        ReceiptAction::Create { commit, sign } => {
            let out_dir = ctx.sscsb_dir().join("out").join("receipts");
            let path = provenance::create_receipt(&ctx, &commit, &out_dir)?;
            println!("receipt written: {}", path.display());
            if sign {
                let bundle = path.with_extension("json.sigstore.json");
                let log = provenance::cosign_sign_blob(&ctx, &path, &bundle)?;
                println!("signed: {} \n{log}", bundle.display());
            }
            ok()
        }
        ReceiptAction::Verify { receipt } => {
            println!("{}", provenance::verify_receipt(&ctx, &receipt)?);
            ok()
        }
    }
}

fn cmd_provenance(cwd: &std::path::Path, action: ProvenanceAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        ProvenanceAction::Verify {
            artifact,
            provenance: prov,
            source_uri,
            source_tag,
        } => {
            let output = provenance::verify_artifact(
                &ctx,
                &provenance::ProvenanceArgs {
                    artifact: &artifact,
                    provenance: &prov,
                    source_uri: &source_uri,
                    source_tag: source_tag.as_deref(),
                },
            )?;
            println!("{output}");
            ok()
        }
        ProvenanceAction::VerifyBlob {
            artifact,
            bundle,
            identity,
            issuer,
        } => {
            let output =
                provenance::cosign_verify_blob(&ctx, &artifact, &bundle, &identity, &issuer)?;
            println!("{output}");
            ok()
        }
        ProvenanceAction::Inspect { file } => {
            let text = std::fs::read_to_string(&file)?;
            let s = provenance::inspect_dsse(&text)?;
            println!("statement: {}", s.statement_type);
            println!("predicate: {}", s.predicate_type);
            for (name, digest) in &s.subjects {
                println!("subject:   {name} → {digest}");
            }
            if let Some(b) = &s.builder_id {
                println!("builder:   {b}");
            }
            ok()
        }
    }
}

fn cmd_dtrack(cwd: &std::path::Path, action: DtrackAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    let cfg = ctx.require_config()?;
    match action {
        DtrackAction::Upload { bom } => {
            let bom_path = bom.unwrap_or_else(|| sbom::sbom_output_path(&ctx, "cyclonedx-json"));
            anyhow::ensure!(
                bom_path.is_file(),
                "no SBOM at {} — run `sscsb sbom` first",
                bom_path.display()
            );
            println!("{}", observability::dtrack_upload(&ctx, cfg, &bom_path)?);
            ok()
        }
    }
}

fn cmd_guac(cwd: &std::path::Path, action: GuacAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        GuacAction::Ingest { dir } => {
            println!("{}", observability::guac_ingest(&ctx, dir.as_deref())?);
            ok()
        }
    }
}

fn cmd_vex(cwd: &std::path::Path, action: VexAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        VexAction::Create {
            vuln,
            product,
            status,
            justification,
        } => {
            let path = observability::vex_create(
                &ctx,
                &observability::VexArgs {
                    vuln: &vuln,
                    product: &product,
                    status: &status,
                    justification: justification.as_deref(),
                },
            )?;
            println!("OpenVEX written: {}", path.display());
            ok()
        }
    }
}

fn cmd_oras(cwd: &std::path::Path, action: OrasAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        OrasAction::Push { reference, file } => {
            println!("{}", observability::oras_push(&ctx, &reference, &file)?);
            ok()
        }
    }
}

fn cmd_signers(cwd: &std::path::Path, action: SignersAction) -> Result<ExitCode> {
    let ctx = Ctx::discover(cwd)?;
    match action {
        SignersAction::List => {
            for line in signers::describe_signers(&ctx)? {
                println!("{line}");
            }
            ok()
        }
        SignersAction::Add {
            principal,
            class,
            ssh_key,
            gpg_fingerprint,
            backend,
            hardware_backed,
            expires,
        } => {
            let cfg = ctx.require_config()?;
            let note = signers::add_signer(
                &ctx,
                cfg,
                &signers::NewSigner {
                    principal,
                    class,
                    ssh_public_key: ssh_key,
                    gpg_fingerprint,
                    backend,
                    hardware_backed,
                    expires,
                },
            )?;
            println!("{note}");
            ok()
        }
        SignersAction::Check { range, github_app } => {
            let cfg = ctx.require_config()?;
            if let Some(committer) = github_app {
                let commits =
                    signers::verify_github_app_commits(&ctx, cfg, &committer, range.as_deref())?;
                let mut bad = 0u32;
                for c in &commits {
                    let ok_flag = c.verified && c.committer_matches;
                    if !ok_flag {
                        bad += 1;
                    }
                    println!(
                        "{:<10} {:<9} committer={} ({})",
                        c.sha,
                        if ok_flag { "verified" } else { "UNVERIFIED" },
                        c.committer,
                        c.reason
                    );
                }
                return if bad > 0 { fail(1) } else { ok() };
            }
            let classes = signers::classify_range(&ctx, cfg, range.as_deref())?;
            if classes.is_empty() {
                println!("no commits to classify");
            }
            for c in &classes {
                println!("{:<10} {:<14} {}", c.sha, c.label, c.detail);
            }
            ok()
        }
        SignersAction::VerifyPolicy { base, head } => {
            let problems = signers::verify_policy_changes(&ctx, &base, &head)?;
            if problems.is_empty() {
                println!("policy gate: no unauthorized policy changes in {base}..{head}");
                return ok();
            }
            for p in &problems {
                eprintln!("REJECT: {p}");
            }
            // A "no trusted parent" note is informational, not a hard reject.
            let only_first_push =
                problems.len() == 1 && problems[0].contains("no trusted parent policy");
            if only_first_push {
                ok()
            } else {
                fail(1)
            }
        }
    }
}

fn cmd_agent_key(action: AgentKeyAction) -> Result<ExitCode> {
    match action {
        AgentKeyAction::Setup { backend } => {
            for line in signers::agent_key_setup_guidance(&backend)? {
                println!("{line}");
            }
            ok()
        }
    }
}

fn cmd_tools() -> Result<ExitCode> {
    println!("{:<14} {:<10} {:<12} status", "tool", "pin", "found");
    for spec in tools::TOOLS {
        match tools::detect(spec) {
            tools::ToolStatus::Found { version, path } => println!(
                "{:<14} {:<10} {:<12} {}",
                spec.id,
                spec.pinned_version,
                version.unwrap_or_else(|| "?".into()),
                path
            ),
            tools::ToolStatus::Missing => println!(
                "{:<14} {:<10} {:<12} MISSING ({})",
                spec.id, spec.pinned_version, "-", spec.homepage
            ),
        }
    }
    ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_lists_core_commands() {
        let help = Cli::command().render_long_help().to_string();
        for cmd in [
            "init",
            "enable",
            "disable",
            "verify",
            "report",
            "status",
            "hook",
            "sbom",
            "scan",
            "sast",
            "deps",
            "receipt",
            "provenance",
            "signers",
            "agent-key",
        ] {
            assert!(help.contains(cmd), "help missing `{cmd}`");
        }
    }
}
