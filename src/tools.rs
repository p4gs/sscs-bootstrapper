//! Registry of every external tool sscsb orchestrates: pinned known-good
//! versions, detection, and per-platform install hints. This module is the
//! SINGLE place versions are pinned — nothing in sscsb ever fetches "latest".
//!
//! Pins were resolved against upstream releases on 2026-07-12.

use crate::exec;
use crate::platform::Platform;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct ToolSpec {
    pub id: &'static str,
    pub bin: &'static str,
    /// Known-good pinned version (minimum recommended).
    pub pinned_version: &'static str,
    pub version_args: &'static [&'static str],
    pub homepage: &'static str,
    /// Homebrew formula, if one exists.
    pub brew: Option<&'static str>,
    /// Extra install guidance (Linux/WSL/Windows or no-brew cases).
    pub install_note: &'static str,
}

pub const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        id: "trufflehog",
        bin: "trufflehog",
        pinned_version: "3.95.9",
        version_args: &["--version"],
        homepage: "https://github.com/trufflesecurity/trufflehog",
        brew: Some("trufflehog"),
        install_note: "Release binaries: https://github.com/trufflesecurity/trufflehog/releases",
    },
    ToolSpec {
        id: "gitleaks",
        bin: "gitleaks",
        pinned_version: "8.30.1",
        version_args: &["version"],
        homepage: "https://github.com/gitleaks/gitleaks",
        brew: Some("gitleaks"),
        install_note: "Release binaries: https://github.com/gitleaks/gitleaks/releases",
    },
    ToolSpec {
        id: "syft",
        bin: "syft",
        pinned_version: "1.46.0",
        version_args: &["--version"],
        homepage: "https://github.com/anchore/syft",
        brew: Some("syft"),
        install_note: "Release binaries: https://github.com/anchore/syft/releases",
    },
    ToolSpec {
        id: "trivy",
        bin: "trivy",
        pinned_version: "0.72.0",
        version_args: &["--version"],
        homepage: "https://github.com/aquasecurity/trivy",
        brew: Some("trivy"),
        install_note: "Release binaries: https://github.com/aquasecurity/trivy/releases",
    },
    ToolSpec {
        id: "osv-scanner",
        bin: "osv-scanner",
        pinned_version: "2.4.0",
        version_args: &["--version"],
        homepage: "https://github.com/google/osv-scanner",
        brew: Some("osv-scanner"),
        install_note: "Release binaries: https://github.com/google/osv-scanner/releases",
    },
    ToolSpec {
        id: "grype",
        bin: "grype",
        pinned_version: "0.115.0",
        version_args: &["--version"],
        homepage: "https://github.com/anchore/grype",
        brew: Some("grype"),
        install_note: "Release binaries: https://github.com/anchore/grype/releases",
    },
    ToolSpec {
        id: "bumblebee",
        bin: "bumblebee",
        pinned_version: "0.1.2",
        version_args: &["version"],
        homepage: "https://github.com/perplexityai/bumblebee",
        brew: Some("bumblebee"),
        install_note: "Read-only endpoint inventory scanner (Go, zero dependencies). \
                       Release binaries: https://github.com/perplexityai/bumblebee/releases \
                       — exposure catalogs must use schema_version \"0.1.0\".",
    },
    ToolSpec {
        id: "cosign",
        bin: "cosign",
        pinned_version: "3.1.1",
        version_args: &["version"],
        homepage: "https://github.com/sigstore/cosign",
        brew: Some("cosign"),
        install_note: "Release binaries: https://github.com/sigstore/cosign/releases",
    },
    ToolSpec {
        id: "slsa-verifier",
        bin: "slsa-verifier",
        pinned_version: "2.7.1",
        version_args: &["version"],
        homepage: "https://github.com/slsa-framework/slsa-verifier",
        brew: Some("slsa-verifier"),
        install_note: "Release binaries: https://github.com/slsa-framework/slsa-verifier/releases",
    },
    ToolSpec {
        id: "opengrep",
        bin: "opengrep",
        pinned_version: "1.25.0",
        version_args: &["--version"],
        homepage: "https://github.com/opengrep/opengrep",
        brew: None,
        install_note: "No Homebrew formula; install a pinned release binary: \
                       https://github.com/opengrep/opengrep/releases",
    },
    ToolSpec {
        id: "semgrep",
        bin: "semgrep",
        pinned_version: "1.169.0",
        version_args: &["--version"],
        homepage: "https://github.com/semgrep/semgrep",
        brew: Some("semgrep"),
        install_note: "Also installable via pipx: pipx install semgrep==<pin>",
    },
    ToolSpec {
        id: "sighthound",
        bin: "sighthound",
        pinned_version: "1.0",
        version_args: &["--version"],
        homepage: "https://github.com/Corgea/Sighthound",
        brew: None,
        install_note:
            "Optional fast local Rust-based SAST layer (Corgea); install from upstream releases.",
    },
    ToolSpec {
        id: "gh",
        bin: "gh",
        pinned_version: "2.96.0",
        version_args: &["--version"],
        homepage: "https://cli.github.com",
        brew: Some("gh"),
        install_note: "Required for branch-protection verification (GitHub API).",
    },
    ToolSpec {
        id: "guacone",
        bin: "guacone",
        pinned_version: "1.1.0",
        version_args: &["version"],
        homepage: "https://github.com/guacsec/guac",
        brew: None,
        install_note: "GUAC CLI; see https://docs.guac.sh for the compose quickstart.",
    },
    ToolSpec {
        id: "oras",
        bin: "oras",
        pinned_version: "1.3.3",
        version_args: &["version"],
        homepage: "https://github.com/oras-project/oras",
        brew: Some("oras"),
        install_note: "Optional OCI metadata push (SBOMs/attestations as OCI artifacts).",
    },
    ToolSpec {
        id: "vexctl",
        bin: "vexctl",
        pinned_version: "0.4.4",
        version_args: &["version"],
        homepage: "https://github.com/openvex/vexctl",
        brew: Some("vexctl"),
        install_note: "Optional; sscsb generates OpenVEX natively, vexctl adds merge/attest.",
    },
    ToolSpec {
        id: "witness",
        bin: "witness",
        pinned_version: "0.12.0",
        version_args: &["version"],
        homepage: "https://github.com/in-toto/witness",
        brew: None,
        install_note: "Optional richer build-step attestation; see upstream releases.",
    },
    ToolSpec {
        id: "ssh-tpm-agent",
        bin: "ssh-tpm-agent",
        pinned_version: "0.9.0",
        version_args: &["--version"],
        homepage: "https://github.com/Foxboron/ssh-tpm-agent",
        brew: None,
        install_note: "Linux/TPM only: holds an ssh signing key inside the TPM (non-exportable). \
                       An empty-passphrase TPM key gives touchless agent signing. \
                       See docs/agent-signing.md; macOS/WSL have no TPM — this control degrades.",
    },
    ToolSpec {
        id: "model-signing",
        bin: "model_signing",
        pinned_version: "1.1.1",
        version_args: &["--version"],
        homepage: "https://github.com/sigstore/model-transparency",
        brew: None,
        install_note: "OpenSSF Model Signing CLI: `pip install model-signing==1.1.1` \
                       (invoked as `python3 -m model_signing`). Signs/verifies ML models with Sigstore.",
    },
    ToolSpec {
        id: "gittuf",
        bin: "gittuf",
        pinned_version: "0.15.0",
        version_args: &["version"],
        homepage: "https://github.com/gittuf/gittuf",
        brew: None,
        install_note: "`go install github.com/gittuf/gittuf@v0.15.0` or download release binaries; \
                       adds signed, forge-independent policy over git refs (RSL).",
    },
];

#[derive(Debug, Clone)]
pub enum ToolStatus {
    Found {
        path: String,
        version: Option<String>,
    },
    Missing,
}

pub fn spec(id: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.id == id)
}

/// Detect a tool: locate an EXECUTABLE on PATH and make it answer its own
/// version probe.
///
/// Both halves are load-bearing. A present-but-broken tool is not a working
/// tool: this used to swallow the probe's failure and report `Found` anyway, so
/// anything that merely occupied the name satisfied the control. Together with
/// `find_in_path`'s executable check, a three-line text file named `guacone`
/// no longer flips `sscsb verify --strict guac` from exit 1 to exit 0.
///
/// The probe must RUN, exit 0, and say something. It is deliberately not
/// required to yield a *parseable* version — `ToolStatus::Found.version` is an
/// `Option` because registry entries such as `sighthound` report two-component
/// versions that `extract_version` cannot parse, and declaring a genuinely
/// installed tool missing over that would be a false positive.
///
/// Residual, stated plainly: an *executable* stub that prints anything and
/// exits 0 still detects. Distinguishing a real tool from a convincing
/// impostor needs checksum or signature pinning of the binary itself, which is
/// a separate control, not a detection tweak.
pub fn detect(spec: &ToolSpec) -> ToolStatus {
    let Some(path) = exec::find_in_path(spec.bin) else {
        return ToolStatus::Missing;
    };
    let Ok(out) = exec::run(spec.bin, spec.version_args, None) else {
        return ToolStatus::Missing; // on PATH but unspawnable
    };
    let combined = format!("{} {}", out.stdout, out.stderr);
    if !out.success() || combined.trim().is_empty() {
        return ToolStatus::Missing;
    }
    ToolStatus::Found {
        path: path.display().to_string(),
        version: extract_version(&combined),
    }
}

pub fn is_available(id: &str) -> bool {
    spec(id).is_some_and(|s| matches!(detect(s), ToolStatus::Found { .. }))
}

/// The degrade message shown when an orchestrated tool is unavailable.
pub fn degrade_message(id: &str, platform: Platform) -> String {
    match spec(id) {
        None => format!("unknown tool `{id}`"),
        // `detect` reports Missing for two distinct situations, and telling an
        // operator "not found on PATH" about a binary sitting right there on
        // their PATH is a lie that costs them an hour. Ask PATH again so the
        // message matches the reason.
        Some(s) => unusable_message(s, platform, exec::find_in_path(s.bin).as_deref()),
    }
}

/// The body of [`degrade_message`], with the PATH answer passed in rather than
/// looked up, so both branches are testable without touching the process
/// environment.
fn unusable_message(s: &ToolSpec, platform: Platform, found_at: Option<&Path>) -> String {
    let install = match (platform, s.brew) {
        (Platform::MacOs, Some(f)) => format!("brew install {f}"),
        (Platform::Linux | Platform::Wsl, Some(f)) => {
            format!("brew install {f} (Linuxbrew) or see {}", s.install_note)
        }
        _ => s.install_note.to_string(),
    };
    match found_at {
        Some(p) => format!(
            "{id} found at {path} but `{bin} {probe}` did not succeed — present, not working, \
             so this control cannot run it. Pinned known-good version: {v}. \
             Repair or reinstall: {install} ({home})",
            id = s.id,
            path = p.display(),
            bin = s.bin,
            probe = s.version_args.join(" "),
            v = s.pinned_version,
            home = s.homepage
        ),
        None => format!(
            "{id} not found on PATH — this control cannot run its underlying tool. \
             Pinned known-good version: {v}. Install: {install} ({home})",
            id = s.id,
            v = s.pinned_version,
            home = s.homepage
        ),
    }
}

/// Extract the first `X.Y.Z`-shaped version from arbitrary tool output.
///
/// Every call site (`detect` → `ToolStatus::Found.version`) only ever
/// DISPLAYS the result next to `ToolSpec::pinned_version` for a human to
/// compare (`sscsb tools`, `sscsb verify` messages, degrade text) — nothing
/// in this codebase parses it back into a semver and compares it
/// programmatically against the pin. That is what decides the pre-release
/// question below: the reader is a person, not a comparator.
///
/// A semver pre-release or build-metadata suffix (`-rc1`, `+build.5`,
/// `-alpha.1+exp.sha.5114f85`) is kept in full, not trimmed to the bare
/// `X.Y.Z` core. An `rc` or `+build` artifact is not the same thing that got
/// pinned — silently reporting it as plain `X.Y.Z` would make a pre-release
/// look identical to the pin in that side-by-side display, which is a lie by
/// omission a human reading `sscsb tools` output would have no way to catch.
/// The suffix is only trusted when it is glued directly onto the patch
/// number by `-` or `+` (real semver syntax); anything else trailing after a
/// valid `X.Y.Z` core — a stray 4th dotted segment, other junk — is dropped
/// rather than appended, since it was never part of the version to begin
/// with (see `extract_version_drops_trailing_garbage_instead_of_returning_it`).
pub fn extract_version(text: &str) -> Option<String> {
    for token in text.split(|c: char| c.is_whitespace() || c == ',') {
        let t = token.trim_start_matches('v').trim_matches('"');
        // splitn(3, '.') rather than a full split: the third piece is
        // "everything after the second dot", so a pre-release/build suffix
        // that itself contains dots (`+build.5`) stays intact in `rest`
        // instead of being chopped into separate, indistinguishable parts.
        let mut components = t.splitn(3, '.');
        let major = components.next().unwrap_or("");
        let minor = components.next().unwrap_or("");
        let rest = components.next().unwrap_or("");

        let is_digits = |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit());
        if !is_digits(major) || !is_digits(minor) {
            continue;
        }

        let patch_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        if patch_len == 0 {
            continue; // no numeric patch component at all — not X.Y.Z-shaped
        }
        let (patch, suffix) = rest.split_at(patch_len);

        return Some(if suffix.starts_with('-') || suffix.starts_with('+') {
            format!("{major}.{minor}.{patch}{suffix}") // real semver suffix — keep verbatim
        } else {
            format!("{major}.{minor}.{patch}") // no marker: drop the trailing junk
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_no_duplicate_ids_and_all_pins_are_concrete() {
        let mut seen = std::collections::HashSet::new();
        for t in TOOLS {
            assert!(seen.insert(t.id), "duplicate tool id {}", t.id);
            // Pin must be a concrete dotted version — never "latest".
            let parts: Vec<&str> = t.pinned_version.split('.').collect();
            assert!(
                parts.len() >= 2
                    && parts
                        .iter()
                        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
                "tool {} pin `{}` is not a concrete version",
                t.id,
                t.pinned_version
            );
            assert!(!t.pinned_version.contains("latest"));
        }
    }

    #[test]
    fn extract_version_handles_common_shapes() {
        assert_eq!(
            extract_version("gitleaks version 8.30.1"),
            Some("8.30.1".into())
        );
        assert_eq!(extract_version("trufflehog 3.94.3"), Some("3.94.3".into()));
        assert_eq!(extract_version("Version: 0.72.0"), Some("0.72.0".into()));
        assert_eq!(extract_version("v2.4.0 (go1.24)"), Some("2.4.0".into()));
        assert_eq!(extract_version("no version here"), None);
    }

    #[test]
    fn extract_version_keeps_prerelease_and_build_metadata_suffixes() {
        // A pre-release or build-metadata suffix is semver syntax attached
        // directly to the patch number (no dot in between: `3-rc1`, not
        // `3.rc1`). It denotes a DIFFERENT artifact from the plain release —
        // an `rc` build must never be reported in a way that makes it look
        // identical to the pin — so the full suffix is kept, not stripped.
        assert_eq!(
            extract_version("gitleaks version 2.4.0-rc1"),
            Some("2.4.0-rc1".into())
        );
        // Build metadata may itself contain dots (semver: `+build.5`); those
        // dots belong to the suffix, not to a 4th version component, and
        // must be preserved rather than truncated at the first dot.
        assert_eq!(
            extract_version("trivy 1.2.3+build.5"),
            Some("1.2.3+build.5".into())
        );
        // Combined pre-release + build metadata (real semver example).
        assert_eq!(
            extract_version("tool 1.0.0-alpha.1+exp.sha.5114f85"),
            Some("1.0.0-alpha.1+exp.sha.5114f85".into())
        );
    }

    #[test]
    fn extract_version_drops_trailing_garbage_instead_of_returning_it() {
        // `1.2.3.abc` is not `1.2.3` with build metadata (no `-`/`+`
        // marker) — `.abc` is an unrelated 4th dotted segment. The valid
        // `X.Y.Z` core is real and should still be reported; the garbage
        // must not be tacked onto the returned string as if it were part of
        // the version.
        assert_eq!(extract_version("tool 1.2.3.abc"), Some("1.2.3".into()));
        assert_eq!(
            extract_version("osv-scanner version: 2.4.0.20260101"),
            Some("2.4.0".into())
        );
    }

    #[test]
    fn extract_version_matches_real_installed_tool_output() {
        // Captured verbatim from `<tool> --version` / `<tool> version` run on
        // this machine 2026-08-24 — real output, not invented fixtures. None
        // of these happen to carry a pre-release/build suffix today, but
        // they exercise the same first-token-wins scan the fix runs through,
        // including cosign's multi-line ASCII-art banner and trivy's
        // multi-line vulnerability-DB block, neither of which may parse as
        // an earlier false match.
        assert_eq!(extract_version("8.30.1\n"), Some("8.30.1".into())); // gitleaks version
        assert_eq!(
            extract_version("trufflehog 3.96.0\n"),
            Some("3.96.0".into())
        );
        assert_eq!(extract_version("syft 1.51.0\n"), Some("1.51.0".into()));
        assert_eq!(
            extract_version(
                "Version: 0.74.0\n\
                 Vulnerability DB:\n\
                 \x20 Version: 2\n\
                 \x20 UpdatedAt: 2026-08-24 13:01:06.952742724 +0000 UTC\n"
            ),
            Some("0.74.0".into())
        );
        assert_eq!(
            extract_version(
                "osv-scanner version: 2.5.1\n\
                 osv-scalibr version: 0.5.2\n\
                 commit: n/a\n\
                 built at: n/a\n"
            ),
            Some("2.5.1".into())
        );
        assert_eq!(
            extract_version(
                "  ______   ______        _______. __    _______ .__   __.\n\
                 \x20/      | /  __  \\      /       ||  |  /  _____||  \\ |  |\n\
                 cosign: A tool for Container Signing, Verification and Storage in an OCI registry\n\
                 \n\
                 GitVersion:    v3.1.3\n\
                 GitCommit:     11926fa5bbbbde47e88fc006b625a17769b743b2\n\
                 GoVersion:     go1.26.5\n"
            ),
            Some("3.1.3".into())
        );
        assert_eq!(extract_version("1.25.0\n"), Some("1.25.0".into())); // opengrep --version
    }

    #[test]
    fn detect_finds_git_class_binary_and_misses_absent() {
        // gh is in the registry and present on dev machines/CI images; but to
        // stay hermetic, test detection via a spec we construct for `git`.
        let fake = ToolSpec {
            id: "git-test",
            bin: "git",
            pinned_version: "2.0.0",
            version_args: &["--version"],
            homepage: "",
            brew: None,
            install_note: "",
        };
        match detect(&fake) {
            ToolStatus::Found { version, .. } => assert!(version.is_some()),
            ToolStatus::Missing => panic!("git must be detectable"),
        }
        let absent = ToolSpec {
            id: "absent",
            bin: "sscsb-definitely-not-a-real-binary",
            pinned_version: "1.0.0",
            version_args: &["--version"],
            homepage: "",
            brew: None,
            install_note: "",
        };
        assert!(matches!(detect(&absent), ToolStatus::Missing));
    }

    /// Write `script` as an executable file called `name` inside `dir`.
    #[cfg(unix)]
    fn shim(dir: &std::path::Path, name: &str, script: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A spec whose `bin` name cannot collide with anything on a real machine,
    /// so the decoy is always the only candidate and the fixture never has to
    /// hide a genuine install from the rest of the (threaded) suite.
    fn decoy_spec() -> ToolSpec {
        ToolSpec {
            id: "probe-decoy",
            bin: "sscsb-probe-decoy",
            pinned_version: "1.0.0",
            version_args: &["version"],
            homepage: "https://example.invalid/decoy",
            brew: None,
            install_note: "not a real tool",
        }
    }

    /// A binary that cannot answer its own version probe is not a working
    /// tool. `Found` used to be returned regardless of what the probe did —
    /// which, together with `find_in_path` accepting any regular file, is what
    /// let a three-line text file named `guacone` satisfy a control.
    #[cfg(unix)]
    #[test]
    fn detect_refuses_a_decoy_that_is_not_executable_or_cannot_answer_its_probe() {
        use std::os::unix::fs::PermissionsExt;
        let _lock = crate::testutil::env_lock();
        let dir = tempfile::tempdir().unwrap();
        // Prepend only — nothing on the real PATH is hidden, so a
        // concurrently-running test can still find and spawn its own tools.
        let _path = crate::testutil::PathPrepend::new(dir.path());
        let decoy = dir.path().join("sscsb-probe-decoy");

        // The reported shape: a three-line shell script nobody chmod'd.
        std::fs::write(
            &decoy,
            "#!/bin/sh\n# three lines, never chmod +x\necho hi\n",
        )
        .unwrap();
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o644)).unwrap();
        let status = detect(&decoy_spec());
        assert!(
            matches!(status, ToolStatus::Missing),
            "a non-executable text file must not detect as an installed tool: {status:?}"
        );

        // Half-installed: on PATH, executable, exits non-zero.
        shim(
            dir.path(),
            "sscsb-probe-decoy",
            "#!/bin/sh\necho 'missing shared library' 1>&2\nexit 1\n",
        );
        let broken = detect(&decoy_spec());
        assert!(
            matches!(broken, ToolStatus::Missing),
            "a tool whose version probe fails must not report as available: {broken:?}"
        );

        // A silent stub that exits 0 without saying anything is not a tool
        // either — every real version command prints something.
        shim(dir.path(), "sscsb-probe-decoy", "#!/bin/sh\nexit 0\n");
        let silent = detect(&decoy_spec());
        assert!(
            matches!(silent, ToolStatus::Missing),
            "a silent stub must not report as available: {silent:?}"
        );

        // And the working case still detects, with its version parsed — the
        // guard must not become a false negative for a real install.
        shim(
            dir.path(),
            "sscsb-probe-decoy",
            "#!/bin/sh\necho 'decoy version 1.2.3'\n",
        );
        match detect(&decoy_spec()) {
            ToolStatus::Found { version, path } => {
                assert_eq!(version.as_deref(), Some("1.2.3"));
                assert!(path.ends_with("sscsb-probe-decoy"), "{path}");
            }
            ToolStatus::Missing => panic!("a working tool must still be detected"),
        }

        // A tool that answers but with an unparseable version is still FOUND —
        // `sighthound` reports a two-component version, and calling that
        // missing would be a false positive.
        shim(
            dir.path(),
            "sscsb-probe-decoy",
            "#!/bin/sh\necho 'decoy 1.0'\n",
        );
        match detect(&decoy_spec()) {
            ToolStatus::Found { version, .. } => assert_eq!(version, None),
            ToolStatus::Missing => panic!("an unparseable version is not an absent tool"),
        }
    }

    /// Telling an operator a binary is "not found on PATH" when it is sitting
    /// right there costs them an hour. The two reasons `detect` reports
    /// Missing must read differently — asserted on the pure body so the test
    /// never touches the process environment.
    #[test]
    fn unusable_message_distinguishes_absent_from_present_but_broken() {
        let guacone = spec("guacone").unwrap();

        let absent = unusable_message(guacone, Platform::MacOs, None);
        assert!(absent.contains("guacone not found on PATH"), "{absent}");
        assert!(absent.contains("1.1.0"), "{absent}");

        let broken = unusable_message(
            guacone,
            Platform::MacOs,
            Some(std::path::Path::new("/usr/local/bin/guacone")),
        );
        assert!(
            broken.contains("found at /usr/local/bin/guacone"),
            "{broken}"
        );
        assert!(broken.contains("present, not working"), "{broken}");
        assert!(
            broken.contains("guacone version"),
            "names the probe: {broken}"
        );
        assert!(broken.contains("1.1.0"), "still names the pin: {broken}");
    }

    #[test]
    fn degrade_message_names_tool_pin_and_install_path() {
        let msg = degrade_message("gitleaks", Platform::MacOs);
        assert!(msg.contains("gitleaks"));
        assert!(msg.contains("8.30.1"));
        assert!(msg.contains("brew install gitleaks"));
        let msg2 = degrade_message("opengrep", Platform::Linux);
        assert!(msg2.contains("release"));
    }

    #[test]
    fn degrade_message_reports_unknown_tool_ids_instead_of_panicking() {
        let msg = degrade_message("not-a-registered-tool", Platform::MacOs);
        assert_eq!(msg, "unknown tool `not-a-registered-tool`");
    }

    #[test]
    fn degrade_message_offers_linuxbrew_on_linux_and_wsl_for_brew_formulas() {
        for platform in [Platform::Linux, Platform::Wsl] {
            let msg = degrade_message("gitleaks", platform);
            assert!(
                msg.contains("Linuxbrew"),
                "{platform} degrade message must mention Linuxbrew: {msg}"
            );
        }
    }

    #[test]
    fn is_available_is_false_for_unregistered_ids_and_agrees_with_detect_for_real_ones() {
        assert!(
            !is_available("sscsb-not-a-registered-tool-id"),
            "an id absent from the registry can never be available"
        );
        // For every real tool id, is_available must agree with an
        // independent detect() call — it is a thin, correct wrapper, not a
        // guess, regardless of which tools happen to be installed here.
        //
        // The two calls read the NATURAL PATH, twice, so they must not be
        // interleaved with a sibling test that masks or shims it: a tool that
        // vanishes between them looks like a wrapper bug and is not one.
        let _lock = crate::testutil::env_lock();
        for t in TOOLS {
            let expected = matches!(detect(t), ToolStatus::Found { .. });
            assert_eq!(is_available(t.id), expected, "mismatch for tool {}", t.id);
        }
    }
}
