//! Registry of every external tool sscsb orchestrates: pinned known-good
//! versions, detection, and per-platform install hints. This module is the
//! SINGLE place versions are pinned — nothing in sscsb ever fetches "latest".
//!
//! Pins were resolved against upstream releases on 2026-07-12.

use crate::exec;
use crate::platform::Platform;

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

/// Detect a tool: locate on PATH and capture its reported version.
pub fn detect(spec: &ToolSpec) -> ToolStatus {
    match exec::find_in_path(spec.bin) {
        None => ToolStatus::Missing,
        Some(path) => {
            let version = exec::run(spec.bin, spec.version_args, None)
                .ok()
                .filter(|o| o.success())
                .and_then(|o| {
                    let combined = format!("{} {}", o.stdout, o.stderr);
                    extract_version(&combined)
                });
            ToolStatus::Found {
                path: path.display().to_string(),
                version,
            }
        }
    }
}

pub fn is_available(id: &str) -> bool {
    spec(id).is_some_and(|s| matches!(detect(s), ToolStatus::Found { .. }))
}

/// The degrade message shown when an orchestrated tool is unavailable.
pub fn degrade_message(id: &str, platform: Platform) -> String {
    match spec(id) {
        None => format!("unknown tool `{id}`"),
        Some(s) => {
            let install = match (platform, s.brew) {
                (Platform::MacOs, Some(f)) => format!("brew install {f}"),
                (Platform::Linux | Platform::Wsl, Some(f)) => {
                    format!("brew install {f} (Linuxbrew) or see {}", s.install_note)
                }
                _ => s.install_note.to_string(),
            };
            format!(
                "{id} not found on PATH — this control cannot run its underlying tool. \
                 Pinned known-good version: {v}. Install: {install} ({home})",
                v = s.pinned_version,
                home = s.homepage
            )
        }
    }
}

/// Extract the first `X.Y.Z`-shaped version from arbitrary tool output.
pub fn extract_version(text: &str) -> Option<String> {
    for token in text.split(|c: char| c.is_whitespace() || c == ',') {
        let t = token.trim_start_matches('v').trim_matches('"');
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() >= 3
            && parts
                .iter()
                .take(3)
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        {
            return Some(parts.join("."));
        }
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
        for t in TOOLS {
            let expected = matches!(detect(t), ToolStatus::Found { .. });
            assert_eq!(is_available(t.id), expected, "mismatch for tool {}", t.id);
        }
    }
}
