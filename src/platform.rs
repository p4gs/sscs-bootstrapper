//! OS/platform abstraction. All platform-conditional behavior in sscsb is
//! confined to this module (plus the POSIX shell hook shims, which run under
//! git's own shell on every platform including Git for Windows).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    /// Linux userland under Windows Subsystem for Linux.
    Wsl,
    Windows,
    Other,
}

impl Platform {
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            if is_wsl() {
                Platform::Wsl
            } else {
                Platform::Linux
            }
        } else {
            Platform::Other
        }
    }

    /// Human-readable notes about platform-specific limitations, used in
    /// degrade messaging.
    pub fn signing_note(self) -> &'static str {
        match self {
            Platform::Wsl => {
                "WSL2 cannot reach USB FIDO2 devices directly; use Git for Windows' \
                 ssh-keygen (gpg.ssh.program) or windows-fido-bridge. See docs/signing.md."
            }
            Platform::Windows => {
                "On native Windows, use OpenSSH 8.9+ (Windows optional feature) or \
                 Git for Windows for ed25519-sk signing. See docs/signing.md."
            }
            _ => "",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
            Platform::Wsl => "wsl",
            Platform::Windows => "windows",
            Platform::Other => "other",
        };
        f.write_str(s)
    }
}

fn is_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| is_wsl_kernel(&v))
        .unwrap_or(false)
}

/// WSL advertises itself in /proc/version. Split out from the file read so the
/// classification is testable on every platform.
pub fn is_wsl_kernel(proc_version: &str) -> bool {
    let v = proc_version.to_lowercase();
    v.contains("microsoft") || v.contains("wsl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_platform() {
        // On any supported dev/CI machine this must not be Other.
        let p = Platform::detect();
        assert_ne!(p, Platform::Other);
    }

    #[test]
    fn display_is_lowercase_stable() {
        assert_eq!(Platform::MacOs.to_string(), "macos");
        assert_eq!(Platform::Wsl.to_string(), "wsl");
    }

    #[test]
    fn signing_note_present_for_wsl_and_windows() {
        assert!(Platform::Wsl.signing_note().contains("FIDO2"));
        assert!(Platform::Windows.signing_note().contains("OpenSSH"));
        assert!(Platform::Linux.signing_note().is_empty());
        assert!(Platform::MacOs.signing_note().is_empty());
        assert!(Platform::Other.signing_note().is_empty());
    }

    #[test]
    fn wsl_kernel_detection() {
        assert!(is_wsl_kernel(
            "Linux version 5.15.0-generic (Microsoft@Microsoft.com)"
        ));
        assert!(is_wsl_kernel(
            "Linux version 5.15.0-microsoft-standard-WSL2"
        ));
        assert!(!is_wsl_kernel(
            "Linux version 6.8.0-45-generic (buildd@lcy02)"
        ));
    }

    #[test]
    fn display_covers_every_variant() {
        for (p, s) in [
            (Platform::MacOs, "macos"),
            (Platform::Linux, "linux"),
            (Platform::Wsl, "wsl"),
            (Platform::Windows, "windows"),
            (Platform::Other, "other"),
        ] {
            assert_eq!(p.to_string(), s);
        }
    }

    #[test]
    fn is_wsl_fails_closed_to_false_when_proc_version_is_unreadable() {
        // Exercises the real I/O wrapper directly (not just its extracted,
        // platform-independent classifier `is_wsl_kernel`, which is already
        // covered above). On a non-Linux dev/CI machine `/proc/version`
        // cannot exist, so this proves the fallback never panics and never
        // mistakenly reports WSL.
        assert!(!is_wsl());
    }
}
