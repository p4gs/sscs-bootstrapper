#![no_main]
//! Fuzz sscsb's signer-policy parser (untrusted .sscsb/policy/signers.toml).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sscsb::hooks::parse_signers(s);
    }
});
