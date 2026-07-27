#![no_main]
//! Fuzz sscsb's commit-trailer parser (untrusted commit messages).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sscsb::hooks::parse_trailers(s);
    }
});
