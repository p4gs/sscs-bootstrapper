#![no_main]
//! Fuzz sscsb's dependency-manifest parsers across every ecosystem (untrusted
//! Cargo.lock / package-lock.json / requirements.txt / go.sum / Gemfile.lock).
use libfuzzer_sys::fuzz_target;
use sscsb::deps::Ecosystem;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let eco = match data[0] % 5 {
        0 => Ecosystem::Cargo,
        1 => Ecosystem::Npm,
        2 => Ecosystem::PyPi,
        3 => Ecosystem::Go,
        _ => Ecosystem::RubyGems,
    };
    if let Ok(s) = std::str::from_utf8(&data[1..]) {
        let _ = sscsb::deps::parse_deps(eco, s);
        let _ = sscsb::deps::parse_dep_specs(eco, s);
    }
});
