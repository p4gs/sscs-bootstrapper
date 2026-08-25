#![no_main]
//! Fuzz sscsb's dependency-manifest parsers across every ecosystem (untrusted
//! Cargo.lock / package-lock.json / requirements.txt / go.sum / Gemfile.lock).
use libfuzzer_sys::fuzz_target;
use sscsb::deps::Ecosystem;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // The filename selects the parser for PyPi (pyproject.toml is TOML,
    // requirements.txt is line-oriented), so it is part of the input surface
    // and is fuzzed alongside the content rather than pinned to one shape.
    let (eco, file) = match data[0] % 6 {
        0 => (Ecosystem::Cargo, "Cargo.toml"),
        1 => (Ecosystem::Npm, "package.json"),
        2 => (Ecosystem::PyPi, "pyproject.toml"),
        3 => (Ecosystem::PyPi, "requirements.txt"),
        4 => (Ecosystem::Go, "go.mod"),
        _ => (Ecosystem::RubyGems, "Gemfile"),
    };
    if let Ok(s) = std::str::from_utf8(&data[1..]) {
        let _ = sscsb::deps::parse_deps(eco, file, s);
        let _ = sscsb::deps::parse_dep_specs(eco, file, s);
    }
});
