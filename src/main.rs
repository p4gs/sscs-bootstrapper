use std::process::ExitCode;

fn main() -> ExitCode {
    match sscsb::cli::run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("sscsb error: {err:#}");
            ExitCode::from(2)
        }
    }
}
