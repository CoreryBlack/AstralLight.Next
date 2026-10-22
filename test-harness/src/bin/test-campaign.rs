use std::path::PathBuf;
use test_harness::campaign::{parse_options, run_options};

const USAGE: &str = "test-campaign — Rust campaign runner\n\nUsage:\n  cargo run -p test-harness --bin test-campaign -- [--list|--run] [--verify-items] [--profile ID] [--series ID] [--suite ID] [--all-profiles] [--json] [--run-id ID] [--artifact-root PATH]\n";

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{USAGE}");
        return;
    }
    let options = match parse_options(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("[BLOCKED] {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match run_options(&root, options) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("[BLOCKED] invalid inventory or runner precondition: {error}");
            std::process::exit(2);
        }
    }
}
