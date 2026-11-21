use std::path::PathBuf;
use test_harness::campaign::{
    parse_options, run_darkstar_options, run_options, run_paper_options, DARKSTAR_USAGE,
    PAPER_USAGE,
};

const USAGE: &str = "test-campaign — Rust campaign runner\n\nUsage:\n  cargo run -p test-harness --bin test-campaign -- [--list|--run] [--verify-items] [--profile ID] [--series ID] [--suite ID] [--all-profiles] [--json] [--run-id ID] [--artifact-root PATH]\n";

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    if args.first().is_some_and(|arg| arg == "--paper") {
        match run_paper_options(&root, &args[1..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("[BLOCKED] {error}\n{PAPER_USAGE}");
                std::process::exit(2);
            }
        }
    }
    if args.first().is_some_and(|arg| arg == "--darkstar") {
        let result = run_darkstar_options(&root, &args[1..]);
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("{error}\n{DARKSTAR_USAGE}");
                std::process::exit(2);
            }
        }
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{USAGE}\n{PAPER_USAGE}\n{DARKSTAR_USAGE}");
        return;
    }
    let options = match parse_options(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("[BLOCKED] {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    match run_options(&root, options) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("[BLOCKED] invalid inventory or runner precondition: {error}");
            std::process::exit(2);
        }
    }
}
