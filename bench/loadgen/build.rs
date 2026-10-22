use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

fn command_output(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(manifest_dir)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest directory");
    let manifest_dir = Path::new(&manifest_dir);
    let inputs = [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "src/measurement.rs",
    ];
    let mut hasher = Sha256::new();
    for input in inputs {
        println!("cargo:rerun-if-changed={input}");
        hasher.update(input.as_bytes());
        hasher.update([0]);
        if let Ok(contents) = fs::read(manifest_dir.join(input)) {
            hasher.update(contents);
        }
    }
    let source_sha256 = format!("{:x}", hasher.finalize());
    let source_revision = command_output(manifest_dir, &["rev-parse", "HEAD"])
        .unwrap_or_else(|| "unknown".to_owned());
    let source_dirty = command_output(
        manifest_dir,
        &["status", "--porcelain", "--", "bench/loadgen"],
    )
    .is_some_and(|status| !status.is_empty());
    println!("cargo:rustc-env=LOADGEN_SOURCE_REV={source_revision}");
    println!("cargo:rustc-env=LOADGEN_SOURCE_SHA256={source_sha256}");
    println!("cargo:rustc-env=LOADGEN_SOURCE_DIRTY={source_dirty}");
    println!(
        "cargo:rustc-env=LOADGEN_BUILD_PROFILE={}",
        std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into())
    );
    println!(
        "cargo:rustc-env=LOADGEN_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );
}
