//! memory—v1 formal-path startup preflight: read-only, and it admits no listener.
//!
//! The formal single-node path keeps refusing to serve until memory-v1 production
//! adoption exists. Before that refusal it runs the production startup validation
//! that is possible today: one consistent read of the candidate database, an
//! installation of the rows as the process root, and a report of every evidence
//! family the production grade cannot prove. Dropping the owner makes every handle
//! fail, so the candidate cannot be read after the check returns, and the one-time
//! process root cannot be adopted later in the same process.
//!
//! Nothing here adopts, publishes or serves the root. A clean report would still
//! meet the readiness refusal, so this path never admits a request or a listener.

use anyhow::{bail, Context, Result};
use astral_authorization_root::memory_v1_adoption::ColdLoadFacts;
use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_common::config::AppConfig;

use crate::memory_v1_service::{capture_from_database, install_rows, split_capture};

/// Refusal prefix shared with the formal path's readiness gate.
const NOT_READY: &str = "memory-v1 production path is not ready for a listener";

/// Startup preflight of the formal path. `Ok` only when every evidence family is
/// proven, which the current candidate cannot reach; every other outcome is an error
/// that names its cause.
///
/// Precondition: the caller has already run the strict startup gates
/// (`validate_strict_startup_for`) for this configuration, because this connects to the
/// configured database.
pub(crate) async fn run(config: &AppConfig) -> Result<()> {
    let unproven = inspect(config).await.context(NOT_READY)?;
    refusal_for(&unproven).context(NOT_READY)
}

// memory—v1: Read the candidate database once and report what the candidate cannot prove.
async fn inspect(config: &AppConfig) -> Result<Vec<&'static str>> {
    let capture = capture_from_database(&config.database_url).await?;
    let (rows, facts) = split_capture(capture)?;
    unproven_of_rows(rows, &facts)
}

// memory—v1: Install the rows as the process root and report. The owner is dropped when this
// returns, so every handle fails afterwards.
fn unproven_of_rows(rows: CandidateRows, facts: &ColdLoadFacts) -> Result<Vec<&'static str>> {
    let owner = install_rows(rows)?;
    Ok(owner.unproven_production_families(facts))
}

// memory—v1: Only an empty report passes. Otherwise every unproven family is named, in
// decision order, so a single run shows the whole remaining gap.
fn refusal_for(unproven: &[&str]) -> Result<()> {
    if unproven.is_empty() {
        return Ok(());
    }
    bail!(
        "production adoption cannot prove {} evidence families: {}",
        unproven.len(),
        unproven.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use astral_authorization_root::memory_v1_root::{process_root_handle, RootError};

    use super::*;

    const UNPROVEN: [&str; 10] = [
        "source provenance",
        "consistent snapshot identity",
        "lifecycle and validity",
        "confirmation authority",
        "resource ownership",
        "eligibility",
        "separation of duties",
        "writer coverage",
        "audit correlation",
        "persistence and recovery",
    ];

    #[test]
    // memory—v1: Only an empty report passes; the refusal names every unproven family in order.
    fn refusal_names_every_unproven_family_and_only_an_empty_report_passes() {
        assert!(refusal_for(&[]).is_ok());
        let error = refusal_for(&UNPROVEN).unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "production adoption cannot prove 10 evidence families: {}",
                UNPROVEN.join("; ")
            )
        );
    }

    #[test]
    // memory—v1: The formal path reads and validates the candidate before its listener gates,
    // and never loads through the readiness loader.
    fn formal_path_reads_the_candidate_before_the_listener_gates() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let loaded = production
            .find("AppConfig::from_files_for_memory_v1_preflight(")
            .expect("the formal path loads through the preflight loader");
        let preflight = production
            .find("memory_v1_preflight::run(&config).await?;")
            .expect("the formal path runs the preflight");
        let listener_gate = production
            .find("config.validate_listener_for(JwtValidationRole::Gateway)?;")
            .expect("the formal path keeps its readiness gate");
        assert!(
            loaded < preflight && preflight < listener_gate,
            "the preflight must run before any listener gate"
        );
        assert!(
            !production.contains("AppConfig::from_files_for(\"application\""),
            "the formal path must not load through the readiness loader"
        );
    }

    #[test]
    // memory—v1: The check installs the candidate, names the ten families no cold load can
    // prove, and leaves no readable root behind. It runs in a child process because the process
    // root installs once per process.
    fn preflight_reports_the_unproven_families_and_retires_the_candidate() {
        const CHILD_ENV: &str = "ASTRAL_MEMORY_V1_PREFLIGHT_CHILD";
        if !in_isolated_child(
            "memory_v1_preflight::tests::preflight_reports_the_unproven_families_and_retires_the_candidate",
            CHILD_ENV,
        ) {
            return;
        }
        let (rows, _selections) = crate::memory_v1_composition::full_path_tests::fixture();
        let counts = rows.table_counts();
        let facts = ColdLoadFacts {
            schema_contract_version: 1,
            schema_fingerprint: [7; 32],
            snapshot_counts: counts,
            scanned_counts: counts,
            captured_at_unix_seconds: 1_700_000_000,
        };
        assert_eq!(unproven_of_rows(rows, &facts).unwrap(), UNPROVEN.to_vec());
        assert_eq!(
            process_root_handle().err(),
            Some(RootError::OwnerGone),
            "the candidate must be unreadable once the check returns"
        );
    }

    // memory—v1: Run the body in a child process. Returns `true` only in the child, which must
    // then run it; in the parent this spawns the child, asserts that it passed and returns `false`.
    fn in_isolated_child(test_path: &str, child_env: &str) -> bool {
        if std::env::var_os(child_env).is_some() {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_path, "--nocapture"])
            .env(child_env, "1")
            .output()
            .expect("failed to start the isolated test process");
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        false
    }
}
