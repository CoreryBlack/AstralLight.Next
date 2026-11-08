//! `s15-probe` — S15 live identity-probe executor CLI.
//!
//! Talks ONLY to the frozen read-only test-control probe
//! (`GET /main/api/v1/internal/test-control/worker-id`) on the four
//! allowlisted S15 nodes (AL1–AL4). No business route is reachable from this
//! binary; fault/quorum control is not implemented (no protected production
//! primitive exists) and is never fabricated.
//!
//! Modes:
//! - `--check-config`: load and validate the protected configuration and the
//!   gateway key file. No network I/O ever happens in this mode.
//! - `--execute`: run the four-node probe and write stable artifacts.
//!   Requires `ASTRAL_S15_PROBE_CONFIRM=approved-run` in addition to the
//!   full protected configuration; anything else keeps the process
//!   network-inert and exits BLOCKED.
//!
//! Exit codes: 0 = PASS verdict (only with attested prerequisites),
//! 2 = usage/configuration error (fail-closed, no network), 3 = BLOCKED
//! verdict, 4 = UNKNOWN verdict. Values of protected variables are never
//! printed — only variable names and reason kinds.

use std::process::ExitCode;

use test_harness::readiness_contract::ReadinessStatus;
use test_harness::s15_probe_executor::{
    execute_s15_probe_run, execution_confirmed, load_gateway_key, load_prerequisites_from_env,
    unix_ms_now, write_probe_artifacts, S15ProbeRunInput, S15ProtectedProbeConfig,
    TlsProbeTransport, CONFIRM_VALUE, ENV_CONFIRM,
};
use test_harness::s15_validation::{S15Half, S15_NODE_PLACEMENTS};

const USAGE: &str = "s15-probe — S15 live read-only identity probe executor\n\nUsage:\n  s15-probe --check-config          Validate protected config and key file; no network.\n  s15-probe --execute               Run four-node signed identity/liveness probes; requires\n                                    ASTRAL_S15_PROBE_CONFIRM=approved-run.\n  s15-probe --help\n\nProtected configuration (values never logged; names only):\n  ASTRAL_S15_RUN_ID, ASTRAL_TEST_CONTROL_TOKEN, ASTRAL_S15_GATEWAY_HMAC_FILE,\n  ASTRAL_S15_ACTOR_USER_ID, ASTRAL_S15_ACTOR_IDENTITY_CARD,\n  ASTRAL_S15_ACTOR_USER_CARD, ASTRAL_S15_ACTOR_DOMAIN, ASTRAL_S15_ACTOR_TENANT,\n  ASTRAL_S15_NODE_AL1..AL4, ASTRAL_S15_ARTIFACT_ROOT,\n  ASTRAL_S15_ATTEMPT_TIMEOUT_MS (optional), ASTRAL_S15_MAX_ATTEMPTS (optional),\n  ASTRAL_S15_PREREQUISITES_FILE (declaration only; never evidence),\n  ASTRAL_S15_PROBE_CONFIRM (required for --execute)\n";

const EXIT_USAGE: u8 = 2;
const EXIT_BLOCKED: u8 = 3;
const EXIT_UNKNOWN: u8 = 4;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match args.first().map(String::as_str) {
        Some("--check-config") => run_check_config(),
        Some("--execute") => run_execute(),
        _ => {
            eprint!("[BLOCKED] s15-probe requires exactly one mode\n{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn half_label(half: S15Half) -> &'static str {
    match half {
        S15Half::A => "A",
        S15Half::B => "B",
    }
}

/// Config-only validation; strictly no network.
fn run_check_config() -> ExitCode {
    let config = match S15ProtectedProbeConfig::from_env() {
        Ok(config) => config,
        Err(report) => {
            eprintln!("[BLOCKED] s15-probe protected config invalid (values withheld): {report}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let key_bytes = match load_gateway_key(&config.gateway_hmac_file) {
        Ok(key) => key.len(),
        Err(reason) => {
            eprintln!(
                "[BLOCKED] s15-probe gateway key unusable ({}): {reason}",
                config.gateway_hmac_file.display()
            );
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let placements = S15_NODE_PLACEMENTS
        .iter()
        .map(|placement| {
            format!(
                "{}({})->{}",
                placement.node_id,
                half_label(placement.half),
                placement.database_id
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "[PASS] s15-probe config loaded; run_id={}; placements={}; attempts={}; timeout_ms={}; key_bytes={key_bytes}; no network performed",
        config.campaign_id,
        placements,
        config.max_attempts,
        config.attempt_timeout_ms,
    );
    ExitCode::SUCCESS
}

/// Full protected run: confirm gate → optional attestation → TLS probes →
/// stable artifacts. Every failure path is fail-closed with named reasons.
fn run_execute() -> ExitCode {
    let confirm = std::env::var(ENV_CONFIRM).ok();
    if !execution_confirmed(confirm.as_deref()) {
        eprintln!(
            "[BLOCKED] s15-probe --execute requires {ENV_CONFIRM}={CONFIRM_VALUE}; nothing was executed"
        );
        return ExitCode::from(EXIT_BLOCKED);
    }
    let config = match S15ProtectedProbeConfig::from_env() {
        Ok(config) => config,
        Err(report) => {
            eprintln!("[BLOCKED] s15-probe protected config invalid (values withheld): {report}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let key = match load_gateway_key(&config.gateway_hmac_file) {
        Ok(key) => key,
        Err(reason) => {
            eprintln!(
                "[BLOCKED] s15-probe gateway key unusable ({}): {reason}",
                config.gateway_hmac_file.display()
            );
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let prerequisites = match load_prerequisites_from_env() {
        Ok(prerequisites) => prerequisites,
        Err(reason) => {
            eprintln!("[BLOCKED] s15-probe prerequisites attestation unusable: {reason}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let mut transport = match TlsProbeTransport::new() {
        Ok(transport) => transport,
        Err(reason) => {
            eprintln!("[BLOCKED] s15-probe TLS transport unavailable: {reason}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let now_unix_ms = unix_ms_now();
    let record = match execute_s15_probe_run(
        &mut transport,
        &S15ProbeRunInput {
            config: &config,
            key,
            prerequisites,
            now_unix_ms,
        },
    ) {
        Ok(record) => record,
        Err(reason) => {
            eprintln!("[UNKNOWN] s15-probe run did not reach a terminal state: {reason}");
            return ExitCode::from(EXIT_UNKNOWN);
        }
    };
    let paths = match write_probe_artifacts(&config.artifact_root, &record) {
        Ok(paths) => paths,
        Err(reason) => {
            eprintln!("[BLOCKED] s15-probe artifact write refused: {reason}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    println!(
        "[{}] s15-probe verdict; blockers={}; problems={}; artifacts={}",
        record.verdict.status.as_str(),
        record.verdict.blockers.len(),
        record.verdict.problems.len(),
        paths.run_dir.display()
    );
    for blocker in &record.verdict.blockers {
        println!("blocker: {blocker}");
    }
    match record.verdict.status {
        ReadinessStatus::Pass => ExitCode::SUCCESS,
        ReadinessStatus::Unknown => ExitCode::from(EXIT_UNKNOWN),
        _ => ExitCode::from(EXIT_BLOCKED),
    }
}
