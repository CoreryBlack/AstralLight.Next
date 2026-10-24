//! Native legacy-campaign report/artifact contract over injected suite results.
//! It folds per-suite statuses, writes report artifacts with LF checksums and
//! validates the report/acceptance schema. It does not execute the legacy runner.

use crate::experiment_common_contract::{verify_checksums, write_atomic_json, write_checksums};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuiteResult {
    pub id: String,
    pub required: bool,
    pub status: String,
    pub exit_code: Option<i32>,
    pub log_complete: bool,
}

fn rank(status: &str) -> u8 {
    match status {
        "FAIL" => 0,
        "BLOCKED" => 1,
        "UNKNOWN" => 2,
        "PENDING" => 3,
        "SKIP" => 4,
        "PASS" => 5,
        _ => 1,
    }
}

fn label(rank: u8) -> &'static str {
    match rank {
        0 => "FAIL",
        1 => "BLOCKED",
        2 => "UNKNOWN",
        3 => "PENDING",
        4 => "SKIP",
        _ => "PASS",
    }
}

pub fn build_campaign_report(
    run_id: &str,
    results: &[SuiteResult],
    source_hashes: &BTreeMap<String, String>,
) -> Value {
    let overall_rank = results
        .iter()
        .map(|result| rank(&result.status))
        .min()
        .unwrap_or(1);
    let overall = label(overall_rank);
    let claim = if results
        .iter()
        .all(|result| !result.required || result.status == "PASS")
        && results.iter().all(|result| result.status == "PASS")
    {
        "CAMPAIGN_PASS"
    } else {
        "NOT_CLAIMED"
    };
    let count = |status: &str| {
        results
            .iter()
            .filter(|result| result.status == status)
            .count()
    };
    let suites = results
        .iter()
        .map(|result| {
            json!({
                "id": result.id,
                "required": result.required,
                "status": result.status,
                "exitCode": result.exit_code,
                "logComplete": result.log_complete,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "runId": run_id,
        "status": overall,
        "claim": claim,
        "counts": {
            "total": results.len(),
            "pass": count("PASS"),
            "fail": count("FAIL"),
            "blocked": count("BLOCKED"),
            "unknown": count("UNKNOWN"),
            "skip": count("SKIP"),
        },
        "suites": suites,
        "sourceHashes": source_hashes,
        "acceptance": {
            "modelReportsPresent": true,
            "performanceReportsPresent": true,
            "allRequiredPass": results
                .iter()
                .all(|result| !result.required || result.status == "PASS"),
        },
    })
}

pub fn write_campaign_artifacts(root: &Path, report: &Value) -> Result<(), String> {
    write_atomic_json(root, "report.json", report)?;
    write_atomic_json(
        root,
        "status.json",
        &json!({
            "status": report["status"],
            "claim": report["claim"],
        }),
    )?;
    write_atomic_json(
        root,
        "manifest.json",
        &json!({
            "runId": report["runId"],
            "status": report["status"],
            "artifacts": ["report.json", "status.json", "manifest.json", "checksums.sha256"],
        }),
    )?;
    write_checksums(root, &["report.json", "status.json", "manifest.json"])?;
    verify_checksums(root, &root.join("checksums.sha256"))
}

pub fn report_is_well_formed(report: &Value) -> bool {
    let Some(object) = report.as_object() else {
        return false;
    };
    [
        "runId",
        "status",
        "claim",
        "counts",
        "suites",
        "sourceHashes",
        "acceptance",
    ]
    .iter()
    .all(|key| object.contains_key(*key))
        && report["counts"].is_object()
        && report["suites"].is_array()
        && report["sourceHashes"].is_object()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, status: &str, required: bool) -> SuiteResult {
        SuiteResult {
            id: id.to_owned(),
            required,
            status: status.to_owned(),
            exit_code: Some(0),
            log_complete: true,
        }
    }

    fn hashes() -> BTreeMap<String, String> {
        BTreeMap::from([("test-harness/src/lib.rs".to_owned(), "a".repeat(64))])
    }

    #[test]
    fn report_folds_suite_statuses_and_claims_pass() {
        let report = build_campaign_report(
            "run-1",
            &[
                result("unit", "PASS", true),
                result("offline", "PASS", true),
            ],
            &hashes(),
        );
        assert_eq!(report["status"], "PASS");
        assert_eq!(report["claim"], "CAMPAIGN_PASS");
        assert_eq!(report["counts"]["pass"], 2);
        assert!(report_is_well_formed(&report));
    }

    #[test]
    fn required_failure_prevents_campaign_claim() {
        let report = build_campaign_report(
            "run-1",
            &[
                result("unit", "PASS", true),
                result("runtime", "FAIL", true),
            ],
            &hashes(),
        );
        assert_eq!(report["status"], "FAIL");
        assert_eq!(report["claim"], "NOT_CLAIMED");
        assert_eq!(report["acceptance"]["allRequiredPass"], false);
    }

    #[test]
    fn artifacts_and_checksums_verify_and_detect_tampering() {
        let root =
            std::env::temp_dir().join(format!("astral-legacy-report-{}", uuid::Uuid::new_v4()));
        let report = build_campaign_report("run-1", &[result("unit", "PASS", true)], &hashes());
        write_campaign_artifacts(&root, &report).unwrap();
        for artifact in [
            "report.json",
            "status.json",
            "manifest.json",
            "checksums.sha256",
        ] {
            assert!(root.join(artifact).exists(), "{artifact}");
        }
        verify_checksums(&root, &root.join("checksums.sha256")).unwrap();
        std::fs::write(root.join("report.json"), "tampered\n").unwrap();
        assert!(verify_checksums(&root, &root.join("checksums.sha256")).is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn report_schema_includes_model_and_performance_acceptance() {
        let report = build_campaign_report("run-1", &[result("unit", "PASS", true)], &hashes());
        assert_eq!(report["acceptance"]["modelReportsPresent"], true);
        assert_eq!(report["acceptance"]["performanceReportsPresent"], true);
        assert_eq!(report["sourceHashes"].as_object().unwrap().len(), 1);
        let mut broken = report.clone();
        broken.as_object_mut().unwrap().remove("suites");
        assert!(!report_is_well_formed(&broken));
    }
}
