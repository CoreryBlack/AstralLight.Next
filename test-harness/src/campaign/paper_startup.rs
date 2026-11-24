use super::{execute_native, paper::mysql_scope, suite_id, utc_now, TomlValue, Value, LOG_LIMIT};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(super) const PREPARATION_ID: &str = "paper-usenix-mysql-prepare";

// Issue the short-lived fixture envelope after the offline suites, not before an hour-long soak.
pub(super) fn prepare_then_measure(
    suite: &TomlValue,
    env: &BTreeMap<OsString, OsString>,
    root: &Path,
    directory: &Path,
) -> Result<Value, String> {
    let run = env
        .get(OsStr::new(mysql_scope::RUN_ENV))
        .ok_or("missing paper run")?;
    if suite_id(suite) != "paper-usenix-mysql"
        || env.get(OsStr::new(mysql_scope::PREPARE_ENV)) != Some(run)
        || env.get(OsStr::new(mysql_scope::APPROVAL_ENV)) != Some(run)
    {
        return Err("paper startup preparation has no matching suite and run approval".into());
    }
    let mut prep = suite.clone();
    let args = prep
        .get_mut("argv")
        .and_then(TomlValue::as_array_mut)
        .ok_or("missing paper fixture command")?;
    let command = args
        .iter_mut()
        .find(|arg| arg.as_str() == Some("paper_mysql::cold_snapshot_and_warm_governance"))
        .ok_or("missing exact measured paper test")?;
    *command = "paper_mysql::prepare_signed_synthetic_cold_start".into();
    let fields = prep.as_table_mut().ok_or("invalid paper fixture")?;
    fields.remove("paper_lane");
    fields.insert("id".into(), PREPARATION_ID.into());
    fields.insert("darkstar_lane".into(), "paper-fixture-preparation".into());
    fields.insert(
        "darkstar_postcondition".into(),
        format!("paper-mysql: prepared run={} ", run.to_string_lossy()).into(),
    );
    let start = utc_now();
    let mut evidence = execute_native(&prep, env, root, directory, LOG_LIMIT)?;
    evidence["argv"] = json!(prep.get("argv"));
    evidence["started_at"] = json!(start);
    evidence["finished_at"] = json!(utc_now());
    if evidence["status"] != "PASS" {
        return Ok(
            json!({"status":evidence["status"],"exit_code":evidence["exit_code"],"reason":"required signed fixture preparation did not pass; measured command not dispatched", "log_integrity":evidence["log_integrity"],"stream_disconnect":evidence["stream_disconnect"],"stdout":null,"stderr":null,"paper_consumer_dispatched":false,"paper_preparation":evidence}),
        );
    }
    let mut child = env.clone();
    child.remove(OsStr::new(mysql_scope::PREPARE_ENV));
    let mut measured = execute_native(suite, &child, root, directory, LOG_LIMIT)?;
    measured["paper_preparation"] = evidence;
    measured["paper_consumer_dispatched"] = json!(true);
    Ok(measured)
}
