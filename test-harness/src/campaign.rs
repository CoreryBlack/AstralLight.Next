use crate::{acceptance, model_acceptance};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
#[cfg(any(unix, test))]
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::process::{Child, ExitStatus, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use toml::Value as TomlValue;
use url::Url;

pub const STATUSES: [&str; 6] = ["FAIL", "UNKNOWN", "BLOCKED", "PENDING", "SKIP", "PASS"];
#[cfg(unix)]
const LOG_LIMIT: u64 = 64 * 1024 * 1024;
const DEFAULT_PROFILES: [&str; 3] = ["native-kernel", "offline-validation", "performance-kernel"];
const CLEAR_ENV: [&str; 19] = [
    "DATABASE_URL",
    "REDIS_URL",
    "RABBITMQ_URL",
    "RUST_INTEGRATION_REQUIRED",
    "ASTRAL_TEST_DATABASE_NAME",
    "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL",
    "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE",
    "MYSQL_ROOT_PASSWORD",
    "MYSQL_DATABASE",
    "RABBITMQ_USER",
    "RABBITMQ_PASSWORD",
    "COMPOSE_PROFILES",
    "SKIP_DOCKER",
    "ASTRAL_TARGET_REGION",
    "ASTRAL_PERF_CASE",
    "ASTRAL_PROJECTION_EXECUTION_MODE",
    "ASTRAL_REDIS_PROJECTION_COMPAT",
    "ASTRAL_MESSAGE_TRANSPORT",
    "ASTRAL_MIGRATION_ENV",
];

#[derive(Debug, Clone)]
pub struct Manifest {
    pub raw: TomlValue,
    pub profiles: BTreeMap<String, TomlValue>,
    pub series: BTreeMap<String, TomlValue>,
    pub suites: Vec<TomlValue>,
    pub root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub list: bool,
    pub run: bool,
    pub verify_items: bool,
    pub all_profiles: bool,
    pub json: bool,
    pub profiles: Vec<String>,
    pub series: Vec<String>,
    pub suite_ids: Vec<String>,
    pub run_id: String,
    pub artifact_root: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            list: true,
            run: false,
            verify_items: false,
            all_profiles: false,
            json: false,
            profiles: Vec::new(),
            series: Vec::new(),
            suite_ids: Vec::new(),
            run_id: format!("test-campaign-{}-{}", now.as_nanos(), std::process::id()),
            artifact_root: env::temp_dir(),
        }
    }
}

fn toml_array(value: Option<&TomlValue>) -> Vec<&TomlValue> {
    value
        .and_then(TomlValue::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn str_field<'a>(value: &'a TomlValue, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(TomlValue::as_str)
        .ok_or_else(|| format!("missing string field: {name}"))
}

fn string_array(value: &TomlValue, name: &str) -> Result<Vec<String>, String> {
    value
        .get(name)
        .and_then(TomlValue::as_array)
        .ok_or_else(|| format!("missing array field: {name}"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("invalid {name} entry"))
        })
        .collect()
}

fn registered_services(profile: &str) -> Option<Vec<&'static str>> {
    crate::dependency_profiles::profile_services(profile).map(|services| services.to_vec())
}

pub fn read_manifest(root: &Path) -> Result<Manifest, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolve workspace root: {error}"))?;
    let path = root.join("tests-suite/MANIFEST.toml");
    let text = fs::read_to_string(&path).map_err(|error| format!("read manifest: {error}"))?;
    let raw: TomlValue =
        toml::from_str(&text).map_err(|error| format!("parse manifest: {error}"))?;
    let profiles = toml_array(raw.get("profile"))
        .into_iter()
        .map(|item| {
            let id = str_field(item, "id")?.to_owned();
            Ok((id, item.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if profiles.len() != toml_array(raw.get("profile")).len() {
        return Err("duplicate profile id".into());
    }
    let expected_profiles = crate::dependency_profiles::PROFILE_IDS
        .into_iter()
        .collect::<BTreeSet<_>>();
    if profiles.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_profiles {
        return Err("unknown or missing production profile".into());
    }
    for (id, profile) in &profiles {
        let expected = registered_services(id)
            .expect("known profile")
            .into_iter()
            .collect::<Vec<_>>();
        let actual = string_array(profile, "production_services")?;
        if actual.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(format!("production service contract differs: {id}"));
        }
    }
    let series: BTreeMap<String, TomlValue> = toml_array(raw.get("series"))
        .into_iter()
        .map(|item| Ok((str_field(item, "id")?.to_owned(), item.clone())))
        .collect::<Result<_, String>>()?;
    if series.len() != toml_array(raw.get("series")).len() {
        return Err("duplicate series id".into());
    }
    let suites = toml_array(raw.get("suite"))
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    for suite in &suites {
        let id = str_field(suite, "id")?;
        if !safe_id(id) || !seen.insert(id.to_owned()) {
            return Err(format!("invalid or duplicate suite id: {id}"));
        }
        let profile = str_field(suite, "profile")?;
        let Some(profile_def) = profiles.get(profile) else {
            return Err(format!("unknown suite profile: {id}"));
        };
        if string_array(suite, "test_services")?
            != string_array(profile_def, "production_services")?
        {
            return Err(format!("test/production dependency mismatch: {id}"));
        }
        let labels = string_array(suite, "series")?;
        if labels.is_empty() || labels.iter().any(|label| !series.contains_key(label)) {
            return Err(format!("unknown or missing series: {id}"));
        }
        let scope = str_field(suite, "scope")?;
        if !["component", "offline-model", "integration", "live-campaign"].contains(&scope) {
            return Err(format!("missing evidence scope: {id}"));
        }
        if suite
            .get("selection_policy")
            .and_then(TomlValue::as_str)
            .is_some_and(|policy| policy != "explicit-suite")
        {
            return Err(format!("unknown suite selection policy: {id}"));
        }
        for field in ["owner", "boundary"] {
            if str_field(suite, field).is_err() {
                return Err(format!("missing ownership/proof boundary: {id}"));
            }
        }
        for source in string_array(suite, "sources")? {
            let source_path = root.join(&source);
            let resolved = source_path.canonicalize().unwrap_or(source_path.clone());
            if !resolved.starts_with(&root) || !resolved.exists() {
                return Err(format!("missing or out-of-scope source: {source}"));
            }
        }
        if suite.get("blocked_reason").is_some() {
            if suite
                .get("argv")
                .and_then(TomlValue::as_array)
                .is_some_and(|argv| !argv.is_empty())
            {
                return Err(format!(
                    "blocked campaign must not dispatch legacy argv: {id}"
                ));
            }
            continue;
        }
        let argv = string_array(suite, "argv")?;
        if argv.is_empty() {
            return Err(format!("invalid argv: {id}"));
        }
        if !["cargo", "bash"].contains(&argv[0].as_str()) {
            return Err(format!("unregistered command tool: {id}"));
        }
        if argv[0] == "cargo"
            && (argv.len() < 2
                || ![
                    "check", "test", "clippy", "fmt", "tree", "bench", "run", "-B",
                ]
                .contains(&argv[1].as_str()))
        {
            return Err(format!("unsupported Cargo operation: {id}"));
        }
        if argv.iter().any(|arg| arg.contains("://")) {
            return Err(format!("inline connection URL: {id}"));
        }
        if suite.get("evidence_contract").is_some() {
            let contract = str_field(suite, "evidence_contract")?;
            if !["policy-evaluate-benefit"].contains(&contract)
                || suite.get("acceptance").and_then(TomlValue::as_str) != Some("rust")
            {
                return Err(format!("unknown or incompatible evidence contract: {id}"));
            }
        }
        let timeout = suite
            .get("timeout_seconds")
            .and_then(TomlValue::as_integer)
            .unwrap_or(600);
        if !(1..=3600).contains(&timeout) {
            return Err(format!("invalid bounded timeout: {id}"));
        }
        let acceptance = str_field(suite, "acceptance")?;
        if ![
            "rust",
            "model-json",
            "command",
            "dependency-tree",
            "criterion",
            "criterion-smoke",
            "divan",
        ]
        .contains(&acceptance)
        {
            return Err(format!("unknown acceptance contract: {id}"));
        }
        if ["criterion", "criterion-smoke", "divan"].contains(&acceptance) {
            let cases = suite
                .get("benchmark_cases")
                .and_then(TomlValue::as_array)
                .ok_or_else(|| format!("missing benchmark cases: {id}"))?;
            let unique = cases
                .iter()
                .filter_map(TomlValue::as_str)
                .collect::<BTreeSet<_>>();
            if cases.is_empty() || unique.len() != cases.len() {
                return Err(format!("missing or duplicate benchmark cases: {id}"));
            }
        }
        if suite.get("ignored_policy").and_then(TomlValue::as_str) == Some("outside-selection")
            && (!argv
                .iter()
                .any(|arg| arg == "--workspace" || arg == "--lib")
                || argv.iter().any(|arg| arg == "--ignored"))
        {
            return Err(format!(
                "ignored checks must retain explicit separate selection: {id}"
            ));
        }
    }
    Ok(Manifest {
        raw,
        profiles,
        series,
        suites,
        root,
    })
}

pub fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn suite_labels(suite: &TomlValue) -> Vec<String> {
    string_array(suite, "series").unwrap_or_default()
}
fn suite_profile(suite: &TomlValue) -> String {
    suite
        .get("profile")
        .and_then(TomlValue::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn suite_id(suite: &TomlValue) -> String {
    suite
        .get("id")
        .and_then(TomlValue::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub fn select_suites(
    manifest: &Manifest,
    profiles: &[String],
    labels: &[String],
    suite_ids: &[String],
    running: bool,
    all_profiles: bool,
) -> Result<Vec<TomlValue>, String> {
    let known_profiles = manifest
        .profiles
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if profiles
        .iter()
        .any(|profile| !known_profiles.contains(profile.as_str()))
    {
        return Err("unknown profile selection".into());
    }
    let known_labels = manifest
        .series
        .keys()
        .cloned()
        .chain([
            "RQ".into(),
            "M".into(),
            "E".into(),
            "MT".into(),
            "PERF".into(),
            "CORE".into(),
            "ALL".into(),
        ])
        .collect::<BTreeSet<_>>();
    if labels.iter().any(|label| !known_labels.contains(label)) {
        return Err("unknown series selection".into());
    }
    let known_suites = manifest
        .suites
        .iter()
        .map(suite_id)
        .collect::<BTreeSet<_>>();
    if suite_ids.iter().any(|id| !known_suites.contains(id)) {
        return Err("unknown suite selection".into());
    }
    if all_profiles && !profiles.is_empty() {
        return Err("all-profiles and explicit profiles are mutually exclusive".into());
    }
    let mut profile_set = profiles.iter().cloned().collect::<BTreeSet<_>>();
    if running && !all_profiles && profiles.is_empty() && suite_ids.is_empty() && labels.is_empty()
    {
        profile_set.extend(DEFAULT_PROFILES.iter().map(|value| value.to_string()));
    }
    let portable = running && !all_profiles && suite_ids.is_empty() && labels.is_empty();
    let selected = manifest
        .suites
        .iter()
        .filter(|suite| {
            (profile_set.is_empty() || profile_set.contains(&suite_profile(suite)))
                && labels_match(&suite_labels(suite), labels)
                && (suite_ids.is_empty() || suite_ids.contains(&suite_id(suite)))
                && (!portable || suite.get("blocked_reason").is_none())
                && !(running
                    && !all_profiles
                    && suite_ids.is_empty()
                    && suite.get("selection_policy").and_then(TomlValue::as_str)
                        == Some("explicit-suite"))
        })
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err("empty test selection".into());
    }
    Ok(selected)
}

fn labels_match(series: &[String], labels: &[String]) -> bool {
    if labels.is_empty() || labels.iter().any(|label| label == "ALL") {
        return true;
    }
    series.iter().any(|series_label| {
        labels.iter().any(|label| {
            label == series_label
                || match label.as_str() {
                    "RQ" => numbered_family(series_label, "RQ"),
                    "M" => numbered_family(series_label, "M"),
                    "E" => numbered_family(series_label, "E"),
                    "MT" => series_label.strip_prefix("MT-E").is_some_and(|suffix| {
                        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                    }),
                    _ => false,
                }
        })
    })
}
fn numbered_family(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

pub fn prepare_environment(
    suite: &TomlValue,
    original: &[(OsString, OsString)],
) -> (BTreeMap<OsString, OsString>, Option<String>) {
    let mut result = original.iter().cloned().collect::<BTreeMap<_, _>>();
    for name in CLEAR_ENV {
        result.remove(OsString::from(name).as_os_str());
    }
    result.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
    let profile = suite_profile(suite);
    let Some(services) = registered_services(&profile) else {
        return (
            result,
            Some(format!("unregistered test profile: {profile}")),
        );
    };
    result.insert(
        "ASTRAL_MESSAGE_TRANSPORT".into(),
        if services.contains(&"rabbitmq") {
            "rabbit"
        } else {
            "local"
        }
        .into(),
    );
    if services.is_empty() {
        return (result, None);
    }
    let lookup = |name: &str| {
        original
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    if lookup("TEST_USE_EXISTING") != "1" {
        return (
            result,
            Some(
                "TEST_USE_EXISTING=1 is required; this runner does not provision or migrate".into(),
            ),
        );
    }
    if lookup("ASTRAL_MIGRATION_ENV") != "isolated" || lookup("RUST_INTEGRATION_REQUIRED") != "1" {
        return (
            result,
            Some("isolated migration environment and required integration mode are missing".into()),
        );
    }
    let dedicated =
        suite.get("database_scope").and_then(TomlValue::as_str) == Some("identity-mapping");
    let (url_key, name_key, prefix, max_suffix) = if dedicated {
        (
            "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL",
            "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE",
            "sdk_identity_mapping_test_",
            38usize,
        )
    } else {
        (
            "DATABASE_URL",
            "ASTRAL_TEST_DATABASE_NAME",
            "astral_rehearsal_",
            47usize,
        )
    };
    let url = lookup(url_key);
    let expected_name = lookup(name_key);
    let parsed = Url::parse(&url).ok();
    let path_name = parsed
        .as_ref()
        .map(|value| value.path().trim_start_matches('/').to_owned())
        .unwrap_or_default();
    let valid_name = path_name.starts_with(prefix)
        && path_name.len() > prefix.len()
        && path_name.len() <= prefix.len() + max_suffix
        && path_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && path_name == expected_name;
    let valid_url = parsed.as_ref().is_some_and(|value| {
        value.scheme() == "mysql"
            && matches!(value.host_str(), Some("localhost" | "127.0.0.1"))
            && value.port() == Some(3308)
            && value.query().is_none()
            && value.fragment().is_none()
    });
    if !valid_url || !valid_name {
        return (
            result,
            Some(format!(
                "{url_key} must select the allowlisted isolated loopback database"
            )),
        );
    }
    result.insert("DATABASE_URL".into(), url.into());
    result.insert("RUST_INTEGRATION_REQUIRED".into(), "1".into());
    result.insert("ASTRAL_MIGRATION_ENV".into(), "isolated".into());
    result.insert(name_key.into(), path_name.into());
    for (service, key, scheme, port) in [("rabbitmq", "RABBITMQ_URL", "amqp", 5673)] {
        if !services.contains(&service) {
            continue;
        }
        let value = lookup(key);
        let parsed = Url::parse(&value).ok();
        let valid = parsed.as_ref().is_some_and(|url| {
            url.scheme() == scheme
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
                && url.port() == Some(port)
                && url.fragment().is_none()
                && (service != "rabbitmq" || url.path().len() > 1)
        });
        if !valid {
            return (
                result,
                Some(format!(
                    "{key} is missing its isolated loopback service or explicit vhost"
                )),
            );
        }
        result.insert(key.into(), value.into());
    }
    (result, None)
}

pub fn classify_output(
    suite: &TomlValue,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
    interrupted: bool,
) -> Value {
    let acceptance = suite
        .get("acceptance")
        .and_then(TomlValue::as_str)
        .unwrap_or("command");
    let combined = format!("{stdout}\n{stderr}");
    if interrupted
        || matches!(exit_code, 124 | 130 | 137 | 143)
        || exit_code < 0
        || status_marker(&combined, "UNKNOWN")
    {
        return json!({"status":"UNKNOWN", "reason":"runner interrupted, deadline exceeded or durable outcome unproven"});
    }
    if exit_code != 0 {
        return json!({"status":"FAIL", "reason":format!("required command exited {exit_code}")});
    }
    if suite.get("evidence_contract").is_some() && acceptance != "rust" {
        return json!({"status":"FAIL", "reason":"evidence contracts require Rust summary acceptance"});
    }
    let minimum = suite
        .get("minimum_tests")
        .and_then(TomlValue::as_integer)
        .unwrap_or(1)
        .max(1) as usize;
    let expected = suite
        .get("expected_tests")
        .and_then(TomlValue::as_integer)
        .map(|value| value.max(0) as usize);
    let allow_ignored =
        suite.get("ignored_policy").and_then(TomlValue::as_str) == Some("outside-selection");
    if acceptance == "rust" {
        let result = acceptance::check_rust_output_with_policy(acceptance::RustOutputPolicy {
            expected_tests: expected,
            minimum_tests: minimum,
            performance_cases: suite
                .get("performance_cases")
                .and_then(TomlValue::as_integer)
                .map(|value| value as usize),
            stdout,
            stderr,
            exit_code,
            interrupted,
            allow_outside_selection_ignored: allow_ignored,
        });
        if result["status"] != "PASS" {
            return result;
        }
        if let Some(contract) = suite.get("evidence_contract").and_then(TomlValue::as_str) {
            let mut evidence = match contract {
                "policy-evaluate-benefit" => {
                    crate::evaluate_acceptance::check_evaluate_performance(stdout)
                }
                _ => {
                    return json!({"status":"FAIL", "reason":"unregistered Rust evidence contract"})
                }
            };
            if let (Some(evidence_object), Some(tests)) =
                (evidence.as_object_mut(), result.get("tests").cloned())
            {
                evidence_object.insert("tests".into(), tests);
            }
            return evidence;
        }
        return result;
    }
    for status in ["PENDING", "BLOCKED", "FAIL"] {
        if status_marker(&combined, status) {
            return json!({"status":status, "reason":format!("command reported explicit [{status}] state")});
        }
    }
    if status_marker(&combined, "SKIP") {
        return json!({"status":"SKIP", "reason":"a required check returned an internal skip"});
    }
    match acceptance {
        "model-json" => {
            let parsed = serde_json::from_str::<Value>(stdout);
            match parsed {
                Ok(value) => match suite.get("model_contract").and_then(TomlValue::as_str) {
                    Some("full-contract") => model_acceptance::check_full_contract(
                        &value,
                        suite
                            .get("model_name")
                            .and_then(TomlValue::as_str)
                            .unwrap_or(""),
                    ),
                    Some("universal") => model_acceptance::check_universal(&value),
                    Some("tenant") => model_acceptance::check_tenant(&value),
                    _ => {
                        json!({"status":"FAIL", "reason":"unregistered abstract-model acceptance contract"})
                    }
                },
                Err(_) => {
                    json!({"status":"UNKNOWN", "reason":"missing structured abstract-model result"})
                }
            }
        }
        "criterion" | "criterion-smoke" => {
            let cases = suite
                .get("benchmark_cases")
                .and_then(TomlValue::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(TomlValue::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            acceptance::check_criterion(&cases, stdout, acceptance == "criterion-smoke")
        }
        "divan" => {
            let cases = suite
                .get("benchmark_cases")
                .and_then(TomlValue::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(TomlValue::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let allocation_cases = suite
                .get("allocation_cases")
                .and_then(TomlValue::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(TomlValue::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            acceptance::check_divan(&cases, &allocation_cases, stdout)
        }
        "dependency-tree" => {
            if !stdout
                .lines()
                .any(|line| line.starts_with("astral-single-node v"))
            {
                return json!({"status":"FAIL", "reason":"missing native default dependency tree"});
            }
            if stdout.lines().any(|line| line.starts_with("redis v")) {
                return json!({"status":"FAIL", "reason":"default native binary compiled a Redis dependency"});
            }
            json!({"status":"PASS","reason":"native dependency tree contains no Redis"})
        }
        "unittest" => {
            json!({"status":"FAIL", "reason":"retired non-Rust test acceptance contract"})
        }
        _ => {
            if suite
                .get("required_output")
                .and_then(TomlValue::as_str)
                .is_some_and(|required| !combined.contains(required))
            {
                return json!({"status":"FAIL", "reason":"required command postcondition output is absent"});
            }
            json!({"status":"PASS", "reason":"scoped command completed; see its component proof boundary"})
        }
    }
}

fn status_marker(text: &str, status: &str) -> bool {
    let lower = format!("[{status}]", status = status.to_ascii_lowercase());
    text.lines()
        .any(|line| line.contains(&format!("[{status}]")) || line.contains(&lower))
}

pub fn fold_status(records: &[Value]) -> &'static str {
    STATUSES
        .iter()
        .copied()
        .find(|status| {
            records
                .iter()
                .any(|record| record["status"].as_str() == Some(status))
        })
        .unwrap_or("BLOCKED")
}

pub fn scrub_log(text: &str, env: &[(OsString, OsString)]) -> String {
    let sensitive = [
        "SECRET",
        "PASSWORD",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "DATABASE_URL",
        "REDIS_URL",
        "RABBITMQ_URL",
    ];
    let mut values = env
        .iter()
        .filter_map(|(name, value)| {
            let name = name.to_string_lossy().to_ascii_uppercase();
            let value = value.to_string_lossy().into_owned();
            (!value.is_empty() && sensitive.iter().any(|needle| name.contains(needle)))
                .then_some(value)
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    let mut result = text.to_owned();
    for value in values {
        result = result.replace(&value, "[redacted]");
    }
    let url_re =
        regex::Regex::new(r#"[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+"#).expect("constant regex");
    url_re.replace_all(&result, "[redacted-url]").into_owned()
}

#[cfg(unix)]
fn path_from_git_bytes(path: &[u8]) -> Result<PathBuf, String> {
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path)))
}

#[cfg(not(unix))]
fn path_from_git_bytes(path: &[u8]) -> Result<PathBuf, String> {
    let path = std::str::from_utf8(path)
        .map_err(|error| format!("git path is not valid UTF-8 on this platform: {error}"))?;
    Ok(PathBuf::from(path))
}

pub fn snapshot_hash(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("git ls-files: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed".into());
    }
    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(path_from_git_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    let mut digest = Sha256::new();
    for relative in paths {
        digest.update(relative.as_os_str().as_encoded_bytes());
        digest.update([0]);
        let path = root.join(&relative);
        match fs::read(&path) {
            Ok(bytes) => digest.update(Sha256::digest(bytes)),
            Err(_) => digest.update(b"missing"),
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(any(unix, test))]
fn read_limited_to<R: Read>(reader: R, limit: u64) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut output = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut output)?;
    let truncated = output.len() as u64 > limit;
    if truncated {
        output.truncate(limit as usize);
    }
    Ok((output, truncated))
}

#[cfg(unix)]
fn read_bounded_logs(
    stdout_path: &Path,
    stderr_path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, Vec<u8>, bool), String> {
    let stdout_size = fs::metadata(stdout_path)
        .map_err(|error| format!("inspect stdout artifact: {error}"))?
        .len();
    let stderr_size = fs::metadata(stderr_path)
        .map_err(|error| format!("inspect stderr artifact: {error}"))?
        .len();
    let stdout_limit = stdout_size.min(limit);
    let stderr_limit = stderr_size.min(limit.saturating_sub(stdout_limit));
    let (stdout, stdout_truncated) = read_limited_to(
        File::open(stdout_path).map_err(|error| format!("read stdout artifact: {error}"))?,
        stdout_limit,
    )
    .map_err(|error| format!("read stdout artifact: {error}"))?;
    let (stderr, stderr_truncated) = read_limited_to(
        File::open(stderr_path).map_err(|error| format!("read stderr artifact: {error}"))?,
        stderr_limit,
    )
    .map_err(|error| format!("read stderr artifact: {error}"))?;
    let truncated =
        stdout_truncated || stderr_truncated || stdout_size.saturating_add(stderr_size) > limit;
    Ok((stdout, stderr, truncated))
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: i32) -> Result<(), String> {
    let result = unsafe { libc::kill(-(pid as i32), signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!("signal owned process group: {error}"))
    }
}

#[cfg(unix)]
fn process_group_exists(pid: u32) -> Result<bool, String> {
    let result = unsafe { libc::kill(-(pid as i32), 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!("inspect owned process group: {error}")),
    }
}

#[cfg(unix)]
fn wait_process_group(pid: u32, timeout: Duration) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_exists(pid)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn stop_process_group(child: &mut Child, pid: u32) -> Result<(ExitStatus, bool), String> {
    signal_group(pid, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut child_status = None;
    let group_stopped = loop {
        if child_status.is_none() {
            child_status = child
                .try_wait()
                .map_err(|error| format!("wait terminated child: {error}"))?;
        }
        let stopped = !process_group_exists(pid)?;
        if child_status.is_some() && stopped {
            break stopped;
        }
        if Instant::now() >= deadline {
            break stopped;
        }
        thread::sleep(Duration::from_millis(50));
    };
    if !group_stopped {
        signal_group(pid, libc::SIGKILL)?;
    }
    if child_status.is_none() {
        child_status = Some(
            child
                .wait()
                .map_err(|error| format!("wait terminated child: {error}"))?,
        );
    }
    let group_stopped = if group_stopped {
        true
    } else {
        wait_process_group(pid, Duration::from_secs(15))?
    };
    Ok((
        child_status.expect("child status is reconciled"),
        group_stopped,
    ))
}

#[cfg(unix)]
fn wait_child(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait child: {error}"))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn copy_bounded<R: Read, W: Write>(
    mut reader: R,
    writer: &mut W,
    budget: &AtomicU64,
    limit: u64,
    overflow: &AtomicBool,
) -> Result<(), String> {
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("read child output: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        let mut reserved = budget.load(Ordering::Acquire);
        let allowed = loop {
            let allowed = limit.saturating_sub(reserved).min(read as u64);
            match budget.compare_exchange_weak(
                reserved,
                reserved.saturating_add(allowed),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break allowed as usize,
                Err(actual) => reserved = actual,
            }
        };
        if allowed < read {
            overflow.store(true, Ordering::Release);
        }
        writer
            .write_all(&buffer[..allowed])
            .map_err(|error| format!("write child output artifact: {error}"))?;
    }
}

pub fn execute(
    suite: &TomlValue,
    env: &BTreeMap<OsString, OsString>,
    root: &Path,
    directory: &Path,
) -> Result<Value, String> {
    #[cfg(unix)]
    {
        execute_posix(suite, env, root, directory, LOG_LIMIT)
    }
    #[cfg(not(unix))]
    {
        let _ = (suite, env, root, directory);
        Err("campaign execution requires POSIX process-group log capture".into())
    }
}

#[cfg(unix)]
fn execute_posix(
    suite: &TomlValue,
    env: &BTreeMap<OsString, OsString>,
    root: &Path,
    directory: &Path,
    log_limit: u64,
) -> Result<Value, String> {
    use std::os::unix::process::CommandExt;

    let argv = string_array(suite, "argv")?;
    let stdout_path = directory.join(format!("{}.stdout.log", suite_id(suite)));
    let stderr_path = directory.join(format!("{}.stderr.log", suite_id(suite)));
    let stdout_file = File::options()
        .write(true)
        .create_new(true)
        .open(&stdout_path)
        .map_err(|error| format!("create stdout artifact: {error}"))?;
    let stderr_file = File::options()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
        .map_err(|error| format!("create stderr artifact: {error}"))?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(root)
        .env_clear()
        .envs(env)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn suite: {error}"))?;
    let pid = child.id();
    let stdout_reader = child.stdout.take().ok_or("stdout pipe was not created")?;
    let stderr_reader = child.stderr.take().ok_or("stderr pipe was not created")?;
    let budget = Arc::new(AtomicU64::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let output_error = Arc::new(Mutex::new(None::<String>));
    let stdout_budget = Arc::clone(&budget);
    let stdout_overflow = Arc::clone(&overflow);
    let stdout_error = Arc::clone(&output_error);
    let stdout_drainer = thread::spawn(move || {
        let mut file = stdout_file;
        if let Err(error) = copy_bounded(
            stdout_reader,
            &mut file,
            &stdout_budget,
            log_limit,
            &stdout_overflow,
        ) {
            *stdout_error.lock().unwrap() = Some(error);
        }
        let _ = file.sync_all();
    });
    let stderr_budget = Arc::clone(&budget);
    let stderr_overflow = Arc::clone(&overflow);
    let stderr_error = Arc::clone(&output_error);
    let stderr_drainer = thread::spawn(move || {
        let mut file = stderr_file;
        if let Err(error) = copy_bounded(
            stderr_reader,
            &mut file,
            &stderr_budget,
            log_limit,
            &stderr_overflow,
        ) {
            *stderr_error.lock().unwrap() = Some(error);
        }
        let _ = file.sync_all();
    });
    let timeout = Duration::from_secs(
        suite
            .get("timeout_seconds")
            .and_then(TomlValue::as_integer)
            .unwrap_or(600) as u64,
    );
    let mut interrupted = false;
    let mut status = loop {
        let child_status = wait_child(&mut child, Duration::from_millis(50))?;
        if overflow.load(Ordering::Acquire) || started.elapsed() >= timeout {
            interrupted = true;
            let (status, group_stopped) = stop_process_group(&mut child, pid)?;
            if !group_stopped {
                return Err("owned process group did not exit; log integrity is unknown".into());
            }
            break status;
        }
        if let Some(status) = child_status {
            break status;
        }
    };
    if !interrupted {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if overflow.load(Ordering::Acquire) {
                interrupted = true;
                let (group_status, group_stopped) = stop_process_group(&mut child, pid)?;
                if !group_stopped {
                    return Err("owned process group did not exit; log integrity is unknown".into());
                }
                status = group_status;
                break;
            }
            if !process_group_exists(pid)? {
                break;
            }
            if Instant::now() >= deadline {
                interrupted = true;
                let (group_status, group_stopped) = stop_process_group(&mut child, pid)?;
                if !group_stopped {
                    return Err("owned process group did not exit; log integrity is unknown".into());
                }
                status = group_status;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
    if stdout_drainer.join().is_err() || stderr_drainer.join().is_err() {
        return Err("output drainer panicked; log integrity is unknown".into());
    }
    if let Some(error) = output_error.lock().unwrap().take() {
        return Err(error);
    }
    let logs_truncated = overflow.load(Ordering::Acquire);
    interrupted |= logs_truncated;
    let (out_bytes, err_bytes, bounded_logs_truncated) =
        read_bounded_logs(&stdout_path, &stderr_path, log_limit)?;
    interrupted |= bounded_logs_truncated;
    let scrub_env = env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    let stdout = scrub_log(&String::from_utf8_lossy(&out_bytes), &scrub_env).replace("\r\n", "\n");
    let stderr = scrub_log(&String::from_utf8_lossy(&err_bytes), &scrub_env).replace("\r\n", "\n");
    fs::write(&stdout_path, stdout.as_bytes())
        .map_err(|error| format!("scrub stdout artifact: {error}"))?;
    fs::write(&stderr_path, stderr.as_bytes())
        .map_err(|error| format!("scrub stderr artifact: {error}"))?;
    File::open(&stdout_path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync stdout artifact: {error}"))?;
    File::open(&stderr_path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync stderr artifact: {error}"))?;
    let exit_code = status.code().unwrap_or(-1);
    let mut verdict = classify_output(suite, exit_code, &stdout, &stderr, interrupted);
    let stdout_hash = format!("{:x}", Sha256::digest(stdout.as_bytes()));
    let stderr_hash = format!("{:x}", Sha256::digest(stderr.as_bytes()));
    let obj = verdict.as_object_mut().ok_or("invalid verdict")?;
    obj.insert("exit_code".into(), json!(exit_code));
    obj.insert(
        "elapsed_seconds".into(),
        json!((started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0),
    );
    obj.insert("stdout".into(), json!(stdout_path));
    obj.insert("stderr".into(), json!(stderr_path));
    obj.insert(
        "log_integrity".into(),
        json!(if logs_truncated || bounded_logs_truncated {
            "bounded prefix only; source stream exceeded limit"
        } else if interrupted {
            "bounded prefix only"
        } else {
            "complete"
        }),
    );
    obj.insert("stdout_sha256".into(), json!(stdout_hash));
    obj.insert("stderr_sha256".into(), json!(stderr_hash));
    obj.insert("stream_disconnect".into(), json!(interrupted));
    Ok(verdict)
}

pub fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        list: false,
        ..Options::default()
    };
    let mut index = 0;
    let mut explicit_mode = false;
    while index < args.len() {
        let arg = &args[index];
        let mut value = || -> Result<String, String> {
            index += 1;
            args.get(index)
                .cloned()
                .ok_or_else(|| format!("missing value for {arg}"))
        };
        match arg.as_str() {
            "--list" => {
                options.list = true;
                options.run = false;
                explicit_mode = true;
            }
            "--run" => {
                options.run = true;
                options.list = false;
                explicit_mode = true;
            }
            "--verify-items" => options.verify_items = true,
            "--all-profiles" => options.all_profiles = true,
            "--profile" => options.profiles.push(value()?),
            "--series" => options.series.push(value()?),
            "--suite" => options.suite_ids.push(value()?),
            "--run-id" => options.run_id = value()?,
            "--artifact-root" => options.artifact_root = PathBuf::from(value()?),
            "--json" => options.json = true,
            "-h" | "--help" => return Err("USAGE".into()),
            _ => return Err(format!("unknown argument: {arg}")),
        }
        index += 1;
    }
    if !explicit_mode {
        options.list = !options.run;
    }
    Ok(options)
}

pub fn run_options(root: &Path, options: Options) -> Result<i32, String> {
    let manifest = read_manifest(root)?;
    let selected = select_suites(
        &manifest,
        &options.profiles,
        &options.series,
        &options.suite_ids,
        options.run,
        options.all_profiles,
    )?;
    if !options.run {
        if options.json {
            let suites = selected.iter().map(toml_to_json).collect::<Vec<_>>();
            let profiles = toml_array(manifest.raw.get("profile"))
                .into_iter()
                .map(toml_to_json)
                .collect::<Vec<_>>();
            let series = toml_array(manifest.raw.get("series"))
                .into_iter()
                .map(toml_to_json)
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"profiles":profiles,"series":series,"suites":suites})
                )
                .unwrap()
            );
        } else {
            for suite in &selected {
                let state = if suite.get("blocked_reason").is_some() {
                    "BLOCKED"
                } else {
                    "AVAILABLE"
                };
                println!(
                    "{} | {} | {} | {} | {state}",
                    suite_id(suite),
                    suite_profile(suite),
                    suite_labels(suite).join(","),
                    suite.get("scope").and_then(TomlValue::as_str).unwrap_or("")
                );
            }
        }
        return Ok(0);
    }
    run_selected(
        &manifest,
        &selected,
        &options.run_id,
        &options.artifact_root,
        options.verify_items,
    )
}

fn toml_to_json(value: &TomlValue) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn utc_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}.{:09}Z", now.as_secs(), now.subsec_nanos())
}

fn resolve_artifact_root(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("resolve current directory: {error}"))?
            .join(path)
    };
    let mut resolved = PathBuf::new();
    let mut unresolved = Vec::<OsString>::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            std::path::Component::RootDir => resolved.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if unresolved.pop().is_none() {
                    resolved.pop();
                }
            }
            std::path::Component::Normal(name) => {
                if unresolved.is_empty() {
                    let candidate = resolved.join(name);
                    match fs::symlink_metadata(&candidate) {
                        Ok(_) => {
                            resolved = candidate.canonicalize().map_err(|error| {
                                format!("resolve artifact path component: {error}")
                            })?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            unresolved.push(name.to_owned());
                        }
                        Err(error) => {
                            return Err(format!("inspect artifact path component: {error}"));
                        }
                    }
                } else {
                    unresolved.push(name.to_owned());
                }
            }
        }
    }
    for component in unresolved {
        resolved.push(component);
    }
    Ok(resolved)
}

fn validate_artifact_root(workspace: &Path, artifact_root: &Path) -> Result<PathBuf, String> {
    let workspace = workspace
        .canonicalize()
        .map_err(|error| format!("resolve workspace root: {error}"))?;
    let parent = resolve_artifact_root(artifact_root)?;
    if parent.starts_with(&workspace) {
        return Err("evidence must be outside the tracked workspace".into());
    }
    Ok(parent)
}

fn write_report(path: &Path, report: &Value) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("serialize evidence: {error}"))?;
    let mut file =
        File::create(&temporary).map_err(|error| format!("create evidence temp: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("write evidence temp: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("write evidence newline: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync evidence: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish evidence: {error}"))
}

struct SelectedRuntime<'a, F, E> {
    environment: &'a [(OsString, OsString)],
    snapshot: F,
    execute_command: E,
}

fn run_selected(
    manifest: &Manifest,
    suites: &[TomlValue],
    run_id: &str,
    artifact_root: &Path,
    verify_items: bool,
) -> Result<i32, String> {
    let environment = env::vars_os().collect::<Vec<_>>();
    run_selected_with_runtime(
        manifest,
        suites,
        run_id,
        artifact_root,
        verify_items,
        SelectedRuntime {
            environment: &environment,
            snapshot: snapshot_hash,
            execute_command: execute,
        },
    )
}

fn run_selected_with_runtime<F, E>(
    manifest: &Manifest,
    suites: &[TomlValue],
    run_id: &str,
    artifact_root: &Path,
    verify_items: bool,
    runtime: SelectedRuntime<'_, F, E>,
) -> Result<i32, String>
where
    F: FnMut(&Path) -> Result<String, String>,
    E: FnMut(&TomlValue, &BTreeMap<OsString, OsString>, &Path, &Path) -> Result<Value, String>,
{
    let SelectedRuntime {
        environment,
        mut snapshot,
        mut execute_command,
    } = runtime;
    if !safe_id(run_id) {
        return Err("invalid run id".into());
    }
    let parent = validate_artifact_root(&manifest.root, artifact_root)?;
    fs::create_dir_all(&parent).map_err(|error| format!("create artifact root: {error}"))?;
    let parent = validate_artifact_root(&manifest.root, &parent)?;
    let directory = parent.join(run_id);
    fs::create_dir(&directory).map_err(|error| format!("create run directory: {error}"))?;
    let directory = validate_artifact_root(&manifest.root, &directory)?;
    let frozen = snapshot(&manifest.root)?;
    let mut report = json!({"schema_version":2,"taskId":run_id,"run_id":run_id,"delegated":false,"responsible_agent":"test-harness","cwd":manifest.root,"started_at":utc_now(),"source_sha256":frozen,"status":"PENDING","retries":0,"provisioning":"none; pre-migrated approved dependencies only","selection":suites.iter().map(suite_id).collect::<Vec<_>>(),"results":[],"item_results":[],"verify_items":verify_items,"phase_timing_seconds":[],"rerun_policy":"fix or reconcile the first non-PASS target; rerun the full original selection with a new run id; no cached PASS reuse"});
    let report_path = directory.join("result.json");
    write_report(&report_path, &report)?;
    let mut preflight = Vec::new();
    for suite in suites {
        let mut problem = suite
            .get("blocked_reason")
            .and_then(TomlValue::as_str)
            .map(str::to_owned);
        if problem.is_none() {
            if !cfg!(unix) {
                problem =
                    Some("campaign execution requires POSIX process-group log capture".into());
            } else {
                let (_, environment_problem) = prepare_environment(suite, environment);
                problem = environment_problem;
                if problem.is_none() {
                    let argv = string_array(suite, "argv")?;
                    if resolve_executable(&argv[0], &env::var("PATH").unwrap_or_default()).is_none()
                    {
                        problem = Some(format!("required tool unavailable: {}", argv[0]));
                    }
                }
            }
        }
        if let Some(reason) = problem {
            preflight.push(json!({"id":suite_id(suite),"reason":reason}));
        }
    }
    report["preflight"] =
        json!({"status":if preflight.is_empty(){"PASS"}else{"BLOCKED"},"issues":preflight});
    let selected_ids = suites.iter().map(suite_id).collect::<BTreeSet<_>>();
    report["outside_selection"] = Value::Array(manifest.suites.iter().filter(|suite| !selected_ids.contains(&suite_id(suite))).map(|suite| json!({"id":suite_id(suite),"profile":suite_profile(suite),"executed":false,"reason":suite.get("blocked_reason").and_then(TomlValue::as_str).unwrap_or("outside the explicit production-profile selection")})).collect());
    let preflight_failed = !preflight.is_empty();
    let campaign_started = Instant::now();
    let phases: &[&str] = if verify_items {
        &["items", "collection"]
    } else {
        &["collection"]
    };
    let mut stopped: Option<(String, String, String)> = None;
    for phase in phases {
        let phase_directory = directory.join(phase);
        fs::create_dir(&phase_directory)
            .map_err(|error| format!("create phase directory: {error}"))?;
        let records_key = if *phase == "items" {
            "item_results"
        } else {
            "results"
        };
        for suite in suites {
            let id = suite_id(suite);
            let mut record = json!({"taskId":format!("{run_id}:{phase}:{id}"),"id":id,"phase":phase,"profile":suite_profile(suite),"series":suite_labels(suite),"scope":suite.get("scope"),"owner":suite.get("owner"),"production_services":registered_services(&suite_profile(suite)).unwrap_or_default(),"test_services":string_array(suite,"test_services")?,"boundary":suite.get("boundary"),"argv":suite.get("argv"),"cwd":manifest.root,"started_at":Value::Null,"retries":0,"expected_postcondition":suite.get("acceptance").and_then(TomlValue::as_str).unwrap_or("live evidence"),"exit_code":Value::Null,"stdout":Value::Null,"stderr":Value::Null,"log_integrity":"not started","stream_disconnect":false});
            if preflight_failed {
                let reason = report["preflight"]["issues"]
                    .as_array()
                    .and_then(|items| items.iter().find(|item| item["id"] == id))
                    .and_then(|item| item["reason"].as_str())
                    .unwrap_or("collection preflight failed; no suites dispatched");
                record["status"] = json!("BLOCKED");
                record["reason"] = json!(reason);
            } else if let Some((stop_id, stop_status, _)) = &stopped {
                record["status"] = json!("BLOCKED");
                record["reason"] = json!(format!("prior {stop_status} in {stop_id}; fix or reconcile before a fresh full collection"));
            } else if snapshot(&manifest.root)? != frozen {
                record["status"] = json!("UNKNOWN");
                record["reason"] =
                    json!("source changed after freeze; evidence belongs to another snapshot");
            } else {
                let (mut child_env, issue) = prepare_environment(suite, environment);
                child_env.insert(
                    "CRITERION_HOME".into(),
                    phase_directory.join("criterion").join(&id).into_os_string(),
                );
                let names = child_env
                    .keys()
                    .filter_map(|key| {
                        let name = key.to_string_lossy();
                        [
                            "DATABASE_URL",
                            "RABBITMQ_URL",
                            "REDIS_URL",
                            "RUST_INTEGRATION_REQUIRED",
                            "ASTRAL_TEST_DATABASE_NAME",
                            "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL",
                            "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE",
                            "ASTRAL_MESSAGE_TRANSPORT",
                            "ASTRAL_MIGRATION_ENV",
                        ]
                        .contains(&name.as_ref())
                        .then_some(name.to_string())
                    })
                    .collect::<Vec<_>>();
                record["environment_names"] = json!(names);
                let argv = string_array(suite, "argv")?;
                if let Some(reason) = issue {
                    record["status"] = json!("BLOCKED");
                    record["reason"] = json!(reason);
                } else if resolve_executable(&argv[0], &env::var("PATH").unwrap_or_default())
                    .is_none()
                {
                    record["status"] = json!("BLOCKED");
                    record["reason"] = json!(format!("required tool unavailable: {}", argv[0]));
                } else {
                    let out_path = phase_directory.join(format!("{id}.stdout.log"));
                    let err_path = phase_directory.join(format!("{id}.stderr.log"));
                    record["status"] = json!("PENDING");
                    record["reason"] = json!("command dispatched; result not yet proven");
                    record["started_at"] = json!(utc_now());
                    record["stdout"] = json!(out_path);
                    record["stderr"] = json!(err_path);
                    record["log_integrity"] =
                        json!("in progress; terminal integrity not yet proven");
                    report[records_key]
                        .as_array_mut()
                        .unwrap()
                        .push(record.clone());
                    report["status"] = json!("PENDING");
                    write_report(&report_path, &report)?;
                    match execute_command(suite, &child_env, &manifest.root, &phase_directory) {
                        Ok(result) => {
                            record
                                .as_object_mut()
                                .unwrap()
                                .extend(result.as_object().cloned().unwrap_or_default());
                        }
                        Err(error) => {
                            record["status"] = json!("UNKNOWN");
                            record["reason"] = json!(format!("runner/log interrupted: {error}"));
                            record["stdout"] = json!(out_path);
                            record["stderr"] = json!(err_path);
                            record["log_integrity"] =
                                json!("unknown; reconcile owned process and artifacts");
                            record["stream_disconnect"] = json!(true);
                        }
                    }
                    if snapshot(&manifest.root)? != frozen {
                        record["status"] = json!("UNKNOWN");
                        record["reason"] =
                            json!("source changed while required command was running");
                    }
                }
            }
            record["finished_at"] = json!(utc_now());
            record["actual_postcondition"] = record
                .get("verified_postcondition")
                .cloned()
                .unwrap_or_else(|| record.get("reason").cloned().unwrap_or(Value::Null));
            report["phase_timing_seconds"].as_array_mut().unwrap().push(json!({"id":id,"phase":phase,"finished_at_monotonic_offset":(campaign_started.elapsed().as_secs_f64()*1000.0).round()/1000.0}));
            let status = record["status"].as_str().unwrap_or("UNKNOWN").to_owned();
            if status != "PASS" && stopped.is_none() {
                stopped = Some((id.clone(), status.clone(), phase.to_string()));
                report["stopped_at"] = json!({"id":id,"status":status,"phase":phase});
            }
            let records = report[records_key].as_array_mut().unwrap();
            if records
                .last()
                .is_some_and(|last| last["taskId"] == record["taskId"])
            {
                *records.last_mut().unwrap() = record.clone();
            } else {
                records.push(record.clone());
            }
            report["status"] = json!(stopped
                .as_ref()
                .map(|(_, status, _)| status.as_str())
                .unwrap_or("PENDING"));
            write_report(&report_path, &report)?;
            println!(
                "[{status}] {phase}/{id} ({}/{}): {}",
                suite_profile(suite),
                suite.get("scope").and_then(TomlValue::as_str).unwrap_or(""),
                record["reason"].as_str().unwrap_or("")
            );
        }
    }
    report["finished_at"] = json!(utc_now());
    report["elapsed_seconds"] =
        json!((campaign_started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0);
    let status = stopped
        .as_ref()
        .map(|(_, status, _)| status.as_str())
        .unwrap_or_else(|| {
            let mut all = report["item_results"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            all.extend(report["results"].as_array().cloned().unwrap_or_default());
            fold_status(&all)
        });
    report["status"] = json!(status);
    report["series_results"] = Value::Array(manifest.series.keys().filter_map(|label| {
        let selected = report["results"].as_array()?.iter().filter(|record| record["series"].as_array().is_some_and(|series| series.iter().any(|value| value.as_str()==Some(label)))).cloned().collect::<Vec<_>>();
        if selected.is_empty() { return None; }
        Some(json!({"id":label,"status":fold_status(&selected),"coverage":"selected suites only; not full campaign acceptance","scopes":selected.iter().filter_map(|record|record["scope"].as_str().map(str::to_owned)).collect::<BTreeSet<_>>(),"boundary":manifest.series[label].get("boundary"),"suites":selected.iter().map(|record|record["id"].clone()).collect::<Vec<_>>() }))
    }).collect());
    write_report(&report_path, &report)?;
    println!("[{status}] evidence: {}", report_path.display());
    Ok(if status == "PASS" { 0 } else { 1 })
}

fn resolve_executable(command: &str, path: &str) -> Option<PathBuf> {
    if command.contains('/') {
        return Path::new(command).exists().then(|| PathBuf::from(command));
    }
    env::split_paths(path)
        .map(|directory| directory.join(command))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
#[path = "campaign/run_tests.rs"]
mod run_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct TestDirectory(PathBuf);

    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            for _ in 0..32 {
                let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "astrallight-test-harness-{}-{nonce}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create isolated test directory: {error}"),
                }
            }
            panic!("could not allocate an isolated test directory after bounded attempts");
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn command_suite(argv: &[&str], timeout_seconds: i64) -> TomlValue {
        let mut table = toml::map::Map::new();
        table.insert(
            "id".into(),
            TomlValue::String("runner-process-contract".into()),
        );
        table.insert(
            "argv".into(),
            TomlValue::Array(
                argv.iter()
                    .map(|argument| TomlValue::String((*argument).into()))
                    .collect(),
            ),
        );
        table.insert("acceptance".into(), TomlValue::String("command".into()));
        table.insert(
            "timeout_seconds".into(),
            TomlValue::Integer(timeout_seconds),
        );
        TomlValue::Table(table)
    }

    fn rust_summary(passed: usize, failed: usize, ignored: usize, filtered: usize) -> String {
        format!("test result: ok. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n")
    }

    fn full_model_report(model: &str, summary: bool) -> Value {
        let modes = json!({
            "bracket":{"status":"PASS","violations":0,"explorationComplete":true},
            "strict":{"status":"PASS","violations":0,"explorationComplete":true}
        });
        let model_id = match model {
            "single" => "e5-bounded-model-check",
            "two" => "e5-bounded-model-check-two-mutations",
            _ => unreachable!("known model fixture"),
        };
        let omissions = [
            "pending_probe",
            "post_recheck",
            "final_reload",
            "exact_identity",
            "generation_revoke_fence",
            "host_mediation",
        ];
        let omissions = if summary {
            Value::Object(
                omissions
                    .into_iter()
                    .map(|premise| (premise.to_owned(), json!("FAIL")))
                    .collect(),
            )
        } else {
            json!(omissions
                .into_iter()
                .map(|premise| json!({"premise":premise,"status":"FAIL"}))
                .collect::<Vec<_>>())
        };
        let mut report = json!({"model":model_id,"status":"PASS","omissions":omissions});
        if summary {
            report["modes"] = modes;
        } else {
            report["fullContract"] = json!({"status":"PASS","modes":modes});
        }
        report
    }

    fn isolated_environment() -> Vec<(OsString, OsString)> {
        [
            ("TEST_USE_EXISTING", "1"),
            ("ASTRAL_MIGRATION_ENV", "isolated"),
            ("RUST_INTEGRATION_REQUIRED", "1"),
            (
                "DATABASE_URL",
                "mysql://fixture@127.0.0.1:3308/astral_rehearsal_contract",
            ),
            ("ASTRAL_TEST_DATABASE_NAME", "astral_rehearsal_contract"),
            (
                "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL",
                "mysql://fixture@127.0.0.1:3308/sdk_identity_mapping_test_contract",
            ),
            (
                "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE",
                "sdk_identity_mapping_test_contract",
            ),
            ("RABBITMQ_URL", "amqp://fixture@127.0.0.1:5673/%2f"),
            ("MYSQL_ROOT_PASSWORD", "temporary-fixture"),
            ("MYSQL_DATABASE", "untrusted-database"),
            ("RABBITMQ_USER", "untrusted-user"),
            ("RABBITMQ_PASSWORD", "untrusted-password"),
            ("COMPOSE_PROFILES", "rabbit"),
            ("SKIP_DOCKER", "1"),
            ("ASTRAL_TARGET_REGION", "foreign-region"),
            ("ASTRAL_PERF_CASE", "filtered-case"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
    }

    #[cfg(unix)]
    fn write_fake_cargo(directory: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let cargo = directory.join("cargo");
        fs::write(
            &cargo,
            r##"#!/bin/sh
printf 'called\n' >> "$FAKE_CARGO_LOG"
printf '%s\n' "$@"
exit "${FAKE_CARGO_EXIT:-0}"
"##,
        )
        .unwrap();
        let mut permissions = fs::metadata(&cargo).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&cargo, permissions).unwrap();
        cargo
    }

    #[cfg(unix)]
    fn invoke_shell_script(
        root: &Path,
        directory: &Path,
        script: &str,
        args: &[&str],
        cargo_exit: i32,
    ) -> std::process::Output {
        let log = directory.join("cargo.log");
        let path = format!(
            "{}:{}",
            directory.display(),
            env::var("PATH").unwrap_or_default()
        );
        Command::new("bash")
            .arg(root.join(script))
            .args(args)
            .current_dir(root)
            .env("PATH", path)
            .env("FAKE_CARGO_LOG", log)
            .env("FAKE_CARGO_EXIT", cargo_exit.to_string())
            .output()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn shell_entrypoints_forward_selection_to_the_rust_cli() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let cases = [
            (
                "scripts/run-tests.sh",
                vec!["--campaign", "--list", "--json"],
                vec!["--", "--list", "--json"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--all"],
                vec!["--", "--run", "--verify-items"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["unit"],
                vec!["--", "--run", "--profile", "native-kernel"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--full"],
                vec!["--", "--run", "--verify-items", "--all-profiles"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--integration"],
                vec!["--", "--run", "--profile", "native-single-node"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--rabbit"],
                vec!["--", "--run", "--profile", "standalone-rabbit"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--identity-mapping"],
                vec!["--", "--run", "--suite", "dedicated-identity-mapping"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--bench"],
                vec!["--", "--run", "--profile", "performance-kernel"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--list-series", "--series", "RQ"],
                vec!["--", "--list", "--series", "RQ"],
            ),
            (
                "scripts/run-tests.sh",
                vec!["--campaign", "--run", "--suite", "strict-tenant-isolation"],
                vec!["--", "--run", "--suite", "strict-tenant-isolation"],
            ),
            (
                "tests-suite/matrix/run-mt-matrix.sh",
                vec!["--suites", "mt_extreme_churn mt_extreme_capacity"],
                vec![
                    "--",
                    "--run",
                    "--profile",
                    "native-single-node",
                    "--suite",
                    "mt-churn",
                    "--suite",
                    "mt-capacity",
                ],
            ),
        ];
        for (script, args, expected_tail) in cases {
            let directory = TestDirectory::new();
            write_fake_cargo(&directory.0);
            let output = invoke_shell_script(root, &directory.0, script, &args, 0);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                directory.0.join("cargo.log").is_file(),
                "{script} did not invoke stub Cargo"
            );
            let forwarded = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(
                forwarded.ends_with(
                    &expected_tail
                        .iter()
                        .map(|item| (*item).to_owned())
                        .collect::<Vec<_>>()
                ),
                "{script}: {forwarded:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn shell_entrypoints_propagate_cargo_failures_and_reject_before_dispatch() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for (script, args, status) in [
            ("scripts/run-tests.sh", vec!["--campaign", "--list"], 7),
            (
                "tests-suite/matrix/run-mt-matrix.sh",
                vec!["--suites", "mt_extreme_churn"],
                9,
            ),
        ] {
            let directory = TestDirectory::new();
            write_fake_cargo(&directory.0);
            let output = invoke_shell_script(root, &directory.0, script, &args, status);
            assert_eq!(output.status.code(), Some(status), "{script}");
            assert!(
                directory.0.join("cargo.log").is_file(),
                "{script} did not invoke stub Cargo"
            );
        }

        for (script, args) in [
            ("scripts/run-tests.sh", vec!["--unknown"]),
            (
                "tests-suite/matrix/run-mt-matrix.sh",
                vec!["--profile", "unknown"],
            ),
            (
                "tests-suite/matrix/run-mt-matrix.sh",
                vec!["--suites", "unknown"],
            ),
        ] {
            let directory = TestDirectory::new();
            write_fake_cargo(&directory.0);
            let output = invoke_shell_script(root, &directory.0, script, &args, 0);
            assert_eq!(output.status.code(), Some(2), "{script}");
            assert!(
                output.stdout.is_empty(),
                "{script} unexpectedly dispatched Cargo"
            );
            assert!(
                !directory.0.join("cargo.log").exists(),
                "{script} invoked Cargo before rejecting input"
            );
        }
    }

    #[test]
    fn selection_uses_registered_profiles_and_series_families() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = read_manifest(root).unwrap();
        let selected = select_suites(&manifest, &[], &["RQ".into()], &[], false, false).unwrap();
        assert!(!selected.is_empty());
        assert!(selected.iter().all(|suite| suite_labels(suite)
            .iter()
            .any(|label| numbered_family(label, "RQ"))));
        assert!(select_suites(&manifest, &["unknown".into()], &[], &[], true, false).is_err());
        let default_selection = select_suites(&manifest, &[], &[], &[], true, false).unwrap();
        assert!(default_selection
            .iter()
            .all(|suite| DEFAULT_PROFILES.contains(&suite_profile(suite).as_str())));
        assert!(default_selection
            .iter()
            .all(|suite| suite_id(suite) != "offline-validation-tools"));
        assert!(select_suites(
            &manifest,
            &[],
            &[],
            &["offline-validation-tools".into()],
            true,
            false
        )
        .unwrap()
        .iter()
        .any(|suite| suite_id(suite) == "offline-validation-tools"));

        let expected_series = [
            "RQ1", "RQ2", "RQ3", "RQ4", "RQ5", "M1", "M2", "M3", "M4", "M5", "E1", "E2", "E3",
            "E4", "E5", "MT-E1", "MT-E2", "MT-E3", "MT-E4", "MT-E5", "MT-E6", "PERF", "COMPAT",
            "EXCLUDED",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert!(expected_series.is_subset(
            &manifest
                .series
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        ));

        let default_running = select_suites(&manifest, &[], &[], &[], true, false).unwrap();
        assert!(default_running
            .iter()
            .all(|suite| DEFAULT_PROFILES.contains(&suite_profile(suite).as_str())));
        assert!(default_running
            .iter()
            .all(|suite| suite.get("blocked_reason").is_none()));
        assert!(default_running
            .iter()
            .all(|suite| string_array(suite, "test_services").unwrap().is_empty()));

        let all_profiles = select_suites(&manifest, &[], &[], &[], true, true).unwrap();
        assert_eq!(all_profiles.len(), manifest.suites.len());

        let mut with_blocked = manifest.clone();
        let mut blocked = with_blocked.suites[0].clone();
        if let TomlValue::Table(table) = &mut blocked {
            table.insert(
                "id".to_owned(),
                TomlValue::String("synthetic-blocked".to_owned()),
            );
            table.insert(
                "blocked_reason".to_owned(),
                TomlValue::String("synthetic blocked fixture".to_owned()),
            );
        }
        with_blocked.suites.push(blocked);
        let all_with_blocked = select_suites(&with_blocked, &[], &[], &[], true, true).unwrap();
        assert!(all_with_blocked
            .iter()
            .any(|suite| suite.get("blocked_reason").is_some()));
        assert!(all_profiles
            .iter()
            .all(|suite| suite.get("blocked_reason").is_none()));
        assert!(all_profiles
            .iter()
            .any(|suite| !string_array(suite, "test_services").unwrap().is_empty()));

        let m_family = select_suites(&manifest, &[], &["M".into()], &[], false, false).unwrap();
        assert!(m_family
            .iter()
            .all(|suite| suite_labels(suite).iter().any(|label| {
                label.starts_with('M') && label[1..].bytes().all(|byte| byte.is_ascii_digit())
            })));
        assert!(m_family
            .iter()
            .all(|suite| suite_id(suite) != "mt-capacity"));
        let e_family = select_suites(&manifest, &[], &["E".into()], &[], false, false).unwrap();
        assert!(e_family
            .iter()
            .all(|suite| suite_id(suite) != "mt-capacity"));

        let e2 = select_suites(
            &manifest,
            &["native-kernel".into()],
            &["E2".into()],
            &[],
            false,
            false,
        )
        .unwrap();
        assert_eq!(e2.len(), 5);
        assert!(e2.iter().all(|suite| {
            suite.get("expected_tests").and_then(TomlValue::as_integer) == Some(1)
                && string_array(suite, "argv")
                    .unwrap()
                    .iter()
                    .any(|argument| argument == "--exact")
        }));

        let explicit_integration = select_suites(
            &manifest,
            &[],
            &[],
            &["native-projection-lifecycle".into()],
            true,
            false,
        )
        .unwrap();
        assert_eq!(explicit_integration.len(), 1);
        assert_eq!(
            suite_profile(&explicit_integration[0]),
            "native-single-node"
        );

        let registered = manifest
            .suites
            .iter()
            .map(|suite| (suite_id(suite), suite))
            .collect::<BTreeMap<_, _>>();
        for name in [
            "policy-observability-tests",
            "db-observability-tests",
            "trustgraph-observability-tests",
        ] {
            let suite = registered.get(name).unwrap();
            assert!(string_array(suite, "argv")
                .unwrap()
                .join(" ")
                .contains("e1-observability"));
            assert!(string_array(suite, "test_services").unwrap().is_empty());
        }
        assert!(
            string_array(registered["trustgraph-observability-tests"], "argv")
                .unwrap()
                .join(" ")
                .contains("e3-observability,e4-observability")
        );

        for (profiles, labels, suite_ids) in [
            (vec!["unknown".into()], vec![], vec![]),
            (vec![], vec!["E9".into()], vec![]),
            (vec![], vec![], vec!["not-a-test".into()]),
        ] {
            assert!(select_suites(&manifest, &profiles, &labels, &suite_ids, true, false).is_err());
        }
        assert!(select_suites(
            &manifest,
            &["standalone-rabbit".into()],
            &["MT-E1".into()],
            &[],
            false,
            false,
        )
        .is_err());
        let mt_e2 = select_suites(&manifest, &[], &["MT-E2".into()], &[], false, false).unwrap();
        assert_eq!(mt_e2.len(), 1);
        assert_eq!(suite_id(&mt_e2[0]), "mt-e2-unimplemented");
        assert_eq!(str_field(&mt_e2[0], "acceptance").unwrap(), "rust");
        assert!(string_array(&mt_e2[0], "argv")
            .unwrap()
            .iter()
            .any(|arg| arg.contains("mt_e2_has_no_fabricated_executable_suite")));

        for suite in &manifest.suites {
            assert_eq!(
                string_array(suite, "test_services").unwrap(),
                string_array(
                    &manifest.profiles[&suite_profile(suite)],
                    "production_services"
                )
                .unwrap()
            );
        }
    }

    fn assert_archived_python_migrations_are_accounted(root: &Path, manifest: &Manifest) {
        let archive = root.join("Docs/authorization-validation/archive/python-tests");
        let mapping = fs::read_to_string(archive.join("README.md")).unwrap();
        let mut archived = fs::read_dir(&archive)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("test_") && name.ends_with(".py"))
            .collect::<Vec<_>>();
        archived.sort();
        assert_eq!(
            archived.len(),
            19,
            "the archived Python test inventory changed"
        );
        for source in archived {
            let relative = format!("Docs/authorization-validation/archive/python-tests/{source}");
            assert!(
                mapping.contains(&format!("`{source}`")),
                "unmapped archive source: {source}"
            );
            assert!(
                manifest.suites.iter().any(|suite| {
                    string_array(suite, "sources")
                        .unwrap_or_default()
                        .iter()
                        .any(|registered| registered == &relative)
                }),
                "archived source is absent from every campaign suite source list: {source}"
            );
        }
        assert!(mapping.contains("`campaign-contracts`"));
        assert!(mapping.contains("`shell-runner-contracts`"));
        assert!(mapping.contains("`harness/runner-contracts` is catalog-only"));
    }

    fn assert_python_crosswalk_targets_exist(root: &Path, source: &str, method: &str, row: &str) {
        let rust_targets = row
            .split('|')
            .nth(2)
            .unwrap_or_default()
            .split('`')
            .map(str::trim)
            .filter(|target| target.contains(".rs::"))
            .collect::<Vec<_>>();
        for target in rust_targets {
            let Some((file, symbol)) = target.split_once(".rs::") else {
                continue;
            };
            let relative_source = format!("{file}.rs");
            let mut source_path = root.join("test-harness/src").join(&relative_source);
            if !source_path.is_file() {
                source_path = root.join("test-harness/src/bin").join(
                    Path::new(&relative_source)
                        .file_name()
                        .expect("binary source filename"),
                );
            }
            if !source_path.is_file() {
                source_path = root.join("test-harness/tests").join(
                    Path::new(&relative_source)
                        .file_name()
                        .expect("integration test filename"),
                );
            }
            if !source_path.is_file() {
                source_path = root.join("test-harness").join(&relative_source);
            }
            assert!(
                source_path.is_file(),
                "crosswalk target source is missing for {source}::{method}: {file}.rs"
            );
            let contents = fs::read_to_string(&source_path).unwrap_or_else(|error| {
                panic!(
                    "read crosswalk Rust target for {source}::{method} at {}: {error}",
                    source_path.display()
                )
            });
            let lines = contents.lines().collect::<Vec<_>>();
            let target_name = symbol.rsplit("::").next().unwrap_or_default();
            let target_exists = lines.iter().any(|line| {
                let trimmed = line.trim_start();
                let function_name = trimmed
                    .strip_prefix("pub fn ")
                    .or_else(|| trimmed.strip_prefix("pub async fn "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) async fn "))
                    .or_else(|| trimmed.strip_prefix("fn "))
                    .or_else(|| trimmed.strip_prefix("async fn "))
                    .and_then(|name| {
                        name.split(|character: char| {
                            !(character.is_ascii_alphanumeric() || character == '_')
                        })
                        .next()
                    });
                let function_matches = function_name == Some(target_name);
                let constant_matches = ["const ", "pub const ", "static ", "pub static "]
                    .iter()
                    .any(|prefix| {
                        trimmed
                            .strip_prefix(prefix)
                            .is_some_and(|name| name.starts_with(&format!("{target_name}:")))
                    });
                function_matches || constant_matches
            });
            assert!(
                target_exists,
                "crosswalk Rust symbol is missing for {source}::{method}: {file}::{symbol}"
            );
            let test_name = symbol.strip_prefix("tests::").unwrap_or(target_name);
            if symbol.starts_with("tests::")
                || lines.iter().enumerate().any(|(index, line)| {
                    let trimmed = line.trim_start();
                    trimmed == format!("fn {test_name}() {{")
                        && lines[index.saturating_sub(5)..index]
                            .iter()
                            .any(|previous| matches!(previous.trim(), "#[test]" | "#[tokio::test]"))
                })
            {
                let target_test_exists = lines.iter().enumerate().any(|(index, line)| {
                    let trimmed = line.trim_start();
                    let function_name = trimmed
                        .strip_prefix("fn ")
                        .or_else(|| trimmed.strip_prefix("async fn "))
                        .and_then(|name| {
                            name.split(|character: char| {
                                !(character.is_ascii_alphanumeric() || character == '_')
                            })
                            .next()
                        });
                    let mut previous = index;
                    while previous > 0 && index - previous < 6 {
                        previous -= 1;
                        if matches!(lines[previous].trim(), "#[test]" | "#[tokio::test]") {
                            return function_name == Some(test_name);
                        }
                        if lines[previous].trim().starts_with("fn ")
                            || lines[previous].trim().starts_with("async fn ")
                        {
                            break;
                        }
                    }
                    false
                });
                assert!(
                    target_test_exists,
                    "crosswalk target test function is missing for {source}::{method}: {}::{test_name}",
                    source_path
                        .strip_prefix(root.join("test-harness/src"))
                        .unwrap_or(&source_path)
                        .display()
                );
            }
        }
    }

    fn assert_python_unittest_inventory_is_accounted(root: &Path, manifest: &Manifest) {
        let modules = [
            "Docs/authorization-validation/archive/python-tests/test_bounded_model_execution.py",
            "Docs/authorization-validation/archive/python-tests/test_classify_e1_properties.py",
            "Docs/authorization-validation/archive/python-tests/test_dependency_profiles.py",
            "Docs/authorization-validation/archive/python-tests/test_e1_runner.py",
            "Docs/authorization-validation/archive/python-tests/test_e3_e4.py",
            "Docs/authorization-validation/archive/python-tests/test_e3_runner.py",
            "Docs/authorization-validation/archive/python-tests/test_e4_fault_driver.py",
            "Docs/authorization-validation/archive/python-tests/test_e5_model_check.py",
            "Docs/authorization-validation/archive/python-tests/test_e5_model_check_two_mutations.py",
            "Docs/authorization-validation/archive/python-tests/test_experiment_common.py",
            "Docs/authorization-validation/archive/python-tests/test_experiment_register.py",
            "Docs/authorization-validation/archive/python-tests/test_lifecycle_reducer.py",
            "Docs/authorization-validation/archive/python-tests/test_model_acceptance.py",
            "Docs/authorization-validation/archive/python-tests/test_node_adapter.py",
            "Docs/authorization-validation/archive/python-tests/test_projection_owner_model.py",
            "Docs/authorization-validation/archive/python-tests/test_run_single_node_campaign.py",
            "Docs/authorization-validation/archive/python-tests/test_tenant_isolation_model.py",
            "Docs/authorization-validation/archive/python-tests/test_unbounded_confirmation.py",
            "Docs/authorization-validation/archive/python-tests/test_universal_hypotheses_check.py",
            "scripts/tests/test_entrypoints.py",
            "scripts/tests/test_evaluate_performance_acceptance.py",
            "scripts/tests/test_performance_acceptance.py",
            "scripts/tests/test_test_campaign.py",
            "experiments/tdsc/protocol-runner/test_run_performance.py",
            "Docs/实验/分布式测试/rust-s15/test_s15_validation.py",
        ];
        let mut total_methods = 0usize;
        let mut status_counts = BTreeMap::new();
        let crosswalk = fs::read_to_string(
            root.join("Docs/authorization-validation/python-test-method-crosswalk.md"),
        )
        .expect("read Python-to-Rust method crosswalk");
        let crosswalk_lines = crosswalk.lines().collect::<Vec<_>>();
        const RETIRED_TDSC_SOURCE: &str =
            "experiments/tdsc/protocol-runner/test_run_performance.py";
        // Baseline 62b4349, Git blob 53839fda51d4fe8888da598810b7e75ffb5b18a7.
        const RETIRED_TDSC_METHODS: [&str; 10] = [
            "test_status_classification_is_mutually_exclusive",
            "test_exception_classification_distinguishes_timeout",
            "test_percentiles_are_interpolated",
            "test_empty_percentile_is_none",
            "test_percentile_rejects_invalid_range",
            "test_sample_row_matches_declared_schema",
            "test_schema_rejects_invalid_outcome",
            "test_concurrency_parser_requires_unique_positive_values",
            "test_replicate_summary_has_rate_and_success_throughput_metrics",
            "test_concurrency_summary_uses_replicate_level_metrics",
        ];
        for source in modules {
            let methods = if source == RETIRED_TDSC_SOURCE {
                assert!(
                    !root.join(source).exists(),
                    "retired TDSC Python test must not be restored as a current entrypoint"
                );
                RETIRED_TDSC_METHODS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>()
            } else {
                let contents = fs::read_to_string(root.join(source)).unwrap_or_else(|error| {
                    panic!("read Python migration source {source}: {error}")
                });
                contents
                    .lines()
                    .filter_map(|line| {
                        let trimmed = line.trim_start();
                        trimmed.strip_prefix("def test_").and_then(|name| {
                            name.split_once('(').map(|(name, _)| format!("test_{name}"))
                        })
                    })
                    .collect::<Vec<_>>()
            };
            let method_count = methods.len();
            assert!(
                method_count > 0,
                "Python unittest module has no test methods: {source}"
            );
            total_methods += method_count;
            let registration_source = if source == RETIRED_TDSC_SOURCE {
                "test-harness/src/tdsc_performance.rs"
            } else {
                source
            };
            assert!(
                manifest.suites.iter().any(|suite| {
                    string_array(suite, "sources")
                        .unwrap_or_default()
                        .iter()
                        .any(|registered| registered == registration_source)
                }),
                "Python migration contract is absent from every suite source list: {source}"
            );
            let marker = format!("<!-- python-source: {source} -->");
            assert_eq!(
                crosswalk_lines
                    .iter()
                    .filter(|line| line.trim() == marker)
                    .count(),
                1,
                "crosswalk must contain exactly one source marker: {source}"
            );
            let marker_index = crosswalk_lines
                .iter()
                .position(|line| line.trim() == marker)
                .unwrap();
            let section_start = crosswalk_lines[marker_index + 1..]
                .iter()
                .position(|line| line.trim_start().starts_with('#'))
                .map(|offset| marker_index + 1 + offset)
                .unwrap_or_else(|| panic!("crosswalk source marker has no heading: {source}"));
            let section_end = crosswalk_lines[section_start + 1..]
                .iter()
                .position(|line| line.trim_start().starts_with("#"))
                .map(|offset| section_start + 1 + offset)
                .unwrap_or(crosswalk_lines.len());
            let section = &crosswalk_lines[section_start..section_end];
            assert!(
                crosswalk_lines[marker_index..section_end]
                    .iter()
                    .any(|line| line.contains(source)),
                "crosswalk source section must identify full source path: {source}"
            );
            let section_header = crosswalk_lines[section_start].trim();
            assert!(
                section_header.contains(
                    Path::new(source)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .expect("Python source filename")
                ),
                "crosswalk heading does not match source: {source}"
            );
            for method in methods {
                let method_rows = section
                    .iter()
                    .filter(|line| line.contains('|') && line.contains(&format!("`{method}`")))
                    .collect::<Vec<_>>();
                assert_eq!(
                    method_rows.len(),
                    1,
                    "crosswalk source section must contain exactly one method row for {source}::{method}"
                );
                assert!(
                    method_rows[0].matches('|').count() >= 4,
                    "crosswalk method row must include source, Rust target, and status columns: {source}::{method}"
                );
                let status = method_rows[0].split('|').nth(3).unwrap_or_default().trim();
                let status_kind = ["EQUIVALENT", "PARTIAL", "BLOCKED", "RETIRED"]
                    .into_iter()
                    .find(|known| status.starts_with(known))
                    .unwrap_or_else(|| {
                        panic!("crosswalk method row must declare an evidence status: {source}::{method}")
                    });
                *status_counts.entry(status_kind).or_insert(0usize) += 1;
                if status.starts_with("RETIRED") {
                    assert!(
                        method_rows[0].split('|').nth(2).unwrap_or_default().contains(".rs::"),
                        "retired contract must identify its current rejection or replacement test: {source}::{method}"
                    );
                    assert!(
                        status.contains('：'),
                        "retired contract requires its removal boundary"
                    );
                }
                assert_python_crosswalk_targets_exist(root, source, &method, method_rows[0]);
            }
        }
        assert_eq!(
            modules.len(),
            25,
            "the Python unittest module inventory changed"
        );
        assert_eq!(
            total_methods, 622,
            "the Python unittest method inventory changed"
        );
        for (status, expected) in [
            ("EQUIVALENT", 599),
            ("PARTIAL", 9),
            ("BLOCKED", 0),
            ("RETIRED", 14),
        ] {
            assert_eq!(
                status_counts.get(status).copied().unwrap_or(0),
                expected,
                "crosswalk {status} inventory changed; reconcile method and summary boundaries"
            );
        }

        let campaign = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "campaign-contracts")
            .unwrap();
        assert_eq!(str_field(campaign, "owner").unwrap(), "test-harness");
        assert_eq!(str_field(campaign, "profile").unwrap(), "native-kernel");
        assert_eq!(
            string_array(campaign, "test_services").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(str_field(campaign, "acceptance").unwrap(), "rust");
        assert_eq!(
            campaign
                .get("expected_tests")
                .and_then(TomlValue::as_integer),
            Some(33)
        );
        assert!(campaign.get("blocked_reason").is_none());
        assert_eq!(
            string_array(campaign, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "campaign::",
                "--",
                "--test-threads=1",
                "--skip",
                "shell_entrypoints_"
            ]
        );
        assert_eq!(
            campaign
                .get("minimum_tests")
                .and_then(TomlValue::as_integer),
            Some(33)
        );
        assert!(campaign.get("blocked_reason").is_none());

        let tenant_model = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "offline-tenant-model")
            .unwrap();
        assert_eq!(str_field(tenant_model, "owner").unwrap(), "test-harness");
        assert_eq!(
            str_field(tenant_model, "profile").unwrap(),
            "offline-validation"
        );
        assert_eq!(str_field(tenant_model, "scope").unwrap(), "offline-model");
        assert_eq!(str_field(tenant_model, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(tenant_model, "test_services").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            string_array(tenant_model, "sources").unwrap(),
            vec![
                "test-harness/src/models.rs",
                "Docs/authorization-validation/tools/tenant_isolation_model.py",
                "Docs/authorization-validation/archive/python-tests/test_tenant_isolation_model.py",
            ]
        );
        assert_eq!(
            string_array(tenant_model, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "models::tests::",
                "--",
                "--test-threads=1",
            ]
        );
        for field in ["minimum_tests", "expected_tests"] {
            assert_eq!(
                tenant_model.get(field).and_then(TomlValue::as_integer),
                Some(8)
            );
        }
        assert!(tenant_model.get("blocked_reason").is_none());

        let parser_acceptance = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "performance-acceptance-parser-contracts")
            .unwrap();
        for source in [
            "scripts/performance_acceptance.py",
            "scripts/tests/test_performance_acceptance.py",
        ] {
            assert!(string_array(parser_acceptance, "sources")
                .unwrap()
                .iter()
                .any(|registered| registered == source));
        }
        assert_eq!(
            str_field(parser_acceptance, "owner").unwrap(),
            "test-harness"
        );
        assert_eq!(
            str_field(parser_acceptance, "profile").unwrap(),
            "offline-validation"
        );
        assert_eq!(
            string_array(parser_acceptance, "test_services").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(str_field(parser_acceptance, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(parser_acceptance, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "acceptance::tests::",
                "--",
                "--test-threads=1",
                "--skip",
                "evaluate_acceptance::tests::",
                "--skip",
                "model_acceptance::tests::"
            ]
        );
        for field in ["minimum_tests", "expected_tests"] {
            assert_eq!(
                parser_acceptance.get(field).and_then(TomlValue::as_integer),
                Some(8)
            );
        }

        let evaluate_acceptance = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "policy-evaluate-evidence-contracts")
            .unwrap();
        for source in [
            "scripts/evaluate_performance_acceptance.py",
            "scripts/tests/test_evaluate_performance_acceptance.py",
        ] {
            assert!(string_array(evaluate_acceptance, "sources")
                .unwrap()
                .iter()
                .any(|registered| registered == source));
        }
        assert_eq!(
            str_field(evaluate_acceptance, "owner").unwrap(),
            "test-harness"
        );
        assert_eq!(
            str_field(evaluate_acceptance, "profile").unwrap(),
            "offline-validation"
        );
        assert_eq!(
            string_array(evaluate_acceptance, "test_services").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            str_field(evaluate_acceptance, "acceptance").unwrap(),
            "rust"
        );
        assert_eq!(
            string_array(evaluate_acceptance, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "evaluate_acceptance::tests::",
                "--",
                "--test-threads=1"
            ]
        );
        for field in ["minimum_tests", "expected_tests"] {
            assert_eq!(
                evaluate_acceptance
                    .get(field)
                    .and_then(TomlValue::as_integer),
                Some(11)
            );
        }

        for (id, expected_series, rust_filter, expected_tests, expected_sources) in [
            (
                "e1-frozen-result-contracts",
                "E1",
                "e1_frozen_result::tests::",
                1,
                vec![
                    "test-harness/src/e1_frozen_result.rs",
                    "Docs/authorization-validation/archive/python-tests/test_e1_runner.py",
                ],
            ),
            (
                "e3-config-validation-contracts",
                "E3",
                "e3_config::tests::",
                8,
                vec![
                    "test-harness/src/e3_config.rs",
                    "Docs/authorization-validation/archive/python-tests/test_e3_runner.py",
                ],
            ),
            (
                "e3-report-category-contracts",
                "E3",
                "e3_report::tests::",
                16,
                vec![
                    "test-harness/src/e3_report.rs",
                    "Docs/authorization-validation/archive/python-tests/test_e3_e4.py",
                    "Docs/authorization-validation/archive/python-tests/test_e3_runner.py",
                ],
            ),
            (
                "e4-protocol-contract",
                "E4",
                "e4_protocol::tests::",
                7,
                vec![
                    "test-harness/src/e4_protocol.rs",
                    "Docs/authorization-validation/archive/python-tests/test_e4_fault_driver.py",
                    "Docs/authorization-validation/archive/python-tests/test_experiment_common.py",
                ],
            ),
        ] {
            let suite = manifest
                .suites
                .iter()
                .find(|suite| suite_id(suite) == id)
                .unwrap_or_else(|| panic!("missing offline contract suite {id}"));
            assert_eq!(str_field(suite, "owner").unwrap(), "test-harness");
            assert_eq!(str_field(suite, "profile").unwrap(), "offline-validation");
            assert_eq!(str_field(suite, "scope").unwrap(), "offline-model");
            assert_eq!(str_field(suite, "acceptance").unwrap(), "rust");
            assert_eq!(
                string_array(suite, "series").unwrap(),
                vec![expected_series.to_owned()]
            );
            assert_eq!(
                string_array(suite, "test_services").unwrap(),
                Vec::<String>::new()
            );
            assert_eq!(
                string_array(suite, "sources").unwrap(),
                expected_sources
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                string_array(suite, "argv").unwrap(),
                vec![
                    "cargo",
                    "test",
                    "-p",
                    "test-harness",
                    "--locked",
                    "--lib",
                    rust_filter,
                    "--",
                    "--test-threads=1",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
            );
            for field in ["minimum_tests", "expected_tests"] {
                assert_eq!(
                    suite.get(field).and_then(TomlValue::as_integer),
                    Some(expected_tests),
                    "{id} {field} must match the Rust test count"
                );
            }
            assert!(suite.get("blocked_reason").is_none());
        }

        for (id, module, expected_tests, rust_filter) in [
            (
                "tdsc-performance-helper-contracts",
                "experiments/tdsc/protocol-runner/test_run_performance.py",
                10,
                "tdsc_performance::tests::",
            ),
            (
                "s15-validation-helper-contracts",
                "Docs/实验/分布式测试/rust-s15/test_s15_validation.py",
                6,
                "s15_validation::tests::",
            ),
        ] {
            let suite = manifest
                .suites
                .iter()
                .find(|suite| suite_id(suite) == id)
                .unwrap_or_else(|| panic!("missing native Rust suite {id}"));
            assert_eq!(str_field(suite, "owner").unwrap(), "test-harness");
            assert_eq!(str_field(suite, "profile").unwrap(), "offline-validation");
            assert_eq!(
                string_array(suite, "test_services").unwrap(),
                Vec::<String>::new()
            );
            assert_eq!(str_field(suite, "scope").unwrap(), "component");
            assert_eq!(str_field(suite, "acceptance").unwrap(), "rust");
            let expected_sources = if id.starts_with("tdsc") {
                vec!["test-harness/src/tdsc_performance.rs".to_owned()]
            } else {
                vec![
                    "test-harness/src/s15_validation.rs".to_owned(),
                    module.to_owned(),
                    "Docs/实验/分布式测试/rust-s15/s15_validation.py".to_owned(),
                ]
            };
            assert_eq!(string_array(suite, "sources").unwrap(), expected_sources);
            assert_eq!(
                string_array(suite, "argv").unwrap(),
                vec![
                    "cargo",
                    "test",
                    "-p",
                    "test-harness",
                    "--locked",
                    "--lib",
                    rust_filter,
                    "--",
                    "--test-threads=1"
                ]
            );
            assert_eq!(
                suite.get("minimum_tests").and_then(TomlValue::as_integer),
                Some(expected_tests)
            );
            assert_eq!(
                suite.get("expected_tests").and_then(TomlValue::as_integer),
                Some(expected_tests)
            );
            assert!(suite.get("blocked_reason").is_none());
        }
    }

    #[test]
    fn manifest_entries_are_scoped_and_blocked_entries_are_not_dispatched() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = read_manifest(root).unwrap();
        assert_archived_python_migrations_are_accounted(root, &manifest);
        assert_python_unittest_inventory_is_accounted(root, &manifest);
        assert!(manifest
            .suites
            .iter()
            .filter(|suite| suite.get("blocked_reason").is_some())
            .all(|suite| suite
                .get("argv")
                .and_then(TomlValue::as_array)
                .is_none_or(Vec::is_empty)));
        let e5_single = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "e5-bounded-single")
            .unwrap();
        assert!(e5_single.get("blocked_reason").is_none());
        assert_eq!(str_field(e5_single, "owner").unwrap(), "test-harness");
        assert_eq!(
            str_field(e5_single, "profile").unwrap(),
            "offline-validation"
        );
        assert_eq!(str_field(e5_single, "scope").unwrap(), "offline-model");
        assert_eq!(str_field(e5_single, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(e5_single, "test_services").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            string_array(e5_single, "sources").unwrap(),
            vec![
                "test-harness/src/e5_model.rs",
                "test-harness/src/e5_model/report.rs",
                "test-harness/src/bin/e5-model-check.rs",
                "test-harness/tests/e5_model_check_cli.rs",
                "test-harness/src/fixtures/e5-single-reference-28.json",
                "Docs/authorization-validation/tools/e5_model_check.py",
                "Docs/authorization-validation/archive/python-tests/test_e5_model_check.py",
            ]
        );
        assert_eq!(
            string_array(e5_single, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "e5_model::tests::",
                "--",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            e5_single
                .get("minimum_tests")
                .and_then(TomlValue::as_integer),
            Some(16)
        );
        assert_eq!(
            e5_single
                .get("expected_tests")
                .and_then(TomlValue::as_integer),
            Some(16)
        );
        let e5_cli = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "e5-single-cli-contracts")
            .expect("E5 CLI binary tests have a dedicated manifest suite");
        assert_eq!(str_field(e5_cli, "owner").unwrap(), "test-harness");
        assert_eq!(str_field(e5_cli, "profile").unwrap(), "offline-validation");
        assert_eq!(str_field(e5_cli, "scope").unwrap(), "offline-model");
        assert_eq!(str_field(e5_cli, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(e5_cli, "test_services").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            string_array(e5_cli, "sources").unwrap(),
            vec![
                "test-harness/tests/e5_model_check_cli.rs",
                "test-harness/src/bin/e5-model-check.rs",
                "Docs/authorization-validation/tools/e5_model_check.py",
                "Docs/authorization-validation/archive/python-tests/test_e5_model_check.py",
            ]
        );
        assert_eq!(
            string_array(e5_cli, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--test",
                "e5_model_check_cli",
                "--",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            e5_cli.get("minimum_tests").and_then(TomlValue::as_integer),
            Some(4)
        );
        assert_eq!(
            e5_cli.get("expected_tests").and_then(TomlValue::as_integer),
            Some(4)
        );
        let report_acceptance = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "e5-report-acceptance-contracts")
            .unwrap();
        assert_eq!(
            report_acceptance
                .get("minimum_tests")
                .and_then(TomlValue::as_integer),
            Some(4)
        );
        let e5_two_mutations = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "e5-bounded-two-mutations")
            .unwrap();
        assert!(e5_two_mutations.get("blocked_reason").is_none());
        assert_eq!(str_field(e5_two_mutations, "acceptance").unwrap(), "rust");
        assert_eq!(
            str_field(e5_two_mutations, "owner").unwrap(),
            "test-harness"
        );
        assert_eq!(
            string_array(e5_two_mutations, "sources").unwrap(),
            vec![
                "test-harness/src/two_mutation_model.rs",
                "Docs/authorization-validation/tools/e5_model_check_two_mutations.py",
                "Docs/authorization-validation/archive/python-tests/test_e5_model_check_two_mutations.py",
            ]
        );
        assert_eq!(
            string_array(e5_two_mutations, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "two_mutation_model::tests::",
                "--",
                "--test-threads=1",
            ]
        );
        let universal = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "e5-universal-bounded")
            .unwrap();
        assert!(universal.get("blocked_reason").is_none());
        assert_eq!(str_field(universal, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(universal, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "--release",
                "-p",
                "test-harness",
                "--locked",
                "--test",
                "e5_universal_native",
                "--",
                "--ignored",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            universal
                .get("minimum_tests")
                .and_then(TomlValue::as_integer),
            Some(1)
        );

        let evaluator = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "e5-universal-evaluator-contracts")
            .unwrap();
        assert!(evaluator.get("blocked_reason").is_none());
        assert_eq!(str_field(evaluator, "owner").unwrap(), "test-harness");
        assert_eq!(str_field(evaluator, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(evaluator, "sources").unwrap(),
            vec![
                "test-harness/src/universal_hypotheses.rs",
                "test-harness/src/model_acceptance.rs",
                "Docs/authorization-validation/tools/universal_hypotheses_check.py",
                "Docs/authorization-validation/tools/model_acceptance.py",
                "Docs/authorization-validation/archive/python-tests/test_universal_hypotheses_check.py",
            ]
        );
        assert_eq!(
            string_array(evaluator, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "universal_hypotheses::tests::",
                "--",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            evaluator
                .get("minimum_tests")
                .and_then(TomlValue::as_integer),
            Some(7)
        );

        let projection_owner = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "projection-owner-model-contracts")
            .unwrap();
        assert!(projection_owner.get("blocked_reason").is_none());
        assert_eq!(
            str_field(projection_owner, "owner").unwrap(),
            "test-harness"
        );
        assert_eq!(str_field(projection_owner, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(projection_owner, "sources").unwrap(),
            vec![
                "test-harness/src/projection_owner_model.rs",
                "Docs/authorization-validation/tools/projection_owner_model.py",
                "Docs/authorization-validation/archive/python-tests/test_projection_owner_model.py",
                "tests-suite/series/RQ3/native_projection_lifecycle.rs",
                "tests-suite/series/RQ3/projection_owned_integration.rs",
            ]
        );
        assert_eq!(
            string_array(projection_owner, "argv").unwrap(),
            vec![
                "cargo",
                "test",
                "-p",
                "test-harness",
                "--locked",
                "--lib",
                "projection_owner_model::tests::",
                "--",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            projection_owner
                .get("minimum_tests")
                .and_then(TomlValue::as_integer),
            Some(15)
        );
        let benefit = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "policy-evaluate-benefit")
            .unwrap();
        assert_eq!(
            string_array(benefit, "sources").unwrap(),
            vec![
                "astral-db/src/memory_projection_hub/tests/evaluate_performance.rs",
                "astral-db/src/memory_projection_hub/tests/evaluate_performance/fixture.rs",
                "astral-db/src/memory_projection_hub/tests/evaluate_performance/controls.rs",
                "test-harness/src/evaluate_acceptance.rs",
            ]
        );
        let shell = manifest
            .suites
            .iter()
            .find(|suite| suite_id(suite) == "shell-runner-contracts")
            .unwrap();
        assert_eq!(str_field(shell, "acceptance").unwrap(), "rust");
        assert_eq!(
            string_array(shell, "argv").unwrap(),
            vec![
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "test-harness".to_owned(),
                "--locked".to_owned(),
                "--lib".to_owned(),
                "campaign::tests::shell_entrypoints_".to_owned(),
                "--".to_owned(),
                "--test-threads=1".to_owned(),
            ]
        );
    }

    #[test]
    fn classify_output_requires_complete_evaluate_and_divan_evidence() {
        let evidence_suite: TomlValue = toml::from_str(
            "acceptance='rust'\nminimum_tests=1\nevidence_contract='policy-evaluate-benefit'\n",
        )
        .unwrap();
        let complete = crate::evaluate_acceptance::valid_output_fixture();
        assert_eq!(
            classify_output(&evidence_suite, 0, &complete, "", false)["status"],
            "PASS"
        );
        let incomplete = complete
            .lines()
            .filter(|line| !line.starts_with("EVALUATE_PERF_CASE "))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            classify_output(&evidence_suite, 0, &incomplete, "", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&evidence_suite, 0, &complete, "", true)["status"],
            "UNKNOWN"
        );
        let incompatible: TomlValue =
            toml::from_str("acceptance='command'\nevidence_contract='policy-evaluate-benefit'\n")
                .unwrap();
        assert_eq!(
            classify_output(&incompatible, 0, &complete, "", false)["status"],
            "FAIL"
        );
        let no_records = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n";
        assert_eq!(
            classify_output(&evidence_suite, 0, no_records, "", false)["status"],
            "FAIL"
        );
        for (exit_code, output, expected) in [
            (101, no_records, "FAIL"),
            (0, "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n", "FAIL"),
            (0, "test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n", "SKIP"),
            (0, "[SKIP] missing assertion\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n", "SKIP"),
            (124, no_records, "UNKNOWN"),
        ] {
            assert_eq!(
                classify_output(&evidence_suite, exit_code, output, "", false)["status"],
                expected
            );
        }
    }

    #[test]
    fn explicit_status_and_process_outcomes_keep_fail_closed_precedence() {
        let command: TomlValue =
            toml::from_str("acceptance='command'\nrequired_output='contract'\n").unwrap();
        let rust: TomlValue = toml::from_str("acceptance='rust'\nminimum_tests=1\n").unwrap();
        let successful = [
            (&command, "contract\n", ""),
            (&rust, &rust_summary(1, 0, 0, 0), ""),
        ];
        for status in ["PENDING", "BLOCKED", "FAIL", "UNKNOWN", "SKIP"] {
            for (suite, stdout, stderr) in successful {
                for marker_stream in ["stdout", "stderr"] {
                    let marker = format!("[{status}] explicit runner state\n");
                    let out = if marker_stream == "stdout" {
                        format!("{stdout}{marker}")
                    } else {
                        stdout.to_owned()
                    };
                    let err = if marker_stream == "stderr" {
                        format!("{stderr}{marker}")
                    } else {
                        stderr.to_owned()
                    };
                    assert_eq!(
                        classify_output(suite, 0, &out, &err, false)["status"],
                        status,
                        "{status}/{marker_stream}/{}",
                        str_field(suite, "acceptance").unwrap()
                    );
                    let lower =
                        format!("[{}] explicit runner state\n", status.to_ascii_lowercase());
                    assert_eq!(
                        classify_output(suite, 0, &format!("{stdout}{lower}"), stderr, false)
                            ["status"],
                        status,
                        "lowercase {status}/{}",
                        str_field(suite, "acceptance").unwrap()
                    );
                }
            }
        }
        assert_eq!(
            classify_output(&command, 101, "contract\n[PENDING] unproven\n", "", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&command, 0, "contract\n[PENDING] unproven\n", "", true)["status"],
            "UNKNOWN"
        );
        assert_eq!(
            classify_output(&command, 0, "contract\n[UNKNOWN] unproven\n", "", false)["status"],
            "UNKNOWN"
        );
        for code in [124, 130, 137, 143, -9] {
            assert_eq!(
                classify_output(&command, code, "", "", false)["status"],
                "UNKNOWN"
            );
        }
        assert_eq!(
            classify_output(&command, 101, "", "", false)["status"],
            "FAIL"
        );
    }

    #[test]
    fn model_dependency_and_required_output_acceptance_keep_contract_boundaries() {
        let full_contract: TomlValue = toml::from_str(
            "acceptance='model-json'\nmodel_contract='full-contract'\nmodel_name='single'\n",
        )
        .unwrap();
        let single = full_model_report("single", false);
        assert_eq!(
            classify_output(&full_contract, 0, &single.to_string(), "", false)["status"],
            "PASS"
        );
        let two_summary = full_model_report("two", true);
        let two_contract: TomlValue = toml::from_str(
            "acceptance='model-json'\nmodel_contract='full-contract'\nmodel_name='two'\n",
        )
        .unwrap();
        assert_eq!(
            classify_output(&two_contract, 0, &two_summary.to_string(), "", false)["status"],
            "PASS"
        );
        let mut incomplete = single.clone();
        incomplete["fullContract"]["modes"]
            .as_object_mut()
            .unwrap()
            .remove("strict");
        assert_eq!(
            classify_output(&full_contract, 0, &incomplete.to_string(), "", false)["status"],
            "UNKNOWN"
        );
        let mut violation = single.clone();
        violation["fullContract"]["modes"]["strict"]["violations"] = json!(1);
        assert_eq!(
            classify_output(&full_contract, 0, &violation.to_string(), "", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&full_contract, 0, "not-json", "", false)["status"],
            "UNKNOWN"
        );

        let dependency_tree: TomlValue = toml::from_str("acceptance='dependency-tree'\n").unwrap();
        assert_eq!(
            classify_output(
                &dependency_tree,
                0,
                "astral-single-node v0.1.0\nmysql v8\n",
                "",
                false
            )["status"],
            "PASS"
        );
        assert_eq!(
            classify_output(
                &dependency_tree,
                0,
                "astral-single-node v0.1.0\nredis v1\n",
                "",
                false
            )["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&dependency_tree, 0, "", "", false)["status"],
            "FAIL"
        );

        let command: TomlValue =
            toml::from_str("acceptance='command'\nrequired_output='12 scenarios passed'\n")
                .unwrap();
        assert_eq!(
            classify_output(&command, 0, "", "", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&command, 0, "12 scenarios passed", "", false)["status"],
            "PASS"
        );
    }

    #[test]
    fn cpu_performance_matrix_requires_exact_unique_cases_and_fifteen_samples() {
        let item: TomlValue =
            toml::from_str("acceptance='rust'\nminimum_tests=1\nperformance_cases=2\n").unwrap();
        let samples = serde_json::to_string(&vec![10; 15]).unwrap();
        let one = format!("PERF_MATRIX {{\"case\":\"one\",\"samples\":{samples}}}");
        let two = format!("PERF_MATRIX {{\"case\":\"two\",\"samples\":{samples}}}");
        let complete = format!("{one}\n{two}\n{}", rust_summary(1, 0, 0, 0));
        let accepted = classify_output(&item, 0, &complete, "", false);
        assert_eq!(accepted["status"], "PASS", "{accepted}");
        assert_eq!(accepted["performance"]["cases"], 2);
        assert_eq!(accepted["tests"]["passed"], 1);
        for malformed in [
            rust_summary(1, 0, 0, 0),
            format!("{one}\n{one}\n{}", rust_summary(1, 0, 0, 0)),
            format!(
                "{one}\nPERF_MATRIX {{\"case\":\"two\",\"samples\":[]}}\n{}",
                rust_summary(1, 0, 0, 0)
            ),
            format!(
                "PERF_MATRIX {{\"case\":\"one\",\"samples\":[{}]}}\n{two}\n{}",
                vec!["true"; 15].join(","),
                rust_summary(1, 0, 0, 0)
            ),
        ] {
            assert_eq!(
                classify_output(&item, 0, &malformed, "", false)["status"],
                "FAIL",
                "{malformed}"
            );
        }
        assert_eq!(
            classify_output(&item, 0, &complete, "", true)["status"],
            "UNKNOWN"
        );
        assert_eq!(
            classify_output(&item, 101, &complete, "", false)["status"],
            "FAIL"
        );
    }

    #[test]
    fn divan_exit_zero_requires_complete_timing_and_allocation_rows() {
        let suite: TomlValue = toml::from_str(
            "acceptance='divan'\nbenchmark_cases=['one']\nallocation_cases=['one']\n",
        )
        .unwrap();
        let complete = [
            "one │ 1 ns │ 4 ns │ 2 ns │ 3 ns │ 100 │ 200",
            "  │ alloc: │ │ │ │ │",
            "  │ 1 │ 2 │ 1.5 │ 1.6 │ │",
            "  │ 8 B │ 16 B │ 12 B │ 12.8 B │ │",
        ]
        .join("\n");
        assert_eq!(
            classify_output(&suite, 0, &complete, "", false)["status"],
            "PASS"
        );
        let incomplete = complete.lines().take(1).collect::<Vec<_>>().join("\n");
        assert_eq!(
            classify_output(&suite, 0, &incomplete, "", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&suite, 7, &complete, "", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&suite, 0, &complete, "", true)["status"],
            "UNKNOWN"
        );
    }

    #[test]
    fn artifact_paths_resolve_relative_components_and_reject_workspace_symlinks() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert!(validate_artifact_root(root, Path::new(".")).is_err());
        #[cfg(unix)]
        let outside = TestDirectory::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = outside.0.join("workspace-link");
            symlink(root, &link).unwrap();
            assert!(validate_artifact_root(root, &link).is_err());
        }
        let relative = resolve_artifact_root(Path::new(".")).unwrap();
        assert!(relative.is_absolute());
    }

    #[cfg(unix)]
    #[test]
    fn execute_waits_for_descendants_before_freezing_logs() {
        let directory = TestDirectory::new();
        let suite = command_suite(
            &[
                "/bin/sh",
                "-c",
                "(/bin/sleep 0.2; printf late) & printf early",
            ],
            5,
        );
        let result =
            execute_posix(&suite, &BTreeMap::new(), &directory.0, &directory.0, 1024).unwrap();
        assert_eq!(result["status"], "PASS", "{result}");
        let stdout = fs::read_to_string(result["stdout"].as_str().unwrap()).unwrap();
        assert!(stdout.contains("early"));
        assert!(stdout.contains("late"));
        assert_eq!(result["log_integrity"], "complete");
    }

    #[cfg(unix)]
    #[test]
    fn execute_waits_for_descendant_stderr_and_hashes_the_frozen_bytes() {
        let directory = TestDirectory::new();
        let suite = command_suite(
            &[
                "/bin/sh",
                "-c",
                "(/bin/sleep 0.2; printf 'descendant complete\\n' >&2) & printf 'parent complete\\n'",
            ],
            5,
        );
        let result =
            execute_posix(&suite, &BTreeMap::new(), &directory.0, &directory.0, 1024).unwrap();
        assert_eq!(result["status"], "PASS", "{result}");
        assert_eq!(result["log_integrity"], "complete");
        let stderr_path = result["stderr"].as_str().unwrap();
        let stderr = fs::read(stderr_path).unwrap();
        assert!(String::from_utf8_lossy(&stderr).contains("descendant complete"));
        thread::sleep(Duration::from_millis(300));
        assert_eq!(fs::read(stderr_path).unwrap(), stderr);
        assert_eq!(
            result["stderr_sha256"],
            format!("{:x}", Sha256::digest(&stderr))
        );
    }

    #[cfg(unix)]
    #[test]
    fn execute_timeout_waits_for_delayed_descendant_stderr_before_hashing() {
        let directory = TestDirectory::new();
        use std::os::unix::fs::PermissionsExt;
        let child = directory.0.join("delayed-child.sh");
        fs::write(
            &child,
            "#!/bin/sh\ntrap 'sleep 0.25; printf \"descendant shutdown\\n\" >&2; exit 0' TERM\nwhile :; do /bin/sleep 0.1; done\n",
        )
        .unwrap();
        let parent = directory.0.join("parent.sh");
        fs::write(&parent, format!("#!/bin/sh\n{} &\nwait\n", child.display())).unwrap();
        for script in [&child, &parent] {
            let mut permissions = fs::metadata(script).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(script, permissions).unwrap();
        }
        let suite = command_suite(&[parent.to_str().unwrap()], 3);
        let result =
            execute_posix(&suite, &BTreeMap::new(), &directory.0, &directory.0, 1024).unwrap();
        assert_eq!(result["status"], "UNKNOWN", "{result}");
        assert_eq!(result["stream_disconnect"], true);
        let stderr_path = result["stderr"].as_str().unwrap();
        let stderr = fs::read(stderr_path).unwrap();
        assert!(String::from_utf8_lossy(&stderr).contains("descendant shutdown"));
        thread::sleep(Duration::from_millis(300));
        assert_eq!(fs::read(stderr_path).unwrap(), stderr);
        assert_eq!(
            result["stderr_sha256"],
            format!("{:x}", Sha256::digest(&stderr))
        );
    }

    #[cfg(unix)]
    #[test]
    fn execute_redacts_short_secrets_normalizes_newlines_and_hashes_exact_artifacts() {
        let directory = TestDirectory::new();
        let suite = command_suite(
            &[
                "/bin/sh",
                "-c",
                "printf 'abc123 key-value mixed-case private-value visible mysql://fixture@localhost/db\\r\\n'; printf 'private-value stderr\\r\\n' >&2",
            ],
            5,
        );
        let environment = BTreeMap::from([
            (OsString::from("API_KEY"), OsString::from("abc123")),
            (OsString::from("ACCESS_KEY"), OsString::from("key-value")),
            (OsString::from("apiKey"), OsString::from("mixed-case")),
            (
                OsString::from("PRIVATE_KEY"),
                OsString::from("private-value"),
            ),
            (OsString::from("ORDINARY"), OsString::from("visible")),
        ]);
        let result = execute_posix(&suite, &environment, &directory.0, &directory.0, 1024).unwrap();
        assert_eq!(result["status"], "PASS", "{result}");
        for stream in ["stdout", "stderr"] {
            let bytes = fs::read(result[stream].as_str().unwrap()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("abc123"));
            assert!(!text.contains("key-value"));
            assert!(!text.contains("mixed-case"));
            assert!(!text.contains("private-value"));
            assert!(!text.contains("mysql://"));
            assert!(!bytes.windows(2).any(|pair| pair == b"\r\n"));
            assert_eq!(
                result[format!("{stream}_sha256")],
                format!("{:x}", Sha256::digest(&bytes))
            );
        }
        assert!(fs::read_to_string(result["stdout"].as_str().unwrap())
            .unwrap()
            .contains("visible"));
    }

    #[cfg(unix)]
    #[test]
    fn execute_marks_fast_oversized_logs_unknown_and_keeps_bounded_prefix() {
        let directory = TestDirectory::new();
        let suite = command_suite(&["/bin/sh", "-c", "printf 12345; printf abcde >&2"], 5);
        let result =
            execute_posix(&suite, &BTreeMap::new(), &directory.0, &directory.0, 8).unwrap();
        assert_eq!(result["status"], "UNKNOWN", "{result}");
        assert_eq!(result["stream_disconnect"], true);
        assert!(result["log_integrity"]
            .as_str()
            .unwrap()
            .contains("exceeded limit"));
        let stdout = fs::read(result["stdout"].as_str().unwrap()).unwrap();
        let stderr = fs::read(result["stderr"].as_str().unwrap()).unwrap();
        assert!(stdout.len() + stderr.len() <= 8);
    }

    #[cfg(unix)]
    #[test]
    fn execute_terminates_timed_out_process_group_and_returns_unknown() {
        let directory = TestDirectory::new();
        let mut suite = command_suite(&["/bin/sh", "-c", "/bin/sleep 30"], 1);
        suite["acceptance"] = TomlValue::String("rust".into());
        suite
            .as_table_mut()
            .unwrap()
            .insert("minimum_tests".into(), TomlValue::Integer(1));
        suite.as_table_mut().unwrap().insert(
            "evidence_contract".into(),
            TomlValue::String("policy-evaluate-benefit".into()),
        );
        let result =
            execute_posix(&suite, &BTreeMap::new(), &directory.0, &directory.0, 1024).unwrap();
        assert_eq!(result["status"], "UNKNOWN", "{result}");
        assert_eq!(result["stream_disconnect"], true);
    }

    #[test]
    fn native_environment_clears_live_credentials() {
        let item: TomlValue = toml::from_str("id='x'\nprofile='native-kernel'\ntest_services=[]\nseries=['E1']\nscope='component'\nowner='x'\nboundary='x'\nsources=[]\nargv=['cargo','test']\nacceptance='rust'\n").unwrap();
        let input = isolated_environment();
        let (result, error) = prepare_environment(&item, &input);
        assert!(error.is_none());
        for name in [
            "DATABASE_URL",
            "REDIS_URL",
            "RABBITMQ_URL",
            "RUST_INTEGRATION_REQUIRED",
            "ASTRAL_TEST_DATABASE_NAME",
            "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL",
            "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE",
            "ASTRAL_MIGRATION_ENV",
            "COMPOSE_PROFILES",
        ] {
            assert!(!result.contains_key(std::ffi::OsStr::new(name)), "{name}");
        }
        assert_eq!(
            result
                .get(std::ffi::OsStr::new("ASTRAL_MESSAGE_TRANSPORT"))
                .unwrap(),
            "local"
        );
        assert!(!result.contains_key(std::ffi::OsStr::new("ASTRAL_REDIS_PROJECTION_COMPAT")));
        assert!(!result.contains_key(std::ffi::OsStr::new("ASTRAL_PROJECTION_EXECUTION_MODE")));
    }

    #[test]
    fn native_profiles_select_only_declared_services_and_scrub_retired_selectors() {
        let mut parent = isolated_environment();
        parent.push((
            "ASTRAL_PROJECTION_EXECUTION_MODE".into(),
            "worker-owned".into(),
        ));
        parent.push(("ASTRAL_REDIS_PROJECTION_COMPAT".into(), "true".into()));
        let mut inherited = parent.clone();
        inherited.push((
            "ASTRAL_PROJECTION_EXECUTION_MODE".into(),
            "legacy-hybrid".into(),
        ));
        let kernel: TomlValue = toml::from_str("id='kernel'\nprofile='native-kernel'\ntest_services=[]\nseries=['E1']\nscope='component'\nowner='x'\nboundary='x'\nsources=[]\nargv=['cargo','test']\nacceptance='rust'\n").unwrap();
        let (env, error) = prepare_environment(&kernel, &inherited);
        assert!(error.is_none());
        assert!(!env.contains_key(std::ffi::OsStr::new("ASTRAL_PROJECTION_EXECUTION_MODE")));
        assert!(!env.contains_key(std::ffi::OsStr::new("ASTRAL_REDIS_PROJECTION_COMPAT")));
        assert!(!env.contains_key(std::ffi::OsStr::new("DATABASE_URL")));
        assert!(!env.contains_key(std::ffi::OsStr::new("RABBITMQ_URL")));
        assert!(!env.contains_key(std::ffi::OsStr::new("REDIS_URL")));

        let rabbit: TomlValue = toml::from_str("id='rabbit'\nprofile='standalone-rabbit'\ntest_services=['mysql','rabbitmq']\nseries=['RQ3']\nscope='integration'\nowner='x'\nboundary='x'\nsources=[]\nargv=['cargo','test']\nacceptance='rust'\n").unwrap();
        let (env, error) = prepare_environment(&rabbit, &parent);
        assert!(error.is_none(), "{error:?}");
        assert!(env.contains_key(std::ffi::OsStr::new("RABBITMQ_URL")));
        assert!(!env.contains_key(std::ffi::OsStr::new("REDIS_URL")));
        assert_eq!(
            env[std::ffi::OsStr::new("ASTRAL_MESSAGE_TRANSPORT")],
            "rabbit"
        );
        assert!(!env.contains_key(std::ffi::OsStr::new("ASTRAL_PROJECTION_EXECUTION_MODE")));
        assert!(!env.contains_key(std::ffi::OsStr::new("ASTRAL_REDIS_PROJECTION_COMPAT")));
        let mut bad_vhost = parent.clone();
        bad_vhost
            .iter_mut()
            .find(|(key, _)| key == "RABBITMQ_URL")
            .unwrap()
            .1 = "amqp://fixture@127.0.0.1:5673/".into();
        assert!(prepare_environment(&rabbit, &bad_vhost).1.is_some());

        let unknown_profile: TomlValue = toml::from_str("id='unregistered'\nprofile='unregistered-profile'\ntest_services=[]\nseries=['E1']\nscope='component'\nowner='x'\nboundary='x'\nsources=[]\nargv=['cargo','test']\nacceptance='rust'\n").unwrap();
        assert!(registered_services("unregistered-profile").is_none());
        assert!(prepare_environment(&unknown_profile, &parent).1.is_some());
    }

    #[test]
    fn preflight_requires_an_exact_isolated_database_and_loopback_service() {
        let item: TomlValue = toml::from_str("id='x'\nprofile='standalone-rabbit'\ntest_services=['mysql','rabbitmq']\nseries=['RQ3']\nscope='integration'\nowner='x'\nboundary='x'\nsources=[]\nargv=['cargo','test']\nacceptance='rust'\n").unwrap();
        let input = isolated_environment();
        let (good, error) = prepare_environment(&item, &input);
        assert!(error.is_none(), "{error:?}");
        assert!(good.contains_key(std::ffi::OsStr::new("DATABASE_URL")));
        let mut bad = input.clone();
        bad.iter_mut()
            .find(|(key, _)| key == "DATABASE_URL")
            .unwrap()
            .1 = "mysql://fixture@example.invalid:3308/astral_rehearsal_contract".into();
        assert!(prepare_environment(&item, &bad).1.is_some());

        for (key, value) in [
            ("TEST_USE_EXISTING", "0"),
            ("ASTRAL_MIGRATION_ENV", "production"),
            ("RUST_INTEGRATION_REQUIRED", "0"),
        ] {
            let mut missing = input.clone();
            missing.iter_mut().find(|(name, _)| name == key).unwrap().1 = value.into();
            assert!(prepare_environment(&item, &missing).1.is_some(), "{key}");
        }
        for name in [
            "astral_test",
            "astral_rehearsal_",
            "astral_rehearsal_uppercase",
            "astral_rehearsal_bad-hyphen",
            "astral_rehearsal_other",
        ] {
            let mut mismatch = input.clone();
            mismatch
                .iter_mut()
                .find(|(key, _)| key == "DATABASE_URL")
                .unwrap()
                .1 = format!("mysql://fixture@127.0.0.1:3308/{name}").into();
            assert!(prepare_environment(&item, &mismatch).1.is_some(), "{name}");
        }
        for value in [
            "mysql://fixture@127.0.0.1:3306/astral_rehearsal_contract",
            "mysql://fixture@127.0.0.1:3308/astral_rehearsal_contract?option=1",
        ] {
            let mut mismatch = input.clone();
            mismatch
                .iter_mut()
                .find(|(key, _)| key == "DATABASE_URL")
                .unwrap()
                .1 = value.into();
            assert!(prepare_environment(&item, &mismatch).1.is_some(), "{value}");
        }
    }

    #[test]
    fn dedicated_identity_mapping_requires_its_exact_run_scoped_database() {
        let item: TomlValue = toml::from_str("id='mapping'\nprofile='native-single-node'\ntest_services=['mysql']\nseries=['M5']\nscope='integration'\ndatabase_scope='identity-mapping'\nowner='x'\nboundary='x'\nsources=[]\nargv=['cargo','test']\nacceptance='rust'\n").unwrap();
        let mut input = isolated_environment();
        input.retain(|(key, _)| {
            key != "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL"
                && key != "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE"
        });
        assert!(prepare_environment(&item, &input).1.is_some());

        let mut valid = isolated_environment();
        valid
            .iter_mut()
            .find(|(key, _)| key == "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL")
            .unwrap()
            .1 = "mysql://fixture@127.0.0.1:3308/sdk_identity_mapping_test_run_01".into();
        valid
            .iter_mut()
            .find(|(key, _)| key == "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE")
            .unwrap()
            .1 = "sdk_identity_mapping_test_run_01".into();
        let (prepared, error) = prepare_environment(&item, &valid);
        assert!(error.is_none(), "{error:?}");
        assert_eq!(
            prepared[std::ffi::OsStr::new("DATABASE_URL")],
            valid
                .iter()
                .find(|(key, _)| key == "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL")
                .unwrap()
                .1
        );
        assert_eq!(
            prepared[std::ffi::OsStr::new("INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE")],
            "sdk_identity_mapping_test_run_01"
        );
        for name in [
            "sdk_identity_mapping_test_",
            "sdk_identity_mapping_test_upper-case",
        ] {
            let mut invalid = valid.clone();
            invalid
                .iter_mut()
                .find(|(key, _)| key == "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL")
                .unwrap()
                .1 = format!("mysql://fixture@127.0.0.1:3308/{name}").into();
            invalid
                .iter_mut()
                .find(|(key, _)| key == "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE")
                .unwrap()
                .1 = name.into();
            assert!(prepare_environment(&item, &invalid).1.is_some(), "{name}");
        }
    }

    #[test]
    fn retired_unittest_acceptance_never_mints_pass_from_python_output() {
        let item: TomlValue = toml::from_str("acceptance='unittest'\nminimum_tests=1\n").unwrap();
        for output in [
            "Ran 2 tests in 0.001s\n\nOK\n",
            "Ran 0 tests in 0.001s\n\nOK\n",
            "Ran 2 tests in 0.001s\n\nOK (skipped=1)\n",
            "OK\n",
            "Ran 1 test in 0.001s\n\nFAIL: test_contract\n",
        ] {
            let result = classify_output(&item, 0, "", output, false);
            assert_eq!(result["status"], "FAIL");
            assert_eq!(
                result["reason"],
                "retired non-Rust test acceptance contract"
            );
        }
        assert_eq!(
            classify_output(&item, 101, "", "Ran 2 tests in 0.001s\n\nOK\n", false)["status"],
            "FAIL"
        );
        assert_eq!(
            classify_output(&item, 0, "", "Ran 2 tests in 0.001s\n\nOK\n", true)["status"],
            "UNKNOWN"
        );
    }

    #[test]
    fn secrets_urls_and_status_folding_remain_fail_closed() {
        let env = vec![
            ("API_KEY".into(), "secret-value".into()),
            ("ACCESS_KEY".into(), "abc123".into()),
            ("apiKey".into(), "mixed-case".into()),
            ("PRIVATE_KEY".into(), "private-value".into()),
            ("ORDINARY".into(), "visible".into()),
        ];
        let scrubbed = scrub_log(
            "key=secret-value short=abc123 mixed=mixed-case private=private-value visible=mysql://user@host/db",
            &env,
        );
        for secret in [
            "secret-value",
            "abc123",
            "mixed-case",
            "private-value",
            "mysql://",
        ] {
            assert!(!scrubbed.contains(secret), "{secret}");
        }
        assert!(scrubbed.contains("visible"));
        assert_eq!(
            fold_status(&[json!({"status":"PASS"}), json!({"status":"UNKNOWN"})]),
            "UNKNOWN"
        );
        assert_eq!(fold_status(&[]), "BLOCKED");
    }

    #[test]
    fn oversized_logs_are_detected_and_only_the_bounded_prefix_is_kept() {
        let (bytes, truncated) = read_limited_to(&b"12345"[..], 4).unwrap();
        assert_eq!(bytes, b"1234");
        assert!(truncated);
        let (bytes, truncated) = read_limited_to(&b"1234"[..], 4).unwrap();
        assert_eq!(bytes, b"1234");
        assert!(!truncated);
    }
}
