use crate::e4_protocol::Status;
use regex::Regex;
use std::sync::OnceLock;

pub const DEFAULT_CACHE_EPOCH_KEY: &str = "astral:auth:cache_epoch";
pub const DEFAULT_CLOCK_SKEW_THRESHOLD_S: f64 = 2.0;
pub const READONLY_REDIS_VERBS: [&str; 3] = ["GET", "LLEN", "PING"];
pub const MAX_STORED_STRING: usize = 120;

const ISOLATION_QUERY: &str = "SELECT @@global.transaction_isolation";
const ISOLATION_FALLBACK_QUERY: &str = "SELECT @@global.tx_isolation";
const READ_ONLY_QUERY: &str = "SELECT @@global.read_only";
const SUPER_READ_ONLY_QUERY: &str = "SELECT @@global.super_read_only";
const SESSION_TIME_ZONE_QUERY: &str = "SELECT @@session.time_zone";
const UTC_NOW_QUERY: &str = "SELECT UTC_TIMESTAMP()";
const KNOWN_ISOLATIONS: [&str; 4] = [
    "READ-UNCOMMITTED",
    "READ-COMMITTED",
    "REPEATABLE-READ",
    "SERIALIZABLE",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeError {
    pub class: &'static str,
    pub detail: String,
}

impl ProbeError {
    pub fn new(class: &'static str, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlReply {
    Rows(Vec<Vec<Option<String>>>),
    UnexpectedShape,
}

pub trait ReadOnlyProbe {
    fn sql(&mut self, query: &str) -> Result<SqlReply, ProbeError>;
    fn has_redis(&self) -> bool;
    fn redis(&mut self, argv: &[&str]) -> Result<Option<String>, ProbeError>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CaptureConfig<'a> {
    pub clock_skew_threshold_s: f64,
    pub cache_epoch_key: &'a str,
    pub cache_epoch_query: Option<&'a str>,
}

impl Default for CaptureConfig<'static> {
    fn default() -> Self {
        Self {
            clock_skew_threshold_s: DEFAULT_CLOCK_SKEW_THRESHOLD_S,
            cache_epoch_key: DEFAULT_CACHE_EPOCH_KEY,
            cache_epoch_query: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureInputError {
    InvalidThreshold,
    EmptyNode { index: usize },
    UnsafeCacheEpochQuery,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CheckValue {
    Text(String),
    ClockOffset {
        db_utc: String,
        probe_epoch_s: f64,
        skew_s: f64,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CheckReport {
    pub status: Status,
    pub value: Option<CheckValue>,
    pub query: Option<&'static str>,
    pub note: Option<&'static str>,
    pub error_class: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeChecks {
    pub transaction_isolation: CheckReport,
    pub read_only: CheckReport,
    pub super_read_only: CheckReport,
    pub session_time_zone: CheckReport,
    pub utc_clock_offset: CheckReport,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeReport {
    pub node_key: String,
    pub overall: Status,
    pub checks: NodeChecks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheEpochSource {
    RedisGet,
    Sql,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CacheEpochReport {
    pub status: Status,
    pub source: CacheEpochSource,
    pub value: Option<String>,
    pub note: Option<&'static str>,
    pub error_class: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limitation {
    pub item: &'static str,
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreconditionReport {
    pub kind: &'static str,
    pub node_count: usize,
    pub nodes: Vec<NodeReport>,
    pub cache_epoch: CacheEpochReport,
    pub overall: Status,
    pub clock_skew_threshold_s: f64,
    pub limitations: Vec<Limitation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarProblem {
    note: &'static str,
    error_class: Option<&'static str>,
}

pub fn require_select_only(query: &str) -> Result<(), CaptureInputError> {
    let stripped = line_comments().replace_all(query, " ");
    let stripped = block_comments().replace_all(&stripped, " ");
    let stripped = stripped.trim();
    if stripped.is_empty()
        || !stripped
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SELECT"))
    {
        return Err(CaptureInputError::UnsafeCacheEpochQuery);
    }
    let body = stripped.strip_suffix(';').unwrap_or(stripped);
    if body.contains(';') {
        return Err(CaptureInputError::UnsafeCacheEpochQuery);
    }
    Ok(())
}

fn block_comments() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").expect("constant SQL comment regex"))
}

fn line_comments() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"--[^\n]*|#[^\n]*").expect("constant SQL comment regex"))
}

fn url_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+").expect("constant URL regex"))
}

fn ipv4_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("constant IPv4 regex"))
}

fn hostname_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+(?:com|net|org|edu|gov|io|dev|app|local|internal|lan|example|test|invalid)\b",
        )
        .expect("constant hostname regex")
    })
}

fn scrub_and_bound(value: &str) -> String {
    let value = url_pattern().replace_all(value, "[redacted-host]");
    let value = ipv4_pattern().replace_all(&value, "[redacted-host]");
    let value = hostname_pattern().replace_all(&value, "[redacted-host]");
    value.chars().take(MAX_STORED_STRING).collect()
}

fn status_of(checks: impl IntoIterator<Item = Status>) -> Status {
    checks.into_iter().min().unwrap_or(Status::Blocked)
}

fn read_scalar<P: ReadOnlyProbe>(probe: &mut P, query: &str) -> Result<String, ScalarProblem> {
    require_select_only(query).map_err(|_| ScalarProblem {
        note: "unsafe_query",
        error_class: None,
    })?;
    let rows = probe.sql(query).map_err(|error| ScalarProblem {
        note: "sql_error",
        error_class: Some(error.class),
    })?;
    let SqlReply::Rows(rows) = rows else {
        return Err(ScalarProblem {
            note: "unexpected_result_shape",
            error_class: None,
        });
    };
    if rows.is_empty() {
        return Err(ScalarProblem {
            note: "empty_result",
            error_class: None,
        });
    }
    if rows.len() != 1 || rows[0].len() != 1 {
        return Err(ScalarProblem {
            note: "ambiguous_result",
            error_class: None,
        });
    }
    rows.into_iter()
        .next()
        .and_then(|row| row.into_iter().next())
        .flatten()
        .ok_or(ScalarProblem {
            note: "null_value",
            error_class: None,
        })
}

fn read_scalar_with_fallback<P: ReadOnlyProbe>(
    probe: &mut P,
    primary: &'static str,
    fallback: Option<&'static str>,
) -> Result<(String, &'static str), ScalarProblem> {
    match read_scalar(probe, primary) {
        Ok(value) => Ok((value, primary)),
        Err(primary_error) => match fallback {
            Some(fallback) => match read_scalar(probe, fallback) {
                Ok(value) => Ok((value, fallback)),
                Err(fallback_error) => Err(fallback_error),
            },
            None => Err(primary_error),
        },
    }
}

fn scalar_check<P: ReadOnlyProbe>(
    probe: &mut P,
    primary: &'static str,
    fallback: Option<&'static str>,
    validate: impl FnOnce(&str) -> bool,
) -> CheckReport {
    match read_scalar_with_fallback(probe, primary, fallback) {
        Ok((value, query)) => {
            let valid = validate(&value);
            CheckReport {
                status: if valid { Status::Pass } else { Status::Unknown },
                value: Some(CheckValue::Text(scrub_and_bound(&value))),
                query: Some(query),
                note: (!valid).then_some("value_failed_form_validation"),
                error_class: None,
            }
        }
        Err(problem) => CheckReport {
            status: Status::Unknown,
            value: None,
            query: None,
            note: Some(problem.note),
            error_class: problem.error_class,
        },
    }
}

fn isolation_is_known(value: &str) -> bool {
    let normalized = value.trim().to_ascii_uppercase().replace([' ', '_'], "-");
    KNOWN_ISOLATIONS.contains(&normalized.as_str())
}

fn flag_is_known(value: &str) -> bool {
    matches!(value.trim(), "0" | "1")
}

fn parse_utc_epoch(value: &str) -> Option<i64> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() != 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |start, end| {
        value
            .get(start..end)
            .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|part| part.parse::<i64>().ok())
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year == 0
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }

    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146_097 + day_of_era - 719_468;
    Some(days_since_epoch * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn round_millis(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

fn clock_check<P, C>(probe: &mut P, clock: &mut C, threshold_s: f64) -> CheckReport
where
    P: ReadOnlyProbe,
    C: FnMut() -> Result<f64, ProbeError>,
{
    let db_utc = match read_scalar(probe, UTC_NOW_QUERY) {
        Ok(value) => value,
        Err(problem) => {
            return CheckReport {
                status: Status::Unknown,
                value: None,
                query: None,
                note: Some(problem.note),
                error_class: problem.error_class,
            };
        }
    };
    let probe_epoch_s = match clock() {
        Ok(value) if value.is_finite() => value,
        Ok(_) => {
            return CheckReport {
                status: Status::Unknown,
                value: None,
                query: None,
                note: Some("clock_unavailable"),
                error_class: None,
            };
        }
        Err(error) => {
            return CheckReport {
                status: Status::Unknown,
                value: None,
                query: None,
                note: Some("clock_unavailable"),
                error_class: Some(error.class),
            };
        }
    };
    let Some(db_epoch) = parse_utc_epoch(&db_utc) else {
        return CheckReport {
            status: Status::Unknown,
            value: Some(CheckValue::Text(scrub_and_bound(&db_utc))),
            query: None,
            note: Some("unparseable_utc_timestamp"),
            error_class: None,
        };
    };
    let probe_epoch_s = round_millis(probe_epoch_s);
    let skew_s = round_millis(db_epoch as f64 - probe_epoch_s);
    CheckReport {
        status: if skew_s.abs() <= threshold_s {
            Status::Pass
        } else {
            Status::Fail
        },
        value: Some(CheckValue::ClockOffset {
            db_utc: scrub_and_bound(db_utc.trim()),
            probe_epoch_s,
            skew_s,
        }),
        query: Some(UTC_NOW_QUERY),
        note: None,
        error_class: None,
    }
}

fn cache_epoch<P: ReadOnlyProbe>(
    probe: &mut P,
    cache_epoch_key: &str,
    cache_epoch_query: Option<&str>,
) -> CacheEpochReport {
    if let Some(query) = cache_epoch_query {
        return match read_scalar(probe, query) {
            Ok(value) => {
                let non_empty = !value.trim().is_empty();
                CacheEpochReport {
                    status: if non_empty {
                        Status::Pass
                    } else {
                        Status::Unknown
                    },
                    source: CacheEpochSource::Sql,
                    value: Some(scrub_and_bound(&value)),
                    note: (!non_empty).then_some("empty_value"),
                    error_class: None,
                }
            }
            Err(problem) => CacheEpochReport {
                status: Status::Unknown,
                source: CacheEpochSource::Sql,
                value: None,
                note: Some(problem.note),
                error_class: problem.error_class,
            },
        };
    }
    if cache_epoch_key.is_empty() {
        return CacheEpochReport {
            status: Status::Skip,
            source: CacheEpochSource::RedisGet,
            value: None,
            note: Some("no_cache_epoch_key_configured"),
            error_class: None,
        };
    }
    if !probe.has_redis() {
        return CacheEpochReport {
            status: Status::Blocked,
            source: CacheEpochSource::RedisGet,
            value: None,
            note: Some("redis_capability_missing"),
            error_class: None,
        };
    }
    let argv = ["GET", cache_epoch_key];
    match probe.redis(&argv) {
        Ok(value) => {
            let value = value.unwrap_or_default();
            let value = value.trim();
            if value.is_empty() || value.eq_ignore_ascii_case("nil") {
                CacheEpochReport {
                    status: Status::Skip,
                    source: CacheEpochSource::RedisGet,
                    value: None,
                    note: Some("cache_epoch_absent"),
                    error_class: None,
                }
            } else {
                CacheEpochReport {
                    status: Status::Pass,
                    source: CacheEpochSource::RedisGet,
                    value: Some(scrub_and_bound(value)),
                    note: None,
                    error_class: None,
                }
            }
        }
        Err(error) => CacheEpochReport {
            status: Status::Unknown,
            source: CacheEpochSource::RedisGet,
            value: None,
            note: Some("redis_error"),
            error_class: Some(error.class),
        },
    }
}

pub fn capture_e4_preconditions<P, C>(
    probe: &mut P,
    nodes: &[&str],
    config: CaptureConfig<'_>,
    mut clock: C,
) -> Result<PreconditionReport, CaptureInputError>
where
    P: ReadOnlyProbe,
    C: FnMut() -> Result<f64, ProbeError>,
{
    if !config.clock_skew_threshold_s.is_finite() || config.clock_skew_threshold_s < 0.0 {
        return Err(CaptureInputError::InvalidThreshold);
    }
    if let Some((index, _)) = nodes.iter().enumerate().find(|(_, node)| node.is_empty()) {
        return Err(CaptureInputError::EmptyNode { index });
    }
    if let Some(query) = config.cache_epoch_query {
        require_select_only(query)?;
    }

    let mut node_reports = Vec::with_capacity(nodes.len());
    for (index, _node) in nodes.iter().enumerate() {
        let checks = NodeChecks {
            transaction_isolation: scalar_check(
                probe,
                ISOLATION_QUERY,
                Some(ISOLATION_FALLBACK_QUERY),
                isolation_is_known,
            ),
            read_only: scalar_check(probe, READ_ONLY_QUERY, None, flag_is_known),
            super_read_only: scalar_check(probe, SUPER_READ_ONLY_QUERY, None, flag_is_known),
            session_time_zone: scalar_check(probe, SESSION_TIME_ZONE_QUERY, None, |value| {
                !value.trim().is_empty()
            }),
            utc_clock_offset: clock_check(probe, &mut clock, config.clock_skew_threshold_s),
        };
        let overall = status_of([
            checks.transaction_isolation.status,
            checks.read_only.status,
            checks.super_read_only.status,
            checks.session_time_zone.status,
            checks.utc_clock_offset.status,
        ]);
        node_reports.push(NodeReport {
            node_key: format!("node-{index}"),
            overall,
            checks,
        });
    }

    let cache_epoch = cache_epoch(probe, config.cache_epoch_key, config.cache_epoch_query);
    let overall = status_of(
        node_reports
            .iter()
            .map(|node| node.overall)
            .chain(std::iter::once(cache_epoch.status)),
    );
    Ok(PreconditionReport {
        kind: "e4_preconditions",
        node_count: node_reports.len(),
        nodes: node_reports,
        cache_epoch,
        overall,
        clock_skew_threshold_s: config.clock_skew_threshold_s,
        limitations: [
            "pooled_connection_primary_route",
            "cache_epoch_rotation_history",
            "fault_matrix",
        ]
        .into_iter()
        .map(|item| Limitation {
            item,
            status: Status::Skip,
        })
        .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const UTC_NOW: &str = "2026-09-19 12:00:00";

    struct FakeProbe {
        sql_replies: BTreeMap<String, Result<SqlReply, ProbeError>>,
        sql_queries: Vec<String>,
        redis_available: bool,
        redis_reply: Result<Option<String>, ProbeError>,
        redis_commands: Vec<Vec<String>>,
    }

    impl FakeProbe {
        fn ready() -> Self {
            let mut probe = Self {
                sql_replies: BTreeMap::new(),
                sql_queries: Vec::new(),
                redis_available: true,
                redis_reply: Ok(Some("550e8400-e29b-41d4-a716-446655440000".to_owned())),
                redis_commands: Vec::new(),
            };
            probe.set_row(ISOLATION_QUERY, "REPEATABLE-READ");
            probe.set_row(READ_ONLY_QUERY, "0");
            probe.set_row(SUPER_READ_ONLY_QUERY, "0");
            probe.set_row(SESSION_TIME_ZONE_QUERY, "+00:00");
            probe.set_row(UTC_NOW_QUERY, UTC_NOW);
            probe
        }

        fn set_row(&mut self, query: &str, value: &str) {
            self.sql_replies.insert(
                query.to_owned(),
                Ok(SqlReply::Rows(vec![vec![Some(value.to_owned())]])),
            );
        }

        fn set_rows(&mut self, query: &str, rows: Vec<Vec<Option<String>>>) {
            self.sql_replies
                .insert(query.to_owned(), Ok(SqlReply::Rows(rows)));
        }

        fn set_error(&mut self, query: &str, error: ProbeError) {
            self.sql_replies.insert(query.to_owned(), Err(error));
        }

        fn clock(&self) -> f64 {
            parse_utc_epoch(UTC_NOW).unwrap() as f64
        }
    }

    impl ReadOnlyProbe for FakeProbe {
        fn sql(&mut self, query: &str) -> Result<SqlReply, ProbeError> {
            self.sql_queries.push(query.to_owned());
            self.sql_replies
                .get(query)
                .cloned()
                .unwrap_or_else(|| Ok(SqlReply::Rows(Vec::new())))
        }

        fn has_redis(&self) -> bool {
            self.redis_available
        }

        fn redis(&mut self, argv: &[&str]) -> Result<Option<String>, ProbeError> {
            self.redis_commands
                .push(argv.iter().map(|arg| (*arg).to_owned()).collect());
            if argv.is_empty() || !READONLY_REDIS_VERBS.contains(&argv[0]) {
                return Err(ProbeError::new("UnsafeCommand", "command rejected"));
            }
            self.redis_reply.clone()
        }
    }

    fn capture(probe: &mut FakeProbe, nodes: &[&str]) -> PreconditionReport {
        let clock = probe.clock();
        capture_e4_preconditions(probe, nodes, CaptureConfig::default(), || Ok(clock)).unwrap()
    }

    #[test]
    fn happy_path_is_select_only_and_reads_only_the_cache_epoch_key() {
        let mut probe = FakeProbe::ready();
        let report = capture(&mut probe, &["writer-a"]);
        assert_eq!(report.kind, "e4_preconditions");
        assert_eq!(report.overall, Status::Pass);
        assert_eq!(report.node_count, 1);
        assert_eq!(report.nodes[0].node_key, "node-0");
        let checks = &report.nodes[0].checks;
        assert_eq!(checks.transaction_isolation.status, Status::Pass);
        assert_eq!(checks.read_only.status, Status::Pass);
        assert_eq!(checks.super_read_only.status, Status::Pass);
        assert_eq!(checks.session_time_zone.status, Status::Pass);
        assert_eq!(checks.utc_clock_offset.status, Status::Pass);
        assert_eq!(
            checks.utc_clock_offset.value,
            Some(CheckValue::ClockOffset {
                db_utc: UTC_NOW.to_owned(),
                probe_epoch_s: probe.clock(),
                skew_s: 0.0,
            })
        );
        assert_eq!(report.cache_epoch.status, Status::Pass);
        assert_eq!(
            report.cache_epoch.value.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert!(probe
            .sql_queries
            .iter()
            .all(|query| require_select_only(query).is_ok()));
        assert_eq!(probe.redis_commands, [["GET", DEFAULT_CACHE_EPOCH_KEY]]);
    }

    #[test]
    fn node_labels_are_replaced_with_stable_aliases() {
        let mut probe = FakeProbe::ready();
        let report = capture(&mut probe, &["n1", "n2"]);
        assert_eq!(report.node_count, 2);
        assert_eq!(
            report
                .nodes
                .iter()
                .map(|node| node.node_key.as_str())
                .collect::<Vec<_>>(),
            ["node-0", "node-1"]
        );
        let output = format!("{report:#?}");
        assert!(!output.contains("n1\""));
        assert!(!output.contains("n2\""));
    }

    #[test]
    fn mysql57_fallback_is_used_after_primary_query_failure() {
        let mut probe = FakeProbe::ready();
        probe.sql_replies.remove(ISOLATION_QUERY);
        probe.set_row(ISOLATION_FALLBACK_QUERY, "REPEATABLE-READ");
        let report = capture(&mut probe, &["node"]);
        let check = &report.nodes[0].checks.transaction_isolation;
        assert_eq!(check.status, Status::Pass);
        assert_eq!(check.query, Some(ISOLATION_FALLBACK_QUERY));
        assert!(probe.sql_queries.contains(&ISOLATION_QUERY.to_owned()));
        assert!(probe
            .sql_queries
            .contains(&ISOLATION_FALLBACK_QUERY.to_owned()));
    }

    #[test]
    fn sql_errors_empty_ambiguous_null_and_unexpected_shapes_stay_unknown() {
        let mut failed = FakeProbe::ready();
        failed.set_error(
            READ_ONLY_QUERY,
            ProbeError::new("RuntimeError", "connect failed db.example.invalid"),
        );
        let report = capture(&mut failed, &["n"]);
        let check = &report.nodes[0].checks.read_only;
        assert_eq!(check.status, Status::Unknown);
        assert_eq!(check.error_class, Some("RuntimeError"));
        let output = format!("{report:#?}");
        assert!(!output.contains("db.example.invalid"));
        assert!(!output.contains("connect failed"));

        let cases = [
            (Vec::new(), "empty_result"),
            (
                vec![vec![Some("0".to_owned())], vec![Some("1".to_owned())]],
                "ambiguous_result",
            ),
            (vec![vec![None]], "null_value"),
        ];
        for (rows, note) in cases {
            let mut probe = FakeProbe::ready();
            probe.set_rows(READ_ONLY_QUERY, rows);
            let report = capture(&mut probe, &["n"]);
            let check = &report.nodes[0].checks.read_only;
            assert_eq!(check.status, Status::Unknown);
            assert_eq!(check.note, Some(note));
        }
        let mut unexpected = FakeProbe::ready();
        unexpected
            .sql_replies
            .insert(READ_ONLY_QUERY.to_owned(), Ok(SqlReply::UnexpectedShape));
        assert_eq!(
            capture(&mut unexpected, &["n"]).nodes[0]
                .checks
                .read_only
                .note,
            Some("unexpected_result_shape")
        );
    }

    #[test]
    fn invalid_isolation_and_clock_skew_fail_closed() {
        let mut invalid = FakeProbe::ready();
        invalid.set_row(ISOLATION_QUERY, "MAGIC-LEVEL");
        let report = capture(&mut invalid, &["n"]);
        assert_eq!(
            report.nodes[0].checks.transaction_isolation.status,
            Status::Unknown
        );

        let mut skewed = FakeProbe::ready();
        let skewed_clock = skewed.clock() + 10.0;
        let report =
            capture_e4_preconditions(&mut skewed, &["n"], CaptureConfig::default(), || {
                Ok(skewed_clock)
            })
            .unwrap();
        assert_eq!(report.nodes[0].checks.utc_clock_offset.status, Status::Fail);
        assert_eq!(report.overall, Status::Fail);
    }

    #[test]
    fn clock_failure_and_fail_status_outrank_missing_redis_capability() {
        let mut probe = FakeProbe::ready();
        probe.redis_available = false;
        let report = capture_e4_preconditions(&mut probe, &["n"], CaptureConfig::default(), || {
            Err(ProbeError::new("RuntimeError", "clock unavailable"))
        })
        .unwrap();
        assert_eq!(
            report.nodes[0].checks.utc_clock_offset.status,
            Status::Unknown
        );
        assert_eq!(report.cache_epoch.status, Status::Blocked);
        assert_eq!(report.overall, Status::Blocked);

        let mut skewed = FakeProbe::ready();
        skewed.redis_available = false;
        let clock = skewed.clock() + 10.0;
        let report =
            capture_e4_preconditions(&mut skewed, &["n"], CaptureConfig::default(), || Ok(clock))
                .unwrap();
        assert_eq!(report.nodes[0].checks.utc_clock_offset.status, Status::Fail);
        assert_eq!(report.cache_epoch.status, Status::Blocked);
        assert_eq!(report.overall, Status::Fail);
    }

    #[test]
    fn cache_epoch_absence_errors_capability_and_sql_source_are_distinct() {
        for reply in [
            Ok(None),
            Ok(Some(String::new())),
            Ok(Some("nil".to_owned())),
        ] {
            let mut probe = FakeProbe::ready();
            probe.redis_reply = reply;
            assert_eq!(capture(&mut probe, &["n"]).cache_epoch.status, Status::Skip);
        }

        let mut errored = FakeProbe::ready();
        errored.redis_reply = Err(ProbeError::new(
            "RuntimeError",
            "redis.example.invalid down",
        ));
        let report = capture(&mut errored, &["n"]);
        assert_eq!(report.cache_epoch.status, Status::Unknown);
        assert_eq!(report.cache_epoch.error_class, Some("RuntimeError"));
        assert!(!format!("{report:#?}").contains("redis.example.invalid"));

        let mut no_redis = FakeProbe::ready();
        no_redis.redis_available = false;
        assert_eq!(
            capture(&mut no_redis, &["n"]).cache_epoch.status,
            Status::Blocked
        );

        let mut via_sql = FakeProbe::ready();
        via_sql.set_row(READ_ONLY_QUERY, "0");
        let clock_value = via_sql.clock();
        let report = capture_e4_preconditions(
            &mut via_sql,
            &["n"],
            CaptureConfig {
                cache_epoch_query: Some(READ_ONLY_QUERY),
                ..CaptureConfig::default()
            },
            || Ok(clock_value),
        )
        .unwrap();
        assert_eq!(report.cache_epoch.status, Status::Pass);
        assert_eq!(report.cache_epoch.source, CacheEpochSource::Sql);
        assert_eq!(report.cache_epoch.value.as_deref(), Some("0"));
        assert!(via_sql.redis_commands.is_empty());

        let mut no_key = FakeProbe::ready();
        let clock_value = no_key.clock();
        let report = capture_e4_preconditions(
            &mut no_key,
            &["n"],
            CaptureConfig {
                cache_epoch_key: "",
                ..CaptureConfig::default()
            },
            || Ok(clock_value),
        )
        .unwrap();
        assert_eq!(report.cache_epoch.status, Status::Skip);
        assert_eq!(report.cache_epoch.source, CacheEpochSource::RedisGet);
        assert!(no_key.redis_commands.is_empty());
    }

    #[test]
    fn clock_timestamp_and_threshold_validation_are_exact_and_fail_closed() {
        for invalid_timestamp in [
            "not a timestamp",
            "2026-02-29 12:00:00",
            "2026-13-01 00:00:00",
            "2026-09-19 24:00:00",
            "2026-09-19 12:00:00 UTC",
        ] {
            let mut probe = FakeProbe::ready();
            probe.set_row(UTC_NOW_QUERY, invalid_timestamp);
            let report = capture(&mut probe, &["n"]);
            assert_eq!(
                report.nodes[0].checks.utc_clock_offset.status,
                Status::Unknown,
                "{invalid_timestamp}"
            );
            assert_eq!(
                report.nodes[0].checks.utc_clock_offset.note,
                Some("unparseable_utc_timestamp")
            );
        }

        let mut probe = FakeProbe::ready();
        let clock = probe.clock() + 2.0;
        let report =
            capture_e4_preconditions(&mut probe, &["n"], CaptureConfig::default(), || Ok(clock))
                .unwrap();
        assert_eq!(report.nodes[0].checks.utc_clock_offset.status, Status::Pass);
        assert_eq!(
            report.nodes[0].checks.utc_clock_offset.value,
            Some(CheckValue::ClockOffset {
                db_utc: UTC_NOW.to_owned(),
                probe_epoch_s: clock,
                skew_s: -2.0,
            })
        );

        let mut probe = FakeProbe::ready();
        for threshold in [-0.1, f64::NAN, f64::INFINITY] {
            assert_eq!(
                capture_e4_preconditions(
                    &mut probe,
                    &["n"],
                    CaptureConfig {
                        clock_skew_threshold_s: threshold,
                        ..CaptureConfig::default()
                    },
                    || Ok(0.0),
                )
                .unwrap_err(),
                CaptureInputError::InvalidThreshold
            );
        }
        assert!(probe.sql_queries.is_empty());
        assert!(probe.redis_commands.is_empty());
    }

    #[test]
    fn unsafe_inputs_are_rejected_before_any_probe_call() {
        let mut probe = FakeProbe::ready();
        assert_eq!(
            capture_e4_preconditions(&mut probe, &["ok", ""], CaptureConfig::default(), || Ok(
                0.0
            ),)
            .unwrap_err(),
            CaptureInputError::EmptyNode { index: 1 }
        );
        assert_eq!(
            capture_e4_preconditions(
                &mut probe,
                &["n"],
                CaptureConfig {
                    cache_epoch_query: Some("DELETE FROM t"),
                    ..CaptureConfig::default()
                },
                || Ok(0.0),
            )
            .unwrap_err(),
            CaptureInputError::UnsafeCacheEpochQuery
        );
        assert_eq!(
            capture_e4_preconditions(
                &mut probe,
                &["n"],
                CaptureConfig {
                    clock_skew_threshold_s: f64::NAN,
                    ..CaptureConfig::default()
                },
                || Ok(0.0),
            )
            .unwrap_err(),
            CaptureInputError::InvalidThreshold
        );
        assert!(probe.sql_queries.is_empty());
        assert!(probe.redis_commands.is_empty());
    }

    #[test]
    fn configured_query_uses_select_guard_and_cache_key_absence_is_skipped() {
        for query in [
            "SELECT 1",
            "/* lead */ SELECT 1",
            "  select 1;  ",
            "-- comment\nSELECT 1",
            "SELECT COUNT(*) FROM authorization_delta_event",
        ] {
            assert_eq!(require_select_only(query), Ok(()));
        }
        for query in [
            "",
            "UPDATE t SET x=1",
            "SET x=1",
            "INSERT INTO t VALUES (1)",
            "DELETE FROM t",
            "SELECT 1; DROP TABLE t",
            "SELECT 1;SELECT 2",
        ] {
            assert_eq!(
                require_select_only(query),
                Err(CaptureInputError::UnsafeCacheEpochQuery)
            );
        }
        let mut probe = FakeProbe::ready();
        let clock_value = probe.clock();
        let report = capture_e4_preconditions(
            &mut probe,
            &["n"],
            CaptureConfig {
                cache_epoch_key: "",
                ..CaptureConfig::default()
            },
            || Ok(clock_value),
        )
        .unwrap();
        assert_eq!(report.cache_epoch.status, Status::Skip);
        assert!(probe.redis_commands.is_empty());
        assert_eq!(READONLY_REDIS_VERBS, ["GET", "LLEN", "PING"]);
    }

    #[test]
    fn hostnames_urls_node_aliases_and_probe_errors_are_not_retained() {
        let mut probe = FakeProbe::ready();
        probe.set_row(SESSION_TIME_ZONE_QUERY, "db01.internal.example.com");
        probe.redis_reply = Ok(Some("redis://cache.example.invalid:6380/0".to_owned()));
        let report = capture(&mut probe, &["node.example.invalid"]);
        let output = format!("{report:#?}");
        for forbidden in [
            "node.example.invalid",
            "cache.example.invalid",
            "example.com",
            "db01.internal",
            "redis://",
        ] {
            assert!(!output.contains(forbidden), "report leaked {forbidden}");
        }
        assert!(output.contains("[redacted-host]"));
        assert!(report
            .limitations
            .iter()
            .all(|limitation| limitation.status == Status::Skip));
    }

    #[test]
    fn stored_probe_values_are_host_scrubbed_and_bounded() {
        let value = format!("{} db.example.invalid {}", "x".repeat(140), "y".repeat(140));
        let stored = scrub_and_bound(&value);
        assert_eq!(stored.chars().count(), MAX_STORED_STRING);
        assert!(!stored.contains("db.example.invalid"));
    }
}
