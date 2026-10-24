use serde::Serialize;

pub const SAMPLE_FIELDS: [&str; 8] = [
    "replicate",
    "concurrency",
    "worker",
    "sequence",
    "outcome",
    "status",
    "latency_ns",
    "latency_ms",
];

const OUTCOMES: [&str; 5] = [
    "success",
    "http_4xx",
    "http_5xx",
    "transport_error",
    "timeout",
];

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StatusValue {
    Empty(String),
    Code(u16),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SampleRow {
    pub replicate: u64,
    pub concurrency: u64,
    pub worker: u64,
    pub sequence: u64,
    pub outcome: String,
    pub status: StatusValue,
    pub latency_ns: u64,
    pub latency_ms: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RequestError {
    HttpStatus(u16),
    Timeout,
    UrlError(Box<RequestError>),
    Other,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OutcomeCounts {
    pub success: u64,
    pub http_4xx: u64,
    pub http_5xx: u64,
    pub transport_error: u64,
    pub timeout: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReplicateSummary {
    pub replicate: u64,
    pub concurrency: u64,
    pub sample_count: u64,
    pub successful_count: u64,
    pub error_count: u64,
    pub elapsed_ns: u64,
    pub throughput_qps: f64,
    pub success_qps: f64,
    pub success_rate: f64,
    pub error_rate: f64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub outcomes: OutcomeCounts,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MeanAndSampleSd {
    pub mean: Option<f64>,
    pub sample_sd: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConcurrencySummary {
    pub concurrency: u64,
    pub replicate_count: usize,
    pub sample_count: u64,
    pub outcomes: OutcomeCounts,
    pub throughput_qps: MeanAndSampleSd,
    pub success_qps: MeanAndSampleSd,
    pub success_rate: MeanAndSampleSd,
    pub error_rate: MeanAndSampleSd,
    pub p50_ms: MeanAndSampleSd,
    pub p95_ms: MeanAndSampleSd,
    pub p99_ms: MeanAndSampleSd,
}

pub fn classify_status(status: Option<u16>) -> &'static str {
    match status {
        Some(200..=399) => "success",
        Some(400..=499) => "http_4xx",
        Some(500..=599) => "http_5xx",
        _ => "transport_error",
    }
}

pub fn classify_exception(error: &RequestError) -> (&'static str, Option<u16>) {
    match error {
        RequestError::HttpStatus(status) => (classify_status(Some(*status)), Some(*status)),
        RequestError::Timeout => ("timeout", None),
        RequestError::UrlError(reason) => classify_exception(reason),
        RequestError::Other => ("transport_error", None),
    }
}

pub fn percentile(values: &[f64], percent: f64) -> Result<Option<f64>, &'static str> {
    if values.is_empty() {
        return Ok(None);
    }
    if !percent.is_finite() || !(0.0..=100.0).contains(&percent) {
        return Err("percent must be between 0 and 100");
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    if ordered.len() == 1 {
        return Ok(Some(ordered[0]));
    }
    let position = (ordered.len() - 1) as f64 * (percent / 100.0);
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        return Ok(Some(ordered[lower]));
    }
    Ok(Some(
        ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower as f64),
    ))
}

pub fn parse_concurrencies(raw: &str) -> Result<Vec<u64>, &'static str> {
    if raw.is_empty() || raw.trim() != raw {
        return Err("concurrency list must not have surrounding whitespace");
    }
    let mut values = Vec::new();
    for part in raw.split(',') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("concurrency values must be positive decimal integers");
        }
        let value = part
            .parse::<u64>()
            .map_err(|_| "concurrency value exceeds the supported integer range")?;
        if value == 0 || values.contains(&value) {
            return Err("concurrency values must be positive and unique");
        }
        values.push(value);
    }
    Ok(values)
}

pub fn sample_row(
    replicate: u64,
    concurrency: u64,
    worker: u64,
    sequence: u64,
    outcome: &str,
    status: Option<u16>,
    latency_ns: u64,
) -> Result<SampleRow, &'static str> {
    let row = SampleRow {
        replicate,
        concurrency,
        worker,
        sequence,
        outcome: outcome.to_owned(),
        status: status.map_or_else(|| StatusValue::Empty(String::new()), StatusValue::Code),
        latency_ns,
        latency_ms: format!("{:.6}", latency_ns as f64 / 1_000_000.0),
    };
    validate_sample_row(&row)?;
    Ok(row)
}

pub fn validate_sample_row(row: &SampleRow) -> Result<(), &'static str> {
    if !OUTCOMES.contains(&row.outcome.as_str()) {
        return Err("unknown sample outcome");
    }
    if [row.replicate, row.concurrency, row.worker, row.sequence]
        .into_iter()
        .any(|value| value == 0)
    {
        return Err("sample identifiers and concurrency must be positive");
    }
    Ok(())
}

fn outcome_counts(rows: &[SampleRow]) -> Result<OutcomeCounts, &'static str> {
    let mut counts = OutcomeCounts::default();
    for row in rows {
        validate_sample_row(row)?;
        match row.outcome.as_str() {
            "success" => counts.success += 1,
            "http_4xx" => counts.http_4xx += 1,
            "http_5xx" => counts.http_5xx += 1,
            "transport_error" => counts.transport_error += 1,
            "timeout" => counts.timeout += 1,
            _ => unreachable!("sample outcome was validated"),
        }
    }
    Ok(counts)
}

pub fn replicate_summary(
    rows: &[SampleRow],
    replicate: u64,
    concurrency: u64,
    elapsed_ns: u64,
) -> Result<ReplicateSummary, &'static str> {
    let outcomes = outcome_counts(rows)?;
    let sample_count = rows.len() as u64;
    let successful_count = outcomes.success;
    let success_rate = if sample_count == 0 {
        0.0
    } else {
        successful_count as f64 / sample_count as f64
    };
    let elapsed_seconds = elapsed_ns as f64 / 1_000_000_000.0;
    let latencies_ms = rows
        .iter()
        .map(|row| row.latency_ns as f64 / 1_000_000.0)
        .collect::<Vec<_>>();
    Ok(ReplicateSummary {
        replicate,
        concurrency,
        sample_count,
        successful_count,
        error_count: sample_count - successful_count,
        elapsed_ns,
        throughput_qps: if elapsed_seconds > 0.0 {
            sample_count as f64 / elapsed_seconds
        } else {
            0.0
        },
        success_qps: if elapsed_seconds > 0.0 {
            successful_count as f64 / elapsed_seconds
        } else {
            0.0
        },
        success_rate,
        error_rate: 1.0 - success_rate,
        p50_ms: percentile(&latencies_ms, 50.0)?,
        p95_ms: percentile(&latencies_ms, 95.0)?,
        p99_ms: percentile(&latencies_ms, 99.0)?,
        outcomes,
    })
}

fn mean_and_sample_sd(values: &[f64]) -> MeanAndSampleSd {
    if values.is_empty() {
        return MeanAndSampleSd {
            mean: None,
            sample_sd: None,
        };
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let sample_sd = if values.len() == 1 {
        0.0
    } else {
        let squared_deviations = values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>();
        (squared_deviations / (values.len() - 1) as f64).sqrt()
    };
    MeanAndSampleSd {
        mean: Some(mean),
        sample_sd: Some(sample_sd),
    }
}

pub fn concurrency_summary(
    replicates: &[ReplicateSummary],
    concurrency: u64,
) -> ConcurrencySummary {
    let mut outcomes = OutcomeCounts::default();
    for replicate in replicates {
        outcomes.success += replicate.outcomes.success;
        outcomes.http_4xx += replicate.outcomes.http_4xx;
        outcomes.http_5xx += replicate.outcomes.http_5xx;
        outcomes.transport_error += replicate.outcomes.transport_error;
        outcomes.timeout += replicate.outcomes.timeout;
    }
    let metric = |select: fn(&ReplicateSummary) -> Option<f64>| {
        let values = replicates.iter().filter_map(select).collect::<Vec<_>>();
        mean_and_sample_sd(&values)
    };
    ConcurrencySummary {
        concurrency,
        replicate_count: replicates.len(),
        sample_count: replicates.iter().map(|row| row.sample_count).sum(),
        outcomes,
        throughput_qps: metric(|row| Some(row.throughput_qps)),
        success_qps: metric(|row| Some(row.success_qps)),
        success_rate: metric(|row| Some(row.success_rate)),
        error_rate: metric(|row| Some(row.error_rate)),
        p50_ms: metric(|row| row.p50_ms),
        p95_ms: metric(|row| row.p95_ms),
        p99_ms: metric(|row| row.p99_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(outcome: &str, status: u16, latency_ns: u64, worker: u64) -> SampleRow {
        sample_row(1, 2, worker, 1, outcome, Some(status), latency_ns).unwrap()
    }

    struct ReplicateMetrics {
        throughput_qps: f64,
        success_qps: f64,
        success_rate: f64,
        error_rate: f64,
        p50_ms: f64,
        p95_ms: f64,
        p99_ms: f64,
        sample_count: u64,
    }

    fn replicate(metrics: ReplicateMetrics, outcomes: OutcomeCounts) -> ReplicateSummary {
        ReplicateSummary {
            replicate: 1,
            concurrency: 2,
            sample_count: metrics.sample_count,
            successful_count: outcomes.success,
            error_count: metrics.sample_count - outcomes.success,
            elapsed_ns: 1_000_000_000,
            throughput_qps: metrics.throughput_qps,
            success_qps: metrics.success_qps,
            success_rate: metrics.success_rate,
            error_rate: metrics.error_rate,
            p50_ms: Some(metrics.p50_ms),
            p95_ms: Some(metrics.p95_ms),
            p99_ms: Some(metrics.p99_ms),
            outcomes,
        }
    }

    #[test]
    fn test_status_classification_is_mutually_exclusive() {
        for (status, expected) in [
            (Some(200), "success"),
            (Some(302), "success"),
            (Some(400), "http_4xx"),
            (Some(499), "http_4xx"),
            (Some(500), "http_5xx"),
            (Some(599), "http_5xx"),
            (Some(0), "transport_error"),
            (None, "transport_error"),
        ] {
            assert_eq!(classify_status(status), expected);
        }
    }

    #[test]
    fn test_exception_classification_distinguishes_timeout() {
        assert_eq!(
            classify_exception(&RequestError::Timeout),
            ("timeout", None)
        );
        assert_eq!(
            classify_exception(&RequestError::UrlError(Box::new(RequestError::Timeout))),
            ("timeout", None)
        );
        assert_eq!(
            classify_exception(&RequestError::HttpStatus(404)),
            ("http_4xx", Some(404))
        );
        assert_eq!(
            classify_exception(&RequestError::UrlError(Box::new(RequestError::Other))),
            ("transport_error", None)
        );
    }

    #[test]
    fn test_percentiles_are_interpolated() {
        let values = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile(&values, 0.0).unwrap(), Some(1.0));
        assert_eq!(percentile(&values, 50.0).unwrap(), Some(2.5));
        assert!((percentile(&values, 95.0).unwrap().unwrap() - 3.85).abs() < 1e-12);
        assert_eq!(percentile(&values, 100.0).unwrap(), Some(4.0));
    }

    #[test]
    fn test_empty_percentile_is_none() {
        assert_eq!(percentile(&[], 50.0).unwrap(), None);
        assert_eq!(percentile(&[], 101.0).unwrap(), None);
    }

    #[test]
    fn test_percentile_rejects_invalid_range() {
        assert!(percentile(&[1.0], 101.0).is_err());
        assert!(percentile(&[1.0], f64::NAN).is_err());
    }

    #[test]
    fn test_sample_row_matches_declared_schema() {
        let row = sample_row(1, 4, 2, 3, "success", Some(200), 2_500_000).unwrap();
        assert_eq!(
            SAMPLE_FIELDS,
            [
                "replicate",
                "concurrency",
                "worker",
                "sequence",
                "outcome",
                "status",
                "latency_ns",
                "latency_ms"
            ]
        );
        let serialized = serde_json::to_string(&row).unwrap();
        let positions = SAMPLE_FIELDS
            .iter()
            .map(|field| serialized.find(&format!("\"{field}\"")).unwrap())
            .collect::<Vec<_>>();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(row.latency_ms, "2.500000");
        validate_sample_row(&row).unwrap();
    }

    #[test]
    fn test_schema_rejects_invalid_outcome() {
        let mut row = sample("success", 200, 1, 1);
        row.outcome = "unknown".into();
        assert_eq!(validate_sample_row(&row), Err("unknown sample outcome"));
    }

    #[test]
    fn test_concurrency_parser_requires_unique_positive_values() {
        assert_eq!(parse_concurrencies("1,4,8").unwrap(), vec![1, 4, 8]);
        for value in ["", "1, 4", "1,1", "0,4", "a,4", " 1,4"] {
            assert!(parse_concurrencies(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn test_replicate_summary_has_rate_and_success_throughput_metrics() {
        let rows = vec![
            sample("success", 200, 1_000_000, 1),
            sample("http_5xx", 503, 3_000_000, 2),
        ];
        let summary = replicate_summary(&rows, 1, 2, 1_000_000_000).unwrap();
        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.successful_count, 1);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.throughput_qps, 2.0);
        assert_eq!(summary.success_qps, 1.0);
        assert_eq!(summary.success_rate, 0.5);
        assert_eq!(summary.error_rate, 0.5);
        assert_eq!(summary.outcomes.success, 1);
        assert_eq!(summary.outcomes.http_5xx, 1);
        assert_eq!(summary.p50_ms, Some(2.0));
    }

    #[test]
    fn test_concurrency_summary_uses_replicate_level_metrics() {
        let first = replicate(
            ReplicateMetrics {
                throughput_qps: 4.0,
                success_qps: 3.0,
                success_rate: 0.75,
                error_rate: 0.25,
                p50_ms: 1.0,
                p95_ms: 2.0,
                p99_ms: 3.0,
                sample_count: 4,
            },
            OutcomeCounts {
                success: 3,
                http_4xx: 1,
                ..OutcomeCounts::default()
            },
        );
        let second = replicate(
            ReplicateMetrics {
                throughput_qps: 6.0,
                success_qps: 6.0,
                success_rate: 1.0,
                error_rate: 0.0,
                p50_ms: 2.0,
                p95_ms: 4.0,
                p99_ms: 5.0,
                sample_count: 6,
            },
            OutcomeCounts {
                success: 6,
                ..OutcomeCounts::default()
            },
        );
        let summary = concurrency_summary(&[first, second], 2);
        assert_eq!(summary.throughput_qps.mean, Some(5.0));
        assert_eq!(summary.success_qps.mean, Some(4.5));
        assert_eq!(summary.success_rate.mean, Some(0.875));
        assert_eq!(summary.error_rate.mean, Some(0.125));
        assert_eq!(summary.sample_count, 10);
        assert_eq!(summary.replicate_count, 2);
        assert_eq!(summary.outcomes.http_4xx, 1);
    }
}
