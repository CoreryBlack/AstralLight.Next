#![recursion_limit = "256"]

//! Standalone signed HTTP load generator for native AstralLight deployments.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

mod measurement;
use measurement::{
    run_closed_loop, run_count, run_open_loop, MeasurementBoundary, RequestOutcome, RequestSample,
    ResourceSample, Stats,
};

type HmacSha256 = Hmac<Sha256>;

const USAGE: &str = "\
loadgen — AstralLight HMAC v3 压测客户端（GIL-free）

用法:
  loadgen [选项]

选项:
      --url <URL>             目标 base url（默认 http://127.0.0.1:9005）
      --path <PATH>           请求路径（默认 /main/api/v1/rule-sets/9071/entries）
      --method <M>            GET|POST|PUT|DELETE（默认 GET）
      --body <BODY>           POST/PUT 请求体
  -c, --concurrency <N>       closed-loop 并发数（默认 1）
  -d, --duration <SEC>        测量时长（默认 20）
  -n, --count <N>             总请求数（>0 时优先于 duration）
      --warmup <N>            预热请求数（不计入测量）
      --rate <RPS>            offered open-loop 速率（0 = closed-loop）
      --max-inflight <N>      open-loop 在途上限（默认并发数）
      --drain-timeout-ms <MS> 测量后最大排空等待（默认 30000）
      --threads <N>           Tokio worker 数（默认 1）
      --timeout-ms <MS>       单请求超时（默认 10000）
      --max-errors <N>        错误数停止阈值（默认不限）
      --stop-at-error-limit   达阈值停止派发、排空并保留测点
      --run-id <ID>           测量运行 ID（也是请求 ID 的确定性种子）
      --p99-slo-ms <MS>       p99 延迟上限 SLO（容量判定必填）
      --error-rate-slo <F>    错误率上限 SLO（容量判定必填）
      --output-file <PATH>    JSON artifact；目标必须不存在
      --hmac-secret <S>       HMAC 密钥（缺省读 LOADGEN_HMAC_SECRET）
      --prefix <S>            签名前缀（默认 astral-gateway-v3）
      --user-id <ID>          平台用户 id（默认 9031）
      --icard <ID>            identity card id（默认 9041）
      --card <ID>             user card id（默认 9061）
      --domain <ID>           domain id（默认 9011）
      --tenant <ID>           tenant id（默认 9001）
      --output <MODE>         text|json（默认 text）
  -h, --help                  帮助
";

#[derive(Debug, Clone)]
struct Ids {
    user: String,
    icard: String,
    card: String,
    domain: String,
    tenant: String,
}

#[derive(Debug)]
struct Args {
    url: String,
    path: String,
    method: String,
    body: Option<String>,
    concurrency: usize,
    duration: f64,
    count: u64,
    warmup: u64,
    rate: f64,
    max_in_flight: usize,
    drain_timeout_ms: u64,
    max_errors: u64,
    stop_at_error_limit: bool,
    run_id: Option<String>,
    p99_slo_ms: Option<f64>,
    error_rate_slo: Option<f64>,
    output_file: Option<String>,
    threads: usize,
    timeout_ms: u64,
    secret: String,
    prefix: String,
    ids: Ids,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|arg| arg == "-h" || arg == "--help") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    let mut url = String::from("http://127.0.0.1:9005");
    let mut path = String::from("/main/api/v1/rule-sets/9071/entries");
    let mut method = String::from("GET");
    let mut body = None;
    let mut concurrency = 1usize;
    let mut duration: f64 = 20.0;
    let mut count = 0;
    let mut warmup = 0;
    let mut rate: f64 = 0.0;
    let mut max_in_flight = None;
    let mut drain_timeout_ms = 30_000;
    let mut max_errors = 0;
    let mut stop_at_error_limit = false;
    let mut run_id = None;
    let mut p99_slo_ms = None;
    let mut error_rate_slo = None;
    let mut output_file = None;
    let mut threads = 1usize;
    let mut timeout_ms = 10_000;
    let mut secret = String::new();
    let mut prefix = String::from("astral-gateway-v3");
    let mut user = String::from("9031");
    let mut icard = String::from("9041");
    let mut card = String::from("9061");
    let mut domain = String::from("9011");
    let mut tenant = String::from("9001");
    let mut json_output = false;

    let mut index = 0;
    while index < argv.len() {
        let flag = argv[index].as_str();
        let mut next = || -> Result<String, String> {
            index += 1;
            argv.get(index)
                .cloned()
                .ok_or_else(|| format!("缺少 {flag} 的值"))
        };
        match flag {
            "--url" => url = next()?,
            "--path" => path = next()?,
            "--method" => method = next()?.to_uppercase(),
            "--body" => body = Some(next()?),
            "-c" | "--concurrency" => {
                concurrency = next()?
                    .parse()
                    .map_err(|error| format!("--concurrency: {error}"))?
            }
            "-d" | "--duration" => {
                duration = next()?
                    .parse()
                    .map_err(|error| format!("--duration: {error}"))?
            }
            "-n" | "--count" => {
                count = next()?
                    .parse()
                    .map_err(|error| format!("--count: {error}"))?
            }
            "--warmup" => {
                warmup = next()?
                    .parse()
                    .map_err(|error| format!("--warmup: {error}"))?
            }
            "--rate" => {
                rate = next()?
                    .parse()
                    .map_err(|error| format!("--rate: {error}"))?
            }
            "--max-inflight" => {
                max_in_flight = Some(
                    next()?
                        .parse()
                        .map_err(|error| format!("--max-inflight: {error}"))?,
                )
            }
            "--drain-timeout-ms" => {
                drain_timeout_ms = next()?
                    .parse()
                    .map_err(|error| format!("--drain-timeout-ms: {error}"))?
            }
            "--max-errors" => {
                max_errors = next()?
                    .parse()
                    .map_err(|error| format!("--max-errors: {error}"))?
            }
            "--stop-at-error-limit" => stop_at_error_limit = true,
            "--run-id" => run_id = Some(next()?),
            "--p99-slo-ms" => {
                p99_slo_ms = Some(
                    next()?
                        .parse()
                        .map_err(|error| format!("--p99-slo-ms: {error}"))?,
                )
            }
            "--error-rate-slo" => {
                error_rate_slo = Some(
                    next()?
                        .parse()
                        .map_err(|error| format!("--error-rate-slo: {error}"))?,
                )
            }
            "--output-file" => output_file = Some(next()?),
            "--threads" => {
                threads = next()?
                    .parse()
                    .map_err(|error| format!("--threads: {error}"))?
            }
            "--timeout-ms" => {
                timeout_ms = next()?
                    .parse()
                    .map_err(|error| format!("--timeout-ms: {error}"))?
            }
            "--hmac-secret" => secret = next()?,
            "--prefix" => prefix = next()?,
            "--user-id" => user = next()?,
            "--icard" => icard = next()?,
            "--card" => card = next()?,
            "--domain" => domain = next()?,
            "--tenant" => tenant = next()?,
            "--output" => {
                let mode = next()?;
                if !matches!(mode.to_ascii_lowercase().as_str(), "text" | "json") {
                    return Err("--output 必须是 text 或 json".into());
                }
                json_output = mode.eq_ignore_ascii_case("json");
            }
            other => return Err(format!("未知参数 {other}（--help 查看用法）")),
        }
        index += 1;
    }

    if secret.is_empty() {
        secret = std::env::var("LOADGEN_HMAC_SECRET").unwrap_or_default();
    }
    if secret.is_empty() {
        return Err("缺少 HMAC 密钥：--hmac-secret 或环境变量 LOADGEN_HMAC_SECRET".into());
    }
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
        return Err(format!("不支持的 method: {method}"));
    }
    if !duration.is_finite() || duration <= 0.0 {
        return Err("--duration 必须是有限正数".into());
    }
    if !rate.is_finite() || !(0.0..=1_000_000.0).contains(&rate) {
        return Err("--rate 必须在 0 到 1000000 之间".into());
    }
    if concurrency == 0 || concurrency > 1_000_000 {
        return Err("--concurrency 必须在 1 到 1000000 之间".into());
    }
    if threads == 0 || threads > 256 {
        return Err("--threads 必须在 1 到 256 之间".into());
    }
    if max_in_flight.is_some_and(|limit| limit == 0 || limit > 1_000_000) {
        return Err("--max-inflight 必须在 1 到 1000000 之间".into());
    }
    if timeout_ms == 0 || drain_timeout_ms == 0 {
        return Err("请求和 drain timeout 必须大于 0".into());
    }
    if !stop_at_error_limit && max_errors > 0 {
        return Err("--max-errors 需要同时指定 --stop-at-error-limit".into());
    }
    if p99_slo_ms.is_some_and(|value: f64| !value.is_finite() || value <= 0.0) {
        return Err("--p99-slo-ms 必须是有限正数".into());
    }
    if error_rate_slo.is_some_and(|value: f64| !value.is_finite() || !(0.0..=1.0).contains(&value))
    {
        return Err("--error-rate-slo 必须在 0 到 1 之间".into());
    }
    if p99_slo_ms.is_some() != error_rate_slo.is_some() {
        return Err("--p99-slo-ms 与 --error-rate-slo 必须同时提供".into());
    }
    if run_id.as_ref().is_some_and(|value| value.is_empty()) {
        return Err("--run-id 不得为空".into());
    }

    Ok(Args {
        url: url.trim_end_matches('/').to_owned(),
        path,
        method,
        body,
        concurrency,
        duration,
        count,
        warmup,
        rate,
        max_in_flight: max_in_flight.unwrap_or(concurrency),
        drain_timeout_ms,
        max_errors,
        stop_at_error_limit,
        run_id,
        p99_slo_ms,
        error_rate_slo,
        output_file,
        threads,
        timeout_ms,
        secret,
        prefix,
        ids: Ids {
            user,
            icard,
            card,
            domain,
            tenant,
        },
        json: json_output,
    })
}

fn sanitized_target(value: &str) -> String {
    let Some((scheme, authority_and_path)) = value.split_once("://") else {
        return "invalid_url".to_owned();
    };
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if scheme.is_empty() || host.is_empty() {
        "invalid_url".to_owned()
    } else {
        format!("{scheme}://{host}")
    }
}

fn sanitized_path(value: &str) -> &str {
    value.split(['?', '#']).next().unwrap_or_default()
}

fn sanitize_hostname(host: String) -> String {
    host.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':' | '[' | ']')
            {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn sample_process_resources(
    boundary: MeasurementBoundary,
    requested_at: Instant,
) -> ResourceSample {
    let sample_started_at = Instant::now();
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned());
    let status = fs::read_to_string("/proc/self/status").ok();
    let status_value = |key: &str| -> Option<u64> {
        status.as_ref()?.lines().find_map(|line| {
            let value = line.strip_prefix(key)?.split_whitespace().next()?;
            value.parse::<u64>().ok()
        })
    };
    let status_text = |key: &str| -> Option<String> {
        status.as_ref()?.lines().find_map(|line| {
            let value = line.strip_prefix(key)?.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
    };
    let cpu_ticks = fs::read_to_string("/proc/self/stat")
        .ok()
        .as_deref()
        .and_then(process_cpu_ticks);
    let cpu_stat = fs::read_to_string("/sys/fs/cgroup/cpu.stat").ok();
    let cgroup_value = |key: &str| -> Option<u64> {
        cpu_stat.as_ref()?.lines().find_map(|line| {
            let (field, value) = line.split_once(char::is_whitespace)?;
            (field == key)
                .then(|| value.trim().parse::<u64>().ok())
                .flatten()
        })
    };
    let cpu_quota = fs::read_to_string("/sys/fs/cgroup/cpu.max")
        .ok()
        .map(|value| value.trim().to_owned());
    let sampled_at = Instant::now();
    ResourceSample {
        requested_at: Some(requested_at),
        sample_started_at: Some(sample_started_at),
        sampled_at: Some(sampled_at),
        details: json!({
            "boundary": match boundary {
                MeasurementBoundary::Start => "start",
                MeasurementBoundary::End => "end",
            },
            "host": sanitize_hostname(host),
            "pid": std::process::id(),
            "cpu_user_system_ticks": cpu_ticks,
            "memory_rss_kib": status_value("VmRSS:"),
            "cpu_set": status_text("Cpus_allowed_list:"),
            "cpu_quota": cpu_quota,
            "cpu_throttled_periods": cgroup_value("nr_throttled"),
            "cpu_throttled_usec": cgroup_value("throttled_usec"),
        }),
    }
}

fn process_cpu_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let mut fields = stat.get(close + 2..)?.split_whitespace();
    let user = fields.nth(11)?.parse::<u64>().ok()?;
    let system = fields.next()?.parse::<u64>().ok()?;
    user.checked_add(system)
}

fn signed_offset_ns(origin: Instant, at: Option<Instant>) -> Option<i128> {
    let at = at?;
    if at >= origin {
        i128::try_from(at.duration_since(origin).as_nanos()).ok()
    } else {
        i128::try_from(origin.duration_since(at).as_nanos())
            .ok()
            .map(|offset| -offset)
    }
}

const RESOURCE_ALIGNMENT_TOLERANCE_NS: i128 = 1_000_000;

fn resource_sample_is_aligned(sample: &ResourceSample, boundary: Instant) -> bool {
    let (Some(requested_at), Some(started_at), Some(sampled_at)) = (
        sample.requested_at,
        sample.sample_started_at,
        sample.sampled_at,
    ) else {
        return false;
    };
    started_at >= requested_at
        && sampled_at >= started_at
        && [requested_at, started_at, sampled_at]
            .into_iter()
            .all(|at| {
                signed_offset_ns(boundary, Some(at)).is_some_and(|offset| {
                    (-RESOURCE_ALIGNMENT_TOLERANCE_NS..=RESOURCE_ALIGNMENT_TOLERANCE_NS)
                        .contains(&offset)
                })
            })
}

fn resource_sample_report(
    sample: &ResourceSample,
    measurement_start: Instant,
    boundary: Instant,
) -> Value {
    if sample.requested_at.is_none()
        && sample.sample_started_at.is_none()
        && sample.sampled_at.is_none()
        && sample.details.is_null()
    {
        return Value::Null;
    }
    json!({
        "requested_offset_from_measurement_start_ns": signed_offset_ns(measurement_start, sample.requested_at),
        "sample_started_offset_from_measurement_start_ns": signed_offset_ns(measurement_start, sample.sample_started_at),
        "sampled_offset_from_measurement_start_ns": signed_offset_ns(measurement_start, sample.sampled_at),
        "requested_offset_from_boundary_ns": signed_offset_ns(boundary, sample.requested_at),
        "sample_started_offset_from_boundary_ns": signed_offset_ns(boundary, sample.sample_started_at),
        "sampled_offset_from_boundary_ns": signed_offset_ns(boundary, sample.sampled_at),
        "sampling_duration_ns": sample.sample_started_at.zip(sample.sampled_at).map(|(started, sampled)| sampled.saturating_duration_since(started).as_nanos()),
        "aligned_within_1ms": resource_sample_is_aligned(sample, boundary),
        "details": sample.details,
    })
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

fn sign(
    secret: &str,
    prefix: &str,
    method: &str,
    path: &str,
    ids: &Ids,
    timestamp: &str,
) -> String {
    let payload = [
        prefix,
        method,
        path,
        ids.user.as_str(),
        "PLATFORM_USER",
        "",
        ids.icard.as_str(),
        ids.card.as_str(),
        ids.domain.as_str(),
        ids.tenant.as_str(),
        "",
        "",
        "",
        "",
        timestamp,
    ]
    .join("\n");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    hex(&mac.finalize().into_bytes())
}

fn request_id_seed(run_seed: &str) -> u64 {
    run_seed
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

fn deterministic_request_id(seed: u64, sequence: u64) -> String {
    let sequence = sequence & 0x3fff_ffff_ffff_ffff;
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        seed as u32,
        (seed >> 32) as u16,
        (seed >> 48) as u16 & 0x0fff,
        0x8000 | ((sequence >> 48) as u16 & 0x3fff),
        sequence & 0x0000_ffff_ffff_ffff,
    )
}

#[derive(Clone)]
struct Ctx {
    client: reqwest::Client,
    base: Arc<str>,
    path: Arc<str>,
    method: Arc<str>,
    body: Option<Arc<str>>,
    secret: Arc<str>,
    prefix: Arc<str>,
    ids: Arc<Ids>,
    request_id_seed: u64,
}

async fn one_request(ctx: Ctx, due: Instant, sequence: u64) -> RequestSample {
    let task_started = Instant::now();
    let path_no_query = ctx.path.split('?').next().unwrap_or(ctx.path.as_ref());
    let timestamp = now_millis().to_string();
    let signature = sign(
        &ctx.secret,
        &ctx.prefix,
        &ctx.method,
        path_no_query,
        &ctx.ids,
        &timestamp,
    );
    let request_id = deterministic_request_id(ctx.request_id_seed, sequence);
    let url = format!("{}{}", ctx.base, ctx.path);
    let mut request = match ctx.method.as_ref() {
        "POST" => ctx.client.post(&url),
        "PUT" => ctx.client.put(&url),
        "DELETE" => ctx.client.delete(&url),
        _ => ctx.client.get(&url),
    };
    request = request
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .header("x-user-id", &*ctx.ids.user)
        .header("x-principal-kind", "PLATFORM_USER")
        .header("x-identity-card-id", &*ctx.ids.icard)
        .header("x-user-card-id", &*ctx.ids.card)
        .header("x-user-card-domain-id", &*ctx.ids.domain)
        .header("x-user-card-tenant-id", &*ctx.ids.tenant)
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", &timestamp)
        .header("x-gateway-signature", signature);
    if let Some(body) = &ctx.body {
        request = request.body(body.to_string());
    }
    let request_started = Instant::now();
    let outcome = match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            match response.bytes().await {
                Ok(_) => RequestOutcome::Http(status),
                Err(error) if error.is_timeout() => RequestOutcome::Timeout,
                Err(_) => RequestOutcome::Transport,
            }
        }
        Err(error) if error.is_timeout() => RequestOutcome::Timeout,
        Err(_) => RequestOutcome::Transport,
    };
    let completed_at = Instant::now();
    RequestSample::new(outcome, due, task_started, request_started, completed_at)
}

fn percent(histogram: &measurement::Histogram, percentile: f64) -> Option<u64> {
    histogram.percentile_ns(percentile)
}

fn serialize_report(
    args: &Args,
    stats: &Stats,
    run_id: &str,
    mode: &str,
    started_at_unix_ms: u128,
) -> Value {
    let cohort_results_accounted = stats.measurement_cohort_results_accounted();
    let cohort_latency_complete = stats.measurement_cohort_latency_results_complete();
    let request_results_complete = stats.request_results_complete();
    let latency_population_complete = if mode == "fixed_count" {
        stats.request_latency_results_complete()
    } else {
        cohort_latency_complete
    };
    let p99 = latency_population_complete
        .then(|| percent(&stats.latency, 99.0))
        .flatten();
    let request_error_rate = stats.request_error_rate();
    let measurement_cohort_error_rate = stats.measurement_cohort_error_rate();
    let measurement_cohort_error_rate_ci95 = stats.measurement_cohort_error_rate_ci95();
    let request_error_rate_ci95 = stats.request_error_rate_ci95();
    let slo_error_rate_ci95 = if mode == "fixed_count" {
        request_error_rate_ci95
    } else {
        measurement_cohort_error_rate_ci95
    };
    let p99_ci95 = latency_population_complete
        .then(|| stats.latency.percentile_ci95_ns(99.0))
        .flatten();
    let p99_ci95_relative_half_width = latency_population_complete
        .then(|| stats.latency.percentile_ci95_relative_half_width(99.0))
        .flatten();
    let loadgen_underrun_rate = stats.loadgen_underrun_rate();
    let loadgen_underrun_rate_ci95 = stats.loadgen_underrun_rate_ci95();
    let error_rate_slo_decision = args.error_rate_slo.map(|limit| {
        slo_error_rate_ci95
            .map(|(lower, upper)| {
                if upper <= limit {
                    "PASS"
                } else if lower > limit {
                    "FAIL"
                } else {
                    "UNKNOWN"
                }
            })
            .unwrap_or("UNKNOWN")
    });
    let p99_slo_decision = if !latency_population_complete {
        args.p99_slo_ms.map(|_| "UNKNOWN")
    } else {
        args.p99_slo_ms
            .zip(p99_ci95)
            .map(|(limit_ms, (lower, upper))| {
                let limit_ns = limit_ms * 1_000_000.0;
                if upper as f64 <= limit_ns {
                    "PASS"
                } else if lower as f64 > limit_ns {
                    "FAIL"
                } else {
                    "UNKNOWN"
                }
            })
    };
    let p99_precision_met =
        p99_ci95_relative_half_width.is_some_and(|half_width| half_width <= 0.02);
    let selected_population_accounted = if mode == "fixed_count" {
        request_results_complete
    } else {
        cohort_results_accounted
    };
    let run_measurement_status = if args.p99_slo_ms.is_none() || stats.scheduled == 0 {
        "DATA_ONLY"
    } else if !stats.accounting_ok()
        || !request_results_complete
        || !selected_population_accounted
        || stats.stop_reason != "normal"
    {
        "UNKNOWN_ACCOUNTING_OR_DRAIN"
    } else if stats.loadgen_underrun_count() > 0 {
        "UNKNOWN_LOADGEN_UNDERRUN"
    } else if !latency_population_complete {
        "UNKNOWN_COHORT_LATENCY_INCOMPLETE"
    } else if mode != "open_loop" {
        "NON_OPEN_LOOP_DIAGNOSTIC_ONLY"
    } else if p99_slo_decision == Some("FAIL") || error_rate_slo_decision == Some("FAIL") {
        "FAIL_CONFIDENT_SINGLE_RUN_SLO"
    } else if p99_slo_decision != Some("PASS") || error_rate_slo_decision != Some("PASS") {
        "UNKNOWN_SLO_CONFIDENCE_INTERVAL_CROSSES_LIMIT"
    } else if !p99_precision_met {
        "UNKNOWN_WITHIN_RUN_P99_CI_NOT_WITHIN_2PCT"
    } else {
        "PASS_SINGLE_RUN_SLO"
    };
    let slo_population = match mode {
        "open_loop" => "measurement_due_at_cohort_including_drain_completions_excluding_warmup",
        "fixed_count" => "fixed_count_requests_including_drain_completions_excluding_warmup",
        _ => "closed_loop_requests_started_in_measurement_including_drain_completions_excluding_warmup",
    };
    let capacity_status = "UNKNOWN_REQUIRES_REPEATED_RUN_CI_AND_SUT_EVIDENCE";
    let binary_sha256 = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| {
            use sha2::Digest;
            format!("{:x}", Sha256::digest(bytes))
        });
    let mut codes = serde_json::Map::new();
    for (code, count) in stats.codes.iter().enumerate() {
        if *count > 0 {
            codes.insert(code.to_string(), json!(count));
        }
    }
    let latency_buckets = stats
        .latency
        .nonempty_buckets()
        .map(|(upper_ns, count)| json!({"upper_bound_ns": upper_ns, "count": count}))
        .collect::<Vec<_>>();
    let queue_wait_buckets = stats
        .queue_wait
        .nonempty_buckets()
        .map(|(upper_ns, count)| json!({"upper_bound_ns": upper_ns, "count": count}))
        .collect::<Vec<_>>();
    let start_boundary = stats.measurement_start;
    let end_boundary = stats.measurement_end;
    let start_sampling_aligned = resource_sample_is_aligned(&stats.resource_start, start_boundary);
    let end_sampling_aligned = resource_sample_is_aligned(&stats.resource_end, end_boundary);
    let time_buckets = stats
        .buckets
        .iter()
        .map(|bucket| {
            json!({
                "start_ns": bucket.start_ns,
                "end_ns": bucket.end_ns,
                "active_measurement_window": bucket.start_ns < stats.measurement_duration().as_nanos() as u64,
                "scheduled": bucket.scheduled,
                "started": bucket.started,
                "missed": bucket.missed,
                "dropped": bucket.dropped,
                "aborted": bucket.aborted,
                "completed": bucket.completed,
                "ok": bucket.ok,
                "http_fail": bucket.http_fail,
                "transport_err": bucket.transport_err,
                "timeout_err": bucket.timeout_err,
                "worker_error": bucket.worker_error,
                "cohort_started": bucket.started,
                "cohort_completed": bucket.cohort_completed,
                "cohort_ok": bucket.cohort_ok,
                "cohort_failures": bucket.cohort_failures,
                "cohort_worker_errors": bucket.cohort_worker_errors,
                "cohort_cancelled": bucket.cohort_cancelled,
                "in_flight_end": bucket.in_flight_end,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 2,
        "run_id": run_id,
        "started_at_unix_ms": started_at_unix_ms,
        "measurement": {
            "mode": mode,
            "target": {"scheme_host": sanitized_target(&args.url), "path": sanitized_path(&args.path), "method": args.method},
            "build": {
                "source_revision": env!("LOADGEN_SOURCE_REV"),
                "source_sha256": env!("LOADGEN_SOURCE_SHA256"),
                "source_dirty": env!("LOADGEN_SOURCE_DIRTY") == "true",
                "binary_sha256": binary_sha256,
                "profile": env!("LOADGEN_BUILD_PROFILE"),
                "target": env!("LOADGEN_TARGET"),
            },
            "resource_evidence": {
                "loadgen_host": {
                    "start": resource_sample_report(&stats.resource_start, stats.measurement_start, stats.measurement_start),
                    "end": resource_sample_report(&stats.resource_end, stats.measurement_start, stats.measurement_end),
                    "cpu_user_system_ticks_delta_diagnostic": (start_sampling_aligned && end_sampling_aligned).then(|| stats.resource_end.details["cpu_user_system_ticks"].as_u64().zip(stats.resource_start.details["cpu_user_system_ticks"].as_u64()).map(|(end, start)| end.saturating_sub(start))).flatten(),
                    "cpu_throttled_periods_delta_diagnostic": (start_sampling_aligned && end_sampling_aligned).then(|| stats.resource_end.details["cpu_throttled_periods"].as_u64().zip(stats.resource_start.details["cpu_throttled_periods"].as_u64()).map(|(end, start)| end.saturating_sub(start))).flatten(),
                    "cpu_throttled_usec_delta_diagnostic": (start_sampling_aligned && end_sampling_aligned).then(|| stats.resource_end.details["cpu_throttled_usec"].as_u64().zip(stats.resource_start.details["cpu_throttled_usec"].as_u64()).map(|(end, start)| end.saturating_sub(start))).flatten(),
                    "sampling_tolerance_ns": RESOURCE_ALIGNMENT_TOLERANCE_NS,
                    "start_sampling_aligned": start_sampling_aligned,
                    "end_sampling_aligned": end_sampling_aligned,
                    "sampling_status": if start_sampling_aligned && end_sampling_aligned { "ALIGNED_WITHIN_1MS_DIAGNOSTIC_ONLY" } else if stats.resource_start.sampled_at.is_some() && stats.resource_end.sampled_at.is_some() { "UNKNOWN_BOUNDARY_SAMPLE_MISALIGNED" } else { "UNKNOWN_BOUNDARY_SAMPLE_MISSING" },
                },
                "sut_host": null,
                "capacity_attribution": "BLOCKED_NO_APPROVED_SUT_SAMPLING_CHANNEL",
            },
            "offered_rate_rps": args.rate,
            "duration_s": args.duration,
            "warmup_requests": args.warmup,
            "drain_timeout_ms": args.drain_timeout_ms,
            "concurrency": args.concurrency,
            "max_in_flight": args.max_in_flight,
            "tokio_threads": args.threads,
            "connection_pool_max_idle_per_host": args.max_in_flight.saturating_add(8),
            "request_timeout_ms": args.timeout_ms,
            "slo": {"p99_ms": args.p99_slo_ms, "error_rate": args.error_rate_slo},
            "status": run_measurement_status,
            "system_capacity_status": capacity_status,
            "stop_reason": stats.stop_reason,
            "timing": {
                "run_start_unix_ms": started_at_unix_ms,
                "measurement_start_unix_ms": started_at_unix_ms.saturating_add(stats.measurement_start_offset_ns().unwrap_or_default() / 1_000_000),
                "measurement_end_unix_ms": stats.measurement_end_unix_ms(started_at_unix_ms),
                "measurement_start_offset_from_run_origin_ns": stats.measurement_start_offset_ns(),
                "measurement_end_offset_from_run_origin_ns": stats.measurement_end_offset_ns(),
                "measurement_window_ns": stats.measurement_duration().as_nanos(),
                "resource_sampling_start": {"requested_offset_from_boundary_ns": signed_offset_ns(stats.measurement_start, stats.resource_start.requested_at), "sample_started_offset_from_boundary_ns": signed_offset_ns(stats.measurement_start, stats.resource_start.sample_started_at), "sampled_offset_from_boundary_ns": signed_offset_ns(stats.measurement_start, stats.resource_start.sampled_at)},
                "resource_sampling_end": {"requested_offset_from_boundary_ns": signed_offset_ns(stats.measurement_end, stats.resource_end.requested_at), "sample_started_offset_from_boundary_ns": signed_offset_ns(stats.measurement_end, stats.resource_end.sample_started_at), "sampled_offset_from_boundary_ns": signed_offset_ns(stats.measurement_end, stats.resource_end.sampled_at)},
                "client_in_flight_snapshot_at_offset_from_run_origin_ns": signed_offset_ns(stats.run_origin, stats.measurement_in_flight_snapshot_at()),
                "client_in_flight_snapshot_offset_from_boundary_ns": stats.measurement_in_flight_offset_ns(),
                "client_in_flight_snapshot_offset_from_run_origin_ns": stats.measurement_in_flight_snapshot_offset_ns(),
                "client_in_flight_snapshot_reliable": stats.measurement_in_flight_snapshot_is_reliable(),
                "drain_duration_ns": stats.drain_duration.as_nanos(),
            },
            "measurement_window_ns": stats.measurement_duration().as_nanos(),
            "drain_duration_ns": stats.drain_duration.as_nanos(),
            "client_measurement_in_flight_end": stats.measurement_in_flight_end,
            "clock": {
                "boundary": "same_process_std_instant_offsets_from_run_origin",
                "measurement_start_offset_from_run_origin_ns": stats.measurement_start_offset_ns(),
                "measurement_end_offset_from_run_origin_ns": stats.measurement_end_offset_ns(),
                "measurement_duration_ns": stats.measurement_duration().as_nanos(),
                "cross_host_monotonic_comparable": false,
            },
            "hardware_resources": {
                "loadgen": {"host": null, "cpu_set": null, "memory_bytes": null, "cpu_quota": null, "cpu_throttling": null},
                "sut": {"host": null, "cpu_set": null, "memory_bytes": null, "cpu_quota": null, "cpu_throttling": null},
                "sampling_windows": {"loadgen": null, "sut": null},
            },
            "stop_at_error_limit": args.stop_at_error_limit,
            "max_errors": args.max_errors,
            "precision_gate": {
                "run_level_confidence": 0.95,
                "run_level_relative_half_width_limit": 0.02,
                "run_level_estimate": null,
                "run_level_ci": null,
                "run_level_status": "UNKNOWN_REQUIRES_INDEPENDENT_RUNS",
                "within_run_p99_sample_ci95_ns": p99_ci95,
                "within_run_p99_relative_half_width": p99_ci95_relative_half_width,
                "within_run_p99_precision_met_2pct": p99_precision_met,
                "note": "within-run request samples are not independent run-level replicates",
            },
            "counters": {
                "scheduled": stats.scheduled,
                "started": stats.started,
                "missed": stats.missed,
                "dropped": stats.dropped,
                "aborted": stats.aborted,
                "completed": stats.completed,
                "ok": stats.ok,
                "http_fail": stats.http_fail,
                "transport_err": stats.transport_err,
                "timeout_err": stats.timeout_err,
                "cancelled": stats.cancelled,
                "worker_error": stats.worker_error,
                "failures": stats.failures(),
                "in_flight_after_drain": stats.in_flight,
                "client_measurement_in_flight_end": stats.measurement_in_flight_end,
                "measurement_cohort_cancelled": stats.measurement_cohort_cancelled(),
                "max_in_flight_seen": stats.max_in_flight_seen,
                "accounting_ok": stats.accounting_ok(),
            },
            "observed": {
                "measurement_window_seconds": stats.measurement_duration().as_secs_f64(),
                "measurement_window_success_completions": stats.window_successes(),
                "success_rps": stats.window_successes() as f64 / stats.measurement_duration().as_secs_f64().max(f64::MIN_POSITIVE),
                "measurement_cohort_successes_including_drain": stats.measurement_cohort_successes(),
                "request_cohort_successes_including_drain": stats.ok,
                "request_error_rate": request_error_rate,
                "request_error_rate_ci95": request_error_rate_ci95,
                "measurement_cohort_error_rate": measurement_cohort_error_rate,
                "measurement_cohort_error_rate_ci95": measurement_cohort_error_rate_ci95,
                "slo_error_rate_population": if mode == "fixed_count" { "all_fixed_count_requests" } else { "measurement_due_at_cohort" },
                "slo_error_rate_ci95": slo_error_rate_ci95,
                "measurement_cohort_started": stats.measurement_cohort_started(),
                "measurement_cohort_failures": stats.measurement_cohort_failures(),
                "measurement_cohort_worker_errors": stats.measurement_cohort_worker_errors(),
                "measurement_cohort_cancelled": stats.measurement_cohort_cancelled(),
                "measurement_cohort_results_accounted": cohort_results_accounted,
                "measurement_cohort_latency_results_complete": cohort_latency_complete,
                "error_rate_slo_ci_decision": error_rate_slo_decision,
                "loadgen_underrun_count": stats.loadgen_underrun_count(),
                "loadgen_underrun_rate": loadgen_underrun_rate,
                "loadgen_underrun_rate_ci95": loadgen_underrun_rate_ci95,
                "p50_ns": latency_population_complete.then(|| percent(&stats.latency, 50.0)).flatten(),
                "p90_ns": latency_population_complete.then(|| percent(&stats.latency, 90.0)).flatten(),
                "p99_ns": p99,
                "p99_ci95_ns": p99_ci95,
                "p99_sample_ci95_relative_half_width": p99_ci95_relative_half_width,
                "p99_sample_precision_met_2pct": p99_precision_met,
                "p999_ns": latency_population_complete.then(|| percent(&stats.latency, 99.9)).flatten(),
                "mean_ns": latency_population_complete.then(|| stats.latency.mean_ns()).flatten(),
                "max_ns": latency_population_complete.then(|| stats.latency.max_ns()).flatten(),
                "queue_wait_p99_ns": latency_population_complete.then(|| percent(&stats.queue_wait, 99.0)).flatten(),
                "preparation_p99_ns": latency_population_complete.then(|| percent(&stats.preparation, 99.0)).flatten(),
                "client_in_flight_slope_per_second": stats.client_in_flight_slope_per_second(),
                "client_in_flight_stable": stats
                    .client_in_flight_slope_per_second()
                    .map(|slope| slope <= 0.0),
                "sut_backlog_slope_per_second": null,
                "sut_backlog_stable": null,
                "drain_duration_ms": stats.drain_duration.as_secs_f64() * 1000.0,
            },
            "slo_evaluation": {
                "p99_ci_decision": p99_slo_decision,
                "error_rate_ci_decision": error_rate_slo_decision,
                "slo_population": slo_population,
                "single_run_pass": mode == "open_loop" && run_measurement_status == "PASS_SINGLE_RUN_SLO",
                "p99_confidently_meets_slo": p99_slo_decision == Some("PASS"),
                "error_rate_confidently_meets_slo": error_rate_slo_decision == Some("PASS"),
                "measurement_cohort_results_accounted": cohort_results_accounted,
                "measurement_cohort_latency_results_complete": cohort_latency_complete,
                "measurement_cohort_cancelled": stats.measurement_cohort_cancelled(),
                "request_error_rate_ci95": request_error_rate_ci95,
                "slo_error_rate_ci95": slo_error_rate_ci95,
                "slo_error_rate_population": if mode == "fixed_count" { "all_fixed_count_requests" } else { "measurement_due_at_cohort" },
                "loadgen_underrun_count": stats.loadgen_underrun_count(),
                "capacity_claim": "UNKNOWN_REQUIRES_REPEATED_RUN_CI_AND_SUT_RESOURCE_EVIDENCE",
            },
            "latency_histogram": {"unit": "ns", "bounds_policy": "exact_below_100us_then_1pct_relative_buckets", "buckets": latency_buckets},
            "queue_wait_histogram": {"unit": "ns", "bounds_policy": "exact_below_100us_then_1pct_relative_buckets", "buckets": queue_wait_buckets},
            "time_buckets": time_buckets,
            "status_codes": codes,
        },
    })
}

fn write_artifact(path: &str, value: &Value) -> Result<(), String> {
    let destination = Path::new(path);
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = destination
        .file_name()
        .ok_or_else(|| "artifact path must name a file".to_owned())?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        now_millis()
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create temporary artifact: {error}"))?;
        serde_json::to_writer_pretty(&mut file, value).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        fs::hard_link(&temporary, destination)
            .map_err(|error| format!("cannot publish unique artifact {path}: {error}"))?;
        fs::remove_file(&temporary).map_err(|error| error.to_string())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn print_report(args: &Args, value: &Value) {
    if args.json {
        println!(
            "{}",
            serde_json::to_string(value).expect("serialize report")
        );
        return;
    }
    let measurement = &value["measurement"];
    println!(
        "mode={} concurrency={} offered_rate={} duration={:.2}s | scheduled={} started={} missed={} dropped={} aborted={} completed={} ok={} failures={} client_in_flight_after_drain={} | success_RPS={:.1} | p50={:?} p90={:?} p99={:?} p999={:?} | status={}",
        measurement["mode"].as_str().unwrap_or("unknown"),
        args.concurrency,
        args.rate,
        args.duration,
        measurement["counters"]["scheduled"].as_u64().unwrap_or_default(),
        measurement["counters"]["started"].as_u64().unwrap_or_default(),
        measurement["counters"]["missed"].as_u64().unwrap_or_default(),
        measurement["counters"]["dropped"].as_u64().unwrap_or_default(),
        measurement["counters"]["aborted"].as_u64().unwrap_or_default(),
        measurement["counters"]["completed"].as_u64().unwrap_or_default(),
        measurement["counters"]["ok"].as_u64().unwrap_or_default(),
        measurement["counters"]["failures"].as_u64().unwrap_or_default(),
        measurement["counters"]["in_flight_after_drain"].as_u64().unwrap_or_default(),
        measurement["observed"]["success_rps"].as_f64().unwrap_or_default(),
        measurement["observed"]["p50_ns"],
        measurement["observed"]["p90_ns"],
        measurement["observed"]["p99_ns"],
        measurement["observed"]["p999_ns"],
        measurement["status"].as_str().unwrap_or("UNKNOWN"),
    );
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("loadgen: {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run(args));
}

async fn run(args: Args) {
    let run_started_at_unix_ms = now_millis();
    let run_origin = Instant::now();
    let client = reqwest::Client::builder()
        .tcp_nodelay(true)
        .timeout(Duration::from_millis(args.timeout_ms))
        .pool_idle_timeout(Duration::from_secs(75))
        .pool_max_idle_per_host(args.max_in_flight.saturating_add(8))
        .build()
        .expect("http client");
    let run_seed = args
        .run_id
        .clone()
        .unwrap_or_else(|| format!("loadgen-{}-{}", now_millis(), std::process::id()));
    let ctx = Ctx {
        client,
        base: Arc::from(args.url.as_str()),
        path: Arc::from(args.path.as_str()),
        method: Arc::from(args.method.as_str()),
        body: args.body.as_deref().map(Arc::from),
        secret: Arc::from(args.secret.as_str()),
        prefix: Arc::from(args.prefix.as_str()),
        ids: Arc::new(args.ids.clone()),
        request_id_seed: request_id_seed(&run_seed),
    };

    if args.warmup > 0 {
        let warmup_start = Instant::now();
        let warmup_ctx = ctx.clone();
        let warmup = run_count(
            move |due, sequence| {
                let ctx = warmup_ctx.clone();
                async move { one_request(ctx, due, sequence).await }
            },
            warmup_start,
            args.max_in_flight,
            args.warmup,
        )
        .await;
        eprintln!(
            "warmup_requests={} warmup_duration_s={:.3} warmup_failures={}",
            warmup.completed,
            warmup_start.elapsed().as_secs_f64(),
            warmup.failures()
        );
    }

    let duration = Duration::from_secs_f64(args.duration);
    let start = Instant::now();
    let request_sequence_offset = args.warmup;
    let request_ctx = ctx.clone();
    let request = move |due: Instant, sequence: u64| {
        let request_ctx = request_ctx.clone();
        let sequence = sequence.saturating_add(request_sequence_offset);
        async move { one_request(request_ctx, due, sequence).await }
    };
    let mut stats = if args.count > 0 {
        run_count(request, start, args.max_in_flight, args.count).await
    } else if args.rate > 0.0 {
        run_open_loop(
            request,
            start,
            args.rate,
            duration,
            args.max_in_flight,
            Duration::from_millis(args.drain_timeout_ms),
            args.stop_at_error_limit,
            args.max_errors,
            sample_process_resources,
        )
        .await
    } else {
        run_closed_loop(
            request,
            start,
            args.max_in_flight,
            duration,
            Duration::from_millis(args.drain_timeout_ms),
        )
        .await
    };
    stats.run_origin = run_origin;
    let mode = if args.count > 0 {
        "fixed_count"
    } else if args.rate > 0.0 {
        "open_loop"
    } else {
        "closed_loop"
    };
    let report = serialize_report(&args, &stats, &run_seed, mode, run_started_at_unix_ms);
    if let Some(path) = &args.output_file {
        if let Err(error) = write_artifact(path, &report) {
            eprintln!("loadgen artifact: {error}");
            std::process::exit(2);
        }
    }
    print_report(&args, &report);
    let should_stop =
        args.stop_at_error_limit && args.max_errors > 0 && stats.failures() >= args.max_errors;
    let failed = !stats.accounting_ok() || should_stop;
    if failed {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            url: "http://127.0.0.1:9005".into(),
            path: "/probe".into(),
            method: "GET".into(),
            body: None,
            concurrency: 1,
            duration: 1.0,
            count: 0,
            warmup: 0,
            rate: 10.0,
            max_in_flight: 1,
            drain_timeout_ms: 100,
            max_errors: 0,
            stop_at_error_limit: false,
            run_id: None,
            p99_slo_ms: None,
            error_rate_slo: None,
            output_file: None,
            threads: 1,
            timeout_ms: 100,
            secret: "test-secret".into(),
            prefix: "test".into(),
            ids: Ids {
                user: "1".into(),
                icard: "2".into(),
                card: "3".into(),
                domain: "4".into(),
                tenant: "5".into(),
            },
            json: true,
        }
    }

    #[test]
    fn capacity_is_data_only_without_both_slos() {
        let args = args();
        let stats = Stats::new(Instant::now(), Duration::from_secs(1));
        let report = serialize_report(&args, &stats, "run", "open_loop", now_millis());
        assert_eq!(report["measurement"]["status"], "DATA_ONLY");
        assert_eq!(report["schema_version"], 2);
        assert!(
            report["measurement"]["clock"]["measurement_start_offset_from_run_origin_ns"]
                .is_number()
        );
        assert!(
            report["measurement"]["clock"]["measurement_end_offset_from_run_origin_ns"].is_number()
        );
        assert_eq!(
            report["measurement"]["slo_evaluation"]["capacity_claim"],
            "UNKNOWN_REQUIRES_REPEATED_RUN_CI_AND_SUT_RESOURCE_EVIDENCE"
        );
    }

    #[test]
    fn resource_boundary_sampling_requires_all_timestamps_within_tolerance() {
        let boundary = Instant::now();
        let aligned = ResourceSample {
            requested_at: Some(boundary),
            sample_started_at: Some(boundary + Duration::from_micros(100)),
            sampled_at: Some(boundary + Duration::from_micros(200)),
            details: json!({"cpu": 1}),
        };
        assert!(resource_sample_is_aligned(&aligned, boundary));
        let late = ResourceSample {
            sampled_at: Some(boundary + Duration::from_millis(2)),
            ..aligned.clone()
        };
        assert!(!resource_sample_is_aligned(&late, boundary));
        assert!(!resource_sample_is_aligned(
            &ResourceSample::default(),
            boundary
        ));
        let early_start = ResourceSample {
            sample_started_at: Some(boundary - Duration::from_nanos(1)),
            ..aligned.clone()
        };
        assert!(!resource_sample_is_aligned(&early_start, boundary));
        let reversed = ResourceSample {
            sampled_at: Some(boundary),
            sample_started_at: Some(boundary + Duration::from_nanos(1)),
            ..aligned
        };
        assert!(!resource_sample_is_aligned(&reversed, boundary));
    }

    #[test]
    fn cancelled_cohort_is_unknown_for_both_slos_and_cannot_pass_single_run() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let stats = runtime.block_on(async {
            run_open_loop(
                |due, _sequence| async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    RequestSample::new(
                        RequestOutcome::Http(200),
                        due,
                        Instant::now(),
                        Instant::now(),
                        Instant::now(),
                    )
                },
                Instant::now(),
                100.0,
                Duration::from_millis(10),
                1,
                Duration::from_millis(5),
                false,
                0,
                sample_process_resources,
            )
            .await
        });
        let mut args = args();
        args.p99_slo_ms = Some(100.0);
        args.error_rate_slo = Some(0.01);
        let report = serialize_report(&args, &stats, "cancelled-run", "open_loop", now_millis());
        let measurement = &report["measurement"];
        assert_eq!(measurement["status"], "UNKNOWN_ACCOUNTING_OR_DRAIN");
        assert_eq!(
            measurement["observed"]["measurement_cohort_error_rate_ci95"],
            Value::Null
        );
        assert_eq!(measurement["observed"]["slo_error_rate_ci95"], Value::Null);
        assert_eq!(
            measurement["observed"]["error_rate_slo_ci_decision"],
            "UNKNOWN"
        );
        assert_eq!(measurement["slo_evaluation"]["p99_ci_decision"], "UNKNOWN");
        assert_eq!(measurement["slo_evaluation"]["single_run_pass"], false);
        assert_eq!(measurement["observed"]["measurement_cohort_cancelled"], 1);
    }

    #[test]
    fn report_strips_url_credentials_and_cannot_pass_before_ci_converges() {
        let mut args = args();
        args.url = "https://bench-user:bench-secret@example.test:9443/base".into();
        args.p99_slo_ms = Some(100.0);
        args.error_rate_slo = Some(0.01);
        let start = Instant::now();
        let stats = Stats::new(start, Duration::from_secs(3));
        let report = serialize_report(&args, &stats, "run", "open_loop", now_millis());
        let rendered = report.to_string();
        assert!(!rendered.contains("bench-user"));
        assert!(!rendered.contains("bench-secret"));
        assert_eq!(
            report["measurement"]["target"]["scheme_host"],
            "https://example.test:9443"
        );
        assert_eq!(
            report["measurement"]["system_capacity_status"],
            "UNKNOWN_REQUIRES_REPEATED_RUN_CI_AND_SUT_EVIDENCE"
        );
    }

    #[test]
    fn capacity_report_does_not_promote_single_run_to_system_capacity() {
        let mut args = args();
        args.p99_slo_ms = Some(100.0);
        args.error_rate_slo = Some(0.01);
        let start = Instant::now();
        let mut stats = Stats::new(start, Duration::from_secs(3));
        for outcome in [
            RequestOutcome::Http(200),
            RequestOutcome::Http(200),
            RequestOutcome::Http(200),
        ] {
            stats.scheduled += 1;
            stats.record_started(start);
            stats.record_completion(RequestSample::new(
                outcome,
                start,
                start,
                start,
                start + Duration::from_millis(1),
            ));
        }
        stats.finalize_windows();
        let report = serialize_report(&args, &stats, "run", "open_loop", now_millis());
        assert_eq!(
            report["measurement"]["status"],
            "UNKNOWN_SLO_CONFIDENCE_INTERVAL_CROSSES_LIMIT"
        );
        assert_eq!(
            report["measurement"]["system_capacity_status"],
            "UNKNOWN_REQUIRES_REPEATED_RUN_CI_AND_SUT_EVIDENCE"
        );
        assert_eq!(
            report["measurement"]["slo_evaluation"]["single_run_pass"],
            false
        );
        assert_eq!(
            report["measurement"]["slo_evaluation"]["p99_confidently_meets_slo"],
            true
        );
        assert_eq!(
            report["measurement"]["slo_evaluation"]["error_rate_confidently_meets_slo"],
            false
        );
        assert_eq!(
            report["measurement"]["slo_evaluation"]["capacity_claim"],
            "UNKNOWN_REQUIRES_REPEATED_RUN_CI_AND_SUT_RESOURCE_EVIDENCE"
        );
    }

    #[test]
    fn output_artifacts_refuse_overwrite() {
        let path = std::env::temp_dir().join(format!(
            "loadgen-artifact-{}-{}.json",
            std::process::id(),
            now_millis()
        ));
        let value = json!({"schema_version": 1});
        write_artifact(path.to_str().unwrap(), &value).unwrap();
        assert!(write_artifact(path.to_str().unwrap(), &value).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
