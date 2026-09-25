//! 定时采集后台任务 — 对应 Java `MetricCollectTask` + `AlertEvaluationTask`。
//!
//! 两个 tokio 循环：
//! - 30s：服务探活（`GET {uri}/api/health`）+ 告警评估
//! - 60s：系统指标（sysinfo）+ Redis 指标 + 每日清理（UTC 3 时）
//!
//! 单次周期失败只记录 warning，不中断后续周期。

use std::time::{Duration, Instant};

use tokio::time::interval;

use astral_common::config::AppConfig;

use crate::dispatch;
use crate::AppState;

/// 启动采集后台任务。调用方需持有返回的 JoinHandle 以避免被 drop 取消。
pub fn spawn_collector(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let fast = interval(Duration::from_secs(30));
        let slow = interval(Duration::from_secs(60));
        let (mut fast, mut slow) = (fast, slow);

        loop {
            tokio::select! {
                _ = fast.tick() => {
                    run_probe_and_evaluate(&state).await;
                }
                _ = slow.tick() => {
                    run_system_and_redis(&state).await;
                    maybe_cleanup(&state).await;
                }
            }
        }
    })
}

async fn run_probe_and_evaluate(state: &AppState) {
    let cycle_start = Instant::now();
    let services = probe_targets(&state.config);
    for (service_name, uri) in services {
        probe_service(state, &service_name, &uri).await;
    }
    metrics::histogram!("astral_monitor_collect_cycle_seconds", "kind" => "probe")
        .record(cycle_start.elapsed().as_secs_f64());

    // 告警评估与通知派发解耦：评估持久化告警，派发在后台任务执行，
    // webhook 超时不得阻塞 30s 探活循环。
    let eval_start = Instant::now();
    match state.monitor_service.evaluate_alert_rules(60).await {
        Ok(alerts) => {
            for alert in alerts {
                let monitor_service = state.monitor_service.clone();
                tokio::spawn(async move {
                    dispatch::dispatch_alert(monitor_service.as_ref(), &alert).await;
                });
            }
        }
        Err(error) => tracing::warn!(error = %error, "alert rule evaluation failed"),
    }
    metrics::histogram!("astral_monitor_alert_evaluation_seconds")
        .record(eval_start.elapsed().as_secs_f64());
}

async fn run_system_and_redis(state: &AppState) {
    let cycle_start = Instant::now();
    collect_system(state).await;
    collect_redis(state).await;
    metrics::histogram!("astral_monitor_collect_cycle_seconds", "kind" => "system")
        .record(cycle_start.elapsed().as_secs_f64());
}

async fn maybe_cleanup(state: &AppState) {
    let hour = time::OffsetDateTime::now_utc().hour();
    if hour == 3 {
        if let Err(error) = state.monitor_service.cleanup_old_data().await {
            tracing::warn!(error = %error, "monitor data cleanup failed");
        }
    }
}

/// 探活目标：从配置 URI 推导（非空才探）。
fn probe_targets(config: &AppConfig) -> Vec<(String, String)> {
    let mut targets = Vec::new();
    if !config.identity_service_uri.is_empty() {
        targets.push(("identity".into(), config.identity_service_uri.clone()));
    }
    if !config.learn_service_uri.is_empty() {
        targets.push(("learn".into(), config.learn_service_uri.clone()));
    }
    if !config.chat_service_uri.is_empty() {
        targets.push(("chat".into(), config.chat_service_uri.clone()));
    }
    if !config.gateway_service_uri.is_empty() {
        targets.push(("gateway".into(), config.gateway_service_uri.clone()));
    }
    if !config.trust_graph_uri.is_empty() {
        targets.push(("trustgraph".into(), config.trust_graph_uri.clone()));
    }
    targets
}

/// 探活单个服务：GET {uri}/api/health，2s 超时，写 latency + reachable。
async fn probe_service(state: &AppState, service_name: &str, uri: &str) {
    let health_url = format!("{}/api/health", uri.trim_end_matches('/'));
    let start = std::time::Instant::now();
    let reachable = reqwest::Client::new()
        .get(&health_url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map(|response| response.status().is_success())
        .unwrap_or(false);
    let latency_ms = start.elapsed().as_millis() as i64;

    metrics::gauge!("astral_monitor_service_reachable", "service" => service_name.to_string())
        .set(if reachable { 1.0 } else { 0.0 });
    metrics::histogram!("astral_monitor_service_probe_latency_seconds", "service" => service_name.to_string())
        .record(latency_ms as f64 / 1000.0);

    if let Err(error) = state
        .monitor_service
        .collect_service_metrics(service_name, latency_ms, reachable)
        .await
    {
        tracing::warn!(service = service_name, error = %error, "service probe persistence failed");
    }
}

/// 采集系统 CPU/内存/磁盘使用率（sysinfo）。
async fn collect_system(state: &AppState) {
    let mut system = sysinfo::System::new_all();
    system.refresh_cpu_all();
    system.refresh_memory();

    let cpu = system.global_cpu_usage() as f64;

    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let memory_percent = if total_memory > 0 {
        used_memory as f64 * 100.0 / total_memory as f64
    } else {
        0.0
    };

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut total_space = 0u64;
    let mut available_space = 0u64;
    for disk in &disks {
        total_space += disk.total_space();
        available_space += disk.available_space();
    }
    let disk_percent = if total_space > 0 {
        (total_space - available_space) as f64 * 100.0 / total_space as f64
    } else {
        0.0
    };

    if let Err(error) = state
        .monitor_service
        .collect_system_metrics(cpu, memory_percent, disk_percent)
        .await
    {
        tracing::warn!(error = %error, "system metric collection failed");
    }
}

/// 采集 Redis 指标（INFO memory/stats/clients + DBSIZE）。
async fn collect_redis(state: &AppState) {
    let redis_url = state.config.redis_url.clone();
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(error = %error, "redis metric collection skipped: open client failed");
            return;
        }
    };
    let mut conn = match client.get_connection_manager().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(error = %error, "redis metric collection skipped: connect failed");
            return;
        }
    };

    let memory_info: Result<String, _> = redis::cmd("INFO")
        .arg("memory")
        .query_async(&mut conn)
        .await;
    let stats_info: Result<String, _> =
        redis::cmd("INFO").arg("stats").query_async(&mut conn).await;
    let clients_info: Result<String, _> = redis::cmd("INFO")
        .arg("clients")
        .query_async(&mut conn)
        .await;
    let db_size: Result<i64, _> = redis::cmd("DBSIZE").query_async(&mut conn).await;

    let memory_info = match memory_info {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(error = %error, "redis INFO memory failed");
            return;
        }
    };
    let stats_info = match stats_info {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(error = %error, "redis INFO stats failed");
            return;
        }
    };
    let clients_info = match clients_info {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(error = %error, "redis INFO clients failed");
            return;
        }
    };
    let key_count = db_size.unwrap_or(0);

    let used_memory = parse_info_field(&memory_info, "used_memory").unwrap_or(0);
    let max_memory = parse_info_field(&memory_info, "maxmemory").unwrap_or(0);
    let hits = parse_info_field(&stats_info, "keyspace_hits").unwrap_or(0);
    let misses = parse_info_field(&stats_info, "keyspace_misses").unwrap_or(0);
    let connected_clients = parse_info_field(&clients_info, "connected_clients").unwrap_or(0);

    let hit_rate = if hits + misses > 0 {
        hits as f64 * 100.0 / (hits + misses) as f64
    } else {
        0.0
    };
    let used_memory_mb = used_memory as f64 / (1024.0 * 1024.0);
    // Java 默认回退 2GB（maxmemory=0 时）。
    let max_memory_effective = if max_memory > 0 {
        max_memory
    } else {
        2_147_483_648
    };
    let max_memory_mb = max_memory_effective as f64 / (1024.0 * 1024.0);

    if let Err(error) = state
        .monitor_service
        .collect_redis_metrics(
            hit_rate,
            connected_clients,
            used_memory_mb,
            max_memory_mb,
            key_count,
        )
        .await
    {
        tracing::warn!(error = %error, "redis metric persistence failed");
    }
}

/// 解析 `INFO` 输出中的 `key:value` 字段（整数值）。
fn parse_info_field(info: &str, key: &str) -> Option<i64> {
    info.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
}
