//! 监控仪表盘 — Java DashboardMonitoringService 的 HTTP adapter。

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

#[derive(Debug, Serialize)]
pub struct CacheStatus {
    pub hit_rate: f64,
    pub connected_clients: i64,
    pub max_clients: i64,
    pub used_memory: String,
    pub used_memory_percent: f64,
    pub key_count: i64,
}

#[derive(Debug, Serialize)]
pub struct ServiceLatency {
    pub name: String,
    pub latency_ms: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemResource {
    pub resource_type: String,
    pub used: f64,
    pub total: f64,
    pub percent: f64,
    pub unit: String,
}

#[derive(Debug, Serialize)]
pub struct TrendPoint {
    pub label: String,
    pub value: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHealth {
    pub name: String,
    pub domain: String,
    pub status: String,
    pub latency: String,
    pub throughput: String,
    pub note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertItem {
    pub level: String,
    pub title: String,
    pub time_ago: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityItem {
    pub time_ago: String,
    pub title: String,
    pub detail: String,
    pub level: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSnapshot {
    pub id: i64,
    pub service_name: String,
    pub metric_type: String,
    pub metric_value: f64,
    pub collected_at: time::OffsetDateTime,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MetricsHistoryFilter {
    pub service_name: Option<String>,
    pub metric_type: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: Option<i64>,
}

pub fn dashboard_routes() -> Router<AppState> {
    Router::new()
        .route("/cache", get(get_cache_status))
        .route("/latency", get(get_service_latencies))
        .route("/resources", get(get_system_resources))
        .route("/trend", get(get_request_trend))
        .route("/services", get(get_service_health))
        .route("/alerts-summary", get(get_dashboard_alerts))
        .route("/activities", get(get_dashboard_activities))
        .route("/metrics/history", get(get_metrics_history))
}

async fn get_cache_status(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Option<CacheStatus>>>, AppError> {
    let (hit_rate, connected, mem_percent, mem_mb, key_count) = tokio::try_join!(
        state.monitor_service.latest_metric("redis", "hit_rate"),
        state
            .monitor_service
            .latest_metric("redis", "connected_clients"),
        state.monitor_service.latest_metric("redis", "memory_usage"),
        state
            .monitor_service
            .latest_metric("redis", "used_memory_mb"),
        state.monitor_service.latest_metric("redis", "key_count"),
    )?;

    let Some(hit_rate) = hit_rate else {
        return Ok(Json(ApiResponse::success(None)));
    };
    let connected = connected.unwrap_or_default() as i64;
    Ok(Json(ApiResponse::success(Some(CacheStatus {
        hit_rate,
        connected_clients: connected,
        max_clients: 16,
        used_memory: format!("{:.1}MB", mem_mb.unwrap_or_default()),
        used_memory_percent: mem_percent.unwrap_or_default(),
        key_count: key_count.unwrap_or_default() as i64,
    }))))
}

async fn get_service_latencies(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<ServiceLatency>>>, AppError> {
    let services = ["gateway", "identity", "learn", "chat"];
    let mut latencies = Vec::with_capacity(services.len());
    for name in services {
        let latency = state
            .monitor_service
            .latest_metric(name, "latency")
            .await?
            .unwrap_or(999.0);
        latencies.push(ServiceLatency {
            name: capitalize(name),
            latency_ms: latency as i64,
        });
    }
    Ok(Json(ApiResponse::success(latencies)))
}

async fn get_system_resources(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SystemResource>>>, AppError> {
    let (cpu, memory, disk) = tokio::try_join!(
        state.monitor_service.latest_metric("system", "cpu_usage"),
        state
            .monitor_service
            .latest_metric("system", "memory_usage"),
        state.monitor_service.latest_metric("system", "disk_usage"),
    )?;
    let cpu = cpu.unwrap_or_default().min(100.0);
    let memory = memory.unwrap_or_default();
    let disk = disk.unwrap_or_default();

    Ok(Json(ApiResponse::success(vec![
        SystemResource {
            resource_type: "CPU".into(),
            used: cpu,
            total: 100.0,
            percent: cpu,
            unit: "%".into(),
        },
        SystemResource {
            resource_type: "Memory".into(),
            used: memory,
            total: 100.0,
            percent: memory,
            unit: "%".into(),
        },
        SystemResource {
            resource_type: "Disk".into(),
            used: disk,
            total: 100.0,
            percent: disk,
            unit: "%".into(),
        },
    ])))
}

async fn get_request_trend(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<TrendPoint>>>, AppError> {
    let labels = [
        "00:00", "03:00", "06:00", "09:00", "12:00", "15:00", "18:00", "21:00",
    ];
    let mut trend: Vec<TrendPoint> = labels
        .iter()
        .map(|label| TrendPoint {
            label: (*label).into(),
            value: 0,
        })
        .collect();
    for (slot, average) in state.monitor_service.metric_trend().await? {
        let index = slot as usize;
        if index < trend.len() {
            trend[index].value = average.round() as i64;
        }
    }
    Ok(Json(ApiResponse::success(trend)))
}

async fn get_service_health(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<ServiceHealth>>>, AppError> {
    let services = [
        ("gateway", "API 网关"),
        ("identity", "认证服务"),
        ("learn", "学习服务"),
        ("chat", "聊天服务"),
    ];
    let mut result = Vec::with_capacity(services.len());
    for (name, domain) in services {
        result.push(build_service_health(&state, name, domain).await?);
    }
    Ok(Json(ApiResponse::success(result)))
}

async fn build_service_health(
    state: &AppState,
    service_name: &str,
    domain: &str,
) -> Result<ServiceHealth, AppError> {
    let latency = state
        .monitor_service
        .latest_metric(service_name, "latency")
        .await?;
    let reachable = state
        .monitor_service
        .latest_metric(service_name, "reachable")
        .await?;

    let Some(reachable) = reachable else {
        return Ok(ServiceHealth {
            name: capitalize(service_name),
            domain: domain.into(),
            status: "unknown".into(),
            latency: "未知".into(),
            throughput: "未知".into(),
            note: "暂无监控数据".into(),
        });
    };
    let latency = latency.unwrap_or(999.0);
    let (status, latency_text, throughput, note) = if reachable <= 0.0 {
        (
            "critical",
            "不可达".into(),
            "0/s".into(),
            "服务不可达".into(),
        )
    } else if latency < 50.0 {
        (
            "healthy",
            format!("{latency:.0}ms"),
            "正常".into(),
            "运行正常".into(),
        )
    } else if latency < 100.0 {
        (
            "warning",
            format!("{latency:.0}ms"),
            "偏慢".into(),
            "响应延迟较高".into(),
        )
    } else {
        (
            "critical",
            format!("{latency:.0}ms"),
            "缓慢".into(),
            "服务响应超时".into(),
        )
    };

    Ok(ServiceHealth {
        name: capitalize(service_name),
        domain: domain.into(),
        status: status.into(),
        latency: latency_text,
        throughput,
        note,
    })
}

async fn get_dashboard_alerts(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<AlertItem>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.dashboard_alerts().await?,
    )))
}

async fn get_dashboard_activities(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<ActivityItem>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.dashboard_activities().await?,
    )))
}

async fn get_metrics_history(
    State(state): State<AppState>,
    Query(filter): Query<MetricsHistoryFilter>,
) -> Result<Json<ApiResponse<Vec<MetricSnapshot>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.metric_history(filter).await?,
    )))
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
    }
}
