//! 告警规则管理 — Java AlertRuleService 的 HTTP adapter。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRule {
    pub id: i64,
    pub name: String,
    pub metric: String,
    pub condition_op: String,
    pub threshold: f64,
    pub duration_seconds: i32,
    pub severity: String,
    pub enabled: i8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreateAlertReq {
    pub name: String,
    pub metric: String,
    pub condition_op: Option<String>,
    pub threshold: f64,
    pub duration_seconds: Option<i32>,
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleFilter {
    pub metric: Option<String>,
    pub enabled: Option<i8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertHistory {
    pub id: i64,
    pub rule_id: i64,
    pub rule_name: Option<String>,
    pub metric_type: Option<String>,
    pub actual_value: Option<f64>,
    pub severity: String,
    pub status: String,
    pub triggered_at: time::OffsetDateTime,
    pub resolved_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AlertHistoryFilter {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityLog {
    pub id: i64,
    pub event_type: String,
    pub title: Option<String>,
    pub detail: Option<String>,
    pub level: String,
    pub source_service: Option<String>,
    pub occurred_at: time::OffsetDateTime,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ActivityLogFilter {
    pub event_type: Option<String>,
    pub level: Option<String>,
    pub source_service: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: Option<i64>,
}

pub fn alert_routes() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(list_rules))
        .route("/alerts", post(create_rule))
        .route("/alerts/{id}", get(get_rule))
        .route("/alerts/{id}", put(update_rule))
        .route("/alerts/{id}", delete(delete_rule))
        .route("/alerts/{id}/toggle", post(toggle_rule))
        .route("/alert-rules", get(list_rules))
        .route("/alert-rules", post(create_rule))
        .route("/alert-rules/{id}", get(get_rule))
        .route("/alert-rules/{id}", put(update_rule))
        .route("/alert-rules/{id}", delete(delete_rule))
        .route("/alert-rules/{id}/toggle", put(toggle_rule))
        .route("/alert-history", get(list_alert_history))
        .route("/alert-history/{id}/ack", put(acknowledge_alert))
        .route("/rules", get(list_rules))
        .route("/alerts/rules", get(list_rules))
        .route("/audit-logs", get(list_activity_logs))
        .route("/activity-logs", get(list_activity_logs))
}

async fn list_rules(
    State(state): State<AppState>,
    Query(filter): Query<AlertRuleFilter>,
) -> Result<Json<ApiResponse<Vec<AlertRule>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.list_rules(filter).await?,
    )))
}

async fn create_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Json(request): Json<CreateAlertReq>,
) -> Result<Json<ApiResponse<AlertRule>>, AppError> {
    let context =
        crate::mutation::context(&headers, &policy, admission, "monitor", "create", None)?;
    let mutation = crate::repository::MonitorMutation::CreateRule(rule_update(0, request));
    match state
        .monitor_service
        .protected_mutation(&context, mutation)
        .await?
    {
        crate::repository::MonitorMutationResult::Rule(rule) => {
            Ok(Json(ApiResponse::success(rule.into())))
        }
        _ => Err(crate::mutation::unexpected_result()),
    }
}

async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<AlertRule>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.get_rule(id).await?,
    )))
}

fn rule_update(id: i64, request: CreateAlertReq) -> crate::repository::AlertRuleUpdate {
    crate::repository::AlertRuleUpdate {
        id,
        name: request.name,
        metric: request.metric,
        condition_op: request.condition_op.unwrap_or_else(|| ">=".into()),
        threshold: request.threshold,
        duration_seconds: request.duration_seconds.unwrap_or(60),
        severity: request.severity.unwrap_or_else(|| "WARNING".into()),
    }
}

async fn update_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(request): Json<CreateAlertReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context =
        crate::mutation::context(&headers, &policy, admission, "monitor", "update", Some(id))?;
    state
        .monitor_service
        .protected_mutation(
            &context,
            crate::repository::MonitorMutation::UpdateRule(rule_update(id, request)),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context =
        crate::mutation::context(&headers, &policy, admission, "monitor", "delete", Some(id))?;
    state
        .monitor_service
        .protected_mutation(&context, crate::repository::MonitorMutation::DeleteRule(id))
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn toggle_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<AlertRule>>, AppError> {
    let context =
        crate::mutation::context(&headers, &policy, admission, "monitor", "update", Some(id))?;
    match state
        .monitor_service
        .protected_mutation(&context, crate::repository::MonitorMutation::ToggleRule(id))
        .await?
    {
        crate::repository::MonitorMutationResult::Rule(rule) => {
            Ok(Json(ApiResponse::success(rule.into())))
        }
        _ => Err(crate::mutation::unexpected_result()),
    }
}

async fn list_alert_history(
    State(state): State<AppState>,
    Query(filter): Query<AlertHistoryFilter>,
) -> Result<Json<ApiResponse<Vec<AlertHistory>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.list_alert_history(filter).await?,
    )))
}

async fn acknowledge_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context =
        crate::mutation::context(&headers, &policy, admission, "monitor", "update", Some(id))?;
    state
        .monitor_service
        .protected_mutation(
            &context,
            crate::repository::MonitorMutation::Acknowledge(id),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_activity_logs(
    State(state): State<AppState>,
    Query(filter): Query<ActivityLogFilter>,
) -> Result<Json<ApiResponse<Vec<ActivityLog>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.list_activity_logs(filter).await?,
    )))
}
