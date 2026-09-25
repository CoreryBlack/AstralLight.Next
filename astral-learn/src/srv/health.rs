//! 健康检查

use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::AppState;

pub fn health_routes() -> Router<AppState> {
    Router::new().route("/health", get(health_check))
}

async fn health_check() -> Json<serde_json::Value> {
    let now = time::OffsetDateTime::now_utc();
    let ts = format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    Json(json!({
        "status": "UP",
        "timestamp": ts,
    }))
}
