//! AstralMonitor — 监控与告警服务

use std::sync::Arc;

use axum::extract::FromRef;
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;

use astral_common::config::AppConfig;

pub mod alerts;
pub mod collector;
pub mod dashboard;
pub mod dispatch;
pub mod endpoints;
pub mod mutation;
pub mod notifications;
pub mod repository;
pub mod service;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: MySqlPool,
    pub engine: Arc<PolicyEngine>,
    /// Fixed trust-root verifier for request-bound authorization fences. A
    /// missing provider is not-ready in Strict mode; DurableOnly is an explicit
    /// compatibility profile.
    pub authorization_fence_provider: Option<Arc<astral_db::SqlxAuthorizationFenceProvider>>,
    pub monitor_service: Arc<service::MonitorService>,
}

impl FromRef<AppState> for MySqlPool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for astral_common::config::AppConfig {
    fn from_ref(state: &AppState) -> Self {
        (*state.config).clone()
    }
}
