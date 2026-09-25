//! AstralLight 公共基础设施
//!
//! 提供配置加载、统一错误处理、Tower 中间件、API 响应契约、权限规则服务等。

pub mod audit;
pub mod config;
pub mod contract;
pub mod cross_city_signature;
pub mod error;
#[cfg(any(feature = "e3-observability", feature = "e4-observability", test))]
pub mod experiment_observation;
pub mod metrics_runtime;
pub mod middleware;
pub mod service;
pub mod token_contract;
pub mod tracing;

pub use astral_types::ResourceRegistry;
pub use cross_city_signature::{
    CrossCityEvidenceReplayKey, CrossCityNodeIdentity, CrossCitySignatureError,
    CrossCityVerifiedEvidence,
};
