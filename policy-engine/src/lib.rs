//! AstralLight 权限策略评估引擎核心
//!
//! PolicyEngine 是权限控制系统的决策核心，实现三层评估模型：
//!
//! - **L1**: RuleSet 匹配（先 OVERLAY 后 BASE）—— 规则集共享模式
//! - **L2**: PermissionRule 回退 —— 旧路径兼容 + CARD_ONLY 特例
//! - **L3**: DEFAULT_DENY —— 未匹配时默认拒绝（fail-closed）
//!
//! `policy-engine` crate 只承载纯规则评估逻辑，不直接依赖 MySQL、Redis
//! 或 RabbitMQ。数据库访问通过 `RuleRepository` trait 注入。
//!
//! Phase 2 additionally exposes a Rust-native, no-I/O authorization hot-state compiler
//! kernel. Its versioned candidate and full-rebuild oracle are deliberately not production
//! projection wiring; SQL/Redis/MQ/worker integration remains a later boundary.

mod arbiter;
mod authorization_compiler;
mod circuit_breaker;
mod client;
mod condition;
mod consistency;
mod cross_city_conflict;
mod data_scope;
#[cfg(any(feature = "e1-observability", test))]
pub mod e1_observation;
mod engine;
mod hit_stats;
/// 组织范围（ORG_SCOPE）准入读取合同（main/admission owner 维护的实现）。
pub mod org_admission;
/// 组织范围（ORG_SCOPE）纯编译器内核（types/compiler owner 维护；Phase 2 default-off）。
mod org_compiler;

pub use arbiter::*;
pub use authorization_compiler::*;
pub use circuit_breaker::*;
pub use client::*;
pub use condition::*;
pub use consistency::*;
pub use cross_city_conflict::*;
pub use data_scope::*;
pub use engine::*;
pub use hit_stats::*;
pub use org_admission::OrgAuthorityRead;
pub use org_compiler::*;
