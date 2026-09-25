//! AstralLight 共享类型定义
//!
//! 本 crate 包含跨模块共享的核心类型：权限评估引擎的输入/输出类型、
//! 错误模型、资源注册表等。不依赖数据库、缓存、MQ 等外部基础设施。

mod context;
mod cross_city;
mod decision;
mod eligibility;
mod entities;
mod error;
mod grant;
/// 组织范围（ORG_SCOPE）共享类型合同 — Phase 2 default-off（types owner 维护）。
pub mod org_scope;
mod projection;
pub mod registry;

pub use context::*;
pub use cross_city::*;
pub use decision::*;
pub use eligibility::*;
pub use entities::*;
pub use error::*;
pub use grant::*;
pub use projection::*;
pub use registry::*;
