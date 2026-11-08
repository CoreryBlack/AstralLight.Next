//! AstralLight 共享类型定义
//!
//! 本 crate 包含跨模块共享的核心类型：权限评估引擎的输入/输出类型、
//! 错误模型、资源注册表等。不依赖数据库、缓存、MQ 等外部基础设施。

pub mod authority_protocol;
mod authorization_authority;
mod context;
mod cross_city;
mod decision;
mod edition;
mod eligibility;
mod entities;
mod error;
mod grant;
mod org_authority_proof;
/// 组织范围（ORG_SCOPE）共享类型合同 — Phase 2 default-off（types owner 维护）。
pub mod org_scope;
mod projection;
mod publication;
pub mod registry;
mod request_binding;
mod rule_set;

pub use authority_protocol::*;
pub use authorization_authority::*;
pub use context::*;
pub use cross_city::*;
pub use decision::*;
pub use edition::*;
pub use eligibility::*;
pub use entities::*;
pub use error::*;
pub use grant::*;
pub use org_authority_proof::*;
pub use projection::*;
pub use publication::*;
pub use registry::*;
pub use request_binding::*;
pub use rule_set::*;
