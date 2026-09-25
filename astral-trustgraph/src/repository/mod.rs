//! TrustGraph 数据访问层（Repository Port + SQLx Adapter）
//!
//! 对齐 Java Infrastructure Mapper 边界：Repository 仅返回领域 record 与
//! `AstralError`，不返回 Axum/HTTP 类型。HTTP handler 负责参数解析与响应包装。
//!
//! 第一批：6 个纯 CRUD 单表模块；第二批：规则/规则集/委托写路径
//! （副作用链编排在 `service` 层，不在 repository）；
//! 第四批：剩余纯 CRUD 模块（部门/套餐/继承/动作/资源类型/审计/SoD/命中统计）。

pub mod admin_group_repository;
pub mod audit_log_repository;
pub mod card_template_repository;
pub mod cross_org_grant_repository;
pub mod delegation_repository;
pub mod department_repository;
pub mod domain_repository;
pub mod global_admin_repository;
pub mod grading_repository;
pub mod grant_ledger_adapter;
pub mod hit_stat_repository;
pub mod inheritance_config_repository;
pub mod level_repository;
pub mod level_template_repository;
pub mod permission_action_repository;
pub mod permission_request_repository;
pub mod platform_package_repository;
pub mod projection_repository;
pub mod resource_type_repository;
pub mod rule_repository;
pub mod rule_set_repository;
pub mod sod_repository;
pub mod template_repository;
pub mod tenant_repository;
pub mod user_card_repository;
