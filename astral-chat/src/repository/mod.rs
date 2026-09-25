//! 聊天域数据访问层（对齐 Java `ChatMapper` 边界）
//!
//! Repository 返回领域 record + `AstralError`，不返回 Axum/HTTP 类型；
//! 多实体事务（如群主转让）收敛为 repository 聚合方法；MQ/WS 副作用由 service 编排。

pub mod client_session_repository;
pub mod conversation_repository;
pub mod member_repository;
pub mod message_repository;
