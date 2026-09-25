//! AstralLight 缓存层
//!
//! 提供 Redis 缓存封装：
//! - `CachedRuleRepository`：RuleRepository 的缓存包装，减少数据库查询
//! - `MessageIdempotentService`：MQ 消息幂等去重（Redis SETNX）

mod cache_repository;
mod idempotent;

pub use cache_repository::*;
pub use idempotent::*;
