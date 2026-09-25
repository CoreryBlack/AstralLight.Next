//! 消息幂等服务
//!
//! 使用 Redis SETNX 实现 MQ 消息去重。每条消息处理前检查是否已处理，
//! 已处理则跳过，未处理则标记后正常消费。

use std::time::Duration;

use redis::AsyncCommands;

/// 消息幂等去重服务
pub struct MessageIdempotentService {
    redis: redis::aio::ConnectionManager,
    /// 幂等 key 的默认过期时间
    default_ttl: Duration,
}

impl MessageIdempotentService {
    /// 创建幂等服务
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self {
            redis,
            default_ttl: Duration::from_secs(86400), // 24h
        }
    }

    /// 检查消息是否已处理（原子操作）
    ///
    /// - 未处理：设置 key → 返回 `Ok(false)`
    /// - 已处理：返回 `Ok(true)`
    /// - Redis 错误：返回 `Err`
    pub async fn is_processed(
        &self,
        message_type: &str,
        message_id: &str,
    ) -> Result<bool, IdempotentError> {
        let key = format!("mq:idempotent:{message_type}:{message_id}");
        let mut conn = self.redis.clone();

        let result: bool = conn.set_nx(&key, "1").await?;

        if result {
            // 首次设置成功 → 消息未处理过，设置 TTL
            let _: Result<(), _> = conn
                .expire::<_, ()>(&key, self.default_ttl.as_secs() as i64)
                .await;
            Ok(false)
        } else {
            // key 已存在 → 消息已处理
            Ok(true)
        }
    }

    /// 显式标记消息为已处理（覆盖现有标记）
    pub async fn mark_processed(
        &self,
        message_type: &str,
        message_id: &str,
    ) -> Result<(), IdempotentError> {
        let key = format!("mq:idempotent:{message_type}:{message_id}");
        let mut conn = self.redis.clone();

        conn.set_ex::<_, _, ()>(key, "1", self.default_ttl.as_secs())
            .await?;
        Ok(())
    }

    /// 清除幂等标记（用于死信重试场景）
    pub async fn clear(&self, message_type: &str, message_id: &str) -> Result<(), IdempotentError> {
        let key = format!("mq:idempotent:{message_type}:{message_id}");
        let mut conn = self.redis.clone();

        conn.del::<_, ()>(&key).await?;
        Ok(())
    }
}

/// 幂等服务错误
#[derive(Debug, thiserror::Error)]
pub enum IdempotentError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

#[cfg(test)]
mod tests {
    // 测试依赖 Redis 实例，移入集成测试目录
    // 参见 crate::tests/
    #[test]
    fn test_stub() {
        // placeholder — real tests live in tests/redis_key_scope_tests.rs
    }
}
