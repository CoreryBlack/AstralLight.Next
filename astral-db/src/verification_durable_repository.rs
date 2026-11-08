//! Durable cross-replica verification repository（taskId
//! `global-authority-20261107-verification`）。
//!
//! 对应 migration `20261107000002_verification_durable.sql` 的三张表：
//! `verification_challenge`（HMAC 摘要挑战）、`verification_proof`（一次性
//! 目标绑定 proof）、`verification_budget`（跨副本主体预算）。
//!
//! 投递（outbox/intent/lease）刻意不在本模块：共享
//! `astral_common::delivery`（`DeliveryOwner` + `SqlxDeliveryIntentRepository`
//! over `al_delivery_intent`）拥有投递状态机，verification 只提供 purpose/
//! target 上下文与稳定 operation id，不建独立投递表、不启动独立 worker。
//!
//! ## 所有权边界（与 `repository.rs` verification fns 的分工）
//!
//! - 行 TTL 由调用方（astral-identity verification 服务）计算 `expires_at`
//!   时拥有；本模块只存储与按 TTL 过滤，不自造有效期。
//! - 全部语句都是单语句原语：原子性由调用方的**单一短事务**组合（supersede、
//!   预算递增、CAS 消费、proof 签发必须同事务提交/回滚）。本模块不持有事务
//!   生命周期，不产生部分提交。
//! - 明文边界：code 与 proof token 的明文永不落库；本模块只接收 32 字节
//!   HMAC 摘要（key 由调用方从受保护环境解析，绝不入 DB/日志/git）。
//! - 预算原子性：`bump_budget` 以主键行锁（InnoDB）实现跨副本原子递增，
//!   读回计数在同事务内；超限由调用方整体回滚（递增随之撤销），绝不放行
//!   超预算请求。
//! - GC：死行由有界扫描清理（`cleanup_expired_verification`），由调用方在
//!   签发路径机会式触发；本模块不启动后台 worker。
//! - 幂等：`operation_id` 由调用方保证显式稳定（HTTP `X-Operation-Id`），
//!   `uk_vch_operation` 兜底并发重复；唯一键冲突由调用方按幂等命中处理。

use sqlx::{Executor, MySql, MySqlPool};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use crate::repository::DbError;

/// 预算 scope：签发。
pub const SCOPE_SEND: &str = "SEND";
/// 预算 scope：校验。
pub const SCOPE_VERIFY: &str = "VERIFY";
/// 预算 scope：password-reset 发送预算（taskId
/// `authority-v7-peripheral-20261107`；复用 `verification_budget` 表，
/// scope/purpose 与 verification 键空间互不重叠，无 schema 变更）。
pub const SCOPE_PASSWORD_RESET: &str = "RESET";
/// 预算主体：验证目标（target_hash）。
pub const SUBJECT_TARGET: &str = "TARGET";
/// 预算主体：已解析客户端 IP（ip_hash）。
pub const SUBJECT_IP: &str = "IP";
/// password-reset 预算 purpose（ascii、≤32 字符，与 verification purpose
/// 键空间隔离）。
pub const PURPOSE_PASSWORD_RESET: &str = "password-reset";

fn prim_now() -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
}

/// 活跃挑战行（只暴露比对所需字段；摘要以字节比较，不转文本）。
#[derive(Debug, sqlx::FromRow)]
pub struct OpenChallenge {
    pub id: i64,
    pub code_digest: Vec<u8>,
    pub attempts: u32,
}

/// 挑战签发结果。`idempotent = true` 表示同 (operation_id, purpose) 的活跃
/// 挑战已存在（幂等重放，未消耗新预算、未作废旧挑战）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub challenge_id: i64,
    pub idempotent: bool,
}

/// 按显式 operation id 查找活跃（未关闭、未过期）挑战（幂等重放入口）。
pub async fn find_active_challenge_by_operation<'e, E>(
    executor: E,
    operation_id: &str,
    purpose: &str,
) -> Result<Option<i64>, DbError>
where
    E: Executor<'e, Database = MySql>,
{
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM verification_challenge \
             WHERE operation_id = ? AND purpose = ? AND closed_at IS NULL AND expires_at > NOW() \
             LIMIT 1",
    )
    .bind(operation_id)
    .bind(purpose)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// 原子预算递增：主键行锁下 upsert + 读回（同事务），返回是否仍在预算内。
///
/// 超预算时调用方必须让整个事务回滚——递增随事务撤销，绝不留下"拒绝但计数"
/// 的脏预算。跨副本由 InnoDB 主键行锁串行化：并发事务在 upsert 上阻塞至
/// 前序事务提交/回滚，计数读回不丢增。
pub async fn bump_budget(
    executor: &mut sqlx::MySqlConnection,
    scope: &str,
    subject_kind: &str,
    subject_hash: &[u8; 32],
    purpose: &str,
    window_start: PrimitiveDateTime,
    cap: i64,
) -> Result<bool, DbError> {
    sqlx::query(
        "INSERT INTO verification_budget \
         (scope, subject_kind, subject_hash, purpose, window_start, hit_count) \
         VALUES (?, ?, ?, ?, ?, 1) \
         ON DUPLICATE KEY UPDATE hit_count = hit_count + 1",
    )
    .bind(scope)
    .bind(subject_kind)
    .bind(subject_hash.as_slice())
    .bind(purpose)
    .bind(window_start)
    .execute(&mut *executor)
    .await?;
    let (count,): (i64,) = sqlx::query_as(
        "SELECT hit_count FROM verification_budget \
         WHERE scope = ? AND subject_kind = ? AND subject_hash = ? AND purpose = ? \
           AND window_start = ?",
    )
    .bind(scope)
    .bind(subject_kind)
    .bind(subject_hash.as_slice())
    .bind(purpose)
    .bind(window_start)
    .fetch_one(&mut *executor)
    .await?;
    Ok(count <= cap)
}

/// 跨副本 password-reset 发送预算（taskId `authority-v7-peripheral-20261107`）：
/// 同一短事务内按 (submitted identifier hash, resolved client IP hash) 递增。
/// 复用 `verification_budget` 主键行锁语义；`scope=RESET`、
/// `purpose=password-reset` 与 verification 键空间互不重叠（表无 CHECK 约束，
/// 无 schema 变更）。返回 `(within_target, within_ip)`；调用方超预算必须
/// 整体回滚（递增随事务撤销），绝不留下"拒绝但计数"的脏预算。
/// `subject_kind=TARGET` 承载提交标识（`HMAC(identifier)`，调用方域分隔），
/// `subject_kind=IP` 承载 `HMAC(resolved client IP)`。
pub async fn bump_password_reset_send_budget(
    executor: &mut sqlx::MySqlConnection,
    identifier_hashes: &[[u8; 32]],
    ip_hash: &[u8; 32],
    window_start: PrimitiveDateTime,
    cap_per_target: i64,
    cap_per_ip: i64,
) -> Result<Vec<bool>, DbError> {
    let mut within = Vec::with_capacity(identifier_hashes.len() + 1);
    for identifier_hash in identifier_hashes {
        within.push(
            bump_budget(
                executor,
                SCOPE_PASSWORD_RESET,
                SUBJECT_TARGET,
                identifier_hash,
                PURPOSE_PASSWORD_RESET,
                window_start,
                cap_per_target,
            )
            .await?,
        );
    }
    within.push(
        bump_budget(
            executor,
            SCOPE_PASSWORD_RESET,
            SUBJECT_IP,
            ip_hash,
            PURPOSE_PASSWORD_RESET,
            window_start,
            cap_per_ip,
        )
        .await?,
    );
    Ok(within)
}

/// 关闭同 (target_hash, purpose) 的全部活跃挑战（supersede：签发新挑战前
/// 调用；旧码从此不可再校验，不允许双活窗口）。返回关闭行数。
pub async fn close_open_challenges<'e, E>(
    executor: E,
    target_hash: &[u8; 32],
    purpose: &str,
) -> Result<u64, DbError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        "UPDATE verification_challenge \
         SET closed_at = NOW(), close_kind = 'SUPERSEDED' \
         WHERE target_hash = ? AND purpose = ? AND closed_at IS NULL",
    )
    .bind(target_hash.as_slice())
    .bind(purpose)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// 插入新挑战行（caller 已在同一事务内完成幂等检查/预算/supersede）。
/// 返回 durable 行 id（send/verify/proof 审计之间的稳定 correlation id）。
pub async fn insert_challenge<'e, E>(
    executor: E,
    purpose: &str,
    target_hash: &[u8; 32],
    code_digest: &[u8; 32],
    operation_id: &str,
    expires_at: PrimitiveDateTime,
) -> Result<i64, DbError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        "INSERT INTO verification_challenge \
         (purpose, target_hash, code_digest, operation_id, attempts, expires_at) \
         VALUES (?, ?, ?, ?, 0, ?)",
    )
    .bind(purpose)
    .bind(target_hash.as_slice())
    .bind(code_digest.as_slice())
    .bind(operation_id)
    .bind(expires_at)
    .execute(executor)
    .await?;
    if result.rows_affected() != 1 || result.last_insert_id() == 0 {
        return Err(DbError::Mapping(
            "verification challenge was not durably issued".into(),
        ));
    }
    Ok(result.last_insert_id() as i64)
}

/// 查找同 (target_hash, purpose) 的唯一活跃挑战（未关闭、未过期）。
/// 签发侧 supersede 保证同 key 至多一个活跃挑战；本查询只做候选选择，
/// 消费必须经 `close_challenge_and_issue_proof` 的 CAS。
pub async fn find_open_challenge<'e, E>(
    executor: E,
    target_hash: &[u8; 32],
    purpose: &str,
) -> Result<Option<OpenChallenge>, DbError>
where
    E: Executor<'e, Database = MySql>,
{
    let row = sqlx::query_as::<_, OpenChallenge>(
        "SELECT id, code_digest, attempts FROM verification_challenge \
         WHERE target_hash = ? AND purpose = ? AND closed_at IS NULL AND expires_at > NOW() \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(target_hash.as_slice())
    .bind(purpose)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// 原子尝试计数（摘要不匹配时调用）：CAS `attempts < max_attempts` 且未关闭；
/// 达到上限的同一语句路径内将挑战关闭（`EXHAUSTED`，fail-closed）。
/// 返回本次尝试是否仍被记录（挑战已关闭时为 false）。
pub async fn bump_challenge_attempts(
    executor: &mut sqlx::MySqlConnection,
    challenge_id: i64,
    max_attempts: u32,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE verification_challenge \
         SET attempts = attempts + 1 \
         WHERE id = ? AND closed_at IS NULL AND attempts < ?",
    )
    .bind(challenge_id)
    .bind(max_attempts)
    .execute(&mut *executor)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    // 达到上限即关闭（同事务内；无预算的挑战不再接受任何尝试）。
    sqlx::query(
        "UPDATE verification_challenge \
         SET closed_at = NOW(), close_kind = 'EXHAUSTED' \
         WHERE id = ? AND closed_at IS NULL AND attempts >= ?",
    )
    .bind(challenge_id)
    .bind(max_attempts)
    .execute(&mut *executor)
    .await?;
    Ok(true)
}

/// one-shot 消费挑战并同事务签发 proof（CAS：挑战未关闭才允许；proof 只存
/// HMAC 摘要）。任一步失败由调用方回滚整个事务，绝不出现"挑战已消费但
/// proof 未签发"的中间态。返回 proof 行 id。
pub async fn close_challenge_and_issue_proof(
    executor: &mut sqlx::MySqlConnection,
    challenge_id: i64,
    close_kind: &str,
    purpose: &str,
    target_hash: &[u8; 32],
    proof_hash: &[u8; 32],
    proof_expires_at: PrimitiveDateTime,
) -> Result<i64, DbError> {
    let closed = sqlx::query(
        "UPDATE verification_challenge \
         SET closed_at = NOW(), close_kind = ? \
         WHERE id = ? AND closed_at IS NULL",
    )
    .bind(close_kind)
    .bind(challenge_id)
    .execute(&mut *executor)
    .await?;
    if closed.rows_affected() != 1 {
        return Err(DbError::Mapping(
            "verification challenge was already consumed or expired".into(),
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO verification_proof \
         (purpose, target_hash, proof_hash, challenge_id, expires_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(purpose)
    .bind(target_hash.as_slice())
    .bind(proof_hash.as_slice())
    .bind(challenge_id)
    .bind(proof_expires_at)
    .execute(&mut *executor)
    .await?;
    if inserted.rows_affected() != 1 || inserted.last_insert_id() == 0 {
        return Err(DbError::Mapping(
            "verification proof was not durably issued".into(),
        ));
    }
    Ok(inserted.last_insert_id() as i64)
}

/// one-shot 消费 proof（CAS：purpose + target_hash 绑定 + 未消费 + 未过期）。
/// 必须在消费方的业务事务内调用（注册：用户插入同一事务）；返回 false 表示
/// proof 无效/过期/已消费/目标不匹配——调用方必须让业务事务回滚，绝不静默
/// 降级为无验证路径。
pub async fn consume_proof<'e, E>(
    executor: E,
    proof_hash: &[u8; 32],
    purpose: &str,
    target_hash: &[u8; 32],
    consumed_ref: Option<&str>,
) -> Result<bool, DbError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        "UPDATE verification_proof \
         SET consumed_at = NOW(), consumed_ref = ? \
         WHERE proof_hash = ? AND purpose = ? AND target_hash = ? \
           AND consumed_at IS NULL AND expires_at > NOW()",
    )
    .bind(consumed_ref)
    .bind(proof_hash.as_slice())
    .bind(purpose)
    .bind(target_hash.as_slice())
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 有界机会式 GC：删除过期超过 `retention` 的死行（挑战按 expires_at、proof
/// 按 expires_at、预算窗口按 window_start），单次每表最多 `limit` 行。走
/// idx_*_expires 索引，扫描量有界；失败只影响存储膨胀，调用方记录日志但不
/// 阻塞签发。返回 (challenges, proofs, budgets) 各表删除行数。
pub async fn cleanup_expired_verification(
    pool: &MySqlPool,
    retention: Duration,
    limit: u64,
) -> Result<(u64, u64, u64), DbError> {
    let cutoff_prim = prim_now() - retention;
    let challenges = sqlx::query("DELETE FROM verification_challenge WHERE expires_at < ? LIMIT ?")
        .bind(cutoff_prim)
        .bind(limit)
        .execute(pool)
        .await?
        .rows_affected();
    let proofs = sqlx::query("DELETE FROM verification_proof WHERE expires_at < ? LIMIT ?")
        .bind(cutoff_prim)
        .bind(limit)
        .execute(pool)
        .await?
        .rows_affected();
    let budgets = sqlx::query("DELETE FROM verification_budget WHERE window_start < ? LIMIT ?")
        .bind(cutoff_prim)
        .bind(limit)
        .execute(pool)
        .await?
        .rows_affected();
    Ok((challenges, proofs, budgets))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 集成前置：MySQL 可达且本 migration 已应用（主注册 schema）。
    /// 显式 ignored（AGENTS §10.0：完整 integration 必须用显式 ignored 命令
    /// 与真实依赖运行；无 env 时记 SKIP 而非 PASS）。
    async fn integration_pool() -> Option<MySqlPool> {
        let url = std::env::var("ASTRAL_VERIFICATION_TEST_MYSQL_URL").ok()?;
        if url.trim().is_empty() {
            return None;
        }
        Some(
            MySqlPool::connect(url.trim())
                .await
                .expect("connect test mysql"),
        )
    }

    /// 进程内唯一 32 字节测试向量（计数器填充，无加密语义，仅保证互异）。
    fn unique_subject(seed: &str) -> [u8; 32] {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut out = [0u8; 32];
        let seed_bytes = seed.as_bytes();
        out[..seed_bytes.len().min(16)].copy_from_slice(&seed_bytes[..seed_bytes.len().min(16)]);
        out[16..24].copy_from_slice(&n.to_le_bytes());
        out[24..32].copy_from_slice(&std::process::id().to_le_bytes());
        out
    }

    #[test]
    fn budget_window_and_scope_consts_are_stable() {
        assert_eq!(SCOPE_SEND, "SEND");
        assert_eq!(SCOPE_VERIFY, "VERIFY");
        assert_eq!(SUBJECT_TARGET, "TARGET");
        assert_eq!(SUBJECT_IP, "IP");
    }

    /// password-reset 预算键形态：与 verification 键空间互不重叠，且列宽
    /// 合同（scope VARCHAR(8) / purpose VARCHAR(32) ascii_bin）不被突破。
    #[test]
    fn password_reset_budget_keys_are_disjoint_and_bounded() {
        assert_eq!(SCOPE_PASSWORD_RESET, "RESET");
        assert_eq!(PURPOSE_PASSWORD_RESET, "password-reset");
        assert_ne!(SCOPE_PASSWORD_RESET, SCOPE_SEND);
        assert_ne!(SCOPE_PASSWORD_RESET, SCOPE_VERIFY);
        assert_ne!(PURPOSE_PASSWORD_RESET, "register");
        assert!(SCOPE_PASSWORD_RESET.len() <= 8);
        assert!(PURPOSE_PASSWORD_RESET.len() <= 32);
        assert!(
            PURPOSE_PASSWORD_RESET
                .chars()
                .all(|c| c.is_ascii() && !c.is_control()),
            "purpose must stay ascii (column charset ascii_bin)"
        );
    }

    /// 显式 ignored：真实 MySQL 集成（签发→幂等重放→预算超限→one-shot
    /// proof 消费→GC）。需要 ASTRAL_VERIFICATION_TEST_MYSQL_URL 且已应用
    /// migration 20261107000002。
    #[tokio::test]
    #[ignore = "requires ASTRAL_VERIFICATION_TEST_MYSQL_URL with migration 20261107000002 applied"]
    async fn durable_verification_roundtrip_and_budget_bounds() {
        let Some(pool) = integration_pool().await else {
            eprintln!("[SKIP] ASTRAL_VERIFICATION_TEST_MYSQL_URL not set");
            return;
        };
        let purpose = "register";
        let target = unique_subject("roundtrip-target");
        let ip = unique_subject("roundtrip-ip");
        static OP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let operation_id = format!(
            "op-{}-{}",
            std::process::id(),
            OP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let expires = prim_now() + Duration::minutes(5);

        // 签发（超预算上限设置远大于用例计数）。
        let issued = issue_challenge_tx(
            &pool,
            purpose,
            &target,
            &[9u8; 32],
            &operation_id,
            expires,
            &ip,
            100,
            100,
        )
        .await
        .expect("issue challenge");
        assert!(!issued.idempotent);

        // 幂等重放：同 operation id → 同一行，不产生新挑战。
        let replay = issue_challenge_tx(
            &pool,
            purpose,
            &target,
            &[9u8; 32],
            &operation_id,
            expires,
            &ip,
            100,
            100,
        )
        .await
        .expect("idempotent replay");
        assert!(replay.idempotent && replay.challenge_id == issued.challenge_id);

        // one-shot proof 消费：首次成功，二次失败（CAS）。
        let mut tx = pool.begin().await.expect("begin");
        let proof_expires = prim_now() + Duration::minutes(10);
        let proof_id = close_challenge_and_issue_proof(
            &mut tx,
            issued.challenge_id,
            "CONSUMED",
            purpose,
            &target,
            &[7u8; 32],
            proof_expires,
        )
        .await
        .expect("consume + issue proof");
        tx.commit().await.expect("commit");
        assert!(proof_id > 0);

        let consumed_again = consume_proof(&pool, &[7u8; 32], purpose, &target, Some("regression"))
            .await
            .expect("second consume must be CAS-rejected");
        assert!(!consumed_again, "proof must be one-shot");

        // 预算：cap=2 → 第 3 次递增超限（预算必须经行锁连接执行）。
        let window = prim_now();
        let mut conn = pool.acquire().await.expect("acquire budget connection");
        assert!(bump_budget(
            &mut conn,
            SCOPE_SEND,
            SUBJECT_TARGET,
            &target,
            purpose,
            window,
            2
        )
        .await
        .unwrap());
        assert!(bump_budget(
            &mut conn,
            SCOPE_SEND,
            SUBJECT_TARGET,
            &target,
            purpose,
            window,
            2
        )
        .await
        .unwrap());
        assert!(
            !bump_budget(
                &mut conn,
                SCOPE_SEND,
                SUBJECT_TARGET,
                &target,
                purpose,
                window,
                2
            )
            .await
            .unwrap(),
            "budget must fail closed at cap"
        );

        // 有界 GC 可执行（不校验删除量，只验证路径可用）。
        let _ = cleanup_expired_verification(&pool, Duration::ZERO, 10)
            .await
            .expect("gc");
    }

    /// 组合事务助手（镜像 identity 服务侧签发事务形状，供集成用例复用）。
    #[allow(clippy::too_many_arguments)]
    async fn issue_challenge_tx(
        pool: &MySqlPool,
        purpose: &str,
        target_hash: &[u8; 32],
        code_digest: &[u8; 32],
        operation_id: &str,
        expires_at: PrimitiveDateTime,
        ip_hash: &[u8; 32],
        cap_target: i64,
        cap_ip: i64,
    ) -> Result<IssuedChallenge, DbError> {
        let mut tx = pool.begin().await?;
        if let Some(id) =
            find_active_challenge_by_operation(&mut *tx, operation_id, purpose).await?
        {
            tx.commit().await?;
            return Ok(IssuedChallenge {
                challenge_id: id,
                idempotent: true,
            });
        }
        let window = prim_now();
        let within_target = bump_budget(
            &mut tx,
            SCOPE_SEND,
            SUBJECT_TARGET,
            target_hash,
            purpose,
            window,
            cap_target,
        )
        .await?;
        let within_ip = bump_budget(
            &mut tx, SCOPE_SEND, SUBJECT_IP, ip_hash, purpose, window, cap_ip,
        )
        .await?;
        if !(within_target && within_ip) {
            return Err(DbError::Mapping("verification send budget exceeded".into()));
        }
        close_open_challenges(&mut *tx, target_hash, purpose).await?;
        let challenge_id = insert_challenge(
            &mut *tx,
            purpose,
            target_hash,
            code_digest,
            operation_id,
            expires_at,
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedChallenge {
            challenge_id,
            idempotent: false,
        })
    }
}
