//! 用户分级数据访问 — GradingRepository
//!
//! 对齐 Java `IdentityUserGradingMapper` 边界（identity_user_grading 表）。
//! 创建走 `INSERT ... ON DUPLICATE KEY UPDATE` 幂等（uk_iug_user_domain）。
//!
//! ## 源写栅栏（memory ownership 读面合同）
//!
//! `identity_user_grading` 是受保护资源 resolver（`TargetLookupKind::UserGrading`）
//! 的 ownership 事实面：本仓全部 mutation（upsert/delete）在内存投影 hub 已
//! 安装时必须先取得 hub source writer 栅栏
//! （`astral_db::memory_projection_hub::acquire_source_guard`）再执行：
//! - hub 未安装（独立部署/纯测试）→ `Ok(None)`，行为完全不变；
//! - hub 已安装而拒发证 → `Err` fail-closed，绝不静默 no-op；
//! - 单条 autocommit 语句 await 前 arm、结果判定后 settle（Ok → proven；
//!   Err → sticky uncertain）；await 窗口内任务取消 → 栅栏随 future Drop 且
//!   unproven → hub sticky uncertain（提交结果未知绝不当作已回滚）。
//!
//! 栅栏 Drop 统一失效正向读缓存并推进 hub 纪元/token，使 ownership 记忆
//! 读面与本仓事实即时一致。

use std::future::Future;

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::memory_projection_hub::SourceTransactionGuard;
use astral_types::AstralError;

/// 用户分级记录（identity_user_grading）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GradingRecord {
    pub id: i64,
    pub user_id: i64,
    pub level_id: i64,
    pub domain_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（user_id / domain_id 可选）
#[derive(Debug, Default)]
pub struct GradingFilter {
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
}

const GRADING_SELECT_COLUMNS: &str = "id, user_id, level_id, domain_id, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

#[async_trait]
pub trait GradingRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_gradings(&self, filter: &GradingFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY user_id, domain_id）
    async fn list_gradings(
        &self,
        filter: &GradingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GradingRecord>, AstralError>;
    /// 等级是否存在且 ACTIVE（创建校验，对齐现有 handler 语义）
    async fn level_exists_in_domain(
        &self,
        level_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError>;
    /// 幂等 upsert（uk_iug_user_domain，单用户单域唯一）
    async fn upsert_grading(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError>;
    /// upsert 后查回（用户+域唯一，应存在）
    async fn get_grading(&self, user_id: i64, domain_id: i64)
        -> Result<GradingRecord, AstralError>;
    /// 删除，返回是否命中
    async fn delete_grading(&self, id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxGradingRepository {
    db: MySqlPool,
}

impl SqlxGradingRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// fail-closed 取得 hub 源写栅栏（与 astral-identity `source_writer_guard`
/// 同合同；本文件本地持有以避免跨文件 ownership 交叠）：委托 canonical
/// `acquire_source_guard`，不复制第二份 begin 语义。
fn begin_source_write() -> Result<Option<SourceTransactionGuard>, AstralError> {
    astral_db::memory_projection_hub::acquire_source_guard()
}

/// 单条 autocommit 源语句的围栏执行：await 前 arm，结果判定后 settle。
/// 栅栏按值移入本 future：await 窗口内任务被取消 → 栅栏随 future Drop 且
/// unproven → hub sticky uncertain。
async fn fenced_source_write<T, E, F>(
    source_guard: Option<SourceTransactionGuard>,
    write: F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    if let Some(guard) = &source_guard {
        guard.mark_commit_started();
    }
    let result = write.await;
    if let Some(guard) = &source_guard {
        if result.is_ok() {
            guard.mark_commit_proven();
        } else {
            guard.mark_uncertain();
        }
    }
    result
}

/// 向 QueryBuilder 追加 user_id / domain_id 过滤（列表与总数共用同一条件）
fn push_grading_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &GradingFilter,
) {
    if let Some(user_id) = filter.user_id {
        builder.push(" AND user_id = ").push_bind(user_id);
    }
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
}

#[async_trait]
impl GradingRepository for SqlxGradingRepository {
    async fn count_gradings(&self, filter: &GradingFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(*) FROM identity_user_grading WHERE 1=1",
        );
        push_grading_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_gradings(
        &self,
        filter: &GradingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GradingRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {GRADING_SELECT_COLUMNS} FROM identity_user_grading WHERE 1=1"
        ));
        push_grading_filter(&mut builder, filter);
        builder
            .push(" ORDER BY user_id, domain_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<GradingRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn level_exists_in_domain(
        &self,
        level_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_card_level_definition \
             WHERE level_id = ? AND domain_id = ? AND status = 'ACTIVE'",
        )
        .bind(level_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count > 0)
    }

    async fn upsert_grading(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError> {
        let source_guard = begin_source_write()?;
        fenced_source_write(source_guard, async {
            sqlx::query(
                "INSERT INTO identity_user_grading (user_id, level_id, domain_id) \
                 VALUES (?, ?, ?) \
                 ON DUPLICATE KEY UPDATE level_id = VALUES(level_id)",
            )
            .bind(user_id)
            .bind(level_id)
            .bind(domain_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
            Ok(())
        })
        .await
    }

    async fn get_grading(
        &self,
        user_id: i64,
        domain_id: i64,
    ) -> Result<GradingRecord, AstralError> {
        sqlx::query_as::<_, GradingRecord>(&format!(
            "SELECT {GRADING_SELECT_COLUMNS} FROM identity_user_grading WHERE user_id = ? AND domain_id = ?"
        ))
        .bind(user_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_grading(&self, id: i64) -> Result<bool, AstralError> {
        let source_guard = begin_source_write()?;
        fenced_source_write(source_guard, async {
            let result = sqlx::query("DELETE FROM identity_user_grading WHERE id = ?")
                .bind(id)
                .execute(&self.db)
                .await
                .map_err(db_error)?;
            Ok(result.rows_affected() > 0)
        })
        .await
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Grading repository query failed: {error}"))
}

#[cfg(test)]
mod source_writer_fence_tests {
    use super::*;
    use astral_db::memory_projection_hub::MemoryProjectionHub;

    /// 生产段源码（测试段之前）：结构断言只看生产代码。
    fn production_source() -> &'static str {
        include_str!("grading_repository.rs")
            .split(concat!("#[", "cfg(test)]"))
            .next()
            .expect("production section must exist")
    }

    /// 按 marker 取函数体（含签名）。trait 声明以 `;` 结束、实现体先出现
    /// `{` —— 逐个 marker 命中处跳过 trait 声明，只匹配实现体。
    fn function_body(source: &'static str, marker: &str) -> &'static str {
        let mut search_from = 0usize;
        while let Some(relative) = source[search_from..].find(marker) {
            let start = search_from + relative;
            let after_marker = start + marker.len();
            let body_open = match (
                source[after_marker..].find('{'),
                source[after_marker..].find(';'),
            ) {
                (Some(brace), Some(semicolon)) if brace < semicolon => after_marker + brace,
                (Some(brace), None) => after_marker + brace,
                _ => {
                    search_from = after_marker;
                    continue;
                }
            };
            let mut depth = 0usize;
            for (offset, character) in source[body_open..].char_indices() {
                match character {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            let end = body_open + offset;
                            return &source[start..=end];
                        }
                    }
                    _ => {}
                }
            }
            panic!("function body must close: {marker}");
        }
        panic!("function body must exist: {marker}");
    }

    /// 每个 mutation 必须先取栅栏并在栅栏窗口内执行 SQL；只读方法不得
    /// 触发栅栏。
    #[test]
    fn every_mutating_statement_runs_inside_the_fenced_source_writer() {
        let source = production_source();
        for name in ["upsert_grading", "delete_grading"] {
            let body = function_body(source, name);
            assert!(
                body.contains("let source_guard = begin_source_write()?;"),
                "{name} must acquire the hub source writer fence before its SQL"
            );
            assert!(
                body.contains("fenced_source_write("),
                "{name} must execute its write inside the fenced writer"
            );
            let fence = body
                .find("fenced_source_write(")
                .expect("fence call checked above");
            let execute = body
                .rfind(".execute(")
                .expect("mutating fn must execute SQL");
            assert!(
                fence < execute,
                "{name} must not execute SQL outside the fenced writer window"
            );
        }
        assert_eq!(
            source
                .matches("let source_guard = begin_source_write()?;")
                .count(),
            2,
            "fence acquisition count must match the mutating statement count"
        );
        for name in [
            "count_gradings",
            "list_gradings",
            "level_exists_in_domain",
            "get_grading",
        ] {
            assert!(
                !function_body(source, name).contains("begin_source_write()"),
                "{name} is read-only and must not touch the writer fence"
            );
        }
    }

    /// 栅栏生命周期次序：arm 先于 write.await；Ok → proven / 非 proven →
    /// uncertain 都在 await 之后。
    #[test]
    fn fence_helper_arms_before_await_and_settles_after_the_result() {
        let body = function_body(
            production_source(),
            "async fn fenced_source_write<T, E, F>(",
        );
        let arm = body
            .find("guard.mark_commit_started()")
            .expect("the arm call must exist");
        let await_point = body
            .find("write.await")
            .expect("the write await must exist");
        let proven = body
            .find("guard.mark_commit_proven()")
            .expect("the proven settle must exist");
        let uncertain = body
            .find("guard.mark_uncertain()")
            .expect("the uncertain settle must exist");
        assert!(
            arm < await_point,
            "the commit fence must be armed before awaiting the write"
        );
        assert!(
            await_point < proven && await_point < uncertain,
            "both settles must happen after the write outcome is known"
        );
    }

    // ── 栅栏生命周期行为（本地 hub 实例，不安装进程级 global）────────────

    #[tokio::test]
    async fn fenced_write_ok_proves_and_releases_the_writer_gate() {
        let hub = MemoryProjectionHub::default();
        let guard = hub.begin_source_transaction();
        let result: Result<u8, ()> = fenced_source_write(guard, std::future::ready(Ok(7))).await;
        assert_eq!(result, Ok(7));
        assert!(!hub.has_active_source_writer(), "guard must be released");
        assert!(
            !hub.channel_is_suspect(),
            "proven write must not stay suspect"
        );
    }

    #[tokio::test]
    async fn fenced_write_err_marks_uncertain_sticky() {
        let hub = MemoryProjectionHub::default();
        let guard = hub.begin_source_transaction();
        let result: Result<(), u8> = fenced_source_write(guard, std::future::ready(Err(1))).await;
        assert_eq!(result, Err(1));
        assert!(
            !hub.has_active_source_writer(),
            "guard must still be released"
        );
        assert!(hub.channel_is_suspect(), "failed write must stay suspect");
    }

    /// await 窗口内任务被 abort：已武装的栅栏随 future Drop → sticky
    /// uncertain（提交结果未知绝不当作已回滚）。
    #[tokio::test]
    async fn cancellation_mid_write_leaves_the_outcome_unknown() {
        let hub = MemoryProjectionHub::default();
        let guard = hub.begin_source_transaction();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (_gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = fenced_source_write(guard, async move {
                let _ = started_tx.send(());
                let _ = gate_rx.await;
                Ok::<(), ()>(())
            })
            .await;
        });
        started_rx
            .await
            .expect("the fenced write must start and signal");
        task.abort();
        let _ = task.await;
        assert!(
            !hub.has_active_source_writer(),
            "the cancelled task must release the writer gate via Drop"
        );
        assert!(
            hub.channel_is_suspect(),
            "cancelling an armed write await must leave sticky uncertain_source"
        );
    }

    /// hub 未安装（None 栅栏）：围栏执行为纯透传，行为不变。
    #[tokio::test]
    async fn missing_hub_guard_is_a_passthrough() {
        let result: Result<&str, ()> =
            fenced_source_write(None, std::future::ready(Ok("ok"))).await;
        assert_eq!(result, Ok("ok"));
        let result: Result<(), ()> = fenced_source_write(None, std::future::ready(Err(()))).await;
        assert!(result.is_err());
    }

    /// 前置事实：本测试二进制不安装进程级 hub。hub 未安装必须 Ok(None)、
    /// 绝不报错（fail-closed 拒绝只在 hub 已装而拒发证时发生）。
    #[test]
    fn hub_not_installed_yields_a_none_guard_not_a_refusal() {
        let guard = begin_source_write().expect("a missing hub must not refuse");
        assert!(guard.is_none(), "no hub must yield no guard");
    }
}
