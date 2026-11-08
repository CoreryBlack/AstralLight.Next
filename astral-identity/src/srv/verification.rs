//! 邮箱/手机验证服务（durable 跨副本）
//!
//! 对应 Java `VerificationServiceImpl`。taskId
//! `global-authority-20261107-verification`：验证语义升级为 durable
//! cross-replica —— 挑战/proof/预算全部持久化（投递 intent 由共享
//! `astral_common::delivery` 状态机拥有；migration
//! `20261107000002_verification_durable.sql`），摘要化存储（HMAC-SHA256，
//! 受保护环境密钥），跨副本预算原子生效。
//!
//! ## TTL/GC 所有权
//!
//! - 行 TTL 由本服务拥有（`durable::CHALLENGE_TTL` → `expires_at`；proof
//!   TTL 同理），仓储层不自造有效期。
//! - Supersession 由服务层在签发事务内通过仓储层 `close_open_challenges`
//!   拥有：同一 (target_hash, purpose) 至多一个未关闭挑战。
//! - GC 由本服务触发、仓储层执行：签发成功后机会式调用有界
//!   `cleanup_expired_verification`（三表 retention 之后死行，单次有界），
//!   失败只记日志不阻塞签发；本服务不启动后台 worker。
//!
//! ## 稳定 operation/audit correlation
//!
//! - send 必须携带显式稳定 `X-Operation-Id`（校验规则见 durable 模块）：
//!   同 (operation id, purpose) 的活跃挑战幂等返回既有行，不消耗新预算、
//!   不作废旧挑战；并发重复由 `uk_vch_operation` 兜底。
//! - durable 行 id（`challenge_id`）是 send/verify/proof 审计之间的稳定
//!   correlation id：durable 签发后记录 `VERIFICATION_CODE_ISSUED`，one-shot
//!   CAS 消费成功后记录 `VERIFICATION_CODE_VERIFIED`（`AuditEventType`
//!   契约位于 astral-common/src/audit.rs，MQ/DB 双写按 serde wire 值传播）。
//!   审计写入遵循既有非关键身份审计语义（MQ-first DB-fallback 双写；writer
//!   缺失或审计任务未被接纳时退化为结构化 tracing，绝不阻塞签发/校验主链）。
//!   user_id 使用既有匿名 0 哨兵（bootstrap 路径无认证主体）。
//!
//! ## 明文边界（fail-closed）
//!
//! 验证码与 proof token 的明文永不落库、不入日志：DB 只存 HMAC-SHA256
//! 摘要（域分隔绑定 purpose + target_hash），密钥来自
//! `ASTRAL_VERIFICATION_HMAC_KEY`（缺失/过短 → 全部验证操作拒绝）。
//! 预算主体（target / 已解析客户端 IP）同样只以 HMAC 摘要入库。
//!
//! ## 预算（durable 跨副本，替代进程内计数器）
//!
//! - SEND：每 target / 每 IP 在窗口内原子递增（超限拒绝并整体回滚，不留
//!   脏计数）；VERIFY：同语义，另加挑战行内原子尝试上限（`MAX_CHALLENGE_
//!   ATTEMPTS`，达到即关闭挑战，fail-closed）。跨副本由主键行锁保证。
//! - 客户端 IP 解析复用共享限流器语义（同一 trusted_proxy_ips 配置、同一
//!   rightmost-untrusted 链）；无对端扩展时聚合固定哨兵主体，不放宽。
//!
//! ## purpose 注册表（兼容行为，已登记）
//!
//! 只有具备真实同事务消费方的 purpose 才允许签发/校验（当前仅
//! `register`，消费方 = register 端点在用户插入事务内 one-shot CAS 消费
//! proof）。RESET/SENSITIVE 等尚未绑定消费方的 purpose 一律拒绝——收窄
//! 既有"任意 purpose 可签发"行为，属已登记的 fail-closed 兼容变更。
//!
//! ## proof 契约（替代旧 inert UUID token）
//!
//! verify 成功在同一事务内关闭挑战并签发 `verification_proof` 行（one-shot、
//! purpose+target 绑定、短 TTL），返回其不透明 token（仅此一次出库；DB 只存
//! 摘要）。消费方（register）在自身业务事务内经 `consume_proof` CAS 消费：
//! 无效/过期/已消费/目标不匹配 → 业务事务回滚，绝不静默降级为无验证路径。
//! 旧的不落库 UUID token 不再签发。

pub(crate) mod durable;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use rand::Rng;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, PrimitiveDateTime};

use astral_common::audit::{
    audit_event_type_name, global_audit_dual_write, record_audit, spawn_owned_audit, AuditCategory,
    AuditEntry, AuditEventType,
};
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_common::middleware::constant_time_eq;
use astral_db::verification_durable_repository as vrepo;
use astral_types::AstralError;

use crate::AppState;

/// GC 保留窗口：死行（已消费/已关闭或已过期）在过期后仍保留该时长供短期
/// 核对，之后由有界扫描删除（覆盖 challenge/proof/budget 三表）。
const GC_RETENTION: time::Duration = time::Duration::hours(24);

/// 单次 GC 扫描的每表最大删除行数（有界，避免签发路径出现无界删除）。
const GC_BATCH_LIMIT: u64 = 100;

/// DbError → AppError 辅助转换
fn db_err(e: astral_db::DbError) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// 裸 sqlx::Error（事务 begin/commit 边界）→ AppError 辅助转换。
fn sql_err(e: sqlx::Error) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// HMAC 密钥不可用（服务端配置缺失）→ fail-closed 拒绝。
fn key_unavailable() -> AppError {
    AppError::from(AstralError::Database(format!(
        "verification HMAC key unavailable (env {})",
        durable::HMAC_ENV_KEY
    )))
}

fn prim_now_plus(duration: time::Duration) -> PrimitiveDateTime {
    let deadline = OffsetDateTime::now_utc().saturating_add(duration);
    PrimitiveDateTime::new(deadline.date(), deadline.time())
}

/// 审计关联 detail 上界：purpose 是客户端输入，进入有界 detail 前按字符
/// 边界截断（共享 `truncate_at_char_boundary` 合同），整体远小于共享
/// AUDIT_DETAIL_MAX_BYTES 重放上界。
const AUDIT_PURPOSE_MAX_BYTES: usize = 64;

/// 验证码审计关联 detail（有界）：稳定 correlation id 是 durable 行 id
/// （challenge id），send 与 verify 两条审计通过同一 id 关联；验证码明文
/// 永不进入审计 detail。
fn verification_audit_detail(code_id: i64, purpose: &str) -> String {
    format!(
        "codeId={code_id};purpose={}",
        astral_common::audit::truncate_at_char_boundary(purpose, AUDIT_PURPOSE_MAX_BYTES)
    )
}

/// 验证码审计（非关键身份审计语义，对齐 login/cards 审计惯例）：
/// 走共享 MQ-first DB-fallback 双写；writer 未初始化或审计任务未被接纳
/// （容量上限/停机关闭）时退化为结构化 tracing 兜底，绝不阻塞签发或校验
/// 主链，绝不影响 HTTP 结果。user_id 使用既有匿名 0 哨兵（验证码路由为
/// bootstrap 路径、无认证主体；audit_log.user_id NOT NULL，与 login 失败
/// 审计的匿名哨兵一致）。`action`/`event_type` 由调用方在 durable 边界
/// 处固定，`code_id` 是与对端审计事件的唯一稳定关联。
fn spawn_verification_code_audit(
    event_type: AuditEventType,
    action: &'static str,
    code_id: i64,
    purpose: &str,
) {
    let entry = AuditEntry {
        // 匿名 actor 哨兵（见上方契约说明）。
        user_id: Some(0),
        card_id: None,
        action: action.to_string(),
        resource: "verification_code".into(),
        decision: "ALLOW".into(),
        reason: Some(audit_event_type_name(&event_type)),
        event_type,
        category: Some(AuditCategory::IdentityEvent),
        source_ip: None,
        request_id: None,
        domain_id: None,
        tenant_id: None,
        detail: Some(verification_audit_detail(code_id, purpose)),
    };
    let Some(writer) = global_audit_dual_write() else {
        record_audit(entry);
        return;
    };
    let fallback = entry.clone();
    if let Err(reason) = spawn_owned_audit(async move { writer.write(entry).await }) {
        tracing::warn!(
            reason,
            "verification audit task was not admitted; falling back to structured log"
        );
        record_audit(fallback);
    }
}

/// 验证码路由
pub fn verification_routes() -> Router<AppState> {
    Router::new()
        .route("/verification/send", post(send_code))
        .route("/verification/verify", post(verify_code))
}

/// 验证码请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendCodeRequest {
    pub target: String,
    pub purpose: String,
}

/// 验证验证码请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCodeRequest {
    pub target: String,
    pub code: String,
    pub purpose: String,
}

/// 验证码响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    pub verified: bool,
    pub token: Option<String>,
}

/// 判定仓储错误是否为 operation id 唯一键冲突（并发幂等重放竞争）。
fn is_duplicate_operation(error: &astral_db::DbError) -> bool {
    match error {
        astral_db::DbError::Query(err) => err
            .as_database_error()
            .map(|db| {
                db.code().as_deref() == Some("1062") || db.message().contains("Duplicate entry")
            })
            .unwrap_or(false),
        _ => false,
    }
}

/// 签发 durable 挑战：单一短事务内完成幂等检查 → SEND 预算（target+IP）→
/// supersede → 插入。预算超限返回错误（整个事务回滚，递增撤销）；同
/// (operation_id, purpose) 幂等命中直接返回既有行。投递由共享 delivery
/// owner 承接（无独立投递表/worker）。
async fn issue_challenge(
    pool: &sqlx::MySqlPool,
    purpose: &str,
    target_hash: &[u8; 32],
    digest: &[u8; 32],
    operation_id: &str,
    expires_at: PrimitiveDateTime,
    ip_hash: &[u8; 32],
) -> Result<vrepo::IssuedChallenge, AppError> {
    let mut tx = pool.begin().await.map_err(sql_err)?;
    if let Some(id) = vrepo::find_active_challenge_by_operation(&mut *tx, operation_id, purpose)
        .await
        .map_err(db_err)?
    {
        return Ok(vrepo::IssuedChallenge {
            challenge_id: id,
            idempotent: true,
        });
    }
    let window = durable::budget_window_start(OffsetDateTime::now_utc(), durable::SEND_WINDOW);
    let within_target = vrepo::bump_budget(
        &mut tx,
        vrepo::SCOPE_SEND,
        vrepo::SUBJECT_TARGET,
        target_hash,
        purpose,
        window,
        durable::SEND_CAP_PER_TARGET,
    )
    .await
    .map_err(db_err)?;
    let within_ip = vrepo::bump_budget(
        &mut tx,
        vrepo::SCOPE_SEND,
        vrepo::SUBJECT_IP,
        ip_hash,
        purpose,
        window,
        durable::SEND_CAP_PER_IP,
    )
    .await
    .map_err(db_err)?;
    if !(within_target && within_ip) {
        // tx drop → 回滚：预算递增随之撤销，绝不留下"拒绝但计数"的脏状态。
        return Err(AppError::from(AstralError::Auth(
            "Too many verification code requests, please retry later".into(),
        )));
    }
    vrepo::close_open_challenges(&mut *tx, target_hash, purpose)
        .await
        .map_err(db_err)?;
    let challenge_id = match vrepo::insert_challenge(
        &mut *tx,
        purpose,
        target_hash,
        digest,
        operation_id,
        expires_at,
    )
    .await
    {
        Ok(id) => id,
        Err(error) if is_duplicate_operation(&error) => {
            // 并发同 op 竞争：胜者已提交。本事务回滚后按幂等命中返回。
            drop(tx);
            let id = vrepo::find_active_challenge_by_operation(pool, operation_id, purpose)
                .await
                .map_err(db_err)?
                .ok_or_else(|| {
                    AppError::from(AstralError::Database(
                        "verification operation id race lost".into(),
                    ))
                })?;
            return Ok(vrepo::IssuedChallenge {
                challenge_id: id,
                idempotent: true,
            });
        }
        Err(error) => return Err(db_err(error)),
    };
    // 投递状态机由共享 astral_common::delivery（DeliveryOwner +
    // SqlxDeliveryIntentRepository）拥有：verification 不建投递表、不启动
    // worker；签发只产出稳定 operation id 供后续投递关联。
    tx.commit().await.map_err(sql_err)?;
    Ok(vrepo::IssuedChallenge {
        challenge_id,
        idempotent: false,
    })
}

/// 校验 durable 挑战：单一短事务内完成 VERIFY 预算（target+IP）→ 查找活跃
/// 挑战 → 摘要恒时比对 → 失败路径原子尝试计数（达上限关闭挑战）；成功路径
/// 同事务 one-shot 关闭挑战并签发 proof（无"已消费但无 proof"中间态）。
/// `Ok(None)` = 校验失败（无效码或无活跃挑战），预算与尝试计数已持久化。
async fn consume_challenge_issue_proof(
    pool: &sqlx::MySqlPool,
    key: &[u8],
    purpose: &str,
    target_hash: &[u8; 32],
    provided_digest: &[u8; 32],
    ip_hash: &[u8; 32],
) -> Result<Option<(i64, String)>, AppError> {
    let mut tx = pool.begin().await.map_err(sql_err)?;
    let window = durable::budget_window_start(OffsetDateTime::now_utc(), durable::VERIFY_WINDOW);
    let within_target = vrepo::bump_budget(
        &mut tx,
        vrepo::SCOPE_VERIFY,
        vrepo::SUBJECT_TARGET,
        target_hash,
        purpose,
        window,
        durable::VERIFY_CAP_PER_TARGET,
    )
    .await
    .map_err(db_err)?;
    let within_ip = vrepo::bump_budget(
        &mut tx,
        vrepo::SCOPE_VERIFY,
        vrepo::SUBJECT_IP,
        ip_hash,
        purpose,
        window,
        durable::VERIFY_CAP_PER_IP,
    )
    .await
    .map_err(db_err)?;
    if !(within_target && within_ip) {
        return Err(AppError::from(AstralError::Auth(
            "Too many verification attempts, please request a new code".into(),
        )));
    }
    let Some(row) = vrepo::find_open_challenge(&mut *tx, target_hash, purpose)
        .await
        .map_err(db_err)?
    else {
        // 无活跃挑战：预算递增照常持久化（防枚举），返回统一失败语义。
        tx.commit().await.map_err(sql_err)?;
        return Ok(None);
    };
    if !constant_time_eq(provided_digest, &row.code_digest) {
        // 原子尝试计数：达上限同路径关闭挑战（EXHAUSTED，fail-closed）。
        vrepo::bump_challenge_attempts(&mut tx, row.id, durable::MAX_CHALLENGE_ATTEMPTS)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(sql_err)?;
        return Ok(None);
    }
    // one-shot：关闭挑战 + 同事务签发 proof（明文 token 只出库一次）。
    let proof_token = durable::proof_token();
    let proof_hash = durable::proof_hash(key, purpose, target_hash, &proof_token);
    let proof_id = vrepo::close_challenge_and_issue_proof(
        &mut tx,
        row.id,
        "CONSUMED",
        purpose,
        target_hash,
        &proof_hash,
        prim_now_plus(durable::PROOF_TTL),
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(sql_err)?;
    tracing::info!(
        challenge_id = row.id,
        proof_id,
        purpose,
        "verification challenge consumed; durable one-shot proof issued"
    );
    Ok(Some((row.id, proof_token)))
}

/// POST /api/v1/auth/verification/send — 签发 durable 验证挑战
///
/// 必须携带显式稳定 `X-Operation-Id`；purpose 必须在注册表内（当前仅
/// register）。本路由保持 bootstrap 例外（无 AuthorizationAdmission）；验证
/// 码明文不入库不入日志。预算（target/IP）与 supersede 在同一短事务内生效。
async fn send_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: ConnectInfo<SocketAddr>,
    Json(req): Json<SendCodeRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // purpose 注册表：未绑定真实消费方一律拒绝（已登记兼容行为）。
    if !durable::is_registered_purpose(&req.purpose) {
        tracing::warn!(purpose = %req.purpose, "unregistered verification purpose rejected (fail closed)");
        return Err(AppError::from(AstralError::Validation(
            "purpose is not accepted for verification".into(),
        )));
    }
    let operation_id = durable::validate_operation_id(
        headers
            .get("X-Operation-Id")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|reason| AppError::from(AstralError::Validation(reason.into())))?;
    let key = durable::hmac_key().ok_or_else(key_unavailable)?;

    // gen_range 避免取模偏差；空间仍为 10^6，穷举由 durable 预算 + 原子尝试
    // 上限阻断（跨副本）。
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let target_hash = durable::target_hash(key, &req.target);
    let digest = durable::code_digest(key, &req.purpose, &target_hash, &code);
    let ip_hash = durable::client_ip_hash(
        key,
        &headers,
        Some(peer.0.ip()),
        &state.config.gateway.trusted_proxy_ips,
    );

    let issued = issue_challenge(
        &state.db,
        &req.purpose,
        &target_hash,
        &digest,
        operation_id,
        prim_now_plus(durable::CHALLENGE_TTL),
        &ip_hash,
    )
    .await?;

    tracing::info!(
        target = %req.target,
        purpose = %req.purpose,
        challenge_id = issued.challenge_id,
        idempotent = issued.idempotent,
        // 验证码明文不入日志（防泄露）；仅记录签发与稳定 correlation id
        "verification challenge issued (durable; only HMAC digest persisted)"
    );

    // 稳定 audit correlation：durable 签发（supersede 事务已返回行 id）之后
    // 记录 VERIFICATION_CODE_ISSUED；与后续 verify 消费审计通过同一 id 关联
    // （非关键语义：审计失败只告警，绝不阻塞签发）。
    spawn_verification_code_audit(
        AuditEventType::VerificationCodeIssued,
        "send",
        issued.challenge_id,
        &req.purpose,
    );

    // 机会式有界 GC（TTL/GC 所有权见模块文档）：死行过期超过 GC_RETENTION
    // 后由本次签发顺带清理（challenge/proof/budget 三表），单次每表最多
    // GC_BATCH_LIMIT 行；失败不阻塞签发。
    match vrepo::cleanup_expired_verification(&state.db, GC_RETENTION, GC_BATCH_LIMIT).await {
        Ok((challenges, proofs, budgets)) if challenges + proofs + budgets > 0 => {
            tracing::debug!(
                challenges,
                proofs,
                budgets,
                "verification GC removed expired rows"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "verification GC failed (non-fatal)");
        }
    }

    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/verification/verify — 校验并 one-shot 消费，签发 durable
/// one-shot proof
///
/// 消费边界：`close_challenge_and_issue_proof` 以 `closed_at IS NULL` 为 CAS
/// 条件在挑战关闭的同一事务内签发 proof；并发重复提交中仅一个成功（replay
/// 边界）。返回的 `token` 是 durable one-shot proof 的不透明凭据：purpose+
/// target 绑定、短 TTL、DB 只存 HMAC 摘要；消费方（register）在业务事务内
/// CAS 消费。proof 明文不入日志。
async fn verify_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: ConnectInfo<SocketAddr>,
    Json(req): Json<VerifyCodeRequest>,
) -> Result<Json<ApiResponse<VerificationResult>>, AppError> {
    let key = durable::hmac_key().ok_or_else(key_unavailable)?;
    // purpose 注册表：与 send 同源 fail-closed（不枚举未注册 purpose 的
    // 存在性——统一返回"无有效验证码"）。
    if !durable::is_registered_purpose(&req.purpose) {
        tracing::warn!(purpose = %req.purpose, "unregistered verification purpose rejected (fail closed)");
        return Err(AppError::from(AstralError::Auth(
            "No valid verification code found for this target".into(),
        )));
    }
    let target_hash = durable::target_hash(key, &req.target);
    let ip_hash = durable::client_ip_hash(
        key,
        &headers,
        Some(peer.0.ip()),
        &state.config.gateway.trusted_proxy_ips,
    );
    let provided_digest = durable::code_digest(key, &req.purpose, &target_hash, &req.code);

    match consume_challenge_issue_proof(
        &state.db,
        key,
        &req.purpose,
        &target_hash,
        &provided_digest,
        &ip_hash,
    )
    .await?
    {
        Some((challenge_id, proof_token)) => {
            // 稳定 audit correlation：one-shot CAS 消费成功之后记录
            // VERIFICATION_CODE_VERIFIED，与同挑战签发审计通过同一 id 关联
            // （非关键语义：审计失败只告警，绝不改变校验结果）。
            spawn_verification_code_audit(
                AuditEventType::VerificationCodeVerified,
                "verify",
                challenge_id,
                &req.purpose,
            );
            // proof 契约：durable one-shot，register 事务内 CAS 消费；token
            // 明文只此一次出库，绝不入日志。
            Ok(Json(ApiResponse::success(VerificationResult {
                verified: true,
                token: Some(proof_token),
            })))
        }
        None => Err(AppError::from(AstralError::Auth(
            "Invalid verification code".into(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_contract_is_camel_case() {
        let json = serde_json::to_value(VerificationResult {
            verified: true,
            token: Some("opaque-token".into()),
        })
        .expect("serialize");
        assert_eq!(json["verified"], serde_json::Value::Bool(true));
        assert_eq!(json["token"], "opaque-token");

        let json = serde_json::to_value(VerificationResult {
            verified: false,
            token: None,
        })
        .expect("serialize");
        assert_eq!(json["token"], serde_json::Value::Null);

        let send: SendCodeRequest =
            serde_json::from_str(r#"{"target":"a@b.c","purpose":"register"}"#)
                .expect("deserialize");
        assert_eq!(send.target, "a@b.c");
        assert_eq!(send.purpose, "register");

        let verify: VerifyCodeRequest =
            serde_json::from_str(r#"{"target":"a@b.c","code":"123456","purpose":"register"}"#)
                .expect("deserialize");
        assert_eq!(verify.code, "123456");
    }

    /// 源码形状守卫：仅覆盖本文件真实生产区域，检索锚点全部动态拼接，
    /// 避免测试自身字符串造成的自引用假阳性（AGENTS §0E.3）。
    #[test]
    fn verification_source_contract() {
        let source = include_str!("verification.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let normalized: String = production.split_whitespace().collect();

        // 旧 plaintext 路径必须退役：明文码/旧表 fns/进程内计数器/ inert UUID
        // 一律不得回流（锚点动态拼接，避免自引用）。
        for legacy in [
            concat!("issue_", "verification_code("),
            concat!("mark_", "verification_code_verified("),
            concat!("find_", "valid_verification_code("),
            concat!("cleanup_", "expired_verification_codes("),
            concat!("verify_attempt_", "exceeded("),
            concat!("record_", "verify_failure("),
            concat!("uuid::Uuid::", "new_v4()"),
        ] {
            assert!(
                !production.contains(legacy),
                "legacy plaintext/local-counter/inert-token path must not return: {legacy}"
            );
        }

        // durable 路径必须接线：显式稳定 op id、purpose 注册表、恒时摘要
        // 比对、预算事务、one-shot CAS 消费 + 同事务 proof 签发、有界 GC。
        assert!(
            normalized.contains(concat!("validate_", "operation_id("))
                && normalized.contains(
                    "headers.get(\"X-Operation-Id\").and_then(|value|value.to_str().ok())",
                ),
            "send must require the explicit stable operation id header"
        );
        assert!(
            production.contains(concat!("is_", "registered_purpose(&req.purpose)")),
            "send and verify must consult the purpose registry (fail closed)"
        );
        assert!(
            production.contains(concat!(
                "constant_",
                "time_eq(provided_digest, &row.code_digest)"
            )),
            "code comparison must be constant time over digests"
        );
        for anchor in [
            concat!("find_active_", "challenge_by_operation("),
            concat!("bump_", "budget("),
            concat!("close_open_", "challenges("),
            concat!("insert_", "challenge("),
            concat!("close_challenge_", "and_issue_proof("),
            concat!("cleanup_expired_", "verification(&state.db"),
        ] {
            assert!(
                production.contains(anchor),
                "durable repository wiring missing: {anchor}"
            );
        }
        assert!(
            production.contains(concat!("GC_", "BATCH_LIMIT"))
                && production.contains(concat!("GC_", "RETENTION")),
            "GC must use the explicit bounded retention/limit constants"
        );

        // 审计 correlation：durable 签发与 one-shot CAS 成功之后各产生一条
        // 携带 codeId 的稳定审计事件；writer 缺失/任务未接纳时退化为结构化
        // 日志（非关键语义），绝不把审计失败折算成 HTTP 失败。
        let audit_call = concat!("spawn_", "verification_code_audit(");
        assert_eq!(
            production.matches(audit_call).count(),
            3,
            "one definition plus exactly two call sites: durable issue and one-shot CAS success"
        );
        assert!(
            production.contains(concat!("AuditEventType::VerificationCode", "Issued"))
                && production.contains(concat!("AuditEventType::VerificationCode", "Verified")),
            "audits must use the shared stable contract variants"
        );
        assert!(
            production.contains(concat!("codeId=", "{code_id}")),
            "both audits must correlate through the durable row id"
        );
        assert!(
            production.contains(concat!("global_", "audit_dual_write()"))
                && production.contains(concat!("spawn_", "owned_audit(")),
            "verification audits must ride the shared non-critical dual-write path"
        );
        assert!(
            production.contains(concat!("user_id: Some(", "0)")),
            "pre-auth bootstrap audits must use the existing anonymous zero sentinel"
        );

        // 明文边界：code 与 proof token 的明文永不入日志；HMAC 密钥缺失时
        // fail-closed。
        assert!(
            !production.contains(concat!("%req", ".code")),
            "request code plaintext must never be logged"
        );
        assert!(
            !production.contains(concat!("code", " = %")),
            "code field must never be logged via tracing shorthand"
        );
        assert!(
            production.contains(concat!("hmac_", "key().ok_or_else(key_unavailable)")),
            "missing HMAC key must fail closed at both endpoints"
        );
        // proof 只经响应出库，绝不进入 tracing/审计 detail。
        assert!(
            !production.contains("proof_token = %") && !production.contains("token = %"),
            "proof/token plaintext must never be logged"
        );
    }
}
