//! IN_DOUBT 失效恢复运维闭环（当前阶段：只读 inspect + 写路径显式拒绝）。
//!
//! 背景：[`astral_db::LocalMessageRepository`] 的 `load_in_doubt` /
//! `reconcile_in_doubt` 目前没有 production caller。IN_DOUBT 行在
//! per-scope FIFO 中属于未终态行（claim guard 只放行 prior 状态为
//! `PROCESSED`/`QUARANTINED` 之外的阻塞语义），会持续阻断同一
//! `(queue_name, ordering_key)` scope 的后续 notify 投递，需要一条
//! 安全的运维闭环。本模块就是这条闭环的 service 层，配套 CLI 见
//! `astral-trustgraph/src/bin/invalidation_recovery.rs`。
//!
//! 模块边界（对齐 AGENTS §0C/§3.4 与 §7.1 状态词汇）：
//!
//! - **inspect 只读**：实际调用 `LocalMessageRepository::load_in_doubt`
//!   （exact `status='IN_DOUBT'` load），输出全部 scope/provenance 字段
//!   （message_id/operation_id/message_type/queue_name/ordering_key/
//!   tenant_id/origin_region/target_region/schema_version）加上
//!   `payload_sha256`、status 与时序字段以及 bounded 大小信息。
//!   **永不输出** payload_json 内容、header 值、lease_owner（lease token）
//!   与 last_error 原文——这些字段可能承载 token/秘密，只输出
//!   存在性/长度旗标。不读 raw source、不做任何写入；授权语义绝不从
//!   读取结果推导。
//! - **requeue 一律 REFUSED**：handler 的 durable effect 未证明，
//!   requeue 会把未证明 effect 的消息重新投递（潜在双写/重放）；
//!   本工具在任何阶段都不 requeue。
//! - **quarantine 一律 BLOCKED（零 I/O）**：当前 ownership 没有同事务
//!   durable audit/approval contract，普通 hash receipt 不构成审批证明，
//!   因此在拿到已批准入口之前不执行 quarantine settlement：不调用
//!   `reconcile_in_doubt` 写路径、不伪造 `applied=true`/PASS，稳定输出
//!   `QUARANTINE_APPROVAL_GATE_ABSENT`。真实 Exec-L3 运维恢复由主 Agent
//!   登记 runbook + 人工终审门；未来已批准入口可复用
//!   [`QuarantineProvenance`] 纯校验器驱动 `reconcile_in_doubt`
//!   （repo 侧 provenance FOR UPDATE + `status='IN_DOUBT'` CAS 仍是
//!   唯一不变量，幂等由该 CAS 承担）。
//! - **不可证明即 UNKNOWN/PENDING**：绝不以 elapsed time 猜测
//!   NotApplied；DB 读取失败输出稳定机器 code
//!   `DB_ERROR_OUTCOME_UNPROVEN`，不回显 DATABASE_URL 或原始 DB 错误
//!   文本；无任何自动重试。
//! - **无自由文本 reason 通道**：CLI 不接受 `--reason` 之类自由文本
//!   （secret 泄露面），所有输出 reason 使用稳定机器 code。

use astral_db::{LocalMessageError, LocalMessageRepository, LocalMessageRow};
use serde_json::{json, Value};
use time::PrimitiveDateTime;

/// IN_DOUBT 行状态字面量（与 `al_message_outbox.status` 保持一致）。
pub const IN_DOUBT_STATUS: &str = "IN_DOUBT";

/// CLI 输入上限（与 `al_message_outbox` DDL 及 repo 校验一致）。
pub const MAX_MESSAGE_ID_LEN: usize = 128;
pub const MAX_OPERATION_ID_LEN: usize = 128;
pub const MAX_MESSAGE_TYPE_LEN: usize = 64;
pub const MAX_QUEUE_NAME_LEN: usize = 128;
/// operator 审批 run 引用的上限（runbook 语义由主 Agent 登记）。
pub const MAX_RUN_ID_LEN: usize = 128;

/// 稳定机器 reason code（对外输出唯一事实，禁止自由文本）。
pub const REASON_INVALID_ARGUMENTS: &str = "INVALID_ARGUMENTS";
pub const REASON_NO_IN_DOUBT_ROW: &str = "NO_IN_DOUBT_ROW";
pub const REASON_REQUEUE_POLICY_REFUSED: &str = "REQUEUE_POLICY_REFUSED";
pub const REASON_QUARANTINE_APPROVAL_GATE_ABSENT: &str = "QUARANTINE_APPROVAL_GATE_ABSENT";
pub const REASON_DB_ENV_MISSING: &str = "DB_ENV_MISSING";
pub const REASON_DB_URL_SCHEME_INVALID: &str = "DB_URL_SCHEME_INVALID";
pub const REASON_DB_UNREACHABLE: &str = "DB_UNREACHABLE";
pub const REASON_DB_ERROR_OUTCOME_UNPROVEN: &str = "DB_ERROR_OUTCOME_UNPROVEN";

/// 可脚本化退出码（与 shell 约定 0=成功、非 0=分类失败）。
///
/// `Pending`（5）是建模保留位：本单发 CLI 不会留下异步未终态的 durable
/// 动作，因此**绝不输出** `PENDING`——不能证明的写结果一律归 `UNKNOWN`；
/// 该位留给未来异步 settle worker，不得伪造为 PASS。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Pass,
    Usage,
    NoInDoubtRow,
    RequeueRefused,
    ProvenanceConflict,
    Pending,
    Unknown,
    Blocked,
}

impl ExitStatus {
    pub fn code(self) -> i32 {
        match self {
            Self::Pass => 0,
            Self::Usage => 1,
            Self::NoInDoubtRow => 2,
            Self::RequeueRefused => 3,
            Self::ProvenanceConflict => 4,
            Self::Pending => 5,
            Self::Unknown => 6,
            Self::Blocked => 7,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Usage => "USAGE",
            Self::NoInDoubtRow => "NO_IN_DOUBT_ROW",
            Self::RequeueRefused => "REQUEUE_REFUSED",
            Self::ProvenanceConflict => "PROVENANCE_CONFLICT",
            Self::Pending => "PENDING",
            Self::Unknown => "UNKNOWN",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// 输入/用法错误（纯校验层，任何 I/O 之前）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryOpError {
    #[error("invalid arguments: {0}")]
    Usage(String),
}

/// quarantine 写路径所需的完整 provenance（纯数据 + 纯校验）。
///
/// 当前阶段它只用于：解析 `settle` 参数做 shape 校验、与 inspect 行做
/// 纯匹配演示。它**不授权任何写入**；未来已批准入口必须先有同事务
/// durable audit/approval contract，再把它交给
/// `LocalMessageRepository::reconcile_in_doubt`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineProvenance {
    pub message_id: String,
    pub operation_id: String,
    pub message_type: String,
    pub queue_name: String,
    pub payload_sha256: String,
}

impl QuarantineProvenance {
    /// shape 校验：非空、长度上限、无控制字符、digest 为 64 位 hex。
    /// 纯函数，任何 I/O 之前执行（先静态纯校验，再 SQL）。
    pub fn validate_shape(&self) -> Result<(), RecoveryOpError> {
        validate_field("message_id", &self.message_id, MAX_MESSAGE_ID_LEN)?;
        validate_field("operation_id", &self.operation_id, MAX_OPERATION_ID_LEN)?;
        validate_field("message_type", &self.message_type, MAX_MESSAGE_TYPE_LEN)?;
        validate_field("queue_name", &self.queue_name, MAX_QUEUE_NAME_LEN)?;
        validate_sha256_hex("payload_sha256", &self.payload_sha256)?;
        Ok(())
    }

    /// 与一行 durable 数据做纯 provenance 匹配（比较顺序镜像 repo 的
    /// reconcile：先 provenance 后 status；`payload_sha256` 按字节精确
    /// 比较，与 repo 的 CAS 前置一致）。只读，不产生任何状态迁移。
    pub fn matches_row(&self, row: &LocalMessageRow) -> ProvenanceMatch {
        let fields = [
            (
                "message_id",
                row.message_id.as_str(),
                self.message_id.as_str(),
            ),
            (
                "operation_id",
                row.operation_id.as_str(),
                self.operation_id.as_str(),
            ),
            (
                "message_type",
                row.message_type.as_str(),
                self.message_type.as_str(),
            ),
            (
                "queue_name",
                row.queue_name.as_str(),
                self.queue_name.as_str(),
            ),
            (
                "payload_sha256",
                row.payload_sha256.as_str(),
                self.payload_sha256.as_str(),
            ),
        ];
        for (field, stored, expected) in fields {
            if stored != expected {
                return ProvenanceMatch::FieldMismatch { field };
            }
        }
        if row.status != IN_DOUBT_STATUS {
            return ProvenanceMatch::NotInDoubt {
                status: row.status.clone(),
            };
        }
        ProvenanceMatch::Exact
    }
}

/// 纯 provenance 匹配结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceMatch {
    Exact,
    FieldMismatch { field: &'static str },
    NotInDoubt { status: String },
}

/// settle 决策参数（解析后即被策略门拒绝；仅用于稳定拒绝输出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleDecision {
    Requeue,
    Quarantine,
}

impl SettleDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requeue => "requeue",
            Self::Quarantine => "quarantine",
        }
    }
}

/// 一次 settle 请求（shape 合法）；策略门在零 I/O 下拒绝它。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleRequest {
    pub decision: SettleDecision,
    pub provenance: QuarantineProvenance,
    pub run_id: String,
}

/// CLI 子命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCommand {
    Help,
    Inspect { message_id: String },
    Settle(SettleRequest),
}

/// 解析 argv（纯函数）：所有 shape 校验在任何 env 读取/连接之前完成。
pub fn parse_args(args: &[String]) -> Result<RecoveryCommand, RecoveryOpError> {
    let Some(subcommand) = args.first() else {
        return Ok(RecoveryCommand::Help);
    };
    match subcommand.as_str() {
        "help" | "--help" | "-h" => Ok(RecoveryCommand::Help),
        "inspect" => {
            let flags = parse_flags(&args[1..])?;
            reject_unknown_flags(&flags, INSPECT_FLAGS)?;
            let message_id = require_flag(&flags, "--message-id")?.to_string();
            validate_field("--message-id", &message_id, MAX_MESSAGE_ID_LEN)?;
            Ok(RecoveryCommand::Inspect { message_id })
        }
        "settle" => {
            let flags = parse_flags(&args[1..])?;
            reject_unknown_flags(&flags, SETTLE_FLAGS)?;
            let decision = match require_flag(&flags, "--decision")? {
                "requeue" => SettleDecision::Requeue,
                "quarantine" => SettleDecision::Quarantine,
                other => {
                    return Err(RecoveryOpError::Usage(format!(
                        "--decision must be 'requeue' or 'quarantine', got {other:?}"
                    )))
                }
            };
            let provenance = QuarantineProvenance {
                message_id: require_flag(&flags, "--message-id")?.to_string(),
                operation_id: require_flag(&flags, "--operation-id")?.to_string(),
                message_type: require_flag(&flags, "--message-type")?.to_string(),
                queue_name: require_flag(&flags, "--queue-name")?.to_string(),
                payload_sha256: require_flag(&flags, "--payload-sha256")?.to_string(),
            };
            provenance.validate_shape()?;
            let run_id = require_flag(&flags, "--run-id")?.to_string();
            validate_field("--run-id", &run_id, MAX_RUN_ID_LEN)?;
            Ok(RecoveryCommand::Settle(SettleRequest {
                decision,
                provenance,
                run_id,
            }))
        }
        other => Err(RecoveryOpError::Usage(format!(
            "unknown subcommand {other:?}; expected 'inspect', 'settle' or 'help'"
        ))),
    }
}

const INSPECT_FLAGS: &[&str] = &["--message-id"];
const SETTLE_FLAGS: &[&str] = &[
    "--decision",
    "--message-id",
    "--operation-id",
    "--message-type",
    "--queue-name",
    "--payload-sha256",
    "--run-id",
];

fn parse_flags(args: &[String]) -> Result<Vec<(String, String)>, RecoveryOpError> {
    let mut flags = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let name = &args[index];
        let Some(value) = args.get(index + 1) else {
            return Err(RecoveryOpError::Usage(format!(
                "flag {name} is missing its value"
            )));
        };
        if !name.starts_with("--") || name.len() <= 2 {
            return Err(RecoveryOpError::Usage(format!(
                "expected a --flag, got {name:?}"
            )));
        }
        if flags.iter().any(|(existing, _)| existing == name) {
            return Err(RecoveryOpError::Usage(format!("duplicate flag {name}")));
        }
        flags.push((name.clone(), value.clone()));
        index += 2;
    }
    Ok(flags)
}

fn reject_unknown_flags(flags: &[(String, String)], known: &[&str]) -> Result<(), RecoveryOpError> {
    for (name, _) in flags {
        if !known.contains(&name.as_str()) {
            return Err(RecoveryOpError::Usage(format!(
                "unknown flag {name}; accepted flags: {}",
                known.join(" ")
            )));
        }
    }
    Ok(())
}

fn require_flag<'a>(flags: &'a [(String, String)], name: &str) -> Result<&'a str, RecoveryOpError> {
    flags
        .iter()
        .find(|(flag, _)| flag == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| RecoveryOpError::Usage(format!("{name} is required")))
}

fn validate_field(name: &str, value: &str, max_len: usize) -> Result<(), RecoveryOpError> {
    if value.trim().is_empty() {
        return Err(RecoveryOpError::Usage(format!(
            "{name} is required and must not be blank"
        )));
    }
    if value.len() > max_len {
        return Err(RecoveryOpError::Usage(format!(
            "{name} exceeds the {max_len}-character bound"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(RecoveryOpError::Usage(format!(
            "{name} must not contain control characters"
        )));
    }
    Ok(())
}

fn validate_sha256_hex(name: &str, value: &str) -> Result<(), RecoveryOpError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RecoveryOpError::Usage(format!(
            "{name} must be a 64-character hexadecimal digest"
        )));
    }
    Ok(())
}

/// 只读 exact IN_DOUBT load：本模块唯一的 DB 访问面，实际调用
/// `LocalMessageRepository::load_in_doubt`。不读 raw source、无写入、
/// 无自动重试；调用方必须先完成纯校验（bounded inputs）。
pub async fn inspect_in_doubt(
    repo: &LocalMessageRepository,
    message_id: &str,
) -> Result<Option<LocalMessageRow>, LocalMessageError> {
    bounded_inspect_read(
        repo.load_in_doubt(message_id),
        std::time::Duration::from_secs(5),
    )
    .await
}

async fn bounded_inspect_read(
    read: impl std::future::Future<Output = Result<Option<LocalMessageRow>, LocalMessageError>>,
    deadline: std::time::Duration,
) -> Result<Option<LocalMessageRow>, LocalMessageError> {
    tokio::time::timeout(deadline, read)
        .await
        .map_err(|_| LocalMessageError::Database(sqlx::Error::PoolTimedOut))?
}

/// 策略门（纯函数，零 I/O）：settle 在任何阶段都不执行。
///
/// - requeue → `REQUEUE_REFUSED`：handler durable effect 未证明，重放
///   可能双写；策略性拒绝，与任何 proof/审批无关。
/// - quarantine → `BLOCKED`：当前 ownership 无同事务 durable
///   audit/approval contract，审批前置缺失，required gate 未启动。
pub fn refuse_settle(request: &SettleRequest) -> (ExitStatus, &'static str) {
    match request.decision {
        SettleDecision::Requeue => (ExitStatus::RequeueRefused, REASON_REQUEUE_POLICY_REFUSED),
        SettleDecision::Quarantine => (ExitStatus::Blocked, REASON_QUARANTINE_APPROVAL_GATE_ABSENT),
    }
}

/// settle 的稳定拒绝输出（证据行）：显式 `applied: false`，回显
/// operator 供给的非秘密 id（message/operation/type/queue/hash/run），
/// 绝不伪造 PASS。调用方必须在读取 env / 建立连接之前输出并退出。
pub fn settle_refusal_output(request: &SettleRequest, invocation_id: &str) -> (ExitStatus, Value) {
    let (status, reason_code) = refuse_settle(request);
    let explanation = match status {
        ExitStatus::RequeueRefused => {
            "requeue would re-deliver a message whose durable handler effect is unproven; \
             this tool never requeues"
        }
        _ => {
            "no same-transaction durable audit/approval contract exists in the current \
             ownership; quarantine settlement stays blocked until the approved entry point \
             (runbook + human final review) exists"
        }
    };
    (
        status,
        json!({
            "status": status.name(),
            "reason_code": reason_code,
            "command": "settle",
            "decision": request.decision.as_str(),
            "applied": false,
            "invocation_id": invocation_id,
            "message_id": request.provenance.message_id,
            "operation_id": request.provenance.operation_id,
            "message_type": request.provenance.message_type,
            "queue_name": request.provenance.queue_name,
            "payload_sha256": request.provenance.payload_sha256,
            "run_id": request.run_id,
            "explanation": explanation,
        }),
    )
}

/// PASS 行的脱敏投影：21 个 durable 字段全部被"考虑"，其中可能承载
/// 秘密的四个面（payload_json 内容、headers_json 值、lease_owner token、
/// last_error 原文）只输出存在性/长度旗标，其余字段原样输出。
pub fn inspect_pass_json(row: &LocalMessageRow, invocation_id: &str) -> Value {
    json!({
        "status": ExitStatus::Pass.name(),
        "reason_code": Value::Null,
        "command": "inspect",
        "invocation_id": invocation_id,
        "row": {
            "message_id": row.message_id,
            "operation_id": row.operation_id,
            "message_type": row.message_type,
            "queue_name": row.queue_name,
            "ordering_key": row.ordering_key,
            "tenant_id": row.tenant_id,
            "origin_region": row.origin_region,
            "target_region": row.target_region,
            "schema_version": row.schema_version,
            "payload_sha256": row.payload_sha256,
            "status": row.status,
            "attempts": row.attempts,
            "next_attempt_at": opt_time(&row.next_attempt_at),
            "processed_at": opt_time(&row.processed_at),
            "lease_expires_at": opt_time(&row.lease_expires_at),
            "created_at": row.created_at.to_string(),
            "updated_at": row.updated_at.to_string(),
            "lease_owner_present": row.lease_owner.is_some(),
            "headers_present": row.headers_json.is_some(),
            "last_error_present": row.last_error.is_some(),
            "payload_len_bytes": row.payload_json.len(),
        },
        "redaction": "payload_json content, header values, lease_owner token and \
                      last_error text are never emitted",
    })
}

/// inspect 结果 → (退出状态, 证据 JSON)。失败一律 `UNKNOWN` +
/// 稳定机器 code，不回显原始 DB 错误文本（避免泄露 URL/服务端细节）。
pub fn inspect_result_output(
    result: Result<Option<LocalMessageRow>, LocalMessageError>,
    invocation_id: &str,
) -> (ExitStatus, Value) {
    match result {
        Ok(Some(row)) => (ExitStatus::Pass, inspect_pass_json(&row, invocation_id)),
        Ok(None) => (
            ExitStatus::NoInDoubtRow,
            json!({
                "status": ExitStatus::NoInDoubtRow.name(),
                "reason_code": REASON_NO_IN_DOUBT_ROW,
                "command": "inspect",
                "invocation_id": invocation_id,
                "row": Value::Null,
                "note": "no row is currently IN_DOUBT for this message_id (absent or \
                         already terminal); inspect cannot distinguish without raw-source \
                         reads by design",
            }),
        ),
        Err(_) => (
            ExitStatus::Unknown,
            json!({
                "status": ExitStatus::Unknown.name(),
                "reason_code": REASON_DB_ERROR_OUTCOME_UNPROVEN,
                "command": "inspect",
                "invocation_id": invocation_id,
                "row": Value::Null,
                "note": "durable row state could not be proven; re-run the read-only \
                         inspect to reconcile; raw database error details are \
                         intentionally not emitted",
            }),
        ),
    }
}

/// argv 用法错误的稳定输出（stderr）。
pub fn usage_error_output(error: &RecoveryOpError, invocation_id: &str) -> (ExitStatus, Value) {
    (
        ExitStatus::Usage,
        json!({
            "status": ExitStatus::Usage.name(),
            "reason_code": REASON_INVALID_ARGUMENTS,
            "command": Value::Null,
            "invocation_id": invocation_id,
            "detail": error.to_string(),
            "hint": "run with 'help' for usage",
        }),
    )
}

/// inspect 在 DB 门之前的 BLOCKED 证据输出（env 缺失/格式错/连接失败）。
pub fn inspect_blocked_output(reason_code: &str, invocation_id: &str) -> Value {
    json!({
        "status": ExitStatus::Blocked.name(),
        "reason_code": reason_code,
        "command": "inspect",
        "invocation_id": invocation_id,
        "row": Value::Null,
        "note": "required database gate never started; no durable state was read or \
                 changed",
    })
}

pub fn usage_text() -> &'static str {
    "invalidation_recovery — IN_DOUBT outbox recovery ops CLI (read-only phase)\n\
     \n\
     SUBCOMMANDS\n\
     \x20 inspect --message-id <ID>\n\
     \x20     Read-only exact IN_DOUBT load. Emits one JSON evidence line with all\n\
     \x20     scope/provenance fields, payload_sha256, status/timing and bounded size\n\
     \x20     flags. Payload content, header values, lease_owner token and last_error\n\
     \x20     text are never emitted.\n\
     \x20 settle --decision requeue|quarantine --message-id <ID> --operation-id <ID>\n\
     \x20        --message-type <TYPE> --queue-name <QUEUE> --payload-sha256 <HEX64>\n\
     \x20        --run-id <RUN>\n\
     \x20     ALWAYS refused with zero I/O in this phase (no DB connection is made):\n\
     \x20       requeue    -> exit 3 REQUEUE_POLICY_REFUSED (unproven handler effect)\n\
     \x20       quarantine -> exit 7 QUARANTINE_APPROVAL_GATE_ABSENT (no approved\n\
     \x20                     entry point / durable audit+approval contract yet)\n\
     \x20 help\n\
     \n\
     ENV\n\
     \x20 DATABASE_URL  mysql:// URL; its value is never printed.\n\
     \n\
     EXIT CODES\n\
     \x20 0 PASS  1 USAGE  2 NO_IN_DOUBT_ROW  3 REQUEUE_REFUSED  4 PROVENANCE_CONFLICT\n\
     \x20 5 PENDING (reserved, never emitted by this single-shot tool)\n\
     \x20 6 UNKNOWN (durable state unproven; reconcile with a fresh read-only inspect)\n\
     \x20 7 BLOCKED (required gate never started: env/scheme/connect or approval gate)\n"
}

fn opt_time(value: &Option<PrimitiveDateTime>) -> Value {
    value
        .as_ref()
        .map(|time| Value::String(time.to_string()))
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Error as SqlxError;

    fn sample_row() -> LocalMessageRow {
        let created = PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::October, 1).expect("valid date"),
            time::Time::MIDNIGHT,
        );
        LocalMessageRow {
            message_id: "event-1".into(),
            operation_id: "operation-1".into(),
            message_type: "EVIDENCE_INVALIDATED".into(),
            queue_name: "astral.authorization.invalidation".into(),
            ordering_key: Some("authorization:evidence:tenant/7".into()),
            tenant_id: Some(7),
            origin_region: "city-a".into(),
            target_region: None,
            schema_version: 1,
            payload_json: "{}".into(),
            headers_json: None,
            payload_sha256: "0".repeat(64),
            status: IN_DOUBT_STATUS.into(),
            attempts: 2,
            next_attempt_at: None,
            lease_owner: None,
            lease_expires_at: None,
            processed_at: None,
            last_error: None,
            created_at: created,
            updated_at: created,
        }
    }

    #[tokio::test]
    async fn inspect_timeout_drops_the_read_and_reports_unknown() {
        struct ReadDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for ReadDrop {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = ReadDrop(dropped.clone());
        let read = async move {
            let _marker = marker;
            std::future::pending().await
        };
        let result = bounded_inspect_read(read, std::time::Duration::from_millis(10)).await;
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        let (status, output) = inspect_result_output(result, "timeout-test");
        assert_eq!(status, ExitStatus::Unknown);
        assert_eq!(output["reason_code"], REASON_DB_ERROR_OUTCOME_UNPROVEN);
        assert!(output["row"].is_null());
    }

    fn sample_provenance() -> QuarantineProvenance {
        QuarantineProvenance {
            message_id: "event-1".into(),
            operation_id: "operation-1".into(),
            message_type: "EVIDENCE_INVALIDATED".into(),
            queue_name: "astral.authorization.invalidation".into(),
            payload_sha256: "0".repeat(64),
        }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn exit_codes_are_total_distinct_and_documented() {
        let statuses = [
            ExitStatus::Pass,
            ExitStatus::Usage,
            ExitStatus::NoInDoubtRow,
            ExitStatus::RequeueRefused,
            ExitStatus::ProvenanceConflict,
            ExitStatus::Pending,
            ExitStatus::Unknown,
            ExitStatus::Blocked,
        ];
        let mut codes: Vec<i32> = statuses.iter().map(|status| status.code()).collect();
        codes.sort_unstable();
        assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        for status in statuses {
            assert!(!status.name().is_empty());
        }
    }

    #[test]
    fn pending_is_modeled_but_never_emitted_by_any_mapping() {
        // 单发 CLI 没有异步未终态动作：任何映射都不得产出 PENDING。
        let inspect_statuses = [
            inspect_result_output(Ok(Some(sample_row())), "inv").0,
            inspect_result_output(Ok(None), "inv").0,
            inspect_result_output(
                Err(LocalMessageError::Database(SqlxError::RowNotFound)),
                "inv",
            )
            .0,
        ];
        assert!(!inspect_statuses.contains(&ExitStatus::Pending));
        let settle_request = SettleRequest {
            decision: SettleDecision::Quarantine,
            provenance: sample_provenance(),
            run_id: "run-1".into(),
        };
        assert_ne!(refuse_settle(&settle_request).0, ExitStatus::Pending);
        // 保留位语义固定为 5，仅供未来异步 settle worker 使用。
        assert_eq!(ExitStatus::Pending.code(), 5);
    }

    #[test]
    fn parse_inspect_accepts_bounded_message_id() {
        let command =
            parse_args(&args(&["inspect", "--message-id", "event-1"])).expect("valid inspect args");
        assert_eq!(
            command,
            RecoveryCommand::Inspect {
                message_id: "event-1".into()
            }
        );
    }

    #[test]
    fn parse_inspect_rejects_missing_unknown_duplicate_and_bad_inputs() {
        assert!(matches!(
            parse_args(&args(&["inspect"])),
            Err(RecoveryOpError::Usage(message)) if message.contains("--message-id")
        ));
        assert!(matches!(
            parse_args(&args(&["inspect", "--message-id"])),
            Err(RecoveryOpError::Usage(message)) if message.contains("missing its value")
        ));
        assert!(matches!(
            parse_args(&args(&["inspect", "--payload-json", "x", "--message-id", "e"])),
            Err(RecoveryOpError::Usage(message)) if message.contains("unknown flag")
        ));
        assert!(matches!(
            parse_args(&args(&["inspect", "--message-id", "a", "--message-id", "b"])),
            Err(RecoveryOpError::Usage(message)) if message.contains("duplicate")
        ));
        let oversized = "m".repeat(MAX_MESSAGE_ID_LEN + 1);
        assert!(matches!(
            parse_args(&args(&["inspect", "--message-id", oversized.as_str()])),
            Err(RecoveryOpError::Usage(message)) if message.contains("128-character bound")
        ));
        assert!(matches!(
            parse_args(&args(&["inspect", "--message-id", "bad\nid"])),
            Err(RecoveryOpError::Usage(message)) if message.contains("control characters")
        ));
        assert!(matches!(
            parse_args(&args(&["inspect", "--message-id", "   "])),
            Err(RecoveryOpError::Usage(message)) if message.contains("must not be blank")
        ));
    }

    #[test]
    fn parse_settle_accepts_shaped_requests_without_authorizing_them() {
        let command = parse_args(&args(&[
            "settle",
            "--decision",
            "quarantine",
            "--message-id",
            "event-1",
            "--operation-id",
            "operation-1",
            "--message-type",
            "EVIDENCE_INVALIDATED",
            "--queue-name",
            "astral.authorization.invalidation",
            "--payload-sha256",
            &"a".repeat(64),
            "--run-id",
            "run-1",
        ]))
        .expect("shaped settle args parse");
        let RecoveryCommand::Settle(request) = command else {
            panic!("expected settle command");
        };
        assert_eq!(request.decision, SettleDecision::Quarantine);
        assert_eq!(request.provenance, sample_provenance_with_digest("a"));
        // 解析成功 ≠ 授权：策略门仍必须零 I/O 拒绝。
        assert_eq!(
            refuse_settle(&request),
            (ExitStatus::Blocked, REASON_QUARANTINE_APPROVAL_GATE_ABSENT)
        );
    }

    fn sample_provenance_with_digest(byte: &str) -> QuarantineProvenance {
        QuarantineProvenance {
            payload_sha256: byte.repeat(64),
            ..sample_provenance()
        }
    }

    #[test]
    fn parse_settle_rejects_bad_decision_digest_and_free_text_reason() {
        let base = [
            "settle",
            "--decision",
            "quarantine",
            "--message-id",
            "event-1",
            "--operation-id",
            "operation-1",
            "--message-type",
            "EVIDENCE_INVALIDATED",
            "--queue-name",
            "astral.authorization.invalidation",
            "--payload-sha256",
        ];
        assert!(matches!(
            parse_args(&args(&["settle", "--decision", "restart", "--message-id", "e"])),
            Err(RecoveryOpError::Usage(message)) if message.contains("--decision")
        ));
        let bad_digest: Vec<String> = args(&base)
            .into_iter()
            .chain([
                "not-hex".to_string(),
                "--run-id".to_string(),
                "run-1".to_string(),
            ])
            .collect();
        assert!(matches!(
            parse_args(&bad_digest),
            Err(RecoveryOpError::Usage(message)) if message.contains("64-character hexadecimal")
        ));
        // 无自由文本 reason 通道：--reason 必须被当作未知 flag 拒绝。
        let with_reason: Vec<String> = args(&base)
            .into_iter()
            .chain([
                "0".repeat(64),
                "--run-id".to_string(),
                "run-1".to_string(),
                "--reason".to_string(),
                "free text".to_string(),
            ])
            .collect();
        assert!(matches!(
            parse_args(&with_reason),
            Err(RecoveryOpError::Usage(message)) if message.contains("unknown flag")
        ));
        assert!(matches!(
            parse_args(&args(&["settle", "--decision", "quarantine"])),
            Err(RecoveryOpError::Usage(_))
        ));
    }

    #[test]
    fn settle_policy_refuses_both_decisions_with_stable_codes() {
        let requeue = SettleRequest {
            decision: SettleDecision::Requeue,
            provenance: sample_provenance(),
            run_id: "run-1".into(),
        };
        assert_eq!(
            refuse_settle(&requeue),
            (ExitStatus::RequeueRefused, REASON_REQUEUE_POLICY_REFUSED)
        );
        let quarantine = SettleRequest {
            decision: SettleDecision::Quarantine,
            provenance: sample_provenance(),
            run_id: "run-1".into(),
        };
        assert_eq!(
            refuse_settle(&quarantine),
            (ExitStatus::Blocked, REASON_QUARANTINE_APPROVAL_GATE_ABSENT)
        );
    }

    #[test]
    fn settle_refusal_output_never_claims_applied_and_echoes_non_secret_ids() {
        let request = SettleRequest {
            decision: SettleDecision::Quarantine,
            provenance: sample_provenance(),
            run_id: "run-42".into(),
        };
        let (status, output) = settle_refusal_output(&request, "inv-1");
        assert_eq!(status, ExitStatus::Blocked);
        assert_eq!(output["status"], "BLOCKED");
        assert_eq!(output["applied"], false);
        assert_eq!(
            output["reason_code"],
            REASON_QUARANTINE_APPROVAL_GATE_ABSENT
        );
        assert_eq!(output["run_id"], "run-42");
        assert_eq!(output["payload_sha256"], "0".repeat(64));
    }

    #[test]
    fn provenance_match_mirrors_repo_precedence_and_exactness() {
        let row = sample_row();
        assert_eq!(
            sample_provenance().matches_row(&row),
            ProvenanceMatch::Exact
        );
        // 字段不匹配优先于 status（镜像 repo reconcile 的检查顺序）。
        let mut processed = sample_row();
        processed.status = "PROCESSED".into();
        assert_eq!(
            sample_provenance().matches_row(&processed),
            ProvenanceMatch::NotInDoubt {
                status: "PROCESSED".into()
            }
        );
        let mut wrong_operation = sample_row();
        wrong_operation.operation_id = "operation-2".into();
        assert_eq!(
            sample_provenance().matches_row(&wrong_operation),
            ProvenanceMatch::FieldMismatch {
                field: "operation_id"
            }
        );
        let mut wrong_type = sample_row();
        wrong_type.message_type = "OTHER".into();
        assert_eq!(
            sample_provenance().matches_row(&wrong_type),
            ProvenanceMatch::FieldMismatch {
                field: "message_type"
            }
        );
        let mut wrong_queue = sample_row();
        wrong_queue.queue_name = "astral.audit.log".into();
        assert_eq!(
            sample_provenance().matches_row(&wrong_queue),
            ProvenanceMatch::FieldMismatch {
                field: "queue_name"
            }
        );
        // payload_sha256 与 repo CAS 前置一致：字节精确（含大小写）比较。
        let digest = "f".repeat(64);
        let upper = QuarantineProvenance {
            payload_sha256: digest.to_ascii_uppercase(),
            ..sample_provenance_with_digest("f")
        };
        let mut lower_row = sample_row();
        lower_row.payload_sha256 = digest;
        assert_eq!(
            upper.matches_row(&lower_row),
            ProvenanceMatch::FieldMismatch {
                field: "payload_sha256"
            }
        );
    }

    #[test]
    fn provenance_shape_validates_bounds_and_hex() {
        assert!(sample_provenance().validate_shape().is_ok());
        let blank = QuarantineProvenance {
            message_id: "  ".into(),
            ..sample_provenance()
        };
        assert!(matches!(
            blank.validate_shape(),
            Err(RecoveryOpError::Usage(message)) if message.contains("message_id")
        ));
        let oversized = QuarantineProvenance {
            queue_name: "q".repeat(MAX_QUEUE_NAME_LEN + 1),
            ..sample_provenance()
        };
        assert!(matches!(
            oversized.validate_shape(),
            Err(RecoveryOpError::Usage(message)) if message.contains("128-character bound")
        ));
        let bad_digest = QuarantineProvenance {
            payload_sha256: "g".repeat(64),
            ..sample_provenance()
        };
        assert!(matches!(
            bad_digest.validate_shape(),
            Err(RecoveryOpError::Usage(message)) if message.contains("hexadecimal")
        ));
    }

    #[test]
    fn inspect_pass_json_covers_all_durable_fields_and_redacts_secrets() {
        let mut row = sample_row();
        row.payload_json = r#"{"payload":{"token":"super-secret-token-value"}}"#.into();
        row.headers_json = Some(r#"{"authorization":"Bearer super-secret-header-value"}"#.into());
        row.lease_owner = Some("relay-worker:super-secret-lease-token".into());
        row.last_error = Some("super-secret-error-text".into());
        row.next_attempt_at = Some(row.created_at);
        row.lease_expires_at = Some(row.created_at);
        row.processed_at = None;
        row.target_region = Some("city-b".into());

        let output = inspect_pass_json(&row, "inv-1");
        let rendered = output.to_string();
        for secret in [
            "super-secret-token-value",
            "super-secret-header-value",
            "super-secret-lease-token",
            "super-secret-error-text",
        ] {
            assert!(!rendered.contains(secret), "leaked secret: {secret}");
        }

        let projected = output["row"].as_object().expect("row is an object");
        for field in [
            "message_id",
            "operation_id",
            "message_type",
            "queue_name",
            "ordering_key",
            "tenant_id",
            "origin_region",
            "target_region",
            "schema_version",
            "payload_sha256",
            "status",
            "attempts",
            "next_attempt_at",
            "processed_at",
            "lease_expires_at",
            "created_at",
            "updated_at",
            "lease_owner_present",
            "headers_present",
            "last_error_present",
            "payload_len_bytes",
        ] {
            assert!(projected.contains_key(field), "missing field: {field}");
        }
        assert_eq!(
            projected.len(),
            21,
            "every durable field must be accounted for"
        );
        // provenance hash 与 status 原样透传（审计比对锚点）。
        assert_eq!(projected["payload_sha256"], "0".repeat(64));
        assert_eq!(projected["status"], "IN_DOUBT");
        assert_eq!(projected["payload_len_bytes"], row.payload_json.len());
        assert_eq!(projected["headers_present"], true);
        assert_eq!(projected["lease_owner_present"], true);
        assert_eq!(projected["last_error_present"], true);
        assert_eq!(projected["next_attempt_at"], row.created_at.to_string());
        assert_eq!(projected["processed_at"], Value::Null);
    }

    #[test]
    fn inspect_result_output_maps_typed_outcomes_to_stable_statuses() {
        let (status, output) = inspect_result_output(Ok(Some(sample_row())), "inv-1");
        assert_eq!(status, ExitStatus::Pass);
        assert_eq!(output["status"], "PASS");

        let (status, output) = inspect_result_output(Ok(None), "inv-1");
        assert_eq!(status, ExitStatus::NoInDoubtRow);
        assert_eq!(output["reason_code"], REASON_NO_IN_DOUBT_ROW);
        assert_eq!(output["row"], Value::Null);

        let (status, output) = inspect_result_output(
            Err(LocalMessageError::Database(SqlxError::RowNotFound)),
            "inv-1",
        );
        assert_eq!(status, ExitStatus::Unknown);
        assert_eq!(output["reason_code"], REASON_DB_ERROR_OUTCOME_UNPROVEN);
        // 原始 DB 错误文本不外泄。
        assert!(!output.to_string().contains("RowNotFound"));
    }

    #[test]
    fn parse_defaults_to_help_and_rejects_unknown_subcommands() {
        assert_eq!(parse_args(&args(&[])), Ok(RecoveryCommand::Help));
        assert_eq!(parse_args(&args(&["help"])), Ok(RecoveryCommand::Help));
        assert_eq!(parse_args(&args(&["--help"])), Ok(RecoveryCommand::Help));
        assert!(matches!(
            parse_args(&args(&["purge"])),
            Err(RecoveryOpError::Usage(_))
        ));
    }

    #[test]
    fn usage_text_documents_subcommands_flags_and_exit_codes() {
        let usage = usage_text();
        for token in [
            "inspect",
            "settle",
            "--message-id",
            "REQUEUE_POLICY_REFUSED",
            "QUARANTINE_APPROVAL_GATE_ABSENT",
            "PENDING",
            "UNKNOWN",
            "BLOCKED",
        ] {
            assert!(usage.contains(token), "usage must document {token}");
        }
    }
}
