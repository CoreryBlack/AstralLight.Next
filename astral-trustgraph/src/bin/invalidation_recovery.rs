//! IN_DOUBT 失效恢复运维 CLI（当前阶段：只读 inspect + 写路径显式拒绝）。
//!
//! 职责边界（对齐 `service::invalidation_recovery` 模块文档）：
//!
//! - **纯校验先行**：argv 解析与全部 shape 校验在任何 env 读取/连接之前
//!   完成（先静态纯校验，再 SQL）。
//! - **settle 零 I/O**：`settle` 子命令在读取 `DATABASE_URL`、建立连接
//!   之前就被策略门拒绝（requeue → exit 3，quarantine → exit 7）；
//!   本 CLI 从不调用 `reconcile_in_doubt` 写路径，绝不伪造 PASS，
//!   `applied` 恒为 `false`。
//! - **inspect 只读**：唯一 DB 访问是
//!   `LocalMessageRepository::load_in_doubt`；证据 JSON 单行输出到
//!   stdout，敏感面（payload 内容、header 值、lease token、last_error
//!   原文）永不输出。
//! - **失败语义**：DB env 缺失/scheme 非法/连接失败 → `BLOCKED`
//!   （required gate 未启动，无任何 durable 状态被读写）；连接建立后
//!   的读取失败 → `UNKNOWN` + 稳定机器 code，不回显 URL 与原始 DB
//!   错误文本；无自动重试，不能用 elapsed time 猜测任何 durable 结果。
//!
//! 用法与退出码：`invalidation_recovery help`（或见
//! `service::invalidation_recovery::usage_text`）。真实 Exec-L3 运维恢复
//! （quarantine settlement）必须等待主 Agent 登记的 runbook + 人工终审门。

use std::io::Write as _;
use std::time::Duration;

use astral_db::LocalMessageRepository;
use astral_trustgraph::service::invalidation_recovery as recovery;
use serde_json::Value;
use sqlx::mysql::MySqlPoolOptions;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let invocation_id = uuid::Uuid::new_v4().to_string();

    // 1) 纯校验层：argv 解析 + bounded input 校验，先于任何 I/O。
    let command = match recovery::parse_args(&args) {
        Ok(command) => command,
        Err(error) => {
            let (status, output) = recovery::usage_error_output(&error, &invocation_id);
            emit_stderr(&output);
            std::process::exit(status.code());
        }
    };

    match command {
        recovery::RecoveryCommand::Help => {
            print!("{}", recovery::usage_text());
            let _ = std::io::stdout().flush();
        }
        recovery::RecoveryCommand::Settle(request) => {
            // 2) 策略门（零 I/O）：先于 env/连接；从不调用写路径。
            let (status, output) = recovery::settle_refusal_output(&request, &invocation_id);
            emit_stdout(&output);
            std::process::exit(status.code());
        }
        recovery::RecoveryCommand::Inspect { message_id } => {
            // 3) DB 门：env gate → connect gate，失败一律 BLOCKED
            //    （required gate 未启动；URL 值永不打印）。
            let database_url = match read_database_url() {
                Ok(url) => url,
                Err(reason_code) => {
                    emit_stdout(&recovery::inspect_blocked_output(
                        reason_code,
                        &invocation_id,
                    ));
                    std::process::exit(recovery::ExitStatus::Blocked.code());
                }
            };
            let pool = match tokio::time::timeout(
                Duration::from_secs(5),
                MySqlPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(5))
                    .connect(&database_url),
            )
            .await
            {
                Ok(Ok(pool)) => pool,
                Ok(Err(_)) | Err(_) => {
                    emit_stdout(&recovery::inspect_blocked_output(
                        recovery::REASON_DB_UNREACHABLE,
                        &invocation_id,
                    ));
                    std::process::exit(recovery::ExitStatus::Blocked.code());
                }
            };

            // 4) 只读 exact IN_DOUBT load + 脱敏证据输出。
            let repository = LocalMessageRepository::new(pool);
            let result = recovery::inspect_in_doubt(&repository, &message_id).await;
            let (status, output) = recovery::inspect_result_output(result, &invocation_id);
            emit_stdout(&output);
            std::process::exit(status.code());
        }
    }
}

/// 读取并校验 `DATABASE_URL`；失败返回稳定机器 code。URL 值绝不打印，
/// 也不进入任何错误输出。
fn read_database_url() -> Result<String, &'static str> {
    match std::env::var("DATABASE_URL") {
        Ok(value) => {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                Err(recovery::REASON_DB_ENV_MISSING)
            } else if trimmed.starts_with("mysql://") {
                Ok(trimmed)
            } else {
                Err(recovery::REASON_DB_URL_SCHEME_INVALID)
            }
        }
        Err(_) => Err(recovery::REASON_DB_ENV_MISSING),
    }
}

/// 证据行统一单行 JSON 到 stdout（失败时退出码承载分类）。
fn emit_stdout(value: &Value) {
    if let Ok(line) = serde_json::to_string(value) {
        println!("{line}");
        let _ = std::io::stdout().flush();
    }
}

/// 用法错误到 stderr（非证据行）。
fn emit_stderr(value: &Value) {
    if let Ok(line) = serde_json::to_string(value) {
        eprintln!("{line}");
    }
}
