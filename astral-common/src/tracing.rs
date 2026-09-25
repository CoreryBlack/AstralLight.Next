//! 日志与追踪初始化
//!
//! 与 Java SLF4J + Logback 的对应关系：
//! - `tracing_subscriber` → Logback
//! - `tracing::info!()` → SLF4J `logger.info()`
//! - 结构化字段 → MDC

use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry};

/// 初始化 tracing 日志系统
///
/// 配置：
/// - JSON 格式（生产环境可读）
/// - 通过 `RUST_LOG` 环境变量控制日志级别（默认 `info`）
/// - 输出到 stderr（与 Java Logback 一致）
pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let formatting_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    Registry::default()
        .with(env_filter)
        .with(formatting_layer)
        .init();

    tracing::info!(target: "startup", "tracing initialized, log level: RUST_LOG=info");
}

/// 初始化带有 JSON 和终端友好两种输出的日志系统
///
/// 开发环境使用终端格式（带颜色），生产环境使用 JSON 格式
pub fn init_tracing_with_env(service_name: &str, json_output: bool) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if json_output {
        let json_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true);

        Registry::default().with(env_filter).with(json_layer).init();
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true);

        Registry::default().with(env_filter).with(fmt_layer).init();
    }

    tracing::info!(target: "startup", service = %service_name, "service started");
}
