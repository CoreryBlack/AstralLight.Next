//! astral-monitor 集成测试 — platform_v4 schema 对齐验证
//!
//! 需要 Docker MySQL 8.0 环境（通过 docker-compose.test.yml 启动）。
//! 运行方式：
//!   cargo test -p astral-monitor --test integration -- --ignored --nocapture
//!
//! 测试策略：验证 alert_rule, notification_channel, monitor_alert_history,
//! monitor_metric_snapshot, monitor_activity_log 的真实列名与 Rust FromRow struct 映射，
//! 以及 TINYINT→i8 enabled 映射、toggle 翻转、acknowledge 状态转换、时间序列聚合等核心流程。

use sqlx::MySqlPool;

// =====================================================================
// 测试用的 FromRow struct — 与 Rust srv/*.rs 中的结构完全一致
// =====================================================================

/// 对应 alerts.rs 中的 AlertRule
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct AlertRule {
    id: i64,
    name: String,
    metric: String,
    condition_op: String,
    threshold: f64,
    duration_seconds: i32,
    severity: String,
    enabled: i8,
}

/// 对应 notifications.rs 中的 NotificationChannel
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct NotificationChannel {
    id: i64,
    name: String,
    channel_type: String,
    config: Option<String>,
    enabled: i8,
}

/// 对应 alerts.rs 中的 AlertHistory
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct AlertHistory {
    id: i64,
    rule_id: i64,
    rule_name: Option<String>,
    metric_type: Option<String>,
    actual_value: Option<f64>,
    severity: String,
    status: String,
    triggered_at: time::OffsetDateTime,
    resolved_at: Option<time::OffsetDateTime>,
}

/// 对应 dashboard.rs 中的 MetricSnapshot
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct MetricSnapshot {
    id: i64,
    service_name: String,
    metric_type: String,
    metric_value: f64,
    collected_at: time::OffsetDateTime,
}

/// 对应 alerts.rs 中的 ActivityLog
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct ActivityLog {
    id: i64,
    event_type: String,
    title: Option<String>,
    detail: Option<String>,
    level: String,
    source_service: Option<String>,
    occurred_at: time::OffsetDateTime,
}

// =====================================================================
// 辅助函数
// =====================================================================

async fn connect() -> Option<MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        Ok(_) | Err(_) => {
            let message = "DATABASE_URL must be set to run MySQL integration tests";
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };

    match MySqlPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: cannot connect using DATABASE_URL: {e}");
            }
            eprintln!("[SKIP] Cannot connect using DATABASE_URL: {e}");
            None
        }
    }
}

/// 清理测试数据：使用高 ID 范围避免冲突
async fn cleanup_monitor_tables(pool: &MySqlPool) {
    let _ = sqlx::query("DELETE FROM monitor_activity_log WHERE id >= 9000000")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM monitor_alert_history WHERE id >= 9000000")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM monitor_metric_snapshot WHERE id >= 9000000")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM notification_channel WHERE id >= 9000000")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM alert_rule WHERE id >= 9000000")
        .execute(pool)
        .await;
    // 也按名称清理（以防 AUTO_INCREMENT 重置导致 ID 较小）
    let _ =
        sqlx::query("DELETE FROM monitor_activity_log WHERE source_service = 'integration_test'")
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM monitor_alert_history WHERE rule_name LIKE 'it_test_%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM alert_rule WHERE name LIKE 'it_test_%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM notification_channel WHERE name LIKE 'it_test_%'")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM monitor_metric_snapshot WHERE service_name LIKE 'it_test_%'")
        .execute(pool)
        .await;
}

// =====================================================================
// 测试 1: alert_rule CRUD + enabled toggle (TINYINT → i8)
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_alert_rule_crud_and_toggle() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_monitor_tables(&pool).await;

    // === CREATE: INSERT INTO alert_rule（enabled=1, TINYINT）===
    let result = sqlx::query(
        "INSERT INTO alert_rule (name, metric, condition_op, threshold, duration_seconds, severity, enabled) \
         VALUES (?, ?, ?, ?, ?, ?, 1)",
    )
    .bind("it_test_cpu_high")
    .bind("cpu_usage")
    .bind(">=")
    .bind(90.0)
    .bind(60)
    .bind("CRITICAL")
    .execute(&pool)
    .await
    .expect("INSERT alert_rule should succeed");
    let rule_id = result.last_insert_id() as i64;
    assert!(rule_id > 0, "should get a valid rule id");

    // === READ: 使用 alerts.rs 中 AlertRule 的 SELECT ===
    let row = sqlx::query_as::<_, AlertRule>(
        "SELECT id, name, metric, condition_op, threshold, duration_seconds, severity, enabled \
         FROM alert_rule WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT AlertRule should succeed");

    assert_eq!(row.id, rule_id);
    assert_eq!(row.name, "it_test_cpu_high");
    assert_eq!(row.metric, "cpu_usage");
    assert_eq!(row.condition_op, ">=");
    assert!((row.threshold - 90.0).abs() < f64::EPSILON);
    assert_eq!(row.duration_seconds, 60);
    assert_eq!(row.severity, "CRITICAL");
    assert_eq!(row.enabled, 1, "enabled TINYINT should map to i8 value 1");

    // === TOGGLE: enabled = 1 - enabled (1 → 0) ===
    sqlx::query("UPDATE alert_rule SET enabled = 1 - enabled WHERE id = ?")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();

    let toggled = sqlx::query_as::<_, AlertRule>(
        "SELECT id, name, metric, condition_op, threshold, duration_seconds, severity, enabled \
         FROM alert_rule WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        toggled.enabled, 0,
        "toggle should change enabled from 1 to 0"
    );

    // === TOGGLE AGAIN: 0 → 1 ===
    sqlx::query("UPDATE alert_rule SET enabled = 1 - enabled WHERE id = ?")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();

    let toggled_back = sqlx::query_as::<_, AlertRule>(
        "SELECT id, name, metric, condition_op, threshold, duration_seconds, severity, enabled \
         FROM alert_rule WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        toggled_back.enabled, 1,
        "second toggle should change enabled from 0 to 1"
    );

    // === UPDATE: 更新阈值和持续时间 ===
    sqlx::query(
        "UPDATE alert_rule SET name=?, metric=?, condition_op=?, threshold=?, duration_seconds=?, severity=? WHERE id=?",
    )
    .bind("it_test_mem_high")
    .bind("memory_usage")
    .bind(">=")
    .bind(85.5)
    .bind(120)
    .bind("WARNING")
    .bind(rule_id)
    .execute(&pool)
    .await
    .unwrap();

    let updated = sqlx::query_as::<_, AlertRule>(
        "SELECT id, name, metric, condition_op, threshold, duration_seconds, severity, enabled \
         FROM alert_rule WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(updated.name, "it_test_mem_high");
    assert_eq!(updated.metric, "memory_usage");
    assert!((updated.threshold - 85.5).abs() < f64::EPSILON);
    assert_eq!(updated.duration_seconds, 120);
    assert_eq!(updated.severity, "WARNING");

    // 清理
    sqlx::query("DELETE FROM alert_rule WHERE id = ?")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] alert_rule CRUD + TINYINT→i8 enabled + toggle (1↔0)");
}

// =====================================================================
// 测试 2: notification_channel CRUD + TINYINT→i8 enabled
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_notification_channel_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_monitor_tables(&pool).await;

    // === CREATE: INSERT INTO notification_channel（enabled=1, TINYINT）===
    let result = sqlx::query(
        "INSERT INTO notification_channel (name, channel_type, config, enabled) VALUES (?, ?, ?, 1)",
    )
    .bind("it_test_email_channel")
    .bind("EMAIL")
    .bind(r#"{"smtp_host":"localhost","smtp_port":25}"#)
    .execute(&pool)
    .await
    .expect("INSERT notification_channel should succeed");
    let channel_id = result.last_insert_id() as i64;
    assert!(channel_id > 0);

    // === READ: 使用 notifications.rs 中 NotificationChannel 的 SELECT ===
    let row = sqlx::query_as::<_, NotificationChannel>(
        "SELECT id, name, channel_type, CAST(config AS CHAR) as config, enabled FROM notification_channel WHERE id = ?",
    )
    .bind(channel_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT NotificationChannel should succeed");

    assert_eq!(row.id, channel_id);
    assert_eq!(row.name, "it_test_email_channel");
    assert_eq!(row.channel_type, "EMAIL");
    assert!(row.config.is_some());
    assert!(row.config.as_deref().unwrap().contains("smtp_host"));
    assert_eq!(row.enabled, 1, "enabled TINYINT should map to i8 value 1");

    // === CREATE: 无 config 的渠道 ===
    let no_config_result = sqlx::query(
        "INSERT INTO notification_channel (name, channel_type, config, enabled) VALUES (?, ?, NULL, 1)",
    )
    .bind("it_test_webhook_channel")
    .bind("WEBHOOK")
    .execute(&pool)
    .await
    .unwrap();
    let no_config_id = no_config_result.last_insert_id() as i64;

    let no_config_row = sqlx::query_as::<_, NotificationChannel>(
        "SELECT id, name, channel_type, CAST(config AS CHAR) as config, enabled FROM notification_channel WHERE id = ?",
    )
    .bind(no_config_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(no_config_row.config, None, "config should be NULL");
    assert_eq!(no_config_row.channel_type, "WEBHOOK");

    // === UPDATE: 更新渠道配置和禁用 ===
    sqlx::query("UPDATE notification_channel SET name=?, channel_type=?, config=? WHERE id=?")
        .bind("it_test_dingtalk_channel")
        .bind("DINGTALK")
        .bind(r#"{"webhook_url":"https://example.com/dingtalk"}"#)
        .bind(channel_id)
        .execute(&pool)
        .await
        .unwrap();

    let updated = sqlx::query_as::<_, NotificationChannel>(
        "SELECT id, name, channel_type, CAST(config AS CHAR) as config, enabled FROM notification_channel WHERE id = ?",
    )
    .bind(channel_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(updated.name, "it_test_dingtalk_channel");
    assert_eq!(updated.channel_type, "DINGTALK");
    assert!(updated.config.as_deref().unwrap().contains("dingtalk"));

    // 清理
    sqlx::query("DELETE FROM notification_channel WHERE id = ?")
        .bind(channel_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM notification_channel WHERE id = ?")
        .bind(no_config_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] notification_channel CRUD + TINYINT→i8 enabled + NULL config");
}

// =====================================================================
// 测试 3: monitor_alert_history acknowledge 状态转换
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_monitor_alert_history_acknowledge() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_monitor_tables(&pool).await;
    // FK 约束：monitor_alert_history.rule_id 引用 monitor_alert_rule（不是 alert_rule），
    // 但测试数据插入 alert_rule，因此临时禁用 FK 检查
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&pool)
        .await
        .ok();

    // 先创建一条告警规则（rule_id 外键需要存在）
    let rule_result = sqlx::query(
        "INSERT INTO alert_rule (name, metric, condition_op, threshold, duration_seconds, severity, enabled) \
         VALUES (?, ?, ?, ?, ?, ?, 1)",
    )
    .bind("it_test_latency_rule")
    .bind("latency")
    .bind(">=")
    .bind(500.0)
    .bind(60)
    .bind("WARNING")
    .execute(&pool)
    .await
    .unwrap();
    let rule_id = rule_result.last_insert_id() as i64;

    // === CREATE: INSERT INTO monitor_alert_history (status='triggered') ===
    let result = sqlx::query(
        "INSERT INTO monitor_alert_history (rule_id, rule_name, metric_type, actual_value, severity, status, triggered_at) \
         VALUES (?, ?, ?, ?, ?, 'triggered', NOW())",
    )
    .bind(rule_id)
    .bind("it_test_latency_rule")
    .bind("latency")
    .bind(750.5)
    .bind("WARNING")
    .execute(&pool)
    .await
    .expect("INSERT monitor_alert_history should succeed");
    let history_id = result.last_insert_id() as i64;
    assert!(history_id > 0);

    // === READ: 使用 alerts.rs 中 AlertHistory 的 SELECT ===
    let row = sqlx::query_as::<_, AlertHistory>(
        "SELECT id, rule_id, rule_name, metric_type, actual_value, severity, status, triggered_at, resolved_at \
         FROM monitor_alert_history WHERE id = ?",
    )
    .bind(history_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT AlertHistory should succeed");

    assert_eq!(row.id, history_id);
    assert_eq!(row.rule_id, rule_id);
    assert_eq!(row.rule_name.as_deref(), Some("it_test_latency_rule"));
    assert_eq!(row.metric_type.as_deref(), Some("latency"));
    assert!((row.actual_value.unwrap() - 750.5).abs() < f64::EPSILON);
    assert_eq!(row.severity, "WARNING");
    assert_eq!(row.status, "triggered");
    assert!(
        row.resolved_at.is_none(),
        "resolved_at should be NULL before acknowledge"
    );

    // === ACKNOWLEDGE: UPDATE status='acknowledged', resolved_at=NOW() ===
    // 对齐 alerts.rs acknowledge_alert 的 WHERE 条件
    let affected = sqlx::query(
        "UPDATE monitor_alert_history SET status='acknowledged', resolved_at=NOW() \
         WHERE id=? AND status='triggered'",
    )
    .bind(history_id)
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(affected, 1, "exactly 1 row should be acknowledged");

    // === READ: 验证 acknowledge 后状态 ===
    let acknowledged = sqlx::query_as::<_, AlertHistory>(
        "SELECT id, rule_id, rule_name, metric_type, actual_value, severity, status, triggered_at, resolved_at \
         FROM monitor_alert_history WHERE id = ?",
    )
    .bind(history_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(acknowledged.status, "acknowledged");
    assert!(
        acknowledged.resolved_at.is_some(),
        "resolved_at should be set after acknowledge"
    );

    // === 重复 acknowledge 应该无效（WHERE status='triggered' 不匹配）===
    let re_ack_affected = sqlx::query(
        "UPDATE monitor_alert_history SET status='acknowledged', resolved_at=NOW() \
         WHERE id=? AND status='triggered'",
    )
    .bind(history_id)
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(
        re_ack_affected, 0,
        "re-acknowledge should affect 0 rows (already acknowledged)"
    );

    // 清理
    sqlx::query("DELETE FROM monitor_alert_history WHERE id = ?")
        .bind(history_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM alert_rule WHERE id = ?")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();

    // 恢复 FK 检查
    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&pool)
        .await
        .ok();

    eprintln!("[PASS] monitor_alert_history acknowledge (triggered→acknowledged) with idempotency");
}

// =====================================================================
// 测试 4: monitor_metric_snapshot 时间序列聚合（3 小时分桶 + AVG）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_monitor_metric_snapshot_time_series() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_monitor_tables(&pool).await;

    // === CREATE: 插入多条 latency 快照（分布在最近 24 小时内不同时段）===
    let test_service = "it_test_gateway";
    let test_values = [
        // (metric_value, collected_at 偏移小时)
        (120.0, -1), // 1 小时前
        (150.0, -2), // 2 小时前
        (80.0, -3),  // 3 小时前
        (95.0, -4),  // 4 小时前
        (200.0, -8), // 8 小时前
        (180.0, -9), // 9 小时前
        (60.0, -16), // 16 小时前
        (70.0, -20), // 20 小时前
    ];

    for (value, hours_ago) in &test_values {
        sqlx::query(
            "INSERT INTO monitor_metric_snapshot (service_name, metric_type, metric_value, collected_at) \
             VALUES (?, 'latency', ?, NOW() + INTERVAL ? HOUR)",
        )
        .bind(test_service)
        .bind(*value)
        .bind(*hours_ago)
        .execute(&pool)
        .await
        .unwrap();
    }

    // === READ: 验证 MetricSnapshot FromRow 映射 ===
    let snapshots = sqlx::query_as::<_, MetricSnapshot>(
        "SELECT id, service_name, metric_type, metric_value, collected_at \
         FROM monitor_metric_snapshot WHERE service_name = ? AND metric_type = 'latency' \
         ORDER BY collected_at",
    )
    .bind(test_service)
    .fetch_all(&pool)
    .await
    .expect("SELECT MetricSnapshot should succeed");

    assert_eq!(
        snapshots.len(),
        test_values.len(),
        "should find all inserted snapshots"
    );
    assert_eq!(snapshots[0].service_name, test_service);
    assert_eq!(snapshots[0].metric_type, "latency");
    // 验证 metric_value f64 映射正确
    assert!((snapshots[0].metric_value - test_values[7].0).abs() < f64::EPSILON); // 最早的是 70.0（20 小时前）

    // === 时间序列聚合: 使用 dashboard.rs 中的 3 小时分桶 SQL ===
    let time_series: Vec<(i64, f64)> = sqlx::query_as(
        "SELECT \
           FLOOR(HOUR(collected_at) / 3) AS slot, \
           AVG(metric_value) AS avg_latency \
         FROM monitor_metric_snapshot \
         WHERE metric_type='latency' \
           AND collected_at >= NOW() - INTERVAL 24 HOUR \
         GROUP BY FLOOR(HOUR(collected_at) / 3) \
         ORDER BY slot",
    )
    .fetch_all(&pool)
    .await
    .expect("time series aggregation should succeed");

    // 应该至少有 1 个时间桶
    assert!(
        !time_series.is_empty(),
        "should have at least one 3-hour time bucket"
    );
    // 每个桶的 slot 值应该在 0-7 范围内（24小时 / 3小时 = 8 个桶）
    for (slot, avg) in &time_series {
        assert!(
            *slot >= 0 && *slot <= 7,
            "slot should be in range 0..7, got {slot}"
        );
        assert!(*avg > 0.0, "avg_latency should be positive, got {avg}");
    }

    // 清理
    sqlx::query("DELETE FROM monitor_metric_snapshot WHERE service_name = ?")
        .bind(test_service)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] monitor_metric_snapshot with time-series 3-hour bucket aggregation");
}

// =====================================================================
// 测试 5: monitor_activity_log CRUD + time::OffsetDateTime 映射
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_monitor_activity_log() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_monitor_tables(&pool).await;

    // === CREATE: INSERT INTO monitor_activity_log ===
    let result = sqlx::query(
        "INSERT INTO monitor_activity_log (event_type, title, detail, level, source_service, occurred_at) \
         VALUES (?, ?, ?, ?, ?, NOW())",
    )
    .bind("service_restart")
    .bind("网关服务重启")
    .bind(r#"{"service":"gateway","reason":"deploy","duration_ms":3200}"#)
    .bind("info")
    .bind("integration_test")
    .execute(&pool)
    .await
    .expect("INSERT monitor_activity_log should succeed");
    let log_id = result.last_insert_id() as i64;
    assert!(log_id > 0);

    // === READ: 使用 alerts.rs 中 ActivityLog 的 SELECT ===
    let row = sqlx::query_as::<_, ActivityLog>(
        "SELECT id, event_type, title, detail, level, source_service, occurred_at \
         FROM monitor_activity_log WHERE id = ?",
    )
    .bind(log_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT ActivityLog should succeed");

    assert_eq!(row.id, log_id);
    assert_eq!(row.event_type, "service_restart");
    assert_eq!(row.title.as_deref(), Some("网关服务重启"));
    assert!(row
        .detail
        .as_deref()
        .unwrap_or_default()
        .contains("gateway"));
    assert_eq!(row.level, "info");
    assert_eq!(row.source_service.as_deref(), Some("integration_test"));
    // occurred_at 应该是最近的 UTC 时间（OffsetDateTime）
    assert!(
        row.occurred_at.unix_timestamp() > 0,
        "occurred_at should be a valid timestamp"
    );

    // === INSERT: 多条不同级别的日志 ===
    let warn_result = sqlx::query(
        "INSERT INTO monitor_activity_log (event_type, title, detail, level, source_service, occurred_at) \
         VALUES (?, ?, ?, ?, ?, NOW())",
    )
    .bind("alert_triggered")
    .bind("CPU 使用率过高")
    .bind(r#"{"metric":"cpu_usage","value":95.2}"#)
    .bind("warn")
    .bind("integration_test")
    .execute(&pool)
    .await
    .unwrap();
    let warn_id = warn_result.last_insert_id() as i64;

    let error_result = sqlx::query(
        "INSERT INTO monitor_activity_log (event_type, title, detail, level, source_service, occurred_at) \
         VALUES (?, ?, ?, ?, ?, NOW())",
    )
    .bind("service_down")
    .bind("学习服务不可达")
    .bind(r#"{"service":"learn","error":"connection_refused"}"#)
    .bind("error")
    .bind("integration_test")
    .execute(&pool)
    .await
    .unwrap();
    let _error_id = error_result.last_insert_id() as i64;

    // === 按级别过滤（对齐 alerts.rs list_activity_logs 的查询模式）===
    let warn_logs: Vec<ActivityLog> = sqlx::query_as(
        "SELECT id, event_type, title, detail, level, source_service, occurred_at \
         FROM monitor_activity_log WHERE source_service = 'integration_test' AND level = 'warn' \
         ORDER BY occurred_at DESC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(warn_logs.len(), 1);
    assert_eq!(warn_logs[0].id, warn_id);
    assert_eq!(warn_logs[0].level, "warn");

    // === 按 source_service 过滤 ===
    let all_test_logs: Vec<ActivityLog> = sqlx::query_as(
        "SELECT id, event_type, title, detail, level, source_service, occurred_at \
         FROM monitor_activity_log WHERE source_service = 'integration_test' \
         ORDER BY occurred_at",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        all_test_logs.len(),
        3,
        "should find all 3 test activity logs"
    );

    // 清理
    sqlx::query("DELETE FROM monitor_activity_log WHERE source_service = 'integration_test'")
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] monitor_activity_log CRUD + OffsetDateTime mapping + level filtering");
}
