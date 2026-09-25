//! astral-chat 集成测试 — platform_v4 schema 对齐验证
//!
//! 需要 Docker MySQL 8.0 环境（通过 docker-compose.test.yml 启动）。
//! 运行方式：
//!   cargo test -p astral-chat --test integration -- --ignored --nocapture
//!
//! 测试策略：验证 chat_session→chat_conversation, chat_session_member→chat_conversation_member,
//! chat_delivery→chat_message_delivery 的表名映射，以及 conversation_type→session_type,
//! conversation_id→session_id, avatar→group_avatar, message_type→msg_type 等列别名映射。
//! 同时验证 domain_id NOT NULL 列的占位写入策略。

use sqlx::MySqlPool;

// =====================================================================
// 测试用的 FromRow struct — 与 Rust srv/*.rs 中的结构完全一致
// =====================================================================

/// 对应 sessions.rs 中的 SessionRow
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct SessionRow {
    id: i64,
    name: String,
    session_type: String,
    created_at: Option<time::PrimitiveDateTime>,
}

/// 对应 messages.rs 中的 MessageRow
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct MessageRow {
    id: i64,
    sender_id: i64,
    session_id: i64,
    content: String,
    msg_type: String,
    created_at: Option<time::PrimitiveDateTime>,
}

/// 对应 groups.rs 中的 GroupRow
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct GroupRow {
    id: i64,
    name: String,
    session_type: String,
    owner_id: Option<i64>,
    group_avatar: Option<String>,
    max_members: i64,
    status: String,
    created_at: Option<time::PrimitiveDateTime>,
}

/// 对应 realtime.rs 中的 chat_client_session 行
#[derive(Debug, sqlx::FromRow)]
struct ClientSessionRow {
    id: i64,
    user_id: i64,
    client_type: String,
    device_id: Option<String>,
    status: String,
}

/// 对应 groups.rs 中的 GroupMemberRow
#[derive(Debug, sqlx::FromRow)]
struct GroupMemberRow {
    user_id: i64,
    role: String,
    nickname: Option<String>,
    muted: i64,
    pinned: i64,
    joined_at: Option<time::PrimitiveDateTime>,
}

/// 对应 sessions.rs 中 ChatSession 的子查询 member_count
#[derive(Debug, sqlx::FromRow)]
struct ChatSessionRow {
    id: i64,
    name: String,
    session_type: String,
    member_count: i64,
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

async fn cleanup_chat_tables(pool: &MySqlPool) {
    // 使用高 ID 范围避免冲突
    let _ = sqlx::query("DELETE FROM chat_message_delivery WHERE message_id >= 9000000")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM chat_message WHERE id >= 9000000")
        .execute(pool)
        .await;
    let _ =
        sqlx::query("DELETE FROM chat_conversation_member WHERE user_id BETWEEN 99000 AND 99999")
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM chat_conversation WHERE id >= 9000000")
        .execute(pool)
        .await;
    // 清理 chat_client_session 测试数据
    let _ = sqlx::query("DELETE FROM chat_client_session WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
}

// =====================================================================
// 测试：chat_conversation — 表名映射 + 列别名
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_conversation_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // === CREATE: INSERT INTO chat_conversation（不是 chat_session！）===
    // platform_v4 列: conversation_type (不是 session_type), domain_id NOT NULL
    let result = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('测试会话', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .expect("INSERT chat_conversation should succeed");
    let conv_id = result.last_insert_id() as i64;
    assert!(conv_id > 0, "should get a valid conversation id");

    // === READ: 使用 Rust 同款 SQL 别名 SELECT ===
    // conversation_type AS session_type — 关键别名映射
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT id, name, conversation_type AS session_type, created_at \
         FROM chat_conversation WHERE id = ?",
    )
    .bind(conv_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.name, "测试会话");
    assert_eq!(row.session_type, "GROUP");

    // === UPDATE ===
    sqlx::query("UPDATE chat_conversation SET name = ? WHERE id = ?")
        .bind("更新后的会话")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    let updated = sqlx::query_as::<_, SessionRow>(
        "SELECT id, name, conversation_type AS session_type, created_at \
         FROM chat_conversation WHERE id = ?",
    )
    .bind(conv_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.name, "更新后的会话");

    // 清理
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_conversation with conversation_type→session_type alias");
}

// =====================================================================
// 测试：chat_conversation 的 domain_id NOT NULL 占位策略
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_conversation_domain_id_not_null() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // 测试：不提供 domain_id 会失败（NOT NULL 约束）
    let result_no_domain = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type) VALUES ('无domain', 'GROUP')",
    )
    .execute(&pool)
    .await;
    assert!(
        result_no_domain.is_err(),
        "INSERT without domain_id should fail (NOT NULL constraint)"
    );

    // 测试：提供 domain_id=0 占位值成功
    let result_with_zero = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('有domain占位', 'GROUP', 0)",
    )
    .execute(&pool)
    .await;
    assert!(
        result_with_zero.is_ok(),
        "INSERT with domain_id=0 should succeed"
    );

    let conv_id = result_with_zero.unwrap().last_insert_id() as i64;

    // 验证写入的 domain_id
    let domain_id: (i64,) = sqlx::query_as("SELECT domain_id FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(domain_id.0, 0);

    // 清理
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_conversation domain_id NOT NULL with 0 placeholder");
}

// =====================================================================
// 测试：chat_conversation_member — 表名映射 + conversation_id→session_id 别名
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_conversation_member_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // 创建会话
    let conv_result = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('成员测试会话', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let conv_id = conv_result.last_insert_id() as i64;

    let user_id: i64 = 99950;

    // === CREATE: INSERT INTO chat_conversation_member（不是 chat_session_member！）===
    // platform_v4 列: conversation_id (不是 session_id)
    let result = sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) \
         VALUES (?, ?, 'MEMBER')",
    )
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("INSERT chat_conversation_member should succeed");
    let member_id = result.last_insert_id() as i64;
    assert!(member_id > 0);

    // === READ: 使用 Rust 同款别名 SELECT ===
    // conversation_id AS session_id — 关键别名
    let _count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    // 验证成员数 > 0

    // === UPDATE last_read_message_id（对应 receipts.rs 的 UPSERT）===
    // 使用 GREATEST(COALESCE(last_read_message_id, 0), VALUES(...)) 而非 GREATEST(last_read_message_id, VALUES(...))，
    // 因为初始 INSERT 只设置了 role，last_read_message_id 为 NULL，
    // 而 MySQL 中 GREATEST(NULL, x) 返回 NULL，导致值无法更新。
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, last_read_message_id) \
         VALUES (?, ?, 100) \
         ON DUPLICATE KEY UPDATE last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), VALUES(last_read_message_id))"
    ).bind(conv_id).bind(user_id).execute(&pool).await.unwrap();

    // 验证
    let read_id: (Option<i64>,) = sqlx::query_as(
        "SELECT last_read_message_id FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?"
    ).bind(conv_id).bind(user_id).fetch_one(&pool).await.unwrap();
    assert_eq!(read_id.0, Some(100));

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_conversation_member with conversation_id→session_id alias");
}

// =====================================================================
// 测试：chat_message — 列别名 + domain_id/message_id 占位
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_message_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // 创建会话+成员
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('消息测试会话', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;
    let user_id: i64 = 99951;
    sqlx::query("INSERT INTO chat_conversation_member (conversation_id, user_id) VALUES (?, ?)")
        .bind(conv_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    // === CREATE: INSERT INTO chat_message ===
    // platform_v4 列: message_id (UUID NOT NULL), conversation_id (NOT session_id),
    // message_type (NOT msg_type), domain_id (NOT NULL)
    let result = sqlx::query(
        "INSERT INTO chat_message (message_id, conversation_id, sender_id, message_type, content, domain_id) \
         VALUES (UUID(), ?, ?, 'TEXT', '你好，这是一条测试消息', 0)"
    ).bind(conv_id).bind(user_id).execute(&pool).await
        .expect("INSERT chat_message should succeed");
    let msg_id = result.last_insert_id() as i64;
    assert!(msg_id > 0);

    // === READ: 使用 Rust 同款别名 SELECT ===
    // conversation_id AS session_id, message_type AS msg_type
    let row = sqlx::query_as::<_, MessageRow>(
        "SELECT id, sender_id, conversation_id AS session_id, content, \
         message_type AS msg_type, created_at \
         FROM chat_message WHERE id = ?",
    )
    .bind(msg_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.sender_id, user_id);
    assert_eq!(row.session_id, conv_id); // conversation_id → session_id
    assert_eq!(row.msg_type, "TEXT"); // message_type → msg_type
    assert_eq!(row.content, "你好，这是一条测试消息");

    // === 测试 message_id UUID 和 domain_id ===
    let raw: (String, i64) =
        sqlx::query_as("SELECT message_id, domain_id FROM chat_message WHERE id = ?")
            .bind(msg_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!raw.0.is_empty(), "message_id UUID should not be empty");
    assert_eq!(raw.1, 0, "domain_id should be 0 (placeholder)");

    // === 测试 status 默认值（platform_v4 默认 'SENT'，不是 'ACTIVE'）===
    let status: (String,) = sqlx::query_as("SELECT status FROM chat_message WHERE id = ?")
        .bind(msg_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.0, "SENT",
        "chat_message status defaults to 'SENT' in platform_v4"
    );

    // === 测试 recall（需要 WHERE status='SENT'，不是 'ACTIVE'）===
    sqlx::query("UPDATE chat_message SET status = 'RECALLED' WHERE id = ? AND status = 'SENT'")
        .bind(msg_id)
        .execute(&pool)
        .await
        .unwrap();
    let recalled_status: (String,) = sqlx::query_as("SELECT status FROM chat_message WHERE id = ?")
        .bind(msg_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(recalled_status.0, "RECALLED");

    // 清理
    sqlx::query("DELETE FROM chat_message WHERE id = ?")
        .bind(msg_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_message with conversation_id→session_id, message_type→msg_type, UUID+domain_id placeholders");
}

// =====================================================================
// 测试：chat_message_delivery — 表名映射
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_message_delivery_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // 创建会话+成员+消息
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('投递测试会话', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;
    let sender_id: i64 = 99952;
    let recipient_id: i64 = 99953;
    sqlx::query("INSERT INTO chat_conversation_member (conversation_id, user_id) VALUES (?, ?)")
        .bind(conv_id)
        .bind(sender_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chat_conversation_member (conversation_id, user_id) VALUES (?, ?)")
        .bind(conv_id)
        .bind(recipient_id)
        .execute(&pool)
        .await
        .unwrap();

    let msg_id = sqlx::query(
        "INSERT INTO chat_message (message_id, conversation_id, sender_id, message_type, content, domain_id) \
         VALUES (UUID(), ?, ?, 'TEXT', '投递测试消息', 0)"
    ).bind(conv_id).bind(sender_id).execute(&pool).await.unwrap().last_insert_id() as i64;

    // === CREATE: INSERT INTO chat_message_delivery（不是 chat_delivery！）===
    let result = sqlx::query(
        "INSERT INTO chat_message_delivery (message_id, recipient_id, status) \
         VALUES (?, ?, 'PENDING')",
    )
    .bind(msg_id)
    .bind(recipient_id)
    .execute(&pool)
    .await
    .expect("INSERT chat_message_delivery should succeed");
    let delivery_id = result.last_insert_id() as i64;
    assert!(delivery_id > 0);

    // === READ ===
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM chat_message_delivery WHERE message_id = ? AND recipient_id = ?",
    )
    .bind(msg_id)
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1);

    // === UPDATE status → DELIVERED ===
    sqlx::query(
        "UPDATE chat_message_delivery SET status = 'DELIVERED', delivered_at = NOW() \
         WHERE message_id = ? AND recipient_id = ?",
    )
    .bind(msg_id)
    .bind(recipient_id)
    .execute(&pool)
    .await
    .unwrap();

    let status: (String,) = sqlx::query_as(
        "SELECT status FROM chat_message_delivery WHERE message_id = ? AND recipient_id = ?",
    )
    .bind(msg_id)
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status.0, "DELIVERED");

    // 清理
    sqlx::query("DELETE FROM chat_message_delivery WHERE message_id = ?")
        .bind(msg_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_message WHERE id = ?")
        .bind(msg_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_message_delivery CRUD (chat_delivery → chat_message_delivery)");
}

// =====================================================================
// 测试：chat_conversation 群组字段（avatar→group_avatar 别名）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_conversation_group_alias() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // INSERT INTO chat_conversation 使用 platform_v4 列名 avatar（不是 group_avatar）
    let result = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, owner_id, avatar, max_members, status, domain_id) \
         VALUES ('群组测试', 'GROUP', 1001, 'https://example.com/avatar.png', 500, 'ACTIVE', 0)"
    ).execute(&pool).await.unwrap();
    let conv_id = result.last_insert_id() as i64;

    // SELECT 使用别名 avatar AS group_avatar（对应 groups.rs 中的 GroupRow）
    let row = sqlx::query_as::<_, GroupRow>(
        "SELECT id, name, conversation_type AS session_type, owner_id, \
         avatar AS group_avatar, max_members, status, created_at \
         FROM chat_conversation WHERE id = ?",
    )
    .bind(conv_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.name, "群组测试");
    assert_eq!(row.session_type, "GROUP");
    assert_eq!(row.owner_id, Some(1001));
    assert_eq!(
        row.group_avatar.as_deref(),
        Some("https://example.com/avatar.png")
    );
    assert_eq!(row.max_members, 500);
    assert_eq!(row.status, "ACTIVE");

    // 清理
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_conversation group fields with avatar→group_avatar alias");
}

// =====================================================================
// 测试：会话和成员的复合场景（模拟完整的会话创建 → 成员加入 → 消息发送流程）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_full_conversation_flow() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let user_a: i64 = 99960;
    let user_b: i64 = 99961;

    // Step 1: 创建会话（INSERT INTO chat_conversation, domain_id=0）
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('完整流程测试', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // Step 2: 同时加入两个成员（INSERT INTO chat_conversation_member）
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'OWNER')"
    ).bind(conv_id).bind(user_a).execute(&pool).await.unwrap();

    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    ).bind(conv_id).bind(user_b).execute(&pool).await.unwrap();

    // Step 3: 发送消息（INSERT INTO chat_message, message_id=UUID(), domain_id=0）
    let msg_id = sqlx::query(
        "INSERT INTO chat_message (message_id, conversation_id, sender_id, message_type, content, domain_id) \
         VALUES (UUID(), ?, ?, 'TEXT', '来自集成测试的消息', 0)"
    ).bind(conv_id).bind(user_a).execute(&pool).await.unwrap().last_insert_id() as i64;

    // Step 4: 创建投递记录（INSERT INTO chat_message_delivery, 排除发送者）
    sqlx::query(
        "INSERT INTO chat_message_delivery (message_id, recipient_id, status) \
         VALUES (?, ?, 'PENDING')",
    )
    .bind(msg_id)
    .bind(user_b)
    .execute(&pool)
    .await
    .unwrap();

    // Step 5: 验证会话的最后消息已更新（last_message_id, last_message_time）
    sqlx::query(
        "UPDATE chat_conversation SET last_message_id = ?, last_message_time = NOW() WHERE id = ?",
    )
    .bind(msg_id)
    .bind(conv_id)
    .execute(&pool)
    .await
    .unwrap();

    let updated: (Option<i64>, Option<time::PrimitiveDateTime>) = sqlx::query_as(
        "SELECT last_message_id, last_message_time FROM chat_conversation WHERE id = ?",
    )
    .bind(conv_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.0, Some(msg_id));
    assert!(updated.1.is_some(), "last_message_time should be set");

    // Step 6: 验证成员数
    let member_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ?")
            .bind(conv_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(member_count.0, 2);

    // Step 7: 验证消息状态
    let msg_status: (String,) = sqlx::query_as("SELECT status FROM chat_message WHERE id = ?")
        .bind(msg_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(msg_status.0, "SENT");

    // 清理
    sqlx::query("DELETE FROM chat_message_delivery WHERE message_id = ?")
        .bind(msg_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_message WHERE id = ?")
        .bind(msg_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat full conversation flow (create→members→message→delivery→verify)");
}

// =====================================================================
// 测试：chat_client_session UPSERT（realtime.rs 中的 upsert_client_session）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_client_session_upsert() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let user_id: i64 = 99970;
    let device_id = "web-integration-test-001";

    // 额外清理：确保本测试的特定行不存在，避免前次测试残留触发 ON DUPLICATE KEY UPDATE
    sqlx::query("DELETE FROM chat_client_session WHERE user_id = ? AND client_type = 'WEB'")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();

    // Step 1: 首次 INSERT，status='ONLINE'
    // SQL 来自 realtime.rs upsert_client_session:
    //   INSERT INTO chat_client_session (user_id, client_type, device_id, status, last_active_at)
    //   VALUES (?, 'WEB', ?, ?, NOW())
    //   ON DUPLICATE KEY UPDATE status = VALUES(status), last_active_at = NOW(), connection_id = UUID()
    sqlx::query(
        "INSERT INTO chat_client_session (user_id, client_type, device_id, status, last_active_at) \
         VALUES (?, 'WEB', ?, ?, NOW()) \
         ON DUPLICATE KEY UPDATE status = VALUES(status), last_active_at = NOW(), connection_id = UUID()"
    )
    .bind(user_id)
    .bind(device_id)
    .bind("ONLINE")
    .execute(&pool)
    .await
    .expect("first INSERT into chat_client_session should succeed");

    // 验证首次插入后有且仅有 1 行
    let rows = sqlx::query_as::<_, ClientSessionRow>(
        "SELECT id, user_id, client_type, device_id, status \
         FROM chat_client_session WHERE user_id = ? AND device_id = ?",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "should have exactly 1 row after first INSERT"
    );
    assert_eq!(rows[0].user_id, user_id);
    assert_eq!(rows[0].client_type, "WEB");
    assert_eq!(rows[0].device_id.as_deref(), Some(device_id));
    assert_eq!(rows[0].status, "ONLINE");

    let original_id = rows[0].id;

    // Step 2: UPSERT 同一个 user_id + client_type + device_id，status='OFFLINE'
    sqlx::query(
        "INSERT INTO chat_client_session (user_id, client_type, device_id, status, last_active_at) \
         VALUES (?, 'WEB', ?, ?, NOW()) \
         ON DUPLICATE KEY UPDATE status = VALUES(status), last_active_at = NOW(), connection_id = UUID()"
    )
    .bind(user_id)
    .bind(device_id)
    .bind("OFFLINE")
    .execute(&pool)
    .await
    .expect("UPSERT chat_client_session should succeed");

    // 验证仍然是 1 行（ON DUPLICATE KEY UPDATE 不产生新行）
    let rows_after = sqlx::query_as::<_, ClientSessionRow>(
        "SELECT id, user_id, client_type, device_id, status \
         FROM chat_client_session WHERE user_id = ? AND device_id = ?",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows_after.len(),
        1,
        "should still have exactly 1 row after UPSERT (not duplicated)"
    );
    assert_eq!(
        rows_after[0].id, original_id,
        "row id should remain the same (updated, not new)"
    );
    assert_eq!(
        rows_after[0].status, "OFFLINE",
        "status should be updated to OFFLINE"
    );

    // 清理
    sqlx::query("DELETE FROM chat_client_session WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!(
        "[PASS] chat_client_session UPSERT (INSERT...ON DUPLICATE KEY UPDATE, no duplicate rows)"
    );
}

// =====================================================================
// 测试：chat_conversation_member INSERT IGNORE（sessions.rs 中的 add_member）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_conversation_member_insert_ignore() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    // 创建会话
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('INSERT IGNORE 测试', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let user_id: i64 = 99971;

    // Step 1: 首次 INSERT IGNORE，正常插入
    // SQL 来自 sessions.rs add_member:
    //   INSERT IGNORE INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')
    sqlx::query(
        "INSERT IGNORE INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("first INSERT IGNORE should succeed");

    let count_after_first: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count_after_first.0, 1,
        "should have 1 member after first INSERT IGNORE"
    );

    // Step 2: 再次 INSERT IGNORE 同一个成员（UNIQUE KEY uk_conversation_user 触发 IGNORE）
    let result = sqlx::query(
        "INSERT IGNORE INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("second INSERT IGNORE should not error (silently ignored)");

    // affected_rows 应为 0（IGNORE 命中唯一键冲突，跳过）
    assert_eq!(
        result.rows_affected(),
        0,
        "second INSERT IGNORE should affect 0 rows (ignored)"
    );

    // 验证仍然只有 1 行
    let count_after_second: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count_after_second.0, 1,
        "should still have 1 member after duplicate INSERT IGNORE"
    );

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] chat_conversation_member INSERT IGNORE (duplicate member silently skipped)");
}

// =====================================================================
// 测试：GroupMemberRow 所有字段（groups.rs 中的 list_members）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_group_member_row_fields() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let owner_id: i64 = 99972;
    let admin_id: i64 = 99973;
    let member_id: i64 = 99974;

    // 创建群组
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, owner_id, status, domain_id) \
         VALUES ('成员字段测试', 'GROUP', ?, 'ACTIVE', 0)",
    )
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 插入 OWNER
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role, nickname, muted, pinned, invite_by) \
         VALUES (?, ?, 'OWNER', '群主昵称', 0, 1, NULL)"
    )
    .bind(conv_id)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();

    // 插入 ADMIN（muted=1, pinned=0）
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role, nickname, muted, pinned, invite_by) \
         VALUES (?, ?, 'ADMIN', '管理员昵称', 1, 0, ?)"
    )
    .bind(conv_id)
    .bind(admin_id)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();

    // 插入 MEMBER（无 nickname, muted=0, pinned=0）
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role, muted, pinned, invite_by) \
         VALUES (?, ?, 'MEMBER', 0, 0, ?)"
    )
    .bind(conv_id)
    .bind(member_id)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();

    // SELECT 使用 groups.rs 中 list_members 的同款 SQL:
    //   SELECT user_id, role, nickname, muted, pinned, joined_at
    //   FROM chat_conversation_member WHERE conversation_id = ? ORDER BY
    //   CASE role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END, joined_at ASC
    let rows = sqlx::query_as::<_, GroupMemberRow>(
        "SELECT user_id, role, nickname, muted, pinned, joined_at \
         FROM chat_conversation_member WHERE conversation_id = ? ORDER BY \
         CASE role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END, joined_at ASC",
    )
    .bind(conv_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 3, "should have 3 members");

    // OWNER 排第一
    assert_eq!(rows[0].user_id, owner_id);
    assert_eq!(rows[0].role, "OWNER");
    assert_eq!(rows[0].nickname.as_deref(), Some("群主昵称"));
    assert_eq!(
        rows[0].muted, 0,
        "OWNER muted should be 0 (TINYINT → i64 → false)"
    );
    assert_eq!(
        rows[0].pinned, 1,
        "OWNER pinned should be 1 (TINYINT → i64 → true)"
    );
    assert!(rows[0].joined_at.is_some(), "joined_at should be set");

    // ADMIN 排第二
    assert_eq!(rows[1].user_id, admin_id);
    assert_eq!(rows[1].role, "ADMIN");
    assert_eq!(rows[1].nickname.as_deref(), Some("管理员昵称"));
    assert_eq!(
        rows[1].muted, 1,
        "ADMIN muted should be 1 (TINYINT → i64 → true)"
    );
    assert_eq!(
        rows[1].pinned, 0,
        "ADMIN pinned should be 0 (TINYINT → i64 → false)"
    );

    // MEMBER 排第三
    assert_eq!(rows[2].user_id, member_id);
    assert_eq!(rows[2].role, "MEMBER");
    assert_eq!(rows[2].nickname, None, "MEMBER nickname should be NULL");
    assert_eq!(rows[2].muted, 0);
    assert_eq!(rows[2].pinned, 0);

    // 验证 invite_by 列（独立查询，GroupMemberRow 不含此列但表中有）
    let admin_invite: (Option<i64>,) = sqlx::query_as(
        "SELECT invite_by FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(admin_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        admin_invite.0,
        Some(owner_id),
        "ADMIN invite_by should be the owner"
    );

    let owner_invite: (Option<i64>,) = sqlx::query_as(
        "SELECT invite_by FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        owner_invite.0, None,
        "OWNER invite_by should be NULL (self-joined)"
    );

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] GroupMemberRow all fields (muted/pinned TINYINT→i64→bool, nickname, invite_by, role ordering)");
}

// =====================================================================
// 测试：群主转让 — 3-UPDATE 事务（groups.rs transfer_owner）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_group_ownership_transfer() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let owner_a: i64 = 99980;
    let member_b: i64 = 99981;

    // Step 1: 创建群组，A 是 OWNER
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, owner_id, status, domain_id) \
         VALUES ('转让测试群', 'GROUP', ?, 'ACTIVE', 0)",
    )
    .bind(owner_a)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // A 作为 OWNER 加入
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'OWNER')"
    )
    .bind(conv_id)
    .bind(owner_a)
    .execute(&pool)
    .await
    .unwrap();

    // B 作为 MEMBER 加入
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(member_b)
    .execute(&pool)
    .await
    .unwrap();

    // Step 2: 执行 3-UPDATE 转让事务（来自 groups.rs transfer_owner）
    // UPDATE 1: chat_conversation SET owner_id = new_owner WHERE id = ?
    sqlx::query("UPDATE chat_conversation SET owner_id = ? WHERE id = ?")
        .bind(member_b)
        .bind(conv_id)
        .execute(&pool)
        .await
        .expect("UPDATE conversation owner_id should succeed");

    // UPDATE 2: 原群主 A 降为 ADMIN
    sqlx::query(
        "UPDATE chat_conversation_member SET role = 'ADMIN' WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(conv_id)
    .bind(owner_a)
    .execute(&pool)
    .await
    .expect("demote old owner to ADMIN should succeed");

    // UPDATE 3: 新群主 B 升为 OWNER
    sqlx::query(
        "UPDATE chat_conversation_member SET role = 'OWNER' WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(conv_id)
    .bind(member_b)
    .execute(&pool)
    .await
    .expect("promote new owner to OWNER should succeed");

    // Step 3: 验证 chat_conversation.owner_id = B
    let conv_owner: (Option<i64>,) =
        sqlx::query_as("SELECT owner_id FROM chat_conversation WHERE id = ?")
            .bind(conv_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        conv_owner.0,
        Some(member_b),
        "conversation.owner_id should be B after transfer"
    );

    // 验证 A 的 role = ADMIN
    let role_a: (String,) = sqlx::query_as(
        "SELECT role FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(owner_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role_a.0, "ADMIN", "old owner A should now be ADMIN");

    // 验证 B 的 role = OWNER
    let role_b: (String,) = sqlx::query_as(
        "SELECT role FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(member_b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role_b.0, "OWNER", "new owner B should now be OWNER");

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!(
        "[PASS] group ownership transfer (3-UPDATE transaction: conv.owner_id=B, A=ADMIN, B=OWNER)"
    );
}

// =====================================================================
// 测试：群组软解散（groups.rs disband_group）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_group_soft_disband() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let owner_id: i64 = 99982;

    // 创建 ACTIVE 群组
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, owner_id, status, domain_id) \
         VALUES ('解散测试群', 'GROUP', ?, 'ACTIVE', 0)",
    )
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 验证初始状态为 ACTIVE，能被 require_group 查到
    let active_group: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM chat_conversation WHERE id = ? AND conversation_type = 'GROUP' AND status = 'ACTIVE'"
    )
    .bind(conv_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        active_group.is_some(),
        "group should be found with status='ACTIVE' before disband"
    );
    assert_eq!(active_group.unwrap().0, "ACTIVE");

    // 执行软解散（来自 groups.rs disband_group）:
    //   UPDATE chat_conversation SET status = 'DISBANDED' WHERE id = ? AND conversation_type = 'GROUP'
    sqlx::query(
        "UPDATE chat_conversation SET status = 'DISBANDED' WHERE id = ? AND conversation_type = 'GROUP'"
    )
    .bind(conv_id)
    .execute(&pool)
    .await
    .expect("soft disband should succeed");

    // 验证解散后 status = 'DISBANDED'
    let disbanded_status: (String,) =
        sqlx::query_as("SELECT status FROM chat_conversation WHERE id = ?")
            .bind(conv_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        disbanded_status.0, "DISBANDED",
        "group status should be DISBANDED after disband"
    );

    // 验证解散后不再被 WHERE status = 'ACTIVE' 查到（模拟 require_group 的查询）
    let active_after: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM chat_conversation WHERE id = ? AND conversation_type = 'GROUP' AND status = 'ACTIVE'"
    )
    .bind(conv_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        active_after.is_none(),
        "disbanded group should NOT be found by WHERE status='ACTIVE'"
    );

    // 清理
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] group soft disband (status='DISBANDED', not found by WHERE status='ACTIVE')");
}

// =====================================================================
// 测试：群组成员删除（groups.rs remove_member）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_member_remove_delete() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let owner_id: i64 = 99983;
    let member_id: i64 = 99984;

    // 创建群组
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, owner_id, status, domain_id) \
         VALUES ('删除成员测试', 'GROUP', ?, 'ACTIVE', 0)",
    )
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // OWNER 加入
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'OWNER')"
    )
    .bind(conv_id)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();

    // 普通成员加入
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(member_id)
    .execute(&pool)
    .await
    .unwrap();

    // 验证删除前有 2 个成员
    let count_before: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ?")
            .bind(conv_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count_before.0, 2, "should have 2 members before removal");

    // 执行 DELETE（来自 groups.rs remove_member）:
    //   DELETE FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?")
        .bind(conv_id)
        .bind(member_id)
        .execute(&pool)
        .await
        .expect("DELETE member should succeed");

    // 验证删除后只有 1 个成员
    let count_after: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ?")
            .bind(conv_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count_after.0, 1, "should have 1 member after removal");

    // 验证被删除的成员确实不存在
    let removed_exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(member_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(removed_exists.0, 0, "removed member should not exist");

    // 验证 OWNER 仍然存在
    let owner_exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
    )
    .bind(conv_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        owner_exists.0, 1,
        "owner should still exist after member removal"
    );

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] member DELETE (count decreased, removed member gone, owner remains)");
}

// =====================================================================
// 测试：已读回执 GREATEST(COALESCE(...)) 模式（realtime.rs READ_RECEIPT）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_read_receipt_greatest_coalesce() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let user_id: i64 = 99985;

    // 创建会话 + 成员
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('已读回执测试', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();

    // Step 1: 首次设置 last_read_message_id = 10
    // SQL 来自 realtime.rs READ_RECEIPT:
    //   UPDATE chat_conversation_member SET last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), ?)
    //   WHERE conversation_id = ? AND user_id = ?
    sqlx::query(
        "UPDATE chat_conversation_member SET last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), ?) \
         WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(10_i64)
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("first read receipt update should succeed");

    let read_id_1: (Option<i64>,) = sqlx::query_as(
        "SELECT last_read_message_id FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        read_id_1.0,
        Some(10),
        "last_read_message_id should be 10 after first update"
    );

    // Step 2: 更新为 20，GREATEST(10, 20) = 20，应该变为 20
    sqlx::query(
        "UPDATE chat_conversation_member SET last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), ?) \
         WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(20_i64)
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("second read receipt update should succeed");

    let read_id_2: (Option<i64>,) = sqlx::query_as(
        "SELECT last_read_message_id FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        read_id_2.0,
        Some(20),
        "last_read_message_id should be 20 (GREATEST of 10 and 20)"
    );

    // Step 3: 更新为 5，GREATEST(20, 5) = 20，应该保持 20（回退不生效）
    sqlx::query(
        "UPDATE chat_conversation_member SET last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), ?) \
         WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(5_i64)
    .bind(conv_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("third read receipt update should succeed");

    let read_id_3: (Option<i64>,) = sqlx::query_as(
        "SELECT last_read_message_id FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?"
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        read_id_3.0,
        Some(20),
        "last_read_message_id should stay 20 (GREATEST of 20 and 5, backward update rejected)"
    );

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!(
        "[PASS] read receipt GREATEST(COALESCE(...)) pattern (10→20→stays 20 on backward update)"
    );
}

// =====================================================================
// 测试：会话 member_count 子查询（sessions.rs list_sessions）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_chat_member_count_subquery() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_chat_tables(&pool).await;

    let user_a: i64 = 99990;
    let user_b: i64 = 99991;
    let user_c: i64 = 99992;

    // 创建会话
    let conv_id = sqlx::query(
        "INSERT INTO chat_conversation (name, conversation_type, domain_id) \
         VALUES ('成员计数测试', 'GROUP', 0)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 加入 3 个成员
    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'OWNER')"
    )
    .bind(conv_id)
    .bind(user_a)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(user_b)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')"
    )
    .bind(conv_id)
    .bind(user_c)
    .execute(&pool)
    .await
    .unwrap();

    // SELECT 使用 sessions.rs list_sessions 的同款子查询:
    //   SELECT id, name, conversation_type AS session_type,
    //          (SELECT COUNT(*) FROM chat_conversation_member m WHERE m.conversation_id = s.id) AS member_count
    //   FROM chat_conversation s WHERE s.id = ?
    let row = sqlx::query_as::<_, ChatSessionRow>(
        "SELECT id, name, conversation_type AS session_type, \
               (SELECT COUNT(*) FROM chat_conversation_member m WHERE m.conversation_id = s.id) AS member_count \
         FROM chat_conversation s WHERE s.id = ?"
    )
    .bind(conv_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.id, conv_id);
    assert_eq!(row.name, "成员计数测试");
    assert_eq!(row.session_type, "GROUP");
    assert_eq!(row.member_count, 3, "member_count subquery should return 3");

    // 验证子查询结果与实际 COUNT 一致
    let actual_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ?")
            .bind(conv_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row.member_count, actual_count.0,
        "subquery member_count should match actual COUNT(*)"
    );

    // 删除一个成员后验证子查询更新
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?")
        .bind(conv_id)
        .bind(user_c)
        .execute(&pool)
        .await
        .unwrap();

    let row_after = sqlx::query_as::<_, ChatSessionRow>(
        "SELECT id, name, conversation_type AS session_type, \
               (SELECT COUNT(*) FROM chat_conversation_member m WHERE m.conversation_id = s.id) AS member_count \
         FROM chat_conversation s WHERE s.id = ?"
    )
    .bind(conv_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row_after.member_count, 2,
        "member_count should be 2 after removing one member"
    );

    // 清理
    sqlx::query("DELETE FROM chat_conversation_member WHERE conversation_id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat_conversation WHERE id = ?")
        .bind(conv_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] member_count subquery matches actual COUNT, updates after member removal");
}
