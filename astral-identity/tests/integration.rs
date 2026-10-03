//! astral-identity 集成测试 — platform_v4 schema 对齐验证
//!
//! 需要 Docker MySQL 8.0 环境（通过 docker-compose.test.yml 启动）。
//! 运行方式：
//!   cargo test -p astral-identity --test integration -- --ignored --nocapture
//!
//! 测试策略：验证 platform_user, user_local_credential, identity_card,
//! auth_token_family, auth_device_session 的真实列名与 Rust FromRow struct 的别名桥接，
//! 以及三表事务注册、登录聚合 JOIN、级联撤销等核心流程。

use sqlx::MySqlPool;

// =====================================================================
// 测试用的 FromRow struct — 与 Rust srv/*.rs 中的结构完全一致
// =====================================================================

/// 对应 auth.rs 中的 LoginAggregateRow
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct LoginAggregateRow {
    user_id: i64,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    user_status: String,
    login_name: Option<String>,
    password_hash: String,
    password_algo: Option<String>,
    must_change_password: Option<bool>,
    credential_id: i64,
    credential_version: i64,
    card_id: Option<i64>,
    card_status: Option<String>,
    token_version: Option<i64>,
    identity_expires_at: Option<String>,
}

/// 双卡分离下 tenant/domain 的真实来源行（对应 auth_repository find_login_cards
/// 从 user_card 读取组织归属的核心字段）。
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct UserCardTenancyRow {
    card_id: i64,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    card_type: String,
    card_status: String,
}

/// 对应 session.rs 中的 canonical DeviceSessionRow
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct DeviceSessionRow {
    session_id: i64,
    family_id: i64,
    user_id: i64,
    device_id: String,
    device_type: Option<String>,
    client_app_id: Option<String>,
    channel_code: Option<String>,
    current_user_card_id: Option<i64>,
    refresh_token_hash: String,
    refresh_expires_at: Option<time::PrimitiveDateTime>,
    status: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    last_seen_at: Option<time::PrimitiveDateTime>,
    revoked_at: Option<time::PrimitiveDateTime>,
    revoked_reason: Option<String>,
    created_at: time::PrimitiveDateTime,
    updated_at: time::PrimitiveDateTime,
}

/// 对应 session.rs 中的 canonical TokenFamilyRow
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct TokenFamilyRow {
    family_id: i64,
    user_id: i64,
    family_key: String,
    status: String,
    issued_at: time::PrimitiveDateTime,
    expires_at: Option<time::PrimitiveDateTime>,
    revoked_at: Option<time::PrimitiveDateTime>,
    revoked_reason: Option<String>,
    metadata_json: Option<String>,
}

/// 用户列表 LEFT JOIN 行（对应 users.rs list_users 查询）
#[derive(Debug, sqlx::FromRow, PartialEq)]
struct UserListRow {
    user_id: i64,
    login_name: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    status: String,
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

/// 清理测试数据：使用高 ID 范围 + 特殊前缀避免冲突
async fn cleanup_identity_tables(pool: &MySqlPool) {
    // 按 user_no LIKE 模式清理（覆盖远程 DB auto_increment 不在 99000-99999 范围的情况）
    let test_user_ids: Vec<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM platform_user WHERE user_no LIKE 'test_user_%' OR user_no LIKE 'tx_test_%'"
    ).fetch_all(pool).await.unwrap_or_default();

    for (uid,) in &test_user_ids {
        let _ = sqlx::query("DELETE FROM auth_device_session WHERE user_id = ?")
            .bind(uid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM auth_token_family WHERE user_id = ?")
            .bind(uid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM identity_card WHERE user_id = ?")
            .bind(uid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
            .bind(uid)
            .execute(pool)
            .await;
    }
    let _ = sqlx::query(
        "DELETE FROM platform_user WHERE user_no LIKE 'test_user_%' OR user_no LIKE 'tx_test_%'",
    )
    .execute(pool)
    .await;

    // 也按 user_id 范围清理（兜底）
    let _ = sqlx::query("DELETE FROM auth_device_session WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM auth_token_family WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM identity_card WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM user_local_credential WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM platform_user WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
}

/// 创建一个测试用户（platform_user + user_local_credential），返回 user_id
async fn create_test_user(pool: &MySqlPool, suffix: &str) -> i64 {
    let user_result = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES (?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(format!("test_user_{suffix}"))
    .bind(format!("测试用户{suffix}"))
    .execute(pool)
    .await
    .expect("INSERT platform_user should succeed");
    let user_id = user_result.last_insert_id() as i64;

    sqlx::query(
        "INSERT INTO user_local_credential \
         (user_id, login_name, password_hash, password_algo, password_set_at, status) \
         VALUES (?, ?, '$argon2id$v=19$m=65536,t=3,p=1$fake$hash', 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
    )
    .bind(user_id)
    .bind(format!("login_{suffix}"))
    .execute(pool)
    .await
    .expect("INSERT user_local_credential should succeed");

    user_id
}

/// 在事务内创建测试用户（用于 FK 禁用场景）
async fn create_test_user_in_tx(tx: &mut sqlx::Transaction<'_, sqlx::MySql>, suffix: &str) -> i64 {
    let user_result = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES (?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(format!("test_user_{suffix}"))
    .bind(format!("测试用户{suffix}"))
    .execute(&mut **tx)
    .await
    .expect("INSERT platform_user should succeed");
    let user_id = user_result.last_insert_id() as i64;

    sqlx::query(
        "INSERT INTO user_local_credential \
         (user_id, login_name, password_hash, password_algo, password_set_at, status) \
         VALUES (?, ?, '$argon2id$v=19$m=65536,t=3,p=1$fake$hash', 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
    )
    .bind(user_id)
    .bind(format!("login_{suffix}"))
    .execute(&mut **tx)
    .await
    .expect("INSERT user_local_credential should succeed");

    user_id
}

// =====================================================================
// 测试 1: platform_user 软删除 — deleted_at IS NULL 过滤
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_platform_user_soft_delete() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    // === CREATE: INSERT INTO platform_user ===
    let result = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES ('soft_del_test', '软删除测试用户', 'LOCAL', 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .expect("INSERT platform_user should succeed");
    let user_id = result.last_insert_id() as i64;
    assert!(user_id > 0, "should get a valid user_id");

    // === READ: 未删除用户可查到 ===
    #[derive(sqlx::FromRow)]
    struct PlatformUserRow {
        user_id: i64,
        display_name: Option<String>,
        status: String,
    }

    let row = sqlx::query_as::<_, PlatformUserRow>(
        "SELECT user_id, display_name, status \
         FROM platform_user WHERE user_id = ? AND deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(row.is_some(), "user should be visible before soft delete");
    let row = row.unwrap();
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.display_name.as_deref(), Some("软删除测试用户"));
    assert_eq!(row.status, "ACTIVE");

    // === UPDATE: 软删除 ===
    sqlx::query("UPDATE platform_user SET deleted_at = CURRENT_TIMESTAMP WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    // === READ: 软删除后 deleted_at IS NULL 查不到 ===
    let row_after: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM platform_user WHERE user_id = ? AND deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        row_after.is_none(),
        "soft-deleted user should NOT appear in deleted_at IS NULL query"
    );

    // 清理：硬删除
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] platform_user soft delete with deleted_at IS NULL filter");
}

// =====================================================================
// 测试 2: user_local_credential CRUD + login_name 唯一约束
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_user_local_credential_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    let user_id = create_test_user(&pool, "cred_crud").await;

    // === READ: 验证凭证已创建 ===
    let row: (i64, Option<String>, String, Option<String>, Option<bool>, String) = sqlx::query_as(
        "SELECT credential_id, login_name, password_hash, password_algo, must_change_password, status \
         FROM user_local_credential WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(row.0 > 0, "credential_id should be positive");
    assert_eq!(row.1.as_deref(), Some("login_cred_crud"));
    assert!(
        row.2.starts_with("$argon2id"),
        "password_hash should be argon2id format"
    );
    assert_eq!(row.3.as_deref(), Some("ARGON2ID"));
    assert_eq!(row.5, "ACTIVE");

    // === UPDATE: 更新密码 hash ===
    sqlx::query(
        "UPDATE user_local_credential SET password_hash = ?, password_algo = 'ARGON2ID', \
         password_updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    )
    .bind("$argon2id$v=19$m=65536,t=3,p=1$new_salt$new_hash")
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();

    let updated_hash: (String,) =
        sqlx::query_as("SELECT password_hash FROM user_local_credential WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        updated_hash.0.contains("new_hash"),
        "password_hash should be updated"
    );

    // === 唯一约束: 重复 login_name 应失败 ===
    let duplicate_result = sqlx::query(
        "INSERT INTO user_local_credential \
         (user_id, login_name, password_hash, password_algo, password_set_at, status) \
         VALUES (?, 'login_cred_crud', 'dummy', 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
    )
    .bind(user_id + 100) // 不同的 user_id
    .execute(&pool)
    .await;

    assert!(
        duplicate_result.is_err(),
        "duplicate login_name should violate UNIQUE constraint"
    );

    // 清理
    sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] user_local_credential CRUD + login_name uniqueness");
}

// =====================================================================
// 测试 3: identity_card CRUD
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_identity_card_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    // 使用事务确保 FK 检查禁用在同一连接上
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *tx)
        .await
        .ok();

    let user_id = create_test_user_in_tx(&mut tx, "id_card").await;

    // === CREATE: INSERT INTO identity_card ===
    let result = sqlx::query(
        "INSERT INTO identity_card (user_id, status, token_version) VALUES (?, 'ACTIVE', 1)",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .expect("INSERT identity_card should succeed");
    let card_id = result.last_insert_id() as i64;
    assert!(card_id > 0, "should get a valid card_id");

    // === READ ===
    // 双卡分离契约：identity_card 只承载身份认证字段（card_id/user_id/status/token_version），
    // 不承载组织归属（tenant/domain 由 user_card 承载，见 v5 schema identity_card 表注释）。
    let row: (i64, i64, String, i64) = sqlx::query_as(
        "SELECT card_id, user_id, status, token_version \
         FROM identity_card WHERE card_id = ?",
    )
    .bind(card_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    assert_eq!(row.0, card_id);
    assert_eq!(row.1, user_id);
    assert_eq!(row.2, "ACTIVE");
    assert_eq!(row.3, 1, "token_version should be 1");

    // === UPDATE: 状态流转 + token_version 自增（撤销语义） ===
    sqlx::query(
        "UPDATE identity_card SET status = 'DISABLED', token_version = token_version + 1 \
         WHERE card_id = ?",
    )
    .bind(card_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    let updated: (String, i64) =
        sqlx::query_as("SELECT status, token_version FROM identity_card WHERE card_id = ?")
            .bind(card_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(updated.0, "DISABLED");
    assert_eq!(updated.1, 2, "token_version should be incremented to 2");

    // === 双卡分离断言：information_schema 证明 identity_card 无 domain_id/tenant_id 列，
    // 组织归属列只存在于 user_card（v5 schema 物理双卡设计契约） ===
    let ic_tenancy_cols: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_schema = DATABASE() AND table_name = 'identity_card' \
           AND column_name IN ('domain_id', 'tenant_id')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        ic_tenancy_cols.0, 0,
        "identity_card must NOT carry domain_id/tenant_id (tenant/domain belong to user_card)"
    );
    let uc_tenancy_cols: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_schema = DATABASE() AND table_name = 'user_card' \
           AND column_name IN ('domain_id', 'tenant_id')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        uc_tenancy_cols.0, 2,
        "user_card must carry domain_id/tenant_id for organization ownership"
    );

    tx.rollback().await.expect("rollback");
    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&pool)
        .await
        .ok();

    eprintln!(
        "[PASS] identity_card CRUD (card_id/user_id/status/token_version) + dual-card separation"
    );
}

// =====================================================================
// 测试 4: 三表事务注册 — platform_user + user_local_credential + identity_card
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_register_user_three_table_transaction() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    let username = "tx_test_user_001";
    let password_hash = "$argon2id$v=19$m=65536,t=3,p=1$tx_test$tx_hash";

    // === 事务: 三表 INSERT ===
    let mut tx = pool.begin().await.expect("BEGIN should succeed");

    // 1. INSERT platform_user
    let user_result = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES (?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(username)
    .bind(username)
    .execute(&mut *tx)
    .await
    .expect("INSERT platform_user in tx should succeed");
    let user_id = user_result.last_insert_id() as i64;
    assert!(user_id > 0);

    // 2. INSERT user_local_credential
    sqlx::query(
        "INSERT INTO user_local_credential \
         (user_id, login_name, password_hash, password_algo, password_set_at, status) \
         VALUES (?, ?, ?, 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
    )
    .bind(user_id)
    .bind(username)
    .bind(password_hash)
    .execute(&mut *tx)
    .await
    .expect("INSERT user_local_credential in tx should succeed");

    // 3. INSERT identity_card
    let card_result = sqlx::query(
        "INSERT INTO identity_card (user_id, status, token_version) VALUES (?, 'ACTIVE', 1)",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .expect("INSERT identity_card in tx should succeed");
    let card_id = card_result.last_insert_id() as i64;
    assert!(card_id > 0);

    // COMMIT
    tx.commit().await.expect("COMMIT should succeed");

    // === 验证三表数据一致 ===
    let user_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM platform_user WHERE user_id = ? AND deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(user_count.0, 1);

    let cred_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM user_local_credential WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cred_count.0, 1);

    let card_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM identity_card WHERE user_id = ? AND card_id = ?")
            .bind(user_id)
            .bind(card_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(card_count.0, 1);

    // === 测试事务回滚: 故意让第三步失败 ===
    let mut tx2 = pool.begin().await.unwrap();

    let user_result2 = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES ('rollback_test', '回滚测试', 'LOCAL', 'ACTIVE')",
    )
    .execute(&mut *tx2)
    .await
    .unwrap();
    let user_id2 = user_result2.last_insert_id() as i64;

    sqlx::query(
        "INSERT INTO user_local_credential \
         (user_id, login_name, password_hash, password_algo, password_set_at, status) \
         VALUES (?, ?, 'hash', 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
    )
    .bind(user_id2)
    .bind("tx_test_user_001") // 重复的 login_name，会违反唯一约束
    .execute(&mut *tx2)
    .await
    .ok(); // 预期失败

    // ROLLBACK（不 commit）
    tx2.rollback().await.unwrap();

    // 验证回滚后 user_id2 不存在
    let user2_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM platform_user WHERE user_id = ?")
            .bind(user_id2)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(user2_count.0, 0, "rolled back user should not exist");

    // 清理
    sqlx::query("DELETE FROM identity_card WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] three-table transaction (register) with commit and rollback");
}

// =====================================================================
// 测试 5: 登录聚合 JOIN — user_local_credential + platform_user + identity_card
//          （双卡分离：登录侧 tenant/domain 归属由 user_card 承载）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_login_aggregate_join() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    let login_name = "login_agg_test";

    // 创建用户 + 凭证 + 身份卡 + 用户卡
    // 双卡分离：identity_card 只做身份认证；登录侧 tenant/domain 归属来自 user_card。
    let user_result = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES (?, '登录聚合测试', 'LOCAL', 'ACTIVE')",
    )
    .bind(login_name)
    .execute(&pool)
    .await
    .unwrap();
    let user_id = user_result.last_insert_id() as i64;

    sqlx::query(
        "INSERT INTO user_local_credential \
         (user_id, login_name, password_hash, password_algo, password_set_at, status) \
         VALUES (?, ?, '$argon2id$v=19$m=65536,t=3,p=1$salt$hash', 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
    )
    .bind(user_id)
    .bind(login_name)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO identity_card (user_id, status, token_version) VALUES (?, 'ACTIVE', 1)",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();

    // user_card 依赖 platform_domain（fk_uc_domain），先建测试域再发卡
    let domain_result = sqlx::query(
        "INSERT INTO platform_domain (domain_code, domain_name) \
         VALUES ('test_domain_login_agg', '登录聚合测试域')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let domain_id = domain_result.last_insert_id() as i64;

    sqlx::query(
        "INSERT INTO user_card (user_id, domain_id, card_type, card_status, tenant_id, \
         priority, is_primary) \
         VALUES (?, ?, 'ORG_CARD', 'ACTIVE', ?, 100, 1)",
    )
    .bind(user_id)
    .bind(domain_id)
    .bind(200_i64)
    .execute(&pool)
    .await
    .unwrap();

    // === READ: 镜像 auth.rs find_login_aggregate_by_login_name 的完整 JOIN SQL ===
    // 双卡分离语义：聚合只从 identity_card 取 card_id/status/token_version/expires_at；
    // tenant/domain 归属不由 identity_card 提供，见下方 user_card JOIN 验证。
    let row = sqlx::query_as::<_, LoginAggregateRow>(
        "SELECT \
            u.user_id, \
            u.display_name, \
            u.email, \
            u.phone, \
            u.status AS user_status, \
            c.login_name, \
            c.password_hash, \
            c.password_algo, \
            c.must_change_password, \
            c.credential_id, \
            c.credential_version, \
            ic.card_id, \
            ic.status AS card_status, \
            ic.token_version, \
            DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS identity_expires_at \
         FROM user_local_credential c \
         INNER JOIN platform_user u ON u.user_id = c.user_id AND u.deleted_at IS NULL \
         LEFT JOIN identity_card ic ON ic.user_id = u.user_id \
         WHERE c.login_name = ? AND c.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         ORDER BY ic.status = 'ACTIVE' DESC, ic.card_id ASC LIMIT 1",
    )
    .bind(login_name)
    .fetch_one(&pool)
    .await
    .expect("Login aggregate JOIN should succeed");

    // 验证关键字段
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.display_name.as_deref(), Some("登录聚合测试"));
    assert_eq!(row.user_status, "ACTIVE"); // u.status AS user_status
    assert_eq!(row.login_name.as_deref(), Some(login_name));
    assert!(row.password_hash.starts_with("$argon2id"));
    assert_eq!(row.password_algo.as_deref(), Some("ARGON2ID"));
    assert!(row.credential_id > 0);
    assert!(
        row.card_id.is_some(),
        "identity_card should be found via LEFT JOIN"
    );
    assert_eq!(row.card_status.as_deref(), Some("ACTIVE")); // ic.status AS card_status
    assert_eq!(row.token_version, Some(1));

    // === 双卡分离：登录侧 tenant/domain 来自 user_card ===
    // 生产登录链路（auth_repository）中，组织归属由 find_login_cards 从 user_card 读取
    // （SessionGrant.user_card_tenant_id / user_card_domain_id），identity_card 不提供归属。
    // 此处镜像 find_login_cards 的核心 WHERE/ORDER 形态，验证归属列挂在 user_card 上。
    let tenancy = sqlx::query_as::<_, UserCardTenancyRow>(
        "SELECT uc.card_id, uc.domain_id, uc.tenant_id, uc.card_type, uc.card_status \
         FROM user_card uc \
         WHERE uc.user_id = ? AND uc.card_status = 'ACTIVE' \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         ORDER BY uc.is_primary DESC, uc.priority ASC, uc.card_id ASC",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("user_card tenancy row should be found via user_id JOIN");
    assert!(
        tenancy.card_id > 0,
        "user_card should carry organization tenancy"
    );
    assert_eq!(tenancy.domain_id, Some(domain_id));
    assert_eq!(tenancy.tenant_id, Some(200));
    assert_eq!(tenancy.card_type, "ORG_CARD");
    assert_eq!(tenancy.card_status, "ACTIVE");

    // === 测试软删除用户的 JOIN 排除 ===
    sqlx::query("UPDATE platform_user SET deleted_at = CURRENT_TIMESTAMP WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    let deleted_row = sqlx::query_as::<_, LoginAggregateRow>(
        "SELECT \
            u.user_id, \
            u.display_name, \
            u.email, \
            u.phone, \
            u.status AS user_status, \
            c.login_name, \
            c.password_hash, \
            c.password_algo, \
            c.must_change_password, \
            c.credential_id, \
            c.credential_version, \
            ic.card_id, \
            ic.status AS card_status, \
            ic.token_version, \
            DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS identity_expires_at \
         FROM user_local_credential c \
         INNER JOIN platform_user u ON u.user_id = c.user_id AND u.deleted_at IS NULL \
         LEFT JOIN identity_card ic ON ic.user_id = u.user_id \
         WHERE c.login_name = ? AND c.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         ORDER BY ic.status = 'ACTIVE' DESC, ic.card_id ASC LIMIT 1",
    )
    .bind(login_name)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        deleted_row.is_none(),
        "soft-deleted user should NOT appear in INNER JOIN with deleted_at IS NULL"
    );

    // 清理（先删子表 user_card/identity_card，再删 domain）
    sqlx::query("DELETE FROM user_card WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity_card WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_domain WHERE domain_id = ?")
        .bind(domain_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!(
        "[PASS] login aggregate JOIN (production mirror) + tenant/domain from user_card (dual-card)"
    );
}

// =====================================================================
// 测试 6: canonical auth_token_family + auth_device_session
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_auth_token_family_and_device_session() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    let user_id = create_test_user(&pool, "token_family").await;

    // === CREATE: INSERT INTO auth_token_family ===
    let family_biz_key = "test_family_001";
    let family_result = sqlx::query(
        "INSERT INTO auth_token_family (family_key, user_id, status) VALUES (?, ?, 'ACTIVE')",
    )
    .bind(family_biz_key)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("INSERT auth_token_family should succeed");
    let _family_pk = family_result.last_insert_id() as i64;
    assert!(_family_pk > 0, "should get a valid auto-increment id");

    // === READ: 验证 TokenFamilyRow 映射 ===
    let family_row = sqlx::query_as::<_, TokenFamilyRow>(
        "SELECT family_id, user_id, family_key, status, issued_at, expires_at, revoked_at, \
         revoked_reason, metadata_json FROM auth_token_family WHERE family_key = ?",
    )
    .bind(family_biz_key)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(family_row.family_id, _family_pk);
    assert_eq!(family_row.family_key, family_biz_key);
    assert_eq!(family_row.user_id, user_id);
    assert_eq!(family_row.status, "ACTIVE");

    // === CREATE: INSERT INTO auth_device_session ===
    let session_result = sqlx::query(
        "INSERT INTO auth_device_session \
         (family_id, user_id, device_id, refresh_token_hash, status) \
         VALUES (?, ?, ?, ?, 'ACTIVE')",
    )
    .bind(_family_pk)
    .bind(user_id)
    .bind("device_test_001")
    .bind("sha256_hash_of_refresh_token")
    .execute(&pool)
    .await
    .expect("INSERT auth_device_session should succeed");
    let session_id = session_result.last_insert_id() as i64;
    assert!(session_id > 0);

    // === READ: canonical DATETIME/session_id projection ===
    let row = sqlx::query_as::<_, DeviceSessionRow>(
        "SELECT session_id, family_id, user_id, device_id, device_type, client_app_id, channel_code, \
         current_user_card_id, refresh_token_hash, refresh_expires_at, status, ip_address, user_agent, \
         last_seen_at, revoked_at, revoked_reason, created_at, updated_at \
         FROM auth_device_session WHERE session_id = ?",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT canonical DeviceSessionRow should succeed");

    // 验证关键字段
    assert_eq!(row.session_id, session_id);
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.family_id, _family_pk);
    assert_eq!(row.refresh_token_hash, "sha256_hash_of_refresh_token");
    assert_eq!(row.status, "ACTIVE");
    // refresh_expires_at is nullable DATETIME in the canonical contract.
    assert_eq!(
        row.refresh_expires_at, None,
        "refresh_expires_at should be NULL when omitted"
    );
    // revoked_at 应该为 None（未撤销）
    assert_eq!(row.revoked_at, None);
    assert_eq!(row.revoked_reason, None);

    // 清理
    sqlx::query("DELETE FROM auth_device_session WHERE session_id = ?")
        .bind(session_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM auth_token_family WHERE family_id = ?")
        .bind(_family_pk)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] canonical auth_token_family + auth_device_session mappings");
}

// =====================================================================
// 测试 7: Token Family 级联撤销 — family REVOKED → 所有 sessions REVOKED
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_token_family_cascade_revoke() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    let user_id = create_test_user(&pool, "cascade_revoke").await;

    // 创建 token family
    let cascade_family_key = "cascade_family_test_001";
    let family_result = sqlx::query(
        "INSERT INTO auth_token_family (family_key, user_id, status) VALUES (?, ?, 'ACTIVE')",
    )
    .bind(cascade_family_key)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    let _family_pk = family_result.last_insert_id() as i64;

    // 创建 3 个 device sessions（模拟多设备登录）
    let mut session_ids: Vec<i64> = Vec::new();
    for i in 0..3 {
        let result = sqlx::query(
            "INSERT INTO auth_device_session \
             (family_id, user_id, device_id, refresh_token_hash, status) \
             VALUES (?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(_family_pk)
        .bind(user_id)
        .bind(format!("cascade_device_{i}"))
        .bind(format!("cascade_hash_{i}"))
        .execute(&pool)
        .await
        .unwrap();
        session_ids.push(result.last_insert_id() as i64);
    }
    assert_eq!(session_ids.len(), 3);

    // === 级联撤销: 先撤销 family，再撤销所有 sessions ===
    // Step 1: UPDATE auth_token_family
    sqlx::query(
        "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, \
         revoked_reason = 'TOKEN_REUSE_DETECTED' WHERE family_id = ? AND status = 'ACTIVE'",
    )
    .bind(_family_pk)
    .execute(&pool)
    .await
    .unwrap();

    // Step 2: UPDATE auth_device_session（级联）
    sqlx::query(
        "UPDATE auth_device_session SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, \
         revoked_reason = 'TOKEN_REUSE_DETECTED', updated_at = CURRENT_TIMESTAMP \
         WHERE family_id = ? AND status = 'ACTIVE'",
    )
    .bind(_family_pk)
    .execute(&pool)
    .await
    .unwrap();

    // === 验证 family 已撤销 ===
    let family_row = sqlx::query_as::<_, TokenFamilyRow>(
        "SELECT family_id, user_id, family_key, status, issued_at, expires_at, revoked_at, \
         revoked_reason, metadata_json FROM auth_token_family WHERE family_id = ?",
    )
    .bind(_family_pk)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(family_row.status, "REVOKED");

    // === 验证所有 sessions 已撤销 ===
    let active_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM auth_device_session WHERE family_id = ? AND status = 'ACTIVE'",
    )
    .bind(_family_pk)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        active_count.0, 0,
        "all sessions under revoked family should be REVOKED"
    );

    let revoked_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM auth_device_session WHERE family_id = ? AND status = 'REVOKED'",
    )
    .bind(_family_pk)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revoked_count.0, 3, "all 3 sessions should be REVOKED");

    // 验证 canonical DATETIME projection in revoked state
    let revoked_session = sqlx::query_as::<_, DeviceSessionRow>(
        "SELECT session_id, family_id, user_id, device_id, device_type, client_app_id, channel_code, \
         current_user_card_id, refresh_token_hash, refresh_expires_at, status, ip_address, user_agent, \
         last_seen_at, revoked_at, revoked_reason, created_at, updated_at \
         FROM auth_device_session WHERE session_id = ?",
    )
    .bind(session_ids[0])
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(revoked_session.status, "REVOKED");
    assert!(
        revoked_session.revoked_at.is_some(),
        "revoked_at should be populated"
    );
    assert_eq!(
        revoked_session.revoked_reason.as_deref(),
        Some("TOKEN_REUSE_DETECTED")
    );

    // 清理
    sqlx::query("DELETE FROM auth_device_session WHERE family_id = ?")
        .bind(_family_pk)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM auth_token_family WHERE family_id = ?")
        .bind(_family_pk)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] token family cascade revoke (family→all sessions)");
}

// =====================================================================
// 测试 8: 用户列表 LEFT JOIN — platform_user + user_local_credential
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_user_list_left_join() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    cleanup_identity_tables(&pool).await;

    // 创建两个用户：一个有本地凭证，一个没有
    let user_a = create_test_user(&pool, "list_a").await;
    let user_b_result = sqlx::query(
        "INSERT INTO platform_user (user_no, display_name, source_type, status) \
         VALUES ('list_user_b', '列表用户B(无凭证)', 'OAUTH', 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let user_b = user_b_result.last_insert_id() as i64;

    // === READ: 使用 users.rs 中 list_users 的 LEFT JOIN SQL ===
    let rows = sqlx::query_as::<_, UserListRow>(
        "SELECT u.user_id, c.login_name, u.display_name, u.email, u.phone, u.status \
         FROM platform_user u \
         LEFT JOIN user_local_credential c ON c.user_id = u.user_id \
         WHERE u.deleted_at IS NULL \
         ORDER BY u.user_id LIMIT ? OFFSET ?",
    )
    .bind(100)
    .bind(0)
    .fetch_all(&pool)
    .await
    .expect("LEFT JOIN query should succeed");

    // 找到我们创建的测试用户
    let row_a = rows.iter().find(|r| r.user_id == user_a);
    let row_b = rows.iter().find(|r| r.user_id == user_b);

    // user_a 有本地凭证，login_name 应该有值
    assert!(row_a.is_some(), "user_a should be found");
    let row_a = row_a.unwrap();
    assert_eq!(row_a.login_name.as_deref(), Some("login_list_a"));
    assert_eq!(row_a.status, "ACTIVE");

    // user_b 没有本地凭证，login_name 应该为 NULL（LEFT JOIN 行为）
    assert!(row_b.is_some(), "user_b should be found via LEFT JOIN");
    let row_b = row_b.unwrap();
    assert_eq!(
        row_b.login_name, None,
        "user without credential should have NULL login_name"
    );
    assert_eq!(row_b.display_name.as_deref(), Some("列表用户B(无凭证)"));
    assert_eq!(row_b.status, "ACTIVE");

    // 清理
    sqlx::query("DELETE FROM user_local_credential WHERE user_id = ?")
        .bind(user_a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_b)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] user list LEFT JOIN (platform_user + user_local_credential)");
}
