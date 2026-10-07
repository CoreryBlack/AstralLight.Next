//! 安全前提 P-Mapping:SDK 外部身份的强制映射契约(无旁路)。
//!
//! 架构契约(astral-trustgraph/src/service/integration_authorization/mod.rs):
//! SDK 集成授权路径中,`(app_id, issuer, subject)` 到平台身份的映射是
//! **强制前提**——映射缺失时服务返回 `INTEGRATION_NOT_AUTHORIZED`,绝不
//! 回退到裸 token 或旧角色映射;映射绑定的 user/identity_card 与请求上下文
//! 不一致同样拒绝。本前提在真实 MySQL 上验证映射读面的缺失/存在/跨应用
//! 三种形态,与 `astral-db/tests/integration_identity_mapping.rs`(表契约、
//! 专用隔离库)互补。
//!
//! 运行:`cargo test -p testsuite --test premise_identity_mapping -- --ignored`

use astral_db::{
    create_integration_identity_mapping, read_integration_identity_mapping,
    CreateIntegrationIdentityMapping, IntegrationIdentityKey,
};
use testsuite::{connect_suite, SuiteFixture, TenantRole};

#[tokio::test]
#[ignore = "requires isolated MySQL via DATABASE_URL (identity mapping premise)"]
async fn identity_mapping_absence_is_the_refusal_contract() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let fixture = SuiteFixture::new("mapping-premise", &[TenantRole::AllowActive]);
    let salt = uuid::Uuid::new_v4().simple().to_string();
    let user_id = fixture.tenants[0].user_id;
    let identity_card_id = fixture.tenants[0].identity_card_id;
    sqlx::query(
        "INSERT INTO platform_user \
         (user_id, user_no, display_name, source_type, status) \
         VALUES (?, ?, 'testsuite mapping actor', 'LOCAL', 'ACTIVE')",
    )
    .bind(user_id)
    .bind(format!("ts_mapping_user_{salt}"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO identity_card (card_id, user_id, status, token_version) \
         VALUES (?, ?, 'ACTIVE', 1)",
    )
    .bind(identity_card_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO identity_global_admin (user_id, status) VALUES (?, 'ACTIVE')")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    let app_id = format!("testsuite-mapping-{salt}");
    let key = IntegrationIdentityKey::new(
        app_id.clone(),
        format!("https://idp.{salt}.invalid"),
        format!("subject-{salt}"),
    )
    .expect("fixture mapping key must be valid");

    // 遗漏形态:映射不存在 → 读面返回 None;服务契约据此返回
    // INTEGRATION_NOT_AUTHORIZED(无任何旁路)。
    let missing = read_integration_identity_mapping(&pool, &key)
        .await
        .expect("absent mapping read must not error");
    assert!(
        missing.is_none(),
        "a never-registered external identity must not resolve to a platform identity"
    );

    // 注册形态:映射建立后,同一 key 解析到绑定的平台身份。
    let creation = create_integration_identity_mapping(
        &pool,
        CreateIntegrationIdentityMapping {
            key: key.clone(),
            user_id,
            identity_card_id,
            operation_id: format!("op-ts-mapping-{salt}"),
            actor_id: user_id,
        },
    )
    .await;
    if creation.is_err() {
        cleanup_mapping_fixture(&pool, &app_id, &salt, user_id, identity_card_id).await;
    }
    creation.expect("mapping creation must succeed for a fresh key with an active actor");

    let found = read_integration_identity_mapping(&pool, &key)
        .await
        .expect("existing mapping read must not error")
        .expect("created mapping must resolve");
    assert_eq!(found.user_id, user_id);
    assert_eq!(found.identity_card_id, identity_card_id);

    // 跨应用形态:同一 issuer/subject 换一个 app_id 即视为不同外部身份,
    // 仍然缺失 → None(应用维度不共享映射)。
    let other_key = IntegrationIdentityKey::new(
        format!("{app_id}-other"),
        format!("https://idp.{salt}.invalid"),
        format!("subject-{salt}"),
    )
    .expect("other-app mapping key must be valid");
    let cross_app = read_integration_identity_mapping(&pool, &other_key)
        .await
        .expect("cross-app read must not error");
    assert!(
        cross_app.is_none(),
        "mappings must not leak across app_id boundaries"
    );

    cleanup_mapping_fixture(&pool, &app_id, &salt, user_id, identity_card_id).await;
}

async fn cleanup_mapping_fixture(
    pool: &sqlx::MySqlPool,
    app_id: &str,
    salt: &str,
    user_id: i64,
    identity_card_id: i64,
) {
    let mut tx = pool.begin().await.unwrap();
    for mapping_app in [app_id.to_owned(), format!("{app_id}-other")] {
        sqlx::query("DELETE FROM integration_identity_mapping WHERE app_id = ?")
            .bind(mapping_app.into_bytes())
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM integration_identity_mapping_operation WHERE operation_id = ?")
        .bind(format!("op-ts-mapping-{salt}").into_bytes())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM audit_log WHERE event_type = 'IDENTITY_INTEGRATION_MAPPING' AND user_id = ? AND request_id = ?",
    )
    .bind(user_id)
    .bind(format!("op-ts-mapping-{salt}"))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("DELETE FROM identity_global_admin WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity_card WHERE card_id = ?")
        .bind(identity_card_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "mapping fixture actor must be removed");
}

#[tokio::test]
#[ignore = "requires isolated MySQL via DATABASE_URL (identity mapping premise)"]
async fn identity_mapping_absence_is_detectable_for_mismatch_probes() {
    // 服务契约:ctx.user_id != mapping.user_id 或 identity_card 不一致 →
    // INTEGRATION_NOT_AUTHORIZED。本断言锁定"映射 ≠ 授权"的边界:
    // 映射解析成功只提供绑定事实,绑定与请求上下文的一致性由服务强制;
    // 而一切拒绝语义的起点是映射缺席可被确定性观测。
    let Some(pool) = connect_suite().await else {
        return;
    };
    let salt = uuid::Uuid::new_v4().simple().to_string();
    let key = IntegrationIdentityKey::new(
        format!("testsuite-mismatch-{salt}"),
        format!("https://idp.{salt}.invalid"),
        format!("subject-{salt}"),
    )
    .unwrap();
    let absent = read_integration_identity_mapping(&pool, &key)
        .await
        .unwrap();
    assert!(
        absent.is_none(),
        "the refusal contract starts from mapping absence"
    );
}
