//! 安全前提 P-Lease:单机组合进程单写者租约(MySQL GET_LOCK 语义)。
//!
//! 架构契约(astral-single-node/src/main.rs:585-619):composite 是唯一授权
//! 写者,启动期通过会话级咨询锁 `GET_LOCK('astral_single_node_writer', 0)`
//! 占有写者身份;第二个实例**立即**被拒绝启动,进程崩溃时连接断开自动释放,
//! 绝不永久阻塞。现有测试仅覆盖 SQL 形态与监督分类,本前提在真实 MySQL 上
//! 验证互斥与释放-再获取语义。
//!
//! 运行:`cargo test -p testsuite --test premise_single_writer_lease -- --ignored`

use astral_db::memory_projection_hub::acquire_single_writer_lease;
use testsuite::connect_suite;

#[tokio::test]
#[ignore = "requires isolated MySQL via DATABASE_URL (single-writer lease premise)"]
async fn single_writer_lease_is_mutually_exclusive_and_releasable() {
    let Some(pool_a) = connect_suite() else {
        return;
    };
    // 第一写者:取得租约并持有(连接存活 = 租约存活)。
    let lease_a = acquire_single_writer_lease(&pool_a)
        .await
        .expect("first writer must acquire the idle lease");

    // 第二写者:立即失败,绝不排队等待。
    let pool_b = pool_a.clone();
    let second = acquire_single_writer_lease(&pool_b).await;
    let error = second.expect_err("second writer must be refused while the lease is held");
    assert!(
        error.contains("already holds the writer lease"),
        "refusal must identify lease contention: {error}"
    );

    // 释放:持约连接关闭(进程崩溃等价)→ 锁随会话释放 → 新写者可获取。
    drop(lease_a);
    drop(pool_a);
    // 给 MySQL 一点时间完成会话清理(本地回环通常即时)。
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let pool_c = pool_b.clone();
    acquire_single_writer_lease(&pool_c)
        .await
        .expect("released lease must be re-acquirable by a new writer");
}
