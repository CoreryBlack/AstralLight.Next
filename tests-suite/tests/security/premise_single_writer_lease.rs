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
    let Some(pool_a) = connect_suite().await else {
        return;
    };
    // 第一写者:取得租约并持有(连接存活 = 租约存活)。
    let lease_a = acquire_single_writer_lease(&pool_a)
        .await
        .expect("first writer must acquire the idle lease");

    // 第二写者:立即失败,绝不排队等待。
    let pool_b = pool_a.clone();
    let second = acquire_single_writer_lease(&pool_b).await;
    let error = match second {
        Err(error) => error,
        Ok(connection) => {
            connection.close().await.unwrap();
            panic!("second writer must be refused while the lease is held");
        }
    };
    assert!(
        error.contains("already holds the writer lease"),
        "refusal must identify lease contention: {error}"
    );

    // Pool drop can recycle the session, so close the lease connection explicitly.
    lease_a.close().await.expect("lease session must close");
    // COM_QUIT has no response; observe server-side release before reacquiring.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let free: i64 = sqlx::query_scalar("SELECT IS_FREE_LOCK('astral_single_node_writer')")
                .fetch_one(&pool_b)
                .await
                .expect("lock release probe must succeed");
            if free == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed writer session must release its lock within the bounded wait");
    let lease_c = acquire_single_writer_lease(&pool_b)
        .await
        .expect("released lease must be re-acquirable by a new writer");
    lease_c.close().await.expect("new lease session must close");
}
