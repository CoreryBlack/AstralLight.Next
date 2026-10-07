//! 安全前提 P-RedisFree:单机组合进程的 Redis-free 门(纯配置检查,无 DB)。
//!
//! 当前架构契约(astral-common/src/config/mod.rs,redis-layer-retirement-20261002):
//! Redis 兼容是**显式 opt-in 的编译期能力**——`ASTRAL_REDIS_PROJECTION_COMPAT=true`
//! 但二进制未编译 `redis-compat` feature 时,启动必须明确失败,绝不静默
//! Redis-free 化(fail-closed)。2026-10-06 实测:astral-single-node 的
//! `[features]` 为空,composite 二进制天然无适配器,该旗标开启即拒绝启动。
//!
//! 运行:`cargo test -p testsuite --test premise_redis_free_composite`
//! (无需任何外部依赖;`#[ignore]` 不适用——本前提是纯进程内契约)。

use astral_common::config::AppConfig;

#[test]
fn compat_flag_without_compiled_adapter_is_refused_fail_closed() {
    let mut cfg = AppConfig::default();
    cfg.redis_projection_compat_enabled = true;
    // testsuite 默认构建不含 redis-compat:compiled 必须为 false。
    let compiled = cfg!(feature = "redis-compat");
    let outcome = cfg.validate_redis_adapter_support(compiled);
    if compiled {
        // 若未来 testsuite 打开 redis-compat,则本分支断言旗标可被接受,
        // 并显式记录构建形态(不允许静默改判)。
        assert!(
            outcome.is_ok(),
            "redis-compat compiled but compat-enabled config was refused"
        );
    } else {
        assert!(
            outcome.is_err(),
            "compat flag enabled on a non-adapter build must fail closed"
        );
    }
}

#[test]
fn compat_flag_off_is_accepted_without_adapter() {
    let cfg = AppConfig::default();
    assert!(!cfg.redis_projection_compat_enabled);
    cfg.validate_redis_adapter_support(false)
        .expect("default Redis-free configuration must be accepted");
}
