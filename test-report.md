# AstralLight Redis-free 已完成测试详细报告

> 报告日期：2026-10-07。本文依据最终 r3 原始日志和现有执行证据编制，不启动新测试，不修改源码，不把历史成功覆盖本次失败。
>
> **总体结论：测试执行及结果对账已完成，但整体验收为 FAIL。** 最终 E5 共实际执行 **2,853 个 Cargo 测试项：2,851 PASS、2 FAIL**。另有 13 个当前已发现的 ignored 项尚未执行。未发现的 optional-feature、excluded crate、Python 工具及独立 campaign 不包含在此分母中。

## 1. 版本、环境与证据边界

| 项目 | 最终记录 |
|---|---|
| 任务标识 | `astral-rf-20261007-r3` |
| 本地分支 | `fix/redis-free-tests-20261007` |
| 基准提交 | `6901425d0f7a981e0eff20673aee860791229910` |
| 测试版本 | 基准提交 + 本次未提交的测试改写；不是未修改的 main |
| 本地固定目录 | `E:/OfficialVersion/AstralLight-Next` |
| E5 测试目录 | `/tmp/astral-rf-20261007-r3-source`；验证后按范围删除 |
| E5 原仓库 | `/home/astrallight/AstralLight-Next`；main 干净，提交未改变 |
| E5 工具链 | Linux x86_64；rustc/cargo 1.98.0 |
| MySQL | 8.0.46，已迁移隔离库；本轮没有执行 DDL |
| 本地工具链 | Windows Git Bash；rustc/cargo 1.92.0 |
| 外部依赖 | MySQL；Rabbit 审计专项另用 RabbitMQ；默认 gate 不需要 Redis |
| Redis 状态 | 全部最终 r3 gate 期间临时关闭，端口无 listener；结束后恢复 healthy |
| 集成门 | `RUST_INTEGRATION_REQUIRED=1`、`ASTRAL_MIGRATION_ENV=isolated`、`TEST_USE_EXISTING=1` |
| 默认传输 | `ASTRAL_MESSAGE_TRANSPORT=local`；Rabbit 专项显式设为 `rabbit` |
| Redis compatibility | 默认 `ASTRAL_REDIS_PROJECTION_COMPAT=false`，移除 `REDIS_URL` |
| source identity | 20 个变更文件及未改动 Cargo.lock 与 E5 hash 一致；必要时按 LF 规范化对比 |
| 修改边界 | 测试入口、夹具、manifest、README；生产授权逻辑、迁移、consumer、兼容 API 均未改 |
| 提交/推送 | 未提交，未推送 |

凭据来自既有私有环境文件，不进入报告或 Git。破坏性迁移 allowlist 与 backup/drain/cutover proof 变量在本轮进程中移除。复用历史已迁移隔离库不等于证明历史迁移批准或生产迁移验收。

最终 r3 墙钟区间：**2026-10-07 22:17:34 至 22:24:07，UTC+08:00，共 393 秒**。阶段用 shell `SECONDS` 记录单调耗时；测试体耗时来自 Cargo summary。阶段耗时包含启动、编译等，不等于测试体耗时，也不是模型累计 turn 时间。

证据入口：[原执行证据](evidence.md)、[最终 run.log](astral-rf-20261007-r3-run.log)、[source hash](astral-rf-20261007-r3-evidence/source-sha256.log)。

## 2. 汇总及计数方法

| 范围 | PASS | FAIL | 本阶段 ignored | filtered | 状态 |
|---|---:|---:|---:|---:|---|
| E5 `cargo test --workspace --no-fail-fast` | 2,769 | 1 | 96 | 0 | FAIL |
| E5 MySQL 显式 ignored 集成 | 81 | 1 | 0 | 0 | FAIL |
| E5 Rabbit 显式 ignored 审计集成 | 1 | 0 | 0 | 3 | PASS |
| E5 最终 Cargo 测试去重合计 | **2,851** | **2** | **13 仍未执行** | 不累计 | **FAIL** |
| shell runner 编排回归 | 12 个场景 | 0 | 0 | 0 | PASS；不计入 Cargo 数量 |
| E5 独立性能诊断 | 0 | 1 | 0 | 856 | FAIL；重复既有失败测试，不另加总数 |
| 本地审计 request-id 单测复核 | 3 | 0 | 1 | 0 | 单测 PASS；真实集成未在本地执行 |
| 本地 Redis-free 配置复核 | 2 | 0 | 0 | 0 | PASS；不另加 E5 数量 |
| 本地内存读性能复核 | 1 | 0 | 0 | 856 | PASS；不能替代 E5 FAIL |

计数规则：

1. workspace summary 包含库/二进制单测、不需外部服务的 Cargo integration 和 doctest，不仅是 `--lib`。
2. workspace 在本阶段发现 96 个 ignored 项；其中 83 项随后在 MySQL/Rabbit 专项实际执行，共 82 通过、1 失败。
3. 两个阶段的已执行项不重叠：83 个 live 项在 workspace 阶段仅 ignored。因此已执行总数为 `2,769 + 1 + 81 + 1 + 1 = 2,853`。
4. 最终 PASS 数为 `2,769 + 81 + 1 = 2,851`，FAIL 数为 `1 + 1 = 2`；剩余 ignored 为 `96 - 83 = 13`。
5. 本地复核、旧快照、单项性能重试均不叠加为额外唯一通过项目。
6. `exit 0` 不自动等于业务 PASS。本轮检查了内部 `[SKIP]`、ignored 和 filtered；最终已选择 live 目标没有内部 SKIP。
7. feature 未启用而根本没有被 Cargo 发现的 Redis compat 目标、workspace exclude crate 和独立工具，不属于 13 个 ignored 或 2,853 个已执行项。

## 3. 执行命令与质量门

以下均从最终 E5 测试源码根目录执行；连接值不回显。

```bash
bash scripts/run-tests.sh --rabbit
bash scripts/run-tests.sh --integration
bash scripts/run-tests.sh unit
bash scripts/run-tests.sh --check
bash scripts/tests/test-run-tests.sh
cargo fmt --all -- --check
cargo tree --workspace --edges normal,build
```

| 命令或内部 gate | wrapper/阶段退出码 | 阶段耗时 | 结论 | 原始日志 |
|---|---|---:|---|---|
| `--rabbit` | wrapper 0，Cargo 0 | 10s | PASS | [Rabbit runner](astral-rf-20261007-r3-evidence/rabbit-runner.log) |
| `--integration` | wrapper 1；仅 mapping Cargo 101 | 17 个 phase，详见下表 | FAIL | [MySQL runner](astral-rf-20261007-r3-evidence/integration-runner.log) |
| `unit` | wrapper 1，Cargo 101 | 200s | FAIL | [unit runner](astral-rf-20261007-r3-evidence/unit-runner.log) |
| `cargo check --workspace --all-targets` | 0 | 1s | PASS | [check](astral-rf-20261007-r3-evidence/check/check.log) |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | 2s | PASS，E5 1.98 | [Clippy](astral-rf-20261007-r3-evidence/check/clippy.log) |
| `cargo fmt --all -- --check` | 0 | 未单独记录 | PASS | [fmt](astral-rf-20261007-r3-evidence/fmt.log) |
| shell runner contracts | 0 | 未单独记录 | 12/12 PASS | [contracts](astral-rf-20261007-r3-evidence/contracts.log) |
| 默认 normal/build 依赖树 | 0 | 未单独记录 | 无 Redis 编译树条目 | [dependency tree](astral-rf-20261007-r3-evidence/default-dependencies.log) |

每个 phase 超时预算 600 秒，kill grace 15 秒。本轮无阶段超时，日志有完整终态；`REMOTE_EXIT=1`。后台 SSH 派发的退出码 0 仅表示派发完成，没有被用作测试通过证据。

## 4. Workspace 测试详情

workspace 阶段运行 **47 个普通 test binary + 13 个 doctest summary**。部分 binary 不含测试；数量为 Cargo 实际 summary 汇总，不是 60 个全部成功的目标。

| package | 本阶段通过 | 失败 | ignored | 结果范围 |
|---|---:|---:|---:|---|
| `astral-common` | 245 | 0 | 0 | lib 201、audit tenant 32、gateway contract 7、doctest 5 |
| `astral-db` | 856 | 1 | 52 | lib 854 通过/1 失败，migrator CLI 1，doctest 1；DB integration 此时 ignored |
| `astral-gateway` | 53 | 0 | 0 | lib 单测 |
| `astral-identity` | 120 | 0 | 8 | lib 单测；真实 DB suite 此时 ignored |
| `astral-monitor` | 30 | 0 | 5 | lib 27、main 3；真实 DB suite 此时 ignored |
| `astral-mq` | 147 | 0 | 0 | 消息与本地传输实现单测 |
| `astral-sdk` | 4 | 0 | 0 | SDK 单测 |
| `astral-sdk-axum` | 2 | 0 | 0 | Axum 集成适配单测 |
| `astral-sdk-contracts` | 8 | 0 | 0 | 契约单测 |
| `astral-single-node` | 18 | 0 | 0 | 组合进程 main 单测；非真实进程部署验收 |
| `astral-trustgraph` | 842 | 0 | 18 | lib 838、audit request-id 3、doctest 1；真实 DB/MQ suite 此时 ignored |
| `astral-types` | 127 | 0 | 0 | 共享类型/模型单测 |
| `e2e-bootstrap` | 3 | 0 | 0 | bootstrap CLI 单测；未启动真实 e2e |
| `policy-engine` | 312 | 0 | 4 | lib 294、allocation 4、oracle 1、tenant isolation 12、doctest 1 |
| `testsuite` | 2 | 0 | 9 | Redis-free 配置门 2；MT/security 真依赖目标此时 ignored |
| **合计** | **2,769** | **1** | **96** | 完整 workspace 阶段 FAIL |

原始完整测试名和 summary：[unit/unit.log](astral-rf-20261007-r3-evidence/unit/unit.log)。

### 4.1 E1/E2 名称的局部守卫

以下在 workspace 阶段实际 PASS：

- `e1_observation::tests::event_sequence_is_strictly_monotonic`
- `e1_observation::tests::process_observation_id_is_stable_within_one_process`
- `evidence_cache::tests::e2_pending_probe_omission_accepts_stale_candidate_while_full_contract_reloads`
- `evidence_cache::tests::e2_post_recheck_omission_accepts_interleaving_while_full_contract_reloads`
- `evidence_cache::tests::e2_generation_revoke_fence_omission_accepts_stale_candidate`
- `engine::tests::e2_final_reload_omission_accepts_removed_candidate_while_full_contract_reloads`

这些说明观测标识和特定 omission 对比模型/实现守卫通过，不是完整授权验证 E1–E5 campaign，也不是 M1–M5 的独立证明。

## 5. 真实 MySQL 集成

下表的 phase 耗时含 Cargo 启动/必要编译，测试体耗时来自 libtest。17 个 phase 对应 18 个 test binary，其中 TrustGraph 一次调用两个 binary。

| phase / test target | PASS/FAIL | Cargo exit | phase | 测试体耗时 | 日志 |
|---|---|---:|---:|---:|---|
| DB authorization projection | 10/0 | 0 | 28s | 26.53s | [projection](astral-rf-20261007-r3-evidence/integration/db-authorization_projection_integration.log) |
| DB integration | 2/0 | 0 | 6s | 5.23s | [DB integration](astral-rf-20261007-r3-evidence/integration/db-integration.log) |
| DB multi-tenant isolation | 7/0 | 0 | 19s | 18.90s | [tenant isolation](astral-rf-20261007-r3-evidence/integration/db-multi_tenant_isolation.log) |
| DB org scope | 15/0 | 0 | 42s | 41.46s | [org scope](astral-rf-20261007-r3-evidence/integration/db-org_scope_integration.log) |
| DB partition lease | 7/0 | 0 | 4s | 2.96s | [partition lease](astral-rf-20261007-r3-evidence/integration/db-partition_lease_integration.log) |
| DB quarantine | 7/0 | 0 | 7s | 6.46s | [quarantine](astral-rf-20261007-r3-evidence/integration/db-quarantine_integration.log) |
| Identity integration | 8/0 | 0 | 1s | 0.36s | [identity](astral-rf-20261007-r3-evidence/integration/identity.log) |
| Monitor integration | 5/0 | 0 | 1s | 0.22s | [monitor](astral-rf-20261007-r3-evidence/integration/monitor.log) |
| TrustGraph integration + org projector | 12/0 | 0 | 4s | 0.27s + 2.70s | [TrustGraph](astral-rf-20261007-r3-evidence/integration/trustgraph.log) |
| MT-E5 capacity | 1/0 | 0 | 14s | 14.03s | [capacity](astral-rf-20261007-r3-evidence/integration/mt_extreme_capacity.log) |
| MT-E3 churn | 1/0 | 0 | 6s | 3.57s | [churn](astral-rf-20261007-r3-evidence/integration/mt_extreme_churn.log) |
| MT-E4 concurrent updates | 1/0 | 0 | 4s | 3.24s | [cross storm](astral-rf-20261007-r3-evidence/integration/mt_extreme_cross_storm.log) |
| MT-E6 fail-closed landscape | 1/0 | 0 | 4s | 2.84s | [fail-closed](astral-rf-20261007-r3-evidence/integration/mt_extreme_failclosed.log) |
| MT-E1 mixed isolation | 1/0 | 0 | 6s | 5.51s | [MT isolation](astral-rf-20261007-r3-evidence/integration/mt_extreme_isolation.log) |
| Hub invalidation premise | 1/0 | 0 | 3s | 2.67s | [hub](astral-rf-20261007-r3-evidence/integration/hub-invalidation.log) |
| Single-writer lease premise | 1/0 | 0 | 4s | 2.54s | [writer lease](astral-rf-20261007-r3-evidence/integration/writer-lease.log) |
| Identity mapping premise | 1/1 | 101 | 7s | 5.13s | [mapping](astral-rf-20261007-r3-evidence/integration/mapping-premise.log) |
| **合计** | **81/1** | wrapper **1** | 不作为独立 wall clock | 无 ignored、filtered 或内部 SKIP | **FAIL** |

### 5.1 Authorization projection：10/10 PASS

实测验证 stage/finalize/publish 与 strict evidence、CAS 竞争、pending delta、revoke fence 和 archive proof 的选定路径。完整测试名：

```text
aggregate_wide_null_card_revoke_delta_gates_any_card_evidence
archive_intent_lease_and_durable_proof_flow
archive_intent_parent_proof_rejects_mismatch_before_outbox_write
claim_gate_defers_behind_unpublished_same_grant_siblings
competing_publications_admit_exactly_one_cas_winner
content_change_update_via_real_writers_raises_card_fence_and_gates_evidence
null_card_pending_delta_covered_by_published_watermark_does_not_gate
published_evidence_reader_fails_closed_without_current_pointer
stage_finalize_publish_round_trip_yields_strict_card_evidence
unpublished_delta_gates_published_card_evidence_to_pending
```

这组证明这些具体断言在真实 MySQL 上通过，不证明每个 source aggregate、所有并发调度或生产迁移均已验收。

### 5.2 DB integration：2/2 PASS

```text
local_message_exact_claim_is_concurrent_fifo_and_token_fenced
test_sqlx_repository_e2e
```

涵盖 local message 精确 claim、并发 FIFO/token fence，以及既有 SQLx repository 端到端 fixture。repository e2e 不等于真实 HTTP composite e2e。

### 5.3 DB multi-tenant isolation：7/7 PASS

```text
test_audit_log_tenant_filter_invariant
test_cross_tenant_binding_rejection
test_cross_tenant_scope_split_is_corrupt_fail_closed
test_multi_tenant_rule_set_isolation
test_same_tenant_card_evidence_isolation
test_tenant_audit_log_read_write
test_tenant_scoped_query_with_real_db
```

验证租户 scoped 查询、规则集/卡 evidence 隔离、跨租户绑定拒绝、scope split 的 typed corrupt fail-closed 和审计 tenant filter。

### 5.4 Organization scope：15/15 PASS

```text
org_scope_attach_approval_rejects_non_parent_counterparty
org_scope_authority_end_to_end
org_scope_complete_outbox_event_kind_scoped_membership_contract
org_scope_dependency_propagate_mask_remove_revoke_waves_coalesce_and_advance_generation_only
org_scope_dependency_propagate_reparenting_old_and_new_parent_waves
org_scope_dependency_propagate_root_grant_wave_child_then_grandchild_after_republication
org_scope_managed_tenant_flag_off_never_falls_back_to_legacy
org_scope_membership_cap_is_global_fail_closed_and_revoke_frees_capacity
org_scope_membership_cap_serializes_boundary_race_at_read_committed
org_scope_membership_cap_serializes_concurrent_distinct_cards
org_scope_outbox_concurrent_claim_has_one_winner
org_scope_outbox_renew_reclaim_and_stale_worker_fencing
org_scope_outbox_retry_backoff_and_claim_budget_are_durable
org_scope_propagate_subtree_drains_wide_siblings_before_completion
org_scope_propagate_superseded_intent_and_same_root_invalidation
```

覆盖组织父子关系、mask/remove/revoke 与 reparent 波传播、容量边界竞争、outbox lease/reclaim/stale-token、durable backoff/budget；managed flag 关闭不能 legacy fallback。

### 5.5 Partition lease：7/7 PASS

```text
concurrent_expired_reclaim_has_one_winner_without_duplicate_key_deadlock
partition_claim_installs_lease_and_respects_partition_boundary
partition_discovery_returns_only_claimable_partitions
partition_lease_expired_lease_is_taken_over_with_generation_bump
partition_lease_roundtrip_acquire_renew_release
partition_lease_second_owner_is_busy_while_first_is_live
pointer_advance_reclaims_parked_budget_exhausted_event
```

覆盖分区 lease 生命周期、分区边界、活跃 owner 竞争、expired generation bump、并发单一 reclaim winner 与 pointer advance 恢复停放事件。

### 5.6 Quarantine/replay repository：7/7 PASS

```text
test_audit_quarantine_repository_lifecycle
test_concurrent_claim_fencing_and_expired_reclaim
test_expired_reclaim_fences_old_typed_claim
test_max_replay_attempts_are_observable_without_confirmation
test_requested_claim_requires_exact_route_status_and_attempt_ceiling
test_requested_replay_precedes_expired_recovery
test_typed_claim_confirm_and_fail_fencing
```

覆盖 durable quarantine/replay lifecycle、批准请求优先级、exact route/status、尝试上限和 typed token fencing。此处没有把 DB repository 成功冒充 broker 消费完成；后者由独立 Rabbit 专项验证。

### 5.7 Identity：8/8 PASS

```text
test_auth_token_family_and_device_session
test_identity_card_crud
test_login_aggregate_join
test_platform_user_soft_delete
test_register_user_three_table_transaction
test_token_family_cascade_revoke
test_user_list_left_join
test_user_local_credential_crud
```

实际日志包含 token-family/device-session 映射、identity/user 双卡区别、login JOIN 的 tenant/domain 来源、soft-delete filter、三表注册 commit/rollback、token-family 到 session 级联撤销、LEFT JOIN 和 login-name 唯一性。

### 5.8 Monitor：5/5 PASS

```text
test_alert_rule_crud_and_toggle
test_monitor_activity_log
test_monitor_alert_history_acknowledge
test_monitor_metric_snapshot_time_series
test_notification_channel_crud
```

覆盖 alert rule toggle、activity log 时间类型/level filter、acknowledge 幂等、3 小时桶时序聚合、notification channel enabled/NULL config。这组没有验证 Monitor 租户隔离。

### 5.9 TrustGraph：12/12 PASS

常规 integration 11 项：

```text
test_approval_audit_failure_rolls_back_status
test_audit_log_crud
test_delete_with_cascade_call_through_empty_card
test_permission_request_approve_transaction
test_permission_request_date_format_alias
test_permission_rule_crud
test_rule_set_entry_and_card_ref
test_rule_set_id_and_source_type_aliases
test_sod_policy_and_violation
test_user_card_date_format_aliases
test_user_card_soft_delete_cascade
```

org projector 1 项：

```text
production_org_scope_projector_publishes_and_two_workers_do_not_duplicate
```

覆盖 approval/audit 同事务回滚、治理 CRUD/date/alias 契约、空卡 cascade call-through、SoD fixture 和 production org projector 两 worker 不重复发布。origin-region 安装只在测试 fixture 中修正，生产 durable invalidation append 仍保留其要求。

## 6. MT-E 多租户目标与安全前提

本组真实集成中的精确测试名：

```text
mt_e1_sixty_four_tenant_interleaved_isolation
mt_e3_tenant_grant_churn
mt_e4_cross_tenant_invalidation_storm
mt_e5_capacity_512_tenants
mt_e6_mixed_state_fail_closed_landscape
hub_invalidation_notification_is_the_load_bearing_freshness_fence
single_writer_lease_is_mutually_exclusive_and_releasable
```

### 6.1 MT-E1：64 租户交错读写，PASS

- 租户组成：16 AllowActive、32 DenyActive、16 DenySuspended。
- 初代所有 64 张卡发布；AllowActive 初代恰 1 条授权，其他角色为 Ready 零授权。
- 8 个 reader 与 8 个 writer 混合运行；writer 将 allow 卡推进 gen2 两条授权。reader 每任务 128 次读取，合计 1,024 次；读取中允许该租户 1/2 条过渡，不允许外国 tenant grant。
- 全部 64 租户终态回读：allow 为 2 条，deny/suspended 为 0 条。
- 跨租户 probe 实际按 4 租户一组抽取，共 16 对；typed `NotReady(current_pointer_missing)` + Pending。不是穷举全部租户两两组合。
- 每租户一条审计 fixture，验证 tenant/id filter；并非每次授权请求的生产审计采样验收。
- 用时：测试体 5.51s，phase 6s。

### 6.2 MT-E3：8 租户、四轮授权/撤销 churn，PASS

- 先发布 gen1 一条授权；gen2 撤销、gen3 恢复、gen4 再撤销、gen5 再恢复。
- 每轮 4 reader 分担 8 租户读取；writer 逐租户发布，携带并更新最新 current CAS pointer。
- 并发读断言 Ready、0/1 条数量范围和 tenant 对应；每轮收敛断言精确 0/1；gen5 终态恰 1 条。
- 该测试不是持续高频压测；并发 reader 的数量和读取次数受源码界定。
- 用时：测试体 3.57s，phase 6s。

### 6.3 MT-E4：16 租户并发 gen2 发布，PASS

- 先建立 16 个独立 gen1 pointer；16 个 task 并发发布 gen2，4 个 side-reader 循环读直到 writers 完成。
- 实际断言是 Ready、每卡恰 1 条本租户 grant、action=read、Allow，以及收敛后 provenance source_id 对应本租户 entry。
- 源码描述为 invalidation storm，但本目标没有启动真实 LocalBus/Rabbit 节点广播；它是 MySQL published-evidence concurrent update/isolation 测试。
- 未对 grant-id 的具体 tail 或每个未更新租户的 gen1 字节相等作完整证明，不扩大解读源码注释。
- 用时：测试体 3.24s，phase 4s。

### 6.4 MT-E5：512 租户容量，PASS

- 512 个 AllowActive 租户；全部 seed、逐卡发布 gen1、全量 strict 回读 512 卡。
- 每张卡 Ready、恰 1 条 grant，grant 的 tenant/card/user 与该租户 fixture 对应。
- 实测：seed **2.502114634s**，publish **6.55516534s**，read **2.001959935s**；最大单次读取 **5,366 微秒**。
- 测试体 14.03s，phase 14s。以上阶段数字是观测数据，不是性能 SLA，也没有改写为断言阈值。
- 没有证明 512 是系统容量上限，也没有运行 HTTP loadgen。

### 6.5 MT-E6：12 租户混合状态，PASS

- 6 个正常授权终态对照租户、2 个发布后撤销、2 个 DenySuspended 空授权、2 个从未发布。
- 已发布 revoked/suspended fixture 为 Ready 空授权；从未发布为 typed `NotReady(current_pointer_missing)` + Pending，不能把查询异常当作拒绝成功。
- 一个正常卡被其他 11 个租户 scope 读取，全部必须 typed Pending 拒绝；不是每张正常卡都做全部跨租户笛卡尔积。
- 对正常 tenant 检查授权数量与 provenance 不受其他 fixture 状态影响。
- 这里 suspended 卡的发布 fixture 是空 grant；不额外宣称已验证每种生产 tenant-suspension writer 路径。
- 用时：测试体 2.84s，phase 4s。

### 6.6 Hub invalidation premise：PASS

真实 MySQL stage/claim/finalize/publish 后 COMMIT，使用返回的 commit-proven state 安装本地 `MemoryProjectionHub`。确认 gen1 Serve 且一条本租户 grant；直接施加 source_generation=2、published_generation=1 的 invalidation 后，同 scope 必须 DeferToDurable。验证的是 hub freshness 控制；没有测量跨进程 bus 必达、广播延迟或所有 writer invalidation coverage。

### 6.7 Single-writer lease premise：PASS

第一个连接持有 MySQL advisory lock；第二个获取立即拒绝。明确关闭持锁会话，而非将它归还 pool；通过 `IS_FREE_LOCK` 有限等待观察服务端释放；新连接重新获取后再关闭。验证排他与释放，不是完整进程 crash/restart ownership drill。

### 6.8 Redis-free configuration premise：2/2 PASS

在 workspace 和本地复核中执行：

```text
compat_flag_off_is_accepted_without_adapter
compat_flag_without_compiled_adapter_is_refused_fail_closed
```

证明关闭 compat 旗标被接受、未编译 adapter 时启用 compat 必须拒绝。这是纯配置契约，不是实际 composite 部署验收。

## 7. MySQL + Rabbit 审计重放专项

命令：

```bash
cargo test -p astral-trustgraph --test audit_replay_integration \
  -- --ignored --nocapture --test-threads=1
```

实际测试：`mysql_rabbit_audit_replay_real_integration`，**1 PASS、0 FAIL、0 ignored、3 filtered**。测试体 4.94s，phase 10s。三个 filtered 是 request-id 纯单测，已在 workspace 及本地单独执行，不能算这里的 live 集成通过数。

该测试使用真实 MySQL + RabbitMQ，Redis 始终关闭；consumer processing lease 通过既有 `init_idempotency_db` 初始化。四类情景全部达到各自断言：

1. **Happy path**：quarantine -> operator-requested -> worker claim -> Rabbit publisher confirm -> REPLAY_CONFIRMED；private capture queue 收到原 payload、原 message_id、重置的 retry header，death/DLQ 重发 header 被移除。
2. **业务 durable proof**：独立等待 audit_log 恰 1 条正确 PERMISSION_CHECK、mq_idempotent_log=PROCESSED、mq_consumer_lease=COMPLETED；不把 broker confirm 当成业务完成证明。
3. **Malformed payload 与 route refusal**：malformed_json 回到 Quarantined，不得 REPLAY_CONFIRMED；非法路由在 publish 前 allowlist 拒绝，active claim 被 fence 回 Quarantined。
4. **Expired lease/token fence**：过期 REPLAYING claim 被重新获取并增加 generation，发放新 token；旧 token 不能 confirm/fail 新 claim。

测试直接调用 repository，actor 是合法正整数 fixture，不是 HTTP platform-admin 权限链的完整验收。每个唯一 message ID 派生稳定 replay operation ID，清理 exact run-owned audit、quarantine、idempotency、consumer-lease rows。测试成功后干净停止 owned workers/连接。

原始日志：[audit-replay.log](astral-rf-20261007-r3-evidence/rabbit/audit-replay.log)。

## 8. 12 个 Runner 编排回归

这是 mock Cargo/Docker 的 shell 测试，无真实 DB/MQ 效果；本地和 E5 均 PASS。完整场景：

1. unit 无任何服务凭据，使用默认 feature、local transport、Redis-off。
2. 已迁移隔离 MySQL 集成入口不启用 Redis，不启动 Docker/DDL，不误选 dedicated mapping/Rabbit 目标。
3. Cargo 101 原样记录并导致总失败；确定性失败后继续其他已知目标。
4. 测试内部 `[SKIP]` 不折算 PASS。
5. 超时 124 标 UNKNOWN，停止后续 dispatch。
6. managed compose preflight/up -> 现有 migrator -> run-owned cleanup。
7. 部分 startup 失败仍清理本轮资源，不开始迁移。
8. 已占用 compose project 拒绝，不启动也不删除它。
9. 空 vhost Rabbit URL 在测试前拒绝。
10. Rabbit 专项选择 audit-replay，Redis-off 且不启用 redis feature。
11. Redis compat 只有显式模式才 opt-in。
12. matrix 实际选择指定 suite，默认 profile 无 Redis，不使用 `--test '*'`。

日志只有最终 12-scene summary；具体断言和 scene 编排见既有 `scripts/tests/test-run-tests.sh`。不以这个 mock 结果证明 fresh compose 或真实 migration 成功。

## 9. 已完成但未通过的项目

### 9.1 身份映射创建：FAIL

通过项：`identity_mapping_absence_is_detectable_for_mismatch_probes`，新随机 key 不存在时 read 返回 None。

失败项：`identity_mapping_absence_is_the_refusal_contract`。先播种随机 platform_user、identity_card 和 active identity_global_admin，缺失读通过；create 在 operation-ledger status 解码失败，因此同 key 正向 resolve、跨 app 正向隔离这两个后续断言未执行，不能报告为通过。

```text
Database("lock integration mapping operation: error occurred while decoding
column status: mismatched types; Rust String/VARCHAR is not compatible
with SQL BINARY")
```

位置：测试 `tests-suite/tests/security/premise_identity_mapping.rs:88`；生产 `astral-db/src/integration_identity_mapping.rs` 的 `OperationRow.status: String` 和 claim lock query。MySQL 8.0.46 的 ascii_bin ENUM 被 SQLx 识别成 BINARY。当前证据足以确认这个创建路径失败，不证明修复方案或全部元数据兼容性。fixture 清理在 surfacing 原始错误前完成。生产 SQL/解码/迁移未改动，不跳过、不将错误当成授权拒绝。

### 9.2 内存读吞吐 sanity floor：FAIL

工作负载：512 卡 × 每卡 2 aggregate × 每 aggregate 4 grant；预热 2,000 次；顺序读 20,000 次，4 线程各 5,000 次并发读；debug test profile，不是 HTTP QPS。

| 观测 | E5 完整 workspace | E5 独立诊断 | 本地独立复核 |
|---|---:|---:|---:|
| 顺序 reads/s | 29,066 | 29,078 | 60,380 |
| 并发 reads/s | **45,927** | **46,055** | 130,565 |
| 顺序 p99 | 44.269us | 53.288us | 29.000us |
| 并发 p99 | 353.209us | 389.193us | 94.100us |
| 并发 p99.9 | 504.843us | 524.962us | 177.100us |
| 并发 max | 1,007.968us | 650.317us | 327.500us |
| 实际断言结果 | FAIL | FAIL | PASS |

原门限：顺序 >=20,000 reads/s、并发 >=50,000 reads/s、顺序 p99 <250us、并发 p99 <1,000us。失败发生在并发 throughput 断言，后面的 p99 assert 因 panic 不执行；p99 数值虽已打印、数值符合门限，也不能宣称后续断言实际 PASS。

E5 独立诊断只运行一次，2026-10-07 22:30:12–22:30:56（44s 含 41.29s 编译），test body 2.46s，exit 101。没有降低门限、增加 retry 直到绿色或优化生产逻辑。此前旧快照 workspace 曾通过，并不覆盖 r3 FAIL。当前独立复现说明不能仅归因于其他测试同时运行；具体根因未确立。

日志：[完整 unit](astral-rf-20261007-r3-evidence/unit/unit.log)、[E5 diagnosis](astral-rf-20261007-r3-evidence/throughput-diagnostic.log)、[本地对照](local-throughput.log)。

### 9.3 本地 Clippy 1.92：FAIL

`cargo clippy --workspace -- -D warnings` 在未改动 `astral-db/src/memory_projection_hub/assembly_cache.rs:195` 触发 `clippy::nonminimal_bool`，exit 101。E5 1.98 的 all-targets Clippy 通过。两种环境结果分别保留；本次未修生产 lint 或固定统一工具链。

### 9.4 早期 Windows 源码形状断言：FAIL，未完成跨平台修复

此前 Windows 全 workspace 出现 14 个 LF 字符串锚点/CRLF 工作副本相关失败；它们不是最终 E5 的授权行为失败，Linux 最终快照也未复现。但本次没有修复源码形状守卫的跨平台读取策略，也没有宣称 Windows 全量 green。最终本地只完成下面列出的针对性复核。

## 10. 本地补充验证

本地 cwd 为 `E:/OfficialVersion/AstralLight-Next`；使用该最终补丁，没有外部服务依赖。

| 命令（均显式 manifest-path 指向根 Cargo.toml） | 实际结果 | 日志/说明 |
|---|---|---|
| `cargo check --workspace --all-targets` | exit 0，编译 53.67s | [local check](local-workspace-check.log) |
| `cargo clippy --workspace -- -D warnings` | exit 101，既有 nonminimal_bool | [local Clippy](local-clippy.log) |
| `cargo fmt --all -- --check` | exit 0 | 工具调用证据；没有生成 stdout |
| `git diff --check` | exit 0 | 只有 Git line-ending conversion 提示 |
| `bash -n` 三个改写 shell 入口 | exit 0 | 语法检查，无服务效果 |
| `bash scripts/tests/test-run-tests.sh` | exit 0，12 场景 | 不代替真实集成 |
| `cargo test -p astral-trustgraph --test audit_replay_integration -- --test-threads=1` | 3 PASS，1 ignored | [local replay](local-replay-unit.log) |
| `cargo test -p testsuite --test premise_redis_free_composite -- --test-threads=1` | 2 PASS | [local config](local-redis-free-config.log) |
| `cargo test -p astral-db --lib memory_projection_hub::tests::memory_evidence_read_throughput_and_tail_latency_under_warm_multi_card_mirror -- --nocapture` | 1 PASS，856 filtered | [local throughput](local-throughput.log) |
| 修改的 TOML parse、security target path | PASS | 四个 nested security binaries 均有显式 target |
| 两份变更 README 文件链接 | 20/20 存在 | 无新增缺失链接 |

本地 request-id 三项覆盖 ASCII 保持、64-byte 截断、多字节边界不被切断；这些也包含在 E5 workspace PASS 数中。MANIFEST 仍有历史非字面多目录 path 和缺失 `tests-suite/e2e/` recipe 目录；未新增缺失 path，不把目录存在性校验当作 e2e 执行。

## 11. RQ、M、E 系列的准确状态

| 系列 | 本次已执行内容 | 不能宣称的结论 |
|---|---|---|
| RQ 系列 | 没有独立 campaign dispatch 或当前结果 artifact | 不能报告 RQ1–RQ5 通过；历史分布式源码/文档不是当前跑分 |
| M1–M5 | M1 source/projection、M2 CAS/lease、M3 evidence/hub、M4 部分 fail-closed、M5 部分 gateway/middleware 的测试面被覆盖 | 它们是实现假设映射，不是五个可直接计数的独立测试；不能整体证明，mapping 正向创建仍失败 |
| 授权验证 E1–E5 | workspace 中 E1 两项与 E2 四项局部守卫 | 没有执行 `Docs/authorization-validation/tools/` 完整 Python suites、live controllers 或完整协议 |
| MT-E | MT-E1、MT-E3、MT-E4、MT-E5、MT-E6 各 1 PASS | 与授权验证 E1–E5 不同；MT-E2 未发现当前源码/注册项 |
| TLA+/TLC | 未运行 | pinned/checksum-verified TLC 前置不足，不能用 Python model 代替 |

M1–M5 权威映射来自既有 `Docs/authorization-validation/IMPLEMENTATION_MAP.md`；E tools 的编目来自 `tests-suite/MANIFEST.toml`。本轮没有调用 Python unittest/experiment runner，源码存在不能计 PASS。

## 12. 剩余 ignored 与未执行项

workspace 发现的 96 个 ignored 中，83 项已由真依赖阶段执行；以下 **13 项仍未执行**：

```text
create_read_idempotency_cas_revoke_and_permanent_key_ownership
mapping_read_rejects_inactive_or_expired_source_identity
memory_projection_hub::tests::assembly_cache::assembly_cache_performance_probe
memory_projection_hub::tests::performance::memory_evidence_no_regression_matrix
service::audit_replay_worker::tests::mysql_rabbit_replay_worker_integration_skeleton
service::authorization_projector::planning::parent_ordinals::tests::performance::parent_lookup_no_regression_matrix
service::authorization_projector::planning::parent_ordinals::tests::stage_planning_lookup_performance_probe
service::authorization_projector::tests::performance::complete_stage_plan_no_regression_matrix
service::local_projection_worker::tests::shared_ledger_performance_probe
policy-engine/src/client.rs - client (line 8)
policy-engine/src/client.rs - client (line 16)
policy-engine/src/client.rs - client (line 31)
policy-engine/src/client.rs - client::PermissionClient (line 53)
```

其中前两项是 dedicated SDK mapping schema 的独立隔离库测试；仍保留该隔离门。一个 audit worker skeleton 没有因为独立 audit-replay 集成通过而改计 PASS；六个 CPU matrix/probe 未跑；四个 doctest ignored 未跑。

以下不在当前 Cargo 发现范围或需要另行 campaign，**未执行，绝不绿色计数**：

- 新建 compose 的 MySQL/MFA 初始化、全量 approved migration、backup/restore drill。
- Redis compat feature suite；本轮刻意关闭 Redis，optional Redis 在 Cargo.lock 中不等于默认编译依赖。
- excluded/frozen `astral-chat`、`astral-learn`、`astral-cache`、独立 integrations/bench crates。
- Criterion/引擎比较、OPA sidecar、loadgen/HTTP 饱和阶梯。
- 真实 single-node composite 启动后业务 HTTP end-to-end。
- RQ 三节点 campaign、跨节点/跨区恢复/故障、授权验证 E1–E5 Python/live 全协议、TLC 模型。
- 生产环境部署、permission 切流、有效权限变更验收。

## 13. 恢复、资源和日志完整性

最终 pre/post DB 对账：

| postcondition | 前置值 | 结束值 | 结论 |
|---|---:|---:|---|
| active test replay（REPLAY_REQUESTED/REPLAYING） | 0 | 0 | 没有未知活跃 replay |
| PENDING mapping operation | 0 | 0 | 没有新 in-doubt mapping operation |
| writer advisory lock free | 1 | 1 | 租约释放 |
| 既有 QUARANTINED replay 行 | 1 | 1 | 旧失败残留未自动删除或 replay |

旧行 replay_attempts=0、requested_by=NULL；r3 无新增遗留 replay 行。未将它视为当前成功证据，也未做广泛 DB 清理。

Redis/MySQL/Rabbit 原容器均确认 running healthy；远端 main 干净；无活跃 cargo/rustc/worker 测试进程。日志复制与 hash 验证后只移除本轮三个临时源码快照；未删除目标编译目录、原 main、数据卷、容器或数据库。

r3 的一个临时 wrapper 首次因缺证据目录在测试/DB/Redis 修改前退出；检查状态后修正，有限重试一次。其他早期 CRLF launch、错误 Rabbit vhost、fixture 失败属于旧尝试，保留 artifact，不充当最终 PASS。最终 r3 没有残留 UNKNOWN/PENDING；两个 FAIL 明确保留。

报告编制时仅读取本地已留存日志、源码及工作区状态，不重新启动 E5 campaign。解析计数时补充支持含空格的 doctest 名称后，逐条记录与 Cargo summary 完全一致。未执行项和重复运行均未吞掉。

## 14. 结论与证据索引

本次可以确认：默认构建树无 Redis；五个已登记 MT-E 目标通过；真 MySQL published-evidence、组织/租约/隔离/治理测试的选定路径通过；Rabbit audit-replay 的 durable 业务证明通过；runner 在已覆盖失败/超时/ownership 情景下不制造假绿。

本次不能确认：完整 gate 全绿、SDK mapping 创建兼容、E5 性能达到 sanity floor、生产迁移或跨节点/HTTP campaign 验收。身份映射 status 解码与 E5 并发内存读性能仍为 FAIL；本地 Clippy 也有工具链相关既有失败。

- [逐测试项最终结果 CSV](test-results.csv)
- [单一原始执行证据记录](evidence.md)
- [最终 E5 run.log](astral-rf-20261007-r3-run.log)
- [MySQL 实际命令与结果](astral-rf-20261007-r3-evidence/integration-runner.log)
- [Rabbit 实际命令与结果](astral-rf-20261007-r3-evidence/rabbit-runner.log)
- [Workspace 完整原始输出](astral-rf-20261007-r3-evidence/unit/unit.log)
- [E5 质量门](astral-rf-20261007-r3-evidence/check-runner.log)
- [E5 独立性能诊断](astral-rf-20261007-r3-evidence/throughput-diagnostic.log)
- [DB postcondition](astral-rf-20261007-r3-evidence/postcondition.log)
- [源码 hash](astral-rf-20261007-r3-evidence/source-sha256.log)
- [原始远端日志归档](../astral-rf-20261007-delivery.tar.gz)

原始日志归档 SHA256：`375e8752f5ae200a504caa8fd5becaacb5ee504de8b0a4b80f4413c883b56dc3`。该归档先于本报告编制，包含 r3/历史尝试日志；本报告和本地补充日志位于展开目录，不假称已包含在该 hash 中。

主 Agent 已审查命令、数量、实际断言、源文件范围、五链和资源 postcondition；本文是基于同一原始证据记录的人类阅读报告，不是新增规范或规则副本。
