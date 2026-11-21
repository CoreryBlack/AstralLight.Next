-- OFFLINE CANDIDATE / 离线候选：仅供设计审查，不是迁移，不可直接执行。
-- 本文件是 memory-v1 P0 数据库应用（apply）切片的表结构候选，配套
-- astral-db/src/memory_v1_apply.rs / memory_v1_apply_facts.rs /
-- memory_v1_apply_records.rs 的参数化 SQL 执行器。
-- 整份 DDL 故意置于块注释内，不能直接作为建库脚本运行。解除注释不代表获准采用；
-- migration.rs 不会自动执行本文件，任何建库动作仍须按 AGENTS.md 的
-- Exec-L3 门禁另行批准（preflight、备份/恢复、postcondition）。
-- 规范适用范围：Docs/规范/Rust后端编码规范_V1.0.md §15.10（尤其 §15.10.4）与
-- Docs/memory-v1/全新数据库设计.md §7 第 7/9/10/11 条。
-- 本文件只表达核心关系，不证明服务已实现、数据已持久化、审计可恢复或授权有效。
--
-- 约定与边界：
-- 1. 本候选四张元数据表统一使用 mv1_apply_* 命名空间（含审计表），与九张
--    memory_* 授权事实表明确区分：冷加载对未知 memory_* 表严格拒绝，
--    本候选不得被认作授权域表；加载器对未知 memory_* 表的拒绝行为保持不变。
-- 2. 前置表（memory_user / memory_identity_card / memory_tenant / memory_user_card /
--    memory_rule_set / memory_rule_set_version / memory_card_rule_set_binding /
--    memory_binding_confirmation / memory_rule_set_change_confirmation）以
--    Docs/memory-v1/数据库结构候选.sql 为准；本候选只新增 durable tail 四表。
--    两份候选都未经真实 MySQL 验证，均不是冻结的数据库契约。
-- 3. mv1_apply_receipt.boot_id 绑定【原始消息】的 boot 标识（产生该消息的
--    启动标识）；消费方 boot/worker 标识单独保存在 applied_by_boot_id /
--    worker_id，绝不替代原始绑定。跨重启对比回执时不得用消费方 boot 判等。
-- 4. mv1_apply_receipt 是操作回执与去重依据：operation_id 全局唯一；
--    (stream_id, journal_sequence) 唯一。回执内容与消息标识不一致时，
--    执行器 fail-closed 停止并对账，绝不跳过冲突继续恢复。
-- 5. mv1_apply_progress 是每流消费进度（durable tail）：last_frame_hash
--    与 last_journal_sequence 构成连续前缀栅栏。进度行必须由启动/接线侧
--    以 initialize 显式预置并绑定流的 genesis anchor（序号 0/0 + genesis
--    hash）；缺行不是可信 genesis，执行器对缺行 fail-closed 拒绝。
--    DENY 消息只推进 journal 序号，不推进 mutation 序号。epoch 轮换尚未
--    纳入本切片合同，执行器对同流 epoch 变化 fail-closed（EpochChangeNotCovered）。
-- 6. mv1_apply_fence 是消费 worker 的 CAS lease：fence_generation 单调且每
--    次 claim/renew 轮换；claim 只接受从未租用或已过期的行，活跃 lease 必须
--    以当前 token（boot+worker+generation）renew，renew/release/apply 在事务
--    保护下同时匹配 owner+generation+未过期，旧 token（即使同一 boot/worker）
--    一律失效。lease_expires_at 以数据库 UTC 时钟判定，不信任客户端时钟。
-- 7. mv1_apply_audit_event 为 append-only 审计行：一次应用只插入一行；
--    canonical_payload 是审计值/原始观测的完整规范 JSON 编码（原始 DENY
--    观测的 observation_wire_hex 亦存其中），audit_row_digest 是其域分隔
--    SHA-256（与回执绑定）。时间语义显式分离：audit_time_unix 只在值层
--    携带引擎可信时间时绑定；read_started_at_unix 只用于原始观测的读取
--    开始时刻，明确不是最终可信时间；两者都可为 NULL，不制造时间。
--    本表没有 UPDATE/DELETE 路径，也没有任何行级状态可被改写为授权证明；
--    数据库行永远不是 ALLOW。
-- 8. 所有 BIGINT UNSIGNED 序号沿用 journal 帧（1 起始）；DENY 允许
--    mutation_sequence = 0 表示外部基线。容量、保留期限、归档与
--    事后审计重建合同仍未决，不在本候选内。
-- 9. 执行器以本候选的列名/类型为准做参数化绑定；两处（DDL 与 SQL 常量）
--    尚无自动一致性校验，采用前必须先冻结契约并完成真实 MySQL 验收。

/* OFFLINE CANDIDATE: 以下均为注释内的候选 DDL，不可直接执行。

CREATE TABLE mv1_apply_fence (
    stream_id BINARY(16) NOT NULL,
    owner_boot_id BINARY(16) NOT NULL,
    owner_worker_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    lease_expires_at TIMESTAMP(6) NULL,
    fence_generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (stream_id)
) ENGINE=InnoDB;

-- 回执：操作标识、消息序号与内容摘要的唯一绑定（去重与对账依据）。
CREATE TABLE mv1_apply_receipt (
    stream_id BINARY(16) NOT NULL,
    journal_sequence BIGINT UNSIGNED NOT NULL,
    epoch_id BINARY(16) NOT NULL,
    mutation_sequence BIGINT UNSIGNED NOT NULL,
    message_id BINARY(16) NOT NULL,
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    boot_id BINARY(16) NOT NULL COMMENT '原始消息 boot 标识，不是消费方 boot',
    applied_by_boot_id BINARY(16) NOT NULL COMMENT '消费方 boot 标识',
    worker_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    outcome VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_fingerprint BINARY(32) NOT NULL,
    prev_frame_hash BINARY(32) NOT NULL,
    frame_digest BINARY(32) NOT NULL,
    payload_digest BINARY(32) NOT NULL,
    mutation_digest BINARY(32) NOT NULL COMMENT 'DENY 行保存全零，表示无治理变更内容',
    audit_row_digest BINARY(32) NOT NULL,
    fact_operation_count SMALLINT UNSIGNED NOT NULL,
    fact_rows_affected_total BIGINT UNSIGNED NOT NULL,
    applied_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (stream_id, journal_sequence),
    UNIQUE KEY uq_mv1_apply_receipt_operation (operation_id),
    KEY ix_mv1_apply_receipt_epoch (stream_id, epoch_id),
    CONSTRAINT ck_mv1_apply_receipt_outcome CHECK (outcome IN ('APPLIED', 'DENY'))
) ENGINE=InnoDB;

-- 每流消费进度：连续前缀栅栏（journal/mutation 序号 + 上一帧 hash）。
CREATE TABLE mv1_apply_progress (
    stream_id BINARY(16) NOT NULL,
    epoch_id BINARY(16) NOT NULL,
    last_journal_sequence BIGINT UNSIGNED NOT NULL,
    last_mutation_sequence BIGINT UNSIGNED NOT NULL,
    last_frame_hash BINARY(32) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (stream_id)
) ENGINE=InnoDB;

-- append-only 审计行：授权事实、审计、回执、进度在同一事务提交。
CREATE TABLE mv1_apply_audit_event (
    audit_id BINARY(16) NOT NULL,
    stream_id BINARY(16) NOT NULL,
    epoch_id BINARY(16) NOT NULL,
    journal_sequence BIGINT UNSIGNED NOT NULL,
    mutation_sequence BIGINT UNSIGNED NOT NULL,
    message_id BINARY(16) NOT NULL,
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    decision VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reason_code VARBINARY(128) NULL COMMENT '原始 DENY 观测无 reason 字段，保持 NULL，不制造',
    actor_user_id BINARY(16) NOT NULL,
    actor_identity_card_id BINARY(16) NOT NULL,
    resource VARBINARY(256) NOT NULL,
    action VARBINARY(256) NOT NULL,
    audit_time_unix BIGINT NULL COMMENT '仅当值层携带引擎可信时间时绑定；观测路径不制造时间',
    read_started_at_unix BIGINT NULL COMMENT '原始 DENY 观测的读取开始时刻（观测时刻），明确不是 B-4 最终可信时间',
    root_instance_id BINARY(16) NOT NULL,
    root_version BIGINT UNSIGNED NOT NULL,
    root_content_hash BINARY(32) NOT NULL,
    root_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    target_id BINARY(16) NULL,
    change_summary VARBINARY(4096) NULL,
    canonical_payload JSON NOT NULL,
    audit_row_digest BINARY(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (audit_id),
    UNIQUE KEY uq_mv1_apply_audit_event_position (stream_id, journal_sequence),
    UNIQUE KEY uq_mv1_apply_audit_event_operation (operation_id),
    KEY ix_mv1_apply_audit_event_stream (stream_id, mutation_sequence)
) ENGINE=InnoDB;

*/
