-- OFFLINE CANDIDATE / 离线候选：仅供设计审查，不是迁移，不可直接执行。
-- 全新数据库、无旧数据；不连接数据库、不导入旧模型，不提供初始化数据。
-- 整份 DDL 故意置于块注释内，不能直接作为建库脚本运行。解除注释不代表获准采用。
-- 未经真实 MySQL 环境验证；不得供正式授权读取，也不得作为现行生产协议的替代。
-- 设计依据：同目录《统一规则集结构设计》《用户双卡租户与规则集设计》。
-- 规范适用范围：Docs/规范/Rust后端编码规范_V1.0.md §15.10 定义 memory-v1 单机合同；
-- 旧生产路径继续遵循其适用合同。候选尚须补齐未决合同并完成采用验收。
-- 本文件只表达核心关系，不证明服务已实现、数据已持久化、审计可恢复或授权有效。
--
-- 约定与边界：
-- 1. 所有 BINARY(16) 身份均为候选内部标识；生成方式、字节序及外部表示待定。
--    不把自增值、字段名、显示名称、身份卡或租户父子关系当作授权。
-- 2. 租户自引用 FK 只能保证父节点存在，不能阻止多节点环；并发建树、重挂和
--    无环验证由后续合同解决。身份卡唯一约束仅保证每用户至多一张；每人至少一张
--    的创建及生命周期仍需应用事务和完整性验证。一个用户同一租户可有多张用户卡。
-- 3. 规则集有管理归属，绑定关联具体用户卡与规则集。这里故意不限制二者同租户、
--    同卡的绑定数量或重复组合；这不是允许跨租户或重复绑定的授权。跨租户复用
--    合同未建立时，管理端须拒绝跨租户绑定；组织关系不能自动创建绑定或授权。
-- 4. 绑定只指向规则集稳定身份，不固定某个版本。共享规则集经有权人员确认修改，
--    在共享根原子生效后立即影响已有有效绑定，不以逐卡重新确认为默认前置。
--    修改确认如何覆盖后续变更及影响范围尚待确定，不得把绑定行视作已确认授权。
-- 5. 规则集版本四元组为 version + content + timestamp + hash。version、content、
--    timestamp 的精确字节及三者规范编码后的精确 hash 输入字节均以二进制保存；
--    hash 以原始摘要字节保存，不使用 MySQL JSON 或字符集/排序规则重编码。编码、
--    hash 算法、输入分帧与版本、时间含义和精度、长度上限均待定；当前列容量仅为
--    候选存储上限，不是协议。hash 不包含自身，不能用无分隔的普通拼接替代编码。
--    SQL 无法证明输入与三个字段相符或摘要正确；写入、读取须按未来冻结的合同
--    验证，历史编码及算法必须可识别并保留。影响授权解释的外部元数据须纳入
--    content 或由另一个完整性合同绑定；本候选未解决该问题。
-- 6. 每条成功持久化的版本记录保留完整四元组及精确 hash 输入；此处的主键仅防止
--    同规则集下相同版本标识重复，未定义版本分配、排序、连续性、不可变执法、
--    当前版本指针或缺口检测。不得从最大值或时间戳推断当前版本或完整历史。
--    内存成功可先于异步落盘，崩溃可能丢失已生效版本甚至撤权；数据库目标保存
--    从首版到最新版的所有完整版本，与此存在尚未解决的缺口。队列、顺序、失败
--    通知、落盘确认、缺口发现、恢复和一致性快照均待设计，不能宣称连续完整。
-- 7. 确认表只提供追溯候选：确认人、对象、版本、范围字节、操作关联及时间。
--    它不证明确认人当时有权、确认仍有效、覆盖未来修改、审计已落盘或操作已完成。
--    确认引用版本的 FK 要求数据库先保存该版本；内存先生效时确认与版本的异步
--    落盘顺序、部分失败和崩溃恢复仍待设计，不能据此宣称内存确认必然持久化。
--    撤销、有效期、状态、影响集合、批量确认及确认/审计完整性均待定；缺少可证明
--    的有效确认时不得放行。规则、用户、卡、租户及绑定的状态和资格也尚未建模。
-- 8. 不定义具体规则语言、资源动作、规则冲突或隐式授权，不建立模板、等级、
--    domain、旧 projection 表，不插入初始超级管理员或任何授权。规则条目保存在
--    不透明的完整 content 中，待规则语言确定后再设计可验证的表达和访问方式。
-- 9. 正式请求须经 PolicyEngine.evaluate() 和现行生产授权门禁；缺失、不一致或
--    无法证明时 PENDING/DENY，不能用此候选、原始数据库行或 SQL miss 回退放行。
--    冷加载、约束、并发、权限、快照、恢复、hash 及真实 MySQL 验收均尚未执行。

/* OFFLINE CANDIDATE: 以下均为注释内的候选 DDL，不可直接执行。

CREATE TABLE memory_user (
    user_id BINARY(16) NOT NULL,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB;

CREATE TABLE memory_identity_card (
    identity_card_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    PRIMARY KEY (identity_card_id),
    UNIQUE KEY uq_memory_identity_card_user (user_id),
    CONSTRAINT fk_memory_identity_card_user
        FOREIGN KEY (user_id) REFERENCES memory_user (user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE memory_tenant (
    tenant_id BINARY(16) NOT NULL,
    parent_tenant_id BINARY(16) NULL,
    PRIMARY KEY (tenant_id),
    KEY ix_memory_tenant_parent (parent_tenant_id),
    CONSTRAINT ck_memory_tenant_not_self_parent
        CHECK (parent_tenant_id IS NULL OR parent_tenant_id <> tenant_id),
    CONSTRAINT fk_memory_tenant_parent
        FOREIGN KEY (parent_tenant_id) REFERENCES memory_tenant (tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE memory_user_card (
    user_card_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'ACTIVE',
    PRIMARY KEY (user_card_id),
    KEY ix_memory_user_card_user (user_id),
    KEY ix_memory_user_card_tenant (tenant_id),
    CONSTRAINT fk_memory_user_card_user
        FOREIGN KEY (user_id) REFERENCES memory_user (user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_memory_user_card_tenant
        FOREIGN KEY (tenant_id) REFERENCES memory_tenant (tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE memory_rule_set (
    rule_set_id BINARY(16) NOT NULL,
    owner_tenant_id BINARY(16) NOT NULL,
    current_version_bytes VARBINARY(255) NOT NULL,
    PRIMARY KEY (rule_set_id),
    KEY ix_memory_rule_set_owner (owner_tenant_id),
    CONSTRAINT fk_memory_rule_set_owner
        FOREIGN KEY (owner_tenant_id) REFERENCES memory_tenant (tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE memory_rule_set_version (
    rule_set_id BINARY(16) NOT NULL,
    version_bytes VARBINARY(255) NOT NULL,
    content_bytes LONGBLOB NOT NULL,
    timestamp_bytes VARBINARY(255) NOT NULL,
    hash_input_bytes LONGBLOB NOT NULL,
    hash_bytes VARBINARY(255) NOT NULL,
    PRIMARY KEY (rule_set_id, version_bytes),
    CONSTRAINT fk_memory_rule_set_version_owner
        FOREIGN KEY (rule_set_id) REFERENCES memory_rule_set (rule_set_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE memory_card_rule_set_binding (
    binding_id BINARY(16) NOT NULL,
    user_card_id BINARY(16) NOT NULL,
    rule_set_id BINARY(16) NOT NULL,
    binding_layer VARCHAR(7) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    valid_from BIGINT NULL,
    valid_until BIGINT NULL,
    owner_scope VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NULL,
    tenant_scope VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NULL,
    removed_at BIGINT NULL,
    removed_by VARBINARY(16) NULL,
    overlay_guard BINARY(16) GENERATED ALWAYS AS (CASE WHEN binding_layer = 'OVERLAY' THEN user_card_id ELSE NULL END) STORED,
    PRIMARY KEY (binding_id),
    UNIQUE KEY uq_binding_card_ruleset (user_card_id, rule_set_id),
    UNIQUE KEY uq_binding_one_overlay (overlay_guard),
    UNIQUE KEY uq_memory_binding_rule_set (binding_id, rule_set_id),
    KEY ix_memory_binding_card (user_card_id),
    KEY ix_memory_binding_rule_set (rule_set_id),
    CONSTRAINT ck_memory_binding_layer CHECK (binding_layer IN ('BASE', 'OVERLAY')),
    CONSTRAINT fk_memory_binding_card
        FOREIGN KEY (user_card_id) REFERENCES memory_user_card (user_card_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_memory_binding_rule_set
        FOREIGN KEY (rule_set_id) REFERENCES memory_rule_set (rule_set_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 版本引用只记录该次确认所指内容，不把绑定锁定到该版本。
-- 范围字节和 operation_id 的格式、关联审计及确认有效性合同待定。
CREATE TABLE memory_binding_confirmation (
    confirmation_id BINARY(16) NOT NULL,
    binding_id BINARY(16) NOT NULL,
    rule_set_id BINARY(16) NOT NULL,
    version_bytes VARBINARY(255) NOT NULL,
    confirmer_user_id BINARY(16) NOT NULL,
    scope_bytes LONGBLOB NOT NULL,
    operation_id VARBINARY(255) NOT NULL,
    confirmed_at_bytes VARBINARY(255) NOT NULL,
    revoked_at BIGINT NULL,
    revoked_by VARBINARY(16) NULL,
    PRIMARY KEY (confirmation_id),
    KEY ix_memory_binding_confirmation_binding (binding_id, rule_set_id),
    KEY ix_memory_binding_confirmation_version (rule_set_id, version_bytes),
    KEY ix_memory_binding_confirmation_confirmer (confirmer_user_id),
    KEY ix_memory_binding_confirmation_operation (operation_id),
    CONSTRAINT fk_memory_binding_confirmation_binding
        FOREIGN KEY (binding_id, rule_set_id)
        REFERENCES memory_card_rule_set_binding (binding_id, rule_set_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_memory_binding_confirmation_version
        FOREIGN KEY (rule_set_id, version_bytes)
        REFERENCES memory_rule_set_version (rule_set_id, version_bytes)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_memory_binding_confirmation_user
        FOREIGN KEY (confirmer_user_id) REFERENCES memory_user (user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 规则集修改确认仅作为追溯骨架；是否及如何覆盖已有绑定仍待决。
CREATE TABLE memory_rule_set_change_confirmation (
    confirmation_id BINARY(16) NOT NULL,
    rule_set_id BINARY(16) NOT NULL,
    version_bytes VARBINARY(255) NOT NULL,
    confirmer_user_id BINARY(16) NOT NULL,
    affected_scope_bytes LONGBLOB NOT NULL,
    operation_id VARBINARY(255) NOT NULL,
    confirmed_at_bytes VARBINARY(255) NOT NULL,
    revoked_at BIGINT NULL,
    revoked_by VARBINARY(16) NULL,
    PRIMARY KEY (confirmation_id),
    KEY ix_memory_change_confirmation_version (rule_set_id, version_bytes),
    KEY ix_memory_change_confirmation_confirmer (confirmer_user_id),
    KEY ix_memory_change_confirmation_operation (operation_id),
    CONSTRAINT fk_memory_change_confirmation_version
        FOREIGN KEY (rule_set_id, version_bytes)
        REFERENCES memory_rule_set_version (rule_set_id, version_bytes)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_memory_change_confirmation_user
        FOREIGN KEY (confirmer_user_id) REFERENCES memory_user (user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

*/
