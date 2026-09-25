# V5 模型修正筹划（专供 Rust）V1.0

> 版本：V1.0（部分实施/筹划中）
> 日期：2026-08-10
> 范围：基于 **v4 canonical 表架构**（`Docs/sql/full_schema_v4.sql`）筹划 **v5 模型修正**——未来专供 Rust 使用（Rust 独立演进，不要求 Java 同步）。
> 依据：《Rust架构模型设计修正记录.md》问题 1-8、问题 14。
> 状态：**部分实施/筹划中**；每项标注 决策/待定/前置条件（已完成项以「已完成」标注，未完成项保留 决策/待定/前置条件）。**2026-08-11 更新**：公共资格服务（D1）与 CARD/ELIGIBILITY 双投影通道已落地（见 §3.5、§四、§五），资格 fan-out / identity expiry / validity API 列为后续项。

---

## 一、v5 目标与原则

| 原则 | 说明 |
|------|------|
| 专供 Rust | v5 是 Rust 的目标态 schema；Java 沿用 v4 或另行演进，互不阻塞 |
| 突破冻结 | v5 允许 DDL 变更（v4 阶段冻结仅约束过渡期）；Redis key / RabbitMQ 拓扑不在本筹划范围（另行决策） |
| 建模正确 | identity_card 回归纯身份证（问题 1），仅承担身份/会话锚点；组织归属唯一由 user_card 承载 |
| 双卡对应 | identity_card 与 user_card 经同一 platform_user、authenticated user、Token/SessionGrant 对齐，证明双卡对应；证明成功后由 user_card + rule_set 承担资源/动作授权（问题 12） |
| 收敛评估链 | 租户上下文统一来自 user_card；引擎/签发/网关同源（问题 8 D1） |
| 补 Chat scope | 会话/群组获得物理 scope（问题 3） |
| 消除漂移 | Rust baseline 与 v5 合一，不再有 canonical/baseline 两套（问题 2） |

---

## 二、v4 现状表盘点（已核实）

### 2.1 权限链路核心表（v4 canonical + Rust migration 补充）

| 表 | v4 关键列 | 现状问题（v5 动因） |
|----|----------|---------------------|
| `identity_card` | domain_id（注释"默认领域上下文"）、tenant_id、status、token_version、expires_at、disabled_reason | tenant/domain **无人写入**；Rust 曾读取（问题 1/2）——代码层已移除读取/写入（见 §3.1 状态） |
| `user_card` | domain_id、tenant_id、card_type、card_status、template_id、level_id、priority、is_primary、valid_from/valid_until | 组织归属唯一承载点（v5 强化）；starter 卡 tenant/domain 为 NULL |
| `auth_device_session` | current_user_card_id（注释"当前激活的用户卡ID"）、refresh_token_hash、session_version/epoch、family_id | 已绑 user_card，语义正确；v5 明确"会话只绑 user_card" |
| `auth_token_family` | family_id、user_id、family_key、status、revoked_at | 无问题；保持 |
| `auth_session_jti_index` | session_id、jti、user_id、session_epoch、status（Rust migration 20260728000001） | 投影索引；保持 |
| `card_rule_set_ref` | card_id（用户卡）、rule_set_id、ref_type BASE/OVERLAY、tenant_id | 评估不依赖其 tenant_id（user_card 为源）；保持 |
| `rule_set` / `rule_set_entry` / `rule_set_snapshot` | tenant_id、resource/action/effect/condition/priority/valid_from/valid_to | tenant_id 仅管理用途；保持 |
| `permission_rule` / `permission_rule_snapshot` | card_id（用户卡）、resource、action、effect、valid、tenant_id | 评估不依赖其 tenant_id；保持 |
| `authorization_projection_head` | aggregate_type/aggregate_id、source/projected generation、revoke_fence、status（Rust migration 20260729000003） | 语义为 **CARD（user_card）** + **ELIGIBILITY（资格，2026-08-11 新增）** 双聚合通道（`ProjectionAggregate::Card/Eligibility`，见 `astral-types/src/projection.rs`） |
| `chat_conversation` | **domain_id NOT NULL、无 tenant_id**、owner_id、status、is_deleted | 问题 3：无 tenant 归属 |
| `chat_conversation_member` | conversation_id、user_id（UNIQUE）、role、left_at、invite_by | 用户级成员；v5 决策见 §3.4 |
| `chat_message` | conversation_id、sender_id、domain_id NOT NULL、message_id UUID | 已 scope（domain）；保持 |

### 2.2 关键漂移事实（问题 2）

- Rust baseline（20240630000001_baseline.sql）identity_card 仅 id/user_id/card_number/password_hash/real_name/status/valid_from/valid_until/deleted_at——**连 tenant_id/domain_id/expires_at/token_version 都没有**，与 canonical 严重不一致。
- `authorization_projection_head`、`auth_session_jti_index` 仅在 Rust 自有 migration 定义，canonical 无——**Rust 已在 v4 之上独立加表**，v5 是把这层独立正式化。

---

## 三、v5 表级修正

### 3.1 identity_card — 回归纯身份证

| 项 | v4 | v5 决策 | 理由 |
|----|----|--------|------|
| `tenant_id` | 列存在（NULL，无人写） | **Rust 不再读取/写入**；列保留（Java 兼容）或标注 DEPRECATED | 身份证不承担组织归属（问题 1） |
| `domain_id` | 列存在（注释"默认领域上下文"） | **Rust 不再读取**；同上去语义 | 同上 |
| `expires_at` | 列存在 | 保留；**补索引**（登录/refresh 频繁过滤） | 身份过期校验是硬约束 |
| `token_version` | 列存在 | 保留 | 会话撤销用 |
| 新增 | — | 无 | 不引入新身份属性 |

**状态：部分实施/决策（已完成：代码层移除依赖）**——Rust 代码层已不再读取/写入 identity tenant/domain（claims/header/ctx/ChatScope 已同步，问题 1 修正已落地）；`identity_card.expires_at` 保留并待补索引；列保留/删除仍是 Java 兼容与 schema 决策（本筹划仅作决策，不代表 DDL 已完成）。

### 3.2 user_card — 组织归属唯一承载点

| 项 | v4 | v5 决策 | 理由 |
|----|----|--------|------|
| `tenant_id`/`domain_id` | 允许 NULL | 平台授权卡**必填**；starter 卡保持 NULL（无组织用户） | 组织归属唯一来源；starter 语义保留 |
| `card_type` | PLATFORM_CARD/ORG_CARD/STARTER_CARD | 保持 | 模板/等级已由 template_id/level_id 承载 |
| 索引 | idx_uc_user/domain/tenant 存在 | 保持；补 `(tenant_id, domain_id)` 联合索引 | 租户域映射检查高频 |
| 新增 | — | 无 | — |

**状态：决策**（约束收紧 + 索引；需评估 starter 卡创建路径是否受影响）。

### 3.3 会话/家族 — 语义明确化

| 表 | v5 决策 |
|----|--------|
| `auth_device_session.current_user_card_id` | 明确为"会话绑定的唯一授权卡"；**不引入 identity_card_id 列**（一人一身份卡，由 user_id 隐含） |
| `auth_token_family` | 保持 v4 |
| `auth_session_jti_index` | 保持 v4（Rust migration） |

**状态：决策**（不改 DDL，仅文档明确语义）。

### 3.4 Chat — 会话/成员获得 scope（问题 3）

| 项 | v4 | v5 决策（待定） | 理由 |
|----|----|----------------|------|
| `chat_conversation.tenant_id` | 无 | **新增 `tenant_id` 列（可空或 NOT NULL）** | 证明 conversation 归属 tenant（当前只有 domain_id） |
| `chat_conversation.domain_id` | NOT NULL | 保留；与 tenant_id 一起构成物理 scope | 现有隔离基础 |
| `chat_conversation_member` | uk_conversation_user（用户级） | **保持用户级**（member 按 user_id）；scope 由 conversation.domain/tenant + user_card 资格约束 | Chat 是用户级社交，非卡级；避免成员按卡重复 |
| `chat_message` | domain_id NOT NULL | 保持 | 已 scope |

**状态：待定**——conversation tenant_id 是否必填取决于"同一 domain 是否可多 tenant"；若 domain 天然唯一映射 tenant，可不加列（domain 即 scope）；若多租户共域，必须加。

### 3.5 评估链表 — 收敛租户源

| 表 | v5 决策 |
|----|--------|
| `card_rule_set_ref` / `rule_set` / `rule_set_entry` / `permission_rule` | 评估链**不读**这些表的 tenant_id；租户上下文统一来自 `user_card.tenant_id/domain_id`（配合 `tenant`/`tenant_domain_map` 校验）。表的 tenant_id 保留作管理/审计用途 |
| `authorization_projection_head` | 保持（aggregate 语义 = user_card）；如未来需要按 tenant 投影可加 tenant_id 列（暂不） |
| 运行期物理资格校验（`check_card_active`/`check_card_active_cached`） | 当前语义：identity_card 做归属/ACTIVE/expires_at，user_card 做归属/ACTIVE/有效期/tenant/domain 有效（含 `tenant`/`tenant_domain_map` ACTIVE）；**双卡 tenant/domain 互匹断言已撤销**，不再比对身份侧租户（问题 1 修正）；`check_card_active_cached` 委托 `CardEligibilityService::check_cached`，资格缓存绑定 **ELIGIBILITY head**（`projection_type=ELIGIBILITY`） |
| D1 `CardEligibilityService::verify_platform_card_pair` | **已实现（2026-08-11）**：`astral-db::CardEligibilityService`（`astral-db/src/eligibility.rs`）提供 `verify_platform_card_pair`（login/refresh/switch-card 三处复用）与 `check_cached`（兼容 wrapper `check_card_active_cached[_with_options]`，PolicyEngine/Chat 复用）；权威 SQL 只读 identity 身份事实 + user_card 授权/组织事实，identity 不读 tenant/domain |

**状态：部分实施/决策（已完成：租户源收敛与互匹撤销 + D1 统一资格服务；待实施：资格 fan-out / identity expiry / validity API）**——不改 DDL，明确读取源。

### 3.6 新增/缺失项

| 项 | 现状 | v5 决策（待定） |
|----|------|----------------|
| `platform_user ↔ tenant` 成员关系 | v4 无专门成员表（`tenant_member` 类表？） | 若需"用户属于哪些组织"的独立查询，评估新增成员关系表；否则组织归属仅经 user_card 表达 |
| `tenant_domain_map` | v4 存在（1823 行） | 保持；`check_card_active` 依赖其 ACTIVE 状态 |

---

## 四、v5 链路变化（与 schema 修正联动）

| 环节 | v4 | v5（实施状态） |
|------|----|----------------|
| JWT claims | identityTenantId/identityDomainId + userCard* | **移除 identity 侧租户**；identity 仅 identityCardId（**已完成**） |
| 网关租户拦截 | identityTenantId | **userCardTenantId**（**已完成**） |
| login ① | 读 identity_card.tenant/domain | 只取身份事实；租户来自选中 user_card（**已完成**） |
| refresh/switch | 重读 identity_card.tenant/domain | 不再依赖身份侧租户（**已完成**） |
| `check_card_active` | 双卡 tenant/domain 各自匹配 ctx + 双卡互匹（2026-08-10 收紧） | **撤销互匹断言**（**已完成**）；identity_card 归属/ACTIVE/expires_at + user_card 归属/ACTIVE/有效期/tenant/domain 有效（当前语义） |
| `ChatScope` | 要求 identity_tenant/domain | 去掉 identity 租户字段（**已完成**） |
| D1 `CardEligibilityService::verify_platform_card_pair` | `ic.tenant_id = uc.tenant_id` | 两卡各自校验（归属/状态/有效期/scope）——统一服务**已实现**（`astral-db/src/eligibility.rs`），login/refresh/switch-card 三处复用，switch 签发前补 tenant/domain ACTIVE 校验（修正记录问题 14）；运行期 `check_card_active_cached` 委托 `check_cached`，资格缓存 `perm:card:active` 绑定 **ELIGIBILITY head**（`projection_type=ELIGIBILITY`） |

---

## 五、迁移路径（v4 → v5，专供 Rust）

### Phase A — 代码层去身份租户（无 DDL，v4 上即可做）——**已完成**
1. [已完成] 移除 identity tenant/domain 的 claims/header/ctx/ChatScope 依赖（修正记录问题 1，已同步落地）。
2. [已完成] `check_card_active` 回退双卡 tenant/domain 互匹断言（改为两卡各自校验：identity_card 归属/ACTIVE/expires_at + user_card 归属/ACTIVE/有效期/tenant/domain 有效）。
3. [已完成] D1 `CardEligibilityService::verify_platform_card_pair` 按新语义统一落地（`astral-db/src/eligibility.rs`），login/refresh/switch-card 三处复用，switch 签发前补 tenant/domain ACTIVE 校验（修正记录问题 14）。
> 核实：当前未发现 Rust v3 变更所需的 Java 依赖（静态扫描未见 Java 依赖 identityTenantId/identityDomainId），但最终兼容仍需部署/集成验证，未完全确认；部署库 schema 现状核实见问题 2 前置。

### Phase B — schema 对齐（v5 DDL）——**待实施**
1. [待实施] 发布 v5 增量 migration：identity_card 索引（expires_at）、user_card `(tenant_id, domain_id)` 索引。
2. [待决策/待实施] Chat conversation tenant_id（若 §3.4 决策加）。
3. [待实施] Rust baseline 与 v5 合一（消除问题 2 漂移）。

### Phase B（后续）— 资格事件 fan-out / identity expiry / validity API——**待实施**
1. [待实施] tenant/domain status 变化对 user_card 影响范围的可靠 fan-out（当前依赖运行期 JOIN；CARD/ELIGIBILITY 事件仅覆盖 user_card 自身状态/绑定变更，**未覆盖 tenant/domain status fan-out**，不得写成 ELIGIBILITY 事件已覆盖）。
2. [待实施] identity_card.expires_at/status 正式更新入口与独立 source mutation 事件（当前无 `aggregate_type='IDENTITY'` head/outbox/MQ expiry event；自然到期可读时拒绝，显式变更失效链待设计）。
3. [待实施] user_card.valid_from/valid_until 正式更新 API（现有写入路径为 NULL/读时校验；未来更新必须走 ELIGIBILITY 事件）。

### Phase C — Chat 会话/群组 scoped——**仍待解冻**
Chat scoped 仍处于冻结/待解冻状态；解冻后按修正记录问题 3 执行迁移设计 + 跨租户回归测试。

---

## 六、待决策项（筹划结论）

| 决策点 | 选项 | 建议 |
|--------|------|------|
| identity_card.tenant/domain 列保留 or 删除 | a) 保留标注 DEPRECATED（Java 兼容） b) 删除（纯 Rust 库） | **a**（专供 Rust 但部署库可能仍与 Java 共享） |
| user_card tenant/domain 必填约束 | a) 平台卡必填 b) 全保持可空 | **a**，starter 卡例外 |
| chat_conversation 加 tenant_id | a) 加 b) 不加（domain 即 scope） | **待定**：先核实"domain 是否唯一映射 tenant" |
| platform_user↔tenant 成员关系表 | a) 新增 b) 经 user_card 表达 | **b**（当前无需求）；需求出现再加 |
| Java 同步 | a) Rust 先行 v5 b) 等 Java 对齐 | **a**（专供 Rust） |

---

## 七、后续行动

### 已完成
- [x] Rust 代码层移除 identity tenant/domain 读取/写入（claims/header/ctx/ChatScope 已同步，问题 1 修正）
- [x] `check_card_active`/相关物理资格校验撤销双卡 tenant/domain 互匹断言（identity_card 归属/ACTIVE/expires_at + user_card 归属/ACTIVE/有效期/tenant/domain 有效）
- [x] D1 统一 `CardEligibilityService`（`astral-db/src/eligibility.rs`）：`verify_platform_card_pair` login/refresh/switch-card 三处复用，`check_cached` 供 PolicyEngine/Chat 复用（修正记录问题 14）
- [x] CARD/ELIGIBILITY 双投影通道落地：`astral-types::ProjectionAggregate::Card/Eligibility`，公共事务 helper `astral-db::append_projection_event_in_tx`，TrustGraph 单 worker 按 aggregate 分派（CARD 重建规则快照 + 完整 evict + CARD refresh；ELIGIBILITY 仅 evict `perm:card:active`）
- [x] Identity starter card、user_card create/status 与 TrustGraph user-card status/create/delete/restore/bind、global-admin card status 写路径同事务写 CARD + ELIGIBILITY 事件

### 待实施
- [ ] tenant/domain status 变化对 user_card 影响范围的可信 fan-out（当前依赖运行期 JOIN；**不写成 ELIGIBILITY 事件已覆盖**）
- [ ] identity_card `expires_at` 补索引、user_card `(tenant_id, domain_id)` 联合索引（Phase B v5 增量 migration）
- [ ] Rust baseline 与 v5 schema 合一（消除问题 2 漂移，Phase B）
- [ ] Chat conversation tenant_id 落地（若待决策项确认需要，Phase B）
- [ ] Phase C Chat 会话/群组 scoped 解冻后迁移（当前仍冻结/待解冻）
- [ ] identity_card.expires_at/status 正式更新入口与独立 source mutation 事件（显式变更失效链待设计）
- [ ] user_card.valid_from/valid_until 正式更新 API（未来更新必须走 ELIGIBILITY 事件）

### 待决策
- [ ] 核实部署库 identity_card/user_card 实际 schema（问题 2 前置）
- [ ] 核实 "domain → tenant 是否唯一映射"（决定 chat conversation tenant_id，§3.4）
- [ ] identity_card.tenant/domain 列保留 or 删除（Java 兼容与 schema 决策；本筹划仅作决策，DDL 未实施）
- [ ] 部署/集成层面最终兼容性验证（当前仅静态扫描未见 Java 依赖 identityTenantId/identityDomainId，未完全确认）
