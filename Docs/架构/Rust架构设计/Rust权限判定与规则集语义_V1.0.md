# Rust 权限判定与规则集语义 V1.0

> 版本：V1.0
> 原始版本日期：2026-08-22；CURRENT V6 现状补记：2026-10-28
> 适用范围：`AstralLight-Rust` 的 `PolicyEngine`、RuleSet source/compiler 输入语义、双卡资格门禁、已发布授权证据读取与冲突检测。
> 文档性质：**非规范性架构设计/证据材料**，记录当前态事实、审计缺口与历史目标决策对照；历史决策不表示仍为当前实现。工程规范与实施约束以 [Docs/规范/](../../规范/) 和仓库根目录 [AGENTS.md](../../../AGENTS.md) 为准。
> 证据口径：CURRENT V6 当前态以 Rust 源码、migration/schema 或已登记审计为依据；本文保留的旧阶段和快照语义仅作历史/迁移证据，不得解释为当前 API 或授权兼容路径。

## 1. 标记、关联文档与术语

本文使用以下标记：

- **事实（CURRENT V6）**：可由当前代码/schema 直接核验的行为。
- **缺口**：按当前 CURRENT V6 调用/数据链复核后仍存在的未闭合边界；旧版中描述的 legacy 阶段缺口不自动沿用。
- **历史/迁移对照**：旧 snapshot、旧 head、staged evaluator 与 raw/realtime 对照路径的历史定义，只用于解释来源和语义演进，不代表当前接口或兼容行为。
- **目标决策（2026-08-22）**：原始设计记录；与 CURRENT V6 冲突的部分明确视为已取代的历史决策，不作当前目标。

关联资料：

- [Rust 权限投影快照与版本栅栏](./Rust权限投影快照与版本栅栏_V1.0.md)：source mutation、projection worker、snapshot/cache/MQ、版本栅栏与审计旁路。
- [技术专题解析与架构取舍（2026-10-25）](../../技术专题解析与架构取舍_2026-10-25.md)：跨主题概览和未验证边界；当前判定语义仍以本文件及源码为准。
- [Rust 架构模型设计修正记录](./Rust架构模型设计修正记录.md)：问题 4（L2 错误与委托）、问题 9/14（资格投影）等核实记录。
- [物理双卡权限链路评估与设计](./物理双卡权限链路评估与设计_V1.0.md)：双卡事实线路、CARD gate、ELIGIBILITY gate 与残余边界。
- [Rust 迁移 Java 等价适配状态](../../迁移/Rust迁移Java等价适配状态_2026-08-05.md)：L2 exact-first、投影 gate、条件语义和未完成项。
- 规则模式权限体系设计：规则模式历史/模型基线；其中的建议条款不自动等于当前 Rust 事实。
- [Rust 后端编码规范](../../规范/Rust后端编码规范_V1.0.md)：PolicyEngine 与 `astral-db` 的 owner 边界。
- Structurizr 授权决策链路
- Structurizr 权限投影链路
- 授权决策排查图

CURRENT V6 术语与读门边界：

- **CARD / ELIGIBILITY**：旧 CARD projection/read-gate 为历史/迁移语义；ELIGIBILITY 是独立物理资格检查/缓存失效语义，不替代规则授权证据，也不因 V6 改写成 CARD 规则 snapshot。
- **RuleSet source/compiler input**：`rule_set`、`rule_set_entry` 与绑定描述规则语言来源；OVERLAY/BASE、ref/entry 匹配语义是 compiler/admission 解释输入 provenance 的语义，不表示生产 reader 逐层查询旧 snapshot。
- **canonical published evidence**：普通卡正式授权由 CURRENT V6 grant revision/delta，经唯一 WorkerOwned projector 发布 manifest/segment/current，再由 strict reader 消费 `effective_grants`；缺少完整 scope、generation、lineage、seal 或 revoke-fence 证明，只能 PENDING/DENY。
- **ALLOW-only grant 合同**：授权账本只持久化正授权贡献；普通 DENY 不作为 ALLOW grant，撤销由 tombstone/fence 表达。RULE_SET 贡献保留 BASE/OVERLAY provenance；DELEGATION contribution 的 layer 为 None。此数据语义不是旧 L1/L2/L2.5 运行阶段。
- **旧 L1/L2/L2.5、marker dispatch 与 raw/realtime evaluator**：仅为历史文档/迁移对照词汇，不是当前 `PolicyEngine` API、生产路由、test compatibility API 或 fallback。

## 2. 当前判定总链路（CURRENT V6）

**事实**：正式授权唯一入口 `PolicyEngine::evaluate()` 在 AUTHN/CARD_CONTEXT 与 resource/action/ownership 校验后，经 `RuleRepository` 的四个无默认实现 required ports 进入 CURRENT V6 published-evidence strict gate。四个 ports 为 `check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`；不存在 capability marker dispatch、legacy evaluator 或 L1/L2/L2.5 阶段。有效 ALLOW 前复读证据，任何缺失、错误、scope 不符或证明漂移均 PENDING/DENY。接口证据：[`engine/ports.rs`](../../../policy-engine/src/engine/ports.rs)、[`engine/formal.rs`](../../../policy-engine/src/engine/formal.rs)、[`engine/published.rs`](../../../policy-engine/src/engine/published.rs)。

### 2.1 入口与双卡资格

**事实**：`PolicyEngine::evaluate()` 先进行 AUTHN、card context、resource/action 与适用的 ownership 检查，再通过 required ports 读取 CURRENT V6 published evidence。真实 `PLATFORM_USER` 的物理双卡资格由 `astral-db::CardEligibilityService` 负责；`identity_card` 只证明身份，`user_card` 承载授权/组织事实。入口和资格服务证据：[`policy-engine/src/engine/formal.rs`](../../../policy-engine/src/engine/formal.rs)、[`astral-db/src/eligibility.rs`](../../../astral-db/src/eligibility.rs)。

**事实**：资格服务的权威 JOIN 将 identity_card 作为身份事实，将 user_card 作为授权/组织事实，并要求两卡通过同一 user_id 对齐；identity_card 不参与 tenant/domain 比较。见 [`astral-db/src/eligibility.rs:80-153`](../../../astral-db/src/eligibility.rs#L80-L153)、[`eligibility.rs:235-276`](../../../astral-db/src/eligibility.rs#L235-L276)。

**事实**：物理资格读侧独立于 canonical 规则授权 evidence，使用双卡上下文、strict authority checks 和有界进程内 qualification cache；失配/异常回到权威 SQL 或安全拒绝。该资格 cache 不是规则授权证明。细节以 [`astral-db/src/eligibility.rs`](../../../astral-db/src/eligibility.rs) 当前实现为准。

### 2.2 CURRENT V6 published-evidence strict gate

普通卡授权通过 `load_published_card_authorization` 读取 canonical evidence，以 ALLOW-only `effective_grants` 匹配。current pointer、manifest/segment seal、scope、lineage、generation/dependency 与 `revoke_fence_proven` 任一证明不足、读取失败或最终证据复读漂移，都只能 `AUTHORIZATION_PENDING`/DENY；不读取旧 snapshot，不查询 raw source，也不回退 cache。证据：[`engine/published.rs`](../../../policy-engine/src/engine/published.rs)、[`astral-db/src/authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs)。

### 2.3 历史 staged 规则语言与历史 evaluator（非当前接口）

下文关于 OVERLAY/BASE、ref/entry 顺序、wildcard/alias 和 winner 语义，描述 RuleSet source/compiler input 的语言含义及历史规则模型。旧 L1/L2/L2.5 执行顺序、CARD gate、snapshot winner reader、raw/realtime evaluator 和 marker-selected dispatch 只作为历史/迁移证据保留；它们不是当前 `RuleRepository` 接口、兼容 repository 路径或生产 read route。不得将旧 gate/recheck 的历史测试或源码当作 CURRENT V6 的授权实现证明。

## 3. RuleSet 当前语义

### 3.1 数据与读取 owner

**事实**：`rule_set`、`rule_set_entry` 和 `card_rule_set_ref` 是 RuleSet 完整 source 模型；`rule_set_snapshot` 只属于 legacy/迁移对照读模型，不是生产授权来源。canonical projector 将经验证的 RuleSet grant contribution 编译到 ledger，再通过 manifest/segment/current 发布证据；生产 reader 只通过 `load_published_card_authorization` 消费已发布证据。规范字段与读模型合同见 [Rust 后端编码规范 §15.7](../../规范/Rust后端编码规范_V1.0.md#157-规则集完整结构与轻量发布栅栏标准2026-10-28)，代码入口见 [`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs) 与 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs)。

旧 `load_rule_set_snapshots`、`load_snapshot_winners` 等方法名及旧读模型只可作为历史源码/迁移证据；CURRENT V6 的 `RuleRepository` 是四个 required ports，不提供 snapshot reader compatibility dispatch。生产读侧验证 current pointer 指向的 manifest/segment 链、scope、lineage、generation、摘要/seal 与 `revoke_fence_proven`。

### 3.2 跨层顺序：OVERLAY 先于 BASE（规则语言语义）

**规则语言事实**：`OVERLAY > BASE` 描述 RuleSet contribution 的 provenance/层级语义，compiler/admission 按完整规则集合同解释其 effect、priority 和来源；这不是 production reader 逐层遍历旧 refs 的执行阶段。正式 reader 只消费 compiler/projector 证明的 CURRENT V6 `effective_grants`，并通过 published evidence gate 后做 allow-only 匹配。CURRENT V6 具体规则集 source/read-view 语义见 [规范 §15.7](../../规范/Rust后端编码规范_V1.0.md#157-规则集完整结构与轻量发布栅栏标准2026-10-28)。

以下旧 staged first-match 图只保留为历史 RuleSet evaluator 证据，不是当前调用链：

```text
[历史] OVERLAY refs -> first match -> BASE refs -> L2 -> L2.5 -> DEFAULT_DENY
```

### 3.3 层内顺序：ref first-match-wins

**历史语义**：旧 evaluator 按 repository 返回顺序遍历每层 refs，单个 ref 命中即返回。此内容用于解释历史行为；不推断该 first-match 算法当前由 compiler 或 production reader 实现。CURRENT V6 生产语义以规范 §15.7 的完整 RuleSet contract、compiler/admission 实现与 published evidence 为准。旧 `match_layer_first_match` 源码如仍可定位，只作为历史证据，不是当前 API。

**历史 evaluator 语义**：旧 snapshot reader 使用 exact、forward/reverse wildcard 与 action alias 匹配；旧 `RuleSetSnapshot.entries` raw scan 按 priority/effect 顺序单 pass。此处保留用于历史语义追溯，不是 CURRENT V6 `PolicyEngine` 路径或规范化的 current matching contract；不能从旧源码结构推断新 compiler/admission 的实现细节。

### 3.4 winner 语义与 canonical 编译边界

CURRENT V6 的规则集 source/read-view、command validation 与 publication identity 以 [Rust 后端编码规范 §15.7](../../规范/Rust后端编码规范_V1.0.md#157-规则集完整结构与轻量发布栅栏标准2026-10-28) 为准。`AuthorizationCompiler` 对已验证 typed grants 构造 ALLOW-only candidate，`AuthorizationProjector` 将其发布为 manifest/segment/current durable evidence；旧 `ProjectionWorker` 的 snapshot winner 重建、旧 `MAX(version_no)`/`projection_generation`/head gate 只作为 legacy/迁移历史。旧 snapshot 的 `valid_from/valid_to` 写入缺口不等同于 CURRENT V6 strict reader、matcher 与 evidence L1 的 grant-time validity 检查；后者的自然到期也不自动产生 source mutation、delta 或 generation 推进。详见 [`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs)、[`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs)、[`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs)、[`published.rs`](../../../policy-engine/src/engine/published.rs) 与 [`evidence_cache.rs`](../../../astral-db/src/evidence_cache.rs)。

旧 equal-priority `entry_id` tie-break 是历史 winner 编译规则记录，不单独定义 CURRENT V6 的 grant matching contract；source/read view 中的优先级、entry identity 与 canonical publication stamp 依规范和当前 compiler/admission 实现核对。

## 4. 旧快照历史证据与 CURRENT V6 生产来源

### 4.1 语义与生产数据来源

| 维度 | `permission_rule_snapshot`（历史） | `rule_set_snapshot`（历史） | CURRENT V6 published evidence |
|------|----------------------------|---------------------|-------------------------------|
| 历史逻辑来源 | 卡级 `permission_rule` | `rule_set_entry` + `rule_set` | grant revision ledger + typed delta |
| 历史绑定粒度 | `card_id` | `rule_set_id` 经绑定关系使用 | card/tenant scope 由 current/manifest 证明 |
| 当前生产消费者 | 无；仅迁移/历史证据 | 无；仅迁移/历史证据 | `SqlxRuleRepository` → `load_published_card_authorization` |
| 历史版本选择 | 旧表 `MAX(version_no)` | 旧表 `MAX(version_no)` | current pointer → manifest/segment seal + generation/lineage/fence |
| source fallback | 旧历史路径；不是当前 API | 旧历史路径；不是当前 API | 无 source/snapshot/cache fallback |
| 未证明行为 | 当前 formal reader 不消费该表 | 当前 formal reader 不消费该表 | 任一 V6 proof 不足 → PENDING/DENY |

旧快照表结构、迁移和代码仅作为历史/迁移证据核验，不能将它们称为生产授权来源或兼容 evaluator。

### 4.2 历史 snapshot 行匹配语义

以下为旧 L2 evaluator 对 `permission_rule_snapshot` / source-rule 行的区分及 exact-first、priority 单 pass 规则，仅供历史行为追溯；CURRENT V6 formal reader 不读取这些行。旧 snapshot 为空也不能作为当前“空授权”证明，正式读门只能由 current/manifest/segment V6 proof 决定。

### 4.3 旧快照 schema 与 migration 历史

以下 schema、唯一键、`version_no`、旧 `projection_generation`、`MAX(version_no)` 和 validity-window migration 只描述 legacy snapshot 的历史结构与部署差异。它们不属于 CURRENT V6 production read gate，不定义当前兼容 API，也不证明任一部署库已应用迁移或完成清理。`20260827000002_legacy_snapshot_tables_decommission.sql` 的存在亦不证明表已 DROP；环境 postcondition 必须独立取证。canonical 授权当前只以 CURRENT V6 manifest/segment/current proof 为准。

## 5. 历史 staged error 行为与 CURRENT V6 source ownership

### 5.1 历史 L2/L2.5 repository-error 行为

旧 evaluator 对 `permission_rule_snapshot` 读取失败会 fail-closed，旧阶段不将错误当成 no-match 再进入委托；旧委托读侧依赖 CARD generation 证明，raw/source reader 与 realtime 路径均为历史实现。该段保留供审计历史错误处理，不是 CURRENT V6 production 或 compatibility API 的调用链。

### 5.2 当前 source ownership 与授权贡献

CURRENT V6 授权贡献使用封闭的 typed `GrantSourceKind`：`RULE_SET` 的 contribution 必须带 `BASE` 或 `OVERLAY` binding layer；`DIRECT`、`DELEGATION`、`APPROVAL`、`SYSTEM` 均为 `NONE`。普通 direct permission-rule 新增只接受 enabled `MANUAL`；旧 `CARD_ONLY` 仅可读/删除，不能自动改写。`SYSTEM` 当前 reserved-unused，没有生产 append path；不得描述成已经承载 migration/backfill。详见 [`astral-types/src/grant.rs`](../../../astral-types/src/grant.rs) 和 [CURRENT V6 规范 §15.8](../../规范/Rust后端编码规范_V1.0.md#158-current-v6-breaking-change-inventory-与-adoption-notice)。

`source_type` 的旧数据库字段和旧 evaluator source filters 不能代表 typed source ownership；RuleSet/direct/delegation/approval 的 grant mutation 由各自 source owner 同事务记录 grant revision/delta 与 audit correlation，再由唯一 projector 物化。direct mutation 的 `MANUAL` gate 由 `RuleWriteService` 强制，delegation contribution 由 delegation owner 同事务维护，RuleSet 与 approval 使用各自 typed append path。SoD 限制另见 §7.3。规则自然时间窗由 reader/matcher 的读时有效期判定和 L1 时钟复验处理，但不会自动触发 source delta 或 publication-generation advance。


## 6. 其他非授权用途与历史路径

### 6.1 历史 realtime/raw-source evaluator

旧版本曾记录 `evaluate_realtime()` 读取 raw `rule_set_entry`/`permission_rule` 的一致性比较路径。CURRENT V6 已将 capability marker、raw/realtime evaluator 及其 read API 从当前正式/兼容授权合同中移除；历史源码链接仅用于回溯，不能称其为当前诊断 API，也不能让它成为生产 ALLOW 的旁路。

### 6.2 Arbiter 与模拟用途

CURRENT V6 规范明确正式调用链不含 Arbiter/oracle 决策阶段，且当前 checkout 已移除旧 Arbiter kernel/service/API 源文件。若将来另行批准非授权诊断/模拟功能，须以新的 owner、caller trust 和 API/source contract 单独设计；旧路线记录及文件名不证明该 runtime feature 仍存在。任何模拟结果都不能作为正式请求 ALLOW 输入。

## 7. 当前合同与待验证边界

> 本节记录的真实验证缺口仅指本任务未执行或尚无证据的 MySQL/MQ/部署场景；不得从下方历史 §9 复用已取代的 legacy/realtime/cache TODO。

### 7.1 CURRENT V6 strict gate

正式读门经 `load_published_card_authorization` 消费 current pointer 指向的 CURRENT V6 manifest/segment 完整证明，校验 scope、摘要/seal、lineage、generation/dependency 与 `revoke_fence_proven`，并在 ALLOW 前复读；任一缺失、错误或漂移都保持 PENDING/DENY。来源见 [`policy-engine/src/engine/published.rs`](../../../policy-engine/src/engine/published.rs)、[`astral-db/src/authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs) 与 [`astral-trustgraph/src/service/authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs)。

### 7.2 独立 qualification 与 time-window 边界

ELIGIBILITY qualification 是身份卡/用户卡事实校验与独立资格缓存失效语义，不等同旧 CARD rule gate，也不替代 CURRENT V6 published authorization evidence。规则 grant 的 `not_before`/`expires_at` 按每次 strict read 的统一 UTC now 分类，未生效或已到期 contribution 不进入 `effective_grants`；formal matcher 也在评估时复核 validity，evidence L1 命中前按当前时钟重验窗口，翻转即 miss 回 strict reader。自然到期不产生 source mutation、delta 或 publication-generation advance，因此不自动推进 projection/audit lifecycle；若需独立 expiry event 或代际推进须另立合同。旧 snapshot validity migration 不证明此类 scheduler/event 已实现。代码入口：[`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L4682-L4769)、[`published.rs`](../../../policy-engine/src/engine/published.rs#L640-L705)、[`evidence_cache.rs`](../../../astral-db/src/evidence_cache.rs#L34-L43)。

### 7.3 Grant-time SoD

enabled `MANUAL` 直接授权 create/update 在 source transaction 内无条件执行 `astral_db::check_grant_sod_conflict_in_tx`；CREATE 另保留 service 层显式注入的 early validator。锁定卡与 source-rule/card tenant、user/domain 必须一致，未完成卡级/NULL-card aggregate-wide 贡献、缺失证据、策略读取失败或超时均阻止写入。UPDATE 只有在完整锁定 before-image 对应唯一 exact published grant 时，才能从 STATIC held grants 排除该项稳定 `GrantId`，其他 grant 与 DYNAMIC 检查仍执行。事务有界读取与完整身份/内容/provenance 证明以 [Rust 后端编码规范 §15.4](../../规范/Rust后端编码规范_V1.0.md#154-单机内存读写生命周期sod-与审计边界) 为准。代码入口：[`rule_write_service.rs`](../../../astral-trustgraph/src/service/rule_write_service.rs)、[`rule_repository.rs`](../../../astral-trustgraph/src/repository/rule_repository.rs)、[`sod_check.rs`](../../../astral-db/src/sod_check.rs)。

此交易内锁序/并发路径目前只具源码证据；真实 MySQL 下的锁冲突、并发事务与 deadlock/恢复语义尚未执行验证，不得声称已验收。

### 7.4 source/贡献边界

CURRENT V6 typed `GrantSourceKind` 闭集及 `BindingLayer` 约束见 §5.2；它替代旧数据库 `source_type` 字段被当作全局 owner registry 的描述。`SYSTEM` reserved-unused，backfill writer 与实际恢复过程仍不是已证明行为。

## 8. 五链审查边界

### 8.1 调用链

**事实**：CURRENT V6 formal authorization is `PolicyEngine::evaluate()` → four required ports → published-evidence strict gate → ALLOW-only matcher; no staged, marker-selected, raw/realtime or snapshot evaluator is a current branch. Source mutation reaches the unique WorkerOwned projector through committed immutable receipts.

**结论**：保持一个正式授权入口；旧快照、管理模拟与历史 evaluator 不构成生产 fallback。

### 8.2 逻辑链

**事实**：RuleSet source/provenance 与 `GrantSourceKind` / `BindingLayer` 约束、完整 compiler/admission bundle 依 CURRENT V6 规范；published reader 不逐层读取旧 refs，任何 proof 不足或 final reread drift 都不能 ALLOW。

**结论**：版本、来源或绑定变化须保持 proof-before-ALLOW；旧 snapshot/head READY、`MAX(version_no)` 或旧 staged match 不能替代 canonical 证据。

### 8.3 事故链

**事实**：canonical current/manifest/segment 读取失败、scope/lineage/fence/hash 证明不足、projector lease/CAS UNKNOWN 或 archive proof 未完成，都保持 PENDING/DENY 或进入 bounded Blocked/Quarantine/Unknown；不会回退旧 snapshot/source/cache。source-side SoD recheck 遇到 unpublished contribution、缺失 evidence、policy read error 或 transaction deadline 亦拒绝写入。

**结论**：代码路径不等于组合故障或真实部署验收；不能用 typed/mock 测试、静态形状或历史 worker 状态宣布生产集成通过。SoD 真实 MySQL 并发/锁序仍未验证。

### 8.4 数据链

**事实**：canonical 数据链是 grant revision → typed delta + immutable receipt → WorkerOwned projector → manifest/segment/current → published evidence；ELIGIBILITY qualification/cache invalidation 独立，不替代 canonical 授权证据。旧 snapshot/head 和 raw evaluator 只作历史/迁移材料。

**结论**：未来调整须同步 ledger、delta/receipt、manifest/segment seal、lineage/fence、四个 required reader ports、invalidation consumer、SoD published-only evidence 与适用的 migration/backfill 证据；不增加 realtime/raw-source 授权旁路。

### 8.5 审计链

**事实**：source mutation 的 audit correlation 与 grant revision/delta 在 source transaction 内关联；projector publication/archive proof 有独立 durable proof。权限审计旁路与授权判断/发布完成不是同一状态；审计消息/消费完成不能代替 projection proof。

**结论**：授权变更、SoD 拒绝或证据不足须沿对应稳定 operation/message/source identity 可关联；真实审计传输、恢复与部署验收需另取证，本文不声称已通过。

## 9. 历史目标决策（2026-08-22；冲突部分已由 CURRENT V6 取代）

> 本节保留原始决策记录，不是当前路线、API 或实现说明。旧 staged evaluator、L1/L2/L2.5、snapshot CAS/head、realtime/raw-source 和 marker/capability 相关内容仅用于历史追溯；CURRENT V6 事实见 §2–§8 与规范 §15.7–§15.8。

### 9.1 决策：保持 staged first-match

**目标决策**：保留并正式记录当前 RuleSet 的 staged first-match 语义：

```text
OVERLAY refs（按稳定 ref 顺序逐个 first-match）
  -> 若无命中，BASE refs（按稳定 ref 顺序逐个 first-match）
  -> 若无命中，进入 permission_rule_snapshot L2
  -> 若无命中，进入 delegation L2.5
  -> DEFAULT_DENY
```

“staged”表示跨层先后是阶段边界；“first-match”表示层内 ref 与单 ref 匹配顺序的首个有效命中决定效果。该决策不把当前 SQL 返回顺序的不确定性当作稳定排序合同；ref/entry tie-break 仍须在实施时补齐。

### 9.2 决策：当前行 + CAS `version_no`

**目标决策**：RuleSet snapshot 与 permission_rule_snapshot 的长期实现采用“当前行 + CAS `version_no`”写入合同，并与独立 durable aggregate head 对齐：

- 当前逻辑 key 在当前版本内必须唯一；
- writer 以已读 `version_no` 做 CAS，冲突不覆盖新版本；
- 读侧以 aggregate head 证明版本，不单独以 `MAX(version_no)` 证明跨模型一致；
- 删除旧快照不能使 durable version barrier 回到 0；
- version reset、重复逻辑 key、source mutation 与 snapshot 重建不在同一可证明事务内时，读侧进入 PENDING/安全 miss。

这是目标数据/版本合同，不声称当前 Rust migration 已具备完整实现。

### 9.3 决策：Arbiter 仍是冲突检测器

**目标决策**：Arbiter 保持冲突检测器/证据裁决器定位，不成为第四个日常授权阶段，不覆盖 L1/L2/L2.5 的 staged first-match 结果，也不绕过 projection gate。版本不可证明时保持 DEFER/PENDING；只有 READY 版本之间出现可区分分歧才生成冲突信号。

### 9.4 决策：来源 owner 显式化

**目标决策**：未来为每个 source type 建立显式 owner 矩阵，至少记录：source table、写入 owner、投影 aggregate、snapshot target、读侧阶段、撤销/fence 语义、审计事件和补偿入口。此项用于解决 §7.5 ownership gap，当前各局部路径的 source_type 字段不能被视为该矩阵已经存在。

### 9.5 历史决策：L2 错误在 L2.5 前 fail-closed

原始决策记录：旧 L2 repository error 在进入 L2.5 delegation 前 fail-closed，只有明确 NoMatch 才能继续旧阶段。此旧行为不构成当前 evaluator implementation；CURRENT V6 不存在这些阶段。

### 9.6 历史决策：L1/L2/L2.5 阶段标签与 ALLOW-only 账本（2026-08-26）

本条保留 2026-08-26 对 ALLOW-only grant、tombstone/fence 与 BASE/OVERLAY provenance 的历史设计记录；其中把 L1/L2/L2.5 作为当前或 compatibility 阶段，以及 capability marker dispatch、旧 reader/cache migration 状态等描述，均已由 CURRENT V6 取代。当前 grant/source schema、four-port strict reader、WorkerOwned receipt 与 V6 wire/edition 只以 §2–§8 和规范 §15.7–§15.8 为准。历史文本所提 MySQL/backfill/deployment/integration 状态不得推断为已验收或当前待办结论。

## 10. CURRENT V6 文档边界核对

- **当前/历史区分**：CURRENT V6 formal chain、four required ports、WorkerOwned receipts 和 V6 published gate 位于 §2–§8；旧 evaluator/staged/snapshot 词汇显式标为历史。
- **时间边界**：strict reader、matcher 与 bounded L1 对 grant validity window 执行读时/命中时判定；自然时间窗到期不产生 source mutation、delta 或 publication-generation advance。
- **RuleSet source/compiler 区分**：完整 source/read view 与 BASE/OVERLAY provenance 不被写成旧 L1 阶段或旧 snapshot runtime reader；字段与公开合同引用规范 §15.7。
- **SoD**：mandatory early published-only validator 与 source-transaction unconditional recheck 分开说明；明确真实 MySQL 并发/锁序未执行验收。
- **迁移/运行边界**：历史 snapshot/migration 不证明 DROP、backfill、rehearsal、部署或运行时验收；真实 MySQL/MQ 与切流状态必须独立取证。
- **安全与链接**：不含绝对文件 URI、服务器 IP、密码、Token 或密钥；新增源码/规范引用使用仓库相对链接。
