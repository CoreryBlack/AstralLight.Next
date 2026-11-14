# memory-v1 main 基线可继承语义与重新设计边界

> 状态：设计盘点与继承建议，2026-11-14。本文是盘点结论，不是合同：不证明任何语义已采用、不修改规范合同、不开放任何入口。继承项进入正式合同的路径见 §5。
>
> 范围：从 `main` 分支（V6/V7 基线，基线 commit `8582717`）的三层事实源——架构文档、生产代码、DDL（`Docs/sql/full_schema_v4.sql`）——提取对 memory-v1 可直接继承的语义与模式（§2），以及不可继承、需要重新设计的边界（§3）。提取方法：`git show main:<path>`（不切分支）；[Rust权限判定与规则集语义_V1.0.md](../架构/Rust架构设计/Rust权限判定与规则集语义_V1.0.md) 与 main 逐字节一致（diff 为空），其 §2 标注的 CURRENT 事实与 §3/§9 标注的历史语义均已按原文区分。
>
> 总原则：**继承的是语义与模式，不是代码**。main 的 V6/V7 授权读面已按 `memory-v1-retire-legacy-read-20261112`（规范 §15.10 BREAKING CHANGE）从本分支退役；任何继承项都必须以 memory-v1 的类型（`MemoryId`、不透明 content 字节、唯一共享根）重新表达并经 Rust 测试验证。不得引用旧代码、旧证据或旧快照冒充新版授权证明（AGENTS §3.2）。

## 1. main 的两层语义结构（继承判断的前提）

main 的授权语义分两层，继承判断必须分开做：

- **源层（DDL/治理）**：丰富。`permission_rule` 源行含 `effect`（ALLOW/DENY）、`condition_json`、`priority`、`valid_from/valid_to`、`enabled`、对象级 `resource_id`（NULL 表示类型级）与 `source_type`（MANUAL/TEMPLATE/SYSTEM）（`full_schema_v4.sql:1285`）；`user_card` 含 `card_status`、`card_type`（PLATFORM/ORG/STARTER）、`template_id`、`level_id`、`priority`、`is_primary`、`valid_from/valid_until`、`domain_id`（`full_schema_v4.sql:1975`）；审批流 `permission_request` 携带确认状态机（`full_schema_v4.sql:1261`）。
- **热路径（判定）**：有意收窄为 **ALLOW-only 热状态 + 顺序首中（first-match）+ DEFAULT_DENY**。只有 Active+Allow 形态进入热状态；条件在账本边界 fail-closed 拒绝；`priority` 被刻意排除在 grant 裁决身份之外；BASE/OVERLAY 只是 provenance 标签，无运行时层序裁决（`main:astral-types/src/grant.rs:528-546, 815-829`；`main:policy-engine/src/engine/published.rs:474-491, 887-904`）。

这一结构给出的最重要结论：**main 从未在运行时执行过 DENY 规则**——源行可写 DENY，但投影只收 ALLOW，兜底 DEFAULT_DENY。memory-v1 的聚合 deny-wins 是本仓库第一个 DENY 运行时定义，不存在可"恢复"的旧答案（见 §3.2）。

## 2. 可直接继承（语义与模式均适用）

以下各项以合同级表述写入；每项给出 main 证据与 memory-v1 落点。

### 2.1 判定不变式（读侧；第 1、3–5 项已等效实现，第 2 项合同已冻结、实现未完成）

1. **不存在授权回退层**：旧快照、缓存、断路器/降级路径绝不作为授权来源，fallback 恒 DENY（`main:policy-engine/src/engine/published.rs:213-231`、`main:policy-engine/src/engine/formal.rs:514-527`）。memory-v1 已等效实现，合同沿用。
2. **无命中的处理是受控补齐而非直接拒绝**（memory-v1 对 main"无命中即 DEFAULT_DENY"的改写）：无匹配授权时先区分"未加载"与"已证明不存在"——未加载且范围可确定时，由本次请求触发一次有界 MySQL 一致性读取，读取缺失范围的**最新版**事实，在同一 owner 中**增量补全共享根层面的结构**（对象、预建关系、索引与覆盖状态），以新根版本/hash 原子发布；同一请求读者受控进入新读取阶段，废弃旧阶段派生的全部判断，重新读取所有授权依赖并重新评估，最终复核通过才放行。已证明不存在且范围完整才 DENY；不能证明完整或安全合并（冲突、超预算、DB 落后、取消、未知）PENDING/DENY；DB 可能落后于内存，补齐不得覆盖内存事实或复活撤销/删除；已完整的后续请求直接读根、不查 DB（规范 §15.10.3、[请求生命周期与共享根读取设计 §4](请求生命周期与共享根读取设计.md)、[单机唯一共享根设计 §5](单机唯一共享根设计.md)；数据库落后与删除标记的可验证合并协议仍待细化，见[单机唯一共享根设计 §7](单机唯一共享根设计.md)）。实现现状：冷加载为全量装入、根按构造完整，当前无命中即按"已证明不存在"拒绝；服务期根协调器、读者阶段刷新与覆盖证明尚未实现，补齐路径可用之前"未加载"只能 PENDING。
3. **ALLOW 前强制复读，证据漂移即 PENDING**（"stale ALLOW rejected"；Global 目标还二次复读活跃状态）。memory-v1 的最终复核（同一根实例、单调版本、预存 hash、状态、可信时间）是其等效承接，规范 §15.10.3 已冻结。
4. **撤权栅栏**：复核前完成的撤权阻止尚未完成最终检查的旧请求放行；复核通过后发生的撤权不追溯否定本次已通过判断。main 的实现等价物是 evidence 读前读后真读 pointer、零传播窗口（`main:astral-trustgraph/src/repository/global_admin_repository.rs:16-44`）。
5. **读失败/依赖不可用不当作 no-match**（fail-closed；repository 读取失败 ≠ 无授权）。

### 2.2 匹配语义（v1 不启用，登记为 v2 演进预留形态）

6. **资源通配三形态**：对象级 `type:id`、类型级 `type:*` 或裸 `type`、全局 `*`；**类型级请求绝不命中对象级授权**；无前缀/后缀通配（`main:policy-engine/src/engine/published.rs:887-904`、`main:astral-types/src/registry.rs:64-82`）。经 main 生产验证。若 memory-v1 v2 引入通配，直接采用该形态集合与"类型级不命中对象级"规则，并同步其影响面处理：通配授权影响未知 key 集，必须触发受影响范围的完整性重建而非增量修补（`main:policy-engine/src/authorization_compiler.rs:158-159, 461-466`）。
7. **动作别名与全局动作**：`write → {create, update, delete}` 单条别名 + 全局动作 `*`；动作标识符 ascii 小写、匹配严格大小写敏感；动作校验拒绝内嵌 `*`（`main:astral-types/src/registry.rs:22, 174-183`、`main:astral-types/src/org_scope.rs:401-410`）。

### 2.3 输入裁剪决策（v1 直接采用）

8. **条件槽位不存在**：携带条件的授权输入在写入边界 fail-closed 拒绝，评估器不设条件路径（`main:astral-db/src/grant_ledger.rs:317-320`；`condition.rs` 的八个条件评估器在生产求值链不可达）。memory-v1 v1 规则闭集语法（`deny_unknown_fields`）与此一致；合同写明"v1 无条件语义，带条件输入拒绝"。
9. **优先级不参与裁决**：`priority` 只是源行展示与排序属性，被刻意排除在 grant 裁决身份之外（`main:astral-types/src/grant.rs:815-829`）。memory-v1 v1 沿用：不定义优先级语义。

### 2.4 生命周期与撤销（原则级，批次 B 合同蓝本）

10. **撤销双动词分离**：移除授权来源（REMOVE）与撤权（REVOKE）是两类事件，事件号互不交叉；REVOKE 无 canonical payload，语义 hash 锚定被撤销的旧授权内容（`main:astral-trustgraph/src/repository/grant_ledger_adapter.rs:390-391, 926-946`）。
11. **append-only 账本**：授权修订只追加，已有修订永不 `UPDATE`/`DELETE`，tombstone 与状态双向一致性受校验（`main:astral-db/src/grant_repository.rs:1-22, 729, 1028-1036`）。
12. **generation/revoke_fence 不变式**：`revoke_fence ≤ source_generation`；零 fence 是"未发生撤权"的合法初始值；fence 永不超前 generation；每个变更事件携带依赖向量绑定（`main:astral-types/src/grant.rs:189-197`、`main:astral-db/src/projection.rs:184-216, 617-669`）。
13. **审计关联**：operation_id/request_id ≤64 字节全链单点校验；审批审计区分发起请求与审批请求两个 id，均可重试、可去重（`main:astral-db/src/grant_ledger.rs:44-51`、`main:astral-trustgraph/src/repository/audit_log_repository.rs:216-229`）。

### 2.5 确认与治理（状态机级，批次 B 蓝本）

14. **确认状态机 + CAS 确认**：PENDING/APPROVED/REJECTED/CANCELLED；确认动作 `UPDATE … SET status='APPROVED' … WHERE … AND status='PENDING'` 防并发重复确认；确认与生效（插入授权）同一事务（`main:astral-trustgraph/src/repository/permission_request_repository.rs:30-31, 91-93, 795-797`）。
15. **只有已确认贡献可撤销；撤销绝不静默 no-op**（`main:astral-trustgraph/src/repository/permission_request_repository.rs:475-491, 594-597`）。

### 2.6 持久化与发布（模式级，批次 C 蓝本）

16. **同事务五件套**：影响有效授权的源变更在同一短事务内落"源行 + 账本修订 + delta 事件 + outbox + 审计行"；只有 commit 被证明成功才发送；post-commit 单次有界 dispatch，失败保留 outbox 行由 relay 恢复；身份冻结在事务内（`main:astral-trustgraph/src/repository/authorization_source_transaction.rs:1-31`、`main:astral-db/src/grant_ledger.rs:12-18, 685`）。
17. **delta 队列状态机**：PENDING → LEASED → SUCCEEDED，QUARANTINED 为仅运维可回置的终态；独立 worker 唯一消费；发布侧 Conflict/哈希漂移/版本不一致一律 fail-closed，绝不发布、绝不伪造成功（`main:astral-db/src/grant_repository.rs:87-108`、`main:astral-trustgraph/src/service/authorization_projector.rs:1-27`）。
18. **head 串行化与版本推进**：投影 head `FOR UPDATE` 串行化；source_generation 每事件递增，仅 REVOKE 递增撤销 fence（`main:astral-db/src/projection.rs:1-11`）。

## 3. 不可继承、需要重新设计

### 3.1 模型相反或已废除（禁止搬用）

1. **OVERLAY 的位置相反**。main：`rule_set.source_type = TEMPLATE/OVERLAY`，OVERLAY 是规则集的来源类型（`full_schema_v4.sql:1491`）；memory-v1：BASE/OVERLAY 是用户卡与规则集之间的**绑定层**，明确"不在规则集内再造两套结构"（[统一规则集结构设计 §3.1](统一规则集结构设计.md)、规范 §15.10.1）。搬用旧定义即破坏新模型。
2. **domain/level/template 整族已废除**。`user_card` 的 `domain_id/level_id/template_id/priority/is_primary`、`rule_set` 的 TEMPLATE 来源、`identity_level_template*` 表族——规范 §15.10.1 明文"取消独立 domain、等级、卡模板和模板规则"。无继承对象。
3. **标识与编码体系不可映射**。main：i64 自增 + varchar 编码 + datetime + JSON 文本列；memory-v1：16 字节 `MemoryId` + 不透明 content 字节 + 待冻结编码。列形态只能按新版合同重新设计（[数据库结构候选.sql](数据库结构候选.sql)）。
4. **快照表族**。`permission_rule_snapshot`/`rule_set_snapshot` 等 source 快照表被 memory-v1 的规则集四元组版本（version+content+timestamp+hash）替代，不设快照表。
5. **ORG admission/L2 行政授权、cross-city 仲裁、条件评估器、data_scope、上限探针**。与 memory-v1 单进程唯一根模型无关或已超出本次范围（`main:policy-engine/src/org_admission.rs`、`org_compiler.rs`、`cross_city_conflict.rs`、`condition.rs`、`data_scope.rs`），不继承。其"编译器绝不产生授权、PENDING 绝不静默放行"的 fail-closed 精神已由 §2.1 覆盖。

### 3.2 main 也是空白或形态不适用，必须首次定义

6. **DENY 运行时裁决**。main 热路径无 DENY（§1）；memory-v1 的聚合 deny-wins（单规则集任一 DENY 即拒绝；跨绑定聚合，无 first-match、无层序）是首次定义。批次 A 必须将其合同化，并补齐 main 也没有的：多 OVERLAY 冲突、多绑定合并、未知/不支持规则的输入处理。
7. **确认人资格模型**。main 有审批流运行形态与审批权限治理，但审批对象是直接规则；memory-v1 的确认对象是"绑定 → 共享规则集 + 版本"，且共享规则集修改的确认须覆盖既有绑定（[用户双卡租户与规则集设计 §4.2.3](用户双卡租户与规则集设计.md)）。谁有确认权、能否批量确认、确认如何撤销——`AdoptionLimit::ConfirmationAuthority` 指名的缺口，必须重新定义，不能照搬审批对象模型。
8. **初始化/首管建立**。main 的启动种子依赖模板概念（幂等建 `__SUPERADMIN__` 模板 → 按 ResourceRegistry 全量 resource×action 生成 ALLOW 规则 → 建规则集 → 物化进账本，失败即 `SUPERADMIN_INIT_FAILED` 硬失败，`main:astral-trustgraph/src/runtime.rs:1880-2035`）。memory-v1 无模板；须重新设计"超管规则集建立 + 首管用户卡绑定与确认 + 冷加载前完整性验证"流程。可参考的模式仅限：启动期执行、幂等、失败硬失败、按资源注册表全量覆盖。
9. **生命周期状态集的取舍**。main 的六态（Pending/Active/Revoked/Removed/Expired/Archived，`main:astral-types/src/grant.rs:414-424`）与"每身份至多一条 ACTIVE"不变式作用于单 grant 对象；memory-v1 的授权载体是"卡 → 绑定 → 规则集版本"关系族。每类对象（用户卡/绑定/确认/规则集）保留哪些状态、撤销与停用是否分列、有效期落在哪一层，是批次 B 的 schema 决策，不能逐列映射。
10. **同租户多卡**。main 用 `is_primary` + `priority` 表达多卡偏好；memory-v1 明文"不得从本设计推导每用户每租户恰有一张卡"（[用户双卡租户与规则集设计 §4.1](用户双卡租户与规则集设计.md)）。是否引入等价的默认卡/偏好标记待批次 D 决策；`is_primary` 仅作参考。

## 4. 继承项 → 批次落点映射

| 继承项 | 批次 | 承接位置 |
|--------|------|----------|
| §2.1 判定不变式（1、3–5；第 2 项受控补齐待实现，属根协调器） | 已实现/已冻结（补齐随批次 C/根层） | 规范 §15.10.3、[请求生命周期与共享根读取设计](请求生命周期与共享根读取设计.md)、[单机唯一共享根设计](单机唯一共享根设计.md) |
| §2.2 通配/别名（6–7） | A（v2 预留登记） | [权限引擎与规则结构设计](权限引擎与规则结构设计.md) 规则语言合同 |
| §2.3 条件/优先级裁剪（8–9） | A | 同上 |
| §2.4 撤销账本原则（10–12） | B | 生命周期合同 + [数据库结构候选.sql](数据库结构候选.sql) 修订 |
| §2.5 确认状态机（14–15） | B | 确认权合同 + schema 修订 |
| §2.6 持久化模式（16–18） | C | 持久化与恢复合同 |
| §2.4.13 审计关联 | B/C | 各自合同随附 |

## 5. 采用路径与边界

1. 本文档是盘点与继承建议。任何继承项进入正式合同的顺序：批次设计文档（`Docs/memory-v1/` 对应篇正文）→ 规范 §15.10 修订（仅同步合同级变化）→ schema 候选修订 → 实现 → `AdoptionLimit` 对应项退役（每证一族退役一项）。
2. main 引用一律是证据，不移植代码；所有语义以 memory-v1 类型重新表达，并按规范 §15.10.5 的 Rust 测试清单验证（跨租户与双卡、撤权与最终复核、版本不复用、hash 一致性等）。
3. 本文档不改变：正式 listener 仍按 `MemoryV1ProfileNotReady` 拒绝；实验 profile 证据不构成生产采用；旧 V6/V7 代码退役状态不变。
4. 未决事项清单（批次 A/B/C/D 各自的决策入口）以各设计文档 §6/§7 的待决列表为准；本文档不另立清单、不重复登记。
