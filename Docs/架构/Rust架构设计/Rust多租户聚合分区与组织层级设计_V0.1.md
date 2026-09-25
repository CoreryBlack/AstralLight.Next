# Rust 多租户聚合分区与组织层级设计（V0.1）

> 状态：**已批准执行（2026-09-21）**。Q1–Q5 按本稿默认立场拍板，开发窗口覆盖 M1+M2+M3 完整计划。本文档是目标设计记录；任何实现仍须走 AGENTS.md 的 Exec 分层、五链审查、验证门禁与迁移验收。
> 基线：Rust workspace 实现快照；本设计文档不携带历史运行记录。
> 决策记录：Q1=保留 tenant allowlist 信任边界、allowlist 内账本发现分区；Q2=并行 worker 默认 4、上限可配、启动时按池预算守卫；Q3=OVERLAY 仅在已获范围内新增/显式窄化，歧义一律 PENDING（2026-09-22 补充见 §4、§7）；Q5=断路器分区维度五链评审在 M1 实现前完成。
> 初次修订（2026-09-22）：Phase 2 主方案改为共享单元卡；组织规则更新按受影响单元编译，避免按成员展开。现有“一人多卡”不等于“一卡多人”，共享卡与成员资格是待实现的新合同。
> 用户决策补充（2026-09-22）：集团、子公司、部门各有独立 `tenant_id`；非独立行政单位的授权必须来自本行政祖先树，下级向上级申请且不得超出已获范围。行政独立、仅有资金等关系的子公司以自身为授权树根。采纳精确来源剪裁、共同资格约束、旧剪裁不得因 revision 更新静默失效、调岗先撤旧再启新的建议。§4 为据此细化的目标合同，§7 区分用户决策与工程默认方案。
> 关联：审查待办问题清单 §2.2-1（~898s 排水缺口）；[Rust权限投影快照与版本栅栏_V1.0.md](./Rust权限投影快照与版本栅栏_V1.0.md)；[Rust增量重建与实时授权边界_V1.0.md](./Rust增量重建与实时授权边界_V1.0.md)；[FactoredHotState设计_V1.0.md](./FactoredHotState设计_V1.0.md)。
> 阅读约定：§2 描述重设计前基线，§4 记录目标合同与验收要求，§6 单列已有实现与证据边界。当前工作区已包含 default-off 的 ORG_SCOPE source slice（含 projector runtime wiring）；真实迁移、service startup、端到端集成和部署验收仍未执行。代码事实以 source/schema/tests 为准。

## 0. 结论摘要

重设计前基线把租户当作**扁平作用域标签 + 运维配置清单**：`tenant_id` 是授权表的隔离过滤列，平台目录的父子关系不承担授权合同；投影 worker 由静态租户清单驱动串行消费。§6 已记录后续分区实现，以下两阶段分别处理发布工程与授权语义：

- **Phase 1（不改授权语义）**：发布面改为账本发现的聚合分区、分区租约和并行 worker。分区 = `(tenant_id, aggregate_type, aggregate_id)`，每分区串行、跨分区并行；降低 B1 的串行竞争和 B5 的空轮询成本。静态 tenant allowlist 仍保留，新增租户的部署配置边界（B6）不会自动消失。
- **Phase 2（default-off 语义扩展）**：集团/子公司/部门各自隔离为独立 tenant，以受治理的行政祖先树逐级申请和下发权限；行政独立单位建立自己的授权树。每级在已获批 BASE 上应用受限 OVERLAY，经贡献 HAMT 增量编译为共享单元证据。决策端不遍历组织关系；成员资格、跨 tenant provenance 和 union 的共同前提是显式新合同。

不做：决策时关系遍历（ReBAC 化）、Zanzibar 式一致性机器、跨城部署拓扑变更（每城独立 L2/L3 不变）。

## 1. 目标与非目标

### 1.1 目标

| ID | 目标 | 度量 |
|----|------|------|
| G1 | 降低串行调度和空租户轮询开销 | 在固定总负载/连接池预算下，分别测租户数、活跃分区数对 drain 吞吐与公平性的影响 |
| G2 | 行政层级成为受治理的一等授权聚合 | 跨 tenant 批准、成员资格、祖先撤销及独立/移树走完整 durable 路径并通过验收 |
| G3 | 聚合级故障隔离 | 分区维度断路器/缓存配额；共同依赖故障按真实影响范围阻断，局部错误不污染无关租户 |
| G4 | 唯一授权入口、旧路径兼容、决策时零组织遍历 | `PolicyEngine.evaluate()` 保留；新 evidence/provenance 合同显式演进，功能关闭时旧 typed 测试保持 |
| G5 | 失败默认不扩大权限 | 未批准、越界、未知祖先/资格、歧义或世代不一致均 PENDING/DENY |

### 1.2 非目标

- N1：决策时关系遍历/图查询（不做运行时 ReBAC）。
- N2：Zanzibar 式跨租户一致性机器（2026-09-10 已决策免做）。
- N3：跨城拓扑变更：每城独立 L2/L3 部署边界不动，本设计只作用于单部署内部。
- N4：本设计聚焦授权语义、租户隔离和分区运行时，不涉及对外发布或研究范围声明。

## 2. 现状与差距（代码事实）

### 2.1 瓶颈清单（B1–B6）

| ID | 瓶颈 | 证据 |
|----|------|------|
| B1 | 发布面单 worker 串行：每 5s 一个周期顺序遍历全部租户、每租户每周期 ≤8 事件、逐条 `LIMIT 1 FOR UPDATE` 认领后走完整发布事务；吞吐随租户数被摊薄 | `authorization_projector.rs:114`（`POLL_INTERVAL_SECS`）、`:131`（`MAX_EVENTS_PER_TENANT_PER_CYCLE`）、`:805-858`（tick 循环 + 逐租户逐事件） |
| B2 | 服务连接池全租户共享（默认 80，MySQL 服务端 151 预算） | `astral-db/src/lib.rs:133-156` |
| B3 | evidence 缓存为进程内全局 LRU（10 万条、L1 TTL 30s / L2 TTL 300s），无租户/聚合配额，热冷租户互相驱逐 | `astral-db/src/evidence_cache.rs:36-74,140-146` |
| B4 | 断路器键 = resource（+`__global__`），不含租户/聚合维度：一个租户的硬错误风暴（含 `published_card_evidence_corrupt` 类非 business-pending 错误）达阈值后该资源对全部租户 deny | `policy-engine/src/engine.rs:2339-2420`（`check_circuit_breaker`/`record_failure_on_evaluate`） |
| B5 | claim 查询每事件一次 `NOT EXISTS` 相关子查询 + `FOR UPDATE`；空轮询也要 O(租户数) 次查询/周期 | `astral-db/src/grant_repository.rs:1466-1507` |
| B6 | 租户清单是静态启动配置，扩租户需改配置重启 worker 代；空配置 fail-closed 拒绝启动 | `authorization_projector.rs:569-596`（`parse_projector_tenants`）、`:634-638` |
| B7 | 898s 同聚合排水尾部：单 pointer 串行化下竞争败者烧尽 5 次 attempt 预算 → 900s 最大退避 | 待办清单 §2.2-1；`MAX_EVENT_ATTEMPTS:122`、`BACKOFF_CAP_SECS:124`、`MAX_POINTER_MOVED_REPLANS:127`（replan 已缓解但风暴下仍会耗尽） |

### 2.2 已具备的基础（重设计的支点）

- **聚合粒度已预留**：pointer/manifest/delta 的 CAS 键含 `aggregate_type`（`authorization_projection_repository.rs:3603-3615`）——新增聚合类型是演进不是推翻。
- **版本序门按 `(tenant_id, grant_id)`**：不同 grant/不同卡天然无队头阻塞（`grant_repository.rs:1481-1485`）。
- **租约体系成熟**：delta 事件租约（`extend_delta_event_lease`，不改 attempts/cas_version）、F5 看门狗按代重启、旧代租约到期自动 reclaim。
- **组织目录已有世系**：`tenant.parent_tenant_id/path/depth/tenant_type`（`tenant_repository.rs:117-140,387`）——缺的不是数据，是把世系纳入授权合同。
- **eval 的 domain 只是精确相等标签**：`grant.tenant.domain_id != ctx.domain_id → false`（`engine.rs:2546-2548`）；没有继承语义可依赖，也不需要破坏它。

## 3. Phase 1：聚合分区发布面（纯工程）

### 3.1 分区定义

```
partition := (tenant_id, aggregate_type, aggregate_id)
```

每分区内事件**串行**（pointer CAS 本就强制同聚合发布串行；版本序门在分区内继续生效），跨分区**并行**。CARD 聚合即现有 `(tenant, 'CARD', card_id)`；Phase 2 增加 `'ORG_SCOPE'` 类型，Phase 1 不引入新类型。

### 3.2 分区发现（替代静态租户驱动）

- **tenant allowlist 保留为部署信任边界**（决策默认值，见 Q1）：`parse_projector_tenants` 语义不变——部署只消费 allowlist 内租户的事件，空 allowlist 仍 fail-closed 拒绝启动。理由：租户是部署级信任/合规边界（与每城独立部署一致），不应由账本内容自动扩大。
- **allowlist 内的分区从账本发现**：worker 不再按租户轮询，而是从 `authorization_delta_event` 中发现 allowlist 内存在可认领工作的分区（`has_claimable_work` 按分区粒度）。分区是短暂的调度概念：有积压/在途即存在，排空即消亡；不引入新的持久聚合注册表。

### 3.3 分区租约（新增 durable 组件）

- 新表 `authorization_projection_partition_lease`：`(tenant_id, aggregate_type, aggregate_id)` 主键 + `lease_owner` + `lease_token_hash` + `lease_expires_at` + `generation` + `cas_version`。与 delta 事件租约同型：CAS 获取、到期 reclaim、generation/token fence 防陈旧执行。
- **每分区同时至多一个 in-flight 事件**：分区租约天然表达；分区内严格按现有版本序门取事件。
- 看门狗（F5）升级为分区粒度：worker 代停滞/panic 时按分区释放租约并 reclaim，不再整代重启丢掉所有分区的在途状态（整代重启保留为最后手段）。

### 3.4 worker 模型

- `N` 个并行 worker（配置项，默认值见 Q2），每个 worker 循环：`认领分区租约 → 认领该分区分组内最老可认领事件 → 现有单事件处理流程（claim → 事务外编译 → 发布事务 pointer/manifest/segment CAS → completion）原样执行 → 释放/续租`。
- **单事件处理代码路径零改动**：Phase 1 只改调度层（谁、按什么粒度、并行地调用它）。strict gate、编译内核、发布事务、失败分类（`PublishFailureHandling::*`）全部不动。
- 公平性：分区候选按"最老 pending 事件时间"排序 + 每 worker 每 tick 每分区出队上限（替代旧 `MAX_EVENTS_PER_TENANT_PER_CYCLE` 的防饿死职能）；单租户风暴最多占满自己的分区，其他分区不受队头阻塞。

### 3.5 保留的不变式清单

1. 租户边界：所有 claim/pointer/evidence 读写仍带 `tenant_id`；allowlist 外零消费。
2. durable 语义：source transaction 只覆盖 source + head/outbox + audit correlation；发布事务 CAS affected-rows-exactly-one；`PENDING`/`DENY` 兜底不变。
3. 失败分类：`PointerMoved` replan（不消耗 attempt 预算）、business-pending 与 hard-error 区分、attempt 预算/900s cap 语义不变（B7 的 (b) 修复是独立待办，不混入 Phase 1）。
4. 审计关联：分区租约的获取/实际释放/reclaim 全部落审计，可按 `operationId/runId` 关联。**当前工作区实现补充（2026-09-22，未提交）**：fresh acquire、过期 reclaim 与 owner/token 匹配的实际 release 通过 `audit_log` 同一短事务落 `AUTHZ_PARTITION_LEASE` 行；陈旧或已释放句柄的零行 release 是无审计成功 no-op。成功 heartbeat 仅更新租约行的 `last_renewed_at`/`cas_version`，不制造审计风暴；持有者观察到 CAS 丢失时额外落 `RENEW_LOST`。每个 acquire/reclaim episode 生成独立的非秘密 `leaseCorrelationId`（与 fencing token 独立），`request_id` 使用版本化、长度分隔的 SHA-256 规范输入绑定 episode、租户/聚合、owner、transition outcome 和显式 generation/CAS 空值；同一 episode 的 release/renew-lost 可关联，不同 transition 和重复 acquire cycle 不碰撞。原始 token/token hash 不写入审计。用户可见 audit list/count/stats 与 admin `requests_today` 读取统一排除 `decision <> 'INTERNAL'`，取证路径仍可按 `event_type='AUTHZ_PARTITION_LEASE'` 查询。局部 typed/编译证据已完成；真实 MySQL 断言仍属未执行集成门禁，不得折算为 PASS。
5. 观测：E1–E4 观测事件在调度层增加 `partition_id` 维度，既有字段零破坏。

### 3.6 与 898s 的关系

Phase 1 后，同聚合 REMOVE/ADD 风暴只困住该聚合分区，不再占用全局唯一 worker——受影响卡作用域的 ~898s 尾部仍在（B7 未解），但**不再传染其他聚合**。B7 的根治（方向 b：budget-exhausted 由指针前进/看门狗事件即时 reclaim；方向 c 即本 Phase）与 E3 复测另行走实验清单。

## 4. Phase 2：跨租户行政祖先树与共享单元证据（default-off，待实现）

### 4.1 租户隔离、行政祖先树与独立状态

- **集团、子公司、部门各有独立 `tenant_id`**。新增 `aggregate_type='ORG_SCOPE'`，聚合身份仍为 `(tenant_id, aggregate_type, aggregate_id)`；`aggregate_id` 标识该租户内的治理单元，不以集团 tenant 覆盖全部后代 tenant。
- **行政授权关系与资金、股权及展示目录关系分开**。非独立行政单位只能属于一棵授权祖先树；工程默认采用单父树，概念字段为 `authority_root_tenant_id`、`authority_parent_tenant_id`、行政关系版本和生效状态。字段名是设计候选，不表示已建表。环、多个有效父节点、未知根或版本不一致均不得发布可用证据。
- 集团是其行政树的授权根，拥有该树最完整的、经治理批准的权限来源；“最完整”不是平台全局超级权限，也不使集团管理员天然获得所有下级业务数据。管理员身份、持有权限和可向下授予权限分别验证。
- **完全行政独立的子公司以自身为授权树根**；仅接收集团资金等关系不产生集团授权继承，也不使资助方自动获得其员工或数据的权限。独立根的初始权限仍须显式批准，不能从“独立”状态或根身份推导出新权限。
- 行政关系的 source of truth 是经批准的治理 mutation。`tenant.parent/path/depth` 等目录字段只作展示，不得直接改变授权根。创建、挂靠、移树、独立及恢复隶属都记录 source、durable 事件/失效证明、版本与 audit correlation；终端请求或单方修改目录不能自行宣布独立。
- **状态转换不得保留未经重批的旧继承授权**。独立或移树时先使旧依赖失效，再按新根完成批准与发布；共享卡和个人卡上依赖旧根的贡献都纳入影响范围。中间态 PENDING/DENY，身份是否仍有效与授权是否可用分开判断。
- allowlist 继续约束部署消费范围。行政边不会自动扩大 worker 的租户 allowlist；必要祖先证明不可获得时停止相应分支准入，不能跨部署读取未批准租户来补齐。跨城复制与多写者一致性不在本设计内。

### 4.2 逐级申请、授予上限与相对 BASE/OVERLAY

**BASE 是上级已批准向本级下发的贡献集合，不是上级全部权限的自动复制。** 子公司有效结果经批准下发给部门后，才成为部门的 BASE；每一级在自己的 BASE 上应用本级 OVERLAY。

对于有效行政边 `P → C`，令 `Held(P)` 为上级经证明持有的范围，`Delegable(P)` 为其中可向下授予的范围，`Received(C)` 为经上级批准、本级已取得的范围。目标合同为：

```text
Effective(C) ⊆ Received(C) ⊆ Delegable(P) ⊆ Held(P)
Effective(C) = ApplyOverlay(ApprovedBase(P, C), LocalOverlay(C))
```

这里的包含关系同时覆盖资源/动作、资源所属租户、domain、对象范围、有效期和再授予约束，不能只比较动作名称。它表示跨租户批准合同中的范围映射，不是忽略 tenant 后做 grant 集合并集。

1. 下级新增跨租户授权或扩大已获范围必须向直接行政上级申请。上级审批时同时验证自己当前持有、可授予范围及审批操作者的治理权限；**持有某项业务权限不等于有权授予它**。
2. 直接上级缺少权限或再授予能力时，由该上级继续向自己的上级申请，取得批准并完成所需发布后才可向下授权。不得跳过中间授权边，也不能以“集团可能有”或等待审批的记录放行。
3. 已获范围内的本地分配只可行使审批对象明确授予的分配能力；批量、持续或再次分配是否被覆盖必须在批准记录中明确，不能由 worker 推定。资源/动作未注册、范围包含关系不可证明、上级状态未知均 PENDING/DENY。
4. 审批结果绑定来源 tenant、目标 tenant、行政边及其版本、上级 exact grant/revision、申请范围、有效期、再授予限制、批准主体和稳定 operation/event id。审批到 source 提交之间须复验上级持权及失效栅栏，防止审批后撤权仍向下发放。
5. 上下级 tenant 不相等是正常情况，但必须通过显式批准的边形成目标租户证据。请求 tenant、资源 tenant 与授权来源 tenant 分别记录；不能直接改写 grant 的 tenant 或放宽现有 tenant 相等检查。对上级或兄弟租户数据的访问也必须在批准范围内明确，不因组织关系隐含获得。

OVERLAY 只接受以下操作：

- **新增贡献**：在 `Received(C)` 和相应分配能力范围内激活新的独立贡献；同一资源动作可以有多个可审计的合法来源，禁止隐式覆盖或仅保存一个布尔结果。
- **精确来源剪裁**：在本级作用域记录屏蔽/窄化，指向祖先 contribution 的 exact identity/revision。不得修改祖先 grant 本身的生命周期 tombstone，否则会影响兄弟单位；复杂范围收窄只在包含关系可证明时接受。
- **限制延续**：祖先 revision 改变时，既有剪裁必须重新核对、显式迁移或重新审批；不能因旧 revision 不再匹配而静默取消限制。未完成核对的受影响证据保持 PENDING。
- **不重造被剪裁来源**：改名、复制 source_id 或重新包装同一 provenance 不产生独立授权，不能绕过本级剪裁。真正经批准的另一独立贡献可继续有效；若将来需要禁止所有来源取得某项能力，应另立共同约束，不能把来源剪裁冒充全局 DENY。

### 4.3 共享单元卡、成员资格与受约束的 union 准入

- 每个治理单元使用一张共享授权载体，成员复用单元已发布证据；个人卡不复制完整组织规则。**现有 `user_card.user_id`、`CanonicalGrant.user_id`、双卡资格 SQL 和 `ProjectionKey` 都按单用户归属设计**，一人多卡不代表已支持共享卡。共享内容、单元归属和成员资格必须分别建模，不能通过删除 user/tenant 校验实现。
- 成员资格是独立版本化事实，至少绑定主体/身份、目标 tenant、单元、行政根及关系版本、有效期和撤销栅栏。加入、退出、禁用、到期、调岗均有批准来源与 durable 失效路径。共享卡证据健康不能替代“当前请求者仍是合法持有者”的证明。
- 工程默认：行政树单父；成员可以显式拥有多个单元资格，但每项独立批准并限制数量。**当前工作区实现（2026-09-22，未提交）**：每个 `user_id` 全局最多持有 8 条 `active=1` 的 ORG_SCOPE membership（不按行政根或 tenant 分桶）；有效期已结束但尚未显式撤销的 active 行仍占用名额。创建在同一 source 短事务中按固定顺序锁定 `identity_card.uk_ic_user(user_id)` 单表用户锚点、物理双卡绑定、`idx_osmem_card(card_id, active)` 卡级范围和 `idx_osmem_user_active(user_id, active)` 用户范围，再以 bounded count 拒绝超限；单表用户锚点使容量边界不依赖 InnoDB gap-lock 语义，在 `READ COMMITTED` 下也保持串行。超限回滚 operation claim/revision/outbox/audit，不产生 durable 残留。启用前 preflight 必须证明 `uk_ic_user(user_id)` 为唯一单列索引；该基线契约属于既有 identity-card schema，本 additive migration 不创建或修复它。跨 tenant 的资格不是一张跨 tenant 通行证，一次请求只消费对其目标资源作用域有效的分支；首版不自动组合不同独立行政根的权限。
- **非独立单位员工的所有组织业务授权，包括个人卡上的直接/审批授权，都必须追溯到该单位所属行政根。** “个人独立授权”只表示它不依赖某一条部门共享贡献，不表示可以脱离祖先树、绕过授予上限或从未批准的外部来源取权。独立单位员工则按该独立单位自己的祖先树配置权限。
- 祖先单元卡仅是继承编译依赖，不自动成为成员可直接使用的额外分支。否则部门剪裁会被祖先卡重新放行；额外持有者资格必须显式批准，并接受职责分离等共同约束。

**Union corollary 的目标合同（须在实现前形式化评审）**：共同身份、tenant、行政资格及必要的跨分支约束均可证明后，存在一个独立可准入分支即可返回单一 ALLOW。该分支必须同时证明成员资格、完整的批准/祖先依赖、exact candidate identity、当前 manifest 链与完整性；最终一致性点 `t_f` 前的相关资格或祖先收窄不能被遗漏。

- 分支局部 PENDING 只阻断依赖该事实的授权。个人分支确实不依赖损坏的部门贡献且共同检查已完成时，可独立 ALLOW；共同祖先撤销或资格未知影响所有依赖它的分支，不能被 union 绕过。
- SoD 按本次目标作用域内相关的组合授权检查。另一分支未知而可能含冲突权限时，不能把“读不到”当作“无冲突”；必须证明无关或返回 PENDING/DENY。这限定了“分支 PENDING 不污染其他分支”的适用范围。
- 审计分别记录请求者、请求卡、获胜分支/单元卡、source/target tenant、行政根、membership revision、grant/revision、批准关联及所用 manifest/依赖版本。现有 E1 的请求 `card_id` 字段不足以自动归因，需要同步扩展 audit、SoD、命中统计及 host 调用方。
- 调岗默认先撤销旧资格、确认旧授权已不能用于新准入，再激活新资格；允许短暂 PENDING/DENY。并行任职属于另一个显式批准的多资格状态，不从调岗中间态推导。

### 4.4 贡献 HAMT 与增量编译目标

#### 4.4.1 可复用基础与必须补齐的范围

[FactoredHotState设计](./FactoredHotState设计_V1.0.md) 的内容去重、grant 修订保留、贡献集合、HAMT 路径复制和未变段 `Arc` 复用可以继续使用。层级化的目标是同时降低**成员扇出**和**每个单元的局部编译成本**，不把 HAMT 容器当作祖先继承、租户隔离或持久证明本身。

| 结构 | 目标职责 | 与当前实现的差异 |
|------|----------|------------------|
| 共享内容表 | 不可变规则内容按摘要复用 | 当前去重主要在一个 HotState 及其派生状态内；跨 worker 不自动共享 `Arc` |
| 贡献 HAMT | 来源 tenant/org/grant 身份映射到 revision、状态、内容引用和 provenance | 保留多个合法来源，不把相同资源动作压成单一 ALLOW |
| 本级 OVERLAY/剪裁索引 | 对祖先 exact identity/revision 的本地限制 | 新增独立作用域记录，不能复用为对祖先 grant 的全局删除 |
| 资源动作索引 | 精确 key 对应有序贡献桶 | 当前正式 reader 仍匹配 `effective_grants`；热查询索引需接线 |
| 单元证据记录 | 目标 tenant/单元、获批范围、祖先依赖版本、本级根与发布证明 | 当前 key/段包含 card/user，不能改写所有 key 后仍宣称跨单元零复制 |
| 成员资格账本 | 用户对单元证据的消费资格和撤销版本 | 与规则内容分离，成员变更不重编译其他成员或集团规则 |
| 反向依赖索引 | 从来源贡献/行政边定位受影响单元和失效范围 | 必须来自可对账的治理事实，不能依赖可能缺项的进程缓存 |

共享字节不得共享授权归属。跨 tenant 复用只在获批输入与隔离缓存范围内发生，各目标单元保留自己的受认证作用域和依赖证明；公开内容 hash 或 HAMT 节点地址都不是授权凭据。现有段与 matcher 的 tenant/user 约束演进需要版本化契约及迁移验收。

#### 4.4.2 集团变更的增量流程

1. 源事务先记录批准的变更、修订与失效事实；后代展开可异步，但不能出现源撤销已提交而读门仍认为没有撤销的窗口（见 §4.5）。
2. 更新来源贡献的不可变新版本，HAMT 只复制变化 key 所在路径；旧根继续表示旧版本，**不会自动指向新集团权限**。
3. 通过完整反向依赖定位受影响单元，向各单元提供旧/新祖先版本、变化贡献与影响 key。与并发挂靠、移树的交互必须按行政关系版本对账，不能漏掉新旧受影响范围。
4. 每个单元在自己的已证明基态上应用祖先差量，再应用本级剪裁/新增；只重算受影响贡献桶，保留本级限制及未变内容/段引用。
5. 各单元完成自己的版本推进、manifest/segment 校验和 pointer CAS。源变更不能仅靠 MQ ACK 或祖先发布成功就被标成所有后代已完成。
6. 组织规则不按每个成员重编译；但依赖该规则的个人分支仍须接受祖先失效栅栏。**成员卡零全量重编译不等于个人授权免于撤销或资格复验**。

#### 4.4.3 端到端优化缺口与查询边界

- **依赖差量**：现有编译器在 dependency hash 改变时返回 `FullRebuildRequired`。层级依赖增量需要证明旧/新依赖之间的完整差量和影响范围；证明不足仍全量重建/PENDING，不能通过删除依赖检查取得性能。
- **热状态复用**：当前 projector 每个事件调用 `hot_state_from_entries` 重建基态。目标按 tenant/聚合/已发布版本/编译器版本缓存热状态，每次使用都与 durable frontier、依赖 hash 和 ownership 对牌；仅在发布 commit 已证明后接受新基态，UNKNOWN 先对账。冷启动或漂移时由账本恢复。
- **段引用发布**：当前 stage plan 仍遍历候选段并编码摘要。目标贯通影响计划、已验证段引用和摘要，跳过未变段的重复序列化；完整 manifest 的验证成本单列，不冒充局部 HAMT 更新成本。
- **查询索引**：只在已认证的当前单元证据上构建资源/动作索引；按精确、类型通配、全局通配与动作别名查询有限候选桶，保持原有确定性候选顺序、有效期和 exact identity 复验。读取依赖摘要与撤销证明可以有界点查，禁止运行时沿行政树发现或推导授权。
- **持久化与清理**：`im::HashMap` 的持久性表示内存结构共享，不表示数据库已保存 HAMT 节点，也不等于 Merkle 证明。首版保留 manifest/segment 完整性边界；热状态和内容缓存须有容量、TTL、旧根/陈旧条目 GC，失效后回权威恢复路径。更换 durable 段表示另走版本化合同和回滚设计。
- **首版只做共享单元证据主路径**；不同时实现个人卡链式折叠退化模式。通配、复杂范围变更、批量过大、独立/移树等无法证明局部影响的场景保留显式全量路径。

性能口径：`U` 为受影响单元数，`K` 为变化 key 数，`N` 为单元索引规模。热状态命中且差量完整时，每单元计算主要是约 `O(K log_B N)` 的路径复制，加受影响桶的合并/排序/哈希；HAMT 的浅层平均查找不代表整条链 O(1)。在每单元一份批次的模型下，发布仍有约 `U` 次推进及相应 durable 工作。若编译必须等待父单元新发布证据，关键路径仍随树深增长；只有输入版本可独立证明时才可并行，不预先承诺 ε 与深度无关。读侧匹配、冷加载验证、数据库访问、撤销立即阻断和恢复完成时间分别测量。

### 4.5 撤销、资格变更与失效捕获

- 收窄/撤销源事务原子记录相关版本/栅栏、批准关联及可恢复的影响意图；后代 delta 尚未生成时，受影响分支的读门也必须能看到祖先失效事实。不能在大事务内展开所有成员，也不能只依赖最终 fan-out 行存在与否判断安全。
- 实现前固定“祖先失效记录 + 已编译依赖索引/范围”的可见性协议：源提交前的读不作追溯承诺；源提交后、分支最终 `t_f` 前的相关收窄必须被拒绝或已被最终证据表示。影响范围或索引完整性未知时保守阻断相关作用域。后台物化 intent 不能自行扩大范围或创造新授权。
- 祖先撤销影响全部依赖它的单元和个人贡献；本级精确剪裁只影响该级及经其继续下发的对应贡献，不删除兄弟单元或合法独立来源。revision 更新不得造成被剪裁权限复活。
- 成员退出/到期、账户禁用、行政独立/移树都是可能减少有效授权的事件，必须有相应资格/关系失效合同；不能只覆盖规则集 REMOVE。成员资格与组织规则使用不同证据对象，但获胜分支的最终准入须同时证明二者可用。
- 单元证据不可用会使其全体持有者的该分支 PENDING/DENY；是否还能通过个人或其他分支，由共同依赖及 SoD 完整性决定。安全阻断时间与投影排水恢复时间是两个指标，不以更快发布代替撤销安全。

### 4.6 评估、兼容与实现前合同清单

`PolicyEngine.evaluate()` 继续是唯一授权入口；旧个人卡路径在未启用新功能时保持原语义和 typed 测试。新分支增加作用域、成员资格与 provenance，属于显式合同演进，不能称为“输入输出零改动”。当前工作区的 ORG_SCOPE source slice 已在 default-off 条件下接入正式评估与 projector 生命周期；下列项目仍是实现合同与验收清单，任何一项的 source-only 证据都不能代替迁移、真实集成或部署验收：

1. 行政根/边、独立状态转换、跨 tenant 批准、授予上限、剪裁延续的 schema 与状态机；根权限的批准/初始化流程不能由根身份自动代替。
2. 新 contribution/资格/evidence 类型、版本和 source/resource/target tenant 映射；审批期间撤销、资源范围包含和多资格上限的 fail-closed 行为。
3. 祖先失效可见性协议、影响意图与反向依赖完整性、继承差量和并发移树的证明；共享缓存内容身份不能替代 provenance。
4. Gateway 绑定上下文、host 完全中介、SoD、审计、命中统计和 E1 观测的调用方迁移；请求卡与获胜分支不能混用。
5. 编译器版本、热状态缓存及 GC、旧节点读取新证据的 fail-closed 行为、迁移 preflight/验收及关闭功能后的恢复方式。

### 4.7 迁移、开关与控制面

- `ORG_SCOPE`、共享卡和行政树合同增量上线、default-off。目标是无需对全部既有个人卡做强制回填；需要纳入行政树治理的既有授权仍须证明来源并登记依赖，未证明时不能自动视为合规个人独立分支。
- 首版在同一 authoritative store 的已批准部署边界内实现跨 tenant 行政树；不引入跨城多写、跨根权限自动 union 或外部关系推理。后续跨独立根协作须另立显式批准合同。
- 控制面覆盖行政根/边、申请/审批、单元授权绑定、共享载体和成员资格管理。路径按冻结规范登记，使用已注册资源/动作和统一授权入口；列出全部仓内调用方及 schema/证据协议兼容影响后才实施。
- 功能关闭或回滚不能把已受新限制的分支退回旧宽权限路径；保留批准、失效和审计证据，使新分支保持不可准入直至恢复。设计决策不等于批准实际生产 source mutation、迁移或部署。

### 4.8 隔离面（B3/B4 的落点）

- **断路器**：局部证据损坏计数按 resource × tenant/聚合分区隔离；共享基础设施故障是否计入 `__global__` 必须单独分类。不能在保留“所有局部错误累加全局”行为的同时声称单分区故障隔离。实现前完成既定五链评审，验证更改没有绕过读门且故障范围符合分类。
- **缓存与调度份额**：分别设置 tenant/聚合的容量、TTL、GC 与公平性预算。分区并行不等于租户配额隔离；大量分区的单租户风暴仍须通过基准和故障注入确认不会耗尽其他租户的共享连接池/worker。

## 5. 验证计划

| 阶段 | 离线（单机） | 真实集成 | 门禁 |
|------|--------------|----------|------|
| Phase 1 | 分区发现/租约 CAS/公平性/看门狗交互的 typed 测试；调度层 shape 断言 | 真实 MySQL/Redis 的多 worker 并行投影集成（ignored 套件，隔离 fixture） | workspace 四门（fmt/check/clippy/test）不降级 |
| Phase 2 | 上下级持权/再授予范围、行政树/独立状态、共享资格、精确剪裁与 revision 延续、union/SoD、继承差量与 full-oracle parity 的 typed 测试 | 跨 tenant 批准与撤销、成员退出/调岗、并发移树、故障恢复的 durable 路径；迁移 preflight/回滚演练 | 同上 + 新合同与迁移验收 |
| 共同 | 租户数 × 单元数 × 深度 × 成员数 × 变化 key 数矩阵；分别测热编译/冷恢复、序列化、SQL、eval p99、drain、缓存与公平性 | E3 复测；审批后撤权、后代尚未展开、资格退出但共享卡健康、共同祖先失效等时序 | 按 campaign 协议冻结；`localReady`/`overall`、SKIP/UNKNOWN 及归档校验语义不放松 |

Phase 2 必须覆盖的反例：无权限上级批准下级、下级超已获范围、目录/资金关系产生授权、伪造独立状态、祖先卡绕过部门剪裁、改名重造来源、revision 更新解除限制、个人卡绕过共同祖先撤销、跨 tenant 资源误匹配，以及另一分支未知时 SoD 被当作无冲突。安全阻断与恢复可用性分别断言。

E5/TLA 边界：组织树、批准边、成员资格与撤销捕获是否纳入独立 bounded model，在 §4.6 合同评审时确定；不得以既有 E5 模型覆盖新语义。上述均为验证计划，本次文档修订未执行这些测试。

## 6. 里程碑

1. **M1（Phase 1）**：本设计稿评审 → 分区调度实现 → 多租户 bench 基线（真实集成依赖租节点）。
2. **M2（Phase 2）**：M2.1 行政树/跨 tenant 批准/成员资格与撤销合同冻结 → M2.2 default-off 共享单元证据、受约束 union 和调用方迁移 → M2.3 贡献 HAMT 依赖差量、热状态与段引用优化 → 迁移演练及端到端基准。先闭合安全合同，再把局部编译收益接到完整链路；一个月为开发窗口，不是未经验证的完成保证。
3. **M3（B7 收尾）——机制已实现并验收（2026-09-21）**：基于 E5 集成实测的关键发现（退避窗内的事件使整个分区对调度器不可见，discovery 谓词镜像 claim 资格），修复精确化为"指针前进时改写停摆行"而非"唤醒调度器"：聚合发布 durable 成功（pointer CAS 提交）后，对该聚合分区内 `status='PENDING'` 且 `next_attempt_at` 在未来且 `last_error` 携带 `attempt_budget_exhausted` 标记的行，执行 `next_attempt_at=now + cas_version+1`（`grant_repository::reclaim_budget_exhausted_events`，runtime 端口默认 fail-closed，发布成功后严格 best-effort 调用）。普通短退避行与已到期行匹配不到；`attempts` 保持权威不重置；无授权面变化。真 MySQL 验收：partition-lease 套件 6/6（停摆→不可发现→reclaim 恰好 1 行→重新可发现可认领 attempts 6→7→无标记兄弟行退避保留）。剩余：RQ4.B 同型风暴回归 + E3 复测（live 拓扑）。

### M1 实现状态（2026-09-21，代码层）

| 组件 | 状态 | 落点 |
|------|------|------|
| 分区租约表迁移 | 已入库（additive，未对任何数据库执行） | `astral-db/migrations/20260921000001_authorization_projection_partition_lease.sql` |
| 分区租约原语（acquire/过期接管/Busy、renew 心跳、best-effort release、分区发现镜像 claim 资格+版本序门；获取/回收/释放/丢失的 durable audit correlation） | 已实现，typed + ignored 集成断言已编译；真实 MySQL audit 断言未执行 | `astral-db/src/grant_repository.rs`、`astral-db/tests/partition_lease_integration.rs` |
| runtime 端口（discover/acquire/renew/release/claim-in-partition，默认 fail-closed unsupported；生产 Sqlx runtime 全覆盖） | 已实现 | `astral-trustgraph/src/service/authorization_projector.rs` |
| 调度拓扑 `ProjectorSchedulingMode`（默认 TenantSerial）+ `run_partition_worker`（发现→租约→批内续租认领→复用 `process_one_event`）+ `supervise_partition_projector`（N worker、槽位重启、停滞看门狗、有界关闭宽限） | 已实现，7 个 typed 测试 | 同上 |
| 部署面：`ASTRAL_PROJECTOR_SCHEDULING_MODE` / `ASTRAL_PROJECTOR_WORKER_COUNT`（fail-fast 解析）+ Q2 池预算守卫（worker×2 ≤ 池上限） | 已接线 | `astral-trustgraph/src/main.rs` |
| 真实 MySQL/Redis 多 worker 并行集成验收 + 多租户 bench | **BLOCKED**：本机无 `DATABASE_URL`/Redis/RabbitMQ、`mysql` 客户端或 Docker daemon；`partition_lease_integration` 已编译但未运行。ORG_SCOPE 的真实迁移、preflight、备份恢复与回滚演练仍需单独 Exec-L3 批准。 | — |

分区调度**默认关闭**：`scheduling_mode` 默认 `TenantSerial`，生产行为零变化；`partitioned` 由部署显式启用并要求先完成迁移与集成验收。

### M2 实现状态（2026-09-22，代码层，进行中；default-off）

| 组件 | 状态 | 落点 |
|------|------|------|
| ORG_SCOPE additive 迁移（13 表，无 ALTER/回填/删除） | 已创建于当前工作区（截至 2026-09-22 git 未跟踪、待提交；additive，**未对任何数据库执行**） | `astral-db/migrations/20260922000001_org_scope_authority.sql` |
| org_scope_repository（node/request/grant/mask/membership/revision/outbox/publication/current/dependency/operation/audit、flatten compile input、complete_publish） | 已实现，typed 测试覆盖；membership 创建额外执行 global-per-user active cap（8）与 user-range lock，超限 fail-closed | `astral-db/src/org_scope_repository/` |
| org 治理 API/service（ROOT_INIT、挂靠、授予、剪裁、成员资格等路由） | 已实现并注册路由；治理行为受 `ASTRAL_ORG_SCOPE_ENABLED` 门控 | `astral-trustgraph/src/api/org_authorities.rs`、`astral-trustgraph/src/service/org_authorities.rs` |
| org 准入门与编译内核 | 已实现 | `policy-engine/src/org_admission.rs`、`policy-engine/src/org_compiler.rs`（`repository.rs` 提供 `load_org_authorization` hook） |
| org projector worker | 源码已接线：仅在 frozen `ASTRAL_ORG_SCOPE_ENABLED=true` 时解析显式 tenant allowlist、执行只读 schema guard 并启动；关闭时严格逆序 drain。typed 测试已覆盖，未启动 worker、未做真实集成验收 | `astral-trustgraph/src/service/org_scope_projector.rs`、`astral-trustgraph/src/main.rs` |
| 迁移 preflight/回滚脚本 | 已创建于当前工作区（git 未跟踪、待提交；preflight 只读；rollback 破坏性，带逐表空表守卫） | `scripts/org_scope_preflight.sh` |
| 真实迁移应用、preflight/备份恢复/回滚演练、真实集成验收 | 未执行（BLOCKED，依赖 Exec-L3）；其中 membership-cap 的跨独立根、expired-active、revoke-then-create 与并发不同卡断言已编译为 ignored MySQL 测试，尚未运行 | — |

ORG_SCOPE 运行时**默认关闭**：`ASTRAL_ORG_SCOPE_ENABLED` 严格 bool（默认 false，非法值拒绝启动）；迁移文件存在不等于目标数据库已应用；受管租户在旗标关闭/陈旧/未知时必须 DENY，不回退 legacy 或 raw source。迁移/回滚流程与执行状态见 [ORG_SCOPE迁移与回滚操作手册_V0.1.md](../../迁移/ORG_SCOPE迁移与回滚操作手册_V0.1.md)。上表仅记录代码层现状，**不构成 M2 完成或部署验收**。另注（交付状态，截至 2026-09-22）：上表所列 ORG_SCOPE 文件（迁移 SQL、`org_scope_repository`、org 治理 API/service、`org_admission`/`org_compiler`、`org_scope_projector`、preflight/回滚脚本）及相关文档均为 git 未跟踪（untracked），须由后续授权交付步骤 stage/commit 后才进入仓库提交历史；在此之前 release/CI checkout 不包含这些文件，本表状态只对包含这些文件的工作区快照有效（最终冻结语义见 [AGENTS.md §7.2](../../../AGENTS.md)）。

**BREAKING CHANGE（Rust 0.x workspace 内部接口下线，2026-09-22；按 [AGENTS.md §3.3](../../../AGENTS.md) 内部接口门登记）**：`astral_types::org_scope::OrgSubjectFilter::All` 已从源码移除。**替代入口**：`SharedOnly`（共享单元贡献）或精确 `PersonalOf { user_id, card_id }`（显式个人卡对），不再提供"取全部"隐式过滤器。**影响范围**：repository-wide 扫描确认仓内零调用方（现存引用均为 `SharedOnly`/`PersonalOf`，含 typed 测试）；仅 Rust workspace 内部类型，不构成 wire 协议、MQ 协议或数据库协议变化，**无外部 HTTP/MQ/DB 兼容性声明**。**迁移方案**：调用方必须改用显式过滤器（`SharedOnly` 或精确 `PersonalOf`），禁止依赖隐式全量语义。**回滚方案**：仅在源码层恢复该变体；**不得**把恢复 `All` 当作授权语义放宽或绕过 fail-closed 默认拒绝的 workaround。**生效时间**：随包含本次移除的工作区快照即时生效；进入仓库提交历史以后续授权 stage/commit 为准（交付状态见上文另注）。

## 7. 已确定的决策与工程默认方案

### 7.1 2026-09-21 决策（保留）

| ID | 主题 | 已确定立场 |
|----|------|------------|
| Q1 | tenant allowlist | 保留部署信任边界，只在其内发现分区 |
| Q2 | 并行 worker | 默认 4、上限可配，按共享连接池预算守卫 |
| Q3 | OVERLAY | 仅新增/显式窄化、歧义 PENDING；新增受 §4.2 的已获范围与逐级批准约束 |
| Q4 | 开发窗口 | M1+M2+M3 完整计划进入开发窗口 |
| Q5 | 断路器评审 | 分区维度实现前完成五链评审 |

### 7.2 2026-09-22 用户决策（本次确认）

| ID | 主题 | 用户确定的语义 |
|----|------|----------------|
| D1 | 租户身份 | 集团、子公司、部门分别使用独立 `tenant_id` |
| D2 | 下级新增 | 仅在已获取范围内新增；向上级申请并检查上级确实拥有相应权限 |
| D3 | 剪裁对象 | 采纳精确来源剪裁；不把某一贡献的撤销解释为所有来源的全局禁止 |
| D4 | 行政祖先树 | 非完全独立行政单位的授权全部来自集团祖先树；仅资金等关系的行政独立子公司按自身祖先树配置员工权限 |
| D5 | 修订与调岗 | 采纳旧限制不得静默消失、歧义 PENDING、调岗先撤旧再启新 |

### 7.3 工程默认与剩余设计责任

- §4 所用字段名、单父树、多资格有界及并行任职显式批准、持权与再授予能力分离、同 authoritative store 内实现、直接上级逐级申请、源失效证明及共享单元主路径，是根据 D1–D5 细化的工程方案；不表示这些 schema/API 已实现或已批准生产部署。
- 基本业务语义已足够继续 §4.6 的合同设计；剩余工作由实现设计承担：确切 schema/API、范围包含算法、审批与撤销并发控制、root 初始化批准路径、失效可见性证明、迁移恢复和容量参数。遇到超出 D1–D5 的新业务语义才另行决策。
- 本次更新仅记录决策和目标合同；运行代码、数据库、实验归档及正式规范均未因此改变。

## 8. 维护约定

- 本文为非规范性架构设计；实现事实落地后，以代码/迁移/测试为准回填状态，并同步 [Rust架构设计 README](./README.md) 导航。
- 任何与 AGENTS.md §3 不变式冲突的发现，先停实现、登记差异、补验证。
