# Rust 架构设计

本目录收录独立 Rust 后端的认证、会话、双卡上下文、权限评估、规则集、投影、委托、仲裁、组织层级、内存读面与治理设计材料。下面按**每份架构/储备 Markdown 文件**提供主题解释与状态入口；状态截至当前 checkout 的静态证据核对，不能替代测试运行、数据库迁移、真实依赖集成或部署验收。

## 项目图集

- [项目架构与接口图集](../图集/index.html)：模块架构、接口族、279 条 endpoint 全集与单接口跨模块调用链。

## 如何阅读与判断状态

- **源码事实 / 已实施基线**只描述能由当前源码定位的机制；不自动表示它在目标环境启用或已验收。
- **已批准目标**表示设计方向获批，不表示所有实现、迁移或部署已完成。
- **部分接线 / 筹划中**须区分已经有的 source code、尚未实现的契约和未执行的集成门禁。
- **历史快照 / 问题登记 / 候选讨论**分别是某日期的观测、缺口账本或未批准选项，不是当前实现证明或批准决策。
- 对象级受保护请求仍须由服务专属 owner resolver 在 `PolicyEngine::evaluate()` 前解析目标归属；候选文件和共享上下文 helper 不会改变该要求。

## 访问控制、身份与授权决策

- [Rust 访问控制总览与调整路线](Rust访问控制总览与调整路线_V1.0.md)：分析 Gateway、Identity、TrustGraph、owner resolver、`PolicyEngine::evaluate()` 与 published-evidence 之间的职责链；生产 strict gate 与兼容/诊断面分开描述。**当前基线 + 调整路线；不代表全链部署验收。**
- [Rust 权限判定与规则集语义](Rust权限判定与规则集语义_V1.0.md)：解释 AUTHN、双卡资格、规则集匹配、strict published-evidence、委托和 legacy/test 阶段的判定差别。**当前实现事实与未闭合边界并列。**
- [Rust 双卡身份与授权上下文](Rust双卡身份与授权上下文_V1.0.md)：分析 `identity_card` 身份事实与 `user_card` 授权载体、会话签发/刷新/切卡和上下文传递；区分已有资格读时检查与未闭合的身份状态/资格 fan-out。**当前基线与缺口索引。**
- [Rust Arbiter 与 GlobalAdmin 治理链](RustArbiter与GlobalAdmin治理链_V1.0.md)：分解仲裁证据/冲突解决与平台管理员特权卡生命周期；明确纯函数多数计算不是经过认证的节点 quorum，Arbiter 不是普通请求的授权入口。**当前基线评估，信任与审计缺口仍需闭合。**
- [物理双卡权限链路评估与设计](物理双卡权限链路评估与设计_V1.0.md)：分析双卡链路的历史问题、工程取舍和修正路线，用于理解设计动机。**评估材料；不是当前状态验收记录。**
- [物理双卡权限链路目标态设计](物理双卡权限链路设计_V1.0.md)：逐段描述身份卡/用户卡、会话、Gateway、服务上下文与 PolicyEngine 的目标合同。**目标态规定；部分能力有源码，不能据此声称全部完成。**

## Canonical 投影、缓存与恢复

- [Rust 权限投影快照与版本栅栏](Rust权限投影快照与版本栅栏_V1.0.md)：解析 source mutation、grant/delta、manifest/segment/current、generation/revoke fence 与 legacy snapshot 的证据职责；§2.4 对接 **CURRENT V6** 完整规则集与轻量发布身份的[规范 §15.7](../../规范/Rust后端编码规范_V1.0.md#157-规则集完整结构与轻量发布栅栏标准2026-10-28)，并区分历史 v3 migration artifact。**当前代码事实、缺口和目标决策分层记录；迁移/切流另行验收。**
- [Rust 增量重建与实时授权边界](Rust增量重建与实时授权边界_V1.0.md)：分析 compiler、projector、严格读者、realtime 诊断、规则时间窗及资格到期边界；说明 ACK 和旧快照为何不能替代 canonical 证据。**边界说明；包含未闭合项。**
- [Rust 内存权威读面与失效通道架构方案](Rust内存权威读面与失效通道架构方案_V0.1.md)：逐层说明单机 owner、LocalBus、MySQL durable intent、memory hub/read token、失效传播与 UNKNOWN 恢复。**P0–P5 主体已有代码接线和本地门禁；真实 DB/MQ、迁移、并发/崩溃及部署验收未完成。**
- [多云、半区权威与攻击恢复设计 QA](多云半区权威与攻击恢复设计_QA.md)：以 Q01–Q18 记录攻击场景、用户设定、此前回复、待澄清点和逐项回答，覆盖历史 v3 请求、CURRENT V6 代际栅栏、NTP、恢复与等保目标。**持续讨论稿；不构成完整协议批准、实现或测评证明。**
- [FactoredHotState 设计](FactoredHotState设计_V1.0.md)：详解 HotState 中 RuleSet 共享内容、绑定关系、per-grant lifecycle 与卡私有层的事实化表示及语义等价性。**内存编译内核基线已实施；durable 跨卡段共享、RuleSet 级 delta、ID 池化仍属后续路线。**
- [内存镜像读面巨卡优化储备](Rust内存镜像读面巨卡优化技术储备_V0.1.md)：解析大卡完整证据装配的成本、stamp 对牌与容量/TTL 缓存、单卡规模护栏和 evidence-contract 候选。**路线一 assembly cache 已在当前 checkout 接线；规模护栏与证据合同改造未完成；性能收益尚未重测验收。**

## 组织、模型演进与网关

- [多租户聚合分区与组织层级设计](Rust多租户聚合分区与组织层级设计_V0.1.md)：分析 tenant/aggregate partition、lease 和并行 projector（Phase 1），以及行政祖先、BASE/OVERLAY、membership、贡献 HAMT 与撤销（Phase 2）。**目标设计已批准；M1 分区调度代码已实现，但默认仍为 `TenantSerial`，partitioned 模式需显式启用且真实多 worker 集成/基准未验收；M2 ORG_SCOPE source slice 与 projector runtime 已有 default-off 接线，完整授权语义、迁移和部署验收仍未完成。**
- [V5 模型修正筹划](V5模型修正筹划_专供Rust_V1.0.md)：逐项跟踪 canonical v4 基线上的身份/资格、fan-out、到期及 schema/model 修订。**部分实施/筹划中；各项状态以原文为准。**
- [Pointer 对牌 Redis hint 模式 B](Pointer对牌模式B设计_V1.0.md)：分析 MySQL pointer 对牌的成本、Redis hint 的读前/读后对牌、失效与回退候选。**讨论稿、未批准实施；文中约 5 秒撤销窗口是候选风险而非当前行为。**
- [Gateway 当前链路与 A–F 解耦路线](Rust-Gateway当前实际链路与解耦对照设计_V1.0.md)：描述 Gateway 认证/签名/转发链及 A–F 解耦目标；独立的[2026-10-25 当前源码交叉核验](技术专题-Gateway-A-F当前源码复核_2026-10-25.md)逐阶段辨识代码证据，避免把历史 Redis 读路径或计划阶段当作当前事实。**主体是 2026-08-11 历史快照；交叉核验为静态源码观察，不是运行验收。**
- [Rust 架构模型设计修正记录](Rust架构模型设计修正记录.md)：按问题记录代码/schema 核实、修正决定和未闭合边界。**活文档问题账本；不构成统一目标设计或规范正文。**

## 技术储备：逐项技术解析

以下每项均给出对应主题的主解析入口。未获批的储备会讨论问题分解、候选取舍和安全/恢复边界，但候选分析不等于架构批准。

### 原始储备

- [Mobius 应急策略模板库](技术储备-Mobius应急策略模板库.md)：分析模板版本、审批实例、授权 source mutation、投影、到期/撤销和审计之间的生命周期；存储或模板形态均为待决候选。**路线图储备，无专项批准设计或实现证据。**
- [临时授权到期回收](技术储备-临时授权到期回收.md)：区分 Delegation `effective_until` 的对账回收与 RuleSet `valid_to` 自然到期；解析后者为何仍需事件/调度与 canonical projection 更新。**Delegation worker 已存在；RuleSet expiry 闭环和方案仍未定。**
- [分级通知与风暴防护](技术储备-通知分级与风暴防护.md)：拆解告警阈值、按规则近期触发去重、有界 WEBHOOK dispatch 与失败/UNKNOWN，并比较未批准的分级路由和聚合抑制方案。**局部告警能力已实现，完整编排/风暴防护未闭合。**
- [闲置异构算力编排](技术储备-异构算力编排.md)：分析资源发现、能力标签、任务路由、配额、公平性、取消和恢复等调度问题；区分测试主机与 projector worker。**无通用产品调度实现或获批资源模型。**
- [无侵入式接管与源码注入](技术储备-无侵入式接管与源码注入.md)：比较显式 SDK/middleware、sidecar/proxy 与源码织入在强制覆盖、owner 可信度、发布与故障恢复上的差异。**无通用代理/注入实现；现有 SDK 仍需显式接入。**
- [异构存量权限系统接管](技术储备-异构权限系统接管.md)：分开分析身份映射与策略语义迁移，并比较 adapter、导入物化、双运行对账的冲突、撤销和回滚边界。**无通用迁移转换器或已批准切流方案。**
- [跨系统统一权限视图](技术储备-跨系统统一权限视图.md)：比较联邦查询、物化视图和混合索引，解析 source coverage、新鲜度、租户隔离与部分不可用/UNKNOWN。**无统一跨系统视图合同或实现证明。**
- [存量系统继承授权内核](技术储备-存量系统继承授权内核.md)：解释内部 HotState/HAMT、generation/fence 与 strict evidence 的不同职责，再评估库/SDK、PDP service、sidecar 集成形态。**内部构件有实现；外部接管宿主与通用 adapter 未证实。**

### 补充储备

- [多机双通道冗余投递](Rust多机双通道冗余投递技术储备_V0.1.md)：分析独立故障域、同 operation 多 message、operation 级 claim/幂等与 source intent 收口。**预留设计、未实施；不承诺 exactly-once。**
- [巨卡内存镜像优化](Rust内存镜像读面巨卡优化技术储备_V0.1.md)：主详解见上方“Canonical 投影、缓存与恢复”；路线状态按源码复核，不再把已接线缓存写成未实施。
- [FactoredHotState 后续路线](FactoredHotState设计_V1.0.md)：主详解见上方 FactoredHotState；逐项解释 durable 跨卡段共享、RuleSet 级 delta 和 operation/event ID 池化触及的合同边界。**基线已实施，三项后续未完成。**
- [Pointer 对牌模式 B](Pointer对牌模式B设计_V1.0.md)：主详解见上方；方案、Redis hint 对牌与失效回退可读，约 5 秒撤销窗口仍是未批准取舍。**未实施。**
- [ORG_SCOPE Phase 2](Rust多租户聚合分区与组织层级设计_V0.1.md)：主详解见上方组织设计；区分 Phase 1 分区调度与 Phase 2 授权语义/共享卡。**目标设计获批、source 部分接线且 default-off；迁移、owner resolver 和真实验收未闭合。**
- [Gateway A–F 解耦路线](Rust-Gateway当前实际链路与解耦对照设计_V1.0.md)：主详解见上方；2026-10-25 交叉表逐项辨识 golden tests、wire crate、session owner、route/WS/breaker、config 与 Learn/Chat 解冻门。**A–F 均不能凭设计稿视为整体完成。**
- [授权生命周期与治理扩展](技术专题-授权生命周期与治理扩展.md)：逐 owner 解析 source owner/caller-scope、身份与资格 fan-out、RuleSet 到期、Arbiter quorum、GlobalAdmin 审计和 ORG_SCOPE。**跨主题缺口索引及技术解析，不是整体获批方案。**
- [Rust 后端迁移架构决策](../../迁移/Rust后端迁移架构决策_V1.0.md)：以迁移决策记录为主入口，并参阅[技术专题解析与架构取舍](../../技术专题解析与架构取舍_2026-10-25.md)区分已确认的 Axum/Tokio、SQLx、Lapin 选型，与条件性 `sea-query` hedge、备选项及当前源码接线。**该文件为决策确认稿，不等于所有组件均已集成或迁移验收完成；当前依赖版本以 Cargo manifest/lock 为准。**

## 跨主题分析与运行证据

- [技术专题解析与架构取舍（2026-10-25）](../../技术专题解析与架构取舍_2026-10-25.md)：解析 Java→Rust 边界、Axum/Tokio/Tower、SQLx/SeaORM/Diesel、Lapin/amqprs、授权引擎比较和 canonical/legacy projection；区分当前事实、历史决策与候选。
- [授权执行期能力曲线（2026-10-25）](../../实验/基准测试/授权执行期能力曲线_20261025.md)：完整 `PolicyEngine::evaluate()` 的本机 CPU 测量与受限历史对照；不是 HTTP QPS、真实依赖集成或生产容量。

## 规范与验证入口

- [Rust 后端编码规范](../../规范/Rust后端编码规范_V1.0.md)
- [统一消息协议](../../规范/统一消息协议与智能层消息规范_2026-03-18.md)
- [统一接口路径规范](../../规范/统一接口路径规范_V5.md)
- [迁移索引](../../迁移/README.md)

架构文档负责技术机制、目标、取舍和证据边界；工程规范及 Agent 执行门禁分别以 `Docs/规范/` 与仓库根目录 `AGENTS.md` 为准。目标态、候选方案、源码接线、迁移执行和真实环境验收不得混写成同一状态。
