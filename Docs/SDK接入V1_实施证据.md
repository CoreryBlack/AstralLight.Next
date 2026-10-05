# SDK V1 实施证据

## 任务与状态

- taskId: `sdk-integration-v1-20261005`；责任 Agent: 主 Agent。
- 固定 cwd: `/Users/coreryblack/Code/AstralLight.Next`；分支: `feat/sdk-integration-v1`；代码基线: `ffda47c`。
- 用户批准范围: 分支内 SDK/平台接入实现、最小身份映射设计与 migration 文件、独立业务样板、文档及隔离测试。未提交、未推送、未发放真实凭据、未创建真实映射、未迁移、未部署或生产启用。
- 执行动作: 静态检索/复核为 Exec-L0；隔离构建和回环测试为 Exec-L1，使用本任务临时 target 和有界 runner。实际 source mutation、migration、外部发布和部署的 Exec-L3 门禁没有启动，也未被本次代码批准替代。
- 本地命令门禁已通过，真实环境验收未完成。下表的 `PASS` 只表示对应命令和断言实际执行通过；86 项 ignored 不计 PASS，不能据此宣布整体生产接入 PASS。
- 设计/使用合同见 [SDK 接入 V1](SDK接入V1.md)；迁移/恢复见 [操作说明](迁移/SDK身份映射迁移与恢复_V1.0.md)；样板见 [integrations](../integrations/README.md)。

## 目标文件与职责

| Owner | 新增与修改范围 |
|---|---|
| SDK | `astral-sdk-contracts/`、`astral-sdk/`、`astral-sdk-axum/`，根 workspace/lock |
| Identity / DB | `integration_identity_mapping` repository/schema/tests、additive migration、显式导出与迁移链尾测试；Identity 管理路由、middleware/runtime |
| Gateway / 公共路径 | 仅映射管理精确路径转发、动作/ownership 分类及对应测试 |
| TrustGraph | 专用 integration API/service/config/session、窄 SoD/fence helper、runtime 装配和既有准入源码守卫 |
| 独立业务 | `integrations/` 的 Chat、Learn、test-support、自包含 workspace/lock |
| 文档 | 本记录、SDK 设计/使用说明、迁移恢复说明及 Docs/迁移索引 |

旧 `astral-chat`、`astral-learn`、`astral-cache` 源码、历史 migration 和 AGENTS/规范正文没有修改。新功能 additive、默认关闭；不删除稳定 API、legacy 或 compatibility 入口。SDK manifests 不继承平台 workspace 依赖，许可保持 AGPL-3.0-or-later，未发布 crates。

## 委派与接管

按 SDK、数据库 mapping 和独立业务目录划分 ownership，收益是独立实现可并行；平台准入、共享装配、规范、合并和最终验收由主 Agent 串行负责。子 Agent 不提交、不推送、不递归委派，主 Agent 不把其完成消息当成验收。

| 子任务 / Agent | 回报与最终处理 |
|---|---|
| SDK / `agent_2400f8c9-bad5-4ca4-bb4a-aec2d25b97e5` | 原稿存在 actor、manifest/path/facts 绑定和客户端边界缺口；冻结后承认最终验证未闭合。主 Agent 对账后接管，修正并执行最终门禁。 |
| Mapping / `agent_e7d2331e-732b-4ae1-b861-119f797b32d3` | 提交 repository、DDL、单元/ignored 测试原稿；主 Agent 修正纯读取 guard、管理员锁、schema、清理范围及类型合同。 |
| Mapping 审查/抽取 / `agent_8c5bdc27-6055-47df-827d-0204676b27cd` | 报告 audit engine、HTTP unknown/CAS 错误和 key grammar 三项缺口，抽取 schema/tests；行为修复由主 Agent 完成并复核。 |
| 独立样板 / `agent_a57bdda2-0165-48ee-b89d-0f4f29efe2de` | provider 不可用；检查 git/diff/未跟踪文件和进程后确认没有该任务写入，由主 Agent 独占 integrations 实施，没有重复派发。 |

所有写入 Agent 已冻结，最终门禁由主 Agent 执行。接管检查覆盖工作区、目标文件、命令状态及内容 hash；本任务没有真实 durable 业务操作可被重复执行。历史分段回报未保存统一精确 phase 时间，不补造时间；以下完整门禁保存了实际起止时间和单调耗时。

## 五链审查

五链全部适用；主 Agent 已完成静态与本地合同层审查，真实外部依赖边界仍按下文列为未执行。

| 链 | 实施与核对 | 已执行证据 / 覆盖边界 |
|---|---|---|
| 调用 | additive/default-off 路由；Gateway 签名层包住新入口；PolicyEngine 仍唯一授权入口；SDK/样板无平台内部依赖 | workspace check/test；路由、动作和源码守卫；独立依赖树禁止项为空。真实 Gateway/JWT 全链未执行。 |
| 逻辑 | app/issuer/manifest/path-target/tenant/domain 对牌；最小映射、当前会话、strict evidence、context-aware/ORG-aware SoD、原 fence；无角色或 raw/source 放行 | SDK 合同、配置拒绝、same-policy/fence/audit 顺序守卫、HTTP/WS 故障矩阵；真实 session/SoD/fence 并发故障未执行。 |
| 事故 | 请求/响应限长、超时、无自动重试/ALLOW 缓存；缺 schema 启用失败；UnknownCommit/InDoubt 返回 PENDING 和对账要求 | loopback Pending/Deny/超时/重定向/坏签名/过期/大响应；HTTP 错误分类测试。真实断网、COMMIT unknown、worker crash 未执行。 |
| 数据 | byte-exact 永久映射键；状态仅前向、revision CAS、稳定 operation ledger；本地 facts/revision 复检，网络不在持锁事务内 | repository/DDL 静态合同、Learn 对象迁移/父范围/精确列表/幂等、Chat 成员与目标范围测试。真实 MySQL metadata/锁序/并发未证明。 |
| 审计 | mapping/source/ledger/audit 同事务且 preflight 要求 audit_log 为 InnoDB；准入 ASSESSED/INVALIDATED 与业务 commit 分开，按 digest/operation 关联 | SQL 合同、JSON allowlist、错误脱敏、准入前后终检守卫、本地 receipt；真实审计落盘/崩溃恢复未执行。 |

## 耦合与信任边界

- SDK DTO/签名只在 contracts 定义，平台通过窄服务消费，不复制 PolicyContext，不把数据库或引擎 port 扩散到 SDK。
- mapping schema 与测试在原 owner 内抽取，保留原短事务、锁序和 operation/audit 边界；不是只移动测试后宣称完全解耦。repository 生产入口仍约 1008 行，保留同一 aggregate 的事务/ledger/audit 协作。
- TrustGraph 使用独立 route state，不扩充万能 AppState；SoD/fence 抽取保持既有调用方，源码守卫扫描实际生产文件，不靠遗漏文件或 lint 豁免通过。
- 业务 resolver 接收窄 ResourceRequest 元数据，避免跨 await 借用非 Sync body；Chat/Learn 独立消费公共 SDK，不借内部 SQL/引擎入口。
- 应用私钥和经批准的本地事实 resolver 是信任边界；SDK 无法证明被攻陷的业务 owner 没有谎报本地事实。每资源单应用 owner 和精确租户/域范围只限制其授权面。

攻击者可控制业务参数、伪造身份头、重放请求/响应、替换 app/清单/主体/目标/owner/租户，或利用状态漂移和依赖故障。阻断点为可信 Gateway 上下文、应用/决策签名、nonce、映射/session、strict evidence/SoD/原 fence 和本地事实 CAS。误放行会导致跨主体/跨租户访问及业务副作用，因此未知时 PENDING/DENY；误拒绝降低可用性，以原因码、对账和新评估恢复，不用旧 ALLOW 或 source fallback。

## 完整本地门禁

首轮 runId: `sdk-integration-v1-final-20261006`。标签不是时间证据；实际 UTC 时间是 2026-10-05。两个 suite 并行，suite 内顺序执行；下列耗时为单调 elapsed，不是累计模型 turn 时间。

前置条件: 从固定仓库根目录执行，Rust/Cargo 和既有本地 registry/lock 可用；清除 `DATABASE_URL`、`REDIS_URL`、`RABBITMQ_URL`、`RUST_INTEGRATION_REQUIRED` 和两个 SDK enable 环境变量，Cargo offline/locked。测试网络仅本地回环；使用 `/tmp/astral-sdk-20261005-target` 与 `/tmp/astral-sdk-samples-20261005-target`，不启用共享服务或数据库迁移。所有命令 timeout 600 秒，retry=0，streamDisconnect=false，stdout/stderr 合并完整保存并有 SHA-256；退出码均为 0。

| suite | 精确命令 | UTC 开始/结束 | 单调秒 | 结果 |
|---|---|---|---|---|
| workspace | `cargo check --workspace --offline --locked` | 17:47:09.304676 / 17:47:26.473442 | 17.168 | PASS |
| workspace | `cargo clippy --workspace --offline --locked -- -D warnings` | 17:47:26.473695 / 17:47:30.869159 | 4.395 | PASS |
| workspace | `cargo test --workspace --offline --locked -- --nocapture` | 17:47:30.869409 / 17:49:40.381695 | 129.510 | PASS；2765 passed、0 failed、86 ignored |
| workspace | `cargo fmt --all -- --check` | 17:49:40.382944 / 17:49:41.535817 | 1.153 | PASS |
| samples | `cargo check --manifest-path integrations/Cargo.toml --workspace --offline --locked` | 17:47:09.304678 / 17:47:10.214223 | 0.909 | PASS |
| samples | `cargo clippy --manifest-path integrations/Cargo.toml --workspace --all-targets --offline --locked -- -D warnings` | 17:47:10.214490 / 17:47:13.179631 | 2.965 | PASS |
| samples | `cargo test --manifest-path integrations/Cargo.toml --workspace --offline --locked -- --nocapture` | 17:47:13.179885 / 17:47:19.244938 | 6.065 | PASS；12 passed、0 failed、0 ignored |
| samples | `cargo fmt --manifest-path integrations/Cargo.toml --all -- --check` | 17:47:19.245329 / 17:47:20.471522 | 1.226 | PASS |
| samples | `cargo tree --manifest-path integrations/Cargo.toml --workspace --offline --locked --prefix none --format '{p}'` | 17:47:20.471901 / 17:47:20.555764 | 0.084 | PASS；禁止依赖为空 |

命令级环境、精确时间、退出码、完整日志路径/hash、ignored/内部 SKIP 和 postcondition 已记录在本机 `.zcode/evidence/sdk-integration-v1-final-20261006/` 的 workspace 与 samples results 中；`.zcode/` 由仓库忽略，不作为 PR 文件发布，本记录保留可移植的结果摘要。

日志 hash 核对全部一致；两个 suite 的 snapshot 内容 hash 与门禁完成时工作区一致。`git diff --check` 通过。SDK/迁移说明/样板 README 相对文件链接检查通过。

### 测试覆盖解释

- workspace 2765 passed 包含既有测试和本次新测试，不是 2765 项 SDK 新增测试；contracts 8、SDK core 4、Axum adapter 2 项单元测试均实际执行。
- workspace 86 ignored 为框架 SKIP，含 76 项真实依赖集成、6 项手工性能 probe/matrix 和 4 项文档示例；新 mapping 的两项真实 MySQL 测试均 ignored，未执行。
- 两个 suite 的日志内部 `[SKIP]` 均为 0。`RUST_INTEGRATION_REQUIRED` 已清除，未运行显式 ignored integration；命令退出 0 不代表这些集成通过。
- 日志两条 `error: aborting due to 1 previous error` 对应既有 CrossCityVerifiedEvidence 的预期 compile_fail doctest；两项均 `compile fail ... ok`，不是失败测试。
- 独立 12 项测试含 SDK 实际回环 HTTP、Axum layer/一次 proof/local commit、真实回环 WebSocket 握手/逐帧撤销/重连，以及本地 scope/revision/幂等/故障矩阵。模拟 MissingMapping/StaleSession 等响应仅证明客户端合同，不证明平台数据库状态。
- 禁止依赖断言覆盖 `astral-db`、`astral-common`、`astral-types`、`policy-engine`、`astral-mq`、`sqlx`，实际依赖树均没有这些包。

### 最终冻结证据

本记录完整门禁对应 runId `sdk-integration-v1-final-freeze-20261006`，再次执行上述九条命令且全部 exit 0，计数与首轮一致。最终精确时间、退出码、内容 snapshot 和最终对账保留在本机 `.zcode/evidence/sdk-integration-v1-final-freeze-20261006/`，不覆盖首轮证据、不作为可移植链接发布。发布前仅移除本记录中的本地 artifact 链接；代码和契约没有变化，提交前仍复核工作区、内容 hash 与适用门禁。

最终对账核对命令/log SHA-256、全体 tracked+非 ignored untracked 文件内容、代码相对首轮无漂移、最终分支/范围、相对链接和临时资源清理。构建 target 在门禁结束及确认无任务进程后清理，日志/snapshot/results 保留；不以 inode、设备号或 ACK 代替内容或 durable proof。

## 失败与接管记录

- 首次 `apply_patch` 不可用，exit 127；检查 git/diff 确认无写入后使用 dedicated Write/Edit。没有重复 durable 业务动作。
- 早期编译/测试发现请求主体或 route/resolver shape 不一致、Axum body 借用 future 非 Send、Router state、test helper 可见性、SDK 测试未接回等问题，均修正后重新验证，不扩大生产接口或放宽断言。
- 早期 workspace 测试两项失败是 DDL 排版敏感断言和旧 migration tail；保留安全断言，改为列形状 token 检查并登记新 additive tail。
- 严格 clippy 曾拒绝复杂 tuple、过多参数、大 Response error 和 unused import；用局部 FromRow/MappingAudit/MappingHttpError 类型解决，无新增 lint 豁免。
- nested workspace/lock 和 yanked 离线解析问题通过自包含 manifest、沿用既有 lock 后规范解析解决，没有联网升级依赖；本任务早期生成的嵌套 lock/target 已核对后清理。
- audit_log 引擎证明、管理端 UnknownCommit/CAS 状态、字节 key grammar、实际时钟、path-target/重叠清单、稳定 operation ID、回环代理和 structured audit detail 等主审缺口均已修复；冻结后日志与内容 hash 无未知漂移。

以上历史失败没有被改写为 PASS；首轮及最终门禁针对修复后的快照重新执行。最终命令没有 timeout/runner 断流或未知退出码；真实外部业务 postcondition 则没有执行，不声称已证明。

## 未执行与残余风险

| 状态 | 未覆盖项及原因 |
|---|---|
| BLOCKED，未启动 | 真实 MySQL metadata、映射创建/停用/CAS/并发/管理员撤销、COMMIT unknown 与崩溃恢复；缺受保护隔离环境与迁移/source mutation 批准。 |
| BLOCKED，未启动 | 真实 Gateway/JWT/session、strict published projection、SoD/fence 故障、MySQL/MQ、多节点、迁移/备份恢复/部署验收；本次批准不包含这些外部影响。 |
| SKIP | Cargo 86 ignored，包含新 mapping 两项；未执行显式 ignored 命令，不能计 PASS。 |
| 未执行，范围外 | 旧 excluded Chat/Learn/cache 的专用 gate；其源码未改，根 workspace 命令不覆盖它们。默认 feature 以外的 Redis compatibility 及全 feature 矩阵未验证。 |
| 未执行，范围外 | 专门的重复 evaluate/recheck 性能 benchmark；完整准入额外读取和评估成本仍需受控测量。 |

远程准入和本地业务 commit 非原子；5 秒 TTL 不能消除跨系统撤销窗口。非 Clone proof 只限制同一内存对象消费，不能承诺分布式 exactly-once。Chat/Learn 使用有界内存 ledger/receipt，生产业务必须持久化 operation/payload/receipt 与自身事务/outbox并对账未知结果。

准入 audit_log 没有 request/phase 唯一键，只有 single-attempt/未知结果对账语义；ASSESSED 不证明响应送达或业务提交。映射 audit/source/ledger 的同事务语义和 preflight 元数据仍需真实 MySQL 验收。V1 不开放任意 IdP、不自动建卡授予权限、不实现旧 Chat/Learn 完整业务迁移或生产切流。
