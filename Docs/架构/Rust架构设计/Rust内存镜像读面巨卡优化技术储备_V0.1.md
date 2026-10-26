# Rust 内存镜像读面巨卡优化技术储备（V0.1）

> 状态：**分路线跟踪**。路线一“装配结果缓存”已在当前 checkout 的 `MemoryProjectionHub` 中接线；路线二的单卡授权规模护栏与路线三的证据合同改造仍是未实现/未决事项。本文所列测量是 2026-09-30 本机 debug 历史探针，不是当前缓存收益、release 性能或目标环境容量验收。
> 初始储备日期：2026-09-30；状态复核：2026-10-25
> 来源：极限探针 `limit_records_per_read_scaling`（`astral-db/src/memory_projection_hub.rs` 测试模块）曾量化内存镜像读面的单读记录数悬崖；随后接入的缓存代码见 `astral-db/src/memory_projection_hub/assembly_cache.rs`。各自证据边界不同。

## 1. 问题定义（已量化的极限）

内存镜像读面（`MemoryProjectionHub::try_memory_evidence`）每次读取都从零装配完整的
`PublishedCardAuthorization`：记录构建 + 排序 O(n log n) + 等价去重 + 分配密集。
单读成本随**单卡授权记录数**线性×对数增长，与镜像总卡数无关（卡数探针已确认
512/4096/16384 卡吞吐平坦，索引 O(1)）。

实测（本机 debug 构建，informational；release 会显著更快）：

| 单卡记录数（2 聚合 × N 授权） | 吞吐 | p50 | p99 |
|---|---|---|---|
| 8 | 42,441/s | 21.8µs | 51.1µs |
| 128 | 3,320/s | 241.8µs | 476.6µs |
| 512 | 1,112/s | 872.7µs | 1,447.8µs |
| 2048 | 236/s | 4.2ms | 5.1ms |

**影响边界**：权限域单卡授权通常在几十到几百条（p99 < 100µs 舒适区）；千授权级
"巨卡"才进入毫秒区。且悬崖是相对的——同规模下被替代的 DB 严格 reader 需要等量
分类加 SQL 拉取，成本只会更高；巨卡场景内存路径不劣于现状。

## 2. 路线一：装配结果缓存（源码已接线，性能目标未验收）

### 技术机制

`MemoryProjectionHub::try_memory_evidence` 先验证 scope、镜像健康/来源写入状态、待处理事件、聚合索引和镜像 TTL，再取得 scope 的 `ReadToken` 与已安装 publication states。组装缓存不是授权事实源，而是对这组已验证不可变状态所生成的完整 `PublishedCardAuthorization` 做有界 memoization。

当前实现的 key 与 freshness stamp 有意分开：缓存表按 `RefillScope` 区分 `(tenant_id, card_id, user_filter, domain)`；entry stamp 同时绑定 `ReadToken`（health/source/tenant/card revision）、秒级 `read_unix_seconds`、以及排序后的每份 publication 指针、manifest、generation、source/projected generation、revoke fence 和 digest。任一 stamp 不同或缓存 TTL 到期都 miss 并删除旧 entry。装配后，`try_memory_evidence` 再读 hub 状态核对 token 与健康/写入栅栏；只有复核仍匹配才返回 `Serve` 并填充缓存，避免计算期间状态变化后安装或返回旧镜像证据。

### 当前资源与失败边界

- `assembly_cache.rs` 的上限为 1,024 entries、32 MiB 总估算保留字节、单项 8 MiB，TTL 为 1 秒；LRU 通过单调访问序号驱逐，插入时按 TTL 周期清理过期项。字节数是实现中的保留容量估算，不等同 RSS 精确测量。
- 命中返回 `Arc<PublishedCardAuthorization>`，不做旧文档所说的 O(n) 深克隆。未命中则重新完整装配；过大的单项不缓存但仍可完成本次装配。
- 缓存锁 poisoned 时，读命中返回 miss，写入跳过；因其只保存可重算的派生结果，不能据此使用陈旧缓存放行。scope 校验失败、状态变更、pending/fence/健康异常、镜像过期、装配错误或最终 token 复核失败均返回 `DeferToDurable`，交给权威 DB 路径。
- 缓存 miss 或容量压力影响性能而不改变授权内容。这里记录的是当前源码路径，不证明所有调用方、目标发布配置或真实部署都在运行此读面。

### 状态与证据边界

路线一在当前 checkout 已实现并由 `MemoryProjectionHub` 持有 `Arc<AssemblyCache>`；但本次仅静态核对接线与资源/失效规则，没有运行缓存命中/未命中对照基准。§1 的 2026-09-30 数字是缓存接入前的本机 debug 历史探针，不能当作缓存收益、release 数据或容量预测。旧稿中“命中成本 1/10–1/20”“2048 records 降至 0.2–0.4ms”是未验证预测，不能视为现测量。内存镜像外层还有独立镜像容量/TTL/健康门与 strict read token；装配缓存不能替代 L1 evidence cache、durable pointer 对牌或 strict evidence contract。

## 3. 路线二：模型层护栏——巨卡反模式（仍待设计/验证）

单卡挂载大量 effective grants 会增加完整证据装配、记录校验与审计对账成本；装配缓存只降低重复相同状态的重算，不能降低首次装配、换代后重建、不同 user/domain scope 的 miss，也不能消除数据模型本身的高扇出。

当前源码包含全局镜像状态/字节/索引容量上限，但静态检索没有发现旧稿所建议的“单卡 effective grants 超过约 500”业务规模护栏。该数值源自旧 debug 探针下的舒适区判断，并非批准阈值或现行合同。

可评估的方向包括：只产生结构化观测告警（不阻止授权写入）；在 source mutation/规则绑定入口实施有审批及迁移兼容的硬上限；或按规则集/授权域优化数据分布。它们分别影响治理可见性、兼容性与授权数据模型，不能以一个局部计数检查替代授权 owner、规则集语义或拒绝原因。阈值、作用范围、超限写入行为、旧数据处置与告警责任都尚未决策。

## 4. 路线三：结构性合同改造（挂起，不推荐现在做）

- **方案 A（decision-optimized 证据形态）**：正式读只返回镜头内有效授权，跳过
  完整 provenance records。代价：动 `PublishedCardAuthorization` strict evidence
  合同——完整 records + walked 数与声明数对账是审计完整性的根基，合同变更的
  验证成本与回归面大。
- **方案 B（按 ProjectionKey 分段跳读）**：HotState segment 已按 key 分区，
  user-lens 读理论上可跳过无关 segment。代价：受"walked 数必须等于声明总数"的
  合同约束，绕过即违反证据完整性；需同步改造合同。
- 仅当路线一 + 路线二实测仍不够时才评估；评估前必须先完成合同影响分析。

## 5. 实施门禁

- 当前代码仅证明路线一装配缓存已接线。路线二新增规模策略、路线三改变 strict evidence contract，分别需要自己的计划/评审/验证；若要宣称性能收益，还需在目标配置和硬件上测量命中/未命中、发布换代、失效与 durable fallback。
- 本文全部数字为 debug 构建本机历史数据；release 与目标硬件需重测后再做取舍。缓存源码/测试本身不证明生产性能改善。
- 性能回归至少应单独比较 assembly cache 命中、未命中、秒级时间桶变化、publication stamp 变化与最终 token recheck 失败场景；基准数据应另存为对应快照证据，不与本文 2026-09-30 debug 数字混写。

## 6. 决策记录

- 2026-09-30：极限探针发现单读记录数悬崖后，记录三条优化路线；当时的用户决策是“作为储备、之后评估”，不是授权全部路线实施。
- 2026-10-25：源码复核确认路线一 assembly cache 已在当前 checkout 中实现并接入 `MemoryProjectionHub`；这项后续代码变化不改写 2026-09-30 的历史决策，也不证明预测性能收益已达到。路线二单卡规模策略与路线三证据合同改造仍未实施/未决。性能结论需以带明确构建、硬件和快照指纹的新测量为准，不能把旧 debug 数字或本文当前文案当作 release/生产验收。
