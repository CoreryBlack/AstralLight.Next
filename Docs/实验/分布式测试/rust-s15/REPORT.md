# Rust 三节点分布式一致性（S1–S15）与分布式性能 · 实验报告

> 运行标识：`rust3n-dist-20260830`（部署目录 node-b `~/astral-f4rust-20260830`，端口 9105/9106/9107）
> 执行日期：2026-08-31
> 被测二进制：`astral-trustgraph` release（快照 `~/astral-rust3n-20260830`，与归档 commit `928efe0e` 世代一致）
> 对标文档：[`Docs/实验/分布式测试/README.md`](../README.md)（Java RemoteClusterAuthorizationTest S1..S15 场景注册表，不变量 I1..I13）

> 历史证据边界（CURRENT V6）：本报告完整保留 2026-08-31 的三节点、共享 MySQL/Redis/Rabbit
> 实验事实及 `PASS`/`FAIL`/`N/A` 结果；这些结果只用于历史比较、故障分析和测量方法回溯，
> 不代表当前 Rust runtime、当前 Redis 依赖或真实集成 `PASS`。Redis 相关夹具、停机注入和
> 旧 worker 结论属于 retired compatibility evidence；当前 native 验收不得复用本报告数值。
> 未经完整 receipt、canonical generation/published-evidence barrier 和独立对账，任何
> `UNKNOWN`/`PENDING` 仍不是完成或成功。

## 1. 结论摘要

**一致性（S1–S15，2 轮，95 条断言）：79 PASS / 10 FAIL / 6 N/A。**
FAIL 全部收敛为三类且均有解释（见 §4）：S1 并发首写的 delta 版本冲突（产品发现 F6）、
S5/S10 的 lease 绊线时序伪失败（核心不变式本身全部 PASS，DB 复核佐证）、
S6 的一次投影落地前采样伪失败（DB 复核 12/12 PROCESSED terminal=1，补充重跑 PASS）。

**性能（三节点真实网络/共享 MySQL/专用 Redis）：**
- 授权评估基线：node-b 15–28ms（p50），node-c 16–20ms，node-a 36–44ms（VMware 慢节点）；
  8 线程吞吐 node-b/c ≈ 390–410 QPS（V2 干净窗口实测；V4 归档轮因前序 storm 积压回放降至 42–54，见 §5.4 口径说明）。
- **撤销传播 ε（revoke→三节点可见）：S2 紧采样 445/445 无 stale ALLOW**（撤销后首个采样即 DENY，窗口 8.1s 内全节点收敛）。
- P2 交替变更：grant 传播 p50≈251ms / p95≈2073ms；**同聚合第 2 次及以后的 REMOVE 证据传播停滞 >30s（发现 F7）**。
- 跨节点并发写（3 节点同时写同一规则集）：28.5 ops/s（573 ops），outbox 575 行全部 PROCESSED、
  terminal_transitions==1、世代连续无丢失（I1/I4 在风暴负载下成立）。
- 读扩展：3 节点各 1 线程聚合 91.8 QPS（客户端签名/单进程为瓶颈，非服务端上限）。

**产品发现（供后续修复，均有一手证据）：**
| 编号 | 发现 | 证据 |
|------|------|------|
| F3 | `authorization_projection_head` 的 projected_generation/projection_status 为旧通道退役列，新管线不维护（恒 0/PENDING） | 全部场景 head vs pointer/delta 对照 |
| F5 | **Redis 停机永久停摆三节点 delta worker**（进程仍响应 HTTP，只有重启进程恢复）；S15 停机后所有后续投影停摆 | V5→V6 轮间 delta 全部 PENDING attempts=0 |
| F6 | **并发首写触发 delta target_version 冲突**：同聚合两条并发 ADD 均落在 target_version=1，uk_ade_target_version 使其一无法发布，聚合证据链卡死（S1 两轮复现：deltas=[1,1] all_ok=False） | s15_result.json S1_* |
| F7 | **（已并入 F5——复检结论）**P2 的"REMOVE 停滞"为测量伪影：V4 的 prop 规则集 32 条 delta（16 ADD+16 REMOVE）全部 `PENDING, attempts=0`（无 worker 认领），grant 的"收敛"来自 L2 缓存 TTL(300s)+陈旧指针的假象。根因 = F5 的 worker 挂起。需在 F5 修复后重测 P2 才能给出干净的 ADD/REMOVE 传播分布 | 9269 号规则集 delta 状态（2026-08-31 复查） |
| — | POST /arbiter/arbitrate 被路由门结构性阻断（/arbiter→monitor + POST→未注册动作 create，任何规则都无法授权，403 DEFAULT_DENY） | S12/S13 N/A 记录 + 403 响应体 |

S12/S13 的语义证据由同源快照的 canonical 契约测试承担：
`cargo test -p policy-engine --lib arbiter::` → **12 passed / 0 failed**（含 s12_conflicting_decision_arbitration_denies、
s13_arbiter_unavailable_fails_closed、version_agreed_tie_fails_closed 等）；源快照未包含原始日志 `arbiter_contract_tests.log`。

**各项问题的具体修复方案见 [`FIXPLAN.md`](FIXPLAN.md)**（含源码定位、改动清单、验证方法与实施顺序）。
注：F7 经复检已并入 F5（worker 挂起的测量伪影，见 FIXPLAN 修复 1/复检说明）。

## 2. 场景 → Rust 机制映射（与 Java 的差异，如实记录）

| 场景 | 不变量 | Rust 映射 | 结论（2 轮） |
|------|--------|-----------|--------------|
| S1 并发首投影 | I1/I4 | 两节点并发 ADD 同类型条目 + 绑定；证据 = outbox 完整性 + delta SUCCEEDED | 并发写源侧 2×200 ✓、generation 单调 ✓；**delta 冲突卡死（F6）→ FAIL** |
| S2 撤销可见性 | I2/I8 | 删条目 → 8s 紧采样 + 全节点收敛 | **PASS（445/445 无 stale ALLOW，8.1s 全节点 DENY，delta SUCCEEDED）** |
| S3 乱序 READY 不复活 | I2 | durable 层映射：同世代 delta 重放被 `uk_ade_target_version` 结构性拒绝（世代栅栏 = schema 约束） | **PASS（注入被拒、指针不回退、无复活行）** |
| S4 解绑传播 | I7 | unbind → revoke fence 推进 + 全节点 DENY → 重绑恢复 | **PASS（fence 0→1，DENY/ALLOW 传播均 <1s）** |
| S5 lease reclaim | I3 | SIGSTOP a/c → 突发提交 → SIGSTOP b 绊住 claim→publish 窗口 → a/c 到期 reclaim → b 恢复不得二次终态 | reclaim/唯一终态/无二次终态 **PASS**；绊线捕获 0/2（时序，见 §4.2） |
| S6 交替变更 | I4 | 5×（add→3 节点 ALLOW→del→3 节点 DENY），generation 单调 | 行为收敛 **PASS**（V8 两轮 + 补充重跑均 PASS）；outbox/delta 结构断言受 delta-lag 抖动（R1 伪失败，DB 复核 12/12 PROCESSED terminal=1 delta 全 SUCCEEDED；重跑 delta 未全落地——delta worker 延迟与 outbox 解耦，见 §4.3） |
| S7 幂等残留不抑制失效 | I5 | Rust 语义映射：毒化 L2 键后真实变更，决策不被残留污染（失效靠值内世代标签/完整性校验，不物理删键——键存废作为机制证据记录） | **PASS（毒化残留存在下 3 节点 DENY 正确）** |
| S8 ABAC 属性变更 | I6 | Rust rule_set_entry 契约无属性条件列 | **N/A（不进分母）** |
| S9 mutation storm | I2/I4 | 6 add + 6 del 交替，期间采样 + 完整性 | 行为 **PASS**（storm 期间 ALLOW、post-delete 无 stale）；generation 断言 R2 PASS / R1 因采样时序 FAIL |
| S10 并发 projector CAS | I1 | 突发提交中 SIGSTOP 绊住已 claim 行 → lease 有效期内 a/c 不得 steal → 到期 reclaim → 唯一终态 | 唯一终态/无重复 **PASS**；绊线捕获 0/2（时序） |
| S11 决策证据链自洽 | I9 | sim3 决策 + reason(`published:`) + matchedRuleId 跨节点同源核对 | **PASS（grant/revoke 两方向）** |
| S12 冲突仲裁 | I10 | 远程控制面被门阻断（见上）；契约测试 12/12 PASS | N/A（远程）+ 契约 PASS |
| S13 仲裁 fail-closed | I11 | 同上；空证据 4xx PASS | N/A（远程）+ 契约 PASS |
| S14 进程崩溃不复活 | I12 | revoke 提交后 kill -9 node-c → 停机窗口采样 node-b → 重启 → 全节点 DENY | **PASS（停机 0 stale ALLOW，重启后全 DENY）** |
| S15 Redis 停机不复活 | I13 | revoke → docker stop 专用 Redis → 采样 → start → 全节点 DENY | **PASS（0 stale ALLOW，全节点 DENY）** |

分母口径：一致性分母 = 2 轮 × (15 场景 − 1 个 N/A 场景 S8) 的行为断言 + 结构断言；
S12/S13 远程路径 N/A 不进分母，契约证据单列。

## 3. 运行环境与可复现

- 三节点：node-a `<node-a-host>:9105`（VMware，慢）、node-b `<node-b-host>:9106`（Xeon 物理机，与中间件同机）、node-c `<node-c-host>:9107`。
- 共享中间件（node-b）：MySQL 8.0 :3308（run 库 `astral_f4rust_dist_20260830`，116 表 = canonical schema + F4 种子）、专用 Redis 7 容器 `astral_dist_redis_f4rust` :16381、RabbitMQ vhost `rust3n_dist`（仅 audit 消费）。
- 复现：[`deploy_dist.sh`](deploy_dist.sh)（8 步：schema 克隆→专用 Redis→vhost→配置/秘钥→分发→启动→就绪→run_config.json），
  然后 `python3 -u s15_coordinator.py --rounds 2`、`python3 -u s15_perf.py`（均需同目录 run_config.json，0600，不入库）。
- 种子：[`seed_f4rust.sql`](seed_f4rust.sql)（9011–9091 ID 段；用户/卡/规则集种子）。

## 4. 失败与证据边界（PASS/FAIL/KNOWN 判定依据）

### 4.1 S1（F6，产品发现）
两轮均：源侧 2×200、outbox 2 行、head src=3 ✓；但两条并发 ADD 的 delta 均落在
target_version=1（`gens=[1,1]`），uk_ade_target_version 使其一无法发布，聚合证据链卡死，
评估侧持续 `no-matching-grant`（40s 不收敛）。**这是并发首写在当前实现下的真实缺陷**，
不是测试伪影。修复方向：target_version 分配去中心化（写侧 CAS 预占）或冲突 delta 合并。

### 4.2 S5/S10 绊线捕获（伪失败，不变式本体 PASS）
SIGSTOP 时点（突发提交后 150ms）落在 projector 轮询空窗，未捕捉到 claim→publish 中间态
（`stranded=0`）；但同一场景的 I3/I1 核心断言全部 PASS：
reclaim 后 outbox 全部 PROCESSED、每行 terminal_transitions==1、旧 owner 恢复后无第二次终态、
无双 steal。判定：**观察手段时序受限（FAIL 如实记录），不变式判定以同场景其余断言 + DB 复核为准**。

### 4.3 S6 投影落地前采样 / delta-lag 解耦（伪失败 + 机制备注）
R1 的 outbox 断言在末行 delete 投影落地前采样（all_processed 尚为 False）。DB 复核：
12/12 PROCESSED、terminal_transitions 全 1、10 delta 全 SUCCEEDED。补充重跑（`--only S6`）
行为断言 PASS，但 delta 完整性断言仍 FAIL——**delta worker 的落地与 outbox 的
PROCESSED 是两条独立时序**（delta 滞后可达数十秒），结构断言需以 delta 队列自身
收敛为准。见 [`s6_retry.json`](s6_retry.json)。R2 同场景 PASS。

### 4.4 性能口径说明
- V4 归档轮的 P1/P2 在清理 20 个遗留绑定后立即测量，前序 storm 积压（487 delta）正在回放，
  8 线程吞吐被压低（node-b 53.7 / node-c 42.7 / node-a 10.6 QPS）；更干净窗口（V2 中间轮）
  实测 node-b/c 8t ≈ 390–410 QPS、seq p50 15–18ms（该中间轮 JSON 已被 V4 覆盖，数值仅留存于
  实验记录）。**报告以 V2 为吞吐参考、V4 为归档原始数据**。
- P2 的 revoke 不收敛最初记为发现 F7；复查 V4 prop 规则集 delta 状态（32 条全部 PENDING attempts=0）后**并入 F5**：worker 挂起导致零发布，grant"收敛"是 L2 缓存 TTL 假象。F5 修复后需重测 P2（见 FIXPLAN.md）。
- P4 聚合 91.8 QPS 受客户端（node-b 单进程签名 + requests）限制，不代表服务端读上限。

## 5. 证据文件清单

| 文件 | 内容 |
|------|------|
| `s15_result.json` | V8 归档轮（2 轮）全部断言 verdict + 明细 + timeline |
| `s15_run.log` | 源快照未包含该日志 |
| `s6_retry.json` / `s6_retry.log` | JSON 已继承；`s6_retry.log` 源快照未包含 |
| `perf_result.json` | P1–P4 性能结果（V4 归档轮） |
| `perf_run.log` | 源快照未包含该日志 |
| `arbiter_contract_tests.log` | 源快照未包含该日志；不得以旧通过数证明当前运行 |
| `s15_coordinator.py` / `s15_perf.py` | 协调器 / 性能套件（可复现入口） |
| `deploy_dist.sh` / `seed_f4rust.sql` | 部署脚本 / 种子 |

## 6. 未执行项与残余风险

- S12/S13 远程控制面证据缺失（被路由门阻断，见发现表）——若需远程证据，须先修
  route→permission 映射（/arbiter POST 需落到已注册动作或路由白名单）。
- S5/S10 的 lease 中间态捕获未成功：I3/I1 的"并发抢占"方向仅由终态唯一性反向覆盖，
  未正向观测到 CAS 拒绝瞬间（需要产品侧可观测钩子或更细粒度注入）。
- P2 的 REMOVE 停滞（F7）机制未做源码级定位（现象已两轮复现并有 delta 状态证据）。
- 全部结论基于 run 专属库/Redis/vhost；未触碰共享 `astral_bench_redis` 等其他容器。
