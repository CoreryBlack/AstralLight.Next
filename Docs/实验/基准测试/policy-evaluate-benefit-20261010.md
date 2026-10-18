# 完整 PolicyEngine.evaluate 装配缓存收益实验

> 日期：2026-10-10。状态：本地 CPU 矩阵采集 PASS；不是 HTTP、真实数据库或部署验收。
> 首轮测量：`policy-evaluate-benefit-20261010-release-v1`。本文只分析这一轮，不混合历史 hub-only 数据或后续复跑数据。

## 结论与归因

45 个 case 均观察到完整 `PolicyEngine.evaluate()` 平均决策耗时改善：配对批次几何平均的 `forced / cached` 时间比为 **1.392–4.393**，对应约 **28.1%–77.2%** 的平均耗时下降。配对 `cached / forced` 批次吞吐比为 **1.359–4.092**。45 个时间比的探索性 bootstrap 95% 区间下界都大于 1；这是同一机器、同一次运行内的结果，不是经过多重比较校正或独立复现实验的统计保证。

当前不存在跨 repository/engine 的共享 Arc evidence 或共享决策接口。生产装配缓存内部持有 `Arc<PublishedCardAuthorization>`，但 hub 返回 `(*evidence).clone()`，`RuleRepository` 和评估器仍消费 owned evidence。成功 ALLOW 仍执行初始读取和最终复读。因此本实验识别的是**现有装配缓存复用相对每次生产 miss/重装配的完整 CPU 评估收益**，不能把倍数归因于 Arc 指针操作本身，也不是与旧版本完整实现的 A/B 对比。

生产时钟组的实际命中率为 **99.653%–100%**，每 case 的批次平均决策耗时中位数相对理想热组为 **0.987–1.030**。该组从预热状态开始，没有请求间停顿或 source churn，不能外推真实业务流量中的命中率。其尾延迟并不始终接近理想热组：128 grants、单线程、首命中 ALLOW 的生产 P99 为 **527.833 us**，理想热组为 **200.416 us**，约 2.63 倍；该 case 的生产读取全命中，不能简单归因为缓存 miss。本次没有调度/频率观测，尖峰来源保持未归因。

## 测量对象

- 入口为真实 `PolicyEngine.evaluate()`，从调用开始计时至 awaited `PolicyDecision` 返回。
- 保留引擎 AUTHN/context、卡片检查、资源 ownership、ORG 分类、published-evidence 校验/匹配、ALLOW 最终复读、统计和断路器开销。
- synthetic publication、卡片/身份和 Unmanaged ORG 由本地 port 提供；身份固定为 PLATFORM_USER、identity_card 18、user 42、card 17、tenant 7、domain 11，目标为同租户 TenantScoped 资源。
- 所有 grants 永久有效，资源/动作和实际有效首尾 grant 一致；两次证据读取的 generation、dependency、READY、scope 与 token recheck 保持启用。
- **不包含** Gateway 签名、HTTP/socket、真实 MySQL 身份/资格/managed ORG、durable audit delivery、SDK 映射、业务 handler、分配计数或线上容量。
- release 单测构建仍包含测试计数器和端口计时；不是直接部署二进制的性能。

## 冻结设计

三组共用同一个 case 的引擎、上下文和 publication maps，每次测量使用独立装配缓存，防止组间缓存污染：

| 组 | 控制 | 实际检查 |
|---|---|---|
| `cached-fixed-second` | 固定有效秒；真实 1 秒 TTL 不关闭；4 次预热 | 所有证据读取必须是装配缓存命中 |
| `forced-assembly` | 每次读取使用唯一 synthetic 秒；预热使用固定秒 | 零命中；保留真实 production miss、assembly、refill 和 token recheck 成本 |
| `production-clock` | 实际 UTC 秒与真实 TTL | 记录实际命中与 miss，不要求全命中 |

三组均承担相同共享原子 tick 成本。强制 miss 是受控反事实：不禁用生产缓存、不新增 no-cache 算法、不绕过安全 gate，但并不等同于一份历史无缓存实现。

冻结 topology 为 1/8/128/512/2048 grants × 1/4/8 OS threads × 首命中 ALLOW/尾命中 ALLOW/无匹配 DEFAULT_DENY，共 45 case。每 case 18 个配对批次，全部六种组顺序各执行三次，不删除异常值。每线程每批次请求数固定为 `{1:256, 8:256, 128:96, 512:32, 2048:16}`。

实际完成 **810 配对批次、2,430 组测量、1,381,536 次评估、2,302,560 次 scoped evidence 读取**。每组 460,512 次评估、767,520 次证据读取；每次 ALLOW 两读、DEFAULT_DENY 一读。所有完整决策与 expected result 一致，PENDING/mismatch/legacy read 为零，所有 worker 已 join。PENDING、跨秒过期、最终复读过期和最终撤权拒绝在独立控制中验证，不以早期拒绝冒充快路径。

延迟不包含返回后的结果断言、记录和销毁。吞吐的 batch wall 包含 barrier 唤醒、结果核对/记录/销毁、聚合和 worker join，不含显式 thread/runtime 构造与缓存预热。因此吞吐不是“延迟倒数”或服务 QPS。

## 配对结果

下表为 18 个批次均值时间比的几何平均，括号内为固定 seed、2,000 次 bootstrap 的探索性 95% 区间。比值大于 1 表示缓存组更快；不得将区间理解为 45 次比较校正后的部署置信区间。

| Grants | Threads | 首命中 ALLOW | 尾命中 ALLOW | DEFAULT_DENY |
|---:|---:|---:|---:|---:|
| 1 | 1 | 1.499 (1.460–1.545) | 1.469 (1.454–1.484) | 1.392 (1.372–1.407) |
| 1 | 4 | 2.691 (2.676–2.706) | 3.068 (2.863–3.286) | 2.302 (2.228–2.369) |
| 1 | 8 | 3.525 (3.473–3.587) | 3.710 (3.665–3.754) | 2.574 (2.500–2.632) |
| 8 | 1 | 1.544 (1.514–1.598) | 1.513 (1.504–1.523) | 1.485 (1.470–1.498) |
| 8 | 4 | 4.179 (4.126–4.229) | 4.126 (4.075–4.174) | 3.647 (3.585–3.712) |
| 8 | 8 | 4.393 (4.303–4.473) | 4.110 (3.974–4.235) | 3.768 (3.686–3.852) |
| 128 | 1 | 1.702 (1.599–1.880) | 1.594 (1.586–1.601) | 1.593 (1.583–1.602) |
| 128 | 4 | 2.156 (2.141–2.170) | 2.188 (2.165–2.210) | 2.280 (2.251–2.309) |
| 128 | 8 | 2.250 (2.221–2.278) | 2.411 (2.337–2.493) | 2.707 (2.647–2.761) |
| 512 | 1 | 1.605 (1.598–1.611) | 1.615 (1.604–1.627) | 1.603 (1.591–1.616) |
| 512 | 4 | 1.949 (1.928–1.971) | 1.990 (1.954–2.029) | 1.976 (1.949–2.005) |
| 512 | 8 | 2.258 (2.229–2.285) | 2.261 (2.246–2.276) | 2.245 (2.213–2.279) |
| 2048 | 1 | 1.622 (1.607–1.637) | 1.634 (1.593–1.689) | 1.614 (1.591–1.638) |
| 2048 | 4 | 1.963 (1.931–1.995) | 1.942 (1.908–1.978) | 1.959 (1.918–2.002) |
| 2048 | 8 | 2.170 (2.149–2.187) | 2.191 (2.160–2.220) | 2.115 (2.038–2.177) |

代表性的尾命中 ALLOW pooled P50/P99（单位 us，未做 outlier trimming）：

| Grants / threads | 缓存 P50 | 强制装配 P50 | 生产 P50 | 缓存 P99 | 生产 P99 |
|---|---:|---:|---:|---:|---:|
| 1 / 1 | 3.666 | 5.375 | 3.667 | 4.667 | 4.708 |
| 8 / 1 | 13.333 | 20.208 | 13.375 | 17.375 | 16.375 |
| 8 / 8 | 31.875 | 147.208 | 31.458 | 104.125 | 102.541 |
| 128 / 1 | 175.834 | 280.000 | 175.958 | 195.541 | 196.416 |
| 512 / 1 | 695.542 | 1122.000 | 697.458 | 763.625 | 762.166 |
| 2048 / 1 | 2725.125 | 4378.500 | 2726.000 | 3474.792 | 3468.833 |
| 2048 / 8 | 5726.583 | 12915.209 | 5827.500 | 8635.416 | 8840.209 |

全部 45 case 的逐决策延迟、吞吐和 phase summary 以 canonical `result.json` 为准。表格是可读摘要，不是新的独立 evidence。

## 阶段分析

以下为单线程尾命中 ALLOW 的逐决策平均，单位 us。残余是完整 evaluate 耗时减去初始/最终 hub 端口区间，不是新增引擎内部 phase 指标。

| Grants / arm | 初始端口 | 最终端口 | 残余 evaluate | 端口占完整均值 |
|---|---:|---:|---:|---:|
| 8 / 缓存 | 1.985 | 1.994 | 9.612 | 29.3% |
| 8 / 强制装配 | 5.481 | 5.463 | 9.623 | 53.2% |
| 2048 / 缓存 | 395.799 | 392.700 | 1967.187 | 28.6% |
| 2048 / 强制装配 | 1253.328 | 1257.102 | 2006.349 | 55.6% |

这两例的主要耗时差与 hub 端口成本下降一致，但缓存并未消除 owned cloning、evidence validation 或最终读取。热组残余约占 71%，因此不能用 hub-only 的加速比替代完整评估加速比。多线程时还混合了同一热卡上的 cache mutex、refill 与共享统计竞争；8 grants/8 threads 的大幅收益不能解释为 Arc 的独立因果收益或多租户部署扩展性。

## 环境与证据

- CPU：Apple M5，10 个 physical/logical CPU；内存 16 GiB。
- OS：macOS 26.5，build 25F71；目标 `aarch64-apple-darwin`。
- Rust：1.99.0，commit `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`；LLVM 23.1.1。Python 3.11.17。
- 仓库 release：`opt-level="s"`、thin LTO、codegen-units=1、debug none、strip symbols；不是 opt-level=3。构建 jobs=4，Cargo offline/locked，隔离 target。
- 基线 HEAD：`9c25be862a7b9e9c71c18f17961c93863776a9e3`；分支 `test/native-security-claims`，包含保留的未提交 native-security 工作。
- 首轮完整源码内容 SHA256：`96e683b6724bb4e2abd74fe34034368f962e132dd4705c270f78fb7def5c72ec`。
- UTC 起止：`2026-10-10T12:42:04.247325Z` 至 `2026-10-10T12:44:18.752874Z`；campaign 墙钟 134.506 s。benchmark command 131.377 s，包含 release 重编译，不等于纯测量时间。
- benchmark stdout SHA256：`58fb81f2a788d5bff011d21ab11d65d1be56554829faa9cda625b0767bceb4a8`。
- benchmark stderr SHA256：`264423dfc822810f3dcff23d6794fccf3faa42c9f4c6b6977238fcc23c48ca45`。

本机原始 evidence 保留在 run-owned 目录，另在 `$HOME/.zcode/evidence/policy-evaluate-benefit-20261010-KQddLXCb06/` 留存相同字节的归档。其 `policy-evaluate-benefit-20261010-release-v1/result.json` 包含 raw meta、45 case 的全部样本、end、独立计算的 summary、命令、时间和 postcondition；`collection/` 包含完整 stdout/stderr。归档中的绝对执行路径指向原始 run 目录，不改写 canonical 记录。

结果文档和导航落盘后，使用新 runId 从最终快照重跑 required local gates 和相同三项 selection；该复跑是独立 evidence，不覆盖或合并 v1，也不把本文数字冒充其测量值。`task-evidence.json` 记录最终验证状态、精确命令、失败修复、delegation review、文件范围和未执行项。

## 发布范围

本次实验以独立分支 `test/policy-evaluate-benefit-20261010` 从上述 `main` 基线提取，
只发布完整评估测试、严格验收器、三个 suite 注册、runner 接线和本文/导航；
不夹带原工作区先前未提交的 native-security 模型、签名中间件集成或其依赖改动。
上面的 v1 数字与源码 hash 保持原始采集含义，不改写为独立交付分支的结果。
独立分支的提交前 workspace gate 和完整 release 矩阵另以冻结源码重新执行，
其状态在对应 PR 验证说明中记录，不覆盖或合并 v1 样本。
原始 canonical 日志、逐决策数据及完整源码归档仍保存在本地私有 evidence 目录，未随 Git 发布；
公开文件提供实验实现、复跑入口、测量方法、摘要、hash 和限制，不冒充已公开全部原始 artifact。

## 复跑入口

从此 Rust 仓库根目录运行，使用 Python 3.11+ 和隔离的 `CARGO_TARGET_DIR`、仓库外 artifact root；实际 runId 不得复用：

```bash
CARGO_BUILD_JOBS=4 CARGO_NET_OFFLINE=true python3 -B scripts/test_campaign.py \
  --run --suite policy-evaluate-benefit-controls \
  --suite policy-evaluate-evidence-contracts --suite policy-evaluate-benefit \
  --run-id policy-evaluate-benefit-<unique-run-id> \
  --artifact-root "$EVIDENCE_ROOT"
```

runner 按 manifest 顺序执行，不按 `--suite` 参数顺序重排。Rust 子命令是精确 release ignored matrix，输出正常 footer 中的 864 filtered tests 表示未选的其他 Rust 测试，不表示 45 个性能 case 被过滤；缺少任一 case 仍 FAIL。

验收器拒绝 debug、缺项、重复、乱序终态、早期 ALLOW/DENY、scope/count/cache/timing 不一致和不完整结束证明；中断仍 UNKNOWN。13 项专用验收测试包含零收益和负收益的成功采集，采集 PASS 不设速度阈值。另有 65 项 campaign 路由/失败优先级测试和 Rust 正向/过期/撤权控制。

## 适用与未执行

本次不修改生产授权逻辑、pub API、schema、消息、事务或审计 owner。五链审查适用于测试适配器和 evidence 合同；生产变更五链 N/A，最终复读/租户 scope/拒绝语义仍以控制测试核对。测试按 fixture、controls、measurement 分模块，未继续叠加生产大文件职责，未扩大共享接口。

未执行真实 MySQL/RabbitMQ/Redis、签名 HTTP/socket、跨节点、崩溃恢复、migration、部署、SDK 和业务 admission。无新真实服务或权限 mutation，无 commit/push。workspace 全量和 excluded crates 不由这一局部性能任务证明；最小 local gate 为 astral-db check/clippy/lib tests、相关 Python 合同、格式、diff 和完整 release matrix。

残余限制包括单热卡/单 tenant、perpetual grants、无 source churn、单机单次批次、无 CPU affinity/频率控制、短小微基准的时序相关与测量开销。2048 grants/单线程每组只有 288 次测量，P99 特别不能当作高精度尾部保证。本次未观察到负的配对平均收益，不代表其他负载不存在回退。
