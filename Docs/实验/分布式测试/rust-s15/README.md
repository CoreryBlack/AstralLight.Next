# rust-s15：CURRENT V6 四服务器两半区一致性（S1–S15）+ 分布式性能

本目录公开 final9/S15 的可执行 harness 源码、历史报告/结果副本和安全边界。历史资产继承自私有仓库 S15 提交 `b38aaa7680f6c80e6841d05a17e08cd0e50627b1`，节点地址已脱敏；历史结果只用于回溯场景与测量方法，不代表当前仓库代码或当前部署的验证结果。

> CURRENT V6 证据边界：本目录的三节点、Redis、OPA 和 Chat/Learn 相关叙述均属于历史
> baseline/comparison 或 retired compatibility evidence。历史报告中的 `PASS`、Redis
> 故障注入和真实网络数字保持原样，但不是当前 runtime、当前 Redis 依赖或真实集成
> `PASS`。当前 native profile 不以本 harness 的旧部署合同作为验收入口；`UNKNOWN`/
> `PENDING` 仍需完整 receipt/evidence 对账，不能由旧日志或 ACK 晋级。

**CURRENT V6 S15 四服务器两半区设计入口：** 当前 S15 不是 Redis 停机测试，而是固定拓扑下的 WorkerOwned durable recovery contract。

- 半区 A：`AL1`、`AL2` 配对 `DB1`；半区 B：`AL3`、`AL4` 配对 `DB2`。
- 同一数据库内的两台服务器只能使用 `custom_same_db_channel` 自研同库通道；不得用 RabbitMQ 替代同库路径。
- `DB1` 与 `DB2` 之间的消息只能使用 RabbitMQ；不得用同库通道或跨库直连 SQL 绕过 Rabbit durable outbox/inbox。
- 所有路径都必须保留 source COMMIT 后的 immutable receipt、canonical `messageId`、payload digest、lease/CAS、aggregate lane/epoch/token fence、predecessor order、published manifest/current、strict read-gate 和审计关联。

当前仓库的 `LocalBus`/`LocalProjectionBus` 是进程内 Tokio channel，不是两台物理服务器之间的同库通道；它们不能伪装成 `custom_same_db_channel` 的实现。RabbitMQ 跨机 fanout 已有 canonical envelope、durable inbox、ACK 后置和 UNKNOWN 对账约束。因同库跨机自研通道、四节点部署、半区写入者/接管和分区控制尚未形成当前可执行实现，以下拓扑是 S15 的设计与验收门，不代表 live PASS。

当前 S15 的必测断言为：

1. `S15_source_commit_exact_receipt`
2. `S15_transport_identity_matches_canonical_message`
3. `S15_duplicate_delivery_single_terminal`
4. `S15_unknown_outcome_reconciled_before_retry`
5. `S15_no_stale_allow_during_recovery`
6. `S15_published_evidence_ready_after_reconciliation`
7. `S15_four_nodes_two_database_halves`
8. `S15_same_database_pair_uses_custom_channel`
9. `S15_cross_database_uses_rabbitmq`
10. `S15_transport_scope_mismatch_fails_closed`
11. `S15_half_authority_fence_blocks_stale_writer`

这些名称是当前 Rust coverage contract 的 required cases，不是 live 结果。live
campaign 还必须通过四台受保护服务器、两个隔离数据库、半区成员映射、签名身份、
readiness、故障/分区控制器、同库自研通道、跨库 RabbitMQ、四节点状态、半区权威
fence、split-brain fail-closed 和 durable evidence 前置门；任一缺失均为
`BLOCKED`，不能由离线 contract 或历史 Redis PASS 代替。

## 当前架构边界

本目录仍保留历史分布式/RQ campaign harness，供场景和测量方法回溯；当前 S15
只接受四服务器/两半区拓扑：`AL1/AL2 -> DB1`、`AL3/AL4 -> DB2`。两个数据库
必须是隔离的 source owner；跨库不允许直连 SQL、共享事务或用版本数字/NTP 代替
提交证明。

同库路径的 `custom_same_db_channel` 是两台 AL 之间的自研跨机消息通道，数据库
中的 durable outbox/inbox、operation/message identity、lease/CAS 和 UNKNOWN
对账仍是权威；通道 ACK 只表示应用层阶段完成，不能单独证明 published READY。
跨库路径使用 RabbitMQ durable outbox/inbox、canonical envelope、逐节点 inbox、
publisher confirm 后置结算和 UNKNOWN reconciliation。RabbitMQ 不能被用于同库
路径，`LocalBus`/`LocalProjectionBus` 也不能被用于跨服务器路径。

当前仓库尚未实现 `custom_same_db_channel` 的网络化协议，也没有批准的半区 quorum、
双数据库冲突解决或自动接管协议。S15 可以验证单写者、generation/epoch、lease/token
fence、分区时 fail-closed 和恢复证据，但不能把两半区互相可达、旧内存内容或 Rabbit
liveness 宣称为共识或授权完成。

## 文件清单

| 文件 | 说明 |
|------|------|
| `run_cs_evidence.py` | 证据编排器：按安全顺序执行下列脚本，逐步 manifest（命令/cwd/env 名称/起止/exit/artifact/postcondition/verdict；env 只记名称不记值） |
| `s15_coordinator.py` | S1–S15 一致性协调器（对标 Java 场景，Rust 机制映射见文件头注释） |
| `s15_perf.py` | 历史三节点性能套件（P1 评估基线 / P2 传播收敛 ε / P3 并发写风暴 / P3.5 有界排水 / P4 读扩展）；不属于当前四服务器两半区 gate |
| `deploy_dist.sh` | 历史 fresh-only 三节点部署脚本（schema 克隆→专用 Redis→独立 Rabbit vhost→配置→分发→启动→就绪→run_config.json）；不支持当前四节点/两数据库/双通道拓扑 |
| `seed_f4rust.sql` | e2e 种子（namespace e2e_f4rust_*，ID 段 9011–9091） |
| `REPORT.md` / `REPORT_20260901.md` / `RQ345_REPORT_20260903.md` / `PERF_20260901.md` | 历史报告；已继承，仅作场景与测量方法参考 |
| `s15_result*.json` / `s6_retry.json` / `perf_result*.json` / `rq*.json` | 历史结果；已继承，不代表当前代码/部署结果 |
| `archives/astral-final9-evidence-20260906.redacted.tar.gz` | 历史证据归档脱敏副本；原始 SHA-256 与脱敏规则见 [`archives/README.md`](../archives/README.md) |
| `arbiter_contract_tests.log` | 源快照未包含该日志；不得以旧通过数证明当前运行 |
| `FIXPLAN.md` | 产品级问题（F5/F6/arbiter 门/head 对齐/bind 事件缺口）的具体修复方案 |
| `s15_validation.py` / `test_s15_validation.py` | 当前仓库补充的运行范围/覆盖校验；不是源仓库历史资产 |

## 历史部署复现（非 CURRENT V6 gate）

以下入口只用于复现归档实验，不得作为当前 S15 验收入口：

部署必须使用新的 `RUN_ID`、测试库、Redis 容器/端口、Rabbit vhost 和节点端口；
`SNAP_BIN`、`BOOTSTRAP_BIN`、source identity、节点路由和基础设施凭据均由受保护环境显式传入。
`deploy_dist.sh` 是 fresh-only：任一目标资源已存在或端口已占用就停止，未知结果先对账，
不得直接重放。

最终历史证据只通过 `run_cs_evidence.py` 的完整 11 步入口采集。它要求旧 run_config、
OPA、Redis 和旧 integration contract；即便全部步骤通过，也只能记为历史 compatibility
result，不能升级为 CURRENT V6 S15 PASS。



`s15_perf.py` 分开验证三种计数域，禁止跨域相等比较：

- `authorization_projection_head/outbox.source_generation` 是 legacy source/outbox 域，只验证同一聚合的 head 与最新 outbox source generation 一致且 outbox 全部 `PROCESSED`；
- `authorization_projection_current.current_generation` 是 published manifest 链的连续代次 `G`，通过 `1..G` impact plan 全覆盖、逐代 `base_generation = target_generation - 1`、每个 plan 唯一映射一个成功 delta、无超出 `G` 的成功 plan、无未映射成功 delta、同 grant 版本连续，以及 generation-G tip identity、source stamp 与 revoke-fence dominance 一致来证明；
- `authorization_projection_manifest.source_generation` 是 generation-G tip delta 的 source stamp，只与该 tip delta 及 `projected_generation` 对齐，不与 legacy head/outbox source generation 或 `current_generation` 比较。

P2、P3 和 P3.5 仅在上述 published frontier、legacy outbox、impact/archive drain 和当前轮 RULE_SET delta 同时终态时通过。采样使用两个 tenant/aggregate-scoped scalar snapshot：一个证明 published frontier，一个合并 legacy outbox、pending impact/archive 和当前轮 delta；两次查询之间若遇到并发推进，最多产生保守的暂时非终态，不得据此放行或形成有效样本。

### 节点恢复与秘密日志边界

历史协调器将旧三节点状态分为两层：liveness 要求 pidfile 指向当前 run 的 binary、cwd 与唯一监听 PID，且端口返回任意 HTTP 响应；authorization readiness 另行要求签名管理 API 200 和 decision API 200。该段仅适用于历史复现，当前四节点 campaign 必须额外证明两个半区成员、两个数据库 owner 和两条传输路径的 readiness。轮间恢复先停止全部 run-owned 进程，再让历史三节点全部进入 serving，最后在一个共享有界窗口内等待 authorization readiness；不得因暂时 PENDING/非 200 的授权门反复杀死已 serving 的健康进程。启动命令失败纳入三次有限重试，foreign listener 或 identity 不匹配直接 fail-closed。

历史兼容复现中，S15 在 Redis outage 后必须同时证明 `docker start` 成功和认证 PING 恢复，之后才允许整组重启；该步骤只属于旧 Redis contract，不属于 CURRENT V6 gate。TrustGraph 的 RabbitMQ 成功/失败日志不得格式化连接 URL 或第三方连接错误文本，避免 userinfo 中的凭据进入 server log。

手动分步仅用于定位问题，不得拼接为最终验收证据：

安全约束：run_config.json / application.yml / jwt.env / scopes.env / hmac.txt 均含
run 级秘钥，仅存在于节点本地（0600），**不入库不入 git**；仓库内脚本一律使用
环境变量占位符。
