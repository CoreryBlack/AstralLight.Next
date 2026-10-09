# rust-s15：Rust 三节点分布式一致性（S1–S15）+ 分布式性能

本目录公开 final9/S15 的可执行 harness 源码和安全边界。源仓库的历史 `REPORT*.md`、JSON/日志结果和 frozen evidence archive 未复制；本目录代码只能在显式提供的受保护三节点环境中运行，不能把源仓库历史结果当作当前仓库验证。

**入口：** `run_cs_evidence.py`（可执行编排器）。源仓库的历史 `REPORT*.md`、JSON/日志结果和 frozen evidence archive 未复制；本目录代码只能在显式提供的受保护三节点环境中运行，不能把源仓库历史结果当作当前仓库验证。

## 当前架构边界

本目录是历史分布式/RQ campaign harness，不是当前 native 单机验收入口。
其部署、Redis epoch/key invalidation、OPA 比较和恢复脚本仍依赖历史装配；不能
为了执行这些脚本，向当前 MySQL + LocalBus/LocalProjectionBus/MemoryProjectionHub
生产路径添加 Redis、RabbitMQ 或 OPA。当前 standalone/distributed Rabbit profile
只登记 MySQL + RabbitMQ；旧 harness 的额外依赖属于历史比较/兼容边界。

`tests-suite/MANIFEST.toml` 汇集 RQ1-5、M1-5、E1-5、MT 与性能，并分别登记
组件命令与完整 campaign blocker。`scripts/test_campaign.py` 不派发本目录旧
live argv：完整 RQ/S15 仍需适配当前部署 owner、签名身份、generation/fence、
durable consumer 与租户隔离后，再经受保护三节点环境审批和终态核验。
RQ2-D 仍是结构性 N/A；局部 `--skip`、单机 CPU 数据和源码存在不能构成完整
三节点 PASS。以下运行说明保留历史合同，不表示本轮执行或生产依赖推荐。

## 文件清单

| 文件 | 说明 |
|------|------|
| `run_cs_evidence.py` | 证据编排器：按安全顺序执行下列脚本，逐步 manifest（命令/cwd/env 名称/起止/exit/artifact/postcondition/verdict；env 只记名称不记值） |
| `s15_coordinator.py` | S1–S15 一致性协调器（对标 Java 场景，Rust 机制映射见文件头注释） |
| `s15_perf.py` | 三节点性能套件（P1 评估基线 / P2 传播收敛 ε / P3 并发写风暴 / P3.5 有界排水 / P4 读扩展） |
| `deploy_dist.sh` | fresh-only 的 run 专属三节点部署脚本（schema 克隆→专用 Redis→独立 Rabbit vhost→配置→分发→启动→就绪→run_config.json）；目标目录/DB/容器/vhost/端口已存在即失败，不覆盖旧 run |
| `seed_f4rust.sql` | e2e 种子（namespace e2e_f4rust_*，ID 段 9011–9091） |
| `s15_result.json` / `s15_run.log` | 历史一致性结果名；未复制，不代表当前结果 |
| `s6_retry.json` / `s6_retry.log` | 历史 S6 重跑证据名；未复制 |
| `perf_result.json` / `perf_run.log` | 历史 P1-P4 性能结果名；未复制 |
| `arbiter_contract_tests.log` | 历史契约日志名；未复制，不以其旧通过数证明当前运行 |
| `FIXPLAN.md` | 产品级问题（F5/F6/arbiter 门/head 对齐/bind 事件缺口）的具体修复方案 |

## 运行方式（node-b）

部署必须使用新的 `RUN_ID`、测试库、Redis 容器/端口、Rabbit vhost 和节点端口；
`SNAP_BIN`、`BOOTSTRAP_BIN`、source identity、节点路由和基础设施凭据均由受保护环境显式传入。
`deploy_dist.sh` 是 fresh-only：任一目标资源已存在或端口已占用就停止，未知结果先对账，
不得直接重放。

最终证据只通过 `run_cs_evidence.py` 的完整 11 步入口采集。调用方必须显式传入：

- `--run-config` 与零秘密的 `--setup-provenance`；
- run ID、production/source/dirty patch/bootstrap/engine、10-file harness、routing source、TOCTOU script、382-file integration tree 与 OPA image 的期望 identity；
- engine comparison 的 5 次重复和可达 OPA；
- canonical `cargo test --locked -p astral-db --test authorization_projection_integration --release -- --ignored --test-threads=1`、`--integration-cwd E:\\OfficialVersion\\AstralLight-Next` 与环境变量名称 allowlist；
- `--rounds 3` 或更高。

默认 fail-fast。只有11步全部 `PASS`，没有 `FAIL`、`UNKNOWN`、`BLOCKED`、`SKIP`，且
run_config/setup/harness/runtime source 的逐步与末端 hash 全部一致，integration campaign 用户写探针通过时，完整 campaign 才能用于汇总数值。
`--only`/`--skip` 只用于诊断，产物标记 `PASS_WITH_SKIPS`，不得作为完整 campaign。

### RULE_SET generation 域与终态证明

`s15_perf.py` 分开验证三种计数域，禁止跨域相等比较：

- `authorization_projection_head/outbox.source_generation` 是 legacy source/outbox 域，只验证同一聚合的 head 与最新 outbox source generation 一致且 outbox 全部 `PROCESSED`；
- `authorization_projection_current.current_generation` 是 published manifest 链的连续代次 `G`，通过 `1..G` impact plan 全覆盖、逐代 `base_generation = target_generation - 1`、每个 plan 唯一映射一个成功 delta、无超出 `G` 的成功 plan、无未映射成功 delta、同 grant 版本连续，以及 generation-G tip identity、source stamp 与 revoke-fence dominance 一致来证明；
- `authorization_projection_manifest.source_generation` 是 generation-G tip delta 的 source stamp，只与该 tip delta 及 `projected_generation` 对齐，不与 legacy head/outbox source generation 或 `current_generation` 比较。

P2、P3 和 P3.5 仅在上述 published frontier、legacy outbox、impact/archive drain 和当前轮 RULE_SET delta 同时终态时通过。采样使用两个 tenant/aggregate-scoped scalar snapshot：一个证明 published frontier，一个合并 legacy outbox、pending impact/archive 和当前轮 delta；两次查询之间若遇到并发推进，最多产生保守的暂时非终态，不得据此放行或形成有效样本。

### 节点恢复与秘密日志边界

协调器将节点状态分为两层：liveness 要求 pidfile 指向当前 run 的 binary、cwd 与唯一监听 PID，且端口返回任意 HTTP 响应；authorization readiness 另行要求签名管理 API 200 和 decision API 200。轮间恢复先停止全部 run-owned 进程，再让三节点全部进入 serving，最后在一个共享有界窗口内等待 authorization readiness；不得因暂时 PENDING/非 200 的授权门反复杀死已 serving 的健康进程。启动命令失败纳入三次有限重试，foreign listener 或 identity 不匹配直接 fail-closed。

S15 在 Redis outage 后必须同时证明 `docker start` 成功和认证 PING 恢复，之后才允许整组重启。TrustGraph 的 RabbitMQ 成功/失败日志不得格式化连接 URL 或第三方连接错误文本，避免 userinfo 中的凭据进入 server log。

手动分步仅用于定位问题，不得拼接为最终验收证据：

安全约束：run_config.json / application.yml / jwt.env / scopes.env / hmac.txt 均含
run 级秘钥，仅存在于节点本地（0600），**不入库不入 git**；仓库内脚本一律使用
环境变量占位符。
