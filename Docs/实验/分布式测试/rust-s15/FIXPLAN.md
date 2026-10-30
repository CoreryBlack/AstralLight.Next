# 产品级问题修复方案（FIXPLAN）

> 依据：rust-s15 三节点实验（2026-08-31）+ 源码核对（本文件的文件/行号均指向
> `AstralLight-Rust/` 当前 HEAD）。修复排序按"安全影响 × 阻塞面"排列。
> 每项含：根因定位 → 具体改动 → 验证方法。所有修复走常规 PR 流程（分支/评审/CI gate）。

---

> 历史证据边界（CURRENT V6）：本文件是基于 2026-08-31 历史实验和当时源码快照的
> 诊断/修复计划，保留 Redis 故障根因、worker 行为和修复顺序作为历史证据；不构成当前
> Redis runtime、当前部署指导或真实集成 `PASS`。Redis adapter/L2 相关建议属于 retired
> compatibility context；当前软件合同以 bounded process-local L1、strict DB reader、
> canonical publication barrier 和 fail-closed `PENDING`/`DENY` 为准。

## 修复 1（最高优先级）：F5 —— delta worker 在负载/Redis 故障下永久挂起

### 根因定位

三层叠加，任何一层都可能单独造成"进程活着、worker 静默停止"：

1. **Redis 池构建无超时 + 全局锁跨构建持有**
   `astral-db/src/eligibility.rs` `rebuild_redis_conn_pool()`（约 :717）：
   `REDIS_CONN_POOL_BUILD.lock().await` 持锁期间串行 `client.get_connection_manager().await` × 8，
   无任何超时。redis-rs 的连接与命令默认**无超时**；docker stop 后 docker-proxy 仍可能
   accept 连接但黑洞命令 → `get_connection_manager` 永久 pending → 构建锁永久占用 →
   所有 `redis_conn()` 调用方（含 worker 的 L2 推送）级联挂起。
2. **worker 循环内的操作无整体超时**
   `astral-trustgraph/src/service/authorization_projector.rs` `run_worker()`（:427）→
   `process_one_event()`（:1956）：任何一步挂起（Redis push、DB 锁等待、连接池耗尽
   await）都会让 worker 永远停在当次循环内；不再 claim、不 panic、无错误日志——与
   实测"LEASED 行冻结 + 后续事件 attempts=0"完全一致（V3 storm 后 17 LEASED / 93 PENDING）。
3. **无监督**：`start_authorization_projector_with_runtime()`（:394）spawn 一次，
   JoinHandle 无人看护；task panic/退出均静默。

### 改动

**1a. Redis 超时硬化**（`eligibility.rs`）：
- 客户端配置显式超时：`redis::ConnectionInfo`/`RedisConnectionInfo` 设
  `connection_timeout`（2s）与命令响应超时；或对每次 `redis_conn()` 返回的使用点统一包
  `tokio::time::timeout(2s, ...)`。
- `rebuild_redis_conn_pool()`：把"建 8 条连接"移出构建锁——先无锁建连（各自带 2s
  超时、失败计数），成功后再拿锁做双检+原子替换；任一连接失败按现有语义返回 None
  （调用方降级 DB-only），**绝不在持锁状态下 await 网络操作**。

**1b. worker 操作级超时**（`authorization_projector.rs`）：
```rust
match tokio::time::timeout(config.event_deadline, process_one_event(...)).await {
    Ok(_) => {}
    Err(_) => {
        summary.events_deadline_exceeded += 1;
        tracing::error!(event_id=%claimed.event_id, "delta event processing deadline exceeded; releasing lease");
        runtime.release_event(&delta_lease_identity).await;  // 尽力释放，失败靠 lease 过期 reclaim
    }
}
```
`event_deadline` 取 `claim_lease_seconds`（120s）的固定比例（如 90s），进
`AuthorizationProjectorConfig`。release 失败无妨：租约到期后由其他 worker 正常 reclaim
（claim SQL 已覆盖 `LEASED AND lease_expires_at <= NOW()`）。

**1c. L2 推送降级为带硬超时的尽力而为**（`evidence_cache.rs`
`push_published_card_evidence_to_l2` / `push_evidence_to_l2_with`）：
整体包 `timeout(1s)`；它本就是"失败静默、L2 miss 自然回源"的优化路径，1s 内推不完就放弃。

**1d. worker 监督**（`authorization_projector.rs`）：
- `start_authorization_projector_with_runtime` 外包监督循环：
  `loop { tokio::spawn(run_worker(...)) ; 等待 join 或 watchdog }`；
  join 返回（panic/退出）→ error 日志 + 5s 退避重启（携带新 run_id/owner，租约天然隔离）。
- 增加看门狗计数：`summary.last_claim_progress` 时间戳；若"存在可 claim 事件但连续
  N 分钟零 claim 进展"，由监督循环强制重建 worker（可通过把 claim 循环改为返回
  `ClaimProgress` 枚举或在 runtime 层记录 last_claim_at 实现）。
- 暴露 `AuthorizationProjectorHandle` 的健康快照（uptime/last_claim_at/in_flight）到
  现有监控端点，消除"进程健康但投影停摆"的盲区。

### 验证
1. 单元：构造 redis 挂起（tokio test + mock store 永久 pending）→ 断言 1s 超时后
   publish 照常完成、worker 下个周期继续 claim。
2. 集成（现有 harness）：`RUST_INTEGRATION_REQUIRED=1` 跑 evidence_cache_redis_integration；
   新增"docker stop redis 30s → start"用例断言 worker 在 restart 后 1 个轮询周期内恢复 claim。
3. 三节点复测：重跑 `s15_perf.py` P2——预期 ADD/REMOVE 双向收敛且 attempts 正常递增；
   以此同时验证 F7 是否仍存在（见修复 2 的验证）。

---

## 修复 2：F6 —— 并发首写 delta 版本冲突卡死聚合

### 根因定位

`astral-trustgraph/src/repository/rule_set_repository.rs`：

- **ADD 首发路径** `materialize_ruleset_adds_for_bound_card_in_tx()`（:1052）：
  `next_delta_version(None)` 硬编码 base0→target1，**不加锁、不读聚合当前最大版本**。
  两个并发 HTTP 事务同时走该路径 → 两条 target_version=1 的 delta 同时入库（event_id
  不同，插入都成功）→ 发布时一条 CAS 赢、另一条永远落后于 pointer → 重试同样带旧
  target → 预算耗尽 → 聚合证据链死（S1 复现）。
- **UPDATE 路径**（:1130）已是正确写法：`read_latest_delta_target_version_for_update_in_tx`
  （`FOR UPDATE`，`grant_repository.rs` :890）→ `next_delta_version(last_target)`。

### 改动

**2a. 统一版本分配**：把首发路径改为与 UPDATE 路径同构——
```rust
let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
    tx, facts.tenant_id, RULE_SET_AGGREGATE_TYPE, rule_set_id, head.grant_id,
).await...;
let (base_version, target_version) = astral_db::next_delta_version(last_target)...;
```
注意事项：
- `materialize_ruleset_adds_*` 需要 `head.grant_id`；对"聚合尚无 head"的真首发
  （`read_grant_head_for_update_in_tx` 返回 None）保留 `next_delta_version(None)`，
  但必须同时**锁定聚合级互斥点**防止两个事务同时判"无 head"：以
  `SELECT ... FROM authorization_projection_head WHERE aggregate_type='RULE_SET' AND
  aggregate_id=? FOR UPDATE` 作为聚合锁（行不存在时用 `INSERT ... ON DUPLICATE KEY
  UPDATE head_id=head_id` 的意图锁行，或以 rule_set 行 `FOR UPDATE` 作聚合锁——推荐
  后者，rule_set 行天然存在且低竞争）。
- 全仓审计 `next_delta_version(None)` 的其余调用点（delegation/approval/direct 等写侧）
  一并改造，避免同构缺陷留在别的聚合。

**2b. 发布侧自愈（兜底）**：projector 在 publish 失败分类中区分
`target_version <= pointer.current_generation`（stale-target）：不再按普通 Retry 无限
重试，改为一次性以"重读最新版本 + 重排计划"自愈一次；仍失败则 quarantine（稳定
reason_code `auth_projector.stale_target_unrecoverable`），让监控可见。现有
`classify_compile_stage_error`（authorization_projector.rs :3245 附近）增加该分支。

### 验证
1. 单元：模拟两事务并发走首发路径 → 断言产生 target 1/2 而非 1/1。
2. 集成：新增 ignored 集成用例（复用 canonical 配方）：两线程并发对同一新规则集
   add_entry → 断言两条 delta 均发布、pointer gen=2、评估可见。
3. 三节点：重跑 S1（`s15_coordinator.py --only S1`）→ `S1_all_nodes_allow` 与
   `S1_unique_head` 转 PASS（deltas [1,2] all SUCCEEDED）。

---

## 修复 3：arbiter 控制面路由门阻断（解锁 S12/S13 远程证据）

### 根因定位
- `astral-types/src/registry.rs:250`：`self.register("monitor", &["read", "scan"])` —
  无 `create`。
- `astral-common/src/middleware/permission_check_shared.rs`
  `resolve_permission_action()`（:190）：`/arbiter` 的 POST 落入默认映射 → `create`。
- `astral-trustgraph/src/api/permission_check.rs:46`：`("/arbiter", "monitor")`。

三处组合 → `monitor:create` 未注册 → 任何规则都无法授权 → 403 DEFAULT_DENY。

### 改动（最小且语义正确）
1. `registry.rs:250`：`self.register("monitor", &["read", "scan", "arbitrate"]);`
2. `permission_check_shared.rs` `resolve_permission_action()` 增加显式覆盖（对齐文件内
   既有 override 表风格）：
   ```rust
   if resource == "monitor" && method == "POST" && path.contains("/arbiter") {
       return Some("arbitrate");
   }
   ```
3. 授予：arbiter 调用方（控制面协调器所用卡）需要一个 `monitor:arbitrate` 的 ALLOW
   规则（run 种子/正式租户各按需授予）；`s15_coordinator.py` 的种子已具备注入点。
4. 测试：`permission_check.rs` 的 canonical 断言表补 `("/arbiter/arbitrate", "monitor",
   "POST", "arbitrate")`；policy-engine/registry 单测补动作注册断言。

### 验证
三节点重跑 S12/S13（`--only S12,S13`）→ 远程 `DENY+R1_FENCE_DENY` /
`DEFER+EVIDENCE_MISSING` 转 PASS，REPORT 中对应 N/A 移除。

---

## 修复 4：head 退役列与架构口径对齐（观测债务）

### 现状
`authorization_projection_head.projected_generation/projection_status` 由旧链维护，新链
（pointer/delta/manifest）不写（F3）。任何按 head 判断就绪度的监控/断言都会误报。

### 方案（二选一，推荐 A）
- **A（推荐，低风险）**：承认 head 的 src/revoke_fence 为写侧账本、proj/status 为退役列：
  - 文档对齐：`Docs/架构/Rust架构设计/Rust权限投影快照与版本栅栏_V1.0.md` 增补"新链就绪
    权威 = authorization_projection_current（pointer）+ manifest，head.proj/status 冻结不维护"；
  - 迁移清理：并入既定"阶段 5 DROP"窗口删除两列（或改列名为 `_legacy_*` 并加注释），
    依赖方（测试/监控）改读 pointer；
  - AGENTS §3.2 的"READY"口径在文档中显式映射到 pointer.status。
- **B（高成本，不推荐当前做）**：在 publish tx 内同步推进 head.proj/status。但这要求先
  解决"bind/unbind 不产生 delta"（否则 head.src 计数含 bind 而发布版本不含，proj 永远
  追不上 src，PENDING 语义依旧失真）——即先做修复 5 才有意义。

### 验证
A：全仓 `grep projected_generation` 依赖点逐一改造后跑 workspace gate；三节点重跑
S 系列（结构断言已不依赖 head，预期 verdict 不变）。

---

## 修复 5（设计决策项，需产品确认）：bind/unbind 不产生 delta 的事件缺口

### 现象与影响
- 写侧仅为 entry add/delete 创建 RULE_SET delta；bind/unbind 只产生 CARD outbox 事件
  （旧链仅 mark_processed）。后果：**先加条目、后绑定的顺序里，条目在绑定前不产生
  delta；绑定动作本身也不补发** → S1 的"加条目→绑定"组合无法传播（叠加 F6 后完全卡死）；
  绑定空规则集则依赖链不可验证（读门长期 PENDING）。
- 不影响 S4 类场景的原因：unbind/rebind 走 revoke fence + 既有证据的有效性翻转，不依赖
  新 delta。

### 方案（二选一）
- **A（推荐）**：bind 时对每个新受影响卡走既有 fanout 物化
  （`append_ruleset_entry_update_fanout_in_tx` 已具备 per-card 事件面），把该卡当前
  ALLOW 条目以 CARD/RULE_SET delta 补发（幂等：以 grant_id+当前 head 版本去重）；
  unbind 对称地补发 REMOVE。这使"绑定"成为一等授权变更，证据链与 outbox 语义一致。
- **B（收窄语义）**：文档明确"绑定不改证据内容，仅改 fence/有效性"，并在投影/评估层
  保证 bind 状态参与依赖哈希（dependency_hash 已含绑定信息则需证明 evaluator 复读能
  覆盖 bind 变更——当前 S1 的 no-matching-grant 证明覆盖不了）。

### 验证
新增集成用例：新规则集 → add_entry（未绑定）→ bind → 断言 3 节点评估转 ALLOW 且
pointer/delta 链完整；unbind → 反向。S1 在 2a+5A 落地后应完全 PASS。

---

## 实施顺序与依赖

```
1. 修复 1（F5，1a→1b→1c→1d）        ← 先消除测量混杂因素
2. 修复 2（F6，2a→2b）              ← 依赖 1 的健康 worker 才能验证
3. 重测 P2/S1（现有三节点 harness 直接复用）
4. 修复 3（arbiter，独立，可并行）
5. 修复 4A + 修复 5A（设计决策项，各走一次评审）
```

每步的三节点验证命令与判定标准已在各项"验证"小节；全部可在现有 run 部署上执行，
无需新建环境。
