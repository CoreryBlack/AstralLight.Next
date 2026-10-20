# Rust Tokio durable worker 的重试边界：lease、timeout 与 UNKNOWN

> 面向：Rust 异步后端、Tokio 与持久化队列开发者
> 关键词：Rust、Tokio、SQLx、lease、cancellation safety、重试、UNKNOWN

异步 worker 的代码很容易写成“取任务、处理、失败就重试”。但如果一次处理会写 MySQL、推进 projection pointer，数据库 COMMIT 超时之后，进程究竟应该重试还是停止？答案取决于能否证明上次的 durable mutation 没有成功。

AstralLight.Next 的授权 projector 把处理结果分成若干明确状态：成功发布、可重试、确定性分歧需隔离、pointer 被并发推进可重新规划，以及 lease/commit 结果 UNKNOWN。这个状态机比单一 `Result<(), Error>` 更适合描述 Tokio future 被取消后的真实不确定性。

## 一、claim 使用服务端租约与 run-scoped token

`claim_next_delta_event_in_tx` 在 SQL transaction 内选择可领取的 pending/过期 leased event，再安装 owner、服务端过期时间、CAS version 和新 token。token 每次 claim 随机生成，数据库保存其 SHA-256 hash；worker拿到的 claim 包含明文 token，日志 `Debug` 不会输出它。

claim 安装后，repository 再读回服务器生成的过期时间和 post-increment attempt counter。worker 不使用 candidate SELECT 中的旧 attempts 值，因为重试预算必须依据 durable claim 之后的真实次数。未过期的 lease 不会被别的 worker 偷走；过期 lease 则可以通过受控 reclaim 接管。

```rust
let token = DeltaLeaseToken::new_run_scoped();
let install = sqlx::query(DELTA_CLAIM_INSTALL_SQL)
    .bind(lease_owner)
    .bind(token.token_hash().as_bytes().to_vec())
    .bind(lease_seconds)
    .bind(candidate.delta_event_id)
    .execute(&mut **tx)
    .await?;
if install.rows_affected() != 1 {
    return Err(GrantRepositoryError::ClaimRace);
}

let (expires_at, installed_attempts): (Option<PrimitiveDateTime>, i64) =
    sqlx::query_as(DELTA_CLAIM_READBACK_SQL)
        .bind(candidate.delta_event_id)
        .fetch_one(&mut **tx)
        .await?;
let Some(lease_expires_at) = expires_at else {
    return Err(GrantRepositoryError::Mapping(
        "code=grant_repository.claim_expiry_missing".to_owned(),
    ));
};

Ok(DeltaEventClaim {
    delta_event_id: candidate.delta_event_id,
    event_id: candidate.event_id,
    operation_id: candidate.operation_id,
    event_type: DeltaEventType::from_sql(&candidate.event_type)?,
    tenant_id: candidate.tenant_id,
    card_id: candidate.card_id,
    aggregate_type: candidate.aggregate_type,
    aggregate_id: candidate.aggregate_id,
    grant_id: decode_grant_id_sql(&candidate.grant_id)?,
    base_version: candidate.base_version,
    target_version: candidate.target_version,
    source_generation: u64::try_from(candidate.source_generation)
        .map_err(|_| GrantRepositoryError::Mapping(
            "code=grant_repository.invalid_source_generation".to_owned(),
        ))?,
    revoke_fence: {
        let revoke_fence = u64::try_from(candidate.revoke_fence)
            .map_err(|_| GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_revoke_fence".to_owned(),
            ))?;
        validate_delta_fence_relation(
            u64::try_from(candidate.source_generation)
                .map_err(|_| GrantRepositoryError::Mapping(
                    "code=grant_repository.invalid_source_generation".to_owned(),
                ))?,
            revoke_fence,
        )?;
        revoke_fence
    },
    before_image_json: candidate.before_image_json,
    before_digest: Sha256Digest::from_optional_bytes(candidate.before_digest.as_deref())?,
    delta_json: candidate.delta_json,
    semantic_hash: Sha256Digest::from_bytes(candidate.semantic_hash)?,
    dependency_hash: Sha256Digest::from_bytes(candidate.dependency_hash)?,
    compiler_version: candidate.compiler_version,
    attempts: installed_attempts,
    cas_version: candidate.cas_version,
    lease_owner: lease_owner.to_owned(),
    lease_token: token,
    lease_expires_at,
})
```

这段结果映射省略了外围函数的 SQL 候选读取与参数校验，但 claim 的字段完整映射沿用 repository 实现；关键是使用 readback 得到的 `installed_attempts`、服务端 `lease_expires_at` 和本次 `token`，而不是预读快照。lease 不只是“任务正在运行”的布尔标记，而是由 owner、token、过期时间和 CAS 状态共同界定的所有权证明。

## 二、将 I/O 观察、纯决策和事务发布分层

单个 event 的 worker 管线大体是：

1. strict readback 再确认 claim lease 有效；
2. 短事务观察 publication frontier 与 parent references；
3. 只读加载完整 scope ledger；
4. 在事务外完成 partition、验证、compile 与 disposition 决策；
5. 发布时开启新事务，续租并复核 pointer/fence，完成 manifest 与 CAS 发布。

纯 planning/compile future 不应持有数据库锁。若另一个 publisher 在观察和发布之间推进了 pointer，当前事务通过 CAS 检测到 `PointerMoved`。worker 会保留当前 claim lease，在有限次数内重新观察新世界并重新规划；这不是一次 event 失败，不立即消耗普通 retry budget。超过 in-place replan allowance 后才进入常规退避。

这种分层让异步读和 CPU 计算不会被误认为 durable 修改；真正的 source/projection/pointer 更新仍落在明确的短事务里。

## 三、`tokio::time::timeout` 取消 future，不证明数据库没提交

worker 给每个事件设置处理 deadline：

```rust
let processing = tokio::time::timeout(
    config.event_deadline,
    process_one_event(
        &runtime,
        &config,
        &lease_owner,
        &cancellation,
        &claimed,
        &mut summary,
    ),
)
.await;

if processing.is_err() {
    summary.events_deadline_exceeded += 1;
    record_projector_event(ProjectorEventOutcome::DeadlineExceeded);
    tracing::error!(
        event_id = %claimed.event_id,
        operation_id = %claimed.operation_id,
        deadline_secs = config.event_deadline.as_secs(),
        "processing deadline exceeded; lease left to expire-reclaim"
    );
    // 不发 lease mutation。发布事务的提交结果可能是 UNKNOWN。
}
```

Rust 的 `timeout` 到期后会丢弃正在等待的 future。若 SQLx transaction 仍未提交，transaction drop 路径可回滚未完成事务；但如果 COMMIT 已发送、响应在网络中丢失，客户端不能从 timeout 推断服务器端没有提交。因此，timeout 只证明本地等待超时，不能充当 rollback proof。

代码在事件处理 deadline exceeded 时不再对事件发 release/fail mutation。若发布事务已经 commit，事件终态更新也在同一事务内提交，因此不会再满足 claim 条件；若事务未提交，它回滚后留下的 lease 必须先在数据库到期，才可被下一次 claim 安全接管。即使观察到 deadline，也不能据此跳过 lease fence 立刻重放。

同一原则适用于 shutdown cancellation：在 claim 后发现要关闭时，不抢着释放可能仍在执行的所有权，而是让 lease 到期接管；worker handle 的退出与监督层随后对账。

## 四、把失败分类写进类型与唯一 mutation funnel

不同失败不应全都走 `retry()`：

- **暂时性 I/O 失败 / Blocked**：通过统一 `plan_retry_schedule` 根据 durable attempts 计算有限退避；预算耗尽仍保持 PENDING 与最大 backoff，不伪造 QUARANTINED。
- **PointerMoved**：在有界次数内保留 lease、重新观察并计划；超过上限才进入普通退避。
- **确定性数据分歧**：以 live lease guard/CAS 进行一次真实 QUARANTINED 写入；若这次写入结果也未知，不再发 fail/release/retry mutation。
- **LeaseLost / PublicationUnknown**：没有权力再修改该 event。记录 UNKNOWN，等待 durable state 对账。

这也是为什么 worker 把可重试的失败汇入一个 `fail_with_budget`，而把 quarantine 和 UNKNOWN 保持为独立终态路径。重试策略、attempt 计数和状态迁移集中后，少一个错误分支重复写状态的机会。

阶段计时、attempt 计数、lease lost、publication unknown、deadline exceeded 与 quarantine unknown 也分别进入运行汇总/指标。运维看到“失败”时能区分是需要退避、需要修数据，还是必须先对账。

## 五、Tokio worker 的安全问题不是如何更快 retry

正确设计的问题是：future 被 timeout/cancel 后，durable 副作用到哪一步？当前 lease 还归谁？允许进行哪一个、且仅哪一个状态变更？如果这些问题不能回答，正确的分支应是 UNKNOWN，而不是“再跑一次碰碰运气”。

**核心经验：** 把随机 lease token、服务端到期、CAS mutation、attempt readback、有限重规划、唯一重试 funnel 与 UNKNOWN 停止写入组合起来，Tokio worker 才能在崩溃、取消与网络断开时维持可对账的 durable 语义，而不是依赖恰好一次调度。
