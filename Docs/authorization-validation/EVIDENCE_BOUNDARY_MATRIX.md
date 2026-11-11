# Validation Boundary Matrix

> This matrix records what each validation target can establish and when a result
> must be downgraded. It is an engineering control, not a publication-results table.
>
> Current 2026-11-10 source review finds no complete production family chain from durable source through an authority-proven receipt to ledger; etcd snapshot and CertifiedMemory GLOBAL publication proof remain unavailable. The 4213/0/119 workspace result applies only to its earlier frozen snapshot; ignored tests remain SKIP. See [process evidence §0M](认证内存授权状态机实施过程报告_2026-11-08.md#0m-2026-11-10-冻结快照工作区验证).
>
> V7 local implementation and Rust validation are bounded by the latest 2026-11-09 increment recorded below; the root/runtime/composition evidence is local and does not establish CertifiedMemory Serving. The [completion results and review](认证内存授权状态机计划完成度审查报告_2026-11-06.md) retains the detailed review.
> Real dependency, migration, delivery and deployment acceptance remain separate and
> unexecuted. V19–V21 and the retained V6 counts below describe their original local
> snapshots; they are not final V7 acceptance.
> Exact commands, raw logs, review failures and handoffs are recorded once in the
> [implementation process report](认证内存授权状态机实施过程报告_2026-11-08.md#0-v7-当前增量证据2026-11-07持续更新);
> its §0.6 retains the final freeze and execution evidence.
> Fresh F0/F1, source outcome, WorkerOwned completion, certificate history/current,
> certified install and external delivery require separate postconditions.
> V7 local CardRebind evidence covers exact typed card/template/ref/aggregate,
> audit, parent-event and receipt validation. MQ shutdown evidence covers local
> task ownership, cancellation, drain and deadline behavior. Neither establishes
> a real source transaction, remote `APPLIED`, quorum durability or deployment.
> Current conclusions and counts are summarized in the completion review; exact
> attempts remain in the process report. Failed workspace attempts and ignored live
> tests do not upgrade these boundaries.
>
> Retained V6 provenance boundary: Chat/Learn paths and Redis-backed
> fixtures/reports are historical baseline/comparison or retired compatibility
> evidence only. They are not current runtime dependencies, current gates, or
> real-integration `PASS` evidence. Direct Monitor health probes are operational
> observations, distinct from the protected Monitor contract. Resource retirement
> remains fail-closed until canonical revoke, generation, and published-evidence
> barriers are proven. Password delivery is unavailable/`PENDING` unless a
> notifier handoff is proven. `UNKNOWN` and `PENDING` require reconciliation;
> cross-aggregate completion requires complete owned receipt and evidence barriers.

Allowed states are `BASELINE`, `PLANNED`, `PASS`, `FAIL`, `BLOCKED`, `UNKNOWN`,
`PENDING`, and `SKIP`. `PLANNED` is not an execution result, and `UNKNOWN` must not
be rewritten as `PASS`.

| ID | Validation target | State | Required evidence | Supported boundary | Stop or downgrade condition |
|---|---|---|---|---|---|
| V1 | Observe a stale-authorization race between source narrowing and host admission | BASELINE | Historical diagnostic run plus an isolated production-path run | Only the observed workload and protocol boundary | If the production path is not connected, retain the diagnostic-only boundary |
| V2 | Verify that `PolicyEngine.evaluate()` final reload fails closed after pre-observation narrowing | PLANNED | Production entry, final reload, host decision, and ordered timestamps | Static grant contract, one authoritative writer (the composite's monitored `GET_LOCK` lease), and declared M1-M5 assumptions | Missing timestamps or interrupted logs => `UNKNOWN` |
| V3 | Bind final reload to the original candidate instead of a successor grant | PLANNED | Remove/regrant race, successor revision, and exact identity checks | The declared ledger identity contract | Do not infer identity safety when logical ID and revision are not separated |
| V4 | Treat pending probe, cache bracket, final reload, generation fence, and host mediation as independent gates | PLANNED | Isolated test-only controls and a full-contract control | The controlled workload and failure mode only | Stop if a control changes source semantics or cannot be restored |
| V5 | Default to `PENDING` or `DENY` when publication is not proven | BASELINE + PLANNED | DB/cache/projector/lease/restart/parse/integrity fault matrix with reason codes (lease covers both the projector CAS lease and the composite single-writer lease; the dependency-fault matrix includes memory hub, local bus, identity mapping, and writer-lease classes) | Fail-closed decision semantics | Block when the HTTP envelope and business reason code disagree |
| V6 | Separate publication backlog cost from request-side availability | BASELINE + PLANNED | Per-event attempts, queue depth, target/unrelated decision samples, and drain timeline | The recorded workload and sampling boundary | Without request-side samples, report only a workload-level recovery observation |
| V7 | Check deployment prerequisites instead of treating them as assumptions | PLANNED | Isolation level, primary routing, UTC/clock offset, and cache-generation manifest | Only the values observed in the run | Unarchivable or drifting values => `BLOCKED` or fail closed |
| V8 | Explain implementation cost by phase | BASELINE + PLANNED | Cold/warm cache, signed admission, strict read, and final reload timings | Same workload and declared boundary only | Do not compare runs with different workloads or boundaries |
| V9 | Make a validation run reproducible without private host state | PLANNED | Manifest, hashes, redacted configuration, and rerun transcript | Digest integrity plus the published source surface | Missing production schema or binary must be stated explicitly |
| V10 | Keep the threat boundary limited to races and evidence integrity | BASELINE | Attack-surface review and explicit exclusions | Non-Byzantine storage/processes and declared deployment assumptions | Never generalize to Byzantine storage, arbitrary attackers, or replica divergence |
| V11 | Memory projection hub serves only committed publications and honors invalidation as a freshness fence | PLANNED | Hub premise tests (`tests-suite/series/E4/premise_hub_invalidation.rs`) plus a live composite run | The composite process boundary only | A run without invalidation-channel capture must not claim freshness |
| V12 | SDK external identity mapping is mandatory on the integration path | PLANNED | Mapping premise tests (`tests-suite/series/E4/premise_identity_mapping.rs`) plus a live signed SDK admission run | The enabled SDK integration path only | Absent-mapping runs without the refusal reason code are `FAIL`, not PASS |
| V13 | The composite single-writer lease is mutually exclusive and re-acquirable | PLANNED | Lease premise tests on real MySQL (`tests-suite/series/E4/premise_single_writer_lease.rs`) plus a composite restart transcript | One MySQL instance, session-scoped `GET_LOCK` semantics | A competing-writer run without the refusal transcript is `UNKNOWN` |
| V14 | Redis-free composite and compat-enabled deployments are distinct, explicitly declared modes | PLANNED | Startup validation transcripts for both modes (`tests-suite/series/E4/premise_redis_free_composite.rs`) | The declared build feature set | A compat-flagged startup on a non-adapter build must be `FAIL`, never silently Redis-free |
| V18 | Existing Arc-backed assembly reuse is attributed across the full policy evaluation | PLANNED | `policy-evaluate-benefit`: 45 complete release cases, 18 balanced paired batches and three arms, raw decision latency/wall time, exact decision/read/scope/cache counts, correctness controls and paired uncertainty; bounded run analysis in [complete-evaluation record](../实验/基准测试/policy-evaluate-benefit-20261010.md) | Complete `PolicyEngine.evaluate()` CPU call-return with synthetic publication/card/ORG ports and owned evidence; actual-clock reference distinct from ideal warm hits | Missing/filtered/early-deny/debug/partial evidence => FAIL; interruption => UNKNOWN; collection PASS is not a speedup or signed HTTP/MySQL/SDK/business admission claim |
| V19 | Authority issuance lease ingress, completion and disposition plus invalidation recovery are reconciled by stable identity and never auto-retry `UNKNOWN` | PLANNED | Registered pure-Rust contracts (`authority-runtime-reducer-contracts`, `authority-issuance-frontier-contracts`, `invalidation-recovery-reducer-contracts` in `tests-suite/MANIFEST.toml`) plus durable issuer/recovery evidence on real MySQL/RabbitMQ and an approved arbiter/quorum transcript | In-process pure contracts only: authority `Unknown` requires readback by stable lease id before retry, only `Ready` permits proof consumption, issuer frontier accepts only strictly-new generations with an exact parent, and invalidation outbox/inbox requires exact provenance, durable `APPLIED`, monotonic watermark and reconciliation-gated `SERVING` | A local/unit contract `PASS` never implies MySQL, RabbitMQ, four-node, dual-database, external arbiter, TLC, or deployment evidence; those remain `BLOCKED`/`UNKNOWN` until run with their own postconditions |
| V20 | Production-crate recovery/readiness paths fail closed at the same seams the pure contracts model: recovery-op settlement, invalidation runtime supervision, hub fence-sync readiness, strict repository readiness, single-node admission/lease gating, MQ consumer UNKNOWN/quarantine transitions, and invalidation envelope/proof validation | PASS (local/unit only) | Registered Rust suites (`trustgraph-invalidation-recovery-op-contracts`, `trustgraph-invalidation-runtime-supervisor-contracts`, `hub-readiness-negative-contracts`, `db-authorization-readiness-contracts`, `single-node-readiness-liveness-contracts`, `mq-consumer-unknown-transition-contracts`, `mq-invalidation-envelope-fail-closed-contracts` in `tests-suite/MANIFEST.toml`) executed on the final frozen Rust snapshot, plus durable MySQL/RabbitMQ restart/recovery evidence on the separate external gate | In-process local/unit contracts only: recovery-op settle never emits `APPLIED` and inspect timeout stays `UNKNOWN`, the runtime supervisor keeps `SUSPECT` until real reconciliation, the hub serves only after certified root plus durable reconcile, a strict repository without an explicit provider never serves positive authorization, single-node admission closes on required-service/lease loss with liveness separated from authorization, MQ consumers quarantine `UNKNOWN`/malformed input without ACK, and invalidation proofs reject tampered, duplicate or misbound payloads | A local/unit suite `PASS` never implies MySQL, RabbitMQ, four-node, dual-database, external arbiter, TLC, or deployment evidence; those gates keep their own `BLOCKED`/`UNKNOWN` records, and the ignored memory-hub performance matrix and real broker/DB integrations remain separately dispatched |
| V21 | Sensitive source-writer admission, durable commit fences, identity bootstrap hygiene, and resource-registry/runtime reconciliation | PASS (local/unit only) | A historical snapshot recorded affected-crate and workspace Rust checks; see the later snapshot boundaries below. Focused library evidence includes `astral-common` 192 passed/1 ignored, `astral-db` 892 passed/7 ignored, `astral-identity` 155 passed/0 ignored, and `astral-trustgraph` 954 passed/7 ignored. Source-shape contracts cover domains, levels/gradings, inheritance, permission actions, resource-types, `last_login_at`, verification supersession/CAS/GC plus audit correlation and per-process IP limiting, async batch card-bind admission propagation, platform-package admin guarding, and resource-registry PENDING/reload behavior | Local Rust evidence only: proof-bound source transactions revalidate scope and consume admissions before proven commit for migrated writers; resource-types now uses actor-card locking, same-transaction audit correlation, and canonical `commit_consuming`; async batch card-bind derives independent per-item admissions from the verified proof and remains fail-closed on expiry/frontier drift; verification bootstrap keeps one-shot CAS, bounded cleanup, post-CAS audit correlation, and bounded Identity-local IP protection without ordinary admission; platform packages retain the existing platform-admin gate as non-authorization billing data; resource registry keeps durable DB state ahead of runtime installation and returns `PENDING` on post-commit install failure | No MySQL-backed transaction proof, migration execution, MQ/worker recovery, full source-owner coverage, cross-replica global rate limit, external email/SMS delivery, durable verification-token consumer, or external authority evidence may be inferred; ignored integration/doc-test entries remain separately bounded and do not upgrade this local/unit state |

**Later security review (2026-11-10):** the 4193/0/119 workspace result below predates subsequent authority changes. GLOBAL family aggregate certification and certified-memory root install/read remain fail-closed until complete per-scope publication and snapshot proof are implemented; the current code requires a new workspace gate.

## V7 current increment boundary (2026-11-09)

The 2026-11-09 increment adds the following bounded local evidence. It supersedes the 2026-11-08 row wording for these targets, but does not erase earlier command records.

| Target | State | Boundary |
|---|---|---|
| Certified-memory root contract | `PASS (focused Rust)` | Six fact families, explicit coverage, canonical digest/signature, current/history continuity, operation idempotency and leader/CAS fencing are locally tested; real etcd/quorum, mTLS deployment and trusted-source allowlist are not run |
| Authority root service/store/HTTP/client | `PASS (focused Rust)` | Install/read and response verification are locally compiled/tested; no proof of external authority durability, partition recovery or deployed caller authorization |
| Certified-memory root/snapshot coordinator | `PASS (local contract)` | family/inventory/snapshot digests, root record, attestation and readiness checks have focused Rust evidence; inputs are assumed verified. Six ledger adapters and the proof-only sink do not produce source completion or substitute for authority proof. Real quorum, worker ownership and Serving remain unproven. |
| Certified snapshot builder/runtime | `PARTIAL (fail-closed)` | Complete-input builder, canonical snapshot identity, runtime readiness gate and invalidation have local evidence; the durable builder cannot prove complete coverage, root installation or Serving. |
| Startup-frozen authorization surface | `PASS (composition boundary)` | Durable, DbBackedMirror and CertifiedMemory are selected at startup; CertifiedMemory requires authority provider plus serving store and never silently falls back |
| TrustGraph/Identity/Monitor integration | `PASS (fail-closed wiring)` | Middleware reads the frozen surface and returns `503` when absent; current runtimes do not install a serving certified store |
| Single-node CertifiedMemory | `BLOCKED/FAIL-FAST` | Explicitly rejected until complete root/runtime preflight and serving owner exist; Durable/DbBackedMirror remains available |
| Full certified authorization Serving | `NOT PROVEN` | Durable six-family materialization, byte-for-byte root/snapshot coordinator, real F0/F1 signed proof equality, certified ORG/dynamic-owner projection and single-node Serving remain open |

The local composition increment adds an explicit `CertifiedMemoryCompositionRoot`, a `require_serving()` startup gate, and profile-aware frozen-surface reuse across Identity, TrustGraph, and Monitor. The focused composition contract passed 3/3 tests and host package checks passed. This proves only that missing family owners, authority inputs, or readiness cannot open positive reads; it does not prove a real root, authority transport, six-family durable completion, worker/frontier/transport readiness, or single-node Serving.
These rows do not upgrade MySQL outage/recovery, RabbitMQ/mTLS, etcd/quorum, multi-node, migration, deployment, S15/TLC or external delivery evidence. Earlier snapshots and the failed 1104/1/13 attempt are retained in the implementation report. The 2026-11-10 frozen pre-format workspace test completed with **4199 passed, 0 failed, 119 ignored**; ignored entries are `SKIP`, and captured output cannot exclude internal skips. A preceding run failed four campaign tests while report files changed; the frozen rerun passed those tests. After that rerun `cargo fmt --all` and its check succeeded; the formatted source and updated reports still require final snapshot gates. See the implementation report §0H–§0I for the original artifacts and boundaries.

## Recording rules

1. Every result records `campaign_id`, `scenario_id`, source/configuration hashes,
   start/end time, cwd, exit code, log completeness, and durable postcondition.
2. One canonical record represents each fact; do not copy hand-edited numbers into a
   second result file.
3. A new run never overwrites an earlier run. Reused scenarios receive a new stable
   identifier and new hashes.
4. Freeze the unit of analysis before a run: cycle, request, event, card, or deployment.
5. Direct observations, model deductions, and unsupported assumptions are reported in
   separate fields. A missing or failed observation lowers the state; it never upgrades
   a live result.
6. Telemetry and reducers may explain phase cost, but cannot replace source,
   publication, audit, pointer, current/manifest evidence, or other durable proof.
   Legacy `authorization_projection_head`/`outbox` rows are diagnostic only and are
   never a publication proof.

## Offline validation boundary

The following may be executed without external services:

- the Rust runtime unit suites and gateway contract tests;
- Rust-native authorization validation contracts and bounded models registered in `tests-suite/MANIFEST.toml`;
- the bounded model command when its local checks are available.

The 19 legacy Python test modules are archived under `archive/python-tests/` and
are not a current test entry point. Registered Rust contracts now include the E1
JSONL parser, dependency-profile/fault declarations, experiment register, and
E1/E3 lifecycle timing reducer, alongside earlier typed classifier, reconciliation,
protocol and bounded-model targets. Their coverage is limited to the exact offline
assertions in the archive mapping; full runners/reports, read-only probes, node
adapter, fake-controller lifecycle, worker/shard parity, and complete U1-U10
enumeration over both mutation models remain `BLOCKED` where mapped. The strict
complete-bound two-mutation contract, projection-owner finite BFS, and fixture-driven
U1-U10 evaluator reducer are registered offline targets, but do not establish
unbounded properties or external service, deployment, or live campaign evidence.

These checks establish tool and in-process contracts only. A standalone TLA+ input
remains `BLOCKED` until run with an immutable, checksum-verified TLC tool. Database,
cache, broker, Docker, remote-node, and ignored integration suites require their own
isolated environment and postcondition evidence.

The CURRENT V6 authority runtime/issuance and invalidation recovery reducer contracts (`authority-runtime-reducer-contracts`, `authority-issuance-frontier-contracts`, `invalidation-recovery-reducer-contracts`) are likewise registered local/unit targets: they bind authority `Unknown` to readback-by-stable-lease-identity before retry, restrict proof consumption to `Ready`, pin the issuer frontier to strictly-new generations with an exact parent hash, and model outbox/inbox `IN_DOUBT`, exact provenance settlement, durable `APPLIED`, monotonic watermarks and reconciliation-gated `SERVING`. They establish no durable MySQL persistence, RabbitMQ transport, external arbiter/quorum, four-node, dual-database, TLC, or deployment evidence; those gates keep their own `BLOCKED`/`UNKNOWN` records.

The production-crate counterparts of those seams are registered as seven local/unit suites (V20): `trustgraph-invalidation-recovery-op-contracts` (15 tests), `trustgraph-invalidation-runtime-supervisor-contracts` (19), `hub-readiness-negative-contracts` (4, selected by the `fence_sync_` and `authority_pending_` libtest prefix filters), `db-authorization-readiness-contracts` (5), `single-node-readiness-liveness-contracts` (17), `mq-consumer-unknown-transition-contracts` (47) and `mq-invalidation-envelope-fail-closed-contracts` (29). The exact argv were rerun on the final Rust snapshot with 136 passed, 0 failed and 0 ignored; the Hub suite's two filters were executed as separate Cargo commands and reconciled to four tests. This is local/unit in-process evidence only: it proves no MySQL, RabbitMQ, four-node, dual-database, external arbiter, TLC, or deployment behavior; the ignored memory-hub performance matrix and real broker/database integration suites remain separately dispatched with their own postconditions.

The current source-writer/identity hygiene batch adds no new standalone `tests-suite` target: its contracts remain inline Rust tests in the owning crates. On the final frozen local snapshot, `cargo test -p astral-db --lib` reported 939 passed/0 failed/7 ignored, `cargo test -p astral-identity --lib` reported 149 passed/0 failed/0 ignored, and `cargo test -p astral-trustgraph --lib` reported 939 passed/0 failed/7 ignored. These counts include source-shape and bounded contracts for domains, user levels/gradings, inheritance, permission actions, resource-registry reconciliation, `last_login_at`, and verification supersession/CAS/GC. They do not establish real MySQL commit behavior, migration postconditions, RabbitMQ recovery, cross-replica rate limiting, or complete admission coverage for every remaining source owner; resource-type ordinary admission and verification audit consumers remain outside this local proof boundary.
