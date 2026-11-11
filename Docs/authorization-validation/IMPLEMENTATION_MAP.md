# M1-M5 Authorization Assumption Map

This file maps the authorization safety assumptions M1-M5 to the public Rust
implementation and test surfaces. The labels are engineering validation labels and are
independent of the separate multi-tenant delivery milestones that also use M1-M3. Current
executable suite/profile inventory and exact commands are defined by the Rust
`test-campaign` runner and [`tests-suite/MANIFEST.toml`](../../tests-suite/MANIFEST.toml).

| Assumption | Public implementation/test surface | What it can establish | Remaining boundary |
|---|---|---|---|
| M1: source capture | `tests-suite/series/RQ3/authorization_projection_integration.rs`; ruleset repository; source-generation, delta, outbox, revoke-fence, and tenant-scoped mutation code | Exercises selected durable source mutation, generation, and tenant-binding contracts | Not a mechanized proof of atomic capture for every aggregate and affected scope |
| M2: monotone publication | projection, organization-scope, and partition-lease tests; CAS/pointer/generation code; the composite single-writer lease (`GET_LOCK` with monitored lifetime) and the local projection bus that dispatches committed deltas in-process | Exercises selected publication, pointer advancement, projector, and lease-reclaim paths | General multi-writer ordering, replica divergence, and every deployment schedule remain outside local proof |
| M3: faithful representation | projection repository, evidence/cache tests, final-reload tests, and the memory projection hub (invalidation as freshness fence; served state only from committed publications) | Exercises lineage, evidence identity, unpublished-delta gates, and fail-closed reads | Does not prove faithful representation under every storage, process, or deployment failure |
| M4: trusted storage and processes | fail-closed checks, offline harness tests, and the independent TLA+ input | Exercises mismatch/error handling and safe defaults | Non-Byzantine storage/processes and trusted integrity keys remain explicit assumptions; the TLA+ input is `BLOCKED` until verified |
| M5: complete mediation | gateway contract tests, permission middleware, host-admission tests, the mediation omission model, and the SDK integration path's mandatory external identity mapping (`INTEGRATION_NOT_AUTHORIZED` on absence, no bypass) | Exercises signed context, middleware, and selected host-admission contracts | Complete mediation of every deployed host operation is not established by this checkout alone |

List the registered Rust suites with
`cargo run --locked -p test-harness --bin test-campaign -- --list --json`; use only the
exact registered suite/profile commands in MANIFEST for a run. `scripts/run-tests.sh`
forwards to the same Rust runner. Historical or compatibility `entry` records are not
necessarily dispatchable Cargo targets; listing is inventory, not a test result.

E1-E5 are validation/tool labels, not independent proofs of M1-M5. The bounded models
and omission checks provide implementation and model coverage only. Archived Python test
sources and historical reports are indexed at
[`archive/python-tests/README.md`](archive/python-tests/README.md); they are not current
gates, PASS evidence, fallback paths, or runnable recommendations. Rust coverage is
limited to the specified registered contracts, and remaining runtime/deployment gaps
retain their status in the manifest; this map does not rewrite historical results.

## V7 current read-surface boundary (2026-11-09)

The current checkout uses three explicit read surfaces and a separate authority-root contract:

| Surface | Current owner | Positive-read rule | Evidence state |
|---|---|---|---|
| DB-primary | credentials, sessions/JWT/refresh, revocation, audit/ledger, management, cold/recovery | durable status or transaction proof is required | local code boundary; live DB/recovery not run |
| DB-backed accelerator | `MemoryProjectionHub`, `AuxiliaryAuthorizationMirror`, verified-positive session mirror | hit may reduce DB work; miss/stale/suspect must strict-refill or deny by frozen profile | partial/local contracts |
| Certified-memory authority | immutable certified snapshot, authority frontier, ownership/SoD and serving gate | only complete attested serving snapshot; no SQL fallback on miss | composition boundary implemented; current service runtimes pass no serving certified store |

The V7 certified-memory root is now an additive authority contract: six fact families, explicit complete coverage, canonical root digest/signature, current/history continuity, operation idempotency, leader/token fencing, and client-side response verification. A durable completion ledger, strict row reader, six explicit ledger-backed family adapters, caller-owned proof-only completion sink, and operation-id width contract now exist locally; they consume only source-owner completion rows and do not infer empty coverage. The root contract and snapshot/runtime primitives have focused Rust evidence, but no source owner currently writes all six production completion families and the root and local snapshot have not been installed byte-for-byte.

**Source and receipt review (2026-11-10):** No family yet has a complete production path from actual durable source through authority receipt to ledger. The ledger writer's field and payload-digest checks do not establish authority provenance; single-card or member reads do not prove a complete family inventory. The 4213/0/119 workspace result applies only to its earlier frozen snapshot, with ignored tests counted as SKIP. See [process evidence §0M](认证内存授权状态机实施过程报告_2026-11-08.md#0m-2026-11-10-冻结快照工作区验证).

**Later security review (2026-11-10):** The 4193/0/119 result below predates subsequent authority changes and is not the final gate for the changed code. Family aggregate cannot automatically certify a GLOBAL reservation, and certified-memory root install/read fail closed until exact per-scope publication and snapshot proof are implemented. Production Serving remains unproven.

The local coordinator validates the already-authoritative family bundle, canonical snapshot content digest, verified root record, attestation binding, generation/revoke and independent worker/frontier/transport readiness before reusing the existing runtime Serving transition. The 2026-11-10 current workspace snapshot passed `cargo check --workspace --offline --locked`, `cargo clippy --workspace --all-targets --offline --locked -- -D warnings`, `git diff --check`, and `cargo test --workspace --offline --locked` with **4193 passed, 0 failed, 119 ignored**. `cargo fmt --all -- --check` exited `1` because the inherited dirty worktree contains pre-existing formatting differences; the workspace formatter was not used to overwrite existing user changes. This is local Rust evidence only: the six adapters do not materialize source-owner completion rows, call the authority transport, or make `MemoryProjectionHub`, a DB mirror, a RabbitMQ ACK or a local heartbeat into root evidence. The durable builder remains `Pending/Unavailable` until source-owned completion, authority proof, and readiness are available.

The durable snapshot builder deliberately returns `Pending`/`Unavailable` when it cannot prove complete six-family coverage, authority binding, or complete inventory. It does not convert strict published-evidence reads into a Serving root. Full certified authorization composition, F0/F1 signed integration equality, certified ORG/dynamic-owner projection, single-node Serving, MySQL/RabbitMQ/etcd/quorum/mTLS, migration, multi-node, S15/TLC, and deployment evidence remain `PARTIAL`, `BLOCKED`, or `UNKNOWN` as recorded in the validation reports.

The local composition root is now explicit in `astral-db/src/certified_memory_runtime.rs`: it owns materializer/builder/installer lifecycle, exposes `require_serving()`, and provides an explicit durable-owner-context constructor that installs the six ledger adapters. `ensure_authorization_read_surface()` lets Identity, TrustGraph, and Monitor reuse the already-frozen profile and rejects profile split-brain; it does not create a CertifiedMemory candidate with an empty store. Focused Rust evidence covers 4 owner tests, 4 completion-ledger tests, and 3 composition-root tests. Host runtime checks passed locally. These results establish fail-closed composition only; the default startup path remains unavailable until source completion, authority/root transport, and readiness proofs are supplied.

The architecture documentation uses M1-M3 for a different delivery plan. Its public
Rust tests are:

- architecture M1: partition-lease integration and tenant-isolation benchmarks;
- architecture M2: organization-scope integration, projector/service tests, and the
  ORG_SCOPE migrations;
- architecture M3: pointer-advance reclaim coverage and related repository tests.

Database-backed suites are `#[ignore]` tests and require an approved isolated MySQL
service plus pre-migrated test data. The current profile inventory has seven entries in
`tests-suite/MANIFEST.toml`: `native-kernel`, `offline-validation`, `native-single-node`,
`standalone-rabbit`, `distributed`, `performance-kernel`, and `performance-native`.
RabbitMQ is used only by the `standalone-rabbit` and `distributed` profiles. No current
profile, feature, or Cargo test target uses Redis. Historical Redis/compatibility entries
remain history or explicitly blocked boundaries; their presence in the inventory is not
an executable current target or execution result.

## Production-profile index

`tests-suite/MANIFEST.toml` indexes current suites and historical/blocked scopes with
their production dependency contract, exact Rust argv or explicit blocker. The Rust
`test-harness` crate's `test-campaign` binary validates the index before dispatch,
retains nonempty assertion/ignored/SKIP evidence, records a frozen content hash and never
provisions dependencies or retries unknown results. `scripts/run-tests.sh` only forwards
to this Rust runner. Retired Python runner/probe implementations are not execution or
migration recommendations; independent historical reports/results remain unchanged and
are not current gates, PASS evidence, or fallbacks.

The registered `native-projection-lifecycle` suite is a single ignored real-MySQL target
intended to exercise the production TrustGraph source repository, post-commit local
projection dispatch, durable delta/audit correlation, production local worker ownership,
published pointer/fence and strict PolicyEngine evaluation. After proven COMMIT, source
APIs dispatch the complete immutable receipt batch; publication belongs exclusively to
the WorkerOwned owner. A request may only observe exact durable completion through the
bounded read-only wait defined in the Rust norm §15.5. It contributes selected M1/M2/M3
implementation coverage only; this document update did not run it.
Strict tenant fixtures and policy benchmarks separately
exercise scope and final reload while rejecting legacy/raw ports; their timings are
CPU component data, not MySQL/HTTP performance.

Native integration requires MySQL with LocalBus/LocalProjectionBus and the memory
hub; `standalone-rabbit` and `distributed` require MySQL + RabbitMQ. No current profile
uses Redis. Historical RQ/S15 Redis/OPA harnesses and results remain historical or
blocked boundaries, not current executable inputs; current native architecture does not
add middleware to replay them.
Live signed-host races, complete mediation, fault controllers and full distributed
research campaigns remain outside this local result. A per-series `PASS` applies only
to selected component/model/integration evidence, never to an unexecuted full campaign.

## Status boundary

The standalone repository publishes executable source, fixtures, and the Rust runner. It
may retain historical result records separately; those records are not current run
artifacts or current gates. It does not publish credentials, node routing, or live
campaign binaries/results. Missing infrastructure, missing pinned TLC, incomplete live
controller inputs, or absent deployment postconditions remain `BLOCKED`, `UNKNOWN`,
`PENDING`, or `SKIP` according to `AGENTS.md`; source presence never converts them to
`PASS`. The current documentation edit did not run Cargo, a service, or real integration.
