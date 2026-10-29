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

## Separate multi-tenant milestones

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
