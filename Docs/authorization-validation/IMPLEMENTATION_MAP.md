# M1-M5 Authorization Assumption Map

This file maps the authorization safety assumptions M1-M5 to the public Rust
implementation and test surfaces. The labels are engineering validation labels and are
independent of the separate multi-tenant delivery milestones that also use M1-M3.

| Assumption | Public implementation/test surface | What it can establish | Remaining boundary |
|---|---|---|---|
| M1: source capture | `astral-db/tests/authorization_projection_integration.rs`; ruleset repository; source-generation, delta, outbox, revoke-fence, and tenant-scoped mutation code | Exercises selected durable source mutation, generation, and tenant-binding contracts | Not a mechanized proof of atomic capture for every aggregate and affected scope |
| M2: monotone publication | projection, organization-scope, and partition-lease tests; CAS/pointer/generation code; the composite single-writer lease (`GET_LOCK` with monitored lifetime) and the local projection bus that dispatches committed deltas in-process | Exercises selected publication, pointer advancement, projector, and lease-reclaim paths | General multi-writer ordering, replica divergence, and every deployment schedule remain outside local proof |
| M3: faithful representation | projection repository, evidence/cache tests, final-reload tests, and the memory projection hub (invalidation as freshness fence; served state only from committed publications) | Exercises lineage, evidence identity, unpublished-delta gates, and fail-closed reads | Does not prove faithful representation under every storage, process, or deployment failure |
| M4: trusted storage and processes | fail-closed checks, offline harness tests, and the independent TLA+ input | Exercises mismatch/error handling and safe defaults | Non-Byzantine storage/processes and trusted integrity keys remain explicit assumptions; the TLA+ input is `BLOCKED` until verified |
| M5: complete mediation | gateway contract tests, permission middleware, host-admission tests, the mediation omission model, and the SDK integration path's mandatory external identity mapping (`INTEGRATION_NOT_AUTHORIZED` on absence, no bypass) | Exercises signed context, middleware, and selected host-admission contracts | Complete mediation of every deployed host operation is not established by this checkout alone |

E1-E5 are validation/tool labels, not independent proofs of M1-M5. The bounded Python
model and omission tests provide implementation and model coverage only.

## Separate multi-tenant milestones

The architecture documentation uses M1-M3 for a different delivery plan. Its public
Rust tests are:

- architecture M1: partition-lease integration and tenant-isolation benchmarks;
- architecture M2: organization-scope integration, projector/service tests, and the
  ORG_SCOPE migrations;
- architecture M3: pointer-advance reclaim coverage and related repository tests.

Database-backed suites are `#[ignore]` tests and require an isolated MySQL service plus
migrations; Redis- and RabbitMQ-backed suites additionally require the opt-in `redis-compat`
feature and a Rabbit transport respectively. The single-node composite is a strict Redis-free
deployment (redis projection compatibility is refused at startup without a compiled adapter). Their presence in this checkout is not an execution result.

## Production-profile index

`tests-suite/MANIFEST.toml` indexes every RQ/M/E/MT/performance, compatibility and
excluded scope with its production dependency contract and exact command or explicit
blocker. `scripts/test_campaign.py` validates this index before dispatch, retains
nonempty assertion/ignored/SKIP evidence, records a frozen content hash and never
provisions dependencies or retries unknown results.

`tests-suite/tests/native_projection_lifecycle.rs` adds a single ignored real-MySQL
binary exercising the production TrustGraph source repository, post-commit local
projection dispatch, durable delta/audit correlation, production local worker ownership,
published pointer/fence and strict PolicyEngine evaluation. Source APIs can publish
synchronously after COMMIT, so the test does not attribute every publication exclusively
to the async worker. It contributes selected M1/M2/M3 implementation coverage only.
Strict tenant fixtures and policy benchmarks separately
exercise scope and final reload while rejecting legacy/raw ports; their timings are
CPU component data, not MySQL/HTTP performance.

Native integration requires only MySQL with LocalBus/LocalProjectionBus and the memory
hub; standalone/current distributed transport requires MySQL + RabbitMQ; Redis remains
compat-only. Historical RQ/S15 harnesses that require Redis/OPA are retained as legacy
inputs with `BLOCKED` current-campaign status rather than adding middleware to native.
Live signed-host races, complete mediation, fault controllers and full distributed
research campaigns remain outside this local result. A per-series `PASS` applies only
to selected component/model/integration evidence, never to an unexecuted full campaign.

## Status boundary

The standalone repository publishes executable source, fixtures, and runners. It does
not publish historical evidence archives, credentials, node routing, binaries, or
generated campaign results. Missing infrastructure, missing pinned TLC, incomplete live
controller inputs, or absent deployment postconditions remain `BLOCKED`, `UNKNOWN`,
`PENDING`, or `SKIP` according to `AGENTS.md`; source presence never converts them to
`PASS`.
