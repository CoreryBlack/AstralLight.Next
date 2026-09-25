# M1-M5 Authorization Assumption Map

This file maps the authorization safety assumptions M1-M5 to the public Rust
implementation and test surfaces. The labels are engineering validation labels and are
independent of the separate multi-tenant delivery milestones that also use M1-M3.

| Assumption | Public implementation/test surface | What it can establish | Remaining boundary |
|---|---|---|---|
| M1: source capture | `astral-db/tests/authorization_projection_integration.rs`; ruleset repository; source-generation, delta, outbox, revoke-fence, and tenant-scoped mutation code | Exercises selected durable source mutation, generation, and tenant-binding contracts | Not a mechanized proof of atomic capture for every aggregate and affected scope |
| M2: monotone publication | projection, organization-scope, and partition-lease tests; CAS/pointer/generation code | Exercises selected publication, pointer advancement, projector, and lease-reclaim paths | General multi-writer ordering, replica divergence, and every deployment schedule remain outside local proof |
| M3: faithful representation | projection repository, evidence/cache tests, and final-reload tests | Exercises lineage, evidence identity, unpublished-delta gates, and fail-closed reads | Does not prove faithful representation under every storage, process, or deployment failure |
| M4: trusted storage and processes | fail-closed checks, offline harness tests, and the independent TLA+ input | Exercises mismatch/error handling and safe defaults | Non-Byzantine storage/processes and trusted integrity keys remain explicit assumptions; the TLA+ input is `BLOCKED` until verified |
| M5: complete mediation | gateway contract tests, permission middleware, host-admission tests, and the mediation omission model | Exercises signed context, middleware, and selected host-admission contracts | Complete mediation of every deployed host operation is not established by this checkout alone |

E1-E5 are validation/tool labels, not independent proofs of M1-M5. The bounded Python
model and omission tests provide implementation and model coverage only.

## Separate multi-tenant milestones

The architecture documentation uses M1-M3 for a different delivery plan. Its public
Rust tests are:

- architecture M1: partition-lease integration and tenant-isolation benchmarks;
- architecture M2: organization-scope integration, projector/service tests, and the
  ORG_SCOPE migrations;
- architecture M3: pointer-advance reclaim coverage and related repository tests.

Database-backed suites are `#[ignore]` tests and require isolated MySQL/Redis/RabbitMQ
services plus migrations. Their presence in this checkout is not an execution result.

## Status boundary

The standalone repository publishes executable source, fixtures, and runners. It does
not publish historical evidence archives, credentials, node routing, binaries, or
generated campaign results. Missing infrastructure, missing pinned TLC, incomplete live
controller inputs, or absent deployment postconditions remain `BLOCKED`, `UNKNOWN`,
`PENDING`, or `SKIP` according to `AGENTS.md`; source presence never converts them to
`PASS`.
