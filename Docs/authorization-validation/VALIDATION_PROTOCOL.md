# Authorization Validation Protocol

> Updated 2026-10-28. This document defines reusable validation entry points and
> record formats. The current executable inventory and exact suite commands are the
> Rust `test-campaign` runner and [`tests-suite/MANIFEST.toml`](../../tests-suite/MANIFEST.toml).
> This document does not authorize execution; every live run still follows the
> execution, preflight, scope, and durable-postcondition gates in `../../AGENTS.md`.

## Common constraints

- Each run uses `campaign_id=authz-validation-<stable-id>`, each mutation uses a
  stable `operation_id`, each request uses a `request_id`, and each worker attempt uses
  an `attempt_id`.
- Durable reconciliation is scoped by canonical aggregate identity
  `(tenant_id, aggregate_type, aggregate_id)`. Cross-tenant rows, old head/outbox
  records, or unscoped source reads cannot prove the current run's postcondition.
- Use only an isolated test deployment and test database. The current Rust profile
  inventory is `native-kernel`, `offline-validation`, `native-single-node`,
  `standalone-rabbit`, `distributed`, `performance-kernel`, and `performance-native`,
  as registered in `tests-suite/MANIFEST.toml` and the Rust harness. Current native
  profiles do not use Redis; there is no current Redis compatibility feature, profile,
  or Cargo test target. Historical Redis/compatibility results remain historical evidence
  and are not current gates or fallback paths. Do not touch production data, secrets, or
  externally visible services.
- Each phase records a manifest, configuration and binary hashes, command, cwd,
  environment summary, start/end time, exit code, stdout/stderr artifacts, and cleanup.
- A timeout, stream break, killed process, incomplete log, or unproven durable
  postcondition is `UNKNOWN`; reconcile before any retry.
- When evidence is uncertain, the authorization decision remains `PENDING` or `DENY`.
  Absence of an observed stale `ALLOW` is not durable proof.
- Test-only failure controls must be explicit and must never enter a production profile.
- Reducers may sort events only within the same process observation and epoch. Missing
  stages, duplicate ambiguity, cross-epoch events, broken logs, missing terminal proof,
  or cross-node ordering without clock-offset evidence are `UNKNOWN` and excluded from
  percentile calculations.
- Runtime telemetry and offline reducers explain bottlenecks; they do not replace
  durable publication proof or upgrade a blocked live run.

## E1: full decision-path race

**Purpose:** cover the complete `PolicyEngine.evaluate() -> final reload -> host
ALLOW` path rather than a repository-only diagnostic path.

The request must pass signed-context validation, candidate matching, strict evidence
loading, mandatory final identity-stable reload, and host-side `ALLOW/PENDING/DENY`
recording. The fixture ruleset must be enabled and its owner tenant must exactly match
the signed actor tenant.

For every cycle:

1. Publish a known candidate grant and record its identity, revision, origin, scope,
   and manifest hash.
2. Start concurrent readers and record request start, candidate match, final reload,
   authoritative reads, stable check, decision return, and host admission.
3. Apply the source narrowing mutation with a stable operation ID. Reconcile source,
   scoped audit, the operation's terminal delta, and the matching `READY` strict pointer.
   A legacy head/outbox row is diagnostic only and cannot replace current publication
   proof.
4. Observe the delta terminal state, publication watermark, reader terminal states, and
   complete audit/log stream.
5. Classify each `ALLOW` as pre-commit, post-commit-before-final-observation,
   post-final-observation, or in-flight. Do not collapse the categories.

A strictly ordered sample whose mutation completes before the first final authoritative
read must not produce a stable `ALLOW`; it should be `PENDING`, `DENY`, or a result that
already reflects the narrowing. Overlapping intervals remain `UNKNOWN` unless they can
be ordered with the required clock evidence. The final reload identity must equal the
original candidate; a successor with the same resource/action cannot replace it.

## E2: controlled failure checks

Every scenario has a full-contract control and a test-only omission control. The control
may remove an admission connection but must not change source mutation, grant data, or
workload.

| Scenario | Omitted connection | Safety question |
|---|---|---|
| A | pending narrowing probe | Can old evidence be accepted before narrowing is published? |
| B | cache pre/post bracket | Can an interleaving produce an accepted mixed cache state? |
| C | final identity-stable reload | Can a successor replace the candidate? |
| D | exact identity binding | Can action match survive without revision/provenance equality? |
| E | revoke fence / generation check | Can a stale generation or pointer rollback be accepted? |

Every controlled run records the disabled premise, expected hazard, actual outcome,
repeatability, unchanged variables, and recovery. An expected outcome is never assumed
without an executed run.

## E3: recovery tail and request-side observations

Record enqueue, claim, attempt number, backoff, lease, parking/quarantine, terminal
transition, queue depth, published watermark, generation, worker readiness/liveness,
injection interval, drain interval, and fixed-interval decisions for target, unrelated,
and cold-start cards. Keep request-side decision/reason/latency samples separate from
publication-drain and per-event retry history. If a category is absent, retain the
weaker boundary supported by the available data.

## E4: deployment prerequisites and fail closed

For each live run, record the selected production profile, MySQL isolation and
primary routing, UTC session/time source, clock offset, integrity key rotation,
pointer movement, worker/receiver ownership, lease expiry and unknown completion.
The Rust `test-harness` contracts in `dependency_profiles` and `experiment_register`,
together with the MANIFEST profile/suite declarations, define the current dependency
and fault taxonomy. Use the Rust `test-campaign` runner to list/select registered suites;
these declarations do not launch live fault injection:

- `native-single-node`: MySQL, memory hub freshness/TTL/capacity, local projection
  admission/overflow/receiver ownership, source-commit uncertainty, sticky worker
  death, pointer/integrity fences, single-writer session and unknown local completion.
- `standalone-rabbit` and `distributed`: MySQL plus Rabbit transport and durable
  consumer/lease evidence; these are the only current profiles with RabbitMQ.
- `performance-kernel`: no external service dependency.
- `performance-native`: MySQL; HTTP/load evidence still requires its separately approved
  deployment and complete terminal evidence.

There is no current `redis-compat` profile or Redis-backed target. Historical Redis
campaigns and results stay unchanged as history and must not be re-run through retired
runners or treated as current evidence.

Every unproven failure path must terminate in `PENDING` or `DENY` with a reason code.
Plans and fake-controller tests are offline contracts, not executed native faults.
The live controller still requires explicit authorization, run-owned resources,
restoration, reconciliation, complete observations and durable postcondition proof.
No unknown outcome is automatically retried; missing live primitives remain
`BLOCKED`, and interrupted or unproven results remain `UNKNOWN`.

## E5: model and implementation comparison

The abstract state machine contains source commit, durable delta, publication CAS,
cache observations, strict current read, final reload, and host admission. The model
checks only the abstract protocol; runtime tests check implementation behavior. Neither
is a complete proof of every deployment.

Architectural premises added 2026-10 (runtime tests under `tests-suite/series/E4/`,
dependency classes registered by Rust `test-harness` contracts and indexed in
`tests-suite/MANIFEST.toml`):

- `memory_projection_hub` -> the invalidation notification is the load-bearing freshness
  fence: without it the hub serves the previous generation; with it the hub defers to
  durable (`premise_hub_invalidation`).
- `identity_mapping` -> a missing external identity mapping is refused with
  `INTEGRATION_NOT_AUTHORIZED`; mappings never leak across `app_id` boundaries
  (`premise_identity_mapping`).
- `single_writer_lease` -> a second composite writer is refused immediately while the
  lease is held, and the lease is re-acquirable after the holder's session closes
  (`premise_single_writer_lease`).
- Current profile configuration -> native/current suites use the registered strict
  profiles; there is no Redis compatibility adapter/profile or Redis-enabled Cargo
  target to configure. Historical redis-free configuration assertions are not a current
  Redis compatibility test surface.

The registered `native_projection_lifecycle` suite is intended to exercise a real
TrustGraph source repository add/revoke, committed local dispatch, durable delta/audit
correlation, publication pipeline, published pointer/fence and strict PolicyEngine read
with a production local projector owner. Source APIs dispatch the full immutable receipt
batch only after proven COMMIT; the WorkerOwned owner alone performs publication. Request
code only performs bounded read-only exact-completion observation under Rust norm §15.5.
It is one MySQL-backed ignored test per binary because process-global bus ownership is not
resettable, and it is not a signed HTTP host race campaign. No real integration is executed
by this documentation update; consult the run's own evidence before reporting a result.

The current Rust campaign entry point is `test-campaign`; inspect registered profiles and
suites through its list options, then use only the exact commands in
[`tests-suite/MANIFEST.toml`](../../tests-suite/MANIFEST.toml). The shell script
[`scripts/run-tests.sh`](../../scripts/run-tests.sh) only forwards arguments to that Rust
runner. The bounded model and controlled omission suites share these stable premise names:

- `pending_probe` -> `e2-pending-probe-omission`
- `post_recheck` -> `e2-cache-post-recheck-omission`
- `final_reload` -> `e2-final-reload-omission`
- `exact_identity` -> `e2-exact-identity-omission`
- `generation_revoke_fence` -> `e2-generation-revoke-fence-omission`
- `host_mediation` is model-only and has no runtime omission switch.

The classifier vocabulary (`strictly_before`, `overlap_unknown`,
`after_final_observation`, `not_stale`) is locked by the current Rust E1 contract.
Archived Python source/results remain historical only, not current gates, PASS evidence,
fallbacks, or runnable entry points. Any runtime evidence boundary remains at its
registered status in `tests-suite/MANIFEST.toml`; this protocol does not rewrite prior
reports.

## Offline suites and lifecycle observations

The production-profile/series index is in `tests-suite/MANIFEST.toml`; its runner is the
Rust `test-harness` crate's `test-campaign` binary. RQ components, authorization assumptions
M1-M5, E1-E5, MT-E and performance attribution are separate. On an actual run, the runner
executes registered argv against a frozen source hash and existing approved dependencies,
requires nonempty assertions, retains ignored/internal skips, and records `PASS`, `FAIL`,
`BLOCKED`, `SKIP`, `UNKNOWN` or `PENDING`. Per-series summaries describe only the selected
evidence scope, not a full live campaign. A registration or offline contract alone is not
proof that a suite ran. Finite bracket omission counterexamples explicitly remain
incomplete; current worker/shard suite coverage and the complete two-model U1-U10 release
suite are scoped as described by MANIFEST. Archived Python runner/probe implementations
are retired and are not executable recommendations or fallbacks; independent historical
reports/results remain unchanged. Inspect the current Rust suite contract for exact
execution boundaries; do not use retired Python commands.

The local Rust suites cover strict final reload/error classification, gateway identity
contracts, path/resource registration, and observation wiring. They remain in-process
checks. Current native real integration requires MySQL; RabbitMQ is specific to the
`standalone-rabbit` and `distributed` profiles, and current profiles do not depend on
Redis. Docker, ignored integration, remote-node and live fault scenarios require their
own approved environment and remain `BLOCKED` until independently reconciled.

## Complete policy evaluation benefit

The registered `policy-evaluate-benefit` suite is defined to measure the actual
production `PolicyEngine.evaluate()` call through the returned `PolicyDecision`, not only
a hub read. Its strict local adapter checks fixture PLATFORM_USER identity/card/tenant/domain,
uses a classified same-tenant target and an explicit Unmanaged ORG port, then calls the
actual hub. Registration or fixture contracts alone are not measured execution evidence.
The published evidence port remains owned: Arc reuse is internal to assembly caching,
not an Arc evidence/decision API through the engine. The normal validation, matching,
mandatory ALLOW final reload, statistics and circuit-breaker work remain enabled.

The registered suite contract freezes 45 cases before execution: grant sizes
1/8/128/512/2048, threads 1/4/8, and first/last matching ALLOW plus nonmatching
DEFAULT_DENY. Each case has 18 paired batches, rotating all six permutations of
fixed-second cache hits, unique-second forced assembly and real production-clock reads
three times. The contract does not itself assert that this measurement has run. Perpetual scoped grants
keep synthetic clock changes decision-equivalent. Forced assembly retains production
miss/refill costs, not an invented no-cache implementation. Actual cache TTL remains
active: the ideal warm arm must prove every read hit, and the production-clock arm
records its observed hit fraction. Every arm shares the same engine and published
maps while its assembly store is independent; no legacy/raw fallback is permitted.

Before measurement, execute owned evidence/decision parity, two-read ALLOW, one-read
DENY/PENDING, cross-second expiry and final-revoke controls. The optimized matrix
must contain complete `EVALUATE_PERF_META`, 45 `EVALUATE_PERF_CASE` records and one
`EVALUATE_PERF_END` terminal record. Acceptance checks exact topology, balanced orders,
per-decision positive ns, wall ns, fixture calls, read scope/grant/cache counts,
initial/final port timing, correct decisions, and joined workers. Missing/filtered,
debug, duplicate or malformed evidence is FAIL; interruption remains UNKNOWN.

For a completed measured run, preserve the raw observations in its canonical campaign
result. Calculate pooled p50/p99, median batch throughput, paired mean-decision-time and
throughput ratios, and reproducible bootstrap intervals over paired batches. These
intervals are exploratory, unadjusted across cases and conditional on one machine/run;
PASS certifies correct complete collection even when there is no measured improvement.
Latency excludes post-return assertions/destruction; throughput includes wake,
result verification/storage/destruction and joins, but excludes runtime/thread
construction and prewarm. Separate those units from repository phase timings.

No MySQL identity/eligibility or managed ORG queries, signature validation, HTTP
transport, durable audit delivery, SDK mapping, business admission, allocation
counts or deployed service capacity are inferred. Results and limitations are
recorded with source/tool/profile hashes and command artifacts; earlier hub-only
measurements cannot establish this complete-evaluation benefit. A bounded measured
example and its canonical run identifiers are in the
[complete-evaluation record](../实验/基准测试/policy-evaluate-benefit-20261010.md);
the protocol registry remains distinct from that run's acceptance state.

Metrics record low-cardinality phases and result enums only. Identity, secrets, raw
paths, SQL/Redis keys, exception text, and request/operation correlation stay out of
Prometheus labels. A reducer `PASS` means only that its input boundaries are complete,
unique, and sortable; it is not a live publication proof.

## TLA+ input status

The independent TLA+ safety model is registered as `BLOCKED` in the current inventory:
this checkout has no pinned, checksum-verified TLC tool. Do not download tools or start
containers as part of the offline suite. Until an independently verified run exists, the
module remains a draft test input and does not change any E1/E3/E4 status. This document
update did not execute the model or any database-backed/live integration suite.
