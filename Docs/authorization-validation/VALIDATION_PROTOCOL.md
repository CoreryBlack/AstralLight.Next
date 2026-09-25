# Authorization Validation Protocol

> Updated 2026-09-21. This document defines reusable validation entry points and
> record formats. It does not authorize execution; every live run still follows the
> execution, preflight, scope, and durable-postcondition gates in `AGENTS.md`.

## Common constraints

- Each run uses `campaign_id=authz-validation-<stable-id>`, each mutation uses a
  stable `operation_id`, each request uses a `request_id`, and each worker attempt uses
  an `attempt_id`.
- Durable reconciliation is scoped by canonical aggregate identity
  `(tenant_id, aggregate_type, aggregate_id)`. Cross-tenant rows, old head/outbox
  records, or unscoped source reads cannot prove the current run's postcondition.
- Use only an isolated test deployment, test database, and run-scoped Redis. Do not
  touch production data, secrets, or externally visible services.
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

For each live run, record MySQL isolation and primary routing, UTC session/time source,
clock offset, cache-generation initialization/rotation, Redis unavailability, stale
HMAC, pointer movement, worker restart, lease expiry, and unknown acknowledgements.
Every unproven failure path must terminate in `PENDING` or `DENY` with a reason code.
Unprovable prerequisites remain `BLOCKED` or `UNKNOWN`.

## E5: model and implementation comparison

The abstract state machine contains source commit, durable delta, publication CAS,
cache observations, strict current read, final reload, and host admission. The model
checks only the abstract protocol; runtime tests check implementation behavior. Neither
is a complete proof of every deployment.

The bounded model and controlled omission tests share these stable premise names:

- `pending_probe` -> `e2-pending-probe-omission`
- `post_recheck` -> `e2-cache-post-recheck-omission`
- `final_reload` -> `e2-final-reload-omission`
- `exact_identity` -> `e2-exact-identity-omission`
- `generation_revoke_fence` -> `e2-generation-revoke-fence-omission`
- `host_mediation` is model-only and has no runtime omission switch.

The classifier vocabulary (`strictly_before`, `overlap_unknown`,
`after_final_observation`, `not_stale`) is locked by the offline tests. Rename either
side only when the corresponding tests are updated together.

## Offline suites and lifecycle observations

The local Rust suites cover strict final reload/error classification, gateway identity
contracts, path/resource registration, and observation wiring. They remain in-process
checks. MySQL/Redis/RabbitMQ, Docker, ignored integration, remote-node, and live fault
scenarios require their own environment and remain `BLOCKED` until independently
reconciled.

Metrics record low-cardinality phases and result enums only. Identity, secrets, raw
paths, SQL/Redis keys, exception text, and request/operation correlation stay out of
Prometheus labels. A reducer `PASS` means only that its input boundaries are complete,
unique, and sortable; it is not a live publication proof.

## TLA+ input status

The independent TLA+ safety model is currently `BLOCKED`: this checkout has no pinned,
checksum-verified TLC tool. Do not download tools or start containers as part of the
offline suite. Until a verified run exists, the module remains a draft test input and
does not change any E1/E3/E4 status.
