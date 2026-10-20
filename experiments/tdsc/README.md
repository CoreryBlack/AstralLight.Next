# TDSC Experiment Harness

`compose.yml` is the only supported entrypoint for remote Docker evidence runs. It starts a run-scoped MySQL, Redis, RabbitMQ, Identity, TrustGraph, Learn, Gateway, and an optional workload container. The caller must supply every credential through environment variables; this directory contains no endpoint address, password, token, or encryption key.

## Required setup

1. Build or retrieve each service and workload image, then export its immutable digest as the corresponding `TDSC_*_IMAGE` variable.
2. Generate per-run credentials, `TDSC_SESSION_RESPONSE_AES_GCM_KEY`, and, for `lease`, `TDSC_POST_CLAIM_GATE_NONCE` outside the repository.
3. Select an unused `TDSC_RUN_ID` and matching `TDSC_COMPOSE_PROJECT`, a fixed seed, CPU sets, and memory limits.
4. Run `./experiments/tdsc/run.sh protocol` on an exclusive Docker host. The supported modes are `protocol`, `fault`, `performance`, and `lease`.

The preflight rejects a dirty worktree unless `TDSC_ALLOW_DIRTY_WORKTREE=true`, existing project containers, mutable image tags, missing runtime variables, non-performance CPU governor, or a host load above the configured threshold. Raw evidence is written below `results/<run-id>/`, which is deliberately ignored by Git.

## Workloads

- `protocol`: Runs the endpoint SEC matrix and recovery abuse matrix. It includes F5-style client-boundary concurrency: two same-key `recover-by-key` requests for one completed operation must return the same operation and access/refresh credential fingerprints without creating another durable operation or outbox sequence.
- `fault`: Uses a host-side orchestrator for F1 Redis pause/resume, F2 Redis restart and F3 MySQL pause during `recover-by-key`. The in-network probe never receives Docker control access. F3 requires a typed `503` with `DEPENDENCY_UNAVAILABLE` during the pause and the same credential response with one durable operation after MySQL resumes.
- `performance`: Runs a standard-library Python workload with a validated concurrency ladder, barrier-synchronized workers, monotonic timing, independent workload replicates, mutually exclusive outcomes, raw samples, and replicate-level summaries. It measures one protected endpoint on a shared warm deployment; it is not a cold-deployment test or a native-PDP comparison.
- `lease`: Starts a gated worker A first. After A has atomically claimed sequence 1, the host-side orchestrator starts worker B. After lease expiry, B must complete the first event and all ordered events. Evidence records only stable worker labels, counts, token fingerprints, and terminal-transition counts. The guarantee is at-least-once Redis desired-state convergence with owner-fenced durable finalization, not exactly-once Redis writes.
- `comparison`: Intentionally exits nonzero. There is no versioned comparison workload, so it must not create completed evidence.

## Evidence contract

Each completed run records the Git revision, dirty-state decision, seed, immutable image references, resource limits, source SQL checksums, Compose service status, workload output, run status, and SHA-256 checksums. It does not write the Compose-expanded environment because it would include secrets.

The protocol workload creates a run-scoped runtime user and owned active-card fixture only inside the isolated MySQL volume. It records statuses, reason codes, timings, durable-state summaries, stable worker labels, terminal-transition counts, and SHA-256 credential or JTI fingerprints. Access tokens, refresh tokens, passwords, idempotency keys, Redis keys, raw HTTP bodies, database credentials, operation identifiers, nonces, host addresses, and encryption keys remain in temporary runner storage or the runtime environment and are never written to `/evidence`.

The current code and harness have static and unit-test coverage, but no Docker, TLC, fault, lease, protocol, or performance result is implied by this README. Publishable experimental evidence requires a successful run on an exclusive Docker host with immutable image digests and externally retained evidence checksums.
