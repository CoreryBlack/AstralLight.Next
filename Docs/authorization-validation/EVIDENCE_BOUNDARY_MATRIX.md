# Validation Boundary Matrix

> This matrix records what each validation target can establish and when a result
> must be downgraded. It is an engineering control, not a publication-results table.

Allowed states are `BASELINE`, `PLANNED`, `PASS`, `FAIL`, `BLOCKED`, `UNKNOWN`,
`PENDING`, and `SKIP`. `PLANNED` is not an execution result, and `UNKNOWN` must not
be rewritten as `PASS`.

| ID | Validation target | State | Required evidence | Supported boundary | Stop or downgrade condition |
|---|---|---|---|---|---|
| V1 | Observe a stale-authorization race between source narrowing and host admission | BASELINE | Historical diagnostic run plus an isolated production-path run | Only the observed workload and protocol boundary | If the production path is not connected, retain the diagnostic-only boundary |
| V2 | Verify that `PolicyEngine.evaluate()` final reload fails closed after pre-observation narrowing | PLANNED | Production entry, final reload, host decision, and ordered timestamps | Static grant contract, one authoritative writer, and declared M1-M5 assumptions | Missing timestamps or interrupted logs => `UNKNOWN` |
| V3 | Bind final reload to the original candidate instead of a successor grant | PLANNED | Remove/regrant race, successor revision, and exact identity checks | The declared ledger identity contract | Do not infer identity safety when logical ID and revision are not separated |
| V4 | Treat pending probe, cache bracket, final reload, generation fence, and host mediation as independent gates | PLANNED | Isolated test-only controls and a full-contract control | The controlled workload and failure mode only | Stop if a control changes source semantics or cannot be restored |
| V5 | Default to `PENDING` or `DENY` when publication is not proven | BASELINE + PLANNED | DB/cache/projector/lease/restart/parse/integrity fault matrix with reason codes | Fail-closed decision semantics | Block when the HTTP envelope and business reason code disagree |
| V6 | Separate publication backlog cost from request-side availability | BASELINE + PLANNED | Per-event attempts, queue depth, target/unrelated decision samples, and drain timeline | The recorded workload and sampling boundary | Without request-side samples, report only a workload-level recovery observation |
| V7 | Check deployment prerequisites instead of treating them as assumptions | PLANNED | Isolation level, primary routing, UTC/clock offset, and cache-generation manifest | Only the values observed in the run | Unarchivable or drifting values => `BLOCKED` or fail closed |
| V8 | Explain implementation cost by phase | BASELINE + PLANNED | Cold/warm cache, signed admission, strict read, and final reload timings | Same workload and declared boundary only | Do not compare runs with different workloads or boundaries |
| V9 | Make a validation run reproducible without private host state | PLANNED | Manifest, hashes, redacted configuration, and rerun transcript | Digest integrity plus the published source surface | Missing production schema or binary must be stated explicitly |
| V10 | Keep the threat boundary limited to races and evidence integrity | BASELINE | Attack-surface review and explicit exclusions | Non-Byzantine storage/processes and declared deployment assumptions | Never generalize to Byzantine storage, arbitrary attackers, or replica divergence |

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
   publication, audit, pointer, head/outbox, or other durable proof.

## Offline validation boundary

The following may be executed without external services:

- the Rust runtime unit suites and gateway contract tests;
- Python harness, classifier, reducer, and model unit tests;
- the bounded model command when its local checks are available.

These checks establish tool and in-process contracts only. A standalone TLA+ input
remains `BLOCKED` until run with an immutable, checksum-verified TLC tool. Database,
cache, broker, Docker, remote-node, and ignored integration suites require their own
isolated environment and postcondition evidence.
