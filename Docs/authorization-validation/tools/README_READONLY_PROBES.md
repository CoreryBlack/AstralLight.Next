# Read-Only Authorization Probes

This module provides offline-tested read-only helpers for sampling authorization
state and validating fault-matrix fixtures. It uses `Exec-L1` by default and performs
no I/O unless a caller supplies an injected `ReadOnlyProbe`.

## Safety boundary

- All SQL is validated as a single `SELECT`; Redis access is limited to `LLEN`, `GET`,
  and `PING`; HTTP reads use signed `GET` requests.
- The module does not mutate data, inject faults, start or stop services, or write results.
- Node labels are replaced with `node-<index>` aliases. Probe strings are scrubbed for
  host-like values and truncated before return.
- Unprovable prerequisites remain `BLOCKED`, `UNKNOWN`, or `SKIP`; they never collapse
  into `PASS`.

## Files

| File | Purpose |
|---|---|
| `e3_e4.py` | Read-only probes, precondition capture, state sampling, and fault-outcome validation |
| [`archive/python-tests/test_e3_e4.py`](../archive/python-tests/test_e3_e4.py) | Archived test source; not a current executable test gate |

The real adapter is supplied by a separately gated caller. This module checks its own
query restrictions and does not construct a live adapter.

## Probe contract

```python
class ReadOnlyProbe(Protocol):
    def sql(self, query: str) -> list[list[str]]: ...
    def redis(self, *argv: str) -> str: ...
    def signed_get(self, node: str, path: str) -> tuple[int, dict]: ...
```

`capture_e4_preconditions` records database isolation/read-only state, session timezone,
clock offset, and cache-generation state. `sample_e3` captures fixed-interval durable
row counts, Redis pointers, optional queue depth, worker liveness, and per-card signed
decisions. `evaluate_fault_outcomes` accepts only `PENDING` or `DENY` with a reason
code for configured failure fixtures.

## Current offline checks

From the repository root, run the selected Rust contracts:

```bash
cargo test -p test-harness --locked --lib e4_preconditions::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e3_e4_events::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e3_reconciliation::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e4_protocol::tests:: -- --test-threads=1
```

`e4_preconditions::tests::` uses an in-memory typed fake to check SELECT-only scalar
capture, the MySQL 5.7 isolation fallback, the Redis GET allowlist, clock skew,
fail-closed status folding, and host scrubbing. It does not invoke a live probe or
prove any deployed database/cache state. `e3_e4_events::tests::` checks offline log
parsing and request-terminal rules. The E3 sampling, signed HTTP transport and full
probe lifecycle remain outside these contracts. `e3_e4.py --self-test` is retained
as a fail-closed compatibility response and exits nonzero with `BLOCKED`; it does
not discover archived tests. No database, cache, service, container, migration,
or network access is involved in the Rust offline tests.

## Limitations

Snapshot sampling is not a complete event history and cannot establish per-attempt
recovery behavior. A successful fixture validator checks only the fixture structure;
it does not prove a live run. HTTP `ALLOW` observations also require request-side
admission-event reconciliation before treating them as final.

The Rust `e4_preconditions` module covers the offline typed fake-probe contract
for E4 precondition capture; `e3_e4_events`, `e3_reconciliation`, and `e4_protocol`
cover their separately registered parser, evidence, and protocol boundaries. They
do not establish live database/cache state, implement E3 interval sampling, or
prove signed HTTP transport and worker readiness. The archived Python test source
is a migration reference, not an executable fallback; the full
`e3-e4-read-only-probe-parity` suite remains `BLOCKED` in
[`../../../tests-suite/MANIFEST.toml`](../../../tests-suite/MANIFEST.toml).
