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
| `test_e3_e4.py` | Offline unit tests using in-memory probes |

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

## Offline checks

From the repository root:

```bash
python -m unittest discover -s Docs/authorization-validation/tools \
  -t Docs/authorization-validation/tools -p 'test_e3_e4.py' -v
python Docs/authorization-validation/tools/e3_e4.py --self-test
```

Python 3.8+ standard library only. No database, cache, service, container, migration,
or network access is involved.

## Limitations

Snapshot sampling is not a complete event history and cannot establish per-attempt
recovery behavior. A successful fixture validator checks only the fixture structure;
it does not prove a live run. HTTP `ALLOW` observations also require request-side
admission-event reconciliation before treating them as final.
