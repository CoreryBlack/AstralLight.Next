# Read-only authorization probe contracts

The former Python `e3_e4.py` probe implementation and its executable compatibility response have been physically removed. Its archived tests remain a historical method inventory. CURRENT V6 uses the Rust contracts registered in [`tests-suite/MANIFEST.toml`](../../../tests-suite/MANIFEST.toml); Redis probes and adapters are outside the current runtime and validation profiles.

## Current sources

| Source | Scope |
|---|---|
| [`test-harness/src/e4_preconditions.rs`](../../../test-harness/src/e4_preconditions.rs) | Typed SELECT-only precondition capture, optional SQL cache-epoch evidence, clock checks and status folding |
| [`test-harness/src/e3_e4_probe_native.rs`](../../../test-harness/src/e3_e4_probe_native.rs) | Read-only probe orchestration over injected SQL, command and signed-HTTP ports |
| [`test-harness/src/e3_e4_events.rs`](../../../test-harness/src/e3_e4_events.rs), [`e3_reconciliation.rs`](../../../test-harness/src/e3_reconciliation.rs), [`e4_protocol.rs`](../../../test-harness/src/e4_protocol.rs) | Offline event parsing, request reconciliation and protocol rules |
| [`archive/python-tests/test_e3_e4.py`](../archive/python-tests/test_e3_e4.py) | Non-executing historical method inventory; no Python fallback |

## Evidence boundary

The Rust offline suites use typed fakes or injected ports. They do not connect to a database, broker or deployed HTTP service, inject real faults, start workers, or prove deployed readiness. Their results must be recorded separately from real integration acceptance.

Precondition capture accepts single SELECT statements and records only bounded, scrubbed results. An explicitly configured SQL cache-epoch query is optional; absence yields `SKIP`, and missing or unreadable evidence cannot become `PASS`. This epoch field does not restore Redis support. Node names use aliases, and secret or host details must not enter stored reports.

The native probe contract includes injected signed decisions, SELECT snapshots, supplied worker-readiness facts and report folding. Real SQL, signed HTTP, SSH and worker lifecycle require separately authorized adapters and their own observed postconditions. No `e3_e4.py --self-test` entry point remains.

## Rust offline commands

From the repository root:

```bash
cargo test -p test-harness --locked --lib e4_preconditions::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e3_e4_events::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e3_reconciliation::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e4_protocol::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e3_e4_probe_native::tests:: -- --test-threads=1
```

These commands select the corresponding Rust assertions. A command listing is not execution evidence; test counts, ignored tests, internal `SKIP` markers and results belong in the task evidence.

## Limitations

Snapshot samples are not a complete event history and cannot establish per-attempt recovery. Supplied worker-health tuples do not prove a live worker is ready. HTTP `ALLOW` samples require request-side admission-event reconciliation before they can support a final authorization observation.

The registered `e3-e4-read-only-probe-parity` suite covers the native injected-port contract at offline scope. Deployment transport, real dependency state and recovery remain separate integration obligations. Historical Python files and independent model references are not executable acceptance alternatives.
