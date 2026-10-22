# Authorization Validation and Reproduction

This directory contains executable Rust authorization validation tools and test inputs. It does not contain generated results or deployment archives.

## Scope

The directory contains:

- E1-E5 validation tools, Rust-native offline contracts, and archived Python test sources;
- an independent TLA+ safety-model draft and configuration inputs;
- implementation-to-test mapping for the M1-M5 authorization assumptions;
- protocols for race, fault, recovery, deployment-precondition, and evidence-gate checks.

The source tree publishes executable inputs and bounded checks. It does not publish
credentials, host routes, generated evidence, deployment logs, binaries, or private
infrastructure state.

## Status discipline

Validation states are explicit: `PLANNED`, `PASS`, `FAIL`, `BLOCKED`, `UNKNOWN`,
`PENDING`, and `SKIP`. Missing infrastructure, incomplete logs, interrupted streams,
or an unproven durable postcondition must never be converted to `PASS`. Offline unit
tests and abstract model checks do not prove a live database, cache, message broker,
or multi-node deployment.

## Files

- [`EVIDENCE_BOUNDARY_MATRIX.md`](EVIDENCE_BOUNDARY_MATRIX.md): validation targets,
  required evidence, supported conclusions, and downgrade conditions.
- [`VALIDATION_PROTOCOL.md`](VALIDATION_PROTOCOL.md): stable identifiers, read and
  write boundaries, E1-E5 scenarios, fault handling, and recovery observations.
- [`formal/README.md`](formal/README.md): independent TLA+ model inputs and their
  current `BLOCKED` boundary.
- [`tools/`](tools/): retained Python validation tools, read-only probes, classifiers,
  and lifecycle reducers; Python test modules have been moved out of discovery into
  [`archive/python-tests/`](archive/python-tests/README.md). The E5 single-mutation
  checker is implemented in Rust under `test-harness` with a retained baseline fixture.
- [`IMPLEMENTATION_MAP.md`](IMPLEMENTATION_MAP.md): M1-M5 authorization assumptions
  mapped to Rust implementation and test surfaces.

Generated `evidence/`, `artifact/`, result, log, credential, and private deployment
folders are intentionally excluded. A live run requires an isolated environment,
preflight, the execution gates in [`AGENTS.md`](../../AGENTS.md), and durable
postcondition reconciliation.

## Offline checks

From the repository root, the E1 pure event-classification contract and the
E5 single-mutation checker run in Rust. E1 checks same-process event ordering,
exact candidate identity, reachable interval categories, and multi-mutation
representation attribution; it does not parse live logs or establish runtime
behavior. The E1 target contains five Rust tests. E5's full bound-28 report is
regression-compared against the retained Python 2.1.0 baseline:

```bash
cargo test -p test-harness --locked --lib e1_validation::tests:: -- --test-threads=1
cargo run -p test-harness --bin e5-model-check -- --json
cargo test -p test-harness --locked e5_model::tests::full_contract_and_omission_counts_match_the_reference_checker -- --exact
```

The Rust campaign runner has offline fake-Cargo contracts for shell argument
forwarding, Cargo exit propagation, and invalid mode/selection rejection before
dispatch. `scripts/tests/test-run-tests.sh` runs those Rust-owned contracts;
`test_entrypoints.py` is only a compatibility forwarder and does not start a
campaign independently. These wrapper contracts use temporary fake Cargo
executables; they do not run the selected campaign.

The Rust offline harness also contains intentionally partial contracts. Their archived
Python tests are retained under [`archive/python-tests/`](archive/python-tests/README.md)
and are no longer current executable gates:

- `e3_reconciliation::tests::` validates typed, already-parsed E3 attempt
  histories against durable rows, process-epoch attempt pairing, host-admission
  cross-checks, and publication-drain evidence. It is not a JSON/log parser or
  E3 campaign runner: marker/window orchestration, sampling, four-category
  aggregation, full report construction, and injected-probe/controller lifecycle
  remain outside this Rust contract.
- `e4_protocol::tests::` checks typed fail-closed observation classification,
  authorization/preflight rules, one-apply recovery accounting, durable retry
  proof, bounded/redacted strings, and the closed-by-default plan. It does not
  implement the Python driver's fake-controller orchestration or its complete
  profile-specific fault matrix.
- `models::tests::` runs the abstract tenant model and checks T1, T3, T4, and T5.
  Conservation is checked by T5 over the full configuration and proper-gate
  omission set. The Python module's prose names conservation as T2, but neither
  executable report emits a T2 hypothesis; Rust preserves the executable
  T1/T3/T4/T5 registry rather than inventing one.
- `unbounded_confirmation::tests::` checks event-chain closure for the Rust
  single-mutation model in bracket/strict modes with all premises enabled and
  disabled, and compares its default and maximum bounds in both modes. Rust C1
  remains `BLOCKED` because the two-mutation model is absent; C2 covers only the
  single model, and C3/C4 remain `UNKNOWN`. This is not parity with the Python
  checker's two-model C1/C2 report.

The archived Python tests are not run by the readiness campaign or Rust campaign
runner. Current Rust-native offline suites include the E1 JSONL parser, dependency
profile/fault declaration matrix, experiment register, and E1/E3 lifecycle reducer,
in addition to the earlier E1 classifier, typed E3 reconciliation, E4 protocol,
tenant model, E5 single-mutation model, and single-model unbounded-confirmation
contracts. These contracts cover only the exact boundaries documented in the
archive mapping; declarations, parser records, and synthetic timing samples are not
runtime campaign evidence.

The full E1 runner and report, complete E3 runner/report, read-only E3/E4 probes,
E4 fake-controller lifecycle, bounded worker/shard, node adapter, legacy campaign
report schema, two-mutation model, universal-hypothesis computation, projection-owner
BFS, and full two-model unbounded-confirmation remain `BLOCKED` in
`tests-suite/MANIFEST.toml`. Archiving their Python sources does not convert these
items to `PASS`. Live service/DB campaigns remain dependency-gated and are not
offline migration evidence.

The Rust readiness command list replaces Python test discovery with explicit
Rust targets. It runs the complete offline harness and then some focused targets
for E5, tenant, E3, E4 and unbounded confirmation as separate evidence commands.
Those Rust targets overlap by design; the default `native-kernel`/`offline-validation`
profile selection in `tests-suite` omits the whole-harness suite unless that suite
is explicitly selected, preventing the campaign runner from also executing its
narrow contracts by default. No Rust test is claimed to replace an archived Python
contract beyond its registered boundary.

The focused Rust contract targets are:

```bash
cargo test -p test-harness --locked --lib e3_reconciliation::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e4_protocol::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib models::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib unbounded_confirmation::tests:: -- --test-threads=1
```

The former Python test commands are historical only: the 19 `test_*.py`
modules are preserved in [`archive/python-tests/`](archive/python-tests/README.md)
and are not discovered or dispatched. Do not run them as a current gate. Rust
`test-harness` targets above are the current offline test entry points within
their documented boundaries; parity suites for the remaining archived contracts
stay `BLOCKED` in the manifest. Live service/DB campaigns remain
dependency-gated and are not offline migration evidence. Remote reads,
migrations, service startup, fault injection, and durable source mutations
require separate safety gates and are not performed by the default offline tests.

The underlying Python model tools remain migration references, but after their
tests are archived they are not invoked as required readiness evidence. In
particular, the two-mutation and universal-hypothesis models remain `BLOCKED`
until their Rust equivalents are implemented.

```bash
cargo test -p test-harness --locked -- --test-threads=1
cargo test -p test-harness --locked --lib e5_model::tests::full_contract_and_omission_counts_match_the_reference_checker -- --exact
cargo test -p test-harness --locked --lib models::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e3_reconciliation::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib e4_protocol::tests:: -- --test-threads=1
cargo test -p test-harness --locked --lib unbounded_confirmation::tests:: -- --test-threads=1
```

`e1_validation::tests::` runs the five pure Rust E1 classifier tests. They cover
the exhaustive interval/domain grid, fail-closed identity/epoch/order/commit
evidence, two mutation-attribution paths, missing representation indices, and
complete candidate identity. This is a classifier/model contract only; it does
not parse the retained runner's event logs.

`e5-model-check` exhaustively enumerates the Rust bounded observation-protocol
model (one candidate grant, one revocation-class mutation) and checks the full
contract plus the six single-premise omissions. The JSON output is exactly
compared to the retained Python report fixture at the default bound. This is
abstract bounded-model evidence only, not implementation or deployment proof.

`e5_model_check_two_mutations.py` tightens the model's main structural abstraction to TWO concurrent
revocation-class mutations: the safety property becomes the conjunction over
both mutations (a committed-before-t_f mutation must be published AND
represented in the admitted evidence; an evidence set that no longer carries
the candidate at its own revision is a separate identity-substitution
violation). `universal_hypotheses_check.py` runs the stronger universal
hypotheses over the exhaustive enumerations of both models (theorem-domain
safety in both modes, domain accounting conservation, latch/window
universality, torn-read integrity, post-`t_f` accounting, the premise
necessity lattice -- all 62 subsets for the single model, the six
single-premise subsets for the heavier two-mutation model --, omission
sharpness, bound discipline, mode independence, report conservation) and can
freeze a digest-bound run manifest with `--manifest-out`. All of this remains
abstract bounded-model evidence: none of it proves the implementation, a
deployment, or any runtime behavior, and none of it upgrades a live
E1/E3/E4 status. `unbounded_confirmation.py` additionally verifies what the
step bound does and does not hide: event-space closure (every modeled chain
carries unique events, so the enumerated merge space is the entire schedule
space) and bound invariance at MAX_BOUND, while recording the levels that
stay outside mechanical reach today -- parameter unboundedness (the
reduction lemma to at most two mutations, empirically supported, mechanically
unconfirmed) and abstraction unboundedness (deductive proof via TLAPS/Coq,
BLOCKED until a pinned tool exists).

`projection_owner_model.py` separately explores the explicitly bounded request/worker
ownership protocol and runs omission controls plus deterministic scheduling-cost
comparisons. Its state/transition counts and synthetic operation counts are not
MySQL timings, unbounded liveness proofs, or deployment acceptance. The corresponding
real-database tests retain their own evidence scope and dependency requirements.

The `projection-owned-completion-integrity` campaign suite separately runs an ignored
real-MySQL contract on the explicitly approved run-owned clone. It checks exact
historical publication, multi-item commitment completeness, corruption rejection,
and whole-publication rollback after a late seal failure. Its concurrent lock-order
controls observe an actual blocked MySQL statement: a planner keeps the pointer
while completion waits, then verifies delta-lock availability and full frontier
progress. An inverted-order control must reject the delta `NOWAIT` probe. A
separate lane-held control verifies that completion cannot pre-lock the pointer
or active delta and never reports an unfinished event complete. Its synthetic
commands are not source-transaction or HTTP provenance evidence. Negative probes
roll back before the next probe; ambiguous outcomes retain fixtures and are not
replayed.
The `projection-owned-http` suite covers the in-process production signed router
and source-to-worker path; neither suite proves real-socket or multi-node deployment.
