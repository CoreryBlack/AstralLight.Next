# Archived authorization Python tests

These 19 Python test modules were moved from `../../tools/` on 2026-10-22. Their
contents are retained as migration history and review references; they are not a
current test gate and must not be counted as Rust parity or a current `PASS`.
The archive directory is outside the Python tools discovery root, and no current
runner discovers or dispatches these modules.

The Rust targets below are the current executable replacements only for the
specified subcontracts. Any named `BLOCKED` suite remains migration-pending even
though its Python source is archived.

| Archived source | Current Rust target / suite | Coverage status and boundary |
|---|---|---|
| `test_bounded_model_execution.py` | `bounded-worker-shard-contracts` | `BLOCKED`: Rust two-mutation worker/shard partition and reducer are not implemented. |
| `test_classify_e1_properties.py` | `e1-event-classifier`; `e1-live-log-parser-parity` | Partial: Rust covers typed event classification; the Python JSON/log parser and parser failure contracts remain `BLOCKED`. |
| `test_dependency_profiles.py` | `dependency-profile-fault-matrix-contracts` | `BLOCKED`: campaign profile validation is not the eight-profile E4 dependency/fault cross-product. |
| `test_e1_runner.py` | `e1-live-log-parser-parity` | `BLOCKED`: live-log parsing and runner orchestration have no equivalent Rust contract. |
| `test_e3_e4.py` | `e3-e4-read-only-probe-parity`; `e3-attempt-reconciliation-contract`; `e4-protocol-contract` | Partial: selected typed Rust E3/E4 checks run; SQL/Redis/HTTP probes, precondition capture, sampling, and the full probe suite remain `BLOCKED`. |
| `test_e3_runner.py` | `e3-runner-report-parity`; `e3-attempt-reconciliation-contract` | Partial: Rust covers typed post-parse reconciliation only; runner phases, sampling, aggregation, and full report parity remain `BLOCKED`. |
| `test_e4_fault_driver.py` | `e4-fake-controller-lifecycle-parity`; `e4-protocol-contract` | Partial: selected typed protocol rules run in Rust; fake-controller lifecycle and profile fault matrix remain `BLOCKED`. |
| `test_e5_model_check.py` | `e5-bounded-single` | Migrated: the Rust single-mutation bounded model and full bound-28 report are checked against a retained reference fixture. This is abstract model evidence, not runtime/deployment proof. |
| `test_e5_model_check_two_mutations.py` | `e5-bounded-two-mutations`; `bounded-worker-shard-contracts` | `BLOCKED`: equivalent Rust two-mutation state-space and deterministic shard/reducer contracts are absent. |
| `test_experiment_common.py` | `e1-event-classifier`; `e1-live-log-parser-parity`; `e3-runner-report-parity` | Partial: typed E1/E3 subcontracts are covered; shared event parsing and report helpers are not fully migrated and remain `BLOCKED`. |
| `test_experiment_register.py` | `experiment-register-contracts` | `BLOCKED`: Rust does not yet implement the experiment register and its cross-links. |
| `test_lifecycle_reducer.py` | `authorization-lifecycle-reducer-contracts` | `BLOCKED`: no equivalent Rust lifecycle timing reducer, unknown-sample accounting, or percentile contract exists. |
| `test_model_acceptance.py` | `e5-bounded-single`; `e5-universal-bounded`; `legacy-campaign-report-acceptance-parity` | Partial: the Rust single-model and selected tenant acceptance contracts run; universal report and legacy campaign schema parity remain `BLOCKED`. |
| `test_node_adapter.py` | `node-adapter-probe-contracts` | `BLOCKED`: no Rust node adapter, signed-request, transport, or log-slicing contract exists. |
| `test_projection_owner_model.py` | `projection-owner-model-contracts` | `BLOCKED`: equivalent Rust reachable-state BFS and omission controls are absent. |
| `test_run_single_node_campaign.py` | `legacy-campaign-report-acceptance-parity`; `harness/runner-contracts` | Partial: Rust campaign manifest/dispatch and fake-Cargo contracts run; legacy readiness report and artifact-schema parity remain `BLOCKED`. |
| `test_tenant_isolation_model.py` | `offline-tenant-model` | Migrated within the registered boundary: Rust checks T1/T3/T4/T5 across the bounded assignment space; it does not prove SQL or runtime isolation. |
| `test_unbounded_confirmation.py` | `unbounded-confirmation-single-partial`; `unbounded-confirmation-two-model-parity` | Partial: Rust checks single-model event-chain closure and bound invariance; the two-model aggregate remains `BLOCKED`. |
| `test_universal_hypotheses_check.py` | `e5-universal-bounded` | `BLOCKED`: complete U1–U10 evaluation over both Rust models is not implemented. |

Use the registered Rust suites in `tests-suite/MANIFEST.toml` for current
validation. A blocked suite remains blocked until its Rust replacement preserves
and validates the archived contract; the archived Python files are not a fallback
execution path.
