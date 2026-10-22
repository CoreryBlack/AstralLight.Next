# Archived authorization Python tests

These 19 Python test modules were moved from `../../tools/` on 2026-10-22. Their
contents are retained as migration history and review references; they are not a
current test gate and must not be counted as Rust parity or a current `PASS`.
The archive directory is outside the Python tools discovery root, and no current
runner discovers or dispatches these modules.

The Rust targets below are the current executable replacements only for the
specified subcontracts. Any named `BLOCKED` suite remains migration-pending even
though its Python source is archived. The archived test files themselves are
immutable migration references: several docstrings, imports, and old readiness
assertions refer to the former `tools/` layout and are intentionally not executable.

For every archived `test_*.py`, a Rust campaign suite must list that archive path
in `sources`; `campaign::tests::manifest_entries_are_scoped_and_blocked_entries_are_not_dispatched`
checks the complete 19-file inventory and mapping table so additions cannot silently
escape either record.

| Archived source | Current Rust target / suite | Coverage status and boundary |
|---|---|---|
| `test_bounded_model_execution.py` | `bounded-worker-shard-contracts` | `BLOCKED`: Rust two-mutation worker/shard partition and reducer are not implemented. |
| `test_classify_e1_properties.py` | `e1-event-classifier`; `e1-log-parser-contracts`; `e1-live-log-parser-parity` | Partial: Rust covers typed interval classification and E1 JSONL filtering/identity/sequence parsing; E1 runner orchestration, production preflight and full live-run parity remain `BLOCKED`. |
| `test_dependency_profiles.py` | `dependency-profile-fault-matrix-contracts` | Migrated as an offline declaration contract: Rust pins the eight profile IDs, services, dependency/fault membership, all fault-to-dependency metadata, profile-filtered expansion, compatibility-only legacy faults and complete dependency-by-timing rows with profile/dependency/timing/fail-closed fields. This is not a live fault campaign. |
| `test_e1_runner.py` | `e1-log-parser-contracts`; `e1-live-log-parser-parity` | Partial: the Rust E1 JSONL parser preserves malformed matching-record errors, filtering, epoch-scoped sequence uniqueness and ordering; the broader E1 runner's plan/live/preflight/controller orchestration remains `BLOCKED`. |
| `test_e3_e4.py` | `e3-e4-read-only-probe-parity`; `e3-attempt-reconciliation-contract`; `e4-protocol-contract` | Partial: selected typed Rust E3/E4 checks run; SQL/Redis/HTTP probes, precondition capture, sampling, and the full probe suite remain `BLOCKED`. |
| `test_e3_runner.py` | `e3-runner-report-parity`; `e3-attempt-reconciliation-contract` | Partial: Rust covers typed post-parse reconciliation only; runner phases, sampling, aggregation, and full report parity remain `BLOCKED`. |
| `test_e4_fault_driver.py` | `e4-fake-controller-lifecycle-parity`; `e4-protocol-contract` | Partial: selected typed protocol rules run in Rust; fake-controller lifecycle and profile fault matrix remain `BLOCKED`. |
| `test_e5_model_check.py` | `e5-bounded-single` | Migrated: the Rust single-mutation bounded model and full bound-28 report are checked against a retained reference fixture. This is abstract model evidence, not runtime/deployment proof. |
| `test_e5_model_check_two_mutations.py` | `e5-bounded-two-mutations`; `bounded-worker-shard-contracts` | `BLOCKED`: equivalent Rust two-mutation state-space and deterministic shard/reducer contracts are absent. |
| `test_experiment_common.py` | `e1-event-classifier`; `e1-log-parser-contracts`; `e3-attempt-reconciliation-contract`; `e4-protocol-contract`; `authorization-lifecycle-reducer-contracts` | Partial: typed E1/E3/E4 rules, the E1 JSONL parser and E1/E3 lifecycle reductions are covered; E3/E4 event parsers, complete E3/E4 shared helpers, E4 precondition capture and report parity remain `BLOCKED`. |
| `test_experiment_register.py` | `experiment-register-contracts` | Migrated as a declaration contract: Rust pins stimulus source forms/revocation metadata/notes, E2 runtime and model-only premise links, canary injection/expected rates, all profile service/dependency/fault tables and cross-links, full profile-filtered dependency-by-timing row fields, capture requirements and acceptance tables. It records design intent only, not run results. |
| `test_lifecycle_reducer.py` | `authorization-lifecycle-reducer-contracts` | Migrated: Rust reduces same-epoch E1 ALLOW timing and durable E3 claim-to-terminal intervals, excludes unknown samples, requires clock-offset evidence across nodes and uses nearest-rank p50/p95/p99. |
| `test_model_acceptance.py` | `e5-bounded-single`; `e5-universal-bounded`; `legacy-campaign-report-acceptance-parity` | Partial: the Rust single-model and selected tenant acceptance contracts run; universal report and legacy campaign schema parity remain `BLOCKED`. |
| `test_node_adapter.py` | `node-adapter-probe-contracts` | `BLOCKED`: no Rust node adapter, signed-request, transport, or log-slicing contract exists. |
| `test_projection_owner_model.py` | `projection-owner-model-contracts` | `BLOCKED`: equivalent Rust reachable-state BFS and omission controls are absent. |
| `test_run_single_node_campaign.py` | `legacy-campaign-report-acceptance-parity`; `campaign-contracts`; `shell-runner-contracts` | Partial: Rust campaign manifest/dispatch, fake-Cargo behavior, and the readiness E2 command-source links are covered; legacy readiness report/status/artifact schema parity remains `BLOCKED`. `campaign-contracts` and `shell-runner-contracts` are dispatchable `[[suite]]` IDs; `harness/runner-contracts` is catalog-only. |
| `test_tenant_isolation_model.py` | `offline-tenant-model` | Migrated within the registered boundary: Rust checks T1/T3/T4/T5 across the bounded assignment space; it does not prove SQL or runtime isolation. |
| `test_unbounded_confirmation.py` | `unbounded-confirmation-single-partial`; `unbounded-confirmation-two-model-parity` | Partial: Rust checks single-model event-chain closure and bound invariance; the two-model aggregate remains `BLOCKED`. |
| `test_universal_hypotheses_check.py` | `e5-universal-bounded` | `BLOCKED`: complete U1–U10 evaluation over both Rust models is not implemented. |

Use the registered Rust suites in `tests-suite/MANIFEST.toml` for current
validation. A blocked suite remains blocked until its Rust replacement preserves
and validates the archived contract; the archived Python files are not a fallback
execution path.
