# Authorization Validation and Reproduction

This directory contains executable Rust authorization validation tools and test inputs. It does not contain generated results or deployment archives.

## Scope

The directory contains:

- E1-E5 validation tools and their offline unit tests;
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
- [`tools/`](tools/): standard-library Python runners, read-only probes, classifiers,
  lifecycle reducers, and offline tests.
- [`IMPLEMENTATION_MAP.md`](IMPLEMENTATION_MAP.md): M1-M5 authorization assumptions
  mapped to Rust implementation and test surfaces.

Generated `evidence/`, `artifact/`, result, log, credential, and private deployment
folders are intentionally excluded. A live run requires an isolated environment,
preflight, the execution gates in [`AGENTS.md`](../../AGENTS.md), and durable
postcondition reconciliation.

## Offline checks

From the repository root:

```bash
python -m unittest discover -s Docs/authorization-validation/tools \
  -t Docs/authorization-validation/tools -p 'test_*.py' -v
python Docs/authorization-validation/tools/e5_model_check.py --self-test
```

The runners default to local planning and validation. Remote reads, migrations,
service startup, fault injection, and durable source mutations require their own
explicit safety gates and are not performed by the default offline tests.
