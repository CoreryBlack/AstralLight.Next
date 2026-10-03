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
python Docs/authorization-validation/tools/e5_model_check.py --json
python Docs/authorization-validation/tools/e5_model_check_two_mutations.py
python Docs/authorization-validation/tools/universal_hypotheses_check.py --model both
python Docs/authorization-validation/tools/tenant_isolation_model.py
python Docs/authorization-validation/tools/unbounded_confirmation.py
```

`e5_model_check.py` enumerates the bounded observation-protocol model (one
candidate grant, one revocation-class mutation) and checks the full contract
plus the six single-premise omissions. `e5_model_check_two_mutations.py`
tightens the model's main structural abstraction to TWO concurrent
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

The runners default to local planning and validation. Remote reads, migrations,
service startup, fault injection, and durable source mutations require their own
explicit safety gates and are not performed by the default offline tests.
