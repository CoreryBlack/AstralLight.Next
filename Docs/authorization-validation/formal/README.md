# Authorization Evidence-Admission TLA+ Model

**Status: `BLOCKED` — draft specifications only. No verified TLC run exists.**

`AdmissionSafety.tla` is an independent, minimal safety model of the
evidence-admission protocol: two readers, revoke plus successor re-grant, independent
manifest/body publication, torn cache, rollback, read-time pending latch, generation
fence, exact candidate identity, and mediated host admission.

Because this checkout has no verifiable pinned `tla2tools.jar`, these files are not
execution evidence:

- the specifications are unverified drafts and may contain syntax or model errors;
- until a TLC run is archived with command, digest, output, exit status, and checksums,
  the model remains `BLOCKED` and does not change the status of live E1/E3/E4 checks.

## Configurations and expected checks

| Configuration | Premise flipped off | Expected model check |
|---|---|---|
| `AdmissionSafetyFull.cfg` | none (full contract) | all declared invariants hold |
| `AdmissionSafetyNoPendingProbe.cfg` | `PENDING_PROBE` | stale admission counterexample |
| `AdmissionSafetyNoGenerationFence.cfg` | `GEN_FENCE` | torn/stale cache counterexample |
| `AdmissionSafetyNoExactIdentity.cfg` | `EXACT_IDENTITY` | successor substitution counterexample |
| `AdmissionSafetyNoHostMediation.cfg` | `HOST_MEDIATION` | mediation bypass counterexample |

The expected outcome is a check target, not a pre-recorded result. A full-contract
failure or missing counterexample means the specification or configuration needs repair.
`host_mediation` is model-only and has no runtime omission switch.

## How to run

Use an immutable, digest-pinned TLC image or jar in a fresh result directory. Record
the exact command, tool digest, source revision, unedited stdout/stderr, exit status,
and SHA-256 checksums. A nonzero TLC exit keeps the output for diagnosis and fails the
run.

```bash
java -XX:+UseParallelGC -cp <pinned tla2tools.jar> tlc2.TLC \
  -config AdmissionSafetyFull.cfg AdmissionSafety.tla
```

This is a safety model only. Liveness or fairness requires a separate configuration
with explicit fairness assumptions; eventual publication is never unconditional.
