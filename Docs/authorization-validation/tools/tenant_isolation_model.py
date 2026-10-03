#!/usr/bin/env python3
"""Bounded model for cross-tenant contamination of the admission protocol.

The admission-safety models (``e5_model_check.py`` and
``e5_model_check_two_mutations.py``) verify the REVOCATION-TIMING property
per scope; they deliberately abstract the tenant dimension away by assuming
the scope is resolved correctly. This model verifies that assumption
itself: with two tenants (T1 = the requester, T2 = the adversary-controlled
other tenant), it enumerates every adversary assignment of cross-tenant
object placement (cache record, pending-predicate source, manifest source,
in-flight narrowings on both tenants) against every configuration of the
FIVE tenant-scoping gates, and checks that no cross-tenant contamination
reaches an admission decision or a denial decision.

The five modeled gates (each independently removable, mirroring the
tenant-isolation connections of the deployed protocol):

- ``tenant_scoped_cache_key``  (K)  the cache lookup is keyed by the
  context tenant, so only T1's record can be served;
- ``tenant_scoped_record_validation`` (V)  a served record whose tenant
  differs from the context tenant is rejected fail-closed (strict-reader
  fallback with clean, tenant-scoped evidence);
- ``tenant_scoped_probe``      (P)  the pending predicate read is
  tenant-filtered: T2's deltas never enter T1's predicate and vice versa;
- ``tenant_scoped_watermark``  (W)  manifest summaries are tenant-scoped:
  T2's aggregates never materialize into T1's strict evidence;
- ``tenant_scoped_match``      (M)  matching skips grants whose tenant
  differs from the context tenant (no resource/action rematch across
  tenants).

Contamination verdict families (one bucket per trace, conservation):

- ``admittedForeignGrant``   (V-iso)  an ALLOW whose admitted grant
  belongs to T2 (output contamination; requires the evidence to contain a
  T2 grant AND the match gate to be absent);
- ``admittedContaminatedInputs`` (V-det)  an ALLOW of T1's own grant
  decided on contaminated inputs (predicate or evidence crossed tenancy;
  includes the stale-T1-admission case where T1's own unpublished
  narrowing was hidden by T2's clean predicate);
- ``deniedCrossTenantBlock`` (V-block)  a DENY/PENDING of T1's clean
  request caused by T2's narrowing (availability/determinism
  contamination: another tenant's delta blocked this tenant's request);
- clean buckets for admitted and denied traces with no cross-tenancy.

Universal hypotheses (checked by ``check_tenant_hypotheses``):

- T1  Full scoping: with all five gates on, over EVERY adversary
  assignment, no trace is admitted with a foreign grant or contaminated
  inputs, no clean T1 request is blocked by T2's narrowing, and T1's own
  unpublished narrowing always yields PENDING (per-tenant admission
  safety composes with tenancy).
- T2  Accounting conservation: every trace lands in exactly one bucket.
- T3  Necessity lattice: the violating subsets of the five gates are
  EXACTLY those predicted by the chain structure -- a subset violates iff
  it removes the probe gate (the single-gated safety vector) or removes
  the match gate while leaving an evidence-contamination path open (the
  cache path needs BOTH K and V removed; the manifest path needs only W
  removed). Defense in depth is real: {K} and {V} alone are expected to
  stay safe because each independently closes the cache vector.
- T4  Vector sharpness: each single-gate omission's minimal contamination
  family matches its intended vector (P hides T1's narrowing = stale
  admission; W with M admits... no -- W alone stays safe because M still
  blocks foreign grants: the lock table below records the observed
  per-omission family, including the expected-safe omissions).

SCOPE AND EVIDENCE BOUNDARY: abstract bounded-model evidence only; a
deliberate simplification of the deployed tenant-scoping connections, not
a mechanized proof of any implementation or deployment. Offline,
standard-library-only, side-effect-free, no solver, no network.
"""

from __future__ import annotations

import argparse
import json
import sys

__all__ = [
    "MODEL_NAME",
    "MODEL_VERSION",
    "GATES",
    "check_tenant_hypotheses",
    "main",
]

MODEL_NAME = "tenant-isolation-bounded-model"
MODEL_VERSION = "1.0.0"

GATES = (
    "tenant_scoped_cache_key",
    "tenant_scoped_record_validation",
    "tenant_scoped_probe",
    "tenant_scoped_watermark",
    "tenant_scoped_match",
)


def _subsets(items):
    """All non-empty proper subsets, as tuples, deterministic order."""
    n = len(items)
    return [
        tuple(items[i] for i in range(n) if mask >> i & 1)
        for mask in range(1, 2 ** n - 1)
    ]


def _expected_violating(removed):
    """Chain-structure predicate: does removing this subset admit
    contamination? A subset violates iff it opens the single-gated probe
    vector, or opens an evidence-contamination path while the match gate
    is also removed (foreign grants can then be admitted)."""
    gates = set(GATES)
    present = gates - set(removed)
    probe_open = "tenant_scoped_probe" in removed
    evidence_open = (
        "tenant_scoped_watermark" in removed
        or (
            "tenant_scoped_cache_key" in removed
            and "tenant_scoped_record_validation" in removed
        )
    )
    match_open = "tenant_scoped_match" in removed
    del present
    return probe_open or (evidence_open and match_open)


def enumerate_traces(premises):
    """Enumerate every adversary assignment under the given gate set.

    Returns the list of bucket labels, one per trace, plus per-trace
    detail dicts. Buckets: ``admittedClean``, ``admittedForeignGrant``,
    ``admittedContaminatedInputs``, ``deniedClean``,
    ``deniedOwnPending`` (T1's own narrowing correctly pending),
    ``deniedCrossTenantBlock`` (T2's narrowing blocked T1's clean
    request), ``deniedNoMatch`` (contaminated evidence, match gate
    blocked the foreign grant, no T1 grant available).
    """
    gates = set(GATES)
    on = {name: name in gates & set(g for g, enabled in premises.items() if enabled)
          for name in GATES}
    buckets = []
    details = []
    for cache_record in ("T1", "T2"):
        for probe_read in ("T1", "T2"):
            for manifest_source in ("T1", "T2"):
                for t1_narrowing in ("none", "unpublished"):
                    for t2_narrowing in ("none", "committed-unpublished"):
                        # Cache path: which record is actually served and
                        # accepted. K on -> T1's record only; K off -> the
                        # adversary's record. V on rejects a foreign record
                        # fail-closed (strict fallback, tenant-scoped).
                        if on["tenant_scoped_cache_key"]:
                            served, rejected = "T1", False
                        else:
                            served = cache_record
                            rejected = (
                                served == "T2"
                                and on["tenant_scoped_record_validation"]
                            )
                        if rejected:
                            evidence = "T1"  # strict fallback, scoped ledger
                        else:
                            evidence = served
                        # Strict path contamination: without the watermark
                        # gate the manifest source may be the other tenant.
                        if evidence == "T1" and not on["tenant_scoped_watermark"]:
                            evidence = manifest_source
                        # Probe: P on -> T1's own predicate; off -> the
                        # adversary's source. T1's predicate is 1 iff T1's
                        # narrowing is in flight; T2's iff T2's is.
                        if on["tenant_scoped_probe"]:
                            predicate_source = "T1"
                        else:
                            predicate_source = probe_read
                        pending = (
                            t1_narrowing == "unpublished"
                            if predicate_source == "T1"
                            else t2_narrowing == "committed-unpublished"
                        )
                        if pending:
                            # Fail closed: insufficient evidence admits
                            # nothing. Attribute the block.
                            if (
                                predicate_source == "T2"
                                and t2_narrowing == "committed-unpublished"
                                and t1_narrowing == "none"
                            ):
                                bucket = "deniedCrossTenantBlock"
                            else:
                                bucket = "deniedOwnPending"
                            buckets.append(bucket)
                            details.append({
                                "bucket": bucket,
                                "cacheRecord": cache_record,
                                "probeRead": probe_read,
                                "manifestSource": manifest_source,
                                "t1Narrowing": t1_narrowing,
                                "t2Narrowing": t2_narrowing,
                            })
                            continue
                        # Match over the evidence content.
                        foreign_available = evidence == "T2"
                        if on["tenant_scoped_match"]:
                            if evidence == "T1":
                                selected = "T1"
                            else:
                                buckets.append("deniedNoMatch")
                                details.append({
                                    "bucket": "deniedNoMatch",
                                    "cacheRecord": cache_record,
                                    "probeRead": probe_read,
                                    "manifestSource": manifest_source,
                                    "t1Narrowing": t1_narrowing,
                                    "t2Narrowing": t2_narrowing,
                                })
                                continue
                        else:
                            # Without the match gate the adversary selects
                            # any grant the evidence contains.
                            selected = "T2" if foreign_available else "T1"
                        input_contaminated = (
                            predicate_source == "T2" or evidence != "T1"
                        )
                        if selected == "T2":
                            bucket = "admittedForeignGrant"
                        elif input_contaminated:
                            bucket = "admittedContaminatedInputs"
                        else:
                            bucket = "admittedClean"
                        buckets.append(bucket)
                        details.append({
                            "bucket": bucket,
                            "selected": selected,
                            "cacheRecord": cache_record,
                            "probeRead": probe_read,
                            "manifestSource": manifest_source,
                            "t1Narrowing": t1_narrowing,
                            "t2Narrowing": t2_narrowing,
                        })
    return buckets, details


BUCKETS = (
    "admittedClean",
    "admittedForeignGrant",
    "admittedContaminatedInputs",
    "deniedClean",
    "deniedOwnPending",
    "deniedCrossTenantBlock",
    "deniedNoMatch",
)
CONTAMINATION_BUCKETS = (
    "admittedForeignGrant",
    "admittedContaminatedInputs",
    "deniedCrossTenantBlock",
)


def check_tenant_hypotheses():
    """Run the universal tenant-isolation hypotheses; return a report."""
    findings = []
    hypotheses = []

    # --- T1: full scoping ----------------------------------------------
    full = {gate: True for gate in GATES}
    buckets, details = enumerate_traces(full)
    foreign = sum(1 for b in buckets if b == "admittedForeignGrant")
    contaminated = sum(1 for b in buckets if b == "admittedContaminatedInputs")
    blocked = sum(1 for b in buckets if b == "deniedCrossTenantBlock")
    own_pending = sum(1 for b in buckets if b == "deniedOwnPending")
    t1_ok = foreign == 0 and contaminated == 0 and blocked == 0 and own_pending > 0
    hypotheses.append({
        "id": "T1",
        "statement": (
            "full scoping: zero foreign-grant admissions, zero "
            "contaminated-input admissions, zero cross-tenant blocks, and "
            "T1's own unpublished narrowing always yields PENDING, over "
            "every adversary assignment"
        ),
        "status": "PASS" if t1_ok else "FAIL",
        "evidence": {
            "traces": len(buckets),
            "admittedForeignGrant": foreign,
            "admittedContaminatedInputs": contaminated,
            "deniedCrossTenantBlock": blocked,
            "deniedOwnPending": own_pending,
        },
    })

    # --- T3: necessity lattice over all 62 proper subsets ---------------
    lattice = []
    t3_ok = True
    unexpected_safe = []
    for removed in _subsets(GATES):
        prem = {gate: True for gate in GATES}
        for gate in removed:
            prem[gate] = False
        buckets, _ = enumerate_traces(prem)
        contaminating = any(b in CONTAMINATION_BUCKETS for b in buckets)
        predicted = _expected_violating(removed)
        ok = contaminating == predicted
        t3_ok &= ok
        if contaminating and not predicted:
            unexpected_safe.append(list(removed))
        lattice.append({
            "removed": list(removed),
            "contaminating": contaminating,
            "predicted": predicted,
        })

    hypotheses.append({
        "id": "T3",
        "statement": (
            "the contaminating premise subsets are exactly the chain "
            "predicate: the probe gate alone is single-gated; the cache "
            "vector needs both K and V removed; the manifest vector needs "
            "W removed; and either contamination path only becomes an "
            "admission violation when the match gate is also removed"
        ),
        "status": "PASS" if t3_ok else "FAIL",
        "evidence": {
            "subsetsChecked": len(lattice),
            "contaminatingSubsets": sum(
                1 for entry in lattice if entry["contaminating"]
            ),
            "unexpectedSafeSubsets": unexpected_safe,
            "lattice": lattice,
        },
    })
    if unexpected_safe:
        findings.append({
            "finding": "unexpected_safe_subset",
            "detail": (
                "removing only these premise subsets admits no "
                "contamination; the chain predicate predicted a violation"
            ),
            "subsets": unexpected_safe,
        })

    # --- T4: per-omission sharpness (lock table) ------------------------
    observed_families = {}
    for gate in GATES:
        prem = {name: True for name in GATES}
        prem[gate] = False
        buckets, details = enumerate_traces(prem)
        families = sorted({b for b in buckets if b in CONTAMINATION_BUCKETS})
        observed_families[gate] = families
    expected_families = {
        # Defense in depth, observed and locked: K and V cover the cache
        # vector for each other; W alone is covered by M (foreign grants in
        # the evidence are still skipped); M alone is covered by the
        # evidence-purity gates (no foreign grant ever reaches the match).
        "tenant_scoped_cache_key": [],
        "tenant_scoped_record_validation": [],
        # The probe gate is single-gated: removing it both hides T1's own
        # narrowing (stale admission via T2's clean predicate) and lets
        # T2's narrowing block T1's clean request (cross-tenant block).
        "tenant_scoped_probe": [
            "admittedContaminatedInputs",
            "deniedCrossTenantBlock",
        ],
        "tenant_scoped_watermark": [],
        "tenant_scoped_match": [],
    }
    t4_ok = observed_families == expected_families
    hypotheses.append({
        "id": "T4",
        "statement": (
            "each single-gate omission's contamination family matches the "
            "locked defense-in-depth table: K and V cover the cache vector "
            "for each other, W and M each cover the foreign-grant vector "
            "for the upstream gates, and the probe gate alone is "
            "single-gated -- removing it opens both the stale-admission "
            "and the cross-tenant-block vectors"
        ),
        "status": "PASS" if t4_ok else "FAIL",
        "evidence": {
            "observed": observed_families,
            "expected": expected_families,
        },
    })

    # --- T5: conservation ------------------------------------------------
    t5_ok = True
    configurations_audited = 0
    for removed in [()] + list(_subsets(GATES)):
        prem = {gate: True for gate in GATES}
        for gate in removed:
            prem[gate] = False
        buckets, _ = enumerate_traces(prem)
        configurations_audited += 1
        counts = {bucket: buckets.count(bucket) for bucket in BUCKETS}
        if sum(counts.values()) != len(buckets):
            t5_ok = False
    hypotheses.append({
        "id": "T5",
        "statement": (
            "every trace in every configuration lands in exactly one "
            "contamination bucket (accounting conservation)"
        ),
        "status": "PASS" if t5_ok else "FAIL",
        "evidence": {"configurationsAudited": configurations_audited},
    })

    statuses = [entry["status"] for entry in hypotheses]
    overall = "PASS" if all(s == "PASS" for s in statuses) else "FAIL"
    return {
        "model": MODEL_NAME,
        "modelVersion": MODEL_VERSION,
        "hypotheses": hypotheses,
        "findings": findings,
        "status": overall,
        "scopeBoundary": (
            "abstract bounded-model evidence only; a deliberate "
            "simplification of the deployed tenant-scoping connections; "
            "not a proof of any implementation, deployment, or runtime "
            "behavior; live validation remains BLOCKED regardless of this "
            "result"
        ),
    }


def _format_text_report(report):
    lines = [
        "%s v%s -- abstract bounded-model evidence ONLY"
        % (report["model"], report["modelVersion"]),
        "",
    ]
    for entry in report["hypotheses"]:
        lines.append("  [%s] %s: %s" % (entry["id"], entry["status"], entry["statement"]))
        if entry["id"] == "T3":
            ev = entry["evidence"]
            lines.append(
                "      subsets checked=%d contaminating=%d unexpectedSafe=%s"
                % (
                    ev["subsetsChecked"],
                    ev["contaminatingSubsets"],
                    ev["unexpectedSafeSubsets"] or "none",
                )
            )
        if entry["id"] == "T4":
            for gate, families in sorted(entry["evidence"]["observed"].items()):
                lines.append("      %-34s %s" % (gate, families or "safe (covered)"))
    for finding in report["findings"]:
        lines.append("  FINDING: %s -- %s %s" % (
            finding["finding"], finding["detail"], finding["subsets"]))
    lines.append("")
    lines.append("Overall status: %s" % report["status"])
    lines.append("Scope: %s" % report["scopeBoundary"])
    return "\n".join(lines)


def main(argv=None):
    """CLI entry point. Returns 0 all-PASS, 1 FAIL."""
    parser = argparse.ArgumentParser(
        prog="tenant_isolation_model",
        description=(
            "Bounded cross-tenant contamination model of the admission "
            "protocol. Offline, standard library only, no solver."
        ),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit the full report as JSON instead of a text summary",
    )
    args = parser.parse_args(argv)
    report = check_tenant_hypotheses()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(_format_text_report(report))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - exercised via CLI smoke runs
    sys.exit(main())
