#!/usr/bin/env python3
"""Universal-hypothesis checker over the bounded admission-safety model.

Where ``e5_model_check.py`` answers the point question (does the full
contract admit a stale ``strictly_before`` trace?), this checker answers
STRONGER, UNIVERSAL questions about the same exhaustive enumeration. Every
hypothesis is quantified over ALL traces of the bounded model, over ALL
configurations of a family, or over BOTH observation modes -- never over a
sample. All checks are offline, standard-library-only, side-effect-free,
and reuse ``e5_model_check`` as a library without modifying it.

Hypotheses (all must hold for the checker to report PASS):

- U1  Theorem-domain safety, both modes. On the full contract the
      exhaustive exploration is complete and admits ZERO traces whose
      mutation committed strictly before the final observation (the
      theorem domain), in bracket AND strict mode.
- U2  Domain accounting conservation. In EVERY run performed by this
      checker (full contract, omissions, subsets), every admitted trace
      is classified into exactly one theorem domain:
      ``sum(admittedDomainCounts) == admittedTraces``.
- U3  Latch universality and window non-vacuity. On the full contract
      the free decision tail is genuinely enumerated (the family
      ``staleCommitPublishAfterLastReadTraces`` is non-empty: a stale
      commit whose publication completes after the last read and before
      admission) and EVERY trace of that family is denied
      (``admittedStaleCommitPublishAfterLastRead == 0``); the denial
      reasons include the pending-probe latch itself, not merely some
      gate. Verified in both modes.
- U4  Evidence-integrity universality. Torn (mixed manifest/body) cache
      states are genuinely reachable (``tornReadTraces > 0``) and NO
      admitted trace under the full contract carries torn evidence
      (``admittedTornReadTraces == 0`` with an empty by-domain map).
- U5  Post-t_f publication accounting. Traces whose publication fires
      after t_f and before admission are enumerated (non-empty family)
      and every admitted member lies OUTSIDE the theorem domain; the
      checker asserts the accounting inequality
      ``admittedPublishAfterFinalObservation <= admittedTraces -
      admittedStrictlyBefore`` and relies on U1 for the zero
      ``strictly_before`` residue. These admissions are the irreducible
      post-t_f TOCTOU domain, not safety margin.
- U6  Premise-necessity lattice. For EVERY non-empty proper subset of
      the six modeled premises (62 subsets), removing exactly that
      subset admits at least one in-domain violating trace: the full
      contract's safety is carried by the JOINT action of all six
      premises, and no proper subset of premises suffices within the
      model. A subset that comes back safe is reported as a finding
      (candidate sufficient subset), never silently dropped.
- U7  Omission sharpness. Each single-premise omission's MINIMAL
      counterexample belongs to its intended hazard family (the
      schedule class), not to an incidental one; the mapping is locked
      here and must be updated together with the model.
- U8  Bound discipline. At each configuration's required bound the
      exploration is complete; one step below the required bound the
      status is never PASS (an insufficient bound can mint UNKNOWN or a
      decisive FAIL, but never a PASS). PASS is therefore never an
      artifact of a too-small bound.
- U9  Mode independence. The full-contract verdict is identical in the
      bracket and strict observation modes (same status, zero
      violations, complete exploration in both).
- U10 Report conservation. The aggregate report's explored-state and
      explored-trace totals equal the sum over its member runs, and the
      top-level status equals the full-contract status only (omission
      results never leak into it).

SCOPE AND EVIDENCE BOUNDARY (read this first):

- This tool produces ABSTRACT BOUNDED-MODEL EVIDENCE ONLY, conditional
  on every structural assumption of ``e5_model_check.py`` (one candidate
  grant, one revocation-class mutation, one successor revision, one
  rollback, dense steps, latched read-time gates, no admission-time
  re-derivation). It is NOT a mechanized proof of the Rust/Java
  implementations, of any deployment, or of any runtime behavior, and
  it does not upgrade any live E1/E3/E4 status.
- The TLA+ input under ``formal/`` remains a draft: no pinned,
  checksum-verified TLC exists in this checkout. Optional bounded worker
  processes evaluate independent configurations only; no solver or network
  is invoked, and import has no process side effects.
- Status vocabulary is shared with the validation protocol: PASS
  requires the property to hold over the complete exploration; FAIL is
  decisive; UNKNOWN marks incomplete or undecidable domains. Live
  database/cache/broker/multi-node validation stays BLOCKED regardless
  of any PASS here.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import platform
import sys
from pathlib import Path

import e5_model_check as model  # noqa: E402
import e5_model_check_two_mutations as model_two  # noqa: E402

__all__ = [
    "CHECKER_NAME",
    "CHECKER_VERSION",
    "OMISSION_SCHEDULE_CLASS",
    "OMISSION_SCHEDULE_CLASS_TWO_MUTATIONS",
    "MODEL_REGISTRY",
    "check_universal_hypotheses",
    "write_manifest",
    "main",
]

CHECKER_NAME = "universal-hypotheses-check"
CHECKER_VERSION = "1.1.0"

# U7: minimal counterexample schedule class per single-premise omission,
# observed against each model and locked here; the class names come from
# run_model's schedule_class labeling.
OMISSION_SCHEDULE_CLASS = {
    "pending_probe": "source_pending_commit_without_publication",
    "post_recheck": "mutation_published_between_evidence_read_and_last_read",
    "final_reload": "source_pending_commit_without_publication",
    "exact_identity": "successor_revision_identity_confusion",
    "generation_revoke_fence": "stale_generation_pointer_rollback",
    "host_mediation": "bypass_unmediated_admission",
}

# The two-mutation model labels the identity hole with its own class: the
# admitted evidence no longer carries the candidate at all (mutation A's
# body advance removed it), not merely a successor revision. Its
# generation_revoke_fence omission is NOT independently falsifiable (the
# rollback adversary is restricted to the decision tail; pre-read rollback
# hazards live in the single-mutation model), so its expected class is
# None and U7 asserts a complete, counterexample-free exploration.
OMISSION_SCHEDULE_CLASS_TWO_MUTATIONS = dict(OMISSION_SCHEDULE_CLASS)
OMISSION_SCHEDULE_CLASS_TWO_MUTATIONS["exact_identity"] = (
    "candidate_removal_identity_confusion"
)
OMISSION_SCHEDULE_CLASS_TWO_MUTATIONS["generation_revoke_fence"] = None

MODEL_REGISTRY = {"single": model, "two": model_two}

# Premise subsets whose removal is EXPECTED to stay safe within a model,
# with the necessity evidence carried by the other model instead. For the
# two-mutation model the rollback adversary is restricted to the decision
# tail, so removing the generation/revoke fence alone leaves every
# in-flight read latched by the probes; the fence's necessity is
# established by the single-mutation model's pointer-rollback schedule.
EXPECTED_SAFE_SUBSETS = {
    "single": frozenset(),
    "two": frozenset({("generation_revoke_fence",)}),
}


def _audit_conservation(run, ledger):
    """U2: every admitted trace is classified into exactly one domain."""
    total = sum(run["admittedDomainCounts"].values())
    ok = total == run["admittedTraces"]
    ledger.append(
        {
            "premises": [p for p, on in run["premises"].items() if on],
            "mode": run["mode"],
            "bound": run["bound"],
            "admittedTraces": run["admittedTraces"],
            "classifiedSum": total,
        }
    )
    return ok


def _proper_subsets(items):
    """All non-empty proper subsets, as tuples, deterministic order."""
    n = len(items)
    masks = [m for m in range(1, 2 ** n - 1)]
    out = []
    for mask in masks:
        out.append(tuple(items[i] for i in range(n) if mask >> i & 1))
    return out


def check_universal_hypotheses(bound=None, model_name="single", lattice="full", workers=1):
    """Run every universal hypothesis; return a report dict.

    ``model_name`` selects the registered model (``single``: one candidate
    grant + one mutation; ``two``: two concurrent mutations). ``bound`` is
    the exploration bound for the main runs (default: the model's own
    default); U8 derives its own bounds from each configuration's required
    bound. ``lattice`` selects the U6 coverage: ``full`` enumerates all 62
    non-empty proper premise subsets, ``singles`` only the six
    single-premise omissions (for the heavier two-mutation model). The
    overall status is PASS only when every hypothesis PASSes.
    """
    mod = MODEL_REGISTRY[model_name]
    from bounded_model_execution import run_configurations, validate_workers

    validate_workers(workers)
    mapping = (
        OMISSION_SCHEDULE_CLASS if model_name == "single"
        else OMISSION_SCHEDULE_CLASS_TWO_MUTATIONS
    )
    if bound is None:
        bound = mod.DEFAULT_BOUND
    bound = mod.validate_bound(bound)
    full = mod.normalize_premises()

    # Every complete exploration (bound >= requiredBound) of a
    # (premises, mode) configuration yields identical results, so the
    # cache key normalizes the bound for complete runs; under-bound runs
    # (U8) keep their exact bound in the key. U6/U7/U8/U10 would otherwise
    # re-enumerate the same bracket omissions four times.
    run_cache = {}
    if workers > 1:
        configurations = [(full, mode, bound) for mode in ("bracket", "strict")]
        subsets = _proper_subsets(mod.PREMISES) if lattice == "full" else [(p,) for p in mod.PREMISES]
        for removed in subsets:
            configurations.append(({p: p not in removed for p in mod.PREMISES}, "bracket", bound))
        for premise in mod.PREMISES:
            configurations.append((mod.without_premise(premise), "bracket", bound))
        bound_configs = [("full-bracket", full, "bracket"), ("full-strict", full, "strict")]
        bound_configs.extend(("without-" + p, mod.without_premise(p), "bracket") for p in mod.PREMISES)
        for name, premises, mode in bound_configs:
            required = mod.required_bound(premises, mode)
            configurations.append((premises, mode, required))
            if (model_name == "single" or name in {"full-bracket", "full-strict"}) and required - 1 >= mod.MIN_BOUND:
                configurations.append((premises, mode, required - 1))
        run_cache = run_configurations(mod.__name__, configurations, workers)

    def cached_run(prem, mode, run_bound):
        required = mod.required_bound(prem, mode)
        if run_bound >= required:
            key = (tuple(sorted(prem.items())), mode, "complete")
        else:
            key = (tuple(sorted(prem.items())), mode, run_bound)
        if key not in run_cache:
            run_cache[key] = mod.run_model(dict(prem), mode, run_bound)
        return run_cache[key]
    findings = []

    # --- U1 / U3 / U4 / U5 / U9: full contract in both modes -----------
    mode_runs = {
        mode: cached_run(full, mode, bound)
        for mode in ("bracket", "strict")
    }
    u1_evidence = {}
    u1_ok = True
    u3_ok = True
    u4_ok = True
    u5_ok = True
    for mode, run in sorted(mode_runs.items()):
        window = run["admissionWindow"]
        torn = run["mixedManifestBody"]
        mode_u1 = (
            run["status"] == "PASS"
            and run["explorationComplete"]
            and run["admittedDomainCounts"]["strictlyBefore"] == 0
        )
        u1_ok &= mode_u1
        u1_evidence[mode] = {
            "status": run["status"],
            "explorationComplete": run["explorationComplete"],
            "admittedStrictlyBefore": run["admittedDomainCounts"][
                "strictlyBefore"
            ],
            "admittedTraces": run["admittedTraces"],
            "deniedTraces": run["deniedTraces"],
        }
        latch_reasons = {
            key: value
            for key, value in run["denialReasons"].items()
            if key.startswith("pending_probe_latched_unsafe_delta")
        }
        mode_u3 = (
            window["staleCommitPublishAfterLastReadTraces"] > 0
            and window["admittedStaleCommitPublishAfterLastRead"] == 0
            and len(latch_reasons) > 0
            and sum(latch_reasons.values()) > 0
        )
        u3_ok &= mode_u3
        mode_u4 = (
            torn["tornReadTraces"] > 0
            and torn["admittedTornReadTraces"] == 0
            and not torn["admittedTornReadTracesByDomain"]
        )
        u4_ok &= mode_u4
        u3_evidence = {
            "staleCommitPublishAfterLastReadTraces": window[
                "staleCommitPublishAfterLastReadTraces"
            ],
            "admittedStaleCommitPublishAfterLastRead": window[
                "admittedStaleCommitPublishAfterLastRead"
            ],
            "pendingProbeLatchDenials": latch_reasons,
        }
        u4_evidence = {
            "tornReadTraces": torn["tornReadTraces"],
            "admittedTornReadTraces": torn["admittedTornReadTraces"],
            "tornReadTracesByKind": torn["tornReadTracesByKind"],
        }
        u5_evidence_mode = {
            "publishAfterFinalObservationBeforeAdmissionTraces": window[
                "publishAfterFinalObservationBeforeAdmissionTraces"
            ],
            "admittedPublishAfterFinalObservation": window[
                "admittedPublishAfterFinalObservation"
            ],
            "admittedOutsideTheoremDomain": run["admittedTraces"]
            - run["admittedDomainCounts"]["strictlyBefore"],
        }
        u5_ok &= (
            u5_evidence_mode[
                "publishAfterFinalObservationBeforeAdmissionTraces"
            ]
            > 0
            and window["admittedPublishAfterFinalObservation"]
            <= u5_evidence_mode["admittedOutsideTheoremDomain"]
        )

    conservation_ledger = []
    for run in mode_runs.values():
        _audit_conservation(run, conservation_ledger)

    u9_ok = (
        len({run["status"] for run in mode_runs.values()}) == 1
        and all(run["status"] == "PASS" for run in mode_runs.values())
        and all(run["explorationComplete"] for run in mode_runs.values())
    )

    # --- U6: premise-necessity lattice over all 62 proper subsets ------
    lattice_entries = []
    u6_ok = True
    sufficient_subsets = []
    subset_family = (
        _proper_subsets(mod.PREMISES)
        if lattice == "full"
        else [(p,) for p in mod.PREMISES]
    )
    expected_safe = EXPECTED_SAFE_SUBSETS[model_name]
    for removed in subset_family:
        prem = {p: True for p in mod.PREMISES}
        for p in removed:
            prem[p] = False
        run = cached_run(prem, "bracket", bound)
        _audit_conservation(run, conservation_ledger)
        violating = run["violations"] > 0
        if not violating and tuple(removed) not in expected_safe:
            u6_ok = False
            sufficient_subsets.append(list(removed))
        lattice_entries.append(
            {
                "removed": list(removed),
                "status": run["status"],
                "violations": run["violations"],
                "exploredTraces": run["exploredTraces"],
            }
        )

    # --- U7: single-premise omission sharpness -------------------------
    u7_ok = True
    u7_evidence = {}
    for premise in mod.PREMISES:
        run = cached_run(mod.without_premise(premise), "bracket", bound)
        _audit_conservation(run, conservation_ledger)
        cex = run["counterexample"]
        observed = cex["scheduleClass"] if cex else None
        expected = mapping[premise]
        if expected is None:
            # Locked to be not-independently-falsifiable within this model:
            # a complete exploration with no counterexample.
            sharp = (
                run["status"] == "PASS"
                and run["explorationComplete"]
                and run["violations"] == 0
            )
        else:
            sharp = run["status"] == "FAIL" and observed == expected
        u7_ok &= sharp
        u7_evidence[premise] = {
            "status": run["status"],
            "intendedScheduleClass": expected,
            "observedScheduleClass": observed,
            "counterexampleEvents": cex["eventCount"] if cex else None,
        }

    # --- U8: bound discipline ------------------------------------------
    u8_ok = True
    u8_evidence = {}
    configs = [("full-bracket", full, "bracket"), ("full-strict", full, "strict")]
    for premise in mod.PREMISES:
        configs.append(
            ("without-" + premise, mod.without_premise(premise), "bracket")
        )
    # The below-bound spot check enumerates a nearly-full tree, so for the
    # heavier two-mutation model it covers the two full-contract
    # configurations; the per-configuration below-bound discipline is
    # verified exhaustively on the single model (all 8 configs).
    below_names = (
        {"full-bracket", "full-strict"}
        if model_name == "two"
        else {name for name, _, _ in configs}
    )
    for name, prem, mode in configs:
        required = mod.required_bound(prem, mode)
        at_required = cached_run(prem, mode, required)
        _audit_conservation(at_required, conservation_ledger)
        entry = {
            "requiredBound": required,
            "completeAtRequired": at_required["explorationComplete"],
        }
        if name in below_names and required - 1 >= mod.MIN_BOUND:
            below = cached_run(prem, mode, required - 1)
            entry["statusOneStepBelow"] = below["status"]
            entry["neverPassBelowRequired"] = below["status"] != "PASS"
            u8_ok &= entry["neverPassBelowRequired"]
        u8_ok &= entry["completeAtRequired"]
        u8_evidence[name] = entry

    # --- U10: report conservation ---------------------------------------
    if getattr(mod, "SUPPORTS_RUN_CACHE", False):
        report = mod.build_report(bound, run_cache=run_cache)
    else:
        report = mod.build_report(bound)
    member_states = sum(
        run["exploredStates"] for run in report["fullContract"]["modes"].values()
    ) + sum(entry["run"]["exploredStates"] for entry in report["omissions"])
    member_traces = sum(
        run["exploredTraces"] for run in report["fullContract"]["modes"].values()
    ) + sum(entry["run"]["exploredTraces"] for entry in report["omissions"])
    mode_statuses = {
        run["status"] for run in report["fullContract"]["modes"].values()
    }
    expected_top = (
        "FAIL"
        if "FAIL" in mode_statuses
        else ("UNKNOWN" if "UNKNOWN" in mode_statuses else "PASS")
    )
    u10_ok = (
        report["exploredStates"] == member_states
        and report["exploredTraces"] == member_traces
        and report["status"] == expected_top
        and report["fullContract"]["status"] == expected_top
    )
    u10_evidence = {
        "exploredStates": report["exploredStates"],
        "memberStateSum": member_states,
        "exploredTraces": report["exploredTraces"],
        "memberTraceSum": member_traces,
        "topLevelStatus": report["status"],
        "fullContractStatus": report["fullContract"]["status"],
        "expectedTopLevelStatus": expected_top,
    }

    # --- U2 verdict over the ledger --------------------------------------
    u2_ok = all(
        entry["admittedTraces"] == entry["classifiedSum"]
        for entry in conservation_ledger
    )

    if sufficient_subsets:
        findings.append(
            {
                "finding": "candidate_sufficient_subset",
                "detail": (
                    "removing only these premise subsets still admits no "
                    "in-domain violation within the bound; the necessity "
                    "lattice U6 fails for them"
                ),
                "subsets": sufficient_subsets,
            }
        )

    hypotheses = [
        {
            "id": "U1",
            "statement": (
                "full contract: complete exploration, zero admitted traces "
                "in the theorem domain (strictly_before), in both modes"
            ),
            "status": "PASS" if u1_ok else "FAIL",
            "evidence": u1_evidence,
        },
        {
            "id": "U2",
            "statement": (
                "every admitted trace in every run is classified into "
                "exactly one theorem domain (accounting conservation)"
            ),
            "status": "PASS" if u2_ok else "FAIL",
            "evidence": {"runsAudited": len(conservation_ledger)},
        },
        {
            "id": "U3",
            "statement": (
                "the stale-commit publish-after-last-read window is "
                "enumerated and every trace in it is denied by the latched "
                "pending probes, in both modes"
            ),
            "status": "PASS" if u3_ok else "FAIL",
            "evidence": {
                mode: {
                    "staleCommitPublishAfterLastReadTraces": mode_runs[
                        mode
                    ]["admissionWindow"][
                        "staleCommitPublishAfterLastReadTraces"
                    ],
                    "admittedStaleCommitPublishAfterLastRead": mode_runs[
                        mode
                    ]["admissionWindow"][
                        "admittedStaleCommitPublishAfterLastRead"
                    ],
                    "pendingProbeLatchDenials": {
                        key: value
                        for key, value in mode_runs[mode][
                            "denialReasons"
                        ].items()
                        if key.startswith("pending_probe_latched_unsafe_delta")
                    },
                }
                for mode in sorted(mode_runs)
            },
        },
        {
            "id": "U4",
            "statement": (
                "torn manifest/body states are reachable and no admitted "
                "trace carries torn evidence"
            ),
            "status": "PASS" if u4_ok else "FAIL",
            "evidence": {
                mode: {
                    "tornReadTraces": mode_runs[mode]["mixedManifestBody"][
                        "tornReadTraces"
                    ],
                    "admittedTornReadTraces": mode_runs[mode][
                        "mixedManifestBody"
                    ]["admittedTornReadTraces"],
                }
                for mode in sorted(mode_runs)
            },
        },
        {
            "id": "U5",
            "statement": (
                "post-t_f publication traces are enumerated and every "
                "admitted member lies outside the theorem domain "
                "(accounting inequality against the strictly_before "
                "residue)"
            ),
            "status": "PASS" if u5_ok else "FAIL",
            "evidence": {
                mode: {
                    "publishAfterFinalObservationBeforeAdmissionTraces":
                    mode_runs[mode]["admissionWindow"][
                        "publishAfterFinalObservationBeforeAdmissionTraces"
                    ],
                    "admittedPublishAfterFinalObservation": mode_runs[mode][
                        "admissionWindow"
                    ]["admittedPublishAfterFinalObservation"],
                    "admittedOutsideTheoremDomain": mode_runs[mode][
                        "admittedTraces"
                    ]
                    - mode_runs[mode]["admittedDomainCounts"][
                        "strictlyBefore"
                    ],
                }
                for mode in sorted(mode_runs)
            },
        },
        {
            "id": "U6",
            "statement": (
                "every enumerated non-empty proper premise subset (%s) "
                "admits at least one in-domain violation: the safety is "
                "carried by the joint action of all premises"
                % (
                    "all 62 subsets" if lattice == "full"
                    else "the 6 single-premise subsets; the full 62-subset "
                    "lattice is out of scope for this run"
                )
            ),
            "status": "PASS" if u6_ok else "FAIL",
            "evidence": {
                "latticePolicy": lattice,
                "subsetsChecked": len(lattice_entries),
                "violatingSubsets": sum(
                    1 for entry in lattice_entries if entry["violations"] > 0
                ),
                "candidateSufficientSubsets": sufficient_subsets,
                "expectedSafeSubsets": sorted(
                    list(s) for s in expected_safe
                ),
                "lattice": lattice_entries,
            },
        },
        {
            "id": "U7",
            "statement": (
                "each single-premise omission's minimal counterexample "
                "belongs to its intended hazard family"
            ),
            "status": "PASS" if u7_ok else "FAIL",
            "evidence": u7_evidence,
        },
        {
            "id": "U8",
            "statement": (
                "exploration is complete at each configuration's required "
                "bound and one step below it the status is never PASS"
            ),
            "status": "PASS" if u8_ok else "FAIL",
            "evidence": u8_evidence,
        },
        {
            "id": "U9",
            "statement": (
                "the full-contract verdict is identical in bracket and "
                "strict observation modes"
            ),
            "status": "PASS" if u9_ok else "FAIL",
            "evidence": {
                mode: {
                    "status": run["status"],
                    "explorationComplete": run["explorationComplete"],
                    "violations": run["violations"],
                }
                for mode, run in sorted(mode_runs.items())
            },
        },
        {
            "id": "U10",
            "statement": (
                "report totals equal the sum over member runs and the "
                "top-level status reflects the full contract only"
            ),
            "status": "PASS" if u10_ok else "FAIL",
            "evidence": u10_evidence,
        },
    ]

    statuses = [entry["status"] for entry in hypotheses]
    overall = "PASS" if all(s == "PASS" for s in statuses) else "FAIL"
    campaign_id = "authz-validation-%s-univcheck" % (
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    return {
        "campaignId": campaign_id,
        "checker": CHECKER_NAME,
        "checkerVersion": CHECKER_VERSION,
        "modelName": model_name,
        "underlyingModel": mod.MODEL_NAME,
        "underlyingModelVersion": mod.MODEL_VERSION,
        "bound": bound,
        "hypotheses": hypotheses,
        "findings": findings,
        "status": overall,
        "statusMeaning": {
            "PASS": (
                "every universal hypothesis held over the complete "
                "explorations of the bounded abstract model"
            ),
            "FAIL": (
                "at least one universal hypothesis is falsified within the "
                "bounded abstract model; see the failing hypothesis and any "
                "findings"
            ),
        },
        "scopeBoundary": (
            "abstract bounded-model evidence only; conditional on the "
            "structural assumptions of %s v%s; not a proof of any "
            "implementation, deployment, or runtime behavior; live "
            "E1/E3/E4 validation remains BLOCKED regardless of this "
            "result" % (mod.MODEL_NAME, mod.MODEL_VERSION)
        ),
    }


def _format_text_report(report):
    lines = []
    lines.append(
        "%s v%s over %s v%s -- abstract bounded-model evidence ONLY"
        % (
            report["checker"],
            report["checkerVersion"],
            report["underlyingModel"],
            report["underlyingModelVersion"],
        )
    )
    lines.append("bound=%d" % report["bound"])
    lines.append("")
    for entry in report["hypotheses"]:
        lines.append("  [%s] %s: %s" % (entry["id"], entry["status"], entry["statement"]))
        if entry["id"] == "U6":
            ev = entry["evidence"]
            lines.append(
                "      subsets checked=%d violating=%d candidateSufficient=%s"
                % (
                    ev["subsetsChecked"],
                    ev["violatingSubsets"],
                    ev["candidateSufficientSubsets"] or "none",
                )
            )
        if entry["id"] == "U7":
            for premise, item in sorted(entry["evidence"].items()):
                lines.append(
                    "      %-24s %s class=%s (events=%s)"
                    % (
                        premise,
                        item["status"],
                        item["observedScheduleClass"],
                        item["counterexampleEvents"],
                    )
                )
    for finding in report["findings"]:
        lines.append(
            "  FINDING: %s -- %s %s"
            % (finding["finding"], finding["detail"], finding["subsets"])
        )
    lines.append("")
    lines.append("Overall status: %s" % report["status"])
    lines.append("Scope: %s" % report["scopeBoundary"])
    return "\n".join(lines)


_MANIFEST_SOURCES = (
    "e5_model_check.py",
    "e5_model_check_two_mutations.py",
    "bounded_model_execution.py",
    "universal_hypotheses_check.py",
    "experiment_common.py",
    "test_universal_hypotheses_check.py",
    "test_classify_e1_properties.py",
)


def _sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(report, out_path, started_at, finished_at, argv):
    """Freeze a checker run as a digest-bound manifest (recording rules).

    The manifest records the campaign id, tool source hashes, command,
    start/end times, the full report, and the evidence boundary. It is a
    generated result: per the repository policy it belongs under
    ``evidence/`` (gitignored) and never overwrites an earlier run.
    """
    here = Path(__file__).resolve().parent
    manifest = {
        "campaignId": report.get("campaignId"),
        "checker": CHECKER_NAME,
        "checkerVersion": CHECKER_VERSION,
        "model": report.get("underlyingModel"),
        "modelVersion": report.get("underlyingModelVersion"),
        "status": report.get("status"),
        "startedAtUtc": started_at,
        "finishedAtUtc": finished_at,
        "command": list(argv),
        "platform": platform.platform(),
        "pythonVersion": sys.version,
        "sourceHashes": {
            name: _sha256_of(here / name)
            for name in _MANIFEST_SOURCES
            if (here / name).exists()
        },
        "report": report,
        "durablePostcondition": (
            "none required: model workers are side-effect-free and owned by "
            "their invocation; only this manifest file is written"
        ),
        "logCompleteness": (
            "complete: the report embeds all run aggregates; no separate "
            "stdout log is required to interpret it"
        ),
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise SystemExit(
            "refusing to overwrite an existing manifest: %s "
            "(recording rule: a new run never overwrites an earlier run)"
            % out
        )
    out.write_text(json.dumps(manifest, indent=2, sort_keys=False),
                   encoding="utf-8")
    return manifest


def main(argv=None):
    """CLI entry point. Returns a process exit code (0 all-PASS, 1 FAIL)."""
    parser = argparse.ArgumentParser(
        prog="universal_hypotheses_check",
        description=(
            "Universal-hypothesis checker over the bounded admission-safety "
            "model(s). Offline, standard library only, no solver, no network."
        ),
    )
    parser.add_argument(
        "--model",
        choices=("single", "two", "both"),
        default="single",
        help=(
            "which registered model to check: single (one candidate grant "
            "+ one revocation mutation), two (two concurrent mutations), "
            "or both"
        ),
    )
    parser.add_argument(
        "--lattice",
        choices=("full", "singles"),
        default=None,
        help=(
            "U6 coverage: all 62 proper premise subsets (default for the "
            "single model) or the six single-premise subsets (default for "
            "the heavier two-mutation model)"
        ),
    )
    parser.add_argument(
        "--bound",
        type=int,
        default=None,
        help="exploration bound for the main runs; defaults to the model's own default",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full report as JSON instead of a text summary",
    )
    parser.add_argument(
        "--manifest-out",
        default=None,
        help=(
            "write a digest-bound run manifest to this path (under "
            "evidence/; an existing manifest is never overwritten)"
        ),
    )
    from bounded_model_execution import MAX_WORKERS

    parser.add_argument("--workers", type=int, choices=range(1, MAX_WORKERS + 1), default=1,
                        help="bounded independent model processes; configuration coverage is unchanged")
    args = parser.parse_args(argv)
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    model_names = (
        ["single", "two"] if args.model == "both" else [args.model]
    )
    reports = {}
    for name in model_names:
        lattice = args.lattice or ("full" if name == "single" else "singles")
        reports[name] = check_universal_hypotheses(
            args.bound, model_name=name, lattice=lattice, workers=args.workers
        )
    finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if len(reports) == 1:
        report = next(iter(reports.values()))
    else:
        overall = (
            "PASS"
            if all(r["status"] == "PASS" for r in reports.values())
            else "FAIL"
        )
        report = {
            "checker": CHECKER_NAME,
            "checkerVersion": CHECKER_VERSION,
            "models": reports,
            "status": overall,
            "statusMeaning": {
                "PASS": (
                    "every universal hypothesis held for every selected "
                    "model over the complete explorations"
                ),
                "FAIL": (
                    "at least one hypothesis failed for at least one "
                    "selected model"
                ),
            },
        }
    if args.manifest_out:
        if len(reports) == 1:
            write_manifest(
                report, args.manifest_out, started_at, finished_at,
                list(sys.argv) if argv is None else list(argv),
            )
        else:
            (Path(args.manifest_out).parent).mkdir(parents=True, exist_ok=True)
            out = Path(args.manifest_out)
            if out.exists():
                raise SystemExit(
                    "refusing to overwrite an existing manifest: %s" % out
                )
            out.write_text(
                json.dumps(
                    {
                        "campaignId": report.get("campaignId"),
                        "checker": CHECKER_NAME,
                        "checkerVersion": CHECKER_VERSION,
                        "status": report["status"],
                        "startedAtUtc": started_at,
                        "finishedAtUtc": finished_at,
                        "command": list(sys.argv) if argv is None else list(argv),
                        "platform": platform.platform(),
                        "pythonVersion": sys.version,
                        "sourceHashes": {
                            name: _sha256_of(
                                Path(__file__).resolve().parent / name
                            )
                            for name in _MANIFEST_SOURCES
                            if (Path(__file__).resolve().parent / name).exists()
                        },
                        "report": report,
                    },
                    indent=2,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        if len(reports) == 1:
            print(_format_text_report(report))
        else:
            for name, item in reports.items():
                print("==== model: %s ====" % name)
                print(_format_text_report(item))
            print("Overall status (both models): %s" % report["status"])
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - exercised via CLI smoke runs
    sys.exit(main())
