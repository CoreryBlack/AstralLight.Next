#!/usr/bin/env python3
"""Unbounded-confirmation checks for the bounded admission-safety models.

The bounded models answer "is the property safe within the bound?" This
checker answers the NEXT question: "does the bound itself hide anything?"
It separates three levels of "unbounded" and mechanically confirms what
can be confirmed offline today:

- Level 1 (step-count unboundedness, MECHANICALLY CONFIRMED HERE): the
  model's event algebra is finite BY CONSTRUCTION -- every event fires at
  most once (each chain is a total order without repeats), so the merge
  space is the entire well-formed schedule space, not a truncation of a
  longer one. Checks:
    * C1  event-space closure: every modeled chain carries unique events
      (no event can fire twice), so no schedule space exists beyond the
      enumerated one;
    * C2  bound invariance: the full-contract verdict, violation count,
      admitted and denied totals at MAX_BOUND are IDENTICAL to the
      default-bound run (the bound cannot add, remove, or change
      outcomes), combined with the U8 discipline (below the required
      bound a run can never mint a PASS). Together: the enumeration is
      exactly the full schedule space and its verdict is independent of
      the step bound.
- Level 2 (parameter unboundedness -- arbitrary numbers of mutations,
  arbitrary rounds): NOT mechanically confirmed yet. Empirical support
  gathered here: the N=1 and N=2 models' full contracts are both safe
  and their omission families coincide up to the relabeled
  identity-substitution family and the fence subsumption, which supports
  (does not prove) the reduction lemma: any minimal violating trace with
  N mutations reduces to a violating trace with at most two mutations
  (the unrepresented-mutation witness needs at most one candidate-
  removing mutation plus one second narrowing; additional mutations
  cannot change the latched read-time gates). Confirming the lemma
  mechanically requires the parameterized-N refactor and, definitively,
  a deductive proof.
- Level 3 (abstraction unboundedness -- the model vs the real protocol):
  outside every model. The instruments are a deductive proof of the
  conditional admission theorem (TLAPS on the TLA+ draft, or Coq/Isabelle)
  -- BLOCKED in this checkout until a pinned, checksum-verified tool
  exists -- and the M1--M5 premise audits. No bounded enumeration, at any
  bound, can close this level.

SCOPE: offline, standard-library-only, side-effect-free, no solver, no
network. All evidence is abstract bounded-model evidence and never
upgrades a live E1/E3/E4 status.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

import e5_model_check as model  # noqa: E402
import e5_model_check_two_mutations as model_two  # noqa: E402

__all__ = ["CHECKER_NAME", "CHECKER_VERSION", "check_unbounded_confirmation", "main"]

CHECKER_NAME = "unbounded-confirmation-check"
CHECKER_VERSION = "1.0.0"


def _chains_unique(model_module):
    """C1: every modeled chain carries unique events (fires at most once)."""
    problems = []
    for premises_sets in (
        {gate: True for gate in model_module.PREMISES},
        {gate: False for gate in model_module.PREMISES},
    ):
        for mode in ("bracket", "strict"):
            chains = model_module.build_chains(premises_sets, mode)
            for chain_name, events in chains.items():
                seen = set()
                for event in events:
                    if event in seen:
                        problems.append((chain_name, event, mode))
                    seen.add(event)
    return problems


def check_unbounded_confirmation(models=("single", "two")):
    """Run the unbounded-confirmation checks; return a report dict.

    ``models`` selects which registered models participate in the C2
    bound-invariance re-enumeration. The two-mutation model's bracket
    enumeration is expensive, so offline lock tests confirm C2 on the
    single model; the full both-model confirmation belongs to the CLI
    evidence run.
    """
    hypotheses = []
    selected = {
        "single": model,
        "two": model_two,
    }
    models = {name: selected[name] for name in models}

    # --- C1: event-space closure (both models) --------------------------
    problems_single = _chains_unique(model)
    problems_two = _chains_unique(model_two)
    c1_ok = not problems_single and not problems_two
    hypotheses.append({
        "id": "C1",
        "statement": (
            "event-space closure: every modeled chain carries unique "
            "events, so each event fires at most once per trace and the "
            "merge space is the entire well-formed schedule space (no "
            "schedule space exists beyond the enumerated one)"
        ),
        "status": "PASS" if c1_ok else "FAIL",
        "evidence": {
            "singleModelProblems": problems_single,
            "twoMutationModelProblems": problems_two,
        },
    })

    # --- C2: bound invariance at MAX_BOUND (both models, both modes) ----
    c2_ok = True
    c2_evidence = {}
    for model_name, mod in sorted(models.items()):
        full = mod.normalize_premises()
        for mode in ("bracket", "strict"):
            baseline = mod.run_model(full, mode, mod.DEFAULT_BOUND)
            stressed = mod.run_model(full, mode, mod.MAX_BOUND)
            fields = (
                baseline["status"] == stressed["status"]
                and baseline["violations"] == stressed["violations"]
                and baseline["admittedTraces"] == stressed["admittedTraces"]
                and baseline["deniedTraces"] == stressed["deniedTraces"]
                and baseline["explorationComplete"]
                and stressed["explorationComplete"]
                and baseline["exploredTraces"] == stressed["exploredTraces"]
            )
            c2_ok &= fields
            c2_evidence["%s/%s" % (model_name, mode)] = {
                "boundInvariant": fields,
                "status": baseline["status"],
                "exploredTraces": baseline["exploredTraces"],
                "maxBoundExploredTraces": stressed["exploredTraces"],
            }
    hypotheses.append({
        "id": "C2",
        "statement": (
            "bound invariance: the full-contract verdict, totals, and "
            "explored-trace count at MAX_BOUND are identical to the "
            "default-bound run in every configuration -- the step bound "
            "neither truncates nor alters the schedule space"
        ),
        "status": "PASS" if c2_ok else "FAIL",
        "evidence": c2_evidence,
    })

    # --- C3: parameter-unboundedness (cutoff evidence + obligation) ------
    # N=1 vs N=2 family comparison from the two models' verified verdicts.
    n2_manifest = Path(__file__).resolve().parent.parent / "evidence" / "univcheck" / "manifest-20260928T070633Z.json"
    empirical = {
        "n1": {"fullContract": "PASS (both modes, exhaustive)"},
        "n2": {"fullContract": "PASS (both modes, exhaustive)"},
        "familyComparison": (
            "the N=2 omission families coincide with N=1's up to the "
            "relabeled identity-substitution family and the fence "
            "subsumption; no new violating family appears at N=2"
        ),
        "manifestConsidered": n2_manifest.name if n2_manifest.exists() else None,
    }
    hypotheses.append({
        "id": "C3",
        "statement": (
            "parameter unboundedness is NOT mechanically confirmed: the "
            "reduction lemma (any minimal violating trace with N mutations "
            "reduces to at most two mutations) is stated with empirical "
            "support from N=1/N=2, and its mechanical confirmation "
            "requires the parameterized-N refactor plus a deductive proof"
        ),
        "status": "UNKNOWN",
        "evidence": empirical,
    })

    # --- C4: abstraction level -------------------------------------------
    hypotheses.append({
        "id": "C4",
        "statement": (
            "abstraction unboundedness (model vs the real protocol) is "
            "outside every bounded enumeration: the instruments are a "
            "deductive proof of the conditional admission theorem (TLAPS "
            "on the TLA+ draft, or Coq/Isabelle) -- BLOCKED in this "
            "checkout until a pinned checksum-verified tool exists -- and "
            "the M1--M5 premise audits"
        ),
        "status": "UNKNOWN",
        "evidence": {
            "tlaDraft": "Docs/authorization-validation/formal/AdmissionSafety.tla",
            "tlaStatus": "BLOCKED (no pinned checksum-verified TLC/TLAPS)",
            "premises": "M1-M5 premise audits per IMPLEMENTATION_MAP.md",
        },
    })

    decisive = [entry["status"] for entry in hypotheses if entry["status"] != "UNKNOWN"]
    overall = (
        "PASS"
        if decisive and all(s == "PASS" for s in decisive)
        else "FAIL"
    )
    return {
        "checker": CHECKER_NAME,
        "checkerVersion": CHECKER_VERSION,
        "status": overall,
        "statusMeaning": {
            "PASS": (
                "every mechanically decidable unbounded-confirmation check "
                "passed; the UNKNOWN entries mark the levels that require "
                "instrumentation beyond this checkout (C3 parameterized "
                "refactor + deductive proof, C4 deductive proof) and are "
                "explicit obligations, not failures"
            ),
            "FAIL": "at least one mechanically decidable check failed",
        },
        "hypotheses": hypotheses,
        "scopeBoundary": (
            "abstract bounded-model evidence only; not a proof of any "
            "implementation, deployment, or runtime behavior; live "
            "validation remains BLOCKED regardless of this result"
        ),
    }


def _format_text_report(report):
    lines = [
        "%s v%s -- abstract bounded-model evidence ONLY"
        % (report["checker"], report["checkerVersion"]),
        "",
    ]
    for entry in report["hypotheses"]:
        lines.append("  [%s] %s: %s" % (entry["id"], entry["status"], entry["statement"]))
    lines.append("")
    lines.append("Overall status: %s" % report["status"])
    lines.append("Scope: %s" % report["scopeBoundary"])
    return "\n".join(lines)


def main(argv=None):
    """CLI entry point. Returns 0 all-decisive-PASS, 1 otherwise."""
    parser = argparse.ArgumentParser(
        prog="unbounded_confirmation",
        description=(
            "Unbounded-confirmation checks over the bounded admission-"
            "safety models. Offline, standard library only."
        ),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit the full report as JSON instead of a text summary",
    )
    args = parser.parse_args(argv)
    report = check_unbounded_confirmation()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(_format_text_report(report))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - exercised via CLI smoke runs
    sys.exit(main())
