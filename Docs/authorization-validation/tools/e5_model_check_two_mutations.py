#!/usr/bin/env python3
"""Bounded model checker with TWO concurrent revocation-class mutations.

This model tightens the single most significant structural abstraction of
``e5_model_check.py`` (one candidate grant + one revocation-class mutation):
the enumeration now carries TWO concurrently schedulable revocation-class
mutations against one candidate grant and one read-path cache.

- Mutation A removes the candidate grant (its evidence-body advance
  withdraws the candidate from the served evidence).
- Mutation B is a second, independent revocation-class narrowing of the
  same card that does NOT remove the candidate (it narrows a different
  grant). The conditional admission property still requires B to be
  published before any ALLOW whose consistency point postdates B's
  commit, exactly as for A.

The universal safety property checked is therefore the CONJUNCTION over
both mutations: within the bounded model there is NO schedule in which
the full contract admits a trace where ANY mutation committed strictly
before the final observation (t_f) AND the candidate reaches host
admission. This is strictly stronger than the single-mutation property:
each mutation individually and the pair jointly must be covered by the
pending probes, the fence, the bracket/recheck, the final load, and the
identity match.

Cache model (generalized to counts). The read-path cache pair (M, b)
becomes a pair of advance counters over the two mutations:

- ``head``: number of fired PUBLISH events (durable published head;
  rollback does not lower it).
- ``manifest_c``: number of PUBLISH events effective at the read step
  (a rollback clears every manifest advance that fired before it).
- ``body_c``: number of BODY_ADVANCE events effective at the read step
  (the same rollback rule).
- torn ("mixed") state: ``manifest_c != body_c``; with two mutations the
  torn pair can MIX sub-events from DIFFERENT mutations (e.g. A's
  manifest advance with B's body advance), which the single-mutation
  model cannot express.
- candidate presence: the served evidence still carries the candidate at
  its original revision iff A's body advance is NOT effective at the
  read step; a rollback restores the pre-narrowing content, so it also
  restores candidate presence.

Pending probes capture "some mutation is in flight" AT THE READ STEP:
begun but not durable, or durable but publication incomplete
(publication of mutation i completes only when BOTH its manifest advance
and its body advance have fired). With the probe premise on, any probe
observing an in-flight mutation latches the admission fail-closed; there
is no admission-time re-derivation and no admission-side watermark.

Domain classification and violation. Each mutation has its own commit
interval [begin_i, durable_i] against the single consistency point
t_f = m0 (strict mode: the atomic strict load). With TWO mutations the
single-model shortcut (admitted + durable-before-t_f => stale) is WRONG:
a second narrowing that is fully published AND represented in the
admitted evidence satisfies P4 while the candidate remains matchable.
The violation condition is explicit and two-family:

- V1  some mutation committed strictly before t_f AND is NOT represented
      in the admitted evidence (publication incomplete at the evidence
      read, or a rollback tore it away);
- V2  the admitted evidence does not carry the candidate at its original
      revision (identity substitution; reachable only with exact_identity
      removed or via bypass).

A strictly-before mutation that IS represented yields a SAFE, in-domain
admission, reported in its own ``strictlyBeforeRepresented`` domain
bucket. Every admitted trace lands in EXACTLY ONE domain bucket
(conservation): notStale > identitySubstitution > unknownDomain >
strictlyBefore (V1) > strictlyBeforeRepresented > overlapUnknown >
afterFinalObservation. Violations record ``violatingMutations`` -- the
subset of {A, B} strictly before t_f and unrepresented -- and
``candidateAbsent`` for V2, so a violation carried by the second
narrowing alone (B) is distinguishable from one carried by the candidate
removal (A).

SCOPE AND EVIDENCE BOUNDARY (read this first):

- ABSTRACT BOUNDED-MODEL EVIDENCE ONLY. Not a mechanized proof of any
  implementation, deployment, or runtime behavior. The model keeps the
  single model's structural assumptions (fixed checklist order, latched
  read-time gates, dense steps, free decision tail with no admission-time
  re-derivation) and adds: two mutations with independent commit/publication
  chains, count-based cache advances, cross-mutation torn states, and a
  per-mutation theorem domain. Two deliberate restrictions keep the
  enumeration tractable and are covered elsewhere: the single rollback
  adversary fires only in the DECISION TAIL (after the last scheduled
  read; pre-read rollback hazards are exhaustively covered by the
  single-mutation model), and publication is exactly two sub-events per
  mutation.
- Combined-premise omissions are enumerated by
  ``universal_hypotheses_check.py``; this module exposes the same
  premise vocabulary as the single model so the drift-guard naming
  stays aligned.
- The premise vocabulary, the classifier vocabulary, and the report
  shape mirror ``e5_model_check.py``; a rename on either side must be
  synchronized with the tests.

Enumeration: deterministic exhaustive depth-first merge of the event
chains, fixed chain priority (checklist, pre-observation, mutation A,
mutation B, rollback, bypass). The model uses no external solver, subprocess,
socket, or filesystem access; import is side-effect-free. The CLI may use
up to twelve owned processes for disjoint event prefixes, without changing
event order or coverage. Status semantics are identical to the single model:
PASS requires a complete
exploration with zero violations; a concrete counterexample is decisive
(FAIL); UNKNOWN covers incomplete explorations without counterexamples
and out-of-domain admissions; BLOCKED never appears in a report.

Python 3.8+ standard library only.
"""

from __future__ import annotations

import json
import sys

__all__ = [
    "MODEL_NAME",
    "MODEL_VERSION",
    "PREMISES",
    "MIN_BOUND",
    "MAX_BOUND",
    "DEFAULT_BOUND",
    "BoundError",
    "validate_bound",
    "normalize_premises",
    "without_premise",
    "cache_observation_two",
    "build_chains",
    "required_bound",
    "run_model",
    "build_report",
]

MODEL_NAME = "e5-bounded-model-check-two-mutations"
MODEL_VERSION = "1.0.0"

MIN_BOUND = 2
MAX_BOUND = 64
DEFAULT_BOUND = 28

EV_INIT = "INIT"
EV_BEGIN_A = "COMMIT_BEGIN_A"
EV_DURABLE_A = "COMMIT_DURABLE_A"
EV_PUBLISH_A = "PUBLISH_A"
EV_BODY_A = "BODY_ADVANCE_A"
EV_BEGIN_B = "COMMIT_BEGIN_B"
EV_DURABLE_B = "COMMIT_DURABLE_B"
EV_PUBLISH_B = "PUBLISH_B"
EV_BODY_B = "BODY_ADVANCE_B"
EV_ROLLBACK = "ROLLBACK"
EV_PRE_BEGIN = "PRE_OBS_BEGIN"
EV_PRE_END = "PRE_OBS_END"
EV_RELOAD_M0 = "RELOAD_M0"
EV_RELOAD_P0 = "RELOAD_P0"
EV_RELOAD_M1 = "RELOAD_M1"
EV_RELOAD_P1 = "RELOAD_P1"
EV_STRICT_LOAD = "STRICT_LOAD"
EV_MATCH = "MATCH"
EV_POST_BEGIN = "POST_OBS_BEGIN"
EV_POST_END = "POST_OBS_END"
EV_STRICT = "STRICT_OBS"
EV_ADMIT = "ADMIT"
EV_BYPASS = "BYPASS"

M_B_READ_EVENTS = (
    EV_PRE_END,
    EV_RELOAD_M0,
    EV_RELOAD_M1,
    EV_STRICT_LOAD,
    EV_POST_END,
    EV_STRICT,
)
PENDING_PROBE_EVENTS = (EV_RELOAD_P0, EV_RELOAD_P1, EV_STRICT_LOAD)

PREMISES = (
    "pending_probe",
    "post_recheck",
    "final_reload",
    "exact_identity",
    "generation_revoke_fence",
    "host_mediation",
)


class BoundError(ValueError):
    """Raised when a step bound is not a valid finite integer in range."""


def validate_bound(value):
    """Validate a finite step bound; return it as an int or raise BoundError."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BoundError("bound must be an integer, got %r" % (value,))
    if value < MIN_BOUND or value > MAX_BOUND:
        raise BoundError(
            "bound must be a finite bound in [%d, %d], got %d"
            % (MIN_BOUND, MAX_BOUND, value)
        )
    return value


def normalize_premises(premises=None, removed=None):
    """Return a full premise dict; optionally toggle or remove premises."""
    base = {name: True for name in PREMISES}
    if premises:
        for key, val in premises.items():
            if key not in base:
                raise ValueError("unknown premise: %r" % (key,))
            base[key] = bool(val)
    if removed is not None:
        if isinstance(removed, str):
            removed = (removed,)
        for name in removed:
            if name not in base:
                raise ValueError("unknown premise: %r" % (name,))
            base[name] = False
    return base


def without_premise(premise):
    """Premise set for a single-omission experiment (all on, one off)."""
    return normalize_premises(removed=premise)


def cache_observation_two(step, pub_a, body_a, pub_b, body_b, rollback_step,
                          fence_on):
    """Count-based read-path cache observation at ``step``.

    Returns manifest/body advance counters, the durable published head,
    torn/consistent and fence-valid verdicts, and whether the served
    evidence still carries the candidate at its original revision
    (``candidatePresent``). A rollback clears every manifest and body
    advance that fired before it and restores pre-narrowing content; the
    durable head is unaffected.
    """
    head = (1 if pub_a is not None and pub_a <= step else 0) + (
        1 if pub_b is not None and pub_b <= step else 0
    )

    def effective(fired_step):
        return fired_step is not None and fired_step <= step and (
            rollback_step is None or fired_step > rollback_step
        )

    manifest_c = int(effective(pub_a)) + int(effective(pub_b))
    body_c = int(effective(body_a)) + int(effective(body_b))
    candidate_present = not effective(body_a)
    consistent = manifest_c == body_c
    valid = True
    reason = None
    if fence_on:
        if not consistent:
            valid = False
            reason = (
                "manifest_ahead_body_stale"
                if manifest_c > body_c
                else "body_ahead_manifest_stale"
            )
        elif manifest_c < head:
            valid = False
            reason = "generation_below_published_head"
    return {
        "manifestCount": manifest_c,
        "bodyCount": body_c,
        "headCount": head,
        "consistent": consistent,
        "valid": valid,
        "reason": reason,
        "candidatePresent": candidate_present,
    }


def build_chains(premises, mode="bracket"):
    """Build the event chains whose merges are the well-formed schedules."""
    prem = normalize_premises(premises)
    if mode not in ("bracket", "strict"):
        raise ValueError("unknown observation mode: %r" % (mode,))
    checklist = []
    if prem["final_reload"]:
        if mode == "bracket":
            checklist.append(EV_RELOAD_M0)
            if prem["pending_probe"]:
                checklist.append(EV_RELOAD_P0)
            checklist.append(EV_RELOAD_M1)
            if prem["pending_probe"]:
                checklist.append(EV_RELOAD_P1)
        else:
            checklist.append(EV_STRICT_LOAD)
    checklist.append(EV_MATCH)
    recheck = []
    if prem["post_recheck"]:
        recheck = [EV_POST_BEGIN, EV_POST_END] if mode == "bracket" else [EV_STRICT]
        checklist.extend(recheck)
    checklist.append(EV_ADMIT)
    pre = [EV_PRE_BEGIN, EV_PRE_END] if mode == "bracket" else []
    mutation_a = [EV_BEGIN_A, EV_DURABLE_A, EV_PUBLISH_A, EV_BODY_A]
    mutation_b = [EV_BEGIN_B, EV_DURABLE_B, EV_PUBLISH_B, EV_BODY_B]
    rollback = [EV_ROLLBACK]
    bypass = [] if prem["host_mediation"] else [EV_BYPASS]
    return {
        "checklist": checklist,
        "pre": pre,
        "mutation_a": mutation_a,
        "mutation_b": mutation_b,
        "rollback": rollback,
        "bypass": bypass,
        "recheck": recheck,
    }


def required_bound(premises=None, mode="bracket"):
    """Minimum step bound for a complete exploration of this configuration."""
    chains = build_chains(premises, mode)
    total_events = sum(
        len(chains[key])
        for key in ("checklist", "pre", "mutation_a", "mutation_b",
                    "rollback", "bypass")
    )
    return 1 + total_events


def shard_prefixes(premises=None, mode="bracket", bound=DEFAULT_BOUND,
                   rollback_tail_only=True):
    chains = build_chains(premises, mode)
    bound = validate_bound(bound)
    names = ("checklist", "pre", "mutation_a", "mutation_b", "rollback", "bypass")
    lengths = tuple(len(chains[name]) for name in names)
    depth = min(2, bound - 1)
    prefixes = []

    def visit(indices, prefix):
        if len(prefix) == depth or prefix and prefix[-1] in (EV_ADMIT, EV_BYPASS):
            prefixes.append(prefix)
            return
        for slot, name in enumerate(names):
            index = indices[slot]
            if index >= lengths[slot]:
                continue
            event = chains[name][index]
            if slot == 0 and event == EV_MATCH and indices[1] < lengths[1]:
                continue
            if slot == 4 and rollback_tail_only and indices[0] != lengths[0] - 1:
                continue
            next_indices = list(indices)
            next_indices[slot] += 1
            visit(tuple(next_indices), prefix + (event,))

    visit((0, 0, 0, 0, 0, 0), ())
    return prefixes


def run_model(premises=None, mode="bracket", bound=DEFAULT_BOUND,
              rollback_tail_only=True, *, _trace_prefix=()):
    """Exhaustively enumerate the two-mutation configuration; return a run dict.

    The run-dict shape mirrors ``e5_model_check.run_model`` so the
    universal-hypothesis checker can consume both models through one
    interface. Violations record ``violatingMutations`` (the subset of
    {A, B} committed strictly before t_f).

    ``rollback_tail_only`` restricts the single rollback adversary to the
    decision tail (the default, tractable scope; pre-read rollback hazards
    are covered by the single-mutation model). ``False`` restores the full
    adversary for stress runs: pre-read rollbacks then interact with the
    fence (below-head reads) and with per-mutation representation, which
    makes the generation/revoke fence independently load-bearing again.
    Stress runs should keep to strict mode, where the unrestricted
    adversary stays tractable.
    """
    prem = normalize_premises(premises)
    bound = validate_bound(bound)
    chains = build_chains(prem, mode)
    checklist = chains["checklist"]
    pre_chain = chains["pre"]
    mut_a = chains["mutation_a"]
    mut_b = chains["mutation_b"]
    rollback_chain = chains["rollback"]
    bypass_chain = chains["bypass"]
    recheck_events = chains["recheck"]
    checklist_len = len(checklist)
    pre_len = len(pre_chain)
    mut_a_len = len(mut_a)
    mut_b_len = len(mut_b)
    rollback_len = len(rollback_chain)
    prefix_len = len(_trace_prefix)
    recheck_read_event = recheck_events[-1] if recheck_events else None
    checklist_set = frozenset(checklist)
    mut_a_set = frozenset(mut_a)
    mut_b_set = frozenset(mut_b)
    pre_set = frozenset(pre_chain)

    fence_on = prem["generation_revoke_fence"]
    exact_on = prem["exact_identity"]
    probe_on = prem["pending_probe"]
    recheck_on = prem["post_recheck"]
    reload_on = prem["final_reload"]
    bracket_mode = mode == "bracket"
    if bracket_mode:
        configured_probes = (
            [EV_RELOAD_P0, EV_RELOAD_P1] if (reload_on and probe_on) else []
        )
        tf_event = EV_RELOAD_M0
    else:
        configured_probes = [EV_STRICT_LOAD] if (reload_on and probe_on) else []
        tf_event = EV_STRICT_LOAD
    # The observation boundary is determined by the premises alone (the
    # single model's final_observation_interval fallback chain): t_f = m0
    # (or the strict load); without the final load the recheck read's
    # START serves as the boundary, then the pre-observation's start.
    if reload_on:
        boundary_event = tf_event
    elif recheck_on:
        boundary_event = recheck_events[0]
    elif bracket_mode:
        boundary_event = EV_PRE_BEGIN
    else:
        boundary_event = None

    counts = {
        "exploredStates": 0,
        "exploredTraces": 0,
        "incompleteTraces": 0,
        "admittedTraces": 0,
        "deniedTraces": 0,
        "bypassAdmittedTraces": 0,
        "admittedNotStale": 0,
        "admittedStrictlyBefore": 0,
        "admittedStrictlyBeforeRepresented": 0,
        "admittedIdentitySubstitution": 0,
        "admittedOverlapUnknown": 0,
        "admittedAfterFinalObservation": 0,
        "admittedUnknownDomain": 0,
        "violations": 0,
        "violationsByCandidateRemoval": 0,
        "violationsBySecondNarrowingOnly": 0,
        "violationsByBoth": 0,
        "violationsByCandidateAbsent": 0,
        "publishAfterLastReadBeforeAdmissionTraces": 0,
        "admittedPublishAfterLastRead": 0,
        "rollbackAfterLastReadBeforeAdmissionTraces": 0,
        "publishAfterFinalObservationBeforeAdmissionTraces": 0,
        "admittedPublishAfterFinalObservation": 0,
        "staleCommitPublishAfterLastReadTraces": 0,
        "admittedStaleCommitPublishAfterLastRead": 0,
        "tornReadTraces": 0,
        "admittedTornReadTraces": 0,
    }
    denial_reasons = {}
    torn_kind_counts = {
        "manifest_ahead_body_stale": 0,
        "body_ahead_manifest_stale": 0,
    }
    violation_classes = {}
    admitted_torn_by_domain = {}
    best_violation = [None, None, None]

    def compute_read(event, step, pos):
        obs = cache_observation_two(
            step,
            pos.get(EV_PUBLISH_A),
            pos.get(EV_BODY_A),
            pos.get(EV_PUBLISH_B),
            pos.get(EV_BODY_B),
            pos.get(EV_ROLLBACK),
            fence_on,
        )
        return {
            "manifestCount": obs["manifestCount"],
            "bodyCount": obs["bodyCount"],
            "headCount": obs["headCount"],
            "candidatePresent": obs["candidatePresent"],
            "valid": obs["valid"],
            "consistent": obs["consistent"],
            "reason": obs["reason"],
            "step": step,
        }

    def evaluate_admission(pending_obs, reads, evidence, match_ok, pos):
        """Evaluate every gate from the LATCHED read-time observations only."""
        reasons = []
        if not match_ok:
            reasons.append("candidate_match_failed")
        if probe_on:
            for name in configured_probes:
                obs = pending_obs.get(name)
                if obs is None:
                    reasons.append("pending_probe_observation_missing:" + name)
                elif obs["pending"]:
                    reasons.append(
                        "pending_probe_latched_unsafe_delta:" + name
                    )
        if recheck_on:
            rd = reads.get(recheck_read_event)
            if rd is None or not rd["valid"]:
                reasons.append("post_recheck_read_missing_or_rejected")
            elif evidence is None or (
                rd["manifestCount"],
                rd["bodyCount"],
            ) != (evidence["manifestCount"], evidence["bodyCount"]):
                reasons.append("post_recheck_disagrees_with_evidence")
            if bracket_mode:
                prd = reads.get(EV_PRE_END)
                if prd is None or not prd["valid"]:
                    reasons.append("pre_observation_missing_or_rejected")
                else:
                    fired_durables = [
                        pos[name]
                        for name in (EV_DURABLE_A, EV_DURABLE_B)
                        if name in pos
                    ]
                    if fired_durables and prd["step"] >= min(fired_durables):
                        reasons.append("pre_observation_does_not_precede_commit")
        if reload_on:
            m0 = reads.get(EV_RELOAD_M0) if bracket_mode else reads.get(
                EV_STRICT_LOAD
            )
            if m0 is None or not m0["valid"]:
                reasons.append("final_load_read_missing_or_rejected")
            if bracket_mode:
                m1 = reads.get(EV_RELOAD_M1)
                if m1 is None or not m1["valid"]:
                    reasons.append("final_load_read_missing_or_rejected:RELOAD_M1")
        if fence_on:
            rejected = sorted(
                name for name, rd in reads.items() if not rd["valid"]
            )
            if rejected:
                reasons.append(
                    "generation_fence_rejected_reads:" + ",".join(rejected)
                )
        if reasons:
            return "DENIED", ";".join(reasons)
        return "ADMITTED", None

    def schedule_class(pos, reads, evidence, last_read_step):
        """Label the schedule family of a violating trace (pure)."""
        if EV_BYPASS in pos:
            return "bypass_unmediated_admission"
        if any(not rd["consistent"] for rd in reads.values()):
            return "mixed_manifest_body_state"
        if EV_ROLLBACK in pos:
            return "stale_generation_pointer_rollback"
        publishes_fired = [
            name for name in (EV_PUBLISH_A, EV_PUBLISH_B) if name in pos
        ]
        incomplete = any(
            not (
                pos.get(publish) is not None
                and pos.get(body) is not None
            )
            for begin, publish, body in (
                (EV_BEGIN_A, EV_PUBLISH_A, EV_BODY_A),
                (EV_BEGIN_B, EV_PUBLISH_B, EV_BODY_B),
            )
            if begin in pos
        )
        if not publishes_fired or incomplete:
            return "source_pending_commit_without_publication"
        admit_step = pos[EV_ADMIT]
        window_hits = [
            step
            for name in (EV_PUBLISH_A, EV_BODY_A, EV_PUBLISH_B, EV_BODY_B)
            for step in (pos.get(name),)
            if step is not None and last_read_step < step < admit_step
        ]
        if window_hits:
            return "mutation_published_after_last_read_before_admission"
        evidence_step = evidence["step"] if evidence is not None else None
        if evidence_step is not None and any(
            evidence_step < pos[name] <= last_read_step
            for name in (EV_PUBLISH_A, EV_PUBLISH_B)
            if name in pos
        ):
            return "mutation_published_between_evidence_read_and_last_read"
        if evidence is not None and not evidence["candidatePresent"]:
            return "candidate_removal_identity_confusion"
        return "unclassified"

    def record_terminal(seq, pos, obs_step, reads, pending_obs, evidence,
                        outcome, reason, last_read_step, admit_step):
        counts["exploredTraces"] += 1
        torn_kinds = set()
        for rd in reads.values():
            if not rd["consistent"]:
                torn_kinds.add(
                    "manifest_ahead_body_stale"
                    if rd["manifestCount"] > rd["bodyCount"]
                    else "body_ahead_manifest_stale"
                )
        if torn_kinds:
            counts["tornReadTraces"] += 1
            for kind in torn_kinds:
                torn_kind_counts[kind] = torn_kind_counts.get(kind, 0) + 1
        # Torn-read diagnostics count DENIED traces too: the point is that
        # the window interleavings are enumerated and then caught.
        if outcome != "BYPASS_ADMITTED" and reads:
            sub_events = [
                pos.get(name)
                for name in (EV_PUBLISH_A, EV_BODY_A, EV_PUBLISH_B, EV_BODY_B)
            ]
            rollback_pos = pos.get(EV_ROLLBACK)
            publish_in_window = any(
                step is not None and last_read_step < step < admit_step
                for step in sub_events
            )
            rollback_in_window = rollback_pos is not None and (
                last_read_step < rollback_pos < admit_step
            )
            if publish_in_window:
                counts["publishAfterLastReadBeforeAdmissionTraces"] += 1
                if outcome == "ADMITTED":
                    counts["admittedPublishAfterLastRead"] += 1
            if rollback_in_window:
                counts["rollbackAfterLastReadBeforeAdmissionTraces"] += 1
            if reload_on and obs_step is not None:
                after_tf = any(
                    step is not None and obs_step < step < admit_step
                    for step in sub_events
                )
                if after_tf:
                    counts[
                        "publishAfterFinalObservationBeforeAdmissionTraces"
                    ] += 1
                    if outcome == "ADMITTED":
                        counts["admittedPublishAfterFinalObservation"] += 1
                # Per-mutation stale-commit window: the sub-event in the
                # (last_read, admit) tail must belong to the SAME mutation
                # whose commit is strictly before t_f -- with two mutations
                # a tail publication of the OTHER (post-t_f) mutation does
                # not make the pre-t_f one stale.
                for begin, durable, publish, body in (
                    (EV_BEGIN_A, EV_DURABLE_A, EV_PUBLISH_A, EV_BODY_A),
                    (EV_BEGIN_B, EV_DURABLE_B, EV_PUBLISH_B, EV_BODY_B),
                ):
                    if (
                        durable in pos
                        and pos[durable] < obs_step
                        and any(
                            pos.get(name) is not None
                            and last_read_step < pos[name] < admit_step
                            for name in (publish, body)
                        )
                    ):
                        counts["staleCommitPublishAfterLastReadTraces"] += 1
                        if outcome == "ADMITTED":
                            counts[
                                "admittedStaleCommitPublishAfterLastRead"
                            ] += 1
        if outcome == "DENIED":
            counts["deniedTraces"] += 1
            for reason_name in reason.split(";"):
                denial_reasons[reason_name] = (
                    denial_reasons.get(reason_name, 0) + 1
                )
            return
        counts["admittedTraces"] += 1
        if torn_kinds:
            counts["admittedTornReadTraces"] += 1
        if outcome == "BYPASS_ADMITTED":
            counts["bypassAdmittedTraces"] += 1
        # Violation semantics for TWO mutations. The single-model shortcut
        # (admitted + durable-before-t_f => stale) is WRONG here: a second
        # narrowing that is fully published AND represented in the admitted
        # evidence satisfies P4 while the candidate remains matchable. The
        # explicit condition is:
        #   V1  some mutation committed strictly before t_f AND is NOT
        #       represented in the admitted evidence (its publication is
        #       incomplete at the evidence read, or a rollback tore it
        #       away), or
        #   V2  the admitted evidence does not carry the candidate at its
        #       original revision at all (identity substitution; only
        #       reachable with exact_identity removed, or via bypass).
        # A strictly-before mutation that IS represented yields a safe,
        # in-domain admission and gets its own domain bucket.
        durables_fired = [
            pos[name] for name in (EV_DURABLE_A, EV_DURABLE_B) if name in pos
        ]
        evidence_step = evidence["step"] if evidence is not None else None
        rollback_pos = pos.get(EV_ROLLBACK)

        def represented(publish_step, body_step):
            if evidence_step is None:
                return False

            def effective(step_value):
                # Representation is evaluated AS OF the evidence read: a
                # rollback AFTER that read cannot retroactively un-represent
                # the anchored evidence; a rollback BEFORE it clears the
                # advances that fired before the rollback.
                return (
                    step_value is not None
                    and step_value <= evidence_step
                    and (
                        rollback_pos is None
                        or rollback_pos > evidence_step
                        or step_value > rollback_pos
                    )
                )

            return effective(publish_step) and effective(body_step)

        # Observation boundary step, threaded through the enumeration
        # (the boundary event fires at most once per trace; pos does not
        # track read events).
        obs_start = obs_step
        strictly_before = []
        unrepresented = []
        for tag, durable, publish, body in (
            ("A", EV_DURABLE_A, EV_PUBLISH_A, EV_BODY_A),
            ("B", EV_DURABLE_B, EV_PUBLISH_B, EV_BODY_B),
        ):
            if durable in pos and obs_start is not None and pos[durable] < obs_start:
                strictly_before.append(tag)
                if not represented(pos.get(publish), pos.get(body)):
                    unrepresented.append(tag)
        candidate_absent = (
            evidence is not None and not evidence["candidatePresent"]
        )
        violating = bool(unrepresented) or candidate_absent
        # EXACTLY ONE domain bucket per admitted trace (conservation):
        # notStale > identitySubstitution > unknownDomain > strictlyBefore
        # (V1) > strictlyBeforeRepresented > overlapUnknown >
        # afterFinalObservation.
        if not durables_fired:
            counts["admittedNotStale"] += 1
            label = "notStale"
        elif candidate_absent:
            counts["admittedIdentitySubstitution"] += 1
            label = "identitySubstitution"
        elif obs_start is None:
            counts["admittedUnknownDomain"] += 1
            label = "unknownDomain"
        elif unrepresented:
            counts["admittedStrictlyBefore"] += 1
            label = "strictlyBefore"
        elif strictly_before:
            counts["admittedStrictlyBeforeRepresented"] += 1
            label = "strictlyBeforeRepresented"
        elif any(
            pos[begin] <= obs_start
            for begin, durable in (
                (EV_BEGIN_A, EV_DURABLE_A),
                (EV_BEGIN_B, EV_DURABLE_B),
            )
            if durable in pos and pos[durable] >= obs_start
        ):
            counts["admittedOverlapUnknown"] += 1
            label = "overlapUnknown"
        else:
            counts["admittedAfterFinalObservation"] += 1
            label = "afterFinalObservation"
        if torn_kinds:
            admitted_torn_by_domain[label] = (
                admitted_torn_by_domain.get(label, 0) + 1
            )
        if not violating:
            return
        counts["violations"] += 1
        if unrepresented:
            if len(unrepresented) == 2:
                counts["violationsByBoth"] += 1
            elif unrepresented == ["B"]:
                counts["violationsBySecondNarrowingOnly"] += 1
            else:
                counts["violationsByCandidateRemoval"] += 1
        else:
            counts["violationsByCandidateAbsent"] += 1
        cls = schedule_class(pos, reads, evidence, last_read_step)
        violation_classes[cls] = violation_classes.get(cls, 0) + 1
        names = tuple(seq)
        candidate_key = (len(names), names)
        if best_violation[0] is None or candidate_key < (
            best_violation[0],
            best_violation[1],
        ):
            detail = {
                "scheduleClass": cls,
                "outcome": outcome,
                "domain": label,
                "violatingMutations": unrepresented,
                "candidateAbsent": candidate_absent,
                "eventCount": len(names),
                "reads": {
                    name: {
                        "step": rd["step"],
                        "manifestCount": rd["manifestCount"],
                        "bodyCount": rd["bodyCount"],
                        "candidatePresent": rd["candidatePresent"],
                        "valid": rd["valid"],
                        "consistent": rd["consistent"],
                        "reason": rd["reason"],
                    }
                    for name, rd in sorted(reads.items())
                },
                "pendingObservations": {
                    name: {"step": obs["step"], "pending": obs["pending"]}
                    for name, obs in sorted(pending_obs.items())
                },
                "trace": [
                    {"step": index, "event": event}
                    for index, event in enumerate(names)
                ],
            }
            best_violation[0] = len(names)
            best_violation[1] = names
            best_violation[2] = detail

    def dfs(ia, ib, ic, idy, ie, ifr, seq, reads, pending_obs, evidence,
            match_ok, pos, obs_step, rollback_tail_only, last_read_step):
        if prefix_len == 0 or len(seq) >= prefix_len + 1:
            counts["exploredStates"] += 1
        a_next = checklist[ia] if ia < checklist_len else None
        enabled = []
        if a_next is not None and not (a_next == EV_MATCH and ib < pre_len):
            enabled.append(a_next)
        if ib < pre_len:
            enabled.append(pre_chain[ib])
        if ic < mut_a_len:
            enabled.append(mut_a[ic])
        if idy < mut_b_len:
            enabled.append(mut_b[idy])
        # Rollback: single adversarial event, restricted to the DECISION
        # TAIL (every scheduled read has fired; ADMIT is next). Pre-read
        # rollback hazards are exhaustively covered by the single-mutation
        # model; the tail placement preserves the latched-admission
        # stability check at a fraction of the enumeration cost.
        # Stress runs may lift the tail restriction with
        # rollback_tail_only=False; the default keeps the enumeration
        # tractable (pre-read rollback hazards live in the single model).
        if ie < rollback_len and (
            not rollback_tail_only or ia == checklist_len - 1
        ):
            enabled.append(EV_ROLLBACK)
        if bypass_chain and ifr == 0:
            enabled.append(EV_BYPASS)
        if len(seq) >= bound:
            counts["incompleteTraces"] += 1
            counts["exploredTraces"] += 1
            return
        step = len(seq)
        if step <= prefix_len:
            expected = _trace_prefix[step - 1]
            enabled = [expected] if expected in enabled else []
        for event in enabled:
            n_ia, n_ib, n_ic, n_idy, n_ie, n_ifr = ia, ib, ic, idy, ie, ifr
            n_evidence = evidence
            n_obs_step = obs_step
            n_last_read_step = last_read_step
            n_match = match_ok
            terminal = False
            outcome = None
            reason = None
            # In-place state mutation with explicit undo after recursion:
            # semantically identical to copying, but avoids a full dict
            # copy per visited state (the two-mutation enumeration visits
            # orders of magnitude more states than the single model).
            if boundary_event is not None and event == boundary_event:
                # The boundary may be an interval-START marker (POST_OBS_BEGIN
                # / PRE_OBS_BEGIN), which is not itself a read.
                n_obs_step = step
            if event in M_B_READ_EVENTS or event in PENDING_PROBE_EVENTS:
                n_last_read_step = step
            if event in M_B_READ_EVENTS:
                rd = compute_read(event, step, pos)
                reads[event] = rd
                if event == tf_event and reload_on:
                    n_evidence = rd if rd["valid"] else None
            elif event == EV_MATCH:
                if not reload_on:
                    rd = reads.get(EV_PRE_END) if bracket_mode else None
                    n_evidence = rd if (rd is not None and rd["valid"]) else None
                n_match = n_evidence is not None and (
                    n_evidence["candidatePresent"] if exact_on else True
                )
            elif event == EV_ADMIT:
                # Terminal: pos already tracks every mutation/rollback
                # position; reads carry their own steps and t_f is threaded
                # as a parameter, so no full position-map rebuild is needed.
                pos[event] = step
                outcome, reason = evaluate_admission(
                    pending_obs, reads, evidence, match_ok, pos
                )
                terminal = True
            elif event == EV_BYPASS:
                pos[event] = step
                outcome = "BYPASS_ADMITTED"
                terminal = True
            if event in PENDING_PROBE_EVENTS:
                begun_a = ic >= 1
                complete_a = ic >= 4
                begun_b = idy >= 1
                complete_b = idy >= 4
                pending_obs[event] = {
                    "step": step,
                    "pending": (begun_a and not complete_a)
                    or (begun_b and not complete_b),
                }
            if event in checklist_set:
                n_ia += 1
            elif event in mut_a_set:
                n_ic += 1
                pos[event] = step
            elif event in mut_b_set:
                n_idy += 1
                pos[event] = step
            elif event == EV_ROLLBACK:
                n_ie += 1
                pos[event] = step
            elif event in pre_set:
                n_ib += 1
            else:
                n_ifr += 1
            seq.append(event)
            try:
                if terminal:
                    record_terminal(
                        seq, pos, n_obs_step, reads, pending_obs, n_evidence,
                        outcome, reason, n_last_read_step, step,
                    )
                else:
                    dfs(
                        n_ia, n_ib, n_ic, n_idy, n_ie, n_ifr, seq, reads,
                        pending_obs, n_evidence, n_match, pos, n_obs_step,
                        rollback_tail_only, n_last_read_step,
                    )
            finally:
                seq.pop()
                if terminal:
                    del pos[event]
            # Undo the in-place mutations before the next sibling branch.
            if event in M_B_READ_EVENTS:
                del reads[event]
            if event in PENDING_PROBE_EVENTS:
                del pending_obs[event]
            if event in mut_a_set or event in mut_b_set or event == EV_ROLLBACK:
                del pos[event]

    dfs(0, 0, 0, 0, 0, 0, [EV_INIT], {}, {}, None, None, {}, None,
        rollback_tail_only, -1)
    exploration_complete = counts["incompleteTraces"] == 0
    if counts["violations"]:
        status = "FAIL"
    elif exploration_complete:
        status = "PASS"
    else:
        status = "UNKNOWN"
    counterexample = best_violation[2] if best_violation[0] is not None else None
    return {
        "premises": dict(prem),
        "mode": mode,
        "bound": bound,
        "requiredBound": required_bound(prem, mode),
        "explorationComplete": exploration_complete,
        "exploredStates": counts["exploredStates"],
        "exploredTraces": counts["exploredTraces"],
        "incompleteTraces": counts["incompleteTraces"],
        "admittedTraces": counts["admittedTraces"],
        "deniedTraces": counts["deniedTraces"],
        "bypassAdmittedTraces": counts["bypassAdmittedTraces"],
        "admittedDomainCounts": {
            "notStale": counts["admittedNotStale"],
            "strictlyBefore": counts["admittedStrictlyBefore"],
            "strictlyBeforeRepresented": counts[
                "admittedStrictlyBeforeRepresented"
            ],
            "identitySubstitution": counts["admittedIdentitySubstitution"],
            "overlapUnknown": counts["admittedOverlapUnknown"],
            "afterFinalObservation": counts["admittedAfterFinalObservation"],
            "unknownDomain": counts["admittedUnknownDomain"],
        },
        "violations": counts["violations"],
        "violationsByMutation": {
            "candidateRemoval": counts["violationsByCandidateRemoval"],
            "secondNarrowingOnly": counts["violationsBySecondNarrowingOnly"],
            "both": counts["violationsByBoth"],
            "candidateAbsent": counts["violationsByCandidateAbsent"],
        },
        "violationClasses": {
            key: violation_classes[key] for key in sorted(violation_classes)
        },
        "denialReasons": {
            key: denial_reasons[key] for key in sorted(denial_reasons)
        },
        "admissionWindow": {
            "publishAfterLastReadBeforeAdmissionTraces": counts[
                "publishAfterLastReadBeforeAdmissionTraces"
            ],
            "admittedPublishAfterLastRead": counts[
                "admittedPublishAfterLastRead"
            ],
            "rollbackAfterLastReadBeforeAdmissionTraces": counts[
                "rollbackAfterLastReadBeforeAdmissionTraces"
            ],
            "publishAfterFinalObservationBeforeAdmissionTraces": counts[
                "publishAfterFinalObservationBeforeAdmissionTraces"
            ],
            "admittedPublishAfterFinalObservation": counts[
                "admittedPublishAfterFinalObservation"
            ],
            "staleCommitPublishAfterLastReadTraces": counts[
                "staleCommitPublishAfterLastReadTraces"
            ],
            "admittedStaleCommitPublishAfterLastRead": counts[
                "admittedStaleCommitPublishAfterLastRead"
            ],
        },
        "mixedManifestBody": {
            "tornReadTraces": counts["tornReadTraces"],
            "admittedTornReadTraces": counts["admittedTornReadTraces"],
            "admittedTornReadTracesByDomain": dict(
                sorted(admitted_torn_by_domain.items())
            ),
            "tornReadTracesByKind": dict(torn_kind_counts),
        },
        "counterexample": counterexample,
        "status": status,
    }


_ADDITIVE_SHARD_FIELDS = (
    "exploredStates", "exploredTraces", "incompleteTraces", "admittedTraces",
    "deniedTraces", "bypassAdmittedTraces", "admittedDomainCounts", "violations",
    "violationsByMutation", "violationClasses", "denialReasons", "admissionWindow",
    "mixedManifestBody",
)


def merge_shard_runs(premises, mode, bound, shard_runs):
    prefixes = shard_prefixes(premises, mode, bound)
    if [prefix for prefix, _ in shard_runs] != prefixes:
        raise ValueError("missing, duplicated or reordered model shard")
    if not shard_runs:
        raise ValueError("empty model shard set")
    identity = {
        "premises": normalize_premises(premises), "mode": mode, "bound": bound,
        "requiredBound": required_bound(premises, mode),
    }
    result = dict(identity)

    def add_values(values):
        if all(isinstance(value, dict) for value in values):
            keys = sorted({key for value in values for key in value})
            return {key: add_values([value.get(key, 0) for value in values])
                    for key in keys}
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("invalid model shard counter")
        return sum(values)

    for _, run in shard_runs:
        if any(run.get(key) != value for key, value in identity.items()):
            raise ValueError("model shard configuration drift")
    for field in _ADDITIVE_SHARD_FIELDS:
        result[field] = add_values([run[field] for _, run in shard_runs])
    ancestors = {prefix[:length] for prefix in prefixes
                 for length in range(len(prefix))}
    result["exploredStates"] += len(ancestors)
    result["explorationComplete"] = all(run["explorationComplete"] for _, run in shard_runs)
    examples = [run["counterexample"] for _, run in shard_runs
                if run["counterexample"] is not None]
    result["counterexample"] = min(
        examples,
        key=lambda example: (example["eventCount"],
                             tuple(event["event"] for event in example["trace"])),
        default=None,
    )
    result["status"] = (
        "FAIL" if result["violations"]
        else "PASS" if result["explorationComplete"] else "UNKNOWN"
    )
    return result


SUPPORTS_RUN_CACHE = True


def build_report(bound=DEFAULT_BOUND, run_cache=None):
    """Full contract in both modes plus the six single-premise omissions.

    ``run_cache`` optionally maps (premises-items, mode, bound-or-marker)
    to run dicts so the checker can share enumerations across hypotheses;
    keys with the literal marker ``"complete"`` are honored for any bound
    at or above the configuration's required bound.
    """
    bound = validate_bound(bound)

    def cached(prem, mode, run_bound):
        if run_cache is None:
            return run_model(prem, mode, run_bound)
        required = required_bound(prem, mode)
        key = (
            tuple(sorted(prem.items())), mode,
            "complete" if run_bound >= required else run_bound,
        )
        if key not in run_cache:
            run_cache[key] = run_model(dict(prem), mode, run_bound)
        return run_cache[key]

    full = normalize_premises()
    mode_runs = {mode: cached(full, mode, bound) for mode in ("bracket", "strict")}
    statuses = [run["status"] for run in mode_runs.values()]
    full_status = (
        "FAIL" if "FAIL" in statuses
        else ("UNKNOWN" if "UNKNOWN" in statuses else "PASS")
    )
    omissions = []
    for premise in PREMISES:
        run = cached(without_premise(premise), "bracket", bound)
        if run["violations"]:
            o_status = "FAIL"
        elif run["explorationComplete"]:
            o_status = "PASS"
        else:
            o_status = "UNKNOWN"
        omissions.append({"premise": premise, "status": o_status, "run": run})
    member_states = sum(
        run["exploredStates"] for run in mode_runs.values()
    ) + sum(entry["run"]["exploredStates"] for entry in omissions)
    member_traces = sum(
        run["exploredTraces"] for run in mode_runs.values()
    ) + sum(entry["run"]["exploredTraces"] for entry in omissions)
    return {
        "model": MODEL_NAME,
        "modelVersion": MODEL_VERSION,
        "bound": bound,
        "exploredStates": member_states,
        "exploredTraces": member_traces,
        "fullContract": {"status": full_status, "modes": mode_runs},
        "omissions": omissions,
        "status": full_status,
    }


if __name__ == "__main__":  # pragma: no cover - exercised via CLI smoke runs
    import argparse
    from bounded_model_execution import MAX_WORKERS, run_configurations

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, choices=range(1, MAX_WORKERS + 1), default=1)
    args = parser.parse_args()
    configurations = [(normalize_premises(), mode, DEFAULT_BOUND)
                      for mode in ("bracket", "strict")]
    configurations.extend((without_premise(premise), "bracket", DEFAULT_BOUND)
                          for premise in PREMISES)
    run_cache = run_configurations("e5_model_check_two_mutations", configurations, args.workers)
    report = build_report(DEFAULT_BOUND, run_cache=run_cache)
    print(json.dumps({
        "model": report["model"],
        "bound": report["bound"],
        "status": report["status"],
        "modes": {
            mode: {
                "status": run["status"],
                "violations": run["violations"],
                "admitted": run["admittedTraces"],
                "denied": run["deniedTraces"],
                "complete": run["explorationComplete"],
            }
            for mode, run in report["fullContract"]["modes"].items()
        },
        "omissions": {
            entry["premise"]: entry["status"] for entry in report["omissions"]
        },
    }, indent=2))
    sys.exit(0 if report["status"] == "PASS" else 1)
