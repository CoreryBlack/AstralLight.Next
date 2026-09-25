#!/usr/bin/env python3
"""Bounded model checker for abstract authorization admission safety.

For one candidate grant and one revocation-class source mutation, if
every modeled premise/control holds (pending probe, cache pre/post bracket with
post-recheck, final load, exact identity match, generation/revoke read fence,
host mediation), then within the bounded model there is NO schedule in which
the mutation committed strictly before the final observation AND a stale
candidate reaches host admission.

SCOPE AND EVIDENCE BOUNDARY (read this first):

- This tool produces ABSTRACT BOUNDED-MODEL EVIDENCE ONLY. It is NOT a
  mechanized proof of the AstralLight Rust (or Java) implementation, of any
  deployment, or of any runtime behavior. The model is a deliberate
  simplification of the observation protocol (source commit, delta durable,
  manifest/body publication, M/b cache observations, pending probes, strict
  current read, final load, host admission); every simplification and
  structural assumption is listed in the report's ``scopeLimitations`` field.
  A full-contract PASS means: exhaustive enumeration of the schedules of THIS
  abstract model up to the step bound found zero in-domain violating traces.
  It implies nothing beyond that.

- Runtime validation (separate execution records, including the Rust omission tests in
  ``astral-db/src/evidence_cache.rs`` and ``policy-engine/src/engine.rs``) checks code
  paths; this bounded model must never be presented as a proof of the production
  implementation (see ``VALIDATION_PROTOCOL.md``).

Model
-----
The model mirrors the observation protocol that the Rust implementation and
the E1/E2 experiment harness actually validate (``experiment_common.py ::
final_observation_interval``): the final load is an ORDERED observation
sequence, pending state is captured AT READ TIME and latched fail-closed,
and nothing is re-derived at the admission step.

Cache state (explicit manifest/body pair). The read-path cache is a pair
(M, b): the manifest/version generation M ("which version the cache claims")
and the evidence body revision b ("which content the cache serves"). The two
components advance INDEPENDENTLY, so torn ("mixed M/b") states are first-class
modeled states, not incidental:

- consistent: (g0, r0) before publication and (g1, r1) after a complete
  publication;
- torn: (g1, r0) -- stale body under a current manifest/head -- and (g0, r1)
  -- successor body under a stale manifest.

Events (each fires at one discrete step; interval events occupy their two
endpoint steps; steps are dense -- every step fires exactly one event, so only
relative order matters):

- ``INIT``                 step 0: initial published candidate (body r0,
                           manifest g0, published head g0).
- ``COMMIT_BEGIN`` /       source commit interval [begin, durable]; the
  ``COMMIT_DURABLE``      durable delta exists from ``COMMIT_DURABLE`` on
                           (revocation effective at the source).
- ``PUBLISH``              manifest/version advance (the CAS on the version
                           pointer): M: g0 -> g1 and the durable published
                           head becomes g1. By itself it does NOT advance the
                           evidence body.
- ``EVIDENCE_BODY_ADVANCE`` evidence body advance: b: r0 -> r1 (the successor
                           content becomes visible on the read path). It may
                           fire before or after ``PUBLISH`` (both torn orders
                           are reachable) and requires the durable commit.
- ``ROLLBACK``             adversarial read-path reset: the cache returns to
                           (g0, r0); the durable published head stays g1. At
                           most one rollback, only after ``PUBLISH`` (chain
                           order). A later ``EVIDENCE_BODY_ADVANCE``
                           re-advances the body (torn (g0, r1) again).
- ``PRE_OBS_BEGIN`` /      pre-commit cache observation interval (bracket
  ``PRE_OBS_END``         mode). The read observes the cache at its END step.
- ``RELOAD_M0``            first manifest/body read of the final load; the
                           theorem's final observation t_f is THIS step, and
                           the admission evidence is anchored here (m0: "the
                           first authoritative observation that supplies the
                           successful final evidence").
- ``RELOAD_P0``            pending probe inside the final load, after m0:
                           captures the in-flight state AT ITS READ STEP.
- ``RELOAD_M1``            second manifest/body read of the final load.
- ``RELOAD_P1``            second pending probe, after m1. The load's
                           observation bracket is ordered m0 < p0 < m1 < p1.
- ``STRICT_LOAD``          strict mode replaces the m0/p0/m1/p1 sequence with
                           ONE atomic strict load that observes the M/b pair
                           AND the pending state at a single step (the
                           strict_pending_probe).
- ``MATCH``                candidate match: exact (grant, revision) identity
                           when the ``exact_identity`` premise holds, otherwise
                           a grant-presence match (the successor-revision
                           hole).
- ``POST_OBS_BEGIN``/      post-recheck cache observation interval (bracket
  ``POST_OBS_END``        mode); observes at its END step and must agree with
                           the admission evidence.
- ``STRICT_OBS``           atomic strict current read (strict mode recheck).
- ``ADMIT``                host admission via the mediated checklist
                           (terminal). EVERY gate is evaluated from the
                           LATCHED read-time observations only; the model has
                           NO admission-time re-derivation and NO
                           admission-side watermark (the current Rust
                           implementation has neither).
- ``BYPASS``               unmediated admission path (exists only when the
                           ``host_mediation`` premise is removed; terminal).

Latched validation (fail-closed, all captured at read time):

- The pending probes (p0/p1, or the strict load's probe) capture whether an
  incomplete mutation is in flight at their read step: commit begun but not
  durable, or durable but publication incomplete (publication completes only
  when BOTH the manifest advance and the evidence body advance have fired).
  If the ``pending_probe`` premise is on, ANY probe observing an in-flight
  mutation latches the run fail-closed: a publication that completes AFTER
  the probes -- even after the last read and before ADMIT -- does NOT
  resurrect a latched unsafe delta.
- The generation/revoke fence is a READ GATE ONLY (the Rust implementation
  has no admission-time watermark): any M/b read whose observed manifest/body
  pair is mismatched (torn) or whose manifest generation is below the current
  published head is rejected fail-closed, and a rejected read poisons
  admission.
- The post-recheck re-read must be valid and agree with the admission
  evidence (latched identity stability); the pre-observation must precede the
  durable commit.

Decision tail: free events (the mutation chain including both publication
sub-events, the rollback, the pre-observation, the bypass) may interleave
ANYWHERE before the terminal event -- INCLUDING between the last read of the
final load and the admission step; the model does NOT suppress or disable
interleavings in that window, and no gate is re-evaluated there. A publication
completing in that window is caught by the LATCHED pending probes, exactly as
in the real protocol: if the source commit was durable before t_f and
publication had not happened, p0/p1 observed pending=true and the admission
is denied even though publication later completed.

Premises (modeled separately; each is independently removable for the omission
experiments):

- ``pending_probe``           the final load probes pending state at read
                              time (p0/p1 inside the m0<p0<m1<p1 bracket, or
                              the strict load's atomic probe); any probe
                              observing an incomplete mutation latches the
                              admission fail-closed. Removing the premise
                              removes the probes from the load.
- ``post_recheck``            cache pre/post bracket: admission requires a
                              valid pre-observation strictly before the durable
                              commit and a post-recheck read that is valid and
                              agrees with the m0-anchored admission evidence.
- ``final_reload``            admission evidence must come from a valid final
                              load (the ordered m0/p0/m1/p1 sequence or the
                              atomic strict load). Removing it removes the
                              pending probes with it (they run inside the
                              load) and the evidence falls back to the
                              earlier pre-observation (or fails closed in
                              strict mode).
- ``exact_identity``          the candidate match requires the evidence
                              revision to equal the candidate revision r0;
                              without it a successor revision r1 satisfies a
                              grant-presence match.
- ``generation_revoke_fence`` read gate ONLY: reads whose observed
                              manifest/body pair is mismatched (torn) or whose
                              generation is below the published head are
                              rejected fail-closed; a rejected read poisons
                              admission.
- ``host_mediation``          all admission goes through the mediated
                              checklist; without it a ``BYPASS`` path exists.

Domain classification of admitted traces (theorem scope; t_f = m0, or the
strict load in strict mode):

- ``strictly_before``        commit durable step < t_f: IN theorem domain.
- ``overlap_unknown``        the commit interval spans t_f (begun at/before
                             t_f, durable after): OUTSIDE the theorem domain;
                             reported UNKNOWN, never counted as a violation.
- ``after_final_observation`` mutation commits strictly after t_f: the
                             irreducible TOCTOU window the theorem premise
                             excludes; not a violation.
- ``not_stale``              no durable commit at admission.

A VIOLATION is an admitted trace that is stale AND ``strictly_before``. The
full contract must find zero violations. Each single-premise omission must
either produce a concrete minimal counterexample for its intended schedule or
be reported ``not independently falsifiable`` within the bounded model; no
violation is ever pre-assumed, and an omission is never forced to have a
counterexample.

Enumeration
-----------
Exhaustive depth-first enumeration of all well-formed interleavings of the
event chains (each chain is a total order; the interleaving space is exactly
the set of merges of the chains, with the evidence body advance scheduled
freely after the durable commit). Deterministic: fixed chain priority
(checklist, pre-observation, mutation, evidence body, bypass), first-minimal
counterexample selection by (event count, lexicographic event tuple). No
external solver, no subprocess, no socket, no filesystem access, no network;
import is side-effect-free.

Status semantics
----------------
PASS requires a complete exploration with zero violations. A concrete
counterexample is decisive: a run with at least one in-domain violation
reports FAIL even when the exploration was otherwise incomplete. UNKNOWN
covers incomplete explorations without counterexamples and undecidable
(overlap) trace domains. BLOCKED is reserved in the shared evidence vocabulary
for a checker that could not run; this in-process tool raises ``BoundError``
(API) or exits with code 2 (CLI) before any report exists and never emits
BLOCKED. The top-level report status describes ONLY the full contract; each
omission entry carries its own independent single-premise status.

Revision note (v2.1.0): v2.0.0 liberated the decision tail but closed the
final-read-to-admission window with a HYPOTHETICAL admission-side watermark
observation that the current Rust implementation does not have, and it kept
an admission-time re-derivation of the pending probe. Both are wrong for the
real protocol: the pending probes run DURING the final load (ordered
m0 < p0 < m1 < p1, or one atomic strict load), capture the in-flight state at
their read steps, and latch fail-closed; t_f is m0; there is no
admission-time watermark. v2.1.0 models exactly that: the watermark and the
ADMIT-time re-derivation are removed, the decision tail stays free, and the
full contract is safe under the faithful observations because a publication
completing after the last read is caught by the latched unsafe pending delta.
All six single-premise omissions now yield concrete counterexamples,
matching the Rust E2 omission experiments.

CLI
---
    python e5_model_check.py [--max-steps N] [--json]

``--max-steps`` is a finite step bound, validated to the closed interval
[2, 64]; a bound below a configuration's required bound (1 + alphabet size)
yields an incomplete exploration reported UNKNOWN, never PASS. Exit codes:
0 = report produced; 2 = invalid arguments.

Python 3.8+ standard library only. Offline unit tests live in
``test_e5_model_check.py`` next to this file.
"""

from __future__ import annotations

import argparse
import json
import sys

__all__ = [
    "MODEL_NAME",
    "MODEL_VERSION",
    "THEOREM_ID",
    "PREMISES",
    "MIN_BOUND",
    "MAX_BOUND",
    "DEFAULT_BOUND",
    "BoundError",
    "validate_bound",
    "normalize_premises",
    "without_premise",
    "cache_observation",
    "build_chains",
    "required_bound",
    "classify_domain",
    "run_model",
    "build_report",
    "main",
]

MODEL_NAME = "e5-bounded-model-check"
MODEL_VERSION = "2.1.0"
THEOREM_ID = "E5"

MIN_BOUND = 2
MAX_BOUND = 64
DEFAULT_BOUND = 28

CANDIDATE_REVISION = "r0"
SUCCESSOR_REVISION = "r1"
GEN_BEFORE = "g0"
GEN_AFTER = "g1"

EV_INIT = "INIT"
EV_COMMIT_BEGIN = "COMMIT_BEGIN"
EV_COMMIT_DURABLE = "COMMIT_DURABLE"
EV_PUBLISH = "PUBLISH"
EV_BODY_ADVANCE = "EVIDENCE_BODY_ADVANCE"
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

# M/b cache reads (fence-gated, evidence-capable).
M_B_READ_EVENTS = (
    EV_PRE_END,
    EV_RELOAD_M0,
    EV_RELOAD_M1,
    EV_STRICT_LOAD,
    EV_POST_END,
    EV_STRICT,
)
# Pending probes (capture the in-flight state at their read step; the strict
# load probes atomically with its M/b read).
PENDING_PROBE_EVENTS = (EV_RELOAD_P0, EV_RELOAD_P1, EV_STRICT_LOAD)
ALL_READ_EVENTS = M_B_READ_EVENTS + PENDING_PROBE_EVENTS

PREMISES = (
    "pending_probe",
    "post_recheck",
    "final_reload",
    "exact_identity",
    "generation_revoke_fence",
    "host_mediation",
)

PREMISE_DESCRIPTIONS = {
    "pending_probe": (
        "the final load probes pending state at read time (p0 after m0 and "
        "p1 after m1 in the ordered m0<p0<m1<p1 bracket, or the strict "
        "load's atomic probe); any probe observing an incomplete mutation "
        "(commit begun but not durable, or durable but publication "
        "incomplete -- publication completes only when BOTH the manifest "
        "advance and the evidence body advance have fired) latches the "
        "admission fail-closed; publication completing after the probes "
        "does not resurrect a latched unsafe delta and there is no "
        "admission-time re-derivation"
    ),
    "post_recheck": (
        "cache pre/post bracket: valid pre-observation strictly before the "
        "durable commit, plus a post-recheck read (post-observation interval "
        "or strict observation) that is valid and agrees with the "
        "m0-anchored admission evidence"
    ),
    "final_reload": (
        "admission evidence must come from a valid final load -- the ordered "
        "m0/p0/m1/p1 observation sequence (bracket) or one atomic strict "
        "load -- anchored at m0, the theorem's t_f; removing it removes the "
        "pending probes with it (they run inside the load)"
    ),
    "exact_identity": (
        "candidate match requires evidence revision == candidate revision r0 "
        "(without it, grant-presence matching admits successor revisions)"
    ),
    "generation_revoke_fence": (
        "read gate ONLY (the Rust implementation has no admission-time "
        "watermark): reads whose observed manifest/body pair is mismatched "
        "(torn) or whose generation is below the published head are "
        "rejected fail-closed; a rejected read poisons admission"
    ),
    "host_mediation": (
        "all admission goes through the mediated checklist (no bypass path)"
    ),
}

OMISSION_INTENDED_SCHEDULE = {
    "pending_probe": (
        "source-pending trace: the probes are gone, so a publication "
        "completing in the free window after the last read is never latched"
    ),
    "post_recheck": (
        "intra-load publication trace: the mutation fully publishes between "
        "m0 and p0, the m0-anchored evidence goes stale, and with no "
        "post-recheck nothing confronts it"
    ),
    "final_reload": (
        "no-final-load trace: without the load there are no pending probes "
        "and no evidence; the pre-observation fallback admits the stale "
        "candidate (matches the Rust e2 final-reload-omission experiment)"
    ),
    "exact_identity": "successor-revision trace",
    "generation_revoke_fence": (
        "pointer-rollback trace: below-head reads are accepted without the "
        "read gate"
    ),
    "host_mediation": "unmediated bypass admission trace",
}

OMISSION_NOTES = {
    "pending_probe": (
        "Without the pending probe the load observes only m0 and m1. A "
        "schedule where the source commit is durable before t_f (m0), the "
        "cache still serves the pre-invalidation pair (g0, r0) through the "
        "last read, and the publication completes in the free window after "
        "the last read and before admission leaves nothing latched: every "
        "remaining gate passes and the stale candidate is admitted. With "
        "the probe on, p0/p1 would have captured pending=true at read time "
        "and latched the admission fail-closed."
    ),
    "post_recheck": (
        "Without the post-recheck, a schedule where the publication fully "
        "completes INSIDE the final load, between m0 and p0, survives: p0 "
        "and p1 then observe pending=false (the publication is complete at "
        "their read steps), the evidence stays anchored at the earlier m0 "
        "(g0, r0), and no later read confronts it. The admission is stale "
        "(the commit was durable before t_f) and every remaining gate "
        "passes. With the recheck on, the post-read disagrees with the "
        "m0-anchored evidence and denies -- this is the latched identity "
        "stability the real protocol enforces between observations."
    ),
    "final_reload": (
        "Without the final load there are no pending probes (they run "
        "inside the load) and no m0-anchored evidence: the admission "
        "evidence falls back to the earlier pre-observation. A durable "
        "commit before that observation with the publication still "
        "incomplete at admission is admitted stale -- matching the Rust "
        "e2 final-reload-omission experiment, where omitting the final "
        "reload accepts the removed candidate while the full contract "
        "reloads."
    ),
    "exact_identity": (
        "Without exact identity, a fully published successor revision "
        "(r1/g1) satisfies a grant-presence match for candidate r0; the "
        "probes observe pending=false (the publication is complete at "
        "their read steps), the recheck agrees, and the read gate passes. "
        "With identity off a rollback AFTER the last read also violates "
        "(the evidence was already read at g1, so no read re-observes the "
        "rolled-back cache). The full contract rejects both: exact "
        "identity denies the successor revision."
    ),
    "generation_revoke_fence": (
        "Without the read gate, a pointer rollback to (g0, r0) after a "
        "complete publication is served to the final load below the "
        "published head and accepted: the evidence is the stale r0 body, "
        "the probes observe pending=false (the publication completed at "
        "their read steps), and every remaining gate passes. Torn "
        "manifest/body reads are also enumerated without the fence; in the "
        "theorem domain they are still denied (a torn pair implies an "
        "incomplete publication, which the probes latch, or a disagreement "
        "at the recheck), and the only admitted torn-read traces lie in the "
        "after-t_f TOCTOU domain (the mutation begins after m0, publishes, "
        "and a rollback restores the old cache so the recheck agrees again) "
        "-- outside the theorem, never violations. The reported "
        "counterexample is the minimal one."
    ),
    "host_mediation": (
        "Without host mediation a bypass admission path exists that skips "
        "the entire mediated checklist; any schedule reaching it after a "
        "durable commit admits the stale candidate without any gate."
    ),
}

SCOPE_LIMITATIONS = (
    "Abstract discrete-event model of ONE candidate grant and ONE "
    "revocation-class mutation with a single successor revision; not a "
    "mechanized proof of any Rust/Java implementation, deployment, or "
    "runtime behavior.",
    "The full contract fixes the admission checklist order (final load "
    "m0<p0<m1<p1 -> candidate match -> post-recheck -> admission; strict "
    "mode: atomic strict load -> match -> strict recheck -> admission). "
    "Free events -- including both publication sub-events and the rollback "
    "-- DO interleave between the last read and the admission step; the "
    "model does not suppress them, and NO gate is re-evaluated at the "
    "admission step: every gate is latched from read-time observations.",
    "There is NO admission-side watermark and NO admission-time pending "
    "re-derivation in this model: the current Rust implementation has "
    "neither. The final-read-to-admission window is closed by the latched "
    "read-time pending probes (and the post-recheck/fence/identity gates), "
    "not by any admission-time check.",
    "The theorem's final observation t_f is m0 -- the first authoritative "
    "observation that supplies the successful final evidence (strict mode: "
    "the atomic strict load) -- matching experiment_common.py's "
    "final_observation_interval.",
    "The final load's observation bracket is ordered m0 < p0 < m1 < p1 "
    "(bracket mode) with pending captured at p0/p1 read steps; the "
    "evidence is anchored at m0. The within-load cache fence-snapshot "
    "bracket (F0==F1) and the cache-miss fallback to the authoritative "
    "reader are abstracted: a mid-load manifest move is caught by the "
    "latched pending probes (incomplete publication) or the post-recheck "
    "agreement (completed publication), not by a modeled F0==F1 equality.",
    "The pending probes capture 'an incomplete mutation is in flight': "
    "commit begun but not durable, or durable but publication incomplete "
    "(publication completes only when BOTH the manifest advance and the "
    "evidence body advance have fired). Treating begun-but-not-durable as "
    "pending is conservative (deny-more) relative to a gate that only "
    "tracks durable-but-unpublished deltas.",
    "Publication is modeled as two independently scheduled sub-events after "
    "the durable commit: PUBLISH (manifest/version advance, which also "
    "advances the durable published head) and EVIDENCE_BODY_ADVANCE "
    "(evidence body advance). Consistent publication requires both; the torn "
    "states (g1, r0) and (g0, r1) exist between and around them.",
    "The mutation chain is a fixed total order (commit begin -> commit "
    "durable -> manifest advance -> rollback) with the evidence body advance "
    "scheduled freely after the durable commit; at most one rollback, only "
    "after the manifest advance.",
    "Steps are dense (every step fires one event); only relative order affects "
    "outcomes, and absolute timing/idle gaps are not modeled.",
    "Overlapping commit/final-observation intervals (the commit spans t_f: "
    "begun at/before m0, durable after) are classified UNKNOWN (outside the "
    "theorem domain) and are never counted as violations.",
    "Traces where the mutation commits strictly after t_f are outside the "
    "theorem premise (irreducible TOCTOU window) and are not violations.",
    "Each omission experiment removes exactly one premise; combined omissions "
    "are out of scope.",
    "Omission experiments run in bracket (pre-observation plus post-recheck "
    "cache observation pairs) mode; the full contract is checked in both "
    "bracket and strict observation modes.",
    "Omission entry statuses are independent single-premise results: an "
    "omission FAIL demonstrates the removed control is load-bearing within "
    "this model (and, for each control, a matching Rust E2 omission "
    "experiment exists); an omission PASS means not-independently-"
    "falsifiable within this model (the remaining controls close every "
    "enumerated schedule) and is NOT a claim that the control is useless in "
    "the real protocol.",
    "The top-level report status and fullContract.status describe ONLY the "
    "full contract (all modeled premises enabled); they are never an "
    "aggregate over the omission results.",
    "Status precedence: a concrete counterexample is decisive -- a run with "
    "at least one in-domain violation reports FAIL even when the exploration "
    "was otherwise incomplete (bound truncation); PASS requires a complete "
    "exploration with zero violations; UNKNOWN covers incomplete explorations "
    "without counterexamples and undecidable (overlap) trace domains. "
    "BLOCKED is reserved in the shared vocabulary for a checker that could "
    "not run; this in-process tool raises BoundError or exits with code 2 "
    "before any report exists and never emits BLOCKED.",
    "The rollback adversary performs at most one pointer rollback and only "
    "after the manifest advance.",
    "Cache reads observe the cache state at the read's completion step; the "
    "strict-observation mode models an atomic re-check and omits the separate "
    "pre-observation requirement of the bracket mode.",
    "Enumeration is a deterministic exhaustive merge of the event chains "
    "with fixed chain priority (checklist, pre-observation, mutation, "
    "evidence body, bypass); the first reported counterexample is minimal by "
    "(event count, lexicographic event tuple).",
    "A bound below a configuration's required bound (1 + alphabet size) yields "
    "an incomplete exploration reported UNKNOWN, never PASS.",
    "Full-contract PASS is an abstract bounded property only; it is not "
    "evidence about the production implementation by itself.",
)

STATUS_VOCABULARY = {
    "PASS": (
        "the property held in every explored trace of the bounded abstract "
        "model and the exploration was complete"
    ),
    "FAIL": (
        "at least one in-domain counterexample trace exists in the bounded "
        "abstract model; decisive even when the exploration was otherwise "
        "incomplete"
    ),
    "BLOCKED": (
        "reserved in the shared evidence vocabulary for a checker that could "
        "not run (e.g., invalid configuration); this in-process tool raises "
        "BoundError or exits with code 2 before any report exists, so no "
        "report produced by this tool ever carries BLOCKED"
    ),
    "UNKNOWN": (
        "the exploration was incomplete (bound below the configuration's "
        "required bound) without a counterexample, or the trace domain is "
        "undecidable (overlapping commit/final-observation intervals)"
    ),
}

STATUS_SCOPE = (
    "The top-level status and fullContract.status describe ONLY the full "
    "contract (all modeled premises enabled). Each omissions[] entry carries "
    "its own independent single-premise status: an omission FAIL is an "
    "expected, informative result (the removed control is load-bearing "
    "within this model, with a matching Rust E2 omission experiment) and "
    "never changes the top-level status; an omission PASS means "
    "not-independently-falsifiable within this model, not that the control "
    "is useless in the real protocol."
)


class BoundError(ValueError):
    """Raised when a step bound is not a valid finite integer in range."""


def validate_bound(value):
    """Validate a finite step bound; return it as an int or raise BoundError."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BoundError(
            "max-steps must be an integer, got %r" % (value,)
        )
    if value < MIN_BOUND or value > MAX_BOUND:
        raise BoundError(
            "max-steps must be a finite bound in [%d, %d], got %d"
            % (MIN_BOUND, MAX_BOUND, value)
        )
    return value


def normalize_premises(premises=None, removed=None):
    """Return a full premise dict; optionally toggle or remove one premise."""
    base = {name: True for name in PREMISES}
    if premises:
        for key, val in premises.items():
            if key not in base:
                raise ValueError("unknown premise: %r" % (key,))
            base[key] = bool(val)
    if removed is not None:
        if removed not in base:
            raise ValueError("unknown premise: %r" % (removed,))
        base[removed] = False
    return base


def without_premise(premise):
    """Premise set for a single-omission experiment (all on, one off)."""
    return normalize_premises(removed=premise)


def cache_observation(step, publish_step, body_step, rollback_step, fence_on):
    """Pure observation of the read-path cache (M, b) at ``step``.

    The cache is a pair: manifest/version generation M and evidence body
    revision b, which advance independently.

    - ``publish_step``: step of PUBLISH (manifest/version advance; also
      advances the durable published head), or None if it has not fired.
    - ``body_step``: step of EVIDENCE_BODY_ADVANCE (evidence body advance),
      or None.
    - ``rollback_step``: step of ROLLBACK (adversarial read-path reset), or
      None. The reset clears the manifest advance and the body advance as of
      that step; a body advance AFTER the rollback re-advances the body.
    - ``fence_on``: whether the generation/revoke fence read gate applies.

    A step is ``None`` or greater than ``step`` when the event has not fired
    at/before ``step``. Returns a dict with:

    - ``manifest``, ``body``, ``head``: observed pair and durable published
      head generation;
    - ``consistent``: whether the manifest/body pair corresponds
      ((g0, r0) or (g1, r1)); torn pairs are the mixed M/b states;
    - ``valid``, ``reason``: read-gate verdict under the fence premise
      (torn pairs and below-head generations are rejected fail-closed). With
      the fence off every observation is ``valid`` and a torn pair is carried
      raw (mismatched gen/rev) for the downstream controls to confront.
    """
    published = publish_step is not None and publish_step <= step
    advanced = body_step is not None and body_step <= step
    rolled = rollback_step is not None and rollback_step <= step
    head = GEN_AFTER if published else GEN_BEFORE
    manifest = GEN_AFTER if (published and not rolled) else GEN_BEFORE
    body_advanced = advanced and (rollback_step is None or body_step > rollback_step)
    body = SUCCESSOR_REVISION if body_advanced else CANDIDATE_REVISION
    manifest_is_after = manifest == GEN_AFTER
    body_is_after = body == SUCCESSOR_REVISION
    consistent = manifest_is_after == body_is_after
    valid = True
    reason = None
    if fence_on:
        if not consistent:
            valid = False
            reason = (
                "manifest_ahead_body_stale"
                if manifest_is_after
                else "body_ahead_manifest_stale"
            )
        elif not manifest_is_after and head == GEN_AFTER:
            valid = False
            reason = "generation_below_published_head"
    return {
        "manifest": manifest,
        "body": body,
        "head": head,
        "consistent": consistent,
        "valid": valid,
        "reason": reason,
    }


def build_chains(premises, mode="bracket"):
    """Build the event chains whose merges are the well-formed schedules.

    Returns a dict with the checklist chain (fixed order, ending in ADMIT),
    the pre-observation chain (bracket mode only, must complete before MATCH),
    the mutation chain, the evidence-body chain (single event, schedulable
    freely after the durable commit), the bypass chain, and the recheck event
    list. The final load is the ordered sequence m0 < p0 < m1 < p1 (bracket)
    or one atomic strict load (strict); the pending probes are part of the
    load and disappear with the ``pending_probe`` or ``final_reload``
    premises.
    """
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
    mutation = [EV_COMMIT_BEGIN, EV_COMMIT_DURABLE, EV_PUBLISH, EV_ROLLBACK]
    body = [EV_BODY_ADVANCE]
    bypass = [] if prem["host_mediation"] else [EV_BYPASS]
    return {
        "checklist": checklist,
        "pre": pre,
        "mutation": mutation,
        "body": body,
        "bypass": bypass,
        "recheck": recheck,
    }


def required_bound(premises=None, mode="bracket"):
    """Minimum step bound for a complete exploration of this configuration."""
    chains = build_chains(premises, mode)
    total_events = (
        len(chains["checklist"])
        + len(chains["pre"])
        + len(chains["mutation"])
        + len(chains["body"])
        + len(chains["bypass"])
    )
    # INIT occupies step 0; each event one further step.
    return 1 + total_events


def classify_domain(commit_interval, final_observation_interval):
    """Classify the theorem domain of an admitted trace (pure function).

    ``commit_interval`` is (begin, durable) or None when no commit is durable.
    ``final_observation_interval`` is (begin, end) or None when no read exists;
    the model anchors it at the single step t_f = m0 (strict: the atomic
    strict load), so a commit that spans t_f classifies as ``overlap_unknown``.

    Returns one of: ``not_stale`` (no durable commit at admission),
    ``unknown_domain`` (no final observation to order against),
    ``strictly_before`` (in theorem domain), ``overlap_unknown`` (intervals
    intersect; outside theorem domain), ``after_final_observation``.
    """
    if commit_interval is None:
        return "not_stale"
    if final_observation_interval is None:
        return "unknown_domain"
    commit_begin, commit_durable = commit_interval
    obs_begin, obs_end = final_observation_interval
    if commit_durable < obs_begin:
        return "strictly_before"
    if obs_begin <= commit_durable and commit_begin <= obs_end:
        return "overlap_unknown"
    return "after_final_observation"


def run_model(premises=None, mode="bracket", bound=DEFAULT_BOUND):
    """Exhaustively enumerate the configuration; return a run summary dict.

    The enumeration is a depth-first merge of the event chains with fixed
    deterministic ordering. Free events (mutation chain, evidence body
    advance, pre-observation, bypass) may interleave anywhere, including
    between the last read of the final load and ADMIT; the admission step
    evaluates ONLY the latched read-time observations (pending probes,
    fence-gated reads, recheck agreement, identity match) and re-derives
    nothing. Terminal traces are ADMIT (mediated, gated), DENIED (a latched
    gate failed), BYPASS_ADMITTED (unmediated), or incomplete prefixes when
    the bound is below the configuration's required bound.
    """
    prem = normalize_premises(premises)
    bound = validate_bound(bound)
    chains = build_chains(prem, mode)
    checklist = chains["checklist"]
    pre_chain = chains["pre"]
    mutation = chains["mutation"]
    body_chain = chains["body"]
    bypass_chain = chains["bypass"]
    recheck_events = chains["recheck"]
    recheck_read_event = recheck_events[-1] if recheck_events else None
    checklist_set = frozenset(checklist)
    mutation_set = frozenset(mutation)
    body_set = frozenset(body_chain)
    pre_set = frozenset(pre_chain)

    fence_on = prem["generation_revoke_fence"]
    exact_on = prem["exact_identity"]
    probe_on = prem["pending_probe"]
    recheck_on = prem["post_recheck"]
    reload_on = prem["final_reload"]
    bracket_mode = mode == "bracket"
    # The latched pending probes this configuration owns: p0/p1 inside the
    # bracket load, or the strict load's atomic probe. They exist only when
    # both the probe premise and the load itself are present.
    if bracket_mode:
        configured_probes = []
        if reload_on and probe_on:
            configured_probes = [EV_RELOAD_P0, EV_RELOAD_P1]
    else:
        configured_probes = [EV_STRICT_LOAD] if (reload_on and probe_on) else []
    # The theorem's t_f anchor: the first authoritative observation that
    # supplies the successful final evidence (m0, or the strict load).
    if bracket_mode:
        tf_event = EV_RELOAD_M0
    else:
        tf_event = EV_STRICT_LOAD

    counts = {
        "exploredStates": 0,
        "exploredTraces": 0,
        "incompleteTraces": 0,
        "admittedTraces": 0,
        "deniedTraces": 0,
        "bypassAdmittedTraces": 0,
        "admittedNotStale": 0,
        "admittedStrictlyBefore": 0,
        "admittedOverlapUnknown": 0,
        "admittedAfterFinalObservation": 0,
        "admittedUnknownDomain": 0,
        "violations": 0,
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
    torn_kind_counts = {"manifest_ahead_body_stale": 0, "body_ahead_manifest_stale": 0}
    admitted_torn_by_domain = {}
    violation_classes = {}
    best_violation = [None, None, None]  # [event_count, names_tuple, detail_dict]

    def compute_read(event, step, publish_pos, body_pos, rollback_pos):
        """M/b cache read at ``step``: value + fence read-gate verdict."""
        obs = cache_observation(step, publish_pos, body_pos, rollback_pos, fence_on)
        return {
            "gen": obs["manifest"],
            "rev": obs["body"],
            "head": obs["head"],
            "valid": obs["valid"],
            "consistent": obs["consistent"],
            "reason": obs["reason"],
            "step": step,
        }

    def final_observation_interval(pos):
        # t_f is m0 (strict: the atomic strict load) -- a single step.
        if reload_on and tf_event in pos:
            return (pos[tf_event], pos[tf_event])
        if recheck_on and recheck_read_event in pos:
            if recheck_read_event == EV_STRICT:
                step = pos[EV_STRICT]
                return (step, step)
            if EV_POST_BEGIN in pos and EV_POST_END in pos:
                return (pos[EV_POST_BEGIN], pos[EV_POST_END])
        if EV_PRE_BEGIN in pos and EV_PRE_END in pos:
            return (pos[EV_PRE_BEGIN], pos[EV_PRE_END])
        return None

    def evidence_read(reads):
        """The admission evidence under the current premise set (or None)."""
        if reload_on:
            rd = reads.get(tf_event)
            if rd is None or not rd["valid"]:
                return None
            return rd
        if bracket_mode:
            rd = reads.get(EV_PRE_END)
            if rd is None or not rd["valid"]:
                return None
            return rd
        return None  # strict mode without final load: fail closed

    def evaluate_admission(pending_obs, reads, evidence, match_ok,
                           commit_durable_step):
        """Evaluate every gate from the LATCHED read-time observations only.

        There is no admission-time re-derivation and no admission-side
        watermark: the pending probes latched their verdicts at their read
        steps, the fence latched its read rejections, and the recheck latched
        its agreement. A publication completing after the last read cannot
        change any of them.
        """
        reasons = []
        if not match_ok:
            reasons.append("candidate_match_failed")
        if probe_on:
            for name in configured_probes:
                obs = pending_obs.get(name)
                if obs is None:
                    reasons.append("pending_probe_observation_missing:" + name)
                elif obs["pending"]:
                    reasons.append("pending_probe_latched_unsafe_delta:" + name)
        if recheck_on:
            rd = reads.get(recheck_read_event)
            if rd is None or not rd["valid"]:
                reasons.append("post_recheck_read_missing_or_rejected")
            elif evidence is None or (
                (rd["gen"], rd["rev"]) != (evidence["gen"], evidence["rev"])
            ):
                reasons.append("post_recheck_disagrees_with_evidence")
            if bracket_mode:
                prd = reads.get(EV_PRE_END)
                if prd is None or not prd["valid"]:
                    reasons.append("pre_observation_missing_or_rejected")
                elif (
                    commit_durable_step is not None
                    and prd["step"] >= commit_durable_step
                ):
                    reasons.append("pre_observation_does_not_precede_commit")
        if reload_on:
            m0 = reads.get(EV_RELOAD_M0) if bracket_mode else reads.get(EV_STRICT_LOAD)
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
        if EV_PUBLISH not in pos:
            return "source_pending_commit_without_publication"
        admit_step = pos[EV_ADMIT]
        publish_pos = pos[EV_PUBLISH]
        body_pos = pos.get(EV_BODY_ADVANCE)
        if publish_pos < admit_step and (
            publish_pos > last_read_step
            or (body_pos is not None and body_pos > last_read_step)
        ):
            return "mutation_published_after_last_read_before_admission"
        evidence_step = evidence["step"] if evidence is not None else None
        if evidence_step is not None and publish_pos > evidence_step:
            return "mutation_published_between_evidence_read_and_last_read"
        if evidence is not None and evidence["rev"] == SUCCESSOR_REVISION:
            return "successor_revision_identity_confusion"
        return "unclassified"

    def record_terminal(seq, pos, reads, pending_obs, evidence, outcome, reason,
                        last_read_step):
        counts["exploredTraces"] += 1
        # Mixed M/b diagnostics: any M/b read that observed a torn pair. The
        # kind is derived from the observed pair itself (the manifest
        # generation), so it is well-defined with the fence on or off.
        torn_kinds = set()
        for rd in reads.values():
            if not rd["consistent"]:
                torn_kinds.add(
                    "manifest_ahead_body_stale"
                    if rd["gen"] == GEN_AFTER
                    else "body_ahead_manifest_stale"
                )
        if torn_kinds:
            counts["tornReadTraces"] += 1
            for kind in torn_kinds:
                torn_kind_counts[kind] = torn_kind_counts.get(kind, 0) + 1
        # Final-read-to-admission window diagnostics (mediated ADMIT
        # terminals, admitted OR denied): did a publication sub-event (or
        # the rollback) fire strictly after the last read and strictly
        # before ADMIT? Counting denied traces here is the point: it proves
        # the window interleavings are enumerated and then caught.
        if outcome != "BYPASS_ADMITTED" and reads:
            admit_step = pos[EV_ADMIT]
            publish_pos = pos.get(EV_PUBLISH)
            body_pos = pos.get(EV_BODY_ADVANCE)
            rollback_pos = pos.get(EV_ROLLBACK)
            publish_in_window = publish_pos is not None and (
                last_read_step < publish_pos < admit_step
            )
            body_in_window = body_pos is not None and (
                last_read_step < body_pos < admit_step
            )
            rollback_in_window = rollback_pos is not None and (
                last_read_step < rollback_pos < admit_step
            )
            if publish_in_window or body_in_window:
                counts["publishAfterLastReadBeforeAdmissionTraces"] += 1
                if outcome == "ADMITTED":
                    counts["admittedPublishAfterLastRead"] += 1
            if rollback_in_window:
                counts["rollbackAfterLastReadBeforeAdmissionTraces"] += 1
            # Theorem-anchored window (t_f = m0, or the strict load): a
            # publication sub-event firing after t_f and before ADMIT leaves
            # the final evidence unrefreshed; the latched probes are what
            # deny it.
            if reload_on and tf_event in pos:
                tf_step = pos[tf_event]
                publish_after_tf = publish_pos is not None and (
                    tf_step < publish_pos < admit_step
                )
                body_after_tf = body_pos is not None and (
                    tf_step < body_pos < admit_step
                )
                if publish_after_tf or body_after_tf:
                    counts[
                        "publishAfterFinalObservationBeforeAdmissionTraces"
                    ] += 1
                    if outcome == "ADMITTED":
                        counts["admittedPublishAfterFinalObservation"] += 1
                # The coordinator's key scenario, machine-checked: the source
                # commit was durable BEFORE t_f and the publication completes
                # after the last read and before ADMIT. The read-time probes
                # observed the in-flight mutation and latched the admission
                # fail-closed -- no publication-side event can resurrect it.
                if EV_COMMIT_DURABLE in pos and pos[EV_COMMIT_DURABLE] < tf_step:
                    if publish_in_window or body_in_window:
                        counts["staleCommitPublishAfterLastReadTraces"] += 1
                        if outcome == "ADMITTED":
                            counts["admittedStaleCommitPublishAfterLastRead"] += 1
        if outcome == "DENIED":
            counts["deniedTraces"] += 1
            # Per-gate denial evidence: proves WHICH latched gate caught
            # each denied schedule.
            for reason_name in reason.split(";"):
                denial_reasons[reason_name] = denial_reasons.get(reason_name, 0) + 1
            return
        counts["admittedTraces"] += 1
        stale = EV_COMMIT_DURABLE in pos
        if stale:
            commit_interval = (pos[EV_COMMIT_BEGIN], pos[EV_COMMIT_DURABLE])
            domain = classify_domain(commit_interval, final_observation_interval(pos))
        else:
            domain = "not_stale"
        if torn_kinds:
            counts["admittedTornReadTraces"] += 1
            admitted_torn_by_domain[domain] = (
                admitted_torn_by_domain.get(domain, 0) + 1
            )
        if outcome == "BYPASS_ADMITTED":
            counts["bypassAdmittedTraces"] += 1
            # fall through: bypass traces still enter the stale/domain
            # classification and can be violations
        if not stale:
            counts["admittedNotStale"] += 1
            return
        if domain == "strictly_before":
            counts["admittedStrictlyBefore"] += 1
        elif domain == "overlap_unknown":
            counts["admittedOverlapUnknown"] += 1
        elif domain == "after_final_observation":
            counts["admittedAfterFinalObservation"] += 1
        else:
            counts["admittedUnknownDomain"] += 1
        if domain != "strictly_before":
            return  # overlap/unknown-domain traces are NEVER violations
        counts["violations"] += 1
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
                "domain": domain,
                "staleAtAdmission": True,
                "eventCount": len(names),
                "stepCount": len(names),
                "reads": {
                    name: {
                        "step": rd["step"],
                        "gen": rd["gen"],
                        "rev": rd["rev"],
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

    def dfs(ia, ib, ic, idy, ie, seq, reads, pending_obs, evidence, match_ok,
            publish_pos, body_pos, rollback_pos):
        counts["exploredStates"] += 1
        a_next = checklist[ia] if ia < len(checklist) else None
        enabled = []
        if a_next is not None and not (
            a_next == EV_MATCH and ib < len(pre_chain)
        ):
            # Free events remain enabled even when ADMIT is next: the
            # final-read-to-admission window is NOT suppressed, and ADMIT
            # re-derives nothing.
            enabled.append(a_next)
        if ib < len(pre_chain):
            enabled.append(pre_chain[ib])
        if ic < len(mutation):
            enabled.append(mutation[ic])
        if idy < len(body_chain) and ic >= 2:  # body advance needs the durable commit
            enabled.append(EV_BODY_ADVANCE)
        if bypass_chain and ie == 0:
            enabled.append(EV_BYPASS)
        if len(seq) >= bound:  # next event would exceed the step bound
            counts["incompleteTraces"] += 1
            counts["exploredTraces"] += 1
            return
        step = len(seq)
        for event in enabled:  # fixed deterministic priority order
            n_ia, n_ib, n_ic, n_idy, n_ie = ia, ib, ic, idy, ie
            n_publish, n_body, n_rollback = publish_pos, body_pos, rollback_pos
            n_pos = None
            n_reads = reads
            n_pending = pending_obs
            n_evidence = evidence
            n_match = match_ok
            terminal = False
            outcome = None
            reason = None
            if event in M_B_READ_EVENTS:
                n_reads = dict(reads)
                rd = compute_read(event, step, publish_pos, body_pos, rollback_pos)
                n_reads[event] = rd
                if event == tf_event and reload_on:
                    n_evidence = rd if rd["valid"] else None
            elif event == EV_MATCH:
                if not reload_on:
                    n_evidence = evidence_read(reads)
                n_match = n_evidence is not None and (
                    n_evidence["rev"] == CANDIDATE_REVISION if exact_on else True
                )
            elif event == EV_ADMIT:
                pos = {name: index for index, name in enumerate(seq)}
                pos[event] = step
                outcome, reason = evaluate_admission(
                    pending_obs, reads, evidence, match_ok,
                    pos.get(EV_COMMIT_DURABLE),
                )
                terminal = True
                n_pos = pos
            elif event == EV_BYPASS:
                pos = {name: index for index, name in enumerate(seq)}
                pos[event] = step
                outcome = "BYPASS_ADMITTED"
                terminal = True
                n_pos = pos
            if event in PENDING_PROBE_EVENTS:
                # Pending probe: capture the in-flight state AT THIS READ
                # STEP from the current chain cursors (every fired event is
                # at a step before this one). The strict load probes
                # atomically with its M/b read; the latch consults the
                # observation only when the probe premise is on.
                mutation_begun = ic >= 1
                publication_complete = ic >= 3 and idy >= 1
                n_pending = dict(pending_obs)
                n_pending[event] = {
                    "step": step,
                    "pending": mutation_begun and not publication_complete,
                }
            if event in checklist_set:
                n_ia += 1
            elif event in mutation_set:
                n_ic += 1
                if event == EV_PUBLISH:
                    n_publish = step
                elif event == EV_ROLLBACK:
                    n_rollback = step
            elif event in body_set:
                n_idy += 1
                n_body = step
            elif event in pre_set:
                n_ib += 1
            else:  # bypass chain
                n_ie += 1
            n_seq = seq + (event,)
            if terminal:
                last_read_step = max(
                    (
                        [rd["step"] for rd in n_reads.values()]
                        + [obs["step"] for obs in n_pending.values()]
                    ),
                    default=-1,
                )
                record_terminal(
                    n_seq, n_pos, n_reads, n_pending, n_evidence, outcome,
                    reason, last_read_step,
                )
            else:
                dfs(
                    n_ia,
                    n_ib,
                    n_ic,
                    n_idy,
                    n_ie,
                    n_seq,
                    n_reads,
                    n_pending,
                    n_evidence,
                    n_match,
                    n_publish,
                    n_body,
                    n_rollback,
                )

    dfs(
        0,
        0,
        0,
        0,
        0,
        (EV_INIT,),
        {},
        {},
        None,
        None,
        None,
        None,
        None,
    )

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
            "overlapUnknown": counts["admittedOverlapUnknown"],
            "afterFinalObservation": counts["admittedAfterFinalObservation"],
            "unknownDomain": counts["admittedUnknownDomain"],
        },
        "violations": counts["violations"],
        "violationsByDomain": {
            "strictlyBefore": counts["admittedStrictlyBefore"],
            "overlapUnknown": 0,
            "afterFinalObservation": 0,
            "unknownDomain": 0,
            "notStale": 0,
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
            "admittedPublishAfterLastRead": counts["admittedPublishAfterLastRead"],
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


_REPORT_CACHE = {}


def build_report(bound=DEFAULT_BOUND, use_cache=True):
    """Build the full E5 report: full contract (both modes) + omission runs.

    The full contract must show zero in-domain violations in both observation
    modes. Each single-premise omission is then enumerated in bracket mode;
    a found counterexample is reported FAIL (the removal falsifies the
    property within this model), a complete run without violations is
    reported not-independently-falsifiable, and an incomplete exploration is
    UNKNOWN. Omission statuses are independent single-premise results and do
    not change the top-level status, which describes only the full contract.
    """
    bound = validate_bound(bound)
    if use_cache and bound in _REPORT_CACHE:
        return json.loads(json.dumps(_REPORT_CACHE[bound]))
    full_premises = normalize_premises()
    mode_runs = {}
    for mode in ("bracket", "strict"):
        mode_runs[mode] = run_model(full_premises, mode, bound)
    statuses = [run["status"] for run in mode_runs.values()]
    if "FAIL" in statuses:
        full_contract_status = "FAIL"
    elif "UNKNOWN" in statuses:
        full_contract_status = "UNKNOWN"
    else:
        full_contract_status = "PASS"

    omissions = []
    for premise in PREMISES:
        run = run_model(without_premise(premise), "bracket", bound)
        if run["violations"]:
            o_status = "FAIL"
            finding = "counterexample_found"
            counterexample = run["counterexample"]
        elif run["explorationComplete"]:
            o_status = "PASS"
            finding = "not_independently_falsifiable"
            counterexample = None
        else:
            o_status = "UNKNOWN"
            finding = "not_determined_incomplete_exploration"
            counterexample = None
        omissions.append(
            {
                "premise": premise,
                "premiseRemoved": premise,
                "status": o_status,
                "finding": finding,
                "intendedSchedule": OMISSION_INTENDED_SCHEDULE[premise],
                "counterexample": counterexample,
                "note": OMISSION_NOTES[premise],
                "run": run,
            }
        )

    report = {
        "model": MODEL_NAME,
        "modelVersion": MODEL_VERSION,
        "theorem": THEOREM_ID,
        "method": (
            "exhaustive depth-first enumeration of a finite explicit state "
            "model; no external solver, no subprocess, no network"
        ),
        "bound": bound,
        "boundValidation": {"min": MIN_BOUND, "max": MAX_BOUND, "valid": True},
        "exploredStates": sum(
            run["exploredStates"] for run in mode_runs.values()
        ) + sum(entry["run"]["exploredStates"] for entry in omissions),
        "exploredTraces": sum(
            run["exploredTraces"] for run in mode_runs.values()
        ) + sum(entry["run"]["exploredTraces"] for entry in omissions),
        "fullContract": {
            "status": full_contract_status,
            "meaning": (
                "abstract bounded property only, conditional on every "
                "structural assumption in scopeLimitations (fixed checklist "
                "order; pending probes latched at read time inside the final "
                "load m0<p0<m1<p1 or the atomic strict load; t_f = m0; one "
                "mutation, one rollback, one successor revision; two "
                "sub-event publication; dense steps; NO admission-time "
                "re-derivation and NO admission-side watermark, matching "
                "the current Rust implementation): zero traces in this "
                "model where a mutation committed strictly before t_f AND "
                "a stale candidate reached host admission. The window "
                "between the last read and admission is FREE: a publication "
                "completing there is caught by the latched unsafe pending "
                "delta, not by any admission-time check. Out-of-domain "
                "(overlap/after) admissions are reported separately in "
                "admittedDomainCounts and are outside the theorem. This "
                "implies nothing beyond this model and is not evidence "
                "about the production implementation."
            ),
            "modes": mode_runs,
        },
        "omissions": omissions,
        "status": full_contract_status,
        "statusScope": STATUS_SCOPE,
        "statusVocabulary": STATUS_VOCABULARY,
        "premiseDescriptions": dict(PREMISE_DESCRIPTIONS),
        "scopeLimitations": list(SCOPE_LIMITATIONS),
    }
    if use_cache:
        _REPORT_CACHE[bound] = json.loads(json.dumps(report))
    return report


def _format_text_report(report):
    """Render a compact human-readable summary of the report."""
    lines = []
    lines.append(
        "%s v%s (theorem %s) -- abstract bounded-model evidence ONLY"
        % (report["model"], report["modelVersion"], report["theorem"])
    )
    lines.append(
        "bound=%d exploredStates=%d exploredTraces=%d"
        % (report["bound"], report["exploredStates"], report["exploredTraces"])
    )
    lines.append("")
    lines.append("Full contract (all six premises on):")
    for mode, run in sorted(report["fullContract"]["modes"].items()):
        window = run["admissionWindow"]
        mixed = run["mixedManifestBody"]
        lines.append(
            "  [%s] status=%s violations=%d admitted=%d denied=%d "
            "overlapAdmitted=%d complete=%s requiredBound=%d"
            % (
                mode,
                run["status"],
                run["violations"],
                run["admittedTraces"],
                run["deniedTraces"],
                run["admittedDomainCounts"]["overlapUnknown"],
                run["explorationComplete"],
                run["requiredBound"],
            )
        )
        lines.append(
            "      window: publish-after-last-read traces=%d admitted=%d "
            "publish-after-t_f traces=%d admitted=%d; torn M/b reads: "
            "traces=%d admitted=%d"
            % (
                window["publishAfterLastReadBeforeAdmissionTraces"],
                window["admittedPublishAfterLastRead"],
                window["publishAfterFinalObservationBeforeAdmissionTraces"],
                window["admittedPublishAfterFinalObservation"],
                mixed["tornReadTraces"],
                mixed["admittedTornReadTraces"],
            )
        )
        lines.append(
            "      latched denials: %s"
            % json.dumps(run["denialReasons"], sort_keys=True)
        )
    lines.append("  => fullContract status: %s" % report["fullContract"]["status"])
    lines.append("")
    lines.append("Single-premise omission experiments (bracket mode):")
    for entry in report["omissions"]:
        lines.append(
            "  without %-24s status=%s finding=%s" % (
                entry["premise"], entry["status"], entry["finding"]
            )
        )
        cex = entry["counterexample"]
        if cex is not None:
            lines.append(
                "    counterexample: class=%s events=%d trace=%s"
                % (
                    cex["scheduleClass"],
                    cex["eventCount"],
                    " -> ".join(item["event"] for item in cex["trace"]),
                )
            )
    lines.append("")
    lines.append("Overall status: %s" % report["status"])
    lines.append("Status scope: top-level status reflects the full contract only;")
    lines.append("omission statuses are independent single-premise results.")
    lines.append("")
    lines.append("Scope limitations:")
    for item in report["scopeLimitations"]:
        lines.append("  - %s" % item)
    return "\n".join(lines)


def main(argv=None):
    """CLI entry point. Returns a process exit code (0 ok, 2 bad args)."""
    parser = argparse.ArgumentParser(
        prog="e5_model_check",
        description=(
            "E5 bounded model checker: abstract bounded-model evidence for "
            "the candidate-grant revocation observation protocol. Offline, "
            "standard library only, no solver."
        ),
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=DEFAULT_BOUND,
        help="finite step bound, validated to [%d, %d] (default %d)"
        % (MIN_BOUND, MAX_BOUND, DEFAULT_BOUND),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full report as JSON instead of a text summary",
    )
    args = parser.parse_args(argv)
    try:
        bound = validate_bound(args.max_steps)
    except BoundError as exc:
        parser.error(str(exc))  # exits with code 2
    report = build_report(bound)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(_format_text_report(report))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via CLI smoke runs
    sys.exit(main())
