#!/usr/bin/env python3
"""Finite BFS model of projection event ownership and publication safety."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, deque
from typing import NamedTuple

MODEL = "projection-owner-abstract-model"
VERSION = "2.3.0"
DEFAULT_MAX_STATES = 20000
DEFAULT_MAX_DEPTH = 64
MAX_STATES = 20000
MAX_DEPTH = 64
MAX_LEASE_EPISODES_PER_EVENT = 2
MAX_PROVEN_FAILURES_PER_EVENT = 1
MAX_REVOKES = 1
MAX_TARGETS_PER_CALL = 32
MAX_NON_TARGETS_PER_CALL = 1

PENDING, LEASED, EXECUTING, UNKNOWN, PUBLISHED = range(5)
PHASE_NAMES = ("PENDING", "LEASED", "EXECUTING", "UNKNOWN", "PUBLISHED")
NO_OWNER = -1
NO_READ = 0
ALLOW, PENDING_DENY = 1, 2


class State(NamedTuple):
    """Immutable, hashable state for every fact in the finite episode."""
    phase: tuple
    owner: tuple
    token: tuple
    owner_epoch: tuple
    lease_installs: tuple
    attempts: tuple
    execs: tuple
    failures: tuple
    failure_cap: tuple
    aggregate_epoch: int
    previous_owner: tuple
    previous_token: tuple
    previous_epoch: tuple
    stale_release_done: tuple
    source_generation: int
    revoke_fence: int
    revoke_count: int
    revoked: bool
    manifest_generation: int
    manifest_events: int
    current_generation: int
    current_events: int
    impact_events: int
    proof_events: int
    receipt_events: int
    published_order: tuple
    nudges: int
    recovered: int
    unknown: int
    read_decisions: tuple
    bad_binding: bool
    bad_release: bool
    budget_polluted: bool
    bad_receipt: bool


class Scenario(NamedTuple):
    name: str
    grants: tuple
    revisions: tuple
    predecessors: tuple
    request_events: tuple
    source_generations: tuple = (1, 1)
    delta_event_ids: tuple = (1, 2)
    durable_receipts: bool = True


class Premises(NamedTuple):
    exact_binding: bool = True
    single_active_slot: bool = True
    epoch_fence: bool = True
    random_token_fence: bool = True
    worker_owner_check: bool = True
    release_ownership_fence: bool = True
    atomic_publication: bool = True
    durable_source_receipt: bool = True
    failure_budget_clean: bool = True
    strict_read_gate: bool = True


SCENARIOS = (
    Scenario("same-grant-duplicate-and-predecessor-chain",
             ("G", "G"), (1, 2), (-1, 0), (0, 0)),
    Scenario("same-grant-request-predecessor-chain",
             ("G", "G"), (1, 2), (-1, 0), (0, 1)),
    Scenario("independent-grants-same-aggregate",
             ("G", "H"), (1, 1), (-1, -1), (0, 1),
             (1, 1), (7, 7)),
)

# The active-slot negative control isolates the slot invariant. Equal abstract
# ordering keys deliberately disable the separate aggregate-predecessor gate;
# real durable event ids are unique and are covered by ORDER_SCENARIO below.
ACTIVE_SLOT_SCENARIO = Scenario(
    "active-slot-control-fixture", ("G", "H"), (1, 1), (-1, -1), (0, 1),
    (1, 1), (1, 1), True,
)

# A request for source 64 arrives before source 7. Both exact dispatch and poll
# recovery use the same claim loop, so the aggregate predecessor gate must keep
# the later event BUSY without installing or charging an attempt.
ORDER_SCENARIO = Scenario(
    "aggregate-source-generation-delta-id-order",
    ("G", "H"), (1, 1), (-1, -1), (1, 0), (7, 64), (7, 64), True,
)


# These are deliberately separate from the BFS result. They are fixed witness
# descriptions, not claims that the witness is an exhaustive exploration.
SCENARIO_WITNESSES = (
    {"name": "same-grant-duplicate", "steps": [
        "W0 claims E0 for R0", "W1 gets BUSY before lease for duplicate R1",
        "W0 begins E0 once", "W0 publishes E0 atomically",
        "R1 observes E0 already published", "recovery scans lost E1 nudge",
    ]},
    {"name": "same-grant-predecessor", "steps": [
        "publish E0", "recovery enables E1", "claim E1 only after E0 predecessor",
        "publish E1", "final read uses current/manifest/impact/proof gate",
    ]},
    {"name": "independent-grants", "steps": [
        "W0 owns E0", "W1 gets BUSY before lease for E1",
        "W0 publishes E0", "W1 claims E1", "W1 publishes E1 independently",
    ]},
)


def initial_state():
    return State(
        phase=(PENDING, PENDING), owner=(NO_OWNER, NO_OWNER), token=(0, 0),
        owner_epoch=(0, 0), lease_installs=(0, 0), attempts=(0, 0),
        execs=(0, 0),
        failures=(0, 0), failure_cap=(False, False), aggregate_epoch=0,
        previous_owner=(NO_OWNER, NO_OWNER), previous_token=(0, 0),
        previous_epoch=(0, 0), stale_release_done=(False, False),
        source_generation=1, revoke_fence=0, revoke_count=0, revoked=False,
        manifest_generation=0, manifest_events=0, current_generation=0,
        current_events=0, impact_events=0, proof_events=0, receipt_events=0,
        published_order=(), nudges=3, recovered=0, unknown=0,
        read_decisions=(NO_READ, NO_READ),
        bad_binding=False, bad_release=False, budget_polluted=False,
        bad_receipt=False,
    )


def _bit(event):
    return 1 << event


def _set(values, index, value):
    updated = list(values)
    updated[index] = value
    return tuple(updated)


def _has_owner(state):
    return any(owner != NO_OWNER for owner in state.owner)


def _has_unknown(state):
    return state.unknown != 0


def _eligible(state, scenario, event):
    predecessor = scenario.predecessors[event]
    return predecessor < 0 or state.phase[predecessor] == PUBLISHED


def _receipt(scenario, event):
    return ("event-%d" % event, "aggregate-A", scenario.grants[event],
            scenario.revisions[event], scenario.source_generations[event])


def _aggregate_key(scenario, event):
    return (scenario.source_generations[event], scenario.delta_event_ids[event])


def _aggregate_predecessor_exists(state, scenario, event):
    """Return whether an earlier aggregate row is not durably published."""
    candidate_key = _aggregate_key(scenario, event)
    return any(
        _aggregate_key(scenario, predecessor) < candidate_key
        and state.phase[predecessor] != PUBLISHED
        for predecessor in range(len(scenario.grants))
    )


def _publication_proven(state, event):
    """Historical proof used by UNKNOWN reconciliation, independent of freshness."""
    bit = _bit(event)
    return bool(
        state.manifest_events & bit
        and state.current_events & bit
        and state.impact_events & bit
        and state.proof_events & bit
        and state.receipt_events & bit
        and state.current_generation == state.manifest_generation
    )


def _binding_matches(scenario, request, event):
    requested_event = scenario.request_events[request]
    return _receipt(scenario, requested_event) == _receipt(scenario, event)


def _stale_release_is_rejected(state, event, actor, old_token, old_epoch,
                               premises):
    if not premises.release_ownership_fence:
        return False
    checks = []
    if premises.worker_owner_check:
        checks.append(actor != state.owner[event])
    if premises.random_token_fence:
        checks.append(old_token != state.token[event])
    if premises.epoch_fence:
        checks.append(old_epoch != state.owner_epoch[event])
    return any(checks)


def transitions(state, scenario, premises):
    """Generate every enabled transition in the finite abstract episode."""
    result = []

    # Claims are the only transitions that increment lease_installs. Busy is
    # evaluated before installing a lease and therefore cannot spend budget.
    for worker in (0, 1):
        for request in (0, 1, None):
            for event in range(2):
                if state.revoked or not _eligible(state, scenario, event):
                    continue
                if state.phase[event] != PENDING or state.owner[event] != NO_OWNER:
                    continue
                if state.failure_cap[event] or state.failures[event] >= MAX_PROVEN_FAILURES_PER_EVENT:
                    continue
                if state.lease_installs[event] >= MAX_LEASE_EPISODES_PER_EVENT:
                    continue
                if not ((state.nudges | state.recovered) & _bit(event)):
                    continue
                # Recovery may claim a durable event directly, without inventing
                # a client request; request-driven claims still require exact binding.
                matches = True if request is None else _binding_matches(scenario, request, event)
                if request is None and state.recovered & _bit(event) == 0:
                    continue
                if premises.exact_binding and not matches:
                    continue
                if _has_unknown(state):
                    result.append(("busy-before-unknown", state))
                    continue
                if _aggregate_predecessor_exists(state, scenario, event):
                    # Exact dispatch and recovery polling share this gate. It is
                    # before lease installation and never charges any counter.
                    result.append(("busy-before-aggregate-predecessor", state))
                    continue
                if premises.single_active_slot and _has_owner(state):
                    successor = state
                    if not premises.failure_budget_clean:
                        failures = _set(state.failures, event, state.failures[event] + 1)
                        successor = state._replace(
                            failures=failures,
                            failure_cap=_set(state.failure_cap, event,
                                             failures[event] >= MAX_PROVEN_FAILURES_PER_EVENT),
                            budget_polluted=True)
                    result.append(("busy-before-lease", successor))
                    continue
                new_epoch = state.aggregate_epoch + 1
                result.append(("claim-lease-install", state._replace(
                    phase=_set(state.phase, event, LEASED),
                    owner=_set(state.owner, event, worker),
                    token=_set(state.token, event, state.token[event] + 1),
                    owner_epoch=_set(state.owner_epoch, event, new_epoch),
                    lease_installs=_set(state.lease_installs, event,
                                        state.lease_installs[event] + 1),
                    attempts=_set(state.attempts, event,
                                  state.attempts[event] + 1),
                    aggregate_epoch=new_epoch,
                    nudges=state.nudges & ~_bit(event),
                    recovered=state.recovered & ~_bit(event),
                    bad_binding=state.bad_binding or not matches,
                )))

    for event in range(2):
        bit = _bit(event)
        phase = state.phase[event]

        # A nudge can be lost, then found by a recovery scan. Neither changes
        # attempt/failure counters.
        if phase == PENDING and _eligible(state, scenario, event):
            if state.nudges & bit:
                result.append(("lose-nudge", state._replace(
                    nudges=state.nudges & ~bit)))
            elif not (state.recovered & bit):
                result.append(("recovery-scan-lost-nudge", state._replace(
                    recovered=state.recovered | bit)))

        if phase == LEASED and state.owner[event] != NO_OWNER:
            # One begin-exec for the installed lease; this transition alone
            # increments the execution counter.
            result.append(("begin-exec", state._replace(
                phase=_set(state.phase, event, EXECUTING),
                execs=_set(state.execs, event, state.execs[event] + 1))))
            result.append(("release-current-lease", state._replace(
                phase=_set(state.phase, event, PENDING),
                owner=_set(state.owner, event, NO_OWNER))))

        if phase == EXECUTING and state.owner[event] != NO_OWNER:
            # A second begin-exec on the same token is an explicit self-loop.
            result.append(("begin-exec-same-token-idempotent", state))

            # A proven execution failure alone consumes failure budget.
            if state.failures[event] < MAX_PROVEN_FAILURES_PER_EVENT:
                failures = _set(state.failures, event, state.failures[event] + 1)
                result.append(("proven-execution-failure", state._replace(
                    phase=_set(state.phase, event, PENDING),
                    owner=_set(state.owner, event, NO_OWNER),
                    failures=failures,
                    failure_cap=_set(state.failure_cap, event,
                                     failures[event] >= MAX_PROVEN_FAILURES_PER_EVENT))))

            # Stale completion becomes UNKNOWN. Reconciliation, not this edge,
            # decides whether a successor capability may be installed.
            if state.lease_installs[event] < MAX_LEASE_EPISODES_PER_EVENT:
                old_owner = state.owner[event]
                old_token = state.token[event]
                old_epoch = state.owner_epoch[event]
                result.append(("stale-takeover", state._replace(
                    phase=_set(state.phase, event, UNKNOWN),
                    owner=_set(state.owner, event, NO_OWNER),
                    previous_owner=_set(state.previous_owner, event, old_owner),
                    previous_token=_set(state.previous_token, event, old_token),
                    previous_epoch=_set(state.previous_epoch, event, old_epoch),
                    stale_release_done=_set(state.stale_release_done, event, False),
                    unknown=state.unknown | bit)))

            # Publication is possible only with current durable source receipt,
            # and never while this event remains UNKNOWN.
            if (not state.revoked and not (state.unknown & bit)
                    and scenario.durable_receipts and premises.durable_source_receipt):
                mask = state.manifest_events | bit
                phases = _set(state.phase, event, PUBLISHED)
                owners = _set(state.owner, event, NO_OWNER)
                if premises.atomic_publication:
                    result.append(("publish-atomic", state._replace(
                        phase=phases, owner=owners,
                        manifest_generation=state.source_generation,
                        manifest_events=mask, current_generation=state.source_generation,
                        current_events=mask, impact_events=mask, proof_events=mask,
                        receipt_events=state.receipt_events | bit,
                        published_order=state.published_order + (event,))))
                else:
                    result.append(("publish-manifest-only", state._replace(
                        phase=phases, owner=owners,
                        manifest_generation=state.source_generation,
                        manifest_events=mask)))
            elif not state.revoked and not premises.durable_source_receipt:
                # Deliberately weakened path: publication is allowed but has no
                # source-receipt proof, which the independent invariant rejects.
                mask = state.manifest_events | bit
                result.append(("publish-without-source-receipt", state._replace(
                    phase=_set(state.phase, event, PUBLISHED),
                    owner=_set(state.owner, event, NO_OWNER),
                    manifest_generation=state.source_generation,
                    manifest_events=mask, current_generation=state.source_generation,
                    current_events=state.current_events | bit,
                    impact_events=state.impact_events | bit,
                    proof_events=state.proof_events | bit,
                    bad_receipt=True)))

            # Failure before publication commit changes no durable publication row.
            result.append(("publication-precommit-abort", state))

        if phase == UNKNOWN:
            # UNKNOWN has no retry edge. First reconcile durable publication
            # evidence; only an unproven event receives a new capability.
            if _publication_proven(state, event):
                result.append(("reconcile-unknown", state._replace(
                    phase=_set(state.phase, event, PUBLISHED),
                    owner=_set(state.owner, event, NO_OWNER),
                    unknown=state.unknown & ~bit,
                    published_order=state.published_order + (event,))))
            elif state.lease_installs[event] < MAX_LEASE_EPISODES_PER_EVENT:
                for worker in (0, 1):
                    new_epoch = state.aggregate_epoch + 1
                    result.append(("reconcile-unknown", state._replace(
                        phase=_set(state.phase, event, LEASED),
                        owner=_set(state.owner, event, worker),
                        token=_set(state.token, event, state.token[event] + 1),
                        owner_epoch=_set(state.owner_epoch, event, new_epoch),
                        lease_installs=_set(state.lease_installs, event,
                                            state.lease_installs[event] + 1),
                        attempts=_set(state.attempts, event,
                                      state.attempts[event] + 1),
                        aggregate_epoch=new_epoch,
                        unknown=state.unknown & ~bit,
                        nudges=state.nudges & ~bit,
                        recovered=state.recovered & ~bit)))

        if state.manifest_events & bit:
            allowed = bool(
                state.current_events & bit and state.impact_events & bit
                and state.proof_events & bit and state.receipt_events & bit
                and state.current_generation == state.source_generation
                and state.manifest_generation == state.source_generation
                and not state.revoked)
            if not premises.strict_read_gate:
                allowed = bool(state.manifest_events & bit)
            if state.unknown & bit:
                allowed = False
            decision = ALLOW if allowed else PENDING_DENY
            if state.read_decisions[event] != decision:
                result.append(("final-read-allow" if decision == ALLOW
                               else "final-read-pending-deny",
                               state._replace(read_decisions=_set(
                                   state.read_decisions, event, decision))))

        # The old owner can attempt a late release after a takeover. The
        # result is safe if any enabled fence catches it; disabling all fences
        # produces the shortest stale-release counterexample.
        if (state.owner[event] != NO_OWNER
                and state.previous_owner[event] != NO_OWNER
                and not state.stale_release_done[event]):
            old_owner = state.previous_owner[event]
            old_token = state.previous_token[event]
            old_epoch = state.previous_epoch[event]
            if _stale_release_is_rejected(state, event, old_owner, old_token,
                                           old_epoch, premises):
                result.append(("stale-release-rejected", state._replace(
                    stale_release_done=_set(state.stale_release_done, event, True))))
            else:
                result.append(("stale-release-accepted", state._replace(
                    phase=_set(state.phase, event, PENDING),
                    owner=_set(state.owner, event, NO_OWNER),
                    stale_release_done=_set(state.stale_release_done, event, True),
                    bad_release=True)))

    if state.revoke_count < MAX_REVOKES:
        result.append(("source-revoke", state._replace(
            source_generation=state.source_generation + 1,
            revoke_fence=state.revoke_fence + 1,
            revoke_count=state.revoke_count + 1,
            revoked=True, read_decisions=(NO_READ, NO_READ))))
    return result


def invariant_violations(state, scenario):
    """Safety checks intentionally independent of which premise was removed."""
    failures = []
    if state.bad_binding:
        failures.append("wrong-immutable-binding-accepted")
    if state.bad_release:
        failures.append("stale-owner-release-accepted")
    if state.budget_polluted:
        failures.append("busy-consumed-failure-budget")
    if state.bad_receipt:
        failures.append("publication-without-durable-source-receipt")
    # This safety property is unconditional, including the active-slot negative control.
    if sum(owner != NO_OWNER for owner in state.owner) > 1:
        failures.append("aggregate-single-active-slot-violated")
    if not (state.manifest_events == state.current_events
            == state.impact_events == state.proof_events
            == state.receipt_events):
        failures.append("manifest-current-impact-proof-receipt-not-atomic")
    published_keys = [_aggregate_key(scenario, event)
                      for event in state.published_order]
    if published_keys != sorted(published_keys):
        failures.append("aggregate-publication-order-regressed")
    for event in range(2):
        bit = _bit(event)
        if state.unknown & bit and state.phase[event] != UNKNOWN:
            failures.append("unknown-bit-without-unknown-phase:%d" % event)
        if state.unknown & bit and state.read_decisions[event] == ALLOW:
            failures.append("read-gate-allowed-with-unknown:%d" % event)
        if state.phase[event] == PUBLISHED:
            if state.unknown & bit:
                failures.append("published-with-unknown-bit:%d" % event)
            if not state.proof_events & bit:
                failures.append("published-without-event-proof:%d" % event)
            if not state.receipt_events & bit:
                failures.append("published-without-source-receipt:%d" % event)
        if state.failures[event] > MAX_PROVEN_FAILURES_PER_EVENT:
            failures.append("proven-failure-budget-exceeded:%d" % event)
        if state.lease_installs[event] > MAX_LEASE_EPISODES_PER_EVENT:
            failures.append("lease-episode-bound-exceeded:%d" % event)
        if state.revoked and state.read_decisions[event] == ALLOW:
            failures.append("read-gate-allowed-after-source-revoke:%d" % event)
    return failures


def _state_summary(state):
    return {
        "phase": [PHASE_NAMES[value] for value in state.phase],
        "owner": list(state.owner), "token": list(state.token),
        "aggregateEpoch": state.aggregate_epoch,
        "leaseInstalls": list(state.lease_installs), "attempts": list(state.attempts),
        "execs": list(state.execs),
        "provenFailures": list(state.failures), "failureCap": list(state.failure_cap),
        "sourceGeneration": state.source_generation, "revokeFence": state.revoke_fence,
        "manifestEvents": state.manifest_events, "currentEvents": state.current_events,
        "impactEvents": state.impact_events, "proofEvents": state.proof_events,
        "receiptEvents": state.receipt_events, "unknown": state.unknown,
        "publishedOrder": list(state.published_order),
        "readDecisions": list(state.read_decisions),
    }


def _path_to(state, parents):
    path = []
    while parents[state] is not None:
        previous, action = parents[state]
        path.append(action)
        state = previous
    return list(reversed(path))


def explore(scenario, premises=Premises(), max_states=DEFAULT_MAX_STATES,
            max_depth=DEFAULT_MAX_DEPTH, stop_at_counterexample=False):
    """BFS all reachable states, or stop at the shortest violating path."""
    start = initial_state()
    queue = deque([(start, 0)])
    parents = {start: None}
    depths = {start: 0}
    transitions_generated = 0
    action_counts = Counter()
    expanded = 0
    cutoffs = []
    counterexample = None
    liveness_witness = None

    while queue:
        state, depth = queue.popleft()
        expanded += 1
        state_violations = invariant_violations(state, scenario)
        if state_violations and counterexample is None:
            counterexample = {"violations": state_violations,
                              "state": _state_summary(state),
                              "trace": _path_to(state, parents)}
            if stop_at_counterexample:
                break
        if state.phase == (PUBLISHED, PUBLISHED) and liveness_witness is None:
            liveness_witness = _path_to(state, parents)
        outgoing = transitions(state, scenario, premises)
        transitions_generated += len(outgoing)
        action_counts.update(action for action, _ in outgoing)
        unseen = [(action, successor) for action, successor in outgoing
                  if successor not in parents]
        if depth >= max_depth and unseen:
            cutoffs.append({"kind": "max_depth", "depth": depth,
                            "unseenSuccessors": len(unseen)})
            continue
        for action, successor in unseen:
            if len(parents) >= max_states:
                cutoffs.append({"kind": "max_states", "limit": max_states,
                                "nextTransition": action})
                queue.clear()
                break
            parents[successor] = (state, action)
            depths[successor] = depth + 1
            queue.append((successor, depth + 1))
        if stop_at_counterexample and counterexample is not None:
            break

    complete = not cutoffs and not (stop_at_counterexample and counterexample is not None)
    if counterexample is not None:
        status = "COUNTEREXAMPLE"
    elif complete:
        status = "PASS"
    else:
        status = "UNKNOWN"
    return {
        "status": status, "explorationComplete": complete,
        "counterexampleFound": counterexample is not None,
        "states": {"distinctReachable": len(parents), "expanded": expanded,
                   "limit": max_states, "maxDepthReached": max(depths.values(), default=0)},
        "transitions": {"generated": transitions_generated,
                        "byKind": dict(sorted(action_counts.items()))},
        "cutoffs": cutoffs, "counterexample": counterexample,
        "conditionalLiveness": {
            "property": "both events reach PUBLISHED within this finite episode",
            "status": "WITNESS" if liveness_witness is not None else "NO_WITNESS",
            "shortestWitness": liveness_witness,
            "assumptions": ["source does not revoke", "no proven execution failure",
                            "lost nudge is eventually recovered",
                            "enabled worker transitions are eventually scheduled"],
            "notUniversalFairnessProof": True,
        },
    }


def _negative_controls(max_states, max_depth):
    controls = (
        ("wrong-binding", SCENARIOS[2], Premises(exact_binding=False)),
        ("active-slot", ACTIVE_SLOT_SCENARIO, Premises(single_active_slot=False)),
        ("ownership-fence-combination", SCENARIOS[0], Premises(
            epoch_fence=False, random_token_fence=False, worker_owner_check=False,
            release_ownership_fence=False)),
        ("half-publication", SCENARIOS[2], Premises(atomic_publication=False)),
        ("stale-release", SCENARIOS[0], Premises(release_ownership_fence=False)),
        ("budget-pollution", SCENARIOS[2], Premises(failure_budget_clean=False)),
        ("read-gate-bypass", SCENARIOS[2], Premises(strict_read_gate=False)),
        ("missing-durable-source-receipt", SCENARIOS[2],
         Premises(durable_source_receipt=False)),
    )
    results = []
    for name, scenario, premises in controls:
        report = explore(scenario, premises, max_states, max_depth,
                         stop_at_counterexample=True)
        results.append({
            "id": name,
            "droppedPremises": [field for field, value in
                                zip(Premises._fields, premises) if not value],
            "status": report["status"],
            "explorationComplete": report["explorationComplete"],
            "counterexampleFound": report["counterexampleFound"],
            "states": report["states"], "transitions": report["transitions"],
            "cutoffs": report["cutoffs"], "counterexample": report["counterexample"],
        })
    epoch_only = explore(SCENARIOS[0], Premises(epoch_fence=False),
                         max_states, max_depth)
    ordering = explore(ORDER_SCENARIO, max_states=max_states, max_depth=max_depth)
    return {
        "counterexamples": results,
        "epochOmissionAlone": {
            "status": epoch_only["status"],
            "explorationComplete": epoch_only["explorationComplete"],
            "states": epoch_only["states"], "transitions": epoch_only["transitions"],
            "interpretation": "random-token and worker-owner fences remain; no vulnerability is asserted",
        },
        "aggregateOrdering": {
            "status": ordering["status"],
            "explorationComplete": ordering["explorationComplete"],
            "states": ordering["states"], "transitions": ordering["transitions"],
            "cutoffs": ordering["cutoffs"], "counterexample": ordering["counterexample"],
        },
    }


def _fixed_schedule_ablation():
    rows = [
        {"variant": "legacy_scope_claim", "scopeCalls": 2,
         "nonTargetCandidatesVisited": 2, "nonTargetPerCallMax": 1,
         "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
         "exactBindingChecks": 0, "workerOwnerChecks": 0, "failureBudgetChecks": 0},
        {"variant": "exact_claim", "scopeCalls": 0,
         "nonTargetCandidatesVisited": 0, "nonTargetPerCallMax": 0,
         "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
         "exactBindingChecks": 2, "workerOwnerChecks": 0, "failureBudgetChecks": 0},
        {"variant": "exact+worker_owner", "scopeCalls": 0,
         "nonTargetCandidatesVisited": 0, "nonTargetPerCallMax": 0,
         "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
         "exactBindingChecks": 2, "workerOwnerChecks": 2, "failureBudgetChecks": 0},
        {"variant": "exact+owner+failure_budget", "scopeCalls": 0,
         "nonTargetCandidatesVisited": 0, "nonTargetPerCallMax": 0,
         "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
         "exactBindingChecks": 3, "workerOwnerChecks": 2, "failureBudgetChecks": 3},
    ]
    return {
        "kind": "fixed_schedule_abstract_operation_counts",
        "fixture": "2 requests, 2 workers, 2 events in one aggregate",
        "legacyRule": "stop at first non-target; at most one non-target per call",
        "notDatabasePerformance": True, "notGlobalOptimum": True,
        "notUnboundedProof": True, "rows": rows,
    }


def run_model(max_states=DEFAULT_MAX_STATES, max_depth=DEFAULT_MAX_DEPTH):
    if type(max_states) is not int or not 1 <= max_states <= MAX_STATES:
        raise ValueError("max_states must be an integer from 1 to %d" % MAX_STATES)
    if type(max_depth) is not int or not 1 <= max_depth <= MAX_DEPTH:
        raise ValueError("max_depth must be an integer from 1 to %d" % MAX_DEPTH)

    cases = []
    for scenario in SCENARIOS:
        report = explore(scenario, max_states=max_states, max_depth=max_depth)
        report["name"] = scenario.name
        report["requests"] = list(scenario.request_events)
        report["events"] = [{"grant": scenario.grants[event],
                              "revision": scenario.revisions[event],
                              "predecessor": scenario.predecessors[event]}
                             for event in range(2)]
        cases.append(report)

    negative = _negative_controls(max_states, max_depth)
    base_complete = all(case["status"] == "PASS"
                        and case["explorationComplete"] for case in cases)
    controls_found = all(item["counterexampleFound"]
                         and item["status"] == "COUNTEREXAMPLE"
                         and not item["explorationComplete"]
                         for item in negative["counterexamples"])
    epoch_safe = (negative["epochOmissionAlone"]["status"] == "PASS"
                  and negative["epochOmissionAlone"]["explorationComplete"])
    ordering_safe = (negative["aggregateOrdering"]["status"] == "PASS"
                     and negative["aggregateOrdering"]["explorationComplete"])
    if base_complete and controls_found and epoch_safe and ordering_safe:
        status = "PASS"
    elif any(case["status"] == "UNKNOWN" for case in cases) or not controls_found:
        status = "UNKNOWN"
    else:
        status = "FAIL"

    return {
        "model": MODEL, "version": VERSION, "status": status,
        "explorationComplete": base_complete and epoch_safe and ordering_safe,
        "evidenceBoundary": "complete BFS over the stated finite episode only; not an unbounded or production proof",
        "finiteUniverse": {
            "events": 2, "workers": 2, "requests": 2,
            "maxLeaseEpisodesPerEvent": MAX_LEASE_EPISODES_PER_EVENT,
            "maxProvenFailuresPerEvent": MAX_PROVEN_FAILURES_PER_EVENT,
            "maxSourceRevokes": MAX_REVOKES,
            "maxAggregateEpoch": 2 * MAX_LEASE_EPISODES_PER_EVENT,
            "maxStatesPerSearch": max_states, "maxDepthPerSearch": max_depth,
            "hardMaxStates": MAX_STATES, "hardMaxDepth": MAX_DEPTH,
        },
        "stateSemantics": {
            "stateType": "immutable hashable NamedTuple",
            "claimCounterIncrement": "lease installation only",
            "beginExec": "increments once per lease; same-token repeat is idempotent",
            "failureBudget": "only proven execution failure consumes budget",
            "busyOrReleaseConsumesFailureBudget": False,
            "unknown": "reconcile durable publication proof before successor lease",
            "exhaustedEvent": "PENDING_WITH_FAILURE_CAP",
            "publicationAtomicFields": ["manifest", "current", "impact", "event_proof", "source_receipt"],
            "durableSourceReceipt": "immutable event/aggregate/grant/revision/generation binding",
            "aggregatePredecessor": "(source_generation, delta_event_id); exact and poll share Busy-before-install gate",
            "ownership": "aggregate epoch + random-token abstraction + worker-owner fence",
        },
        "scenarioWitnesses": list(SCENARIO_WITNESSES),
        "cases": cases, "negativeControls": negative,
        "ablation": _fixed_schedule_ablation(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON")
    parser.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    args = parser.parse_args(argv)
    try:
        report = run_model(args.max_states, args.max_depth)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True,
                     separators=(",", ":") if args.json else None,
                     indent=None if args.json else 2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
