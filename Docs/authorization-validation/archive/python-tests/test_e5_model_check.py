#!/usr/bin/env python3
"""Offline unit tests for the E5 bounded model checker (``e5_model_check.py``).

Execution class: Exec-L1, offline only. These tests are pure computation:
they import the checker module, run its exhaustive enumeration, and assert on
the resulting reports. No services, containers, network, sockets, subprocesses,
or filesystem writes are used. Run with::

    python -m unittest discover -s Docs/authorization-validation/tools -p "test_e5_model_check.py" -v

Coverage (v2.1.0 -- faithful Rust observation semantics):

- the final load is the ordered sequence m0 < p0 < m1 < p1 (bracket) or one
  atomic strict load with an embedded pending probe; the admission evidence
  anchors at m0 and the theorem's final observation t_f is m0,
- the pending probes capture the in-flight state AT THEIR READ STEPS and
  latch fail-closed: a publication completing after the last read and before
  ADMIT is denied whenever the commit was durable before t_f, and there is
  NO admission-time re-derivation and NO admission-side watermark (the
  current Rust implementation has neither),
- the decision tail is FREE: mutation/publication interleavings between the
  last read and ADMIT are enumerated, in-domain ones are denied by the
  latched probes, and after-t_f ones are honestly reported as the
  irreducible TOCTOU window (outside the theorem, never violations),
- mixed manifest/body (M/b) cache states: explicit torn states (stale body
  r0 under manifest/head g1, and the converse) are enumerated and rejected,
- each modeled single-premise omission yields a concrete counterexample
  (matching the Rust E2 omission experiments); nothing is pre-assumed,
- deterministic counterexamples and deterministic reports,
- interval-overlap traces classified UNKNOWN and never counted as violations,
- invalid bound validation and the below-bound FAIL-vs-UNKNOWN precedence,
- status scope, BLOCKED reachability, structural assumptions in
  machine-readable scopeLimitations,
- import safety: no subprocess/socket/network imports, no module-level side
  effects, and the required abstract-evidence-only docstring disclaimer.
"""

from __future__ import annotations

import ast
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import e5_model_check as e5  # noqa: E402

BANNED_IMPORT_ROOTS = (
    "subprocess",
    "socket",
    "_socket",
    "ssl",
    "http",
    "urllib",
    "urllib.request",
    "urllib.parse",
    "ftplib",
    "telnetlib",
    "smtplib",
    "poplib",
    "imaplib",
    "nntplib",
    "xmlrpc",
    "asyncio",
    "selectors",
    "asyncore",
    "asynchat",
)

# One shared full report for the default bound (build cost is ~5s).
REPORT = e5.build_report(e5.DEFAULT_BOUND)


def event_names(counterexample):
    """Return the event-name list of a counterexample trace."""
    return [item["event"] for item in counterexample["trace"]]


def index_of(events, name):
    return events.index(name)


class FullContractTests(unittest.TestCase):
    """The full contract must be safe at multiple bounds, in both modes."""

    def test_full_contract_pass_at_default_bound_both_modes(self):
        fc = REPORT["fullContract"]
        self.assertEqual(fc["status"], "PASS")
        for mode in ("bracket", "strict"):
            run = fc["modes"][mode]
            self.assertEqual(run["status"], "PASS", mode)
            self.assertEqual(run["violations"], 0, mode)
            self.assertTrue(run["explorationComplete"], mode)
            self.assertEqual(run["bound"], e5.DEFAULT_BOUND, mode)
            self.assertGreaterEqual(run["bound"], run["requiredBound"], mode)

    def test_full_contract_pass_at_two_bounds(self):
        for bound in (e5.required_bound(), e5.required_bound() + 4):
            for mode in ("bracket", "strict"):
                run = e5.run_model(e5.normalize_premises(), mode, bound)
                self.assertEqual(run["status"], "PASS", (bound, mode))
                self.assertEqual(run["violations"], 0, (bound, mode))
                self.assertTrue(run["explorationComplete"], (bound, mode))
                self.assertEqual(run["bound"], bound, (bound, mode))

    def test_no_in_domain_stale_admission_under_faithful_probes(self):
        for mode in ("bracket", "strict"):
            run = REPORT["fullContract"]["modes"][mode]
            # The theorem domain: a mutation committed strictly before t_f
            # (m0) and a stale candidate admitted -- zero such traces.
            self.assertEqual(run["admittedDomainCounts"]["strictlyBefore"], 0, mode)
            self.assertEqual(run["violations"], 0, mode)
            # The decision tail is free and the key window schedule is
            # enumerated: commit durable BEFORE t_f with a publication
            # sub-event firing after the last read and before ADMIT ...
            window = run["admissionWindow"]
            self.assertGreater(
                window["staleCommitPublishAfterLastReadTraces"], 0, mode
            )
            # ... and every one of them is denied by the LATCHED read-time
            # pending probes (the publication cannot resurrect a latched
            # unsafe delta; there is no admission-time check to fool).
            self.assertEqual(
                window["admittedStaleCommitPublishAfterLastRead"], 0, mode
            )
            latched = [
                key
                for key in run["denialReasons"]
                if key.startswith("pending_probe_latched_unsafe_delta")
            ]
            self.assertTrue(latched, mode)

    def test_no_admission_time_mechanism_exists(self):
        # The model must not contain any admission-time watermark or
        # re-derivation: the fence is a READ GATE ONLY, the pending premise
        # is latched at read time, and the v2.0.0 counterfactual field is
        # gone.
        self.assertIn("read gate ONLY", e5.PREMISE_DESCRIPTIONS["generation_revoke_fence"])
        self.assertIn("read time", e5.PREMISE_DESCRIPTIONS["pending_probe"])
        payload = json.dumps(REPORT)
        self.assertNotIn("admissionWatermarkCounterfactual", payload)
        self.assertNotIn("admission_watermark", payload)

    def test_out_of_domain_window_is_reported_honestly(self):
        # A mutation that BEGINS after t_f is invisible to the read-time
        # probes by construction; the model honestly admits such schedules
        # in the after-final-observation domain (the irreducible TOCTOU
        # window) and never counts them as violations.
        for mode in ("bracket", "strict"):
            run = REPORT["fullContract"]["modes"][mode]
            self.assertGreater(
                run["admittedDomainCounts"]["afterFinalObservation"], 0, mode
            )
            self.assertGreater(
                run["admissionWindow"]["admittedPublishAfterFinalObservation"],
                0,
                mode,
            )
            self.assertEqual(
                run["violationsByDomain"]["afterFinalObservation"], 0, mode
            )
            self.assertEqual(run["violationsByDomain"]["overlapUnknown"], 0, mode)

    def test_full_contract_violations_only_from_in_domain_traces(self):
        for mode in ("bracket", "strict"):
            run = REPORT["fullContract"]["modes"][mode]
            self.assertEqual(
                run["violations"],
                run["admittedDomainCounts"]["strictlyBefore"],
                mode,
            )
            for domain, count in run["violationsByDomain"].items():
                if domain != "strictlyBefore":
                    self.assertEqual(count, 0, (mode, domain))


class FaithfulObservationStructureTests(unittest.TestCase):
    """The modeled observation sequence matches the real protocol."""

    def test_final_load_is_ordered_m0_p0_m1_p1(self):
        chains = e5.build_chains(e5.normalize_premises(), "bracket")
        self.assertEqual(
            chains["checklist"][:5],
            [
                e5.EV_RELOAD_M0,
                e5.EV_RELOAD_P0,
                e5.EV_RELOAD_M1,
                e5.EV_RELOAD_P1,
                e5.EV_MATCH,
            ],
        )
        self.assertEqual(chains["recheck"], [e5.EV_POST_BEGIN, e5.EV_POST_END])
        self.assertEqual(chains["checklist"][-1], e5.EV_ADMIT)

    def test_strict_load_is_one_atomic_event_with_embedded_probe(self):
        chains = e5.build_chains(e5.normalize_premises(), "strict")
        self.assertEqual(
            chains["checklist"],
            [e5.EV_STRICT_LOAD, e5.EV_MATCH, e5.EV_STRICT, e5.EV_ADMIT],
        )
        self.assertEqual(chains["pre"], [])

    def test_probes_and_load_disappear_with_their_premises(self):
        no_probe = e5.build_chains(e5.without_premise("pending_probe"), "bracket")
        self.assertNotIn(e5.EV_RELOAD_P0, no_probe["checklist"])
        self.assertNotIn(e5.EV_RELOAD_P1, no_probe["checklist"])
        self.assertIn(e5.EV_RELOAD_M0, no_probe["checklist"])
        no_load = e5.build_chains(e5.without_premise("final_reload"), "bracket")
        for event in (
            e5.EV_RELOAD_M0,
            e5.EV_RELOAD_P0,
            e5.EV_RELOAD_M1,
            e5.EV_RELOAD_P1,
        ):
            self.assertNotIn(event, no_load["checklist"])
        no_probe_strict = e5.build_chains(
            e5.without_premise("pending_probe"), "strict"
        )
        self.assertIn(e5.EV_STRICT_LOAD, no_probe_strict["checklist"])

    def test_tf_anchor_is_m0_bracket_and_strict_load_strict(self):
        # The domain classification anchors t_f at the first authoritative
        # observation of the final load: m0 in bracket mode, the atomic
        # strict load in strict mode.
        for mode, anchor in (("bracket", e5.EV_RELOAD_M0), ("strict", e5.EV_STRICT_LOAD)):
            run = e5.run_model(e5.normalize_premises(), mode, e5.required_bound())
            self.assertEqual(run["status"], "PASS", mode)
        # Pure check: a commit durable one step before the anchor is
        # strictly_before; one at/after it is not.
        self.assertEqual(e5.classify_domain((1, 4), (5, 5)), "strictly_before")
        self.assertEqual(e5.classify_domain((3, 6), (5, 5)), "overlap_unknown")
        self.assertEqual(e5.classify_domain((6, 8), (5, 5)), "after_final_observation")


class LatchedProbeTests(unittest.TestCase):
    """Pending probes latch at read time; nothing is re-derived at ADMIT."""

    def test_probe_omission_admits_commit_durable_before_tf(self):
        # Removing the probe premise removes the probes from the load; the
        # coordinator's key schedule (commit durable before t_f, publication
        # completing after the last read and before ADMIT) is then ADMITTED:
        # the latched-probe control is what closes it in the full contract.
        run = e5.run_model(
            e5.without_premise("pending_probe"), "bracket", e5.DEFAULT_BOUND
        )
        self.assertEqual(run["status"], "FAIL")
        window = run["admissionWindow"]
        self.assertGreater(window["staleCommitPublishAfterLastReadTraces"], 0)
        self.assertGreater(window["admittedStaleCommitPublishAfterLastRead"], 0)

    def test_probe_omission_minimal_trace_has_no_admission_time_check(self):
        # The minimal pending-probe-omission counterexample never publishes
        # at all, yet is admitted: this proves the model has NO
        # admission-time in-flight re-derivation (an admission-time check
        # would deny a durable-but-unpublished mutation at ADMIT).
        entry = {
            entry["premise"]: entry for entry in REPORT["omissions"]
        }["pending_probe"]
        cex = entry["counterexample"]
        self.assertEqual(
            cex["scheduleClass"], "source_pending_commit_without_publication"
        )
        events = event_names(cex)
        self.assertIn(e5.EV_COMMIT_DURABLE, events)
        self.assertNotIn(e5.EV_PUBLISH, events)
        self.assertNotIn(e5.EV_BODY_ADVANCE, events)
        self.assertIn(e5.EV_ADMIT, events)
        self.assertEqual(cex["pendingObservations"], {})

    def test_latched_probes_survive_late_publication(self):
        # In the full contract the probes latch pending at their read steps;
        # the denial reason names the probe that latched the unsafe delta.
        run = REPORT["fullContract"]["modes"]["bracket"]
        latched_keys = [
            key
            for key in run["denialReasons"]
            if key.startswith("pending_probe_latched_unsafe_delta:RELOAD_P")
        ]
        self.assertIn(
            "pending_probe_latched_unsafe_delta:RELOAD_P0", latched_keys
        )
        self.assertIn(
            "pending_probe_latched_unsafe_delta:RELOAD_P1", latched_keys
        )


class MixedManifestBodyTests(unittest.TestCase):
    """Mixed M/b cache states are explicit, enumerated, and rejected."""

    def test_cache_observation_consistent_states(self):
        pre = e5.cache_observation(10, None, None, None, True)
        self.assertEqual(
            (pre["manifest"], pre["body"], pre["head"]),
            (e5.GEN_BEFORE, e5.CANDIDATE_REVISION, e5.GEN_BEFORE),
        )
        self.assertTrue(pre["consistent"])
        self.assertTrue(pre["valid"])
        post = e5.cache_observation(10, 4, 5, None, True)
        self.assertEqual(
            (post["manifest"], post["body"], post["head"]),
            (e5.GEN_AFTER, e5.SUCCESSOR_REVISION, e5.GEN_AFTER),
        )
        self.assertTrue(post["consistent"])
        self.assertTrue(post["valid"])
        # an event fires at its own step (read at the publish step sees g1)
        boundary = e5.cache_observation(4, 4, None, None, True)
        self.assertEqual(boundary["manifest"], e5.GEN_AFTER)

    def test_cache_observation_stale_body_under_current_manifest(self):
        # PUBLISH fired (manifest/head g1) but the evidence body is still
        # r0: the required mixed M/b state.
        obs = e5.cache_observation(10, 4, None, None, True)
        self.assertEqual(
            (obs["manifest"], obs["body"], obs["head"]),
            (e5.GEN_AFTER, e5.CANDIDATE_REVISION, e5.GEN_AFTER),
        )
        self.assertFalse(obs["consistent"])
        self.assertFalse(obs["valid"])
        self.assertEqual(obs["reason"], "manifest_ahead_body_stale")

    def test_cache_observation_converse_body_ahead_of_manifest(self):
        # Converse torn state: successor body r1 visible while the
        # manifest/head still says g0.
        obs = e5.cache_observation(10, None, 4, None, True)
        self.assertEqual(
            (obs["manifest"], obs["body"], obs["head"]),
            (e5.GEN_BEFORE, e5.SUCCESSOR_REVISION, e5.GEN_BEFORE),
        )
        self.assertFalse(obs["consistent"])
        self.assertFalse(obs["valid"])
        self.assertEqual(obs["reason"], "body_ahead_manifest_stale")

    def test_cache_observation_rollback_and_post_rollback_torn(self):
        # Rollback resets the read path to (g0, r0) -- including a body
        # advance that happened before it; the durable head stays g1, so a
        # read is below-head and rejected.
        obs = e5.cache_observation(10, 4, 3, 5, True)
        self.assertEqual(
            (obs["manifest"], obs["body"], obs["head"]),
            (e5.GEN_BEFORE, e5.CANDIDATE_REVISION, e5.GEN_AFTER),
        )
        self.assertTrue(obs["consistent"])
        self.assertFalse(obs["valid"])
        self.assertEqual(obs["reason"], "generation_below_published_head")
        # A body advance AFTER the rollback re-advances the body: torn again.
        obs2 = e5.cache_observation(10, 4, 7, 5, True)
        self.assertEqual(
            (obs2["manifest"], obs2["body"]), (e5.GEN_BEFORE, e5.SUCCESSOR_REVISION)
        )
        self.assertFalse(obs2["consistent"])
        self.assertFalse(obs2["valid"])
        self.assertEqual(obs2["reason"], "body_ahead_manifest_stale")

    def test_cache_observation_without_fence_carries_torn_pairs_raw(self):
        # With the fence premise off there is no read gate: the torn pair is
        # reported valid (for the downstream controls to confront) and the
        # raw mismatched gen/rev pair is carried.
        for publish_step, body_step in ((4, None), (None, 4)):
            obs = e5.cache_observation(10, publish_step, body_step, None, False)
            self.assertTrue(obs["valid"])
            self.assertFalse(obs["consistent"])
            self.assertIsNone(obs["reason"])

    def test_torn_states_enumerated_and_rejected_in_full_contract(self):
        for mode in ("bracket", "strict"):
            run = REPORT["fullContract"]["modes"][mode]
            mixed = run["mixedManifestBody"]
            # Both torn directions are reachable and observed by reads...
            self.assertGreater(mixed["tornReadTraces"], 0, mode)
            self.assertGreater(
                mixed["tornReadTracesByKind"]["manifest_ahead_body_stale"], 0, mode
            )
            self.assertGreater(
                mixed["tornReadTracesByKind"]["body_ahead_manifest_stale"], 0, mode
            )
            # ...and no read from a torn state ever reaches admission.
            self.assertEqual(mixed["admittedTornReadTraces"], 0, mode)

    def test_torn_reads_rejected_even_without_the_fence(self):
        # With the fence premise removed, torn reads are carried raw. In the
        # theorem domain they are still denied (a torn pair implies an
        # incomplete publication, which the latched probes catch, or a
        # disagreement at the recheck), so the fence omission's
        # counterexample is the pointer-rollback trace. The only ADMITTED
        # torn-read traces lie in the after-t_f TOCTOU domain: the mutation
        # begins after m0 (invisible to the read-time probes), publishes,
        # and a rollback restores the old cache so the recheck agrees again
        # -- outside the theorem, never violations.
        run = e5.run_model(
            e5.without_premise("generation_revoke_fence"), "bracket",
            e5.DEFAULT_BOUND,
        )
        self.assertEqual(run["status"], "FAIL")
        mixed = run["mixedManifestBody"]
        self.assertGreater(mixed["tornReadTraces"], 0)
        self.assertGreater(mixed["admittedTornReadTraces"], 0)
        self.assertEqual(
            set(mixed["admittedTornReadTracesByDomain"]),
            {"after_final_observation"},
        )
        self.assertEqual(
            run["counterexample"]["scheduleClass"],
            "stale_generation_pointer_rollback",
        )
        self.assertEqual(
            run["violations"],
            run["admittedDomainCounts"]["strictlyBefore"],
        )


class OmissionTests(unittest.TestCase):
    """Each single-premise omission yields a concrete counterexample
    (matching the Rust E2 omission experiments). No violation is
    pre-assumed; every counterexample below is found by exhaustive
    enumeration."""

    def _omission(self, premise):
        entries = {
            entry["premise"]: entry for entry in REPORT["omissions"]
        }
        self.assertEqual(set(entries), set(e5.PREMISES))
        return entries[premise]

    def test_pending_probe_omission_source_pending_trace(self):
        entry = self._omission("pending_probe")
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["finding"], "counterexample_found")
        cex = entry["counterexample"]
        self.assertEqual(
            cex["scheduleClass"], "source_pending_commit_without_publication"
        )
        events = event_names(cex)
        # Durable commit before t_f, no probes left in the load, admission
        # on the pre-invalidation evidence.
        self.assertIn(e5.EV_COMMIT_DURABLE, events)
        self.assertNotIn(e5.EV_PUBLISH, events)
        self.assertIn(e5.EV_ADMIT, events)
        self.assertTrue(cex["staleAtAdmission"])
        self.assertEqual(cex["domain"], "strictly_before")
        self.assertEqual(entry["premiseRemoved"], "pending_probe")

    def test_post_recheck_omission_intra_load_publication_trace(self):
        # The mutation fully publishes BETWEEN m0 and p0: the probes
        # correctly observe pending=false at their read steps, but the
        # evidence stays anchored at the earlier m0 (g0, r0) and -- with the
        # recheck removed -- no later read confronts it.
        entry = self._omission("post_recheck")
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["finding"], "counterexample_found")
        cex = entry["counterexample"]
        self.assertEqual(
            cex["scheduleClass"],
            "mutation_published_between_evidence_read_and_last_read",
        )
        events = event_names(cex)
        self.assertIn(e5.EV_RELOAD_M0, events)
        self.assertIn(e5.EV_RELOAD_P0, events)
        self.assertLess(index_of(events, e5.EV_RELOAD_M0), index_of(events, e5.EV_PUBLISH))
        self.assertLess(index_of(events, e5.EV_PUBLISH), index_of(events, e5.EV_RELOAD_P0))
        # The probes observed the publication as complete at their steps...
        self.assertEqual(cex["pendingObservations"][e5.EV_RELOAD_P0]["pending"], False)
        self.assertEqual(cex["pendingObservations"][e5.EV_RELOAD_P1]["pending"], False)
        # ...while the m0-anchored evidence is the stale pre-publication
        # body and the load's second manifest read already saw the successor.
        self.assertEqual(
            (cex["reads"][e5.EV_RELOAD_M0]["gen"], cex["reads"][e5.EV_RELOAD_M0]["rev"]),
            (e5.GEN_BEFORE, e5.CANDIDATE_REVISION),
        )
        self.assertEqual(
            (cex["reads"][e5.EV_RELOAD_M1]["gen"], cex["reads"][e5.EV_RELOAD_M1]["rev"]),
            (e5.GEN_AFTER, e5.SUCCESSOR_REVISION),
        )
        self.assertNotIn(e5.EV_POST_END, events)  # recheck removed with premise
        self.assertEqual(cex["domain"], "strictly_before")

    def test_final_reload_omission_no_load_no_probes_trace(self):
        # Removing the final load removes the pending probes with it and
        # falls back to the pre-observation evidence: a durable commit
        # before that observation is admitted stale (matches the Rust e2
        # final-reload-omission experiment).
        entry = self._omission("final_reload")
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["finding"], "counterexample_found")
        cex = entry["counterexample"]
        self.assertEqual(
            cex["scheduleClass"], "source_pending_commit_without_publication"
        )
        events = event_names(cex)
        for event in (
            e5.EV_RELOAD_M0,
            e5.EV_RELOAD_P0,
            e5.EV_RELOAD_M1,
            e5.EV_RELOAD_P1,
        ):
            self.assertNotIn(event, events)
        self.assertEqual(cex["pendingObservations"], {})
        self.assertIn(e5.EV_COMMIT_DURABLE, events)
        self.assertEqual(cex["domain"], "strictly_before")

    def test_exact_identity_omission_successor_revision_trace(self):
        entry = self._omission("exact_identity")
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["finding"], "counterexample_found")
        cex = entry["counterexample"]
        self.assertEqual(
            cex["scheduleClass"], "successor_revision_identity_confusion"
        )
        events = event_names(cex)
        # Publication completes BEFORE the final load; the probes correctly
        # observe pending=false and every remaining gate passes.
        self.assertLess(index_of(events, e5.EV_PUBLISH), index_of(events, e5.EV_RELOAD_M0))
        self.assertNotIn(e5.EV_ROLLBACK, events)
        for event in (e5.EV_RELOAD_P0, e5.EV_RELOAD_P1, e5.EV_POST_END, e5.EV_MATCH):
            self.assertIn(event, events)
        self.assertEqual(cex["domain"], "strictly_before")
        # With identity off, a rollback AFTER the last read also violates:
        # the evidence was already read at g1, so no read re-observes the
        # rolled-back cache. The full contract rejects both via exact
        # identity.
        self.assertIn(
            "stale_generation_pointer_rollback", entry["run"]["violationClasses"]
        )

    def test_generation_fence_omission_pointer_rollback_trace(self):
        # Without the read gate, a pointer rollback to (g0, r0) after a
        # complete publication is served below the published head and
        # accepted; the probes observe pending=false (the publication
        # completed at their read steps) and every remaining gate passes.
        entry = self._omission("generation_revoke_fence")
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["finding"], "counterexample_found")
        cex = entry["counterexample"]
        self.assertEqual(
            cex["scheduleClass"], "stale_generation_pointer_rollback"
        )
        events = event_names(cex)
        self.assertLess(index_of(events, e5.EV_PUBLISH), index_of(events, e5.EV_ROLLBACK))
        self.assertLess(index_of(events, e5.EV_ROLLBACK), index_of(events, e5.EV_RELOAD_M0))
        self.assertEqual(cex["domain"], "strictly_before")
        # The fence premise is the ONLY control that rejects below-head and
        # torn reads; under single omissions its removal exposes exactly the
        # rollback family (torn reads stay denied by the probes/recheck).
        self.assertEqual(
            entry["run"]["violationClasses"],
            {"stale_generation_pointer_rollback": entry["run"]["violations"]},
        )

    def test_host_mediation_omission_bypass_trace(self):
        entry = self._omission("host_mediation")
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["finding"], "counterexample_found")
        cex = entry["counterexample"]
        self.assertEqual(cex["scheduleClass"], "bypass_unmediated_admission")
        events = event_names(cex)
        self.assertIn(e5.EV_BYPASS, events)
        self.assertIn(e5.EV_COMMIT_DURABLE, events)
        # The minimal bypass counterexample replaces the mediated ADMIT with
        # the unmediated BYPASS terminal after the single t_f read (m0):
        # a violating trace must order the durable commit strictly before
        # some observed authoritative read, and t_f is now one step.
        self.assertNotIn(e5.EV_ADMIT, events)
        self.assertIn(e5.EV_RELOAD_M0, events)
        self.assertLess(
            index_of(events, e5.EV_COMMIT_DURABLE), index_of(events, e5.EV_RELOAD_M0)
        )
        self.assertEqual(cex["eventCount"], 5)
        self.assertEqual(cex["domain"], "strictly_before")

    def test_all_six_omissions_are_load_bearing(self):
        expected = {
            "pending_probe": "FAIL",
            "post_recheck": "FAIL",
            "final_reload": "FAIL",
            "exact_identity": "FAIL",
            "generation_revoke_fence": "FAIL",
            "host_mediation": "FAIL",
        }
        actual = {
            entry["premise"]: entry["status"] for entry in REPORT["omissions"]
        }
        self.assertEqual(actual, expected)
        for entry in REPORT["omissions"]:
            self.assertEqual(entry["finding"], "counterexample_found")
            self.assertIsNotNone(entry["counterexample"])
            self.assertGreater(entry["run"]["violations"], 0)


class DeterminismTests(unittest.TestCase):
    """Deterministic ordering: identical runs produce identical reports."""

    def test_run_model_deterministic(self):
        for premises, mode in (
            (e5.normalize_premises(), "bracket"),
            (e5.without_premise("exact_identity"), "bracket"),
            (e5.without_premise("host_mediation"), "bracket"),
        ):
            first = e5.run_model(premises, mode, 20)
            second = e5.run_model(premises, mode, 20)
            self.assertEqual(
                json.dumps(first, sort_keys=True),
                json.dumps(second, sort_keys=True),
            )
            if first["counterexample"] is not None:
                self.assertEqual(
                    first["counterexample"]["trace"],
                    second["counterexample"]["trace"],
                )

    def test_full_report_deterministic(self):
        # The shared REPORT was computed once at import; an independent fresh
        # computation of the same bound must be JSON-identical.
        fresh = e5.build_report(e5.DEFAULT_BOUND, use_cache=False)
        self.assertEqual(
            json.dumps(fresh, sort_keys=True),
            json.dumps(REPORT, sort_keys=True),
        )


class IntervalDomainTests(unittest.TestCase):
    """Overlapping commit/read intervals are UNKNOWN, never violations."""

    def test_classify_domain_pure_cases(self):
        self.assertEqual(e5.classify_domain((3, 5), (6, 8)), "strictly_before")
        self.assertEqual(e5.classify_domain((3, 5), (5, 8)), "overlap_unknown")
        self.assertEqual(e5.classify_domain((3, 6), (5, 8)), "overlap_unknown")
        self.assertEqual(e5.classify_domain((3, 6), (6, 6)), "overlap_unknown")
        self.assertEqual(
            e5.classify_domain((6, 8), (2, 4)), "after_final_observation"
        )
        self.assertEqual(e5.classify_domain(None, (2, 4)), "not_stale")
        self.assertEqual(e5.classify_domain((3, 5), None), "unknown_domain")

    def test_admitted_overlap_traces_are_never_violations(self):
        # The mediation-off run admits bypass traces across every ordering,
        # including commits spanning t_f (overlap).
        run = e5.run_model(e5.without_premise("host_mediation"), "bracket", 28)
        self.assertGreaterEqual(
            run["admittedDomainCounts"]["overlapUnknown"], 1
        )
        self.assertEqual(run["violationsByDomain"]["overlapUnknown"], 0)
        self.assertEqual(
            run["violations"],
            run["admittedDomainCounts"]["strictlyBefore"],
        )
        self.assertEqual(
            run["violations"], run["violationsByDomain"]["strictlyBefore"]
        )


class BoundValidationTests(unittest.TestCase):
    """The max bound must be finite and validated."""

    def test_valid_bounds_accepted(self):
        self.assertEqual(e5.validate_bound(e5.MIN_BOUND), e5.MIN_BOUND)
        self.assertEqual(e5.validate_bound(e5.MAX_BOUND), e5.MAX_BOUND)
        self.assertEqual(e5.validate_bound(14), 14)

    def test_invalid_bounds_rejected(self):
        for bad in (0, -1, 1, e5.MAX_BOUND + 1, 10 ** 6):
            with self.assertRaises(e5.BoundError, msg=repr(bad)):
                e5.validate_bound(bad)
        for bad in ("12", None, 2.5, True, False, [14]):
            with self.assertRaises(e5.BoundError, msg=repr(bad)):
                e5.validate_bound(bad)

    def test_bound_below_required_gives_unknown_not_pass(self):
        run = e5.run_model(e5.normalize_premises(), "bracket", 8)
        self.assertFalse(run["explorationComplete"])
        self.assertEqual(run["status"], "UNKNOWN")
        self.assertEqual(run["violations"], 0)
        self.assertGreater(run["incompleteTraces"], 0)
        self.assertLess(run["bound"], run["requiredBound"])

    def test_unknown_bounds_never_produce_pass(self):
        report = e5.build_report(8)
        # Both observation modes require more than 8 steps (bracket: 16,
        # strict: 10), so the bracket run cannot complete and the combined
        # status must not claim PASS.
        self.assertNotEqual(report["fullContract"]["status"], "PASS")
        self.assertIn(report["fullContract"]["status"], ("UNKNOWN", "FAIL"))

    def test_below_bound_run_with_counterexample_reports_fail(self):
        # Status precedence: a concrete counterexample is decisive. The
        # pending-probe-omission configuration requires 14 steps for a
        # complete exploration and its minimal counterexample is 11 events,
        # so at bound 13 the exploration is truncated but the counterexample
        # is found: the run must report FAIL, not UNKNOWN.
        run = e5.run_model(
            e5.without_premise("pending_probe"), "bracket", 13
        )
        self.assertEqual(run["status"], "FAIL")
        self.assertFalse(run["explorationComplete"])
        self.assertGreater(run["incompleteTraces"], 0)
        self.assertGreater(run["violations"], 0)
        self.assertLess(run["bound"], run["requiredBound"])
        self.assertIsNotNone(run["counterexample"])


class ImportSafetyTests(unittest.TestCase):
    """Import-safe, side-effect-free, no subprocess/socket/network imports."""

    def _module_source(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "e5_model_check.py"
        )
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_no_subprocess_socket_or_network_imports(self):
        tree = ast.parse(self._module_source())
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.append(node.module)
        for name in imported:
            root = name.split(".")[0]
            self.assertNotIn(
                root, BANNED_IMPORT_ROOTS, "banned import: %s" % name
            )
        # The checker may only use the argparse/json/sys stdlib surface.
        self.assertEqual(
            sorted(set(imported)), ["__future__", "argparse", "json", "sys"]
        )

    def test_no_module_level_side_effects(self):
        tree = ast.parse(self._module_source())
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                continue
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                continue  # module docstring
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                for sub in ast.walk(node):
                    self.assertNotIsInstance(
                        sub, ast.Call, "module-level call found"
                    )
                continue
            if isinstance(node, ast.If):
                test = node.test
                self.assertIsInstance(test, ast.Compare)
                names = {
                    target.id
                    for target in ast.walk(test)
                    if isinstance(target, ast.Name)
                }
                strings = {
                    target.value
                    for target in ast.walk(test)
                    if isinstance(target, ast.Constant)
                    and isinstance(target.value, str)
                }
                self.assertEqual(names, {"__name__"})
                self.assertEqual(strings, {"__main__"})
                continue
            self.fail("unexpected module-level statement: %s" % ast.dump(node))

    def test_import_is_side_effect_free(self):
        # The module is already imported at the top of this test module; a
        # second import from a fresh interpreter context is covered by the
        # module-level statement audit above. Here we assert the imported
        # module exposes only constants/functions and no mutable global that
        # import time could have populated from the environment.
        for name in dir(e5):
            if name.startswith("__"):
                continue
            self.assertNotIsInstance(getattr(e5, name), io.IOBase)

    def test_docstring_states_abstract_evidence_boundary(self):
        doc = " ".join((e5.__doc__ or "").split())
        self.assertIn("ABSTRACT BOUNDED-MODEL EVIDENCE ONLY", doc)
        self.assertIn("NOT a mechanized proof", doc)
        self.assertIn("Rust", doc)
        self.assertIn("v2.1.0", doc)


class ReportSchemaTests(unittest.TestCase):
    """Required report fields, statuses, and JSON serializability."""

    def test_required_top_level_fields(self):
        for key in (
            "model",
            "modelVersion",
            "theorem",
            "bound",
            "exploredStates",
            "exploredTraces",
            "fullContract",
            "omissions",
            "status",
            "statusScope",
            "statusVocabulary",
            "scopeLimitations",
        ):
            self.assertIn(key, REPORT)
        self.assertEqual(REPORT["model"], e5.MODEL_NAME)
        self.assertEqual(REPORT["modelVersion"], "2.1.0")
        self.assertEqual(REPORT["theorem"], e5.THEOREM_ID)
        self.assertGreater(REPORT["exploredStates"], 0)
        self.assertGreater(REPORT["exploredTraces"], 0)

    def test_status_vocabulary_distinguishes_all_four_statuses(self):
        vocab = REPORT["statusVocabulary"]
        for status in ("PASS", "FAIL", "BLOCKED", "UNKNOWN"):
            self.assertIn(status, vocab)
            self.assertIsInstance(vocab[status], str)

    def test_blocked_is_reserved_and_never_emitted(self):
        # BLOCKED is part of the shared evidence vocabulary for a checker
        # that could not run; this in-process tool raises BoundError (API)
        # or exits with code 2 (CLI) before any report exists, so no status
        # field in any report may carry it.
        vocab = REPORT["statusVocabulary"]
        self.assertIn("BoundError", vocab["BLOCKED"])
        self.assertIn("code 2", vocab["BLOCKED"])
        statuses = [REPORT["status"], REPORT["fullContract"]["status"]]
        statuses += [run["status"] for run in REPORT["fullContract"]["modes"].values()]
        statuses += [entry["status"] for entry in REPORT["omissions"]]
        statuses += [entry["run"]["status"] for entry in REPORT["omissions"]]
        for status in statuses:
            self.assertNotEqual(status, "BLOCKED")

    def test_status_scope_separates_full_contract_from_omissions(self):
        scope = REPORT["statusScope"]
        self.assertIn("ONLY the full contract", scope)
        self.assertIn("omissions", scope)
        self.assertIn("independent single-premise status", scope)
        # The top-level status equals the full-contract status and is not an
        # aggregate over the omission results (all six of which FAIL).
        self.assertEqual(REPORT["status"], REPORT["fullContract"]["status"])
        self.assertEqual(REPORT["status"], "PASS")

    def test_scope_limitations_cover_structural_assumptions(self):
        limitations = " ".join(REPORT["scopeLimitations"])
        for assumption in (
            "does not suppress them",            # liberated decision tail
            "NO admission-side watermark and NO admission-time pending re-derivation",
            "not by any admission-time check",   # fence scope: read gate only
            "t_f is m0",                         # theorem anchor
            "m0 < p0 < m1 < p1",                 # ordered final load
            "latched",                           # read-time latch semantics
            "EVIDENCE_BODY_ADVANCE",             # two sub-event publication
            "torn",
            "decisive",                          # FAIL-vs-UNKNOWN precedence
            "independent single-premise results",      # omission status meaning
            "ONLY the full contract",            # top-level status scope
            "BoundError",                        # BLOCKED non-emission
            "not a mechanized proof",            # evidence boundary
            "never counted as violations",       # overlap boundary
        ):
            self.assertIn(assumption, limitations, assumption)

    def test_full_contract_meaning_is_qualified(self):
        meaning = REPORT["fullContract"]["meaning"]
        self.assertIn("abstract bounded property only", meaning)
        self.assertIn("scopeLimitations", meaning)
        self.assertIn("NO admission-time re-derivation and NO admission-side "
                      "watermark", meaning)
        self.assertIn("latched unsafe pending delta", meaning)
        self.assertIn("not evidence about the production implementation", meaning)
        self.assertIn("strictly before t_f", meaning)

    def test_omission_entries_shape(self):
        self.assertEqual(len(REPORT["omissions"]), len(e5.PREMISES))
        self.assertEqual(
            [entry["premise"] for entry in REPORT["omissions"]],
            list(e5.PREMISES),
        )
        for entry in REPORT["omissions"]:
            for key in (
                "premise",
                "premiseRemoved",
                "status",
                "finding",
                "intendedSchedule",
                "counterexample",
                "note",
                "run",
            ):
                self.assertIn(key, entry, (entry["premise"], key))
            self.assertEqual(entry["premise"], entry["premiseRemoved"])
            self.assertIn(entry["status"], ("PASS", "FAIL", "BLOCKED", "UNKNOWN"))
            counterexample = entry["counterexample"]
            if counterexample is not None:
                for key in (
                    "scheduleClass",
                    "domain",
                    "staleAtAdmission",
                    "eventCount",
                    "reads",
                    "pendingObservations",
                    "trace",
                ):
                    self.assertIn(key, counterexample)
                self.assertEqual(counterexample["domain"], "strictly_before")
                self.assertTrue(counterexample["staleAtAdmission"])

    def test_report_is_json_serializable(self):
        payload = json.dumps(REPORT)
        parsed = json.loads(payload)
        self.assertEqual(parsed["model"], REPORT["model"])
        self.assertIn("not a mechanized proof", " ".join(REPORT["scopeLimitations"]))


class CliTests(unittest.TestCase):
    """CLI behavior without subprocesses: call main() in-process."""

    def test_json_cli_produces_parseable_report(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = e5.main(["--max-steps", "17", "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(buffer.getvalue())
        self.assertEqual(parsed["bound"], 17)
        self.assertEqual(parsed["fullContract"]["status"], "PASS")

    def test_text_cli_produces_summary(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = e5.main(["--max-steps", "8"])
        self.assertEqual(code, 0)
        text = buffer.getvalue()
        # Bound 8 is below both modes' required bounds: the honest summary
        # reports UNKNOWN, never PASS.
        self.assertIn("fullContract status: UNKNOWN", text)
        self.assertIn("abstract bounded-model evidence ONLY", text)
        self.assertIn("Status scope", text)

    def test_default_bound_flag_used(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = e5.main(["--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["bound"], e5.DEFAULT_BOUND)

    def test_invalid_bound_cli_exits_with_code_2(self):
        for argv in (["--max-steps", "0"], ["--max-steps", "999"], ["--max-steps", "abc"]):
            with self.assertRaises(SystemExit) as ctx:
                buffer = io.StringIO()
                with redirect_stdout(buffer), redirect_stderr(buffer):
                    e5.main(argv)
            self.assertEqual(ctx.exception.code, 2, argv)


if __name__ == "__main__":
    unittest.main()
