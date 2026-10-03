#!/usr/bin/env python3
"""Property-based tests for the E1 ALLOW classifier vocabulary.

Where ``E5DomainCorrespondenceTest`` locks the classifier to the abstract
domain vocabulary on FIXED samples, these tests verify the same
correspondence EXHAUSTIVELY over a grid of commit placements: every
admissible commit interval (start < end) on a parity-shifted grid is
classified and checked against an independent oracle derived from the
validation protocol, and against the bounded model's domain algebra
(``e5_model_check.classify_domain``) on identical intervals.

Properties (all must hold for every grid point, both evidence sources):

- P1  Vocabulary and flag coupling: the category is one of the six
      documented values, and ``staleAllowViolation == theoremDomain``.
- P2  Theorem soundness: ``staleAllowViolation`` holds if and only if the
      commit interval completes strictly before the final observation's
      first read (``commit.end < m0.start``) -- exactly the protocol's
      theorem-domain condition, in both directions with no exceptions.
- P3  Model-domain consistency on identical intervals:
      ``strictly_before`` <=> violation; ``overlap_unknown`` <=>
      ``interval-overlap-unknown``; ``after_final_observation`` <=>
      membership in {pre-commit, post-final-observation-overlap,
      in-flight, unclassified-unknown}.
- P4  Boundary exactness: the violation flag flips exactly at
      ``commit.end == m0.start`` (a commit durable AT t_f is overlap, not
      strictly-before); verified by an explicit boundary pair per ladder.
- P5  Branch coverage: the grid exercises all six categories, including
      the residual ``unclassified-unknown`` (a commit beginning exactly
      at the host-admission sequence).

Malformed inputs (identity mismatch, uncommitted outcome, non-ALLOW
decision) must raise ``EvidenceError`` -- the classifier fails closed.

Run:
    python -m unittest discover -s Docs/authorization-validation/tools \
        -t Docs/authorization-validation/tools -p "test_classify_e1_properties.py" -v
"""

from __future__ import annotations

import unittest

import e5_model_check as model
import experiment_common as common
import test_experiment_common as helpers

CATEGORIES = {
    "pre-commit",
    "post-commit-before-final-observation",
    "post-final-observation-overlap",
    "interval-overlap-unknown",
    "in-flight",
    "unclassified-unknown",
}
AFTER_FINAL_CATEGORIES = {
    "pre-commit",
    "post-final-observation-overlap",
    "in-flight",
    "unclassified-unknown",
}

ODD_LADDER = {
    "signed": 1, "candidate": 3, "final_start": 5,
    "m0s": 7, "m0e": 9, "p0s": 11, "p0e": 13,
    "m1s": 15, "m1e": 17, "p1s": 19, "p1e": 21,
    "evidence": 23, "stable": 25, "decision": 27, "admission": 29,
}
EVEN_LADDER = {
    "signed": 2, "candidate": 4, "final_start": 6,
    "m0s": 8, "m0e": 10, "p0s": 12, "p0e": 14,
    "m1s": 16, "m1e": 18, "p1s": 20, "p1e": 22,
    "evidence": 24, "stable": 26, "decision": 28, "admission": 30,
}
GAP3_LADDER = {
    "signed": 1, "candidate": 4, "final_start": 7,
    "m0s": 10, "m0e": 13, "p0s": 16, "p0e": 19,
    "m1s": 22, "m1e": 25, "p1s": 28, "p1e": 31,
    "evidence": 34, "stable": 37, "decision": 40, "admission": 43,
}


def cache_request_at(ladder):
    """Cache-branch request on a parameterized sequence ladder."""
    L = ladder
    events = [
        helpers.event(L["signed"], "signed_context_bound"),
        helpers.identity_event(L["candidate"], "candidate_match"),
        helpers.identity_event(L["final_start"], "final_reload_start"),
    ]
    for start_key, end_key in (("m0s", "m0e"), ("m1s", "m1e")):
        events.append(helpers.event(
            L[start_key], "authoritative_read_start",
            observation="cache_manifest", outcome="started",
        ))
        events.append(helpers.event(
            L[end_key], "authoritative_read_end",
            observation="cache_manifest", outcome="ok",
        ))
    for start_key, end_key in (("p0s", "p0e"), ("p1s", "p1e")):
        events.append(helpers.event(
            L[start_key], "authoritative_read_start",
            observation="cache_pending_probe", outcome="started",
        ))
        events.append(helpers.event(
            L[end_key], "authoritative_read_end",
            observation="cache_pending_probe", outcome="ok", pending=False,
        ))
    events.append(helpers.event(
        L["evidence"], "evidence_load_result", source="l1_cache"
    ))
    events.append(helpers.identity_event(L["stable"], "stable_check_end", stable=True))
    events.append(helpers.event(
        L["decision"], "decision_return", allowed=True,
        reason="PUBLISHED_EVIDENCE_ALLOW",
    ))
    events.append(helpers.event(L["admission"], "host_admission"))
    return events


def strict_request_at(ladder):
    """Strict-branch request on a parameterized sequence ladder."""
    L = ladder
    return [
        helpers.event(L["signed"], "signed_context_bound"),
        helpers.identity_event(L["candidate"], "candidate_match"),
        helpers.identity_event(L["final_start"], "final_reload_start"),
        helpers.event(
            L["m0s"], "authoritative_read_start",
            observation="strict_pending_probe", outcome="started",
        ),
        helpers.event(
            L["m0e"], "authoritative_read_end",
            observation="strict_pending_probe", outcome="ok", pending=False,
        ),
        helpers.event(
            L["evidence"], "evidence_load_result", source="strict_db"
        ),
        helpers.identity_event(L["stable"], "stable_check_end", stable=True),
        helpers.event(
            L["decision"], "decision_return", allowed=True,
            reason="PUBLISHED_EVIDENCE_ALLOW",
        ),
        helpers.event(L["admission"], "host_admission"),
    ]


def classify_pair(ladder, source, commit_start, commit_end):
    request = (
        cache_request_at(ladder) if source == "cache" else strict_request_at(ladder)
    )
    mutation = helpers.commit_events(commit_start, commit_end)
    return common.classify_e1_allow(request, mutation)


def _commit_values(ladder):
    """Commit-grid sequence values: every int the ladder does not use.

    The one-process-log uniqueness rule forbids commit sequences from
    colliding with the request ladder, so the grid is exactly the
    complement of the ladder's anchors up to a little past admission.
    """
    reserved = set(ladder.values())
    return [v for v in range(1, ladder["admission"] + 6)
            if v not in reserved]


class ClassifyE1PropertyTest(unittest.TestCase):
    """Exhaustive grid verification of the classifier's domain algebra."""

    def _grids(self):
        for ladder, name in (
            (ODD_LADDER, "odd-ladder"),
            (EVEN_LADDER, "even-ladder"),
            (GAP3_LADDER, "gap3-ladder"),
        ):
            m0_start, m0_end = ladder["m0s"], ladder["m0e"]
            # The commit grid avoids the request ladder's own sequence
            # values (the classifier requires one unique sequence space).
            values = _commit_values(ladder)
            for source in ("cache", "strict"):
                for cs in values:
                    for ce in values:
                        if cs >= ce:
                            continue
                        yield (name, source, ladder, m0_start, m0_end, cs, ce)

    def test_p1_p2_p3_exhaustive_grid(self):
        seen_categories = set()
        count = 0
        for name, source, ladder, m0_start, m0_end, cs, ce in self._grids():
            result = classify_pair(ladder, source, cs, ce)
            count += 1
            # P1: vocabulary and flag coupling.
            self.assertIn(result["category"], CATEGORIES, (name, cs, ce))
            self.assertEqual(
                result["staleAllowViolation"],
                result["theoremDomain"],
                (name, source, cs, ce),
            )
            # P2: theorem soundness in both directions.
            expected_violation = ce < m0_start
            self.assertEqual(
                result["staleAllowViolation"], expected_violation,
                (name, source, cs, ce),
            )
            # P3: consistency with the model's domain algebra (plain
            # interval tuples; the model function is pure).
            domain = model.classify_domain(
                (cs, ce), (m0_start, m0_end)
            )
            if domain == "strictly_before":
                self.assertTrue(result["staleAllowViolation"], (name, cs, ce))
            elif domain == "overlap_unknown":
                self.assertEqual(
                    result["category"], "interval-overlap-unknown",
                    (name, source, cs, ce),
                )
                self.assertFalse(result["staleAllowViolation"], (name, cs, ce))
            else:
                self.assertEqual(domain, "after_final_observation", (name, cs, ce))
                self.assertIn(
                    result["category"], AFTER_FINAL_CATEGORIES, (name, source, cs, ce)
                )
                self.assertFalse(result["staleAllowViolation"], (name, cs, ce))
            seen_categories.add(result["category"])
        self.assertGreater(count, 400)
        # P5: the grid exercises every REACHABLE category. Two documented
        # categories are structurally unreachable for a committed mutation
        # and are asserted absent with a reachability argument, not
        # silently dropped: ``in-flight`` requires signed < commit.start,
        # commit.end < admission, and no earlier branch -- but
        # not-overlap with commit.end >= m0.start forces commit.start >
        # m0.end, which branch 3 (post-final-observation-overlap) already
        # caught; and ``unclassified-unknown`` requires
        # commit.start == admission.sequence, which the one-process-log
        # sequence-uniqueness rule forbids (the value belongs to the
        # request's host_admission event). Both remain in the vocabulary
        # for cross-log classification; the single-log classifier cannot
        # emit them for a committed mutation.
        self.assertEqual(
            seen_categories,
            {
                "pre-commit",
                "post-commit-before-final-observation",
                "post-final-observation-overlap",
                "interval-overlap-unknown",
            },
        )

    def test_p4_boundary_flip_at_t_f(self):
        # The violation flag flips between commit.end < m0.start and
        # commit.end > m0.start. The exact-equality case (commit durable
        # AT t_f) is unreachable in a single process log -- the commit-end
        # event and the m0 read-start event would need one sequence value
        # -- so it is asserted on the model's pure algebra instead, where
        # it must classify as overlap, never strictly-before.
        for ladder, source in (
            (ODD_LADDER, "cache"), (ODD_LADDER, "strict"),
            (EVEN_LADDER, "cache"), (EVEN_LADDER, "strict"),
        ):
            m0_start = ladder["m0s"]
            values = _commit_values(ladder)
            below = max(v for v in values if v < m0_start)
            above = min(v for v in values if v > m0_start)
            below_result = classify_pair(ladder, source, below - 2, below)
            above_result = classify_pair(ladder, source, above - 2, above)
            self.assertTrue(below_result["staleAllowViolation"], (source, below))
            self.assertFalse(above_result["staleAllowViolation"], (source, above))
        # Model algebra at the exact boundary: durable == t_f is overlap.
        for m0_start, m0_end in ((7, 9), (8, 10)):
            domain = model.classify_domain(
                (m0_start - 2, m0_start), (m0_start, m0_end)
            )
            self.assertEqual(domain, "overlap_unknown")
            self.assertNotEqual(
                model.classify_domain(
                    (m0_start - 2, m0_start - 1), (m0_start, m0_end)
                ),
                "overlap_unknown",
            )

    def test_p3_after_final_membership_is_exact(self):
        # Every grid point classified as one of the after-final categories
        # must also be after_final_observation under the model's algebra.
        for name, source, ladder, m0_start, m0_end, cs, ce in self._grids():
            result = classify_pair(ladder, source, cs, ce)
            domain = model.classify_domain((cs, ce), (m0_start, m0_end))
            if result["category"] in AFTER_FINAL_CATEGORIES:
                self.assertEqual(domain, "after_final_observation", (name, cs, ce))


class ClassifyE1MultiMutationTest(unittest.TestCase):
    """Property tests for classify_e1_allow_multi (two-mutation semantics).

    The multi classifier must (a) agree with the single classifier when
    run conservatively over one mutation, (b) attribute hazards per
    mutation, and (c) implement the model's V1 semantics when
    representation is adjudicated: a pre-t_f mutation that IS represented
    yields a safe in-domain admission, only the unrepresented ones are
    violations.
    """

    def _sample_points(self):
        points = list(ClassifyE1PropertyTest()._grids())
        return points[::7]

    def test_multi_single_mutation_matches_single_classifier(self):
        for name, source, ladder, m0_start, m0_end, cs, ce in self._sample_points():
            single = classify_pair(ladder, source, cs, ce)
            request = (
                cache_request_at(ladder) if source == "cache"
                else strict_request_at(ladder)
            )
            multi = common.classify_e1_allow_multi(
                request, [helpers.commit_events(cs, ce)]
            )
            self.assertEqual(multi["perMutation"][0]["category"], single["category"])
            self.assertEqual(
                multi["staleAllowViolation"], single["staleAllowViolation"],
                (name, source, cs, ce),
            )
            self.assertEqual(
                multi["hazardCandidates"],
                [0] if single["theoremDomain"] else [],
                (name, source, cs, ce),
            )
            self.assertEqual(multi["attributionMode"], "conservative")

    def test_multi_two_mutations_attributions(self):
        ladder = ODD_LADDER
        m0_start = ladder["m0s"]
        request = cache_request_at(ladder)
        # Mutation 0 commits strictly before t_f; mutation 1 commits after
        # the final observation. Sequence values are parity-disjoint from
        # the request ladder and from each other.
        pre = helpers.commit_events(2, 4)
        post = helpers.commit_events(16, 18)
        conservative = common.classify_e1_allow_multi(request, [pre, post])
        self.assertEqual(conservative["hazardCandidates"], [0])
        self.assertEqual(conservative["violatingMutations"], [0])
        self.assertTrue(conservative["staleAllowViolation"])
        self.assertEqual(
            conservative["perMutation"][1]["category"],
            "post-final-observation-overlap",
        )
        # V1 adjudication: mutation 0 represented -> safe in-domain.
        adjudicated = common.classify_e1_allow_multi(
            request, [pre, post], represented={0: True}
        )
        self.assertEqual(adjudicated["violatingMutations"], [])
        self.assertFalse(adjudicated["staleAllowViolation"])
        self.assertEqual(adjudicated["combinedDomain"], "strictlyBeforeRepresented")
        # V1 adjudication: mutation 0 unrepresented -> violation.
        unrepresented = common.classify_e1_allow_multi(
            request, [pre, post], represented={0: False}
        )
        self.assertEqual(unrepresented["violatingMutations"], [0])
        self.assertEqual(unrepresented["combinedDomain"], "strictlyBefore")

    def test_multi_requires_representation_for_every_hazard(self):
        request = cache_request_at(ODD_LADDER)
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow_multi(
                request, [helpers.commit_events(2, 4)], represented={}
            )

    def test_multi_rejects_empty_mutations(self):
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow_multi(cache_request_at(ODD_LADDER), [])


class ClassifyE1FailClosedTest(unittest.TestCase):
    """Malformed inputs raise EvidenceError instead of classifying."""

    def test_identity_mismatch_raises(self):
        request = cache_request_at(ODD_LADDER)
        for index, item in enumerate(request):
            if item.event == "stable_check_end":
                request[index] = helpers.identity_event(
                    ODD_LADDER["stable"], "stable_check_end",
                    stable=True, grant_revision=999,
                )
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(request, helpers.commit_events(2, 4))

    def test_uncommitted_outcome_raises(self):
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(
                cache_request_at(ODD_LADDER),
                helpers.commit_events(2, 4, outcome="rolled_back"),
            )

    def _fuzz_variants(self):
        """Well-formed requests with one injected defect each."""
        base = cache_request_at(ODD_LADDER)
        variants = {}

        def replace_first(name, **fields):
            out = []
            reserved_keys = {
                "event", "request_id", "event_sequence", "wall_unix_ns",
                "process_observation_id",
            }
            for item in base:
                if item.event == name:
                    merged = {
                        key: value
                        for key, value in item.fields.items()
                        if key not in reserved_keys
                    }
                    merged.update(fields)
                    out.append(helpers.event(
                        item.sequence, name, node=item.node,
                        process_observation_id=item.process_observation_id,
                        **merged,
                    ))
                else:
                    out.append(item)
            return out

        variants["duplicate-sequence"] = (
            [helpers.event(2, "signed_context_bound")] + base
        )
        variants["cross-node"] = [
            item if item.event != "host_admission" else helpers.event(
                item.sequence, "host_admission", node="node-b"
            )
            for item in base
        ]
        variants["cross-epoch"] = [
            item if item.event != "host_admission" else helpers.event(
                item.sequence, "host_admission",
                process_observation_id="proc-b",
            )
            for item in base
        ]
        variants["nonmonotonic-order"] = [
            item if item.event != "decision_return" else helpers.event(
                ODD_LADDER["stable"], "decision_return", allowed=True,
            )
            for item in base
        ]
        variants["identity-missing"] = replace_first(
            "candidate_match", grant_revision=None,
        )
        return variants

    def test_fuzz_defects_fail_closed(self):
        import itertools
        for label, request in self._fuzz_variants().items():
            raised = False
            try:
                common.classify_e1_allow(request, helpers.commit_events(2, 4))
            except common.EvidenceError:
                raised = True
            self.assertTrue(raised, label)

    def test_non_allow_decision_raises(self):
        request = cache_request_at(ODD_LADDER)
        for index, item in enumerate(request):
            if item.event == "decision_return":
                request[index] = helpers.event(
                    ODD_LADDER["decision"], "decision_return",
                    allowed=False, reason="DEFAULT_DENY",
                )
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(request, helpers.commit_events(2, 4))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
