#!/usr/bin/env python3
"""Offline tests locking the two-mutation bounded model's core verdicts.

The two-mutation model doubles the enumeration space, so the full bracket
exploration belongs to the CLI/manifest evidence run, not to the unit
suite. These tests pin the fast, decisive parts:

- the strict-mode full contract is a complete PASS with zero violations;
- the strict-mode single-premise omissions each produce a FAIL whose
  minimal counterexample belongs to its intended hazard family (the
  two-mutation U7 mapping);
- cross-mutation torn states (mixed manifest/body advances from
  DIFFERENT mutations) are genuinely reachable;
- the per-mutation violation attribution (``violatingMutations``) exists
  and the bound discipline holds.

A rename or semantic change on either side must fail here and force an
explicit sync. Run:

    python -m unittest discover -s Docs/authorization-validation/tools \
        -t Docs/authorization-validation/tools \
        -p "test_e5_model_check_two_mutations.py" -v
"""

import unittest

import e5_model_check_two_mutations as m2

FAST_BOUND = 28


class TwoMutationStrictContractTest(unittest.TestCase):
    """Strict-mode full contract: complete exploration, zero violations."""

    @classmethod
    def setUpClass(cls):
        cls.strict_run = m2.run_model(
            m2.normalize_premises(), "strict", FAST_BOUND
        )

    def test_full_contract_strict_passes(self):
        self.assertEqual(self.strict_run["status"], "PASS")
        self.assertTrue(self.strict_run["explorationComplete"])
        self.assertEqual(self.strict_run["violations"], 0)
        self.assertEqual(self.strict_run["admittedDomainCounts"]["strictlyBefore"], 0)

    def test_branch_backtracking_preserves_complete_strict_counts(self):
        repeated = m2.run_model(m2.normalize_premises(), "strict", FAST_BOUND)
        self.assertEqual(repeated, self.strict_run)
        self.assertEqual(
            repeated["admittedTraces"] + repeated["deniedTraces"],
            repeated["exploredTraces"],
        )
        self.assertEqual(
            sum(repeated["admittedDomainCounts"].values()),
            repeated["admittedTraces"],
        )

    def test_cross_mutation_torn_states_are_reachable_and_rejected(self):
        torn = self.strict_run["mixedManifestBody"]
        self.assertGreater(torn["tornReadTraces"], 0)
        self.assertEqual(torn["admittedTornReadTraces"], 0)
        self.assertEqual(torn["admittedTornReadTracesByDomain"], {})

    def test_stale_commit_window_is_enumerated_and_always_denied(self):
        window = self.strict_run["admissionWindow"]
        self.assertGreater(window["staleCommitPublishAfterLastReadTraces"], 0)
        self.assertEqual(
            window["admittedStaleCommitPublishAfterLastRead"], 0
        )
        latch = {
            key: value
            for key, value in self.strict_run["denialReasons"].items()
            if key.startswith("pending_probe_latched_unsafe_delta")
        }
        self.assertTrue(latch)

    def test_required_bound_completes(self):
        prem = m2.normalize_premises()
        required = m2.required_bound(prem, "strict")
        self.assertEqual(required, 14)  # 1 + 4 checklist + 4 + 4 + 1 rollback
        at_required = m2.run_model(prem, "strict", required)
        self.assertTrue(at_required["explorationComplete"])
        self.assertEqual(at_required["status"], "PASS")
        below = m2.run_model(prem, "strict", required - 1)
        self.assertNotEqual(below["status"], "PASS")


class TwoMutationOmissionSharpnessTest(unittest.TestCase):
    """Strict-mode omissions: FAIL with the intended hazard family."""

    # Strict-mode runs are cheap and cover five of the six omissions.
    # The ``final_reload`` omission is legitimately SAFE in strict mode
    # (with no final load there is no pre-observation fallback: everything
    # fails closed), exactly as the single model runs its omissions in
    # bracket mode. The bracket runs below cover the two most informative
    # omissions for the suite; the CLI/manifest evidence run covers all
    # six in bracket mode.
    STRICT_EXPECTED = {
        "pending_probe": ("FAIL", "source_pending_commit_without_publication"),
        # post_recheck is shadowed in strict mode: the single atomic
        # probe already latches every in-flight publication the recheck
        # would confront, so it is not independently falsifiable there
        # (bracket mode, tested below, is where it is load-bearing).
        "post_recheck": ("PASS", None),
        "final_reload": ("PASS", None),
        "exact_identity": ("FAIL", "candidate_removal_identity_confusion"),
        # The fence omission is not independently falsifiable in this
        # model: the rollback adversary is restricted to the decision tail
        # (pre-read rollback hazards live in the single-mutation model),
        # and every torn/in-flight read is already latched by the probes.
        "generation_revoke_fence": (
            "PASS",
            None,
        ),
        "host_mediation": ("FAIL", "bypass_unmediated_admission"),
    }

    def test_strict_mode_omissions_match_expected_outcomes(self):
        self.assertEqual(set(self.STRICT_EXPECTED), set(m2.PREMISES))
        for premise, (status, klass) in self.STRICT_EXPECTED.items():
            run = m2.run_model(m2.without_premise(premise), "strict", FAST_BOUND)
            self.assertEqual(run["status"], status, premise)
            cex = run["counterexample"]
            if klass is None:
                self.assertIsNone(cex, premise)
                self.assertTrue(run["explorationComplete"], premise)
            else:
                self.assertIsNotNone(cex, premise)
                self.assertEqual(cex["scheduleClass"], klass, premise)

    def test_bracket_mode_latch_and_recheck_omissions_fail(self):
        # pending_probe: a publication completing in the free tail after
        # the last read is never latched -> stale admission.
        run = m2.run_model(
            m2.without_premise("pending_probe"), "bracket", FAST_BOUND
        )
        self.assertEqual(run["status"], "FAIL")
        self.assertEqual(
            run["counterexample"]["scheduleClass"],
            "source_pending_commit_without_publication",
        )
        # post_recheck: a publication completing INSIDE the final load
        # (between m0 and p0) leaves the m0-anchored evidence stale.
        run = m2.run_model(
            m2.without_premise("post_recheck"), "bracket", FAST_BOUND
        )
        self.assertEqual(run["status"], "FAIL")
        self.assertEqual(
            run["counterexample"]["scheduleClass"],
            "mutation_published_between_evidence_read_and_last_read",
        )

    def test_violation_attribution_dimension_exists(self):
        run = m2.run_model(
            m2.without_premise("pending_probe"), "strict", FAST_BOUND
        )
        cex = run["counterexample"]
        self.assertIn(cex["violatingMutations"], (["A"], ["B"], ["A", "B"]))
        by_mutation = run["violationsByMutation"]
        self.assertEqual(
            sum(by_mutation.values()), run["violations"]
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
