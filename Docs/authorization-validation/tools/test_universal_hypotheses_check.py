"""Offline tests locking the universal-hypothesis checker results.

These tests pin the strong, universal properties of the bounded
admission-safety model checked by ``universal_hypotheses_check.py``:
the theorem-domain safety in both observation modes, the domain
accounting conservation, the latch/window universality, the torn-read
integrity, the post-t_f accounting, the premise-necessity lattice, the
omission sharpness mapping, the bound discipline, the mode
independence, and the report conservation.

A rename or semantic change on either side (model or checker) must fail
here and force an explicit sync. Run:

    python -m unittest discover -s Docs/authorization-validation/tools \
        -t Docs/authorization-validation/tools -p "test_universal_hypotheses_check.py" -v

Bound 16 is the maximum required bound over all checked configurations
(full contract, bracket mode: 1 + 15 events); every configuration's
exploration is complete at it, so the verdicts equal the default-bound
verdicts while keeping the suite offline-fast.
"""

import unittest

import e5_model_check as model
import universal_hypotheses_check as uhc

FAST_BOUND = 16


class UniversalHypothesesTest(unittest.TestCase):
    """All universal hypotheses must PASS over the bounded model."""

    @classmethod
    def setUpClass(cls):
        cls.report = uhc.check_universal_hypotheses(FAST_BOUND)

    def test_overall_status_pass(self):
        self.assertEqual(self.report["status"], "PASS")

    def test_every_hypothesis_passes(self):
        for entry in self.report["hypotheses"]:
            self.assertEqual(
                entry["status"],
                "PASS",
                "%s failed: %s" % (entry["id"], entry["statement"]),
            )

    def test_no_findings(self):
        self.assertEqual(self.report["findings"], [])

    def test_u1_theorem_domain_safety_both_modes(self):
        for mode, item in self.report["hypotheses"][0]["evidence"].items():
            self.assertEqual(item["status"], "PASS", mode)
            self.assertTrue(item["explorationComplete"], mode)
            self.assertEqual(item["admittedStrictlyBefore"], 0, mode)

    def test_u3_window_enumerated_and_always_denied(self):
        for mode, item in self.report["hypotheses"][2]["evidence"].items():
            self.assertGreater(
                item["staleCommitPublishAfterLastReadTraces"], 0, mode
            )
            self.assertEqual(
                item["admittedStaleCommitPublishAfterLastRead"], 0, mode
            )
            self.assertTrue(item["pendingProbeLatchDenials"], mode)

    def test_u6_lattice_covers_all_62_proper_subsets(self):
        evidence = self.report["hypotheses"][5]["evidence"]
        self.assertEqual(evidence["subsetsChecked"], 62)
        self.assertEqual(evidence["violatingSubsets"], 62)
        self.assertEqual(evidence["candidateSufficientSubsets"], [])

    def test_u7_sharpness_mapping_locked(self):
        evidence = self.report["hypotheses"][6]["evidence"]
        self.assertEqual(
            sorted(evidence), sorted(uhc.OMISSION_SCHEDULE_CLASS)
        )
        for premise, item in evidence.items():
            self.assertEqual(item["status"], "FAIL", premise)
            self.assertEqual(
                item["observedScheduleClass"],
                uhc.OMISSION_SCHEDULE_CLASS[premise],
                premise,
            )

    def test_u9_mode_independence(self):
        evidence = self.report["hypotheses"][8]["evidence"]
        self.assertEqual(
            {item["status"] for item in evidence.values()}, {"PASS"}
        )
        self.assertEqual(set(evidence), {"bracket", "strict"})


class BoundDisciplineTest(unittest.TestCase):
    """U8 spot checks: an insufficient bound can never mint a PASS."""

    def test_full_contract_below_required_bound_is_unknown(self):
        prem = model.normalize_premises()
        required = model.required_bound(prem, "bracket")
        self.assertGreaterEqual(required - 1, model.MIN_BOUND)
        run = model.run_model(prem, "bracket", required - 1)
        self.assertNotEqual(run["status"], "PASS")
        self.assertGreater(run["incompleteTraces"], 0)

    def test_full_contract_complete_at_required_bound(self):
        for mode in ("bracket", "strict"):
            prem = model.normalize_premises()
            required = model.required_bound(prem, mode)
            run = model.run_model(prem, mode, required)
            self.assertTrue(run["explorationComplete"], mode)
            self.assertEqual(run["violations"], 0, mode)

    def test_omission_counterexample_is_decisive_when_incomplete(self):
        # A decisive counterexample survives bound truncation: the
        # minimal host_mediation violation (5 events) is far below the
        # required bound, so the omission stays FAIL one step below it.
        prem = model.without_premise("host_mediation")
        required = model.required_bound(prem, "bracket")
        run = model.run_model(prem, "bracket", required - 1)
        self.assertEqual(run["status"], "FAIL")
        self.assertGreater(run["violations"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
