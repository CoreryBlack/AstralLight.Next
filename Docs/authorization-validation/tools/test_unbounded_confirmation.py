#!/usr/bin/env python3
"""Offline tests locking the unbounded-confirmation checker's verdicts.

Pins: event-space closure (every chain carries unique events, so the
merge space is the entire schedule space), bound invariance at MAX_BOUND
(the step bound neither truncates nor alters outcomes), and the honest
UNKNOWN obligations for parameter unboundedness (C3) and abstraction
unboundedness (C4). Run:

    python -m unittest discover -s Docs/authorization-validation/tools \
        -t Docs/authorization-validation/tools \
        -p "test_unbounded_confirmation.py" -v
"""

import unittest

import unbounded_confirmation as uc


class UnboundedConfirmationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # C2 on the single model keeps the suite fast; the two-mutation
        # model's MAX_BOUND confirmation runs via the CLI evidence path.
        cls.report = uc.check_unbounded_confirmation(models=("single",))

    def test_overall_status_pass(self):
        self.assertEqual(self.report["status"], "PASS")

    def test_decidable_checks_pass(self):
        statuses = {
            entry["id"]: entry["status"] for entry in self.report["hypotheses"]
        }
        self.assertEqual(statuses["C1"], "PASS")
        self.assertEqual(statuses["C2"], "PASS")

    def test_c1_event_space_closure_clean(self):
        evidence = self.report["hypotheses"][0]["evidence"]
        self.assertEqual(evidence["singleModelProblems"], [])
        self.assertEqual(evidence["twoMutationModelProblems"], [])

    def test_c2_bound_invariance_every_configuration(self):
        evidence = self.report["hypotheses"][1]["evidence"]
        self.assertEqual(
            sorted(evidence), ["single/bracket", "single/strict"]
        )
        for item in evidence.values():
            self.assertTrue(item["boundInvariant"], item)

    def test_c3_c4_are_explicit_obligations_not_failures(self):
        statuses = {
            entry["id"]: entry["status"] for entry in self.report["hypotheses"]
        }
        self.assertEqual(statuses["C3"], "UNKNOWN")
        self.assertEqual(statuses["C4"], "UNKNOWN")
        statement = self.report["hypotheses"][2]["statement"]
        self.assertIn("reduction lemma", statement)
        c3 = self.report["hypotheses"][2]["evidence"]
        self.assertIn("no new violating family appears at N=2",
                      c3["familyComparison"])
        c4 = self.report["hypotheses"][3]["evidence"]
        self.assertEqual(c4["tlaStatus"], "BLOCKED (no pinned checksum-verified TLC/TLAPS)")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
