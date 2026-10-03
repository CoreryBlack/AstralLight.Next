"""Pure tests for S15 selection and coverage classification."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import s15_validation


class S15SelectionValidationTests(unittest.TestCase):
    def test_rejects_nonpositive_rounds_before_run_setup(self) -> None:
        for rounds in (0, -1, True):
            with self.subTest(rounds=rounds):
                self.assertIn(
                    "rounds_must_be_positive",
                    s15_validation.validate_run_selection(rounds, None),
                )

    def test_rejects_unknown_empty_and_whitespace_only_scenarios(self) -> None:
        self.assertEqual(
            s15_validation.validate_run_selection(3, ["S2", "S99"]),
            ["unknown_only:S99"],
        )
        self.assertIn(
            "only_must_select_at_least_one_scenario",
            s15_validation.validate_run_selection(3, []),
        )
        normalized = [part.strip() for part in "S2, ,S4".split(",") if part.strip()]
        self.assertEqual(normalized, ["S2", "S4"])

    def test_required_case_coverage_and_nonpass_are_distinct(self) -> None:
        selected = ["S1"]
        required = s15_validation.REQUIRED_CASES["S1"]
        self.assertEqual(
            s15_validation.missing_required_cases(selected, required[:-1]),
            {"S1": [required[-1]]},
        )
        verdicts = {case: "PASS" for case in required}
        verdicts[required[0]] = "N/A"
        self.assertEqual(
            s15_validation.missing_required_cases(selected, verdicts),
            {},
            "a recorded N/A exists but must fail the positive PASS predicate",
        )
        self.assertEqual(
            s15_validation.missing_nonpass_cases(selected, verdicts),
            {"S1": [required[0]]},
        )

    def test_scoped_or_incomplete_runs_are_partial_not_complete(self) -> None:
        required = s15_validation.REQUIRED_CASES["S1"]
        verdicts = {case: "PASS" for case in required}
        partial = s15_validation.campaign_coverage(
            rounds=3,
            rounds_done=3,
            only=["S1"],
            round_missing_cases=[{}, {}, {}],
            round_case_verdicts=[verdicts, verdicts, verdicts],
        )
        self.assertFalse(partial["complete"])
        self.assertEqual(partial["scope"], "partial")
        incomplete = s15_validation.campaign_coverage(
            rounds=3,
            rounds_done=3,
            only=None,
            round_missing_cases=[{"S1": [required[0]]}, {}, {}],
            round_case_verdicts=[verdicts, verdicts, verdicts],
        )
        self.assertFalse(incomplete["complete"])

    def test_full_scope_requires_three_rounds_and_positive_cases(self) -> None:
        selected = list(s15_validation.SCENARIO_NAMES)
        verdicts = {
            case: "PASS"
            for scenario in selected
            for case in s15_validation.REQUIRED_CASES[scenario]
        }
        full = s15_validation.campaign_coverage(
            rounds=3,
            rounds_done=3,
            only=None,
            round_missing_cases=[{}, {}, {}],
            round_case_verdicts=[verdicts, verdicts, verdicts],
        )
        self.assertTrue(full["complete"])
        self.assertEqual(full["scope"], "full")
        verdicts["S1_both_concurrent_writes_200"] = "FAIL"
        failed = s15_validation.campaign_coverage(
            rounds=3,
            rounds_done=3,
            only=None,
            round_missing_cases=[{}, {}, {}],
            round_case_verdicts=[verdicts, verdicts, verdicts],
        )
        self.assertFalse(failed["complete"])
        self.assertFalse(failed["requiredCasePasses"])


if __name__ == "__main__":
    unittest.main()
