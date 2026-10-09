"""Measured benchmark cases are not proven by exit zero or fixture smoke."""
from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from performance_acceptance import check_criterion, check_divan


class CriterionAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.suite = {"benchmark_cases": ["engine/published_allow", "engine/published_deny"]}
        self.output = "engine/published_allow\n time: [1.0 ns 2.0 ns 3.0 ns]\nengine/published_deny time: [2 us 3 us 4 us]\n"

    def test_exact_complete_cases_and_units_are_preserved(self):
        result = check_criterion(self.suite, self.output)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["performance"]["measurements"]["engine/published_deny"]["estimate_ns"], 3000)

    def test_smoke_is_not_measured_acceptance(self):
        output = "Testing engine/published_allow\nSuccess\nTesting engine/published_deny\nSuccess\n"
        self.assertEqual(check_criterion(self.suite, output, True)["status"], "PASS")
        self.assertEqual(check_criterion(self.suite, output)["status"], "FAIL")

    def test_partial_empty_and_duplicate_measurements_fail(self):
        for output in ("", "Success", self.output.split("engine/published_deny")[0], self.output + self.output):
            self.assertEqual(check_criterion(self.suite, output)["status"], "FAIL")

    def test_nonpositive_reversed_and_unbound_intervals_fail(self):
        for output in (self.output.replace("1.0 ns", "0 ns"), self.output.replace("1.0 ns", "5 ns"),
                       "time: [1 ns 2 ns 3 ns]"):
            self.assertEqual(check_criterion(self.suite, output)["status"], "FAIL")


class DivanAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.suite = {"benchmark_cases": ["shared_build", "private_build"], "allocation_cases": ["shared_build", "private_build"]}
        self.output = "\n".join(
            "\u251c\u2500 " + name + " \u2502 1 ns \u2502 4 ns \u2502 2 ns \u2502 3 ns \u2502 100 \u2502 200\n"
            "  \u2502 alloc: \u2502 \u2502 \u2502 \u2502 \u2502\n"
            "  \u2502 1 \u2502 2 \u2502 1.5 \u2502 1.6 \u2502 \u2502\n"
            "  \u2502 8 B \u2502 16 B \u2502 12 B \u2502 12.8 B \u2502 \u2502"
            for name in self.suite["benchmark_cases"])

    def test_complete_cases_require_sample_counts_and_allocations(self):
        self.assertEqual(check_divan(self.suite, self.output)["status"], "PASS")
        self.assertEqual(check_divan(self.suite, self.output.replace("alloc:", "dealloc:"))["status"], "FAIL")

    def test_filtered_and_empty_measurements_fail(self):
        self.assertEqual(check_divan(self.suite, "")["status"], "FAIL")
        self.assertEqual(check_divan(self.suite, self.output.split("private_build")[0])["status"], "FAIL")

    def test_divan_tree_output_with_fastest_in_name_column(self):
        output = self.output.replace(" \u2502 1 ns", "  1 ns")
        output = output.replace("\u251c\u2500 private_build", "\u2570\u2500 private_build")
        parsed = check_divan(self.suite, output)
        expected = check_divan(self.suite, self.output)
        self.assertEqual(parsed, expected)

    def test_rounded_terminal_branch_retains_full_coverage_checks(self):
        output = self.output.replace("\u251c\u2500 private_build", "\u2570\u2500 private_build")
        self.assertEqual(check_divan(self.suite, output)["status"], "PASS")
        self.assertEqual(check_divan(self.suite, output.replace("alloc:", "max alloc:"))["status"], "FAIL")
        self.assertEqual(check_divan(self.suite, output + "\n" + output)["status"], "FAIL")

    def test_native_table_format_does_not_accept_malformed_fastest_or_samples(self):
        output = self.output.replace(" \u2502 1 ns", "  1 ns")
        for invalid in (output.replace("  1 ns", "  nope"), output.replace("  1 ns", "  0 ns"),
                        output.replace("100", "0"), output.split("private_build")[0]):
            with self.subTest(output=invalid):
                self.assertEqual(check_divan(self.suite, invalid)["status"], "FAIL")

    def test_missing_samples_or_duplicate_cases_fail(self):
        self.assertEqual(check_divan(self.suite, self.output.replace("100", "0"))["status"], "FAIL")
        self.assertEqual(check_divan(self.suite, self.output + "\n" + self.output)["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
