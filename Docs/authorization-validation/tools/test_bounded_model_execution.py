"""Offline process execution must preserve complete configuration reports."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import bounded_model_execution as execution
import e5_model_check as single
import e5_model_check_two_mutations as two


class BoundedModelExecutionTests(unittest.TestCase):
    def test_worker_budget_is_strict_and_bounded(self):
        for value in (0, 13, True, 1.0, "2", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                execution.validate_workers(value)

    def test_e5_worker_budget_remains_finite(self):
        self.assertEqual(execution.MAX_WORKERS, 12)
        for value in (1, 4, 8, 12):
            self.assertEqual(execution.validate_workers(value), value)

    def test_unregistered_model_is_rejected(self):
        with self.assertRaises(ValueError):
            execution.run_configurations("os", [], 1)

    def test_complete_duplicates_are_only_reused_inside_one_call(self):
        full = single.normalize_premises()
        required = single.required_bound(full, "strict")
        configurations = [(full, "strict", 28), (full, "strict", required)]
        with patch.object(single, "run_model", return_value={"status": "PASS"}) as run:
            first = execution.run_configurations("e5_model_check", configurations)
            second = execution.run_configurations("e5_model_check", configurations)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)

    def test_underbound_runs_retain_exact_bound_identity(self):
        full = single.normalize_premises()
        configurations = [(full, "strict", 2), (full, "strict", 3)]
        with patch.object(single, "run_model", return_value={"status": "UNKNOWN"}) as run:
            result = execution.run_configurations("e5_model_check", configurations)
        self.assertEqual(run.call_count, 2)
        self.assertEqual({key[-1] for key in result}, {2, 3})

    def test_parallel_execution_preserves_reports_and_configuration_order(self):
        full = single.normalize_premises()
        configurations = [(full, "bracket", 28), (full, "strict", 28)]
        configurations.extend((single.without_premise(p), "bracket", 28)
                              for p in single.PREMISES)
        serial = execution.run_configurations("e5_model_check", configurations, 1)
        parallel = execution.run_configurations("e5_model_check", configurations, 2)
        self.assertEqual(list(serial), list(parallel))
        self.assertEqual(serial, parallel)

    def test_two_mutation_strict_worker_preserves_counts_and_counterexample(self):
        configurations = [(two.normalize_premises(), "strict", 28),
                          (two.without_premise("host_mediation"), "strict", 28)]
        serial = execution.run_configurations("e5_model_check_two_mutations", configurations, 1)
        parallel = execution.run_configurations("e5_model_check_two_mutations", configurations, 2)
        self.assertEqual(serial, parallel)

    def test_two_mutation_shards_preserve_complete_report_and_counterexamples(self):
        for mode in ("strict", "bracket"):
            for premise in (None, *two.PREMISES):
                premises = two.normalize_premises() if premise is None else two.without_premise(premise)
                bound = 28 if mode == "strict" else 8
                with self.subTest(mode=mode, premise=premise, bound=bound):
                    serial = two.run_model(premises, mode, bound)
                    prefixes = two.shard_prefixes(premises, mode, bound)
                    shards = [(prefix, two.run_model(premises, mode, bound, _trace_prefix=prefix))
                              for prefix in prefixes]
                    self.assertEqual(serial, two.merge_shard_runs(premises, mode, bound, shards))

    def test_two_mutation_shards_preserve_underbound(self):
        premises = two.without_premise("host_mediation")
        for bound in (2, 3, 6):
            serial = two.run_model(premises, "strict", bound)
            prefixes = two.shard_prefixes(premises, "strict", bound)
            shards = [(prefix, two.run_model(premises, "strict", bound, _trace_prefix=prefix))
                      for prefix in prefixes]
            self.assertEqual(serial, two.merge_shard_runs(premises, "strict", bound, shards))

    def test_missing_duplicate_reordered_or_drifted_model_shards_fail(self):
        premises = two.normalize_premises()
        prefixes = two.shard_prefixes(premises, "strict", 3)
        shards = [(prefix, two.run_model(premises, "strict", 3, _trace_prefix=prefix))
                  for prefix in prefixes]
        for invalid in (shards[:-1], shards + shards[:1], list(reversed(shards))):
            with self.assertRaises(ValueError):
                two.merge_shard_runs(premises, "strict", 3, invalid)
        drifted = [(prefix, dict(run, mode="bracket")) for prefix, run in shards]
        with self.assertRaises(ValueError):
            two.merge_shard_runs(premises, "strict", 3, drifted)


if __name__ == "__main__":
    unittest.main()
