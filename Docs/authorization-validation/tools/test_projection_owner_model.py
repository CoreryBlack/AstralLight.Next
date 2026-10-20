"""Standard-library tests for reachable-state projection-owner BFS."""
import unittest

import projection_owner_model as pom


class ProjectionOwnerBfsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = pom.run_model()

    def test_default_bfs_is_reproducible_and_complete_in_finite_universe(self):
        self.assertEqual(self.report, pom.run_model())
        self.assertEqual(self.report["status"], "PASS")
        self.assertTrue(self.report["explorationComplete"])
        self.assertEqual(len(self.report["cases"]), 3)
        for case in self.report["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["status"], "PASS")
                self.assertTrue(case["explorationComplete"])
                self.assertEqual(case["cutoffs"], [])
                self.assertGreater(case["states"]["expanded"], 1)
                self.assertGreater(case["transitions"]["generated"], 0)

    def test_same_grant_predecessor_scenarios_have_liveness_witnesses(self):
        for case in self.report["cases"][:2]:
            self.assertEqual([event["grant"] for event in case["events"]], ["G", "G"])
            self.assertEqual(case["events"][1]["predecessor"], 0)
            self.assertEqual(case["conditionalLiveness"]["status"], "WITNESS")
            self.assertTrue(case["conditionalLiveness"]["shortestWitness"])

    def test_independent_grants_same_aggregate_reach_both_published(self):
        case = self.report["cases"][2]
        self.assertEqual([event["grant"] for event in case["events"]], ["G", "H"])
        self.assertEqual(case["conditionalLiveness"]["status"], "WITNESS")
        self.assertTrue(case["conditionalLiveness"]["shortestWitness"])

    def test_claim_exec_failure_and_release_accounting_transitions(self):
        actions = self.report["cases"][2]["transitions"]["byKind"]
        self.assertIn("claim-lease-install", actions)
        self.assertIn("begin-exec", actions)
        self.assertIn("begin-exec-same-token-idempotent", actions)
        self.assertIn("proven-execution-failure", actions)
        self.assertIn("busy-before-lease", actions)
        self.assertIn("release-current-lease", actions)

    def test_unknown_requires_reconcile_before_retry(self):
        initial = pom.initial_state()
        claimed = next(
            successor for action, successor in pom.transitions(
                initial, pom.SCENARIOS[0], pom.Premises())
            if action == "claim-lease-install" and successor.owner[0] == 0
        )
        executing = next(
            successor for action, successor in pom.transitions(
                claimed, pom.SCENARIOS[0], pom.Premises())
            if action == "begin-exec"
        )
        unknown = next(
            successor for action, successor in pom.transitions(
                executing, pom.SCENARIOS[0], pom.Premises())
            if action == "stale-takeover"
        )
        self.assertEqual(unknown.phase[0], pom.UNKNOWN)
        self.assertEqual(unknown.owner[0], pom.NO_OWNER)
        self.assertEqual(unknown.unknown & 1, 1)
        self.assertEqual(unknown.lease_installs[0], 1)
        reconciled = [
            successor for action, successor in pom.transitions(
                unknown, pom.SCENARIOS[0], pom.Premises())
            if action == "reconcile-unknown"
        ]
        self.assertEqual({successor.owner[0] for successor in reconciled}, {0, 1})
        for successor in reconciled:
            self.assertEqual(successor.phase[0], pom.LEASED)
            self.assertEqual(successor.unknown & 1, 0)
            self.assertEqual(successor.lease_installs[0], 2)
            self.assertEqual(successor.attempts[0], 2)

    def test_unknown_blocks_publish_and_read_allow(self):
        state = pom.initial_state()._replace(
            phase=(pom.UNKNOWN, pom.PENDING),
            unknown=1,
            manifest_generation=1,
            manifest_events=1,
            current_generation=1,
            current_events=1,
            impact_events=1,
            proof_events=1,
            receipt_events=1,
        )
        actions = pom.transitions(state, pom.SCENARIOS[0], pom.Premises())
        kinds = {action for action, _ in actions}
        self.assertNotIn("publish-atomic", kinds)
        self.assertNotIn("final-read-allow", kinds)
        self.assertIn("final-read-pending-deny", kinds)
        reconciled = [
            successor for action, successor in actions
            if action == "reconcile-unknown"
        ]
        self.assertTrue(any(successor.phase[0] == pom.PUBLISHED
                            and successor.unknown == 0 for successor in reconciled))

    def test_normal_atomic_publish_does_not_set_unknown(self):
        initial = pom.initial_state()
        claimed = next(
            successor for action, successor in pom.transitions(
                initial, pom.SCENARIOS[0], pom.Premises())
            if action == "claim-lease-install"
        )
        executing = next(
            successor for action, successor in pom.transitions(
                claimed, pom.SCENARIOS[0], pom.Premises())
            if action == "begin-exec"
        )
        published = next(
            successor for action, successor in pom.transitions(
                executing, pom.SCENARIOS[0], pom.Premises())
            if action == "publish-atomic"
        )
        self.assertEqual(published.unknown, 0)
        self.assertEqual(published.phase[0], pom.PUBLISHED)

    def test_aggregate_predecessor_busy_is_zero_counter_for_exact_and_poll(self):
        scenario = pom.ORDER_SCENARIO
        initial = pom.initial_state()
        exact_busy = [
            successor for action, successor in pom.transitions(
                initial, scenario, pom.Premises())
            if action == "busy-before-aggregate-predecessor"
        ]
        self.assertTrue(exact_busy)
        for successor in exact_busy:
            self.assertEqual(successor, initial)
            self.assertEqual(successor.attempts, (0, 0))
            self.assertEqual(successor.execs, (0, 0))
            self.assertEqual(successor.failures, (0, 0))

        poll_seed = initial._replace(nudges=1)
        poll_state = next(
            successor for action, successor in pom.transitions(
                poll_seed, scenario, pom.Premises())
            if action == "recovery-scan-lost-nudge"
        )
        poll_busy = [
            successor for action, successor in pom.transitions(
                poll_state, scenario, pom.Premises())
            if action == "busy-before-aggregate-predecessor"
        ]
        self.assertTrue(poll_busy)
        for successor in poll_busy:
            self.assertEqual(successor, poll_state)
            self.assertEqual(successor.attempts, (0, 0))
            self.assertEqual(successor.execs, (0, 0))
            self.assertEqual(successor.failures, (0, 0))

    def test_source_7_then_64_cannot_publish_in_reverse_order(self):
        scenario = pom.ORDER_SCENARIO
        initial = pom.initial_state()
        claim_7 = next(
            successor for action, successor in pom.transitions(
                initial, scenario, pom.Premises())
            if action == "claim-lease-install" and successor.owner[0] != pom.NO_OWNER
        )
        begin_7 = next(
            successor for action, successor in pom.transitions(
                claim_7, scenario, pom.Premises())
            if action == "begin-exec"
        )
        publish_7 = next(
            successor for action, successor in pom.transitions(
                begin_7, scenario, pom.Premises())
            if action == "publish-atomic"
        )
        claim_64 = [
            successor for action, successor in pom.transitions(
                publish_7, scenario, pom.Premises())
            if action == "claim-lease-install" and successor.owner[1] != pom.NO_OWNER
        ]
        self.assertTrue(claim_64)
        self.assertEqual(publish_7.published_order, (0,))
        self.assertEqual([scenario.source_generations[event]
                          for event in publish_7.published_order], [7])

    def test_negative_controls_find_shortest_search_counterexamples(self):
        controls = self.report["negativeControls"]["counterexamples"]
        expected = {
            "wrong-binding", "active-slot", "ownership-fence-combination",
            "half-publication", "stale-release", "budget-pollution",
            "read-gate-bypass", "missing-durable-source-receipt",
        }
        self.assertEqual({item["id"] for item in controls}, expected)
        for item in controls:
            with self.subTest(control=item["id"]):
                self.assertEqual(item["status"], "COUNTEREXAMPLE")
                self.assertTrue(item["counterexampleFound"])
                self.assertFalse(item["explorationComplete"])
                self.assertTrue(item["counterexample"]["trace"])

    def test_epoch_omission_alone_is_not_asserted_as_vulnerability(self):
        case = self.report["negativeControls"]["epochOmissionAlone"]
        self.assertEqual(case["status"], "PASS")
        self.assertTrue(case["explorationComplete"])
        self.assertIn("random-token and worker-owner", case["interpretation"])

    def test_cutoff_is_unknown_not_pass(self):
        report = pom.run_model(max_states=1, max_depth=1)
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertFalse(report["explorationComplete"])
        self.assertTrue(any(not case["explorationComplete"] for case in report["cases"]))

    def test_fixed_schedule_ablation_is_not_performance_claim(self):
        ablation = self.report["ablation"]
        self.assertTrue(ablation["notDatabasePerformance"])
        self.assertTrue(ablation["notGlobalOptimum"])
        self.assertTrue(ablation["notUnboundedProof"])
        rows = {item["variant"]: item for item in ablation["rows"]}
        legacy = rows["legacy_scope_claim"]
        self.assertEqual(legacy["nonTargetPerCallMax"], 1)
        self.assertEqual(legacy["targetProcessingCapPerCall"], 32)
        self.assertEqual(legacy["nonTargetCandidatesVisited"], 2)
        self.assertEqual(rows["exact+owner+failure_budget"]["failureBudgetChecks"], 3)

    def test_finite_episode_limits_and_argument_validation(self):
        limits = self.report["finiteUniverse"]
        self.assertEqual(limits["maxLeaseEpisodesPerEvent"], 2)
        self.assertEqual(limits["maxProvenFailuresPerEvent"], 1)
        self.assertEqual(limits["maxSourceRevokes"], 1)
        for kwargs in ({"max_states": 0}, {"max_states": pom.MAX_STATES + 1},
                       {"max_depth": 0}, {"max_depth": pom.MAX_DEPTH + 1},
                       {"max_states": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                pom.run_model(**kwargs)


if __name__ == "__main__":
    unittest.main()
