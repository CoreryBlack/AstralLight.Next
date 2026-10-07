#!/usr/bin/env python3
"""Offline tests locking the declarative experiment register.

The register is the machine-checkable counterpart of the pre-registered
experiment designs. These tests pin its internal consistency: the
stimulus classes, the E2 control-to-premise mapping (including the
model-only exemption), the canary ground truth, the dependency-fault
matrix, and the capture/acceptance tables. A change to any of them must
fail here and force an explicit sync with the protocol and the models.

Run:
    python -m unittest discover -s Docs/authorization-validation/tools \
        -t Docs/authorization-validation/tools -p "test_experiment_register.py" -v
"""

import unittest

import experiment_register as register


class RegisterConsistencyTest(unittest.TestCase):
    def test_register_validates(self):
        report = register.validate_register()
        self.assertEqual(report["status"], "PASS", report["problems"])
        self.assertEqual(report["problems"], [])

    def test_stimulus_classes_complete_and_revocation_class(self):
        self.assertEqual(
            set(register.STIMULUS_CLASSES),
            {
                "rule_set_unbinding",
                "winning_entry_removal",
                "direct_rule_removal",
                "approval_or_delegation_withdrawal",
                "card_disablement",
                "aggregate_wide_narrowing",
            },
        )
        for spec in register.STIMULUS_CLASSES.values():
            self.assertTrue(spec["revocationClass"])
            self.assertTrue(spec["note"])

    def test_e2_controls_cover_every_runtime_switch_premise(self):
        self.assertEqual(
            set(register.E2_CONTROL_SCENARIOS),
            {
                "pending_probe",
                "post_recheck",
                "final_reload",
                "exact_identity",
                "generation_revoke_fence",
            },
        )
        self.assertEqual(
            register.MODEL_ONLY_PREMISES, ("host_mediation",)
        )
        # Cross-register consistency: every control's Rust test id must
        # appear verbatim in the readiness campaign's e2-* command lines,
        # so the register and the frozen campaign cannot drift apart.
        import run_single_node_campaign as campaign
        e2_argv = " ".join(
            " ".join(spec["argv"])
            for spec in campaign.COMMANDS if spec["id"].startswith("e2-")
        )
        for premise, spec in register.E2_CONTROL_SCENARIOS.items():
            self.assertIn(spec["rustTest"], e2_argv, premise)
            self.assertEqual(spec["expectedFinding"], "counterexample_found")

    def test_canary_ground_truth_fixed_by_construction(self):
        self.assertEqual(
            set(register.CANARY_SCENARIOS),
            {"suppressed_revocation_delta", "revision_confused_grant"},
        )
        for spec in register.CANARY_SCENARIOS.values():
            self.assertEqual(spec["expectedDetectionRate"], 1.0)
            self.assertEqual(spec["expectedFalseBlockRate"], 0.0)

    def test_dependency_fault_matrix_is_full_cross_product(self):
        # 2026-10 架构面扩展:四个新依赖类(内存权威读面/本地失效通道/
        # SDK 强制身份映射/单写者租约)进入故障矩阵,叉积完整性约束不变。
        self.assertEqual(
            set(register.DEPENDENCY_CLASSES),
            {"cache", "redis", "publication_worker_or_mq",
             "authoritative_database", "memory_projection_hub",
             "local_projection_bus", "identity_mapping",
             "single_writer_lease"},
        )
        self.assertEqual(set(register.FAULT_TIMINGS),
                         {"steady_state", "in_flight_revocation"})
        self.assertEqual(len(register.DEPENDENCY_FAULT_MATRIX), 16)
        for spec in register.DEPENDENCY_FAULT_MATRIX.values():
            self.assertEqual(spec["acceptance"], "fail_closed")

    def test_capture_and_acceptance_tables_present(self):
        self.assertEqual(
            set(register.CAPTURE_REQUIREMENTS),
            {"E1", "E2", "E3", "E4"},
        )
        self.assertEqual(
            set(register.ACCEPTANCE_CRITERIA),
            {"E1", "E2", "E3", "E4", "E7", "E8"},
        )
        for fields in register.CAPTURE_REQUIREMENTS.values():
            self.assertGreaterEqual(len(fields), 3)
        for criteria in register.ACCEPTANCE_CRITERIA.values():
            self.assertGreaterEqual(len(criteria), 2)
        # The E1 capture table carries the multi-mutation attribution and
        # the stimulus class id -- the two upgrades this register pins.
        self.assertTrue(any(
            "per-mutation hazard attribution" in field
            for field in register.CAPTURE_REQUIREMENTS["E1"]
        ))
        self.assertTrue(any(
            "stimulus class id" in field
            for field in register.CAPTURE_REQUIREMENTS["E1"]
        ))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
