"""Regression fixtures for complete model identities, modes and hypotheses."""
from __future__ import annotations

import copy
import unittest

from model_acceptance import check_full_contract, check_tenant, check_universal

PREMISES = ("pending_probe", "post_recheck", "final_reload", "exact_identity",
            "generation_revoke_fence", "host_mediation")
MODELS = {"single": "e5-bounded-model-check", "two": "e5-bounded-model-check-two-mutations"}


def full_report(name="single", summary=False):
    modes = {mode: {"status": "PASS", "violations": 0, "explorationComplete": True}
             for mode in ("bracket", "strict")}
    report = {"model": MODELS[name], "status": "PASS",
              "fullContract": {"status": "PASS", "modes": modes},
              "omissions": [{"premise": premise, "status": "FAIL"} for premise in PREMISES]}
    if summary:
        report["modes"] = report.pop("fullContract")["modes"]
        report["omissions"] = {premise: "FAIL" for premise in PREMISES}
    return report


def universal_report():
    reports = {}
    for name in MODELS:
        entries = [{"id": f"U{number}", "status": "PASS", "evidence": {}} for number in range(1, 11)]
        by_id = {entry["id"]: entry for entry in entries}
        by_id["U1"]["evidence"] = {mode: {"status": "PASS", "explorationComplete": True, "admittedStrictlyBefore": 0}
                                     for mode in ("bracket", "strict")}
        by_id["U9"]["evidence"] = full_report()["fullContract"]["modes"]
        by_id["U8"]["evidence"] = {key: {"completeAtRequired": True} for key in
                                     ["full-bracket", "full-strict", *("without-" + premise for premise in PREMISES)]}
        by_id["U6"]["evidence"] = {"latticePolicy": "full" if name == "single" else "singles",
                                    "subsetsChecked": 62 if name == "single" else 6}
        reports[name] = {"modelName": name, "underlyingModel": MODELS[name], "status": "PASS", "hypotheses": entries}
    return {"checker": "universal-hypotheses-check", "status": "PASS", "models": reports}


class ModelAcceptanceTests(unittest.TestCase):
    def test_complete_contracts_and_expected_omission_failures(self):
        for name in MODELS:
            for summary in (False, True):
                self.assertEqual(check_full_contract(full_report(name, summary), name)["status"], "PASS")

    def test_missing_unexpected_and_incomplete_modes_are_unknown(self):
        for mode in ("bracket", "strict"):
            report = full_report()
            del report["fullContract"]["modes"][mode]
            self.assertEqual(check_full_contract(report, "single")["status"], "UNKNOWN")
        report = full_report()
        report["fullContract"]["modes"]["unexpected"] = {}
        self.assertEqual(check_full_contract(report, "single")["status"], "UNKNOWN")
        for value in (False, 1, "true", None):
            report = full_report()
            report["fullContract"]["modes"]["strict"]["explorationComplete"] = value
            self.assertEqual(check_full_contract(report, "single")["status"], "UNKNOWN")

    def test_violation_is_fail_and_boolean_is_not_a_count(self):
        report = full_report()
        report["fullContract"]["modes"]["strict"]["violations"] = 1
        self.assertEqual(check_full_contract(report, "single")["status"], "FAIL")
        report["fullContract"]["modes"]["strict"]["violations"] = False
        self.assertEqual(check_full_contract(report, "single")["status"], "UNKNOWN")

    def test_identity_and_omission_registry_cannot_be_missing(self):
        report = full_report()
        self.assertEqual(check_full_contract(report, "two")["status"], "UNKNOWN")
        report["omissions"].pop()
        self.assertEqual(check_full_contract(report, "single")["status"], "UNKNOWN")
        report["omissions"].append(copy.deepcopy(report["omissions"][0]))
        self.assertEqual(check_full_contract(report, "single")["status"], "UNKNOWN")

    def test_universal_requires_both_models_and_all_ten_hypotheses(self):
        report = universal_report()
        self.assertEqual(check_universal(report)["status"], "PASS")
        for name in MODELS:
            changed = copy.deepcopy(report)
            del changed["models"][name]
            self.assertEqual(check_universal(changed)["status"], "UNKNOWN")
            for index in range(10):
                changed = copy.deepcopy(report)
                changed["models"][name]["hypotheses"].pop(index)
                self.assertEqual(check_universal(changed)["status"], "UNKNOWN")

    def test_universal_checks_mode_and_bound_evidence(self):
        for hypothesis in ("U1", "U9"):
            report = universal_report()
            entry = next(item for item in report["models"]["two"]["hypotheses"] if item["id"] == hypothesis)
            entry["evidence"].pop("strict")
            self.assertEqual(check_universal(report)["status"], "UNKNOWN")
        report = universal_report()
        report["models"]["single"]["hypotheses"][7]["evidence"]["full-strict"]["completeAtRequired"] = False
        self.assertEqual(check_universal(report)["status"], "UNKNOWN")

    def test_lattice_policy_and_counts_are_exact(self):
        report = universal_report()
        report["models"]["single"]["hypotheses"][5]["evidence"]["subsetsChecked"] = 6
        self.assertEqual(check_universal(report)["status"], "UNKNOWN")

    def test_failed_hypothesis_is_fail_not_expected_omission(self):
        report = universal_report()
        report["models"]["two"]["hypotheses"][3]["status"] = "FAIL"
        self.assertEqual(check_universal(report)["status"], "FAIL")

    def test_tenant_hypotheses_are_exact_not_u_series(self):
        report = {"model": "tenant-isolation-bounded-model", "status": "PASS",
                  "hypotheses": [{"id": name, "status": "PASS"} for name in ("T1", "T3", "T4", "T5")]}
        self.assertEqual(check_tenant(report)["status"], "PASS")
        report["hypotheses"][1]["id"] = "T1"
        self.assertEqual(check_tenant(report)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
