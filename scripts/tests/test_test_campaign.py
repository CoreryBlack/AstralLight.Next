"""Contracts for the production-equivalent campaign runner; no real services."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("test_campaign", ROOT / "scripts" / "test_campaign.py")
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


def suite(profile="native-kernel", acceptance="rust", **extra):
    return {
        "id": "contract", "profile": profile, "test_services": campaign.SERVICE_SETS[profile],
        "series": ["E4"], "scope": "component", "owner": "runner-contracts", "sources": [],
        "boundary": "synthetic runner contract only", "argv": ["python", "-B", "-c", "print('contract')"],
        "acceptance": acceptance, "minimum_tests": 1, **extra,
    }


def rust_result(passed=1, failed=0, ignored=0, filtered=0):
    return f"test result: {'FAILED' if failed else 'ok'}. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n"


def full_report(model_name="single", summary=False):
    report = {
        "model": campaign.check_full_contract.__globals__["MODELS"][model_name],
        "status": "PASS",
        "fullContract": {"status": "PASS", "modes": {
            mode: {"status": "PASS", "violations": 0, "explorationComplete": True}
            for mode in ("bracket", "strict")}},
        "omissions": [{"premise": name, "status": "FAIL"}
                      for name in sorted(campaign.check_full_contract.__globals__["PREMISES"])],
    }
    if summary:
        report["modes"] = report.pop("fullContract")["modes"]
        report["omissions"] = {entry["premise"]: entry["status"] for entry in report["omissions"]}
    return report


def environment():
    return {
        "DATABASE_URL": "mysql://fixture@127.0.0.1:3308/astral_rehearsal_contract",
        "ASTRAL_TEST_DATABASE_NAME": "astral_rehearsal_contract",
        "REDIS_URL": "redis://127.0.0.1:6380/0",
        "RABBITMQ_URL": "amqp://fixture@127.0.0.1:5673/%2f",
        "ASTRAL_MIGRATION_ENV": "isolated", "RUST_INTEGRATION_REQUIRED": "1",
        "TEST_USE_EXISTING": "1", "ASTRAL_REDIS_PROJECTION_COMPAT": "true",
        "ASTRAL_MESSAGE_TRANSPORT": "rabbit", "ASTRAL_TARGET_REGION": "foreign-region",
        "ASTRAL_PERF_CASE": "one-filtered-case", "COMPOSE_PROFILES": "rabbit,redis-compat",
    }


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = campaign.read_manifest()

    def test_all_series_are_registered(self):
        names = set(self.manifest["series_by_id"])
        self.assertTrue({f"{prefix}{number}" for prefix in ("RQ", "M", "E") for number in range(1, 6)} <= names)
        self.assertTrue({f"MT-E{number}" for number in range(1, 7)} <= names)
        self.assertTrue({"PERF", "COMPAT", "EXCLUDED"} <= names)

    def test_default_does_not_request_live_dependencies(self):
        selected = campaign.select_suites(self.manifest, running=True)
        self.assertTrue(all(item["profile"] in {"native-kernel", "offline-validation", "performance-kernel"} for item in selected))
        self.assertTrue(all(not item.get("blocked_reason") for item in selected))
        self.assertTrue(all(not item["test_services"] for item in selected))

    def test_instrumented_e_series_are_not_lost_by_consolidation(self):
        selected = {entry["id"]: entry for entry in self.manifest["suite"]}
        for name in ("policy-observability-tests", "db-observability-tests", "trustgraph-observability-tests"):
            self.assertIn("e1-observability", " ".join(selected[name]["argv"]))
            self.assertEqual(selected[name]["test_services"], [])
        self.assertIn("e3-observability,e4-observability", " ".join(selected["trustgraph-observability-tests"]["argv"]))

    def test_explicit_all_profiles_retains_blocked_and_live_suites(self):
        selected = campaign.select_suites(self.manifest, running=True, all_profiles=True)
        self.assertEqual(len(selected), len(self.manifest["suite"]))
        self.assertTrue(any(entry.get("blocked_reason") for entry in selected))
        self.assertTrue(any(entry["test_services"] for entry in selected))

    def test_m_family_does_not_include_mt_or_compat(self):
        selected = campaign.select_suites(self.manifest, series=["M"])
        self.assertTrue(all(any(label in {f"M{n}" for n in range(1, 6)} for label in item["series"]) for item in selected))
        self.assertNotIn("mt-capacity", [item["id"] for item in selected])

    def test_e_family_does_not_include_excluded_or_mt(self):
        selected = campaign.select_suites(self.manifest, series=["E"])
        self.assertNotIn("excluded-service-checks", [item["id"] for item in selected])
        self.assertNotIn("mt-capacity", [item["id"] for item in selected])

    def test_exact_e2_has_five_runtime_targets(self):
        selected = campaign.select_suites(self.manifest, profiles=["native-kernel"], series=["E2"])
        self.assertEqual(len(selected), 5)
        self.assertTrue(all(item["expected_tests"] == 1 and "--exact" in item["argv"] for item in selected))

    def test_explicit_suite_overrides_default_profiles(self):
        selected = campaign.select_suites(self.manifest, suite_ids=["native-projection-lifecycle"], running=True)
        self.assertEqual(selected[0]["profile"], "native-single-node")

    def test_unknown_selection_fails(self):
        for kwargs in ({"profiles": ["rabbit-by-default"]}, {"series": ["E9"]}, {"suite_ids": ["not-a-test"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                campaign.select_suites(self.manifest, **kwargs)

    def test_empty_selection_fails(self):
        with self.assertRaises(ValueError):
            campaign.select_suites(self.manifest, profiles=["standalone-rabbit"], series=["MT-E1"])

    def test_test_services_equal_their_production_profile(self):
        for item in self.manifest["suite"]:
            self.assertEqual(item["test_services"], campaign.SERVICE_SETS[item["profile"]])

    def test_service_contract_matches_offline_fault_profiles(self):
        source = ROOT / "Docs" / "authorization-validation" / "tools" / "dependency_profiles.py"
        spec = importlib.util.spec_from_file_location("dependency_profiles_contract", source)
        profiles = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profiles)
        self.assertEqual(set(profiles.PROFILE_IDS), set(campaign.SERVICE_SETS))
        for name, services in campaign.SERVICE_SETS.items():
            self.assertEqual(tuple(services), profiles.SERVICE_DEPENDENCIES_BY_PROFILE[name])
        self.assertEqual(profiles.validate_dependency_profiles()["status"], "PASS")

    def test_blocked_campaign_cannot_dispatch_legacy_command(self):
        for item in self.manifest["suite"]:
            if item.get("blocked_reason"):
                self.assertFalse(item.get("argv"))

    def test_missing_mt_e2_is_explicit(self):
        selected = campaign.select_suites(self.manifest, series=["MT-E2"])
        self.assertEqual(len(selected), 1)
        self.assertTrue(selected[0]["blocked_reason"])


class EnvironmentTests(unittest.TestCase):
    def test_kernel_removes_all_live_credentials(self):
        env, problem = campaign.prepare_environment(suite(), environment())
        self.assertIsNone(problem)
        for name in ("DATABASE_URL", "REDIS_URL", "RABBITMQ_URL", "RUST_INTEGRATION_REQUIRED",
                     "ASTRAL_TEST_DATABASE_NAME", "ASTRAL_TARGET_REGION", "ASTRAL_PERF_CASE"):
            self.assertNotIn(name, env)
        self.assertEqual(env["ASTRAL_MESSAGE_TRANSPORT"], "local")
        self.assertEqual(env["ASTRAL_REDIS_PROJECTION_COMPAT"], "false")

    def test_native_uses_only_mysql(self):
        env, problem = campaign.prepare_environment(suite("native-single-node"), environment())
        self.assertIsNone(problem)
        self.assertIn("DATABASE_URL", env)
        self.assertNotIn("RABBITMQ_URL", env)
        self.assertNotIn("REDIS_URL", env)
        self.assertEqual(env["RUST_INTEGRATION_REQUIRED"], "1")
        self.assertEqual(env["ASTRAL_TEST_DATABASE_NAME"], "astral_rehearsal_contract")

    def test_rabbit_uses_mysql_and_explicit_vhost_only(self):
        env, problem = campaign.prepare_environment(suite("standalone-rabbit"), environment())
        self.assertIsNone(problem)
        self.assertIn("RABBITMQ_URL", env)
        self.assertNotIn("REDIS_URL", env)
        self.assertEqual(env["ASTRAL_MESSAGE_TRANSPORT"], "rabbit")
        bad = environment()
        bad["RABBITMQ_URL"] = "amqp://fixture@127.0.0.1:5673/"
        self.assertIsNotNone(campaign.prepare_environment(suite("standalone-rabbit"), bad)[1])

    def test_redis_is_explicit_compat_only(self):
        env, problem = campaign.prepare_environment(suite("redis-compat"), environment())
        self.assertIsNone(problem)
        self.assertIn("REDIS_URL", env)
        self.assertNotIn("RABBITMQ_URL", env)
        self.assertEqual(env["ASTRAL_REDIS_PROJECTION_COMPAT"], "true")

    def test_absent_live_prerequisite_is_blocked(self):
        for key in ("TEST_USE_EXISTING", "ASTRAL_MIGRATION_ENV", "RUST_INTEGRATION_REQUIRED",
                    "DATABASE_URL", "ASTRAL_TEST_DATABASE_NAME"):
            original = environment()
            original.pop(key)
            with self.subTest(key=key):
                self.assertIsNotNone(campaign.prepare_environment(suite("native-single-node"), original)[1])

    def test_nonisolated_database_and_extra_options_are_rejected(self):
        for value in (
            "mysql://fixture@example.invalid:3308/astral_rehearsal_contract",
            "mysql://fixture@127.0.0.1:3308/astral_test",
            "mysql://fixture@127.0.0.1:3308/astral_rehearsal",
            "mysql://fixture@127.0.0.1:3308/astral_rehearsal_other",
            "mysql://fixture@127.0.0.1:3308/production",
            "mysql://fixture@127.0.0.1:3306/astral_rehearsal_contract",
            "mysql://fixture@127.0.0.1:3308/astral_rehearsal_contract?option=1",
        ):
            original = environment()
            original["DATABASE_URL"] = value
            with self.subTest(value=value):
                self.assertIsNotNone(campaign.prepare_environment(suite("native-single-node"), original)[1])

    def test_run_scoped_database_requires_exact_name_environment(self):
        original = environment()
        original["DATABASE_URL"] = "mysql://fixture@127.0.0.1:3308/astral_rehearsal_e5_r01"
        original["ASTRAL_TEST_DATABASE_NAME"] = "astral_rehearsal_e5_r01"
        env, problem = campaign.prepare_environment(suite("native-single-node"), original)
        self.assertIsNone(problem)
        self.assertEqual(env["ASTRAL_TEST_DATABASE_NAME"], "astral_rehearsal_e5_r01")

        for name in (
            "astral_rehearsal_",
            "astral_rehearsal_uppercase",
            "astral_rehearsal_bad-hyphen",
            "astral_rehearsal_" + "x" * 48,
            "astral_rehearsal_other",
        ):
            with self.subTest(name=name):
                original = environment()
                original["DATABASE_URL"] = f"mysql://fixture@127.0.0.1:3308/{name}"
                original["ASTRAL_TEST_DATABASE_NAME"] = "astral_rehearsal_e5_r01"
                self.assertIsNotNone(campaign.prepare_environment(suite("native-single-node"), original)[1])

    def test_dedicated_mapping_does_not_use_general_database(self):
        original = environment()
        item = suite("native-single-node", database_scope="identity-mapping")
        self.assertIsNotNone(campaign.prepare_environment(item, original)[1])
        original["INTEGRATION_IDENTITY_MAPPING_DATABASE_URL"] = "mysql://fixture@127.0.0.1:3308/sdk_identity_mapping_test_contract"
        original["INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE"] = "sdk_identity_mapping_test_contract"
        env, problem = campaign.prepare_environment(item, original)
        self.assertIsNone(problem)
        self.assertEqual(env["DATABASE_URL"], original["INTEGRATION_IDENTITY_MAPPING_DATABASE_URL"])
        self.assertEqual(env["INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE"], "sdk_identity_mapping_test_contract")
        for invalid_name in ("sdk_identity_mapping_test_", "sdk_identity_mapping_test_" + "x" * 39):
            original["INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE"] = invalid_name
            original["INTEGRATION_IDENTITY_MAPPING_DATABASE_URL"] = f"mysql://fixture@127.0.0.1:3308/{invalid_name}"
            with self.subTest(invalid_name=invalid_name):
                self.assertIsNotNone(campaign.prepare_environment(item, original)[1])


class AcceptanceTests(unittest.TestCase):
    def classify(self, item=None, code=0, out="", err="", interrupted=False):
        return campaign.classify_output(item or suite(), code, out, err, interrupted)

    def test_nonzero_is_fail_not_pass(self):
        self.assertEqual(self.classify(code=101)["status"], "FAIL")

    def test_deadline_and_interrupt_are_unknown(self):
        for code in (124, 130, 137, 143, -9):
            self.assertEqual(self.classify(code=code)["status"], "UNKNOWN")
        self.assertEqual(self.classify(code=0, interrupted=True)["status"], "UNKNOWN")

    def test_empty_rust_exit_zero_fails(self):
        self.assertEqual(self.classify(out=rust_result(passed=0, filtered=200))["status"], "FAIL")
        self.assertEqual(self.classify()["status"], "FAIL")

    def test_exact_assertion_count_is_required(self):
        item = suite(expected_tests=1)
        self.assertEqual(self.classify(item, out=rust_result(passed=2))["status"], "FAIL")
        self.assertEqual(self.classify(item, out=rust_result())["status"], "PASS")

    def test_cargo_ignored_not_hidden_by_exit_zero(self):
        verdict = self.classify(out=rust_result(passed=12, ignored=3))
        self.assertEqual(verdict["status"], "SKIP")
        self.assertEqual(verdict["tests"]["passed"], 12)
        self.assertEqual(verdict["tests"]["ignored"], 3)

    def test_internal_skip_preserves_assertion_counts(self):
        verdict = self.classify(out="[SKIP] dependency absent\n" + rust_result())
        self.assertEqual(verdict["status"], "SKIP")
        self.assertEqual(verdict["tests"]["passed"], 1)

    def test_python_requires_nonempty_ok_summary(self):
        item = suite(acceptance="unittest")
        self.assertEqual(self.classify(item, err="Ran 2 tests in 0.001s\n\nOK\n")["status"], "PASS")
        self.assertEqual(self.classify(item, err="Ran 0 tests in 0.001s\n\nOK\n")["status"], "FAIL")
        self.assertEqual(self.classify(item, err="Ran 2 tests in 0.001s\n\nOK (skipped=1)\n")["status"], "SKIP")

    def test_expected_model_counterexample_is_not_whole_failure(self):
        report = full_report()
        item = suite(acceptance="model-json", model_contract="full-contract", model_name="single")
        self.assertEqual(self.classify(item, out=json.dumps(report))["status"], "PASS")

    def test_incomplete_and_missing_model_modes_not_pass(self):
        item = suite(acceptance="model-json", model_contract="full-contract", model_name="single")
        self.assertEqual(self.classify(item, out=json.dumps({"status": "PASS"}))["status"], "UNKNOWN")
        for mode in ("bracket", "strict"):
            report = full_report()
            report["fullContract"]["modes"].pop(mode)
            self.assertEqual(self.classify(item, out=json.dumps(report))["status"], "UNKNOWN")

    def test_model_violation_and_inconsistent_contract_fail(self):
        item = suite(acceptance="model-json", model_contract="full-contract", model_name="single")
        report = full_report()
        report["fullContract"]["modes"]["strict"]["violations"] = 1
        self.assertEqual(self.classify(item, out=json.dumps(report))["status"], "FAIL")
        report = full_report()
        report["fullContract"]["status"] = "FAIL"
        self.assertEqual(self.classify(item, out=json.dumps(report))["status"], "FAIL")

    def test_two_mutation_summary_is_supported(self):
        item = suite(acceptance="model-json", model_contract="full-contract", model_name="two")
        self.assertEqual(self.classify(item, out=json.dumps(full_report("two", True)))["status"], "PASS")

    def test_hypothesis_unknown_is_not_proven(self):
        model = {"model": "tenant-isolation-bounded-model", "status": "PASS", "hypotheses": [{"id": "T1", "status": "UNKNOWN"}]}
        self.assertEqual(self.classify(suite(acceptance="model-json", model_contract="tenant"), out=json.dumps(model))["status"], "UNKNOWN")

    def test_native_dependency_tree_checks_actual_root_and_redis(self):
        item = suite(acceptance="dependency-tree")
        self.assertEqual(self.classify(item, out="astral-single-node v0.1.0\nmysql v8\n")["status"], "PASS")
        self.assertEqual(self.classify(item, out="astral-single-node v0.1.0\nredis v1.0.0\n")["status"], "FAIL")
        self.assertEqual(self.classify(item)["status"], "FAIL")

    def test_required_command_postcondition_is_not_exit_code_only(self):
        item = suite(acceptance="command", required_output="12 scenarios passed")
        self.assertEqual(self.classify(item)["status"], "FAIL")
        self.assertEqual(self.classify(item, out="12 scenarios passed")["status"], "PASS")

    def test_complete_cpu_matrix_preserves_measurements(self):
        rows = [{"case": "one", "metric": "ns-per-plan", "legacy": [20] * 15, "current": [10] * 15},
                {"case": "two", "metric": "ns-per-read", "samples": [30] * 15}]
        stdout = "\n".join("PERF_MATRIX " + json.dumps(row) for row in rows) + "\n" + rust_result()
        verdict = self.classify(suite(performance_cases=2), out=stdout)
        self.assertEqual(verdict["status"], "PASS")
        self.assertEqual(verdict["performance"]["cases"], 2)
        self.assertEqual(verdict["performance"]["scope"], "CPU component only")

    def test_filtered_duplicate_or_empty_performance_is_not_pass(self):
        item = suite(performance_cases=2)
        row = "PERF_MATRIX " + json.dumps({"case": "same", "samples": [10] * 15})
        for stdout in (rust_result(), row + "\n" + rust_result(), row + "\n" + row + "\n" + rust_result()):
            self.assertEqual(self.classify(item, out=stdout)["status"], "FAIL")

    def test_insufficient_performance_samples_fail(self):
        row = "PERF_MATRIX " + json.dumps({"case": "one", "samples": [10] * 14})
        self.assertEqual(self.classify(suite(performance_cases=1), out=row + "\n" + rust_result())["status"], "FAIL")

    def test_explicit_nonpass_state_overrides_exit_zero_success_output(self):
        successes = [
            (suite(acceptance="command", required_output="contract"), "contract\n", ""),
            (suite(acceptance="unittest"), "", "Ran 2 tests in 0.001s\n\nOK\n"),
            (suite(), rust_result(), ""),
        ]
        for status in ("PENDING", "BLOCKED", "FAIL", "UNKNOWN", "SKIP"):
            for item, out, err in successes:
                for stream in ("stdout", "stderr"):
                    with self.subTest(status=status, acceptance=item["acceptance"], stream=stream):
                        marker = f"[{status}] explicit subprocess state\n"
                        verdict = self.classify(item, out=out + (marker if stream == "stdout" else ""),
                                                err=err + (marker if stream == "stderr" else ""))
                        self.assertEqual(verdict["status"], status)

    def test_pending_output_keeps_failure_and_interruption_precedence(self):
        item = suite(acceptance="command", required_output="contract")
        output = "contract\n[PENDING] result not proven\n"
        self.assertEqual(self.classify(item, code=101, out=output)["status"], "FAIL")
        self.assertEqual(self.classify(item, out=output, interrupted=True)["status"], "UNKNOWN")
        self.assertEqual(self.classify(item, out=output + "[UNKNOWN] durable result unproven\n")["status"], "UNKNOWN")

    def test_lowercase_nonpass_markers_are_not_success(self):
        item = suite(acceptance="command", required_output="contract")
        for status in ("PENDING", "BLOCKED", "FAIL", "UNKNOWN", "SKIP"):
            with self.subTest(status=status):
                self.assertEqual(self.classify(item, out=f"contract\n[{status.lower()}] state\n")["status"], status)

    def test_pending_command_output_stops_both_phases_without_retry(self):
        first = suite(acceptance="command", required_output="contract",
                      argv=["python", "-B", "-c", "print('contract'); print('[PENDING] not complete')"])
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        with tempfile.TemporaryDirectory(prefix="astral-pending-command-") as tmp, \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute", wraps=campaign.execute) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.run_selected(manifest, [first, suite(id="second")], "pending-state", tmp, True), 1)
            result = json.loads((Path(tmp) / "pending-state" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual([entry["status"] for entry in result["item_results"]], ["PENDING", "BLOCKED"])
        self.assertEqual([entry["status"] for entry in result["results"]], ["BLOCKED", "BLOCKED"])
        self.assertEqual(result["retries"], 0)

    def test_fold_preserves_nonpass_status(self):
        for status in ("FAIL", "UNKNOWN", "BLOCKED", "PENDING", "SKIP"):
            self.assertEqual(campaign.fold_status([{"status": "PASS"}, {"status": status}]), status)


class EvidenceTests(unittest.TestCase):
    def test_secret_and_connection_url_scrubbing(self):
        original = environment()
        original["ASTRAL_TEST_TOKEN"] = "sensitive-long-token"
        text = "db=" + original["DATABASE_URL"] + " token=sensitive-long-token rabbit=amqp://userinfo@example.invalid/vhost"
        scrubbed = campaign.scrub_log(text, original)
        self.assertNotIn("mysql://", scrubbed)
        self.assertNotIn("amqp://", scrubbed)
        self.assertNotIn("sensitive-long-token", scrubbed)

    def test_real_subprocess_only_writes_owned_temporary_logs(self):
        item = suite(acceptance="command", required_output="contract")
        with tempfile.TemporaryDirectory(prefix="astral-campaign-contract-") as tmp:
            verdict = campaign.execute(item, dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), Path(tmp))
            self.assertEqual(verdict["status"], "PASS")
            self.assertEqual(verdict["exit_code"], 0)
            self.assertEqual(verdict["log_integrity"], "complete")
            self.assertTrue(Path(verdict["stdout"]).is_file())
            self.assertEqual(len(verdict["stdout_sha256"]), 64)

    def test_artifact_hashes_match_exact_written_bytes_after_redaction(self):
        item = suite(acceptance="command", argv=["python", "-B", "-c",
                     "import sys; sys.stdout.buffer.write(b'first\\r\\nsecret-value\\n'); "
                     "sys.stderr.buffer.write(b'error\\r\\nline\\n')"])
        with tempfile.TemporaryDirectory(prefix="astral-log-hash-") as tmp:
            verdict = campaign.execute(item, dict(os.environ, API_KEY="secret-value"), Path(tmp))
            self.assertEqual(verdict["status"], "PASS")
            for stream in ("stdout", "stderr"):
                data = Path(verdict[stream]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), verdict[stream + "_sha256"])
                self.assertNotIn(b"\r\n", data)
                self.assertNotIn(b"secret-value", data)

    def test_subprocess_deadline_is_unknown_without_retry(self):
        item = suite(acceptance="command", timeout_seconds=1, argv=["python", "-B", "-c", "import time; time.sleep(5)"])
        with tempfile.TemporaryDirectory(prefix="astral-campaign-timeout-") as tmp:
            verdict = campaign.execute(item, dict(os.environ), Path(tmp))
            self.assertEqual(verdict["status"], "UNKNOWN")
            self.assertTrue(verdict["stream_disconnect"])
            self.assertEqual(verdict["log_integrity"], "bounded prefix only")

    if os.name != "nt":
        def test_timeout_waits_for_delayed_descendant_stderr_before_hashing(self):
            child = (
                "import os,signal,sys,time; "
                "signal.signal(signal.SIGTERM, lambda *_: (time.sleep(0.25), "
                "sys.stderr.write('descendant shutdown\\n'), sys.stderr.flush(), os._exit(0))); "
                "time.sleep(30)"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-B', '-c', {child!r}]); "
                "time.sleep(30)"
            )
            item = suite(acceptance="command", timeout_seconds=1, argv=["python", "-B", "-c", parent])
            with tempfile.TemporaryDirectory(prefix="astral-group-shutdown-") as tmp:
                verdict = campaign.execute(item, dict(os.environ), Path(tmp))
                self.assertEqual(verdict["status"], "UNKNOWN")
                self.assertTrue(verdict["stream_disconnect"])
                self.assertIn("descendant shutdown", Path(verdict["stderr"]).read_text())
                before = Path(verdict["stderr"]).read_bytes()
                time.sleep(0.35)
                self.assertEqual(Path(verdict["stderr"]).read_bytes(), before)
                self.assertEqual(hashlib.sha256(before).hexdigest(), verdict["stderr_sha256"])

        def test_completed_parent_waits_for_descendant_output_before_pass(self):
            child = "import sys,time; time.sleep(0.25); print('descendant complete', file=sys.stderr)"
            parent = (
                "import subprocess,sys; "
                f"subprocess.Popen([sys.executable, '-B', '-c', {child!r}]); print('contract')"
            )
            item = suite(acceptance="command", required_output="contract", argv=["python", "-B", "-c", parent])
            with tempfile.TemporaryDirectory(prefix="astral-group-completion-") as tmp:
                verdict = campaign.execute(item, dict(os.environ), Path(tmp))
                self.assertEqual(verdict["status"], "PASS")
                self.assertEqual(verdict["log_integrity"], "complete")
                self.assertIn("descendant complete", Path(verdict["stderr"]).read_text())
                data = Path(verdict["stderr"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), verdict["stderr_sha256"])

    def test_unknown_stops_subsequent_dispatch_and_saves_evidence(self):
        first = suite()
        second = suite(id="second")
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        with tempfile.TemporaryDirectory(prefix="astral-campaign-stop-") as tmp, \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute", return_value={"status": "UNKNOWN", "reason": "interrupted", "exit_code": -9}) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            code = campaign.run_selected(manifest, [first, second], "contract-stop", tmp)
            record = json.loads((Path(tmp) / "contract-stop" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 1)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual([item["status"] for item in record["results"]], ["UNKNOWN", "BLOCKED"])
        self.assertEqual(record["retries"], 0)

    def test_source_change_invalidates_result(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        with tempfile.TemporaryDirectory(prefix="astral-campaign-freeze-") as tmp, \
                patch.object(campaign, "snapshot_hash", side_effect=["frozen", "frozen", "changed"]), \
                patch.object(campaign, "execute", return_value={"status": "PASS", "reason": "executed"}), \
                contextlib.redirect_stdout(io.StringIO()):
            campaign.run_selected(manifest, [suite()], "contract-freeze", tmp)
            record = json.loads((Path(tmp) / "contract-freeze" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "UNKNOWN")

    def test_every_nonpass_stops_and_fresh_rerun_restarts_the_selection(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        targets = [suite(), suite(id="second")]
        for status in ("FAIL", "UNKNOWN", "SKIP", "BLOCKED", "PENDING"):
            with self.subTest(status=status), tempfile.TemporaryDirectory(prefix="astral-fail-fast-") as tmp, \
                    patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                    patch.object(campaign, "execute", return_value={"status": status, "reason": "not proven"}) as execute, \
                    contextlib.redirect_stdout(io.StringIO()):
                campaign.run_selected(manifest, targets, "failed", tmp)
                self.assertEqual(execute.call_count, 1)
                result = json.loads((Path(tmp) / "failed" / "result.json").read_text())
                self.assertEqual([entry["status"] for entry in result["results"]], [status, "BLOCKED"])
                execute.reset_mock()
                execute.return_value = {"status": "PASS", "reason": "proven"}
                self.assertEqual(campaign.run_selected(manifest, targets, "fixed", tmp), 0)
                self.assertEqual(execute.call_count, 2)
                self.assertEqual([call.args[0]["id"] for call in execute.call_args_list], ["contract", "second"])

    def test_missing_collection_prerequisite_blocks_all_before_dispatch(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        targets = [suite(), suite("native-single-node", id="mysql")]
        with tempfile.TemporaryDirectory(prefix="astral-preflight-") as tmp, \
                patch.dict(os.environ, {}, clear=True), \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute") as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            campaign.run_selected(manifest, targets, "preflight", tmp)
            result = json.loads((Path(tmp) / "preflight" / "result.json").read_text())
        execute.assert_not_called()
        self.assertEqual(result["preflight"]["status"], "BLOCKED")
        self.assertEqual([entry["status"] for entry in result["results"]], ["BLOCKED", "BLOCKED"])

    def test_common_credential_names_are_redacted_even_for_short_values(self):
        env = {"API_KEY": "abc123", "ACCESS_KEY": "key-value", "apiKey": "mixed-case",
               "PRIVATE_KEY": "private-value", "ORDINARY": "visible"}
        text = "abc123 key-value mixed-case private-value visible"
        result = campaign.scrub_log(text, env)
        self.assertNotIn("abc123", result)
        self.assertNotIn("key-value", result)
        self.assertNotIn("mixed-case", result)
        self.assertNotIn("private-value", result)
        self.assertIn("visible", result)

    def test_verify_items_reruns_every_suite_in_a_fresh_collection_directory(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        targets = [suite(), suite(id="second")]
        with tempfile.TemporaryDirectory(prefix="astral-two-stage-") as tmp, \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute", return_value={"status": "PASS", "reason": "proven"}) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.run_selected(manifest, targets, "twice", tmp, True), 0)
            result = json.loads((Path(tmp) / "twice" / "result.json").read_text())
        self.assertEqual([call.args[0]["id"] for call in execute.call_args_list], ["contract", "second", "contract", "second"])
        self.assertEqual([call.args[2].name for call in execute.call_args_list], ["items", "items", "collection", "collection"])
        self.assertEqual(len(result["item_results"]), 2)
        self.assertEqual(len(result["results"]), 2)

    def test_unfinished_campaign_never_publishes_pass_between_phases(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        targets = [suite(), suite(id="second")]
        saved = []

        def observe_save(path, report):
            saved.append(json.loads(json.dumps(report)))

        with tempfile.TemporaryDirectory(prefix="astral-pending-status-") as tmp, \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute", return_value={"status": "PASS", "reason": "proven"}), \
                patch.object(campaign, "save_record", side_effect=observe_save), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.run_selected(manifest, targets, "pending", tmp, True), 0)
        self.assertEqual(saved[-1]["status"], "PASS")
        self.assertTrue(saved[-1]["finished_at"])
        for report in saved[:-1]:
            self.assertEqual(report["status"], "PENDING")
            self.assertFalse(report.get("finished_at"))
        dispatches = [report for report in saved
                      if any(entry["status"] == "PENDING" for entry in report["item_results"] + report["results"])]
        self.assertEqual(len(dispatches), 4)
        for report in dispatches:
            active = (report["item_results"] + report["results"])[-1]
            self.assertTrue(active["stdout"].endswith(f"{active['id']}.stdout.log"))
            self.assertTrue(active["stderr"].endswith(f"{active['id']}.stderr.log"))
            self.assertIn("in progress", active["log_integrity"])

    def test_item_failure_blocks_entire_collection(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        targets = [suite(), suite(id="second")]
        with tempfile.TemporaryDirectory(prefix="astral-item-stop-") as tmp, \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute", return_value={"status": "FAIL", "reason": "assertion"}) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.run_selected(manifest, targets, "stop", tmp, True), 1)
            result = json.loads((Path(tmp) / "stop" / "result.json").read_text())
        self.assertEqual(execute.call_count, 1)
        self.assertEqual([entry["status"] for entry in result["results"]], ["BLOCKED", "BLOCKED"])
        self.assertEqual(result["stopped_at"]["phase"], "items")

    def test_collection_failure_does_not_dispatch_later_targets(self):
        manifest = {"series_by_id": {"E4": {"boundary": "component only"}}}
        targets = [suite(), suite(id="second")]
        with tempfile.TemporaryDirectory(prefix="astral-collection-stop-") as tmp, \
                patch.object(campaign, "snapshot_hash", return_value="frozen"), \
                patch.object(campaign, "execute", side_effect=[{"status": "PASS", "reason": "ok"}, {"status": "PASS", "reason": "ok"}, {"status": "FAIL", "reason": "assertion"}]) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            campaign.run_selected(manifest, targets, "stop", tmp, True)
            result = json.loads((Path(tmp) / "stop" / "result.json").read_text())
        self.assertEqual(execute.call_count, 3)
        self.assertEqual(result["stopped_at"]["phase"], "collection")
        self.assertEqual([entry["status"] for entry in result["results"]], ["FAIL", "BLOCKED"])

    def test_existing_run_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="astral-campaign-collision-") as tmp:
            (Path(tmp) / "already-exists").mkdir()
            with self.assertRaises(FileExistsError):
                campaign.run_selected({}, [], "already-exists", tmp)

    def test_artifacts_cannot_enter_workspace(self):
        with self.assertRaises(ValueError):
            campaign.run_selected({}, [], "contract-scope", ROOT / "target")

    def test_invalid_run_id_is_rejected(self):
        with self.assertRaises(ValueError):
            campaign.run_selected({}, [], "../escape", tempfile.gettempdir())


if __name__ == "__main__":
    unittest.main()
