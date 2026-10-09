"""Compatibility entrypoints must delegate to the same fail-fast runner."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class EntrypointTests(unittest.TestCase):
    def invoke(self, path, args=(), code=0):
        with tempfile.TemporaryDirectory(prefix="astral-entrypoint-") as tmp:
            directory = Path(tmp)
            binary = directory / "python"
            binary.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@"\nexit "${STUB_EXIT:-0}"\n', encoding="utf-8")
            binary.chmod(0o755)
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"], STUB_EXIT=str(code))
            result = subprocess.run([shutil.which("bash"), (ROOT / path).as_posix(), *args],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=15)
        return result

    def test_aliases_only_select_manifest_suites(self):
        aliases = {
            "--all": ["--run", "--verify-items"], "--full": ["--run", "--verify-items", "--all-profiles"],
            "unit": ["--run", "--profile", "native-kernel"],
            "--integration": ["--run", "--profile", "native-single-node"],
            "--rabbit": ["--run", "--profile", "standalone-rabbit"],
            "--identity-mapping": ["--run", "--suite", "dedicated-identity-mapping"],
            "--redis-compat": ["--run", "--profile", "redis-compat", "--suite", "redis-evidence-compat"],
            "--bench": ["--run", "--profile", "performance-kernel"],
            "--list-series": ["--list"],
        }
        for alias, expected in aliases.items():
            with self.subTest(alias=alias):
                result = self.invoke("scripts/run-tests.sh", [alias])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines()[2:], expected)
                self.assertTrue(result.stdout.splitlines()[1].endswith("/scripts/test_campaign.py"))

    def test_arguments_and_failure_exit_are_preserved(self):
        result = self.invoke("scripts/run-tests.sh", ["--campaign", "--run", "--suite", "strict-tenant-isolation"], 7)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout.splitlines()[2:], ["--run", "--suite", "strict-tenant-isolation"])

    def test_unknown_mode_never_dispatches(self):
        result = self.invoke("scripts/run-tests.sh", ["--unknown"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stdout)

    def test_matrix_translates_exact_suite_selection(self):
        result = self.invoke("tests-suite/matrix/run-mt-matrix.sh", ["--suites", "mt_extreme_churn mt_extreme_capacity"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[2:], ["--run", "--profile", "native-single-node",
                                                        "--suite", "mt-churn", "--suite", "mt-capacity"])

    def test_matrix_rejects_unknown_and_compat_profiles(self):
        for args in (["--suites", "unknown"], ["--suites", ""], ["--profile", "redis-compat"]):
            with self.subTest(args=args):
                result = self.invoke("tests-suite/matrix/run-mt-matrix.sh", args)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(result.stdout)

    def test_matrix_failure_exit_is_preserved(self):
        result = self.invoke("tests-suite/matrix/run-mt-matrix.sh", ["--suites", "mt_extreme_churn"], 1)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
