"""Legacy unittest entrypoint forwarding to Rust-owned runner contracts."""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class EntrypointTests(unittest.TestCase):
    def test_rust_fake_cargo_contracts_are_the_single_source_of_truth(self):
        result = subprocess.run(
            ["bash", (ROOT / "scripts/tests/test-run-tests.sh").as_posix()],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("shell_entrypoints_forward_selection_to_the_rust_cli", result.stdout)
        self.assertIn("shell_entrypoints_propagate_cargo_failures_and_reject_before_dispatch", result.stdout)


if __name__ == "__main__":
    unittest.main()
