"""Offline tests for the shared deployment dependency/fault profiles."""

from __future__ import annotations

import unittest

import dependency_profiles as profiles


class DependencyProfileTests(unittest.TestCase):
    def test_profile_contract_validates(self) -> None:
        report = profiles.validate_dependency_profiles()
        self.assertEqual(report["status"], "PASS", report["problems"])
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["profileCount"], 8)

    def test_canonical_profile_ids_and_services(self) -> None:
        self.assertEqual(
            profiles.PROFILE_IDS,
            (
                "native-kernel",
                "offline-validation",
                "native-single-node",
                "standalone-rabbit",
                "distributed",
                "redis-compat",
                "performance-kernel",
                "performance-native",
            ),
        )
        self.assertEqual(profiles.SERVICE_DEPENDENCIES_BY_PROFILE["native-single-node"], ("mysql",))
        self.assertEqual(
            profiles.SERVICE_DEPENDENCIES_BY_PROFILE["standalone-rabbit"],
            ("mysql", "rabbitmq"),
        )
        self.assertEqual(
            profiles.SERVICE_DEPENDENCIES_BY_PROFILE["distributed"],
            ("mysql", "rabbitmq"),
        )
        self.assertEqual(
            profiles.SERVICE_DEPENDENCIES_BY_PROFILE["redis-compat"],
            ("mysql", "redis"),
        )

    def test_default_native_profile_has_no_redis_or_rabbit(self) -> None:
        dependencies = set(profiles.DEPENDENCY_CLASSES_BY_PROFILE[profiles.DEFAULT_PROFILE])
        self.assertNotIn("redis", dependencies)
        self.assertNotIn("rabbitmq", dependencies)
        self.assertIn("memory_projection_hub", dependencies)
        self.assertIn("local_bus", dependencies)
        self.assertIn("local_projection_bus", dependencies)
        self.assertIn("gateway_integrity", dependencies)

    def test_native_fault_matrix_is_explicit_and_stable(self) -> None:
        self.assertEqual(
            profiles.E4_FAULTS_BY_PROFILE["native-single-node"],
            (
                "memory_channel_suspect",
                "memory_invalidation_omission",
                "local_bus_owner_loss",
                "local_bus_overflow",
                "local_bus_unknown_completion",
                "source_commit_unknown",
                "worker_death_sticky",
                "writer_lease_loss",
                "current_pointer_movement",
                "hmac_failure",
                "mysql_unavailable",
            ),
        )
        self.assertEqual(
            set(profiles.FAULT_DEPENDENCIES["local_bus_overflow"]),
            {"local_bus", "local_projection_bus"},
        )
        self.assertEqual(profiles.FAULT_DEPENDENCIES["hmac_failure"], ("gateway_integrity",))

    def test_legacy_faults_are_compat_only(self) -> None:
        self.assertEqual(
            profiles.E4_FAULTS_BY_PROFILE["redis-compat"],
            profiles.LEGACY_REDIS_COMPAT_FAULTS,
        )
        self.assertNotIn("redis_unavailable", profiles.E4_FAULTS_BY_PROFILE["native-single-node"])
        self.assertNotIn("redis_unavailable", profiles.E4_FAULTS_BY_PROFILE["standalone-rabbit"])

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown_profile"):
            profiles.get_profile("redis")
        with self.assertRaisesRegex(ValueError, "unknown_profile"):
            profiles.dependency_fault_matrix("native")

    def test_each_matrix_is_full_timing_cross_product(self) -> None:
        for profile in profiles.PROFILE_IDS:
            with self.subTest(profile=profile):
                matrix = profiles.dependency_fault_matrix(profile)
                dependencies = profiles.DEPENDENCY_CLASSES_BY_PROFILE[profile]
                self.assertEqual(
                    set(matrix),
                    {
                        f"{dependency}:{timing}"
                        for dependency in dependencies
                        for timing in profiles.FAULT_TIMINGS
                    },
                )
                self.assertTrue(all(item["profile"] == profile for item in matrix.values()))
                self.assertTrue(all(item["acceptance"] == "fail_closed" for item in matrix.values()))


if __name__ == "__main__":
    unittest.main()
