"""Pure deployment-profile contracts for offline authorization validation."""

from __future__ import annotations

from typing import Any, Dict, Tuple

__all__ = [
    "DEFAULT_PROFILE",
    "PROFILE_IDS",
    "SERVICE_DEPENDENCIES_BY_PROFILE",
    "DEPENDENCY_CLASSES_BY_PROFILE",
    "E4_FAULTS_BY_PROFILE",
    "NATIVE_SINGLE_NODE_FAULTS",
    "LEGACY_REDIS_COMPAT_FAULTS",
    "FAULT_DEPENDENCIES",
    "FAULT_DEPENDENCIES_BY_PROFILE",
    "FAULT_TIMINGS",
    "PROFILE_ALIASES",
    "DEPENDENCY_FAULT_MATRIX_BY_PROFILE",
    "dependency_fault_matrix",
    "get_profile",
    "normalize_profile",
    "validate_dependency_profiles",
]

DEFAULT_PROFILE = "native-single-node"
PROFILE_IDS: Tuple[str, ...] = (
    "native-kernel",
    "offline-validation",
    "native-single-node",
    "standalone-rabbit",
    "distributed",
    "redis-compat",
    "performance-kernel",
    "performance-native",
)

# Canonical service names are intentionally lower-case identifiers for use by
# runners and contract tests. Empty means no external service is required.
SERVICE_DEPENDENCIES_BY_PROFILE: Dict[str, Tuple[str, ...]] = {
    "native-kernel": (),
    "offline-validation": (),
    "native-single-node": ("mysql",),
    "standalone-rabbit": ("mysql", "rabbitmq"),
    "distributed": ("mysql", "rabbitmq"),
    "redis-compat": ("mysql", "redis"),
    "performance-kernel": (),
    "performance-native": ("mysql",),
}

DEPENDENCY_CLASSES_BY_PROFILE: Dict[str, Tuple[str, ...]] = {
    "native-kernel": (),
    "offline-validation": (),
    "native-single-node": (
        "cache",
        "publication_worker",
        "authoritative_database",
        "memory_projection_hub",
        "local_bus",
        "local_projection_bus",
        "identity_mapping",
        "gateway_integrity",
        "single_writer_lease",
    ),
    "standalone-rabbit": (
        "cache",
        "publication_worker_or_mq",
        "authoritative_database",
        "rabbitmq",
        "identity_mapping",
        "gateway_integrity",
    ),
    "distributed": (
        "cache",
        "publication_worker_or_mq",
        "authoritative_database",
        "rabbitmq",
        "identity_mapping",
        "gateway_integrity",
    ),
    "redis-compat": (
        "cache",
        "redis",
        "publication_worker_or_mq",
        "authoritative_database",
        "identity_mapping",
        "gateway_integrity",
    ),
    "performance-kernel": (),
    "performance-native": ("cache", "authoritative_database", "gateway_integrity"),
}

NATIVE_SINGLE_NODE_FAULTS: Tuple[str, ...] = (
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
)

# Frozen names used by the former Redis-bound E4 controller protocol. These
# remain available only under redis-compat and are not renamed or weakened.
LEGACY_REDIS_COMPAT_FAULTS: Tuple[str, ...] = (
    "redis_unavailable",
    "stale_hmac",
    "pointer_movement",
    "worker_restart",
    "lease_expiry",
    "unknown_ack",
)

# A fixed compatibility alias is accepted only where an older caller still
# supplies the descriptive name. New callers should use the canonical id.
PROFILE_ALIASES: Dict[str, str] = {}

E4_FAULTS_BY_PROFILE: Dict[str, Tuple[str, ...]] = {
    "native-kernel": (),
    "offline-validation": (),
    "native-single-node": NATIVE_SINGLE_NODE_FAULTS,
    "standalone-rabbit": (
        "source_commit_unknown",
        "rabbit_transport_unavailable",
        "worker_death_sticky",
        "current_pointer_movement",
        "hmac_failure",
        "mysql_unavailable",
    ),
    "distributed": (
        "source_commit_unknown",
        "rabbit_transport_unavailable",
        "worker_death_sticky",
        "current_pointer_movement",
        "hmac_failure",
        "mysql_unavailable",
    ),
    "redis-compat": LEGACY_REDIS_COMPAT_FAULTS,
    "performance-kernel": (),
    "performance-native": (
        "source_commit_unknown",
        "current_pointer_movement",
        "hmac_failure",
        "mysql_unavailable",
    ),
}

FAULT_DEPENDENCIES: Dict[str, Tuple[str, ...]] = {
    "memory_channel_suspect": ("memory_projection_hub",),
    "memory_invalidation_omission": ("memory_projection_hub",),
    "local_bus_owner_loss": ("local_bus", "local_projection_bus"),
    "local_bus_overflow": ("local_bus", "local_projection_bus"),
    "local_bus_unknown_completion": ("local_bus", "local_projection_bus"),
    "source_commit_unknown": ("authoritative_database",),
    "worker_death_sticky": ("publication_worker", "publication_worker_or_mq"),
    "writer_lease_loss": ("single_writer_lease",),
    "current_pointer_movement": ("cache", "authoritative_database"),
    "hmac_failure": ("gateway_integrity",),
    "mysql_unavailable": ("authoritative_database",),
    "rabbit_transport_unavailable": ("rabbitmq",),
    "redis_unavailable": ("redis",),
    "stale_hmac": ("gateway_integrity",),
    "pointer_movement": ("cache", "redis"),
    "worker_restart": ("publication_worker_or_mq",),
    "lease_expiry": ("publication_worker_or_mq",),
    "unknown_ack": ("publication_worker_or_mq",),
}

FAULT_DEPENDENCIES_BY_PROFILE: Dict[str, Dict[str, Tuple[str, ...]]] = {
    profile: {
        fault: tuple(
            dependency
            for dependency in FAULT_DEPENDENCIES[fault]
            if dependency in DEPENDENCY_CLASSES_BY_PROFILE[profile]
        )
        for fault in faults
    }
    for profile, faults in E4_FAULTS_BY_PROFILE.items()
}

FAULT_TIMINGS: Tuple[str, ...] = ("steady_state", "in_flight_revocation")
_DEPENDENCY_SERVICE_REQUIREMENTS = {
    "authoritative_database": "mysql",
    "gateway_integrity": None,
    "rabbitmq": "rabbitmq",
    "redis": "redis",
}


def normalize_profile(profile: str) -> str:
    """Return a canonical profile id, rejecting unknown values."""
    canonical = PROFILE_ALIASES.get(profile, profile)
    if canonical not in PROFILE_IDS:
        raise ValueError("unknown_profile:" + str(profile))
    return canonical


def get_profile(profile: str) -> Dict[str, Any]:
    """Return a normalized profile view; reject unknown identifiers."""
    canonical = normalize_profile(profile)
    return {
        "profile": canonical,
        "services": SERVICE_DEPENDENCIES_BY_PROFILE[canonical],
        "dependencies": DEPENDENCY_CLASSES_BY_PROFILE[canonical],
        "faults": E4_FAULTS_BY_PROFILE[canonical],
        "fault_dependencies": FAULT_DEPENDENCIES_BY_PROFILE[canonical],
    }


def dependency_fault_matrix(profile: str) -> Dict[str, Dict[str, str]]:
    """Build one profile's dependency/timing cross-product."""
    view = get_profile(profile)
    return {
        f"{dependency}:{timing}": {
            "profile": view["profile"],
            "dependency": dependency,
            "timing": timing,
            "acceptance": "fail_closed",
        }
        for dependency in view["dependencies"]
        for timing in FAULT_TIMINGS
    }


DEPENDENCY_FAULT_MATRIX_BY_PROFILE: Dict[str, Dict[str, Dict[str, str]]] = {
    profile: dependency_fault_matrix(profile) for profile in PROFILE_IDS
}


def validate_dependency_profiles() -> Dict[str, Any]:
    """Validate service, dependency, fault, and timing contracts."""
    problems = []
    profile_tables = (
        SERVICE_DEPENDENCIES_BY_PROFILE,
        DEPENDENCY_CLASSES_BY_PROFILE,
        E4_FAULTS_BY_PROFILE,
    )
    for table in profile_tables:
        if set(table) != set(PROFILE_IDS):
            problems.append("profile_table_ids_do_not_match")
    expected_services = {
        "native-kernel": (),
        "offline-validation": (),
        "native-single-node": ("mysql",),
        "standalone-rabbit": ("mysql", "rabbitmq"),
        "distributed": ("mysql", "rabbitmq"),
        "redis-compat": ("mysql", "redis"),
        "performance-kernel": (),
        "performance-native": ("mysql",),
    }
    if SERVICE_DEPENDENCIES_BY_PROFILE != expected_services:
        problems.append("service_dependency_contract_mismatch")

    for profile in PROFILE_IDS:
        services = set(SERVICE_DEPENDENCIES_BY_PROFILE.get(profile, ()))
        dependencies = set(DEPENDENCY_CLASSES_BY_PROFILE.get(profile, ()))
        faults = E4_FAULTS_BY_PROFILE.get(profile, ())
        fault_dependencies = FAULT_DEPENDENCIES_BY_PROFILE.get(profile, {})
        for dependency, service in _DEPENDENCY_SERVICE_REQUIREMENTS.items():
            if dependency in dependencies and service is not None and service not in services:
                problems.append(f"{profile}:dependency_without_service:{dependency}")
        if len(faults) != len(set(faults)):
            problems.append(f"{profile}:duplicate_fault")
        if set(fault_dependencies) != set(faults):
            problems.append(f"{profile}:fault_metadata_profile_mismatch")
        for fault in faults:
            required = fault_dependencies.get(fault, ())
            if not required:
                problems.append(f"{profile}:fault_dependency_not_applicable:{fault}")
            elif not set(required).issubset(dependencies):
                problems.append(f"{profile}:fault_dependency_not_applicable:{fault}")
        matrix = dependency_fault_matrix(profile)
        expected_pairs = {
            f"{dependency}:{timing}"
            for dependency in dependencies
            for timing in FAULT_TIMINGS
        }
        if set(matrix) != expected_pairs:
            problems.append(f"{profile}:dependency_fault_matrix_not_full_cross_product")
        for entry in matrix.values():
            if entry["profile"] != profile or entry["acceptance"] != "fail_closed":
                problems.append(f"{profile}:invalid_fault_matrix_metadata")

    if "redis" in DEPENDENCY_CLASSES_BY_PROFILE[DEFAULT_PROFILE]:
        problems.append("default_profile_includes_redis")
    if "rabbitmq" in DEPENDENCY_CLASSES_BY_PROFILE[DEFAULT_PROFILE]:
        problems.append("default_profile_includes_rabbitmq")
    return {
        "status": "PASS" if not problems else "FAIL",
        "problems": problems,
        "profileCount": len(PROFILE_IDS),
        "dependencyMatrixEntries": sum(
            len(dependency_fault_matrix(profile)) for profile in PROFILE_IDS
        ),
    }


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    report = validate_dependency_profiles()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["status"] == "PASS" else 1)
