use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE_IDS: [&str; 8] = [
    "native-kernel",
    "offline-validation",
    "native-single-node",
    "standalone-rabbit",
    "distributed",
    "redis-compat",
    "performance-kernel",
    "performance-native",
];

const NATIVE_FAULTS: [&str; 11] = [
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
];
const RABBIT_FAULTS: [&str; 6] = [
    "source_commit_unknown",
    "rabbit_transport_unavailable",
    "worker_death_sticky",
    "current_pointer_movement",
    "hmac_failure",
    "mysql_unavailable",
];
const REDIS_COMPAT_FAULTS: [&str; 6] = [
    "redis_unavailable",
    "stale_hmac",
    "pointer_movement",
    "worker_restart",
    "lease_expiry",
    "unknown_ack",
];
const PERFORMANCE_NATIVE_FAULTS: [&str; 4] = [
    "source_commit_unknown",
    "current_pointer_movement",
    "hmac_failure",
    "mysql_unavailable",
];
const NATIVE_DEPENDENCIES: [&str; 9] = [
    "cache",
    "publication_worker",
    "authoritative_database",
    "memory_projection_hub",
    "local_bus",
    "local_projection_bus",
    "identity_mapping",
    "gateway_integrity",
    "single_writer_lease",
];
const RABBIT_DEPENDENCIES: [&str; 6] = [
    "cache",
    "publication_worker_or_mq",
    "authoritative_database",
    "rabbitmq",
    "identity_mapping",
    "gateway_integrity",
];
const REDIS_DEPENDENCIES: [&str; 6] = [
    "cache",
    "redis",
    "publication_worker_or_mq",
    "authoritative_database",
    "identity_mapping",
    "gateway_integrity",
];
const PERFORMANCE_NATIVE_DEPENDENCIES: [&str; 3] =
    ["cache", "authoritative_database", "gateway_integrity"];
pub const FAULT_TIMINGS: [&str; 2] = ["steady_state", "in_flight_revocation"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub id: &'static str,
    pub services: &'static [&'static str],
    pub dependencies: &'static [&'static str],
    pub faults: &'static [&'static str],
}

pub const PROFILES: [Profile; 8] = [
    Profile {
        id: "native-kernel",
        services: &[],
        dependencies: &[],
        faults: &[],
    },
    Profile {
        id: "offline-validation",
        services: &[],
        dependencies: &[],
        faults: &[],
    },
    Profile {
        id: "native-single-node",
        services: &["mysql"],
        dependencies: &NATIVE_DEPENDENCIES,
        faults: &NATIVE_FAULTS,
    },
    Profile {
        id: "standalone-rabbit",
        services: &["mysql", "rabbitmq"],
        dependencies: &RABBIT_DEPENDENCIES,
        faults: &RABBIT_FAULTS,
    },
    Profile {
        id: "distributed",
        services: &["mysql", "rabbitmq"],
        dependencies: &RABBIT_DEPENDENCIES,
        faults: &RABBIT_FAULTS,
    },
    Profile {
        id: "redis-compat",
        services: &["mysql", "redis"],
        dependencies: &REDIS_DEPENDENCIES,
        faults: &REDIS_COMPAT_FAULTS,
    },
    Profile {
        id: "performance-kernel",
        services: &[],
        dependencies: &[],
        faults: &[],
    },
    Profile {
        id: "performance-native",
        services: &["mysql"],
        dependencies: &PERFORMANCE_NATIVE_DEPENDENCIES,
        faults: &PERFORMANCE_NATIVE_FAULTS,
    },
];

fn profile(id: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|profile| profile.id == id)
}

pub fn profile_services(id: &str) -> Option<&'static [&'static str]> {
    profile(id).map(|profile| profile.services)
}

pub fn profile_dependencies(id: &str) -> Option<&'static [&'static str]> {
    profile(id).map(|profile| profile.dependencies)
}

pub fn profile_faults(id: &str) -> Option<&'static [&'static str]> {
    profile(id).map(|profile| profile.faults)
}

pub const FAULT_DEPENDENCIES: [(&str, &[&str]); 18] = [
    ("memory_channel_suspect", &["memory_projection_hub"]),
    ("memory_invalidation_omission", &["memory_projection_hub"]),
    (
        "local_bus_owner_loss",
        &["local_bus", "local_projection_bus"],
    ),
    ("local_bus_overflow", &["local_bus", "local_projection_bus"]),
    (
        "local_bus_unknown_completion",
        &["local_bus", "local_projection_bus"],
    ),
    ("source_commit_unknown", &["authoritative_database"]),
    (
        "worker_death_sticky",
        &["publication_worker", "publication_worker_or_mq"],
    ),
    ("writer_lease_loss", &["single_writer_lease"]),
    (
        "current_pointer_movement",
        &["cache", "authoritative_database"],
    ),
    ("hmac_failure", &["gateway_integrity"]),
    ("mysql_unavailable", &["authoritative_database"]),
    ("rabbit_transport_unavailable", &["rabbitmq"]),
    ("redis_unavailable", &["redis"]),
    ("stale_hmac", &["gateway_integrity"]),
    ("pointer_movement", &["cache", "redis"]),
    ("worker_restart", &["publication_worker_or_mq"]),
    ("lease_expiry", &["publication_worker_or_mq"]),
    ("unknown_ack", &["publication_worker_or_mq"]),
];

pub fn fault_dependencies(fault: &str) -> Option<&'static [&'static str]> {
    FAULT_DEPENDENCIES
        .iter()
        .find_map(|(name, dependencies)| (*name == fault).then_some(*dependencies))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultMatrixEntry {
    pub profile: &'static str,
    pub dependency: &'static str,
    pub timing: &'static str,
    pub acceptance: &'static str,
}

pub fn fault_dependencies_for(profile_id: &str, fault: &str) -> Result<Vec<&'static str>, String> {
    let profile = profile(profile_id).ok_or_else(|| format!("unknown_profile:{profile_id}"))?;
    let required = fault_dependencies(fault).ok_or_else(|| format!("unknown_fault:{fault}"))?;
    Ok(required
        .iter()
        .copied()
        .filter(|dependency| profile.dependencies.contains(dependency))
        .collect())
}

pub fn dependency_fault_matrix(
    profile_id: &str,
) -> Result<BTreeMap<String, FaultMatrixEntry>, String> {
    let profile = profile(profile_id).ok_or_else(|| format!("unknown_profile:{profile_id}"))?;
    Ok(profile
        .dependencies
        .iter()
        .flat_map(|dependency| {
            FAULT_TIMINGS.iter().map(move |timing| {
                (
                    format!("{dependency}:{timing}"),
                    FaultMatrixEntry {
                        profile: profile.id,
                        dependency,
                        timing,
                        acceptance: "fail_closed",
                    },
                )
            })
        })
        .collect())
}

pub fn validate_profiles() -> Result<usize, Vec<String>> {
    let mut problems = Vec::new();
    let mut ids = BTreeSet::new();
    for profile in &PROFILES {
        if !ids.insert(profile.id) {
            problems.push(format!("duplicate_profile:{}", profile.id));
        }
        let services: BTreeSet<_> = profile.services.iter().copied().collect();
        let dependencies: BTreeSet<_> = profile.dependencies.iter().copied().collect();
        if profile.services.iter().collect::<BTreeSet<_>>().len() != profile.services.len() {
            problems.push(format!("{}:duplicate_service", profile.id));
        }
        if profile.dependencies.iter().collect::<BTreeSet<_>>().len() != profile.dependencies.len()
        {
            problems.push(format!("{}:duplicate_dependency", profile.id));
        }
        if dependencies.contains("authoritative_database") && !services.contains("mysql") {
            problems.push(format!("{}:dependency_without_service:mysql", profile.id));
        }
        if dependencies.contains("rabbitmq") && !services.contains("rabbitmq") {
            problems.push(format!(
                "{}:dependency_without_service:rabbitmq",
                profile.id
            ));
        }
        if dependencies.contains("redis") && !services.contains("redis") {
            problems.push(format!("{}:dependency_without_service:redis", profile.id));
        }
        for fault in profile.faults {
            let valid = fault_dependencies(fault).is_some_and(|required| {
                !required.is_empty()
                    && required
                        .iter()
                        .any(|dependency| dependencies.contains(dependency))
            });
            if !valid {
                problems.push(format!(
                    "{}:fault_dependency_not_applicable:{fault}",
                    profile.id
                ));
            }
        }
        let matrix = dependency_fault_matrix(profile.id).expect("registered profile");
        let expected: BTreeSet<_> = profile
            .dependencies
            .iter()
            .flat_map(|dependency| {
                FAULT_TIMINGS
                    .iter()
                    .map(move |timing| format!("{dependency}:{timing}"))
            })
            .collect();
        if matrix.keys().cloned().collect::<BTreeSet<_>>() != expected
            || matrix
                .values()
                .any(|entry| entry.acceptance != "fail_closed")
        {
            problems.push(format!(
                "{}:dependency_fault_matrix_not_full_cross_product",
                profile.id
            ));
        }
        if profile.faults.iter().collect::<BTreeSet<_>>().len() != profile.faults.len() {
            problems.push(format!("{}:duplicate_fault", profile.id));
        }
    }
    if ids != PROFILE_IDS.into_iter().collect() {
        problems.push("profile_ids_do_not_match_registry".to_owned());
    }
    if profile("native-single-node").is_some_and(|item| {
        item.services
            .iter()
            .any(|service| *service == "redis" || *service == "rabbitmq")
            || item
                .dependencies
                .iter()
                .any(|dependency| *dependency == "redis" || *dependency == "rabbitmq")
    }) {
        problems.push("default_profile_includes_legacy_service".to_owned());
    }
    if profile("native-single-node").is_some_and(|item| {
        item.faults
            .iter()
            .any(|fault| REDIS_COMPAT_FAULTS.contains(fault))
    }) {
        problems.push("legacy_faults_escape_redis_compat".to_owned());
    }
    if problems.is_empty() {
        Ok(PROFILES.len())
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_profiles_pin_exact_services_dependencies_and_fault_membership() {
        let expected = [
            ("native-kernel", &[][..], &[][..], &[][..]),
            ("offline-validation", &[][..], &[][..], &[][..]),
            (
                "native-single-node",
                &["mysql"][..],
                &NATIVE_DEPENDENCIES[..],
                &NATIVE_FAULTS[..],
            ),
            (
                "standalone-rabbit",
                &["mysql", "rabbitmq"][..],
                &RABBIT_DEPENDENCIES[..],
                &RABBIT_FAULTS[..],
            ),
            (
                "distributed",
                &["mysql", "rabbitmq"][..],
                &RABBIT_DEPENDENCIES[..],
                &RABBIT_FAULTS[..],
            ),
            (
                "redis-compat",
                &["mysql", "redis"][..],
                &REDIS_DEPENDENCIES[..],
                &REDIS_COMPAT_FAULTS[..],
            ),
            ("performance-kernel", &[][..], &[][..], &[][..]),
            (
                "performance-native",
                &["mysql"][..],
                &PERFORMANCE_NATIVE_DEPENDENCIES[..],
                &PERFORMANCE_NATIVE_FAULTS[..],
            ),
        ];
        assert_eq!(validate_profiles(), Ok(8));
        assert_eq!(PROFILE_IDS, expected.map(|(id, _, _, _)| id));
        for (id, services, dependencies, faults) in expected {
            let actual = profile(id).unwrap();
            assert_eq!(actual.services, services, "{id} services");
            assert_eq!(actual.dependencies, dependencies, "{id} dependencies");
            assert_eq!(actual.faults, faults, "{id} faults");
        }
    }

    #[test]
    fn every_fault_dependency_and_matrix_entry_is_explicit() {
        assert_eq!(FAULT_DEPENDENCIES.len(), 18);
        assert_eq!(
            fault_dependencies("local_bus_overflow"),
            Some(["local_bus", "local_projection_bus"].as_slice())
        );
        assert_eq!(
            fault_dependencies("hmac_failure"),
            Some(["gateway_integrity"].as_slice())
        );
        assert_eq!(
            fault_dependencies("unknown_ack"),
            Some(["publication_worker_or_mq"].as_slice())
        );
        assert_eq!(
            fault_dependencies_for("standalone-rabbit", "worker_death_sticky").unwrap(),
            ["publication_worker_or_mq"]
        );
        assert_eq!(
            fault_dependencies_for("native-single-node", "worker_death_sticky").unwrap(),
            ["publication_worker"]
        );
        assert_eq!(
            fault_dependencies_for("redis-compat", "unknown_ack").unwrap(),
            ["publication_worker_or_mq"]
        );
        assert!(fault_dependencies_for("native-kernel", "unknown_ack")
            .unwrap()
            .is_empty());
        for fault in [
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
            "rabbit_transport_unavailable",
            "redis_unavailable",
            "stale_hmac",
            "pointer_movement",
            "worker_restart",
            "lease_expiry",
            "unknown_ack",
        ] {
            assert!(fault_dependencies(fault).is_some(), "{fault}");
        }
        assert!(fault_dependencies("not-a-fault").is_none());
        for profile in PROFILES {
            let matrix = dependency_fault_matrix(profile.id).unwrap();
            assert_eq!(
                matrix.len(),
                profile.dependencies.len() * FAULT_TIMINGS.len()
            );
            for dependency in profile.dependencies {
                for timing in FAULT_TIMINGS {
                    let entry = &matrix[&format!("{dependency}:{timing}")];
                    assert_eq!(entry.profile, profile.id);
                    assert_eq!(entry.dependency, *dependency);
                    assert_eq!(entry.timing, timing);
                    assert_eq!(entry.acceptance, "fail_closed");
                }
            }
        }
    }

    #[test]
    fn unknown_profiles_and_redis_compat_faults_fail_closed() {
        assert_eq!(
            dependency_fault_matrix("not-a-profile").unwrap_err(),
            "unknown_profile:not-a-profile"
        );
        for fault in REDIS_COMPAT_FAULTS {
            assert!(profile("redis-compat").unwrap().faults.contains(&fault));
            for item in PROFILES.iter().filter(|item| item.id != "redis-compat") {
                assert!(!item.faults.contains(&fault), "{}:{fault}", item.id);
            }
        }
        let native = profile("native-single-node").unwrap();
        assert!(!native.dependencies.contains(&"redis"));
        assert!(!native.dependencies.contains(&"rabbitmq"));
        assert_eq!(native.services, &["mysql"]);
    }
}
