//! Offline gate/static contracts for the remaining external or unimplemented
//! suites. These tests do not execute live deployments, external comparators,
//! TLC, Valgrind or excluded service binaries; they pin the prerequisites,
//! source inventories and explicit non-claims so no suite can silently pass
//! without its required environment.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LivePrerequisites {
    pub approved_deployment: bool,
    pub signed_identity: bool,
    pub readiness: bool,
    pub controller: bool,
    pub three_node_state: bool,
    pub current_transport: bool,
    pub durable_evidence: bool,
}

impl LivePrerequisites {
    pub fn none() -> Self {
        Self {
            approved_deployment: false,
            signed_identity: false,
            readiness: false,
            controller: false,
            three_node_state: false,
            current_transport: false,
            durable_evidence: false,
        }
    }

    pub fn all() -> Self {
        Self {
            approved_deployment: true,
            signed_identity: true,
            readiness: true,
            controller: true,
            three_node_state: true,
            current_transport: true,
            durable_evidence: true,
        }
    }

    fn has(&self, requirement: &str) -> bool {
        match requirement {
            "approved_deployment" => self.approved_deployment,
            "signed_identity" => self.signed_identity,
            "readiness" => self.readiness,
            "controller" => self.controller,
            "three_node_state" => self.three_node_state,
            "current_transport" => self.current_transport,
            "durable_evidence" => self.durable_evidence,
            _ => false,
        }
    }
}

pub fn live_gate_blockers<'a>(
    required: &'a [&'a str],
    prerequisites: &LivePrerequisites,
) -> Vec<&'a str> {
    required
        .iter()
        .copied()
        .filter(|requirement| !prerequisites.has(requirement))
        .collect()
}

pub fn dispatch_plan<'a>(
    required: &'a [&'a str],
    prerequisites: &LivePrerequisites,
) -> Option<&'static str> {
    live_gate_blockers(required, prerequisites)
        .is_empty()
        .then_some("run_campaign")
}

#[cfg(test)]
fn assert_live_gate(required: &[&str]) {
    let none = LivePrerequisites::none();
    assert_eq!(live_gate_blockers(required, &none), required);
    assert_eq!(dispatch_plan(required, &none), None);
    let all = LivePrerequisites::all();
    assert!(live_gate_blockers(required, &all).is_empty());
    assert_eq!(dispatch_plan(required, &all), Some("run_campaign"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rq_a_rule_complexity_contract_is_offline_pinned() {
        let source = include_str!("../../bench/engine-comparison/src/main.rs");
        assert!(source.contains("(10_000, 10, \"native-rq-a\")"));
        assert!(source.contains("(10_000, 5_000, \"native-rq-a\")"));
        assert!(source.contains("--allow-large-gradient"));
        assert!(source.contains("native-rq-a"));
    }

    #[test]
    fn rq_b_card_scale_contract_is_offline_pinned() {
        let source = include_str!("../../bench/engine-comparison/src/main.rs");
        assert!(source.contains("(100, 45, \"native-rq-b\")"));
        assert!(source.contains("(1_000_000, 45, \"native-rq-b\")"));
        assert!(source.contains("storage_bytes_estimate"));
        assert!(source.contains("storage_estimate_note"));
    }

    #[test]
    fn rq_compare_layers_contract_is_offline_pinned() {
        let source = include_str!("../../bench/engine-comparison/src/main.rs");
        for engine in [
            "Casbin(Cached)",
            "Cedar(rust)",
            "OPA(cached)",
            "OPA(no-cache)",
        ] {
            assert!(source.contains(engine), "{engine}");
        }
        assert!(source.contains("SpiceDB"));
    }

    #[test]
    fn rq5_toctou_requires_live_prerequisites() {
        assert_live_gate(&["approved_deployment", "signed_identity", "durable_evidence"]);
    }

    #[test]
    fn rq5_stale_token_replay_requires_live_prerequisites() {
        assert_live_gate(&["three_node_state", "signed_identity", "durable_evidence"]);
    }

    #[test]
    fn rq5_throughput_requires_live_prerequisites() {
        assert_live_gate(&["approved_deployment", "three_node_state", "readiness"]);
    }

    #[test]
    fn rq_current_distributed_campaign_requires_live_prerequisites() {
        assert_live_gate(&[
            "approved_deployment",
            "current_transport",
            "three_node_state",
            "durable_evidence",
        ]);
    }

    #[test]
    fn native_http_campaign_requires_live_prerequisites() {
        assert_live_gate(&[
            "approved_deployment",
            "signed_identity",
            "readiness",
            "durable_evidence",
        ]);
    }

    #[test]
    fn native_live_fault_campaign_requires_live_prerequisites() {
        assert_live_gate(&["approved_deployment", "controller", "signed_identity"]);
    }

    #[test]
    fn mt_e2_has_no_fabricated_executable_suite() {
        let manifest = include_str!("../../tests-suite/MANIFEST.toml");
        assert_eq!(manifest.matches("id = \"mt-e2-unimplemented\"").count(), 1);
        assert!(!manifest.contains("id = \"mt-e2-native\""));
        assert!(!manifest.contains("id = \"mt-e2-executable\""));
    }

    #[test]
    fn tlc_admission_model_is_a_pinned_tla_contract() {
        let tla = include_str!("../../formal/DualCard.tla");
        let cfg = include_str!("../../formal/DualCard.cfg");
        for invariant in [
            "INV1_IdentityCardUnique",
            "INV2_ActiveBelongsToUser",
            "INV3_ActiveCardIsActive",
            "INV6_ContextIdGloballyUnique",
            "INV_OwnerMapping",
            "INV5_AuditTraceability",
            "RuleIsolation",
        ] {
            assert!(
                cfg.contains(invariant) || tla.contains(invariant),
                "{invariant}"
            );
        }
        assert!(cfg.contains("CHECK_DEADLOCK TRUE"));
        let runner = include_str!("../../formal/run-tlc.sh");
        assert!(runner.contains("tlc2.TLC"));
    }

    #[test]
    fn iai_benchmark_is_linux_valgrind_only() {
        let manifest = include_str!("../../policy-engine/Cargo.toml");
        assert!(manifest.contains("name = \"authorization_compiler_iai\""));
        assert!(manifest.contains("required-features = [\"iai\"]"));
        assert!(manifest.contains("iai-callgrind"));
        let bench = include_str!("../../policy-engine/benches/authorization_compiler_iai.rs");
        assert!(!bench.is_empty());
    }

    #[test]
    fn historical_engine_comparison_inventory_is_explicit() {
        let source = include_str!("../../bench/engine-comparison/src/main.rs");
        assert!(source.contains("Casbin(Cached)"));
        assert!(source.contains("Cedar(rust)"));
        assert!(source.contains("OPA"));
        assert!(source.contains("SpiceDB"));
    }

    #[test]
    fn excluded_service_sources_are_outside_the_workspace_gate() {
        let root = include_str!("../../Cargo.toml");
        for excluded in [
            "\"astral-learn\"",
            "\"astral-chat\"",
            "\"astral-cache\"",
            "\"integrations\"",
        ] {
            assert!(root.contains(excluded), "{excluded}");
        }
        let chat_tests = include_str!("../../astral-chat/tests/integration.rs");
        let learn_tests = include_str!("../../astral-learn/tests/integration.rs");
        assert!(chat_tests.contains("#["));
        assert!(learn_tests.contains("#["));
        let verifier = include_str!("../../scripts/verify-excluded-services.ps1");
        assert!(verifier.contains("astral-chat"));
        assert!(verifier.contains("astral-learn"));
        assert!(verifier.contains("cargo test"));
    }

    #[test]
    fn excluded_sdk_integrations_require_service_identities() {
        let workspace = include_str!("../../integrations/Cargo.toml");
        assert!(workspace.contains("[workspace]"));
        for test_file in [
            include_str!("../../integrations/chat/tests/admission.rs"),
            include_str!("../../integrations/chat/tests/websocket.rs"),
            include_str!("../../integrations/learn/tests/admission.rs"),
            include_str!("../../integrations/learn/tests/axum.rs"),
        ] {
            assert!(test_file.contains("TestApplication"));
            assert!(test_file.contains("TestDecisionServer"));
        }
        let readme = include_str!("../../integrations/README.md");
        assert!(readme.to_ascii_lowercase().contains("mysql"));
    }
}
