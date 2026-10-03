//! TrustGraph authorization lifecycle metrics.
//!
//! Every label in this module is a closed enum. Authorization identities,
//! request correlation identifiers, raw paths, and error details belong in
//! structured evidence/audit logs, never in Prometheus labels.

use std::time::Duration;

use astral_types::PolicyDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationAdmissionOutcome {
    Admitted,
    RejectedPolicy,
    RejectedSod,
    RejectedContext,
    RejectedMethodOrRoute,
}

impl AuthorizationAdmissionOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::RejectedPolicy => "rejected_policy",
            Self::RejectedSod => "rejected_sod",
            Self::RejectedContext => "rejected_context",
            Self::RejectedMethodOrRoute => "rejected_method_or_route",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationDecisionOutcome {
    Allow,
    Deny,
    Pending,
    Error,
}

impl AuthorizationDecisionOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Pending => "pending",
            Self::Error => "error",
        }
    }
}

pub(crate) fn classify_policy_decision(decision: &PolicyDecision) -> AuthorizationDecisionOutcome {
    if decision.allowed {
        return AuthorizationDecisionOutcome::Allow;
    }
    match decision.reason.as_str() {
        "AUTHORIZATION_PENDING" => AuthorizationDecisionOutcome::Pending,
        "DEPENDENCY_UNAVAILABLE" | "RULE_SET_UNAVAILABLE" | "CIRCUIT_BREAKER_OPEN" => {
            AuthorizationDecisionOutcome::Error
        }
        "AUTHN_REQUIRED"
        | "CARD_REQUIRED"
        | "CARD_DISABLED"
        | "RESOURCE_REQUIRED"
        | "ACTION_REQUIRED"
        | "DEFAULT_DENY"
        | "RULE_SET_DENY"
        | "REALTIME_DENY"
        | "ORG_AUTHORITY_DISABLED"
        | "GLOBAL_ADMIN_REQUIRED" => AuthorizationDecisionOutcome::Deny,
        _ => AuthorizationDecisionOutcome::Error,
    }
}

pub(crate) fn record_authorization_decision(outcome: AuthorizationDecisionOutcome) {
    metrics::counter!(
        "astral_authz_decisions_total",
        "outcome" => outcome.label()
    )
    .increment(1);
}

pub(crate) fn record_authorization_request(
    outcome: AuthorizationAdmissionOutcome,
    elapsed: Duration,
) {
    let label = outcome.label();
    metrics::counter!(
        "astral_authz_admissions_total",
        "outcome" => label
    )
    .increment(1);
    metrics::histogram!(
        "astral_authz_request_duration_seconds",
        "outcome" => label
    )
    .record(elapsed.as_secs_f64());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SodCheckOutcome {
    Clear,
    Conflict,
    Unavailable,
}

impl SodCheckOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
        }
    }
}

pub(crate) fn record_sod_check(outcome: SodCheckOutcome, elapsed: Duration) {
    let label = outcome.label();
    metrics::counter!(
        "astral_authz_sod_checks_total",
        "outcome" => label
    )
    .increment(1);
    metrics::histogram!(
        "astral_authz_sod_check_duration_seconds",
        "outcome" => label
    )
    .record(elapsed.as_secs_f64());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectorEventOutcome {
    Claimed,
    Published,
    ReleasedRetry,
    Quarantined,
    Blocked,
    LeaseLost,
    PublicationUnknown,
    CommittedMirrorUnavailable,
    Superseded,
    PointerMovedReplanned,
    BudgetExhausted,
    QuarantineUnknown,
    DeadlineExceeded,
}

impl ProjectorEventOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Published => "published",
            Self::ReleasedRetry => "released_retry",
            Self::Quarantined => "quarantined",
            Self::Blocked => "blocked",
            Self::LeaseLost => "lease_lost",
            Self::PublicationUnknown => "publication_unknown",
            Self::CommittedMirrorUnavailable => "committed_mirror_unavailable",
            Self::Superseded => "superseded",
            Self::PointerMovedReplanned => "pointer_moved_replanned",
            Self::BudgetExhausted => "budget_exhausted",
            Self::QuarantineUnknown => "quarantine_unknown",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }
}

pub(crate) fn record_projector_event(outcome: ProjectorEventOutcome) {
    metrics::counter!(
        "astral_authz_projector_events_total",
        "outcome" => outcome.label()
    )
    .increment(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectorPhase {
    Readback,
    Observe,
    Ledger,
    Decide,
    Publish,
    Total,
}

impl ProjectorPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Readback => "readback",
            Self::Observe => "observe",
            Self::Ledger => "ledger",
            Self::Decide => "decide",
            Self::Publish => "publish",
            Self::Total => "total",
        }
    }
}

pub(crate) fn record_projector_phase(phase: ProjectorPhase, elapsed: Duration) {
    metrics::histogram!(
        "astral_authz_projector_phase_duration_seconds",
        "phase" => phase.label()
    )
    .record(elapsed.as_secs_f64());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncPublishMetricOutcome {
    Published,
    Delegated,
    Failed,
    SkippedEmpty,
    SkippedImpactThreshold,
}

impl SyncPublishMetricOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Delegated => "delegated",
            Self::Failed => "failed",
            Self::SkippedEmpty => "skipped_empty",
            Self::SkippedImpactThreshold => "skipped_impact_threshold",
        }
    }
}

pub(crate) fn record_sync_publish(outcome: SyncPublishMetricOutcome, elapsed: Duration) {
    let label = outcome.label();
    metrics::counter!(
        "astral_authz_sync_publish_total",
        "outcome" => label
    )
    .increment(1);
    metrics::histogram!(
        "astral_authz_sync_publish_duration_seconds",
        "outcome" => label
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::{
        classify_policy_decision, record_authorization_decision, record_authorization_request,
        record_projector_event, record_projector_phase, record_sod_check, record_sync_publish,
        AuthorizationAdmissionOutcome, AuthorizationDecisionOutcome, ProjectorEventOutcome,
        ProjectorPhase, SodCheckOutcome, SyncPublishMetricOutcome,
    };
    use astral_types::PolicyDecision;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use std::sync::{Once, OnceLock};

    static INSTALL: Once = Once::new();
    static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

    fn shared_handle() -> PrometheusHandle {
        INSTALL.call_once(|| {
            let _ = HANDLE.set(PrometheusBuilder::new().install_recorder().ok());
        });
        HANDLE
            .get()
            .expect("handle slot initialized")
            .as_ref()
            .expect("first install in test process must succeed")
            .clone()
    }

    fn decision(allowed: bool, reason: &str) -> PolicyDecision {
        PolicyDecision {
            allowed,
            reason: reason.to_owned(),
            matched_rule: None,
            audit_required: false,
            evaluation_path: Vec::new(),
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: None,
        }
    }

    #[test]
    fn decision_outcomes_use_only_the_closed_metric_vocabulary() {
        assert_eq!(
            classify_policy_decision(&decision(true, "PUBLISHED_EVIDENCE_ALLOW")),
            AuthorizationDecisionOutcome::Allow
        );
        for reason in [
            "AUTHN_REQUIRED",
            "CARD_REQUIRED",
            "CARD_DISABLED",
            "RESOURCE_REQUIRED",
            "ACTION_REQUIRED",
            "DEFAULT_DENY",
            "RULE_SET_DENY",
            "REALTIME_DENY",
            "ORG_AUTHORITY_DISABLED",
            "GLOBAL_ADMIN_REQUIRED",
        ] {
            assert_eq!(
                classify_policy_decision(&decision(false, reason)),
                AuthorizationDecisionOutcome::Deny,
                "{reason} must remain a bounded deny outcome"
            );
        }
        assert_eq!(
            classify_policy_decision(&decision(false, "AUTHORIZATION_PENDING")),
            AuthorizationDecisionOutcome::Pending
        );
        for reason in [
            "DEPENDENCY_UNAVAILABLE",
            "RULE_SET_UNAVAILABLE",
            "CIRCUIT_BREAKER_OPEN",
            "unexpected dynamic failure",
        ] {
            assert_eq!(
                classify_policy_decision(&decision(false, reason)),
                AuthorizationDecisionOutcome::Error,
                "{reason} must remain a bounded error outcome"
            );
        }
    }

    #[test]
    fn recorders_expose_only_expected_metric_names_and_labels() {
        let handle = shared_handle();
        record_authorization_decision(AuthorizationDecisionOutcome::Pending);
        record_authorization_request(
            AuthorizationAdmissionOutcome::RejectedPolicy,
            std::time::Duration::from_millis(2),
        );
        record_sod_check(
            SodCheckOutcome::Unavailable,
            std::time::Duration::from_millis(2),
        );
        record_projector_event(ProjectorEventOutcome::Published);
        record_projector_phase(ProjectorPhase::Publish, std::time::Duration::from_millis(3));
        record_sync_publish(
            SyncPublishMetricOutcome::Delegated,
            std::time::Duration::from_millis(4),
        );
        let body = handle.render();
        assert!(body.contains("astral_authz_decisions_total"));
        assert!(body.contains("outcome=\"pending\""));
        assert!(body.contains("astral_authz_admissions_total"));
        assert!(body.contains("outcome=\"rejected_policy\""));
        assert!(body.contains("astral_authz_sod_checks_total"));
        assert!(body.contains("outcome=\"unavailable\""));
        assert!(body.contains("astral_authz_projector_events_total"));
        assert!(body.contains("outcome=\"published\""));
        assert!(body.contains("astral_authz_projector_phase_duration_seconds"));
        assert!(body.contains("phase=\"publish\""));
        assert!(body.contains("astral_authz_sync_publish_total"));
        assert!(body.contains("outcome=\"delegated\""));
    }

    fn assert_closed_vocabulary(labels: &[&str]) {
        assert!(labels.iter().all(|label| !label.is_empty()));
        assert!(labels.iter().all(|label| {
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }));
        let unique = labels
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn all_metric_labels_are_bounded_constants() {
        let decisions = [
            AuthorizationDecisionOutcome::Allow,
            AuthorizationDecisionOutcome::Deny,
            AuthorizationDecisionOutcome::Pending,
            AuthorizationDecisionOutcome::Error,
        ];
        assert_closed_vocabulary(&decisions.map(AuthorizationDecisionOutcome::label));
        assert_eq!(decisions.len(), 4);

        let admission = [
            AuthorizationAdmissionOutcome::Admitted,
            AuthorizationAdmissionOutcome::RejectedPolicy,
            AuthorizationAdmissionOutcome::RejectedSod,
            AuthorizationAdmissionOutcome::RejectedContext,
            AuthorizationAdmissionOutcome::RejectedMethodOrRoute,
        ];
        assert_closed_vocabulary(&admission.map(AuthorizationAdmissionOutcome::label));
        assert_eq!(admission.len(), 5);

        let sod = [
            SodCheckOutcome::Clear,
            SodCheckOutcome::Conflict,
            SodCheckOutcome::Unavailable,
        ];
        assert_closed_vocabulary(&sod.map(SodCheckOutcome::label));
        assert_eq!(sod.len(), 3);

        let projector = [
            ProjectorEventOutcome::Claimed,
            ProjectorEventOutcome::Published,
            ProjectorEventOutcome::ReleasedRetry,
            ProjectorEventOutcome::Quarantined,
            ProjectorEventOutcome::Blocked,
            ProjectorEventOutcome::LeaseLost,
            ProjectorEventOutcome::PublicationUnknown,
            ProjectorEventOutcome::CommittedMirrorUnavailable,
            ProjectorEventOutcome::Superseded,
            ProjectorEventOutcome::PointerMovedReplanned,
            ProjectorEventOutcome::BudgetExhausted,
            ProjectorEventOutcome::QuarantineUnknown,
            ProjectorEventOutcome::DeadlineExceeded,
        ];
        assert_closed_vocabulary(&projector.map(ProjectorEventOutcome::label));
        assert_eq!(projector.len(), 13);

        let phases = [
            ProjectorPhase::Readback,
            ProjectorPhase::Observe,
            ProjectorPhase::Ledger,
            ProjectorPhase::Decide,
            ProjectorPhase::Publish,
            ProjectorPhase::Total,
        ];
        assert_closed_vocabulary(&phases.map(ProjectorPhase::label));
        assert_eq!(phases.len(), 6);

        let sync = [
            SyncPublishMetricOutcome::Published,
            SyncPublishMetricOutcome::Delegated,
            SyncPublishMetricOutcome::Failed,
            SyncPublishMetricOutcome::SkippedEmpty,
            SyncPublishMetricOutcome::SkippedImpactThreshold,
        ];
        assert_closed_vocabulary(&sync.map(SyncPublishMetricOutcome::label));
        assert_eq!(sync.len(), 5);
    }
}
