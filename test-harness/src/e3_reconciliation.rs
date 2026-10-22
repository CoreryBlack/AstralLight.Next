use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EVENTS: usize = 20_000;
pub const MAX_EVENT_IDS: usize = 512;
pub const MAX_CROSSCHECK_REQUEST_IDS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    Pass,
    Pending,
    Unknown,
    Blocked,
    Fail,
    Skip,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Pending => "PENDING",
            Self::Unknown => "UNKNOWN",
            Self::Blocked => "BLOCKED",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E3EventKind {
    EnqueueStaged,
    ClaimCommitted,
    PublishCommitted,
    QuarantineCommitted,
    TerminalUnknown,
    BackoffCommitted,
    ReleaseCommitted,
    LeaseLeftToExpire,
    RetryScheduled,
    PointerReplan,
    ReleaseRequested,
}

impl E3EventKind {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::PublishCommitted
                | Self::QuarantineCommitted
                | Self::TerminalUnknown
                | Self::BackoffCommitted
                | Self::ReleaseCommitted
                | Self::LeaseLeftToExpire
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EnqueueStaged => "enqueue_staged",
            Self::ClaimCommitted => "claim_committed",
            Self::PublishCommitted => "publish_committed",
            Self::QuarantineCommitted => "quarantine_committed",
            Self::TerminalUnknown => "terminal_unknown",
            Self::BackoffCommitted => "backoff_committed",
            Self::ReleaseCommitted => "release_committed",
            Self::LeaseLeftToExpire => "lease_left_to_expire",
            Self::RetryScheduled => "retry_scheduled",
            Self::PointerReplan => "pointer_replan",
            Self::ReleaseRequested => "release_requested",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E3Event {
    pub kind: E3EventKind,
    pub node: String,
    pub process_observation_id: String,
    pub sequence: u64,
    pub wall_unix_ns: u64,
    pub delta_event_id: u64,
    pub event_id: String,
    pub operation_id: Option<String>,
    pub attempts: Option<u32>,
    pub durable: Option<bool>,
    pub outcome: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRow {
    pub attempts: u32,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerEventReport {
    pub status: EvidenceStatus,
    pub attempts: u32,
    pub last_attempt: Option<u32>,
    pub terminal: Option<&'static str>,
    pub event_id: Option<String>,
    pub paired_attempts: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptHistoryReport {
    pub status: EvidenceStatus,
    pub events: usize,
    pub attempts: usize,
    pub per_event: BTreeMap<String, PerEventReport>,
    pub unknown: Vec<String>,
    pub attempt_bound_exceeded: Vec<String>,
    pub paired_attempts: usize,
    pub cumulative_attempt_wall_ns: u128,
}

fn empty_report(status: EvidenceStatus, events: usize, problem: &str) -> AttemptHistoryReport {
    AttemptHistoryReport {
        status,
        events,
        attempts: 0,
        per_event: BTreeMap::new(),
        unknown: vec![problem.to_owned()],
        attempt_bound_exceeded: Vec::new(),
        paired_attempts: 0,
        cumulative_attempt_wall_ns: 0,
    }
}

pub fn validate_attempt_history(
    events: &[E3Event],
    durable_rows: Option<&BTreeMap<String, DurableRow>>,
    max_attempts: u32,
) -> AttemptHistoryReport {
    if max_attempts == 0 {
        return empty_report(
            EvidenceStatus::Blocked,
            events.len(),
            "invalid_attempt_bound",
        );
    }
    if events.is_empty() {
        return empty_report(EvidenceStatus::Blocked, 0, "no_authz_e3_events");
    }
    if events.len() > MAX_EVENTS {
        return empty_report(
            EvidenceStatus::Blocked,
            events.len(),
            "event_log_bound_exceeded",
        );
    }

    let mut event_ids = BTreeSet::new();
    let mut epoch_sequences = BTreeMap::<(String, String, u64), ()>::new();
    for event in events {
        if event.sequence == 0
            || event.process_observation_id.is_empty()
            || event.event_id.is_empty()
            || event.attempts == Some(0)
            || event.operation_id.as_ref().is_some_and(String::is_empty)
        {
            return empty_report(EvidenceStatus::Unknown, events.len(), "malformed_e3_event");
        }
        event_ids.insert(event.event_id.as_str());
        let key = (
            event.node.clone(),
            event.process_observation_id.clone(),
            event.sequence,
        );
        if epoch_sequences.insert(key, ()).is_some() {
            return empty_report(
                EvidenceStatus::Unknown,
                events.len(),
                "duplicate_process_local_sequence",
            );
        }
    }
    if event_ids.len() > MAX_EVENT_IDS {
        return empty_report(
            EvidenceStatus::Blocked,
            events.len(),
            "event_id_bound_exceeded",
        );
    }

    let mut by_delta = BTreeMap::<u64, Vec<&E3Event>>::new();
    for event in events {
        by_delta
            .entry(event.delta_event_id)
            .or_default()
            .push(event);
    }

    let mut per_event = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    let mut attempts_total = 0usize;
    let mut paired_total = 0usize;
    let mut pending = false;
    let mut attempt_bound_exceeded = Vec::new();

    for (delta_id, history) in by_delta {
        let key = delta_id.to_string();
        let mut delta_unknown = BTreeSet::new();
        let mut claims = history
            .iter()
            .copied()
            .filter(|event| event.kind == E3EventKind::ClaimCommitted)
            .collect::<Vec<_>>();
        claims.sort_by_key(|event| event.attempts.unwrap_or(0));
        if claims.is_empty() {
            unknown.insert(format!("{delta_id}:missing_claim"));
            per_event.insert(
                key,
                PerEventReport {
                    status: EvidenceStatus::Unknown,
                    attempts: 0,
                    last_attempt: None,
                    terminal: None,
                    event_id: None,
                    paired_attempts: Vec::new(),
                },
            );
            continue;
        }

        let ids = history
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<BTreeSet<_>>();
        let operation_ids = history
            .iter()
            .filter_map(|event| event.operation_id.as_deref())
            .collect::<BTreeSet<_>>();
        if ids.len() != 1 {
            delta_unknown.insert("event_identity_drift".to_owned());
        }
        if operation_ids.len() > 1 {
            delta_unknown.insert("operation_identity_drift".to_owned());
        }

        if claims.iter().any(|event| event.attempts.is_none()) {
            unknown.insert(format!("{delta_id}:claim_attempt_missing"));
            per_event.insert(
                key,
                PerEventReport {
                    status: EvidenceStatus::Unknown,
                    attempts: claims.len() as u32,
                    last_attempt: None,
                    terminal: None,
                    event_id: None,
                    paired_attempts: Vec::new(),
                },
            );
            continue;
        }

        let mut claim_attempts = claims
            .iter()
            .filter_map(|event| event.attempts)
            .collect::<Vec<_>>();
        claim_attempts.sort_unstable();
        attempts_total += claim_attempts.len();
        if claim_attempts.windows(2).any(|pair| pair[0] == pair[1]) {
            delta_unknown.insert("duplicate_attempt".to_owned());
        } else if claim_attempts
            .iter()
            .enumerate()
            .any(|(index, attempt)| *attempt != index as u32 + 1)
        {
            delta_unknown.insert("attempt_history_gap".to_owned());
        }
        let final_attempt = claim_attempts.last().copied();

        let mut by_process = BTreeMap::<(String, String), Vec<&E3Event>>::new();
        for event in &history {
            by_process
                .entry((event.node.clone(), event.process_observation_id.clone()))
                .or_default()
                .push(event);
        }
        let mut paired = BTreeMap::<u32, (&E3Event, &E3Event)>::new();
        for ((node, process_id), mut process_events) in by_process {
            process_events.sort_by_key(|event| event.sequence);
            let epoch = format!(
                "{}/{}",
                if node.is_empty() {
                    "unknown-node"
                } else {
                    &node
                },
                process_id
            );
            let mut open_claim: Option<&E3Event> = None;
            for event in process_events {
                if event.kind == E3EventKind::EnqueueStaged {
                    continue;
                }
                if event.kind == E3EventKind::ClaimCommitted {
                    if let Some(claim) = open_claim {
                        delta_unknown.insert(format!(
                            "{epoch}:attempt_{}:claim_without_terminal",
                            claim.attempts.unwrap_or(0)
                        ));
                    }
                    open_claim = Some(event);
                    continue;
                }
                let Some(claim) = open_claim else {
                    delta_unknown.insert(format!(
                        "{epoch}:{}:without_open_claim",
                        event.kind.as_str()
                    ));
                    continue;
                };
                if event.event_id != claim.event_id {
                    delta_unknown.insert(format!(
                        "{epoch}:attempt_{}:event_identity_drift",
                        claim.attempts.unwrap_or(0)
                    ));
                }
                if event.operation_id.is_some() && event.operation_id != claim.operation_id {
                    delta_unknown.insert(format!(
                        "{epoch}:attempt_{}:operation_identity_drift",
                        claim.attempts.unwrap_or(0)
                    ));
                }
                if event.attempts.is_some() && event.attempts != claim.attempts {
                    delta_unknown.insert(format!(
                        "{epoch}:attempt_{}:attempt_identity_drift",
                        claim.attempts.unwrap_or(0)
                    ));
                }
                if event.kind.is_terminal() {
                    let attempt = claim.attempts.unwrap_or(0);
                    if paired.insert(attempt, (claim, event)).is_some() {
                        delta_unknown.insert(format!("attempt_{attempt}:multiple_terminal_pairs"));
                    }
                    open_claim = None;
                }
            }
            if let Some(claim) = open_claim {
                delta_unknown.insert(format!(
                    "{epoch}:attempt_{}:claim_without_terminal",
                    claim.attempts.unwrap_or(0)
                ));
            }
        }

        for attempt in &claim_attempts {
            if !paired.contains_key(attempt) {
                delta_unknown.insert(format!("attempt_{attempt}:missing_process_local_terminal"));
            }
        }
        paired_total += paired.len();
        if paired.is_empty() {
            delta_unknown.insert("no_paired_attempt".to_owned());
            unknown.extend(
                delta_unknown
                    .into_iter()
                    .map(|reason| format!("{delta_id}:{reason}")),
            );
            per_event.insert(
                key,
                PerEventReport {
                    status: EvidenceStatus::Unknown,
                    attempts: claims.len() as u32,
                    last_attempt: final_attempt,
                    terminal: None,
                    event_id: None,
                    paired_attempts: Vec::new(),
                },
            );
            continue;
        }

        let selected_attempt = final_attempt
            .filter(|attempt| paired.contains_key(attempt))
            .or_else(|| paired.keys().next_back().copied())
            .expect("paired attempt exists");
        for (attempt, (_, terminal)) in &paired {
            if terminal.kind == E3EventKind::TerminalUnknown || terminal.durable != Some(true) {
                delta_unknown.insert(format!("attempt_{attempt}:outcome_unknown"));
            }
            if Some(*attempt) < final_attempt
                && matches!(
                    terminal.kind,
                    E3EventKind::PublishCommitted | E3EventKind::QuarantineCommitted
                )
            {
                delta_unknown.insert(format!(
                    "attempt_{attempt}:terminal_state_precedes_later_claim"
                ));
            }
        }
        let (_, terminal) = paired[&selected_attempt];
        let mut event_status = match terminal.kind {
            E3EventKind::TerminalUnknown => {
                delta_unknown.insert(
                    terminal
                        .outcome
                        .clone()
                        .unwrap_or_else(|| terminal.kind.as_str().to_owned()),
                );
                EvidenceStatus::Unknown
            }
            E3EventKind::BackoffCommitted
            | E3EventKind::ReleaseCommitted
            | E3EventKind::LeaseLeftToExpire
                if terminal.durable == Some(true) =>
            {
                pending = true;
                EvidenceStatus::Pending
            }
            E3EventKind::PublishCommitted
                if terminal.durable == Some(true)
                    && terminal.outcome.as_deref() == Some("succeeded") =>
            {
                EvidenceStatus::Pass
            }
            E3EventKind::QuarantineCommitted
                if terminal.durable == Some(true)
                    && terminal.outcome.as_deref() == Some("quarantined") =>
            {
                EvidenceStatus::Pass
            }
            _ => {
                delta_unknown.insert(format!(
                    "invalid_terminal:{}:{}",
                    terminal.kind.as_str(),
                    terminal.outcome.as_deref().unwrap_or("")
                ));
                EvidenceStatus::Unknown
            }
        };

        if let Some(rows) = durable_rows {
            match rows.get(&terminal.event_id) {
                None => {
                    event_status = EvidenceStatus::Unknown;
                    delta_unknown.insert("missing_durable_row".to_owned());
                }
                Some(row) => {
                    if Some(row.attempts) != final_attempt {
                        event_status = EvidenceStatus::Unknown;
                        delta_unknown.insert("durable_attempt_mismatch".to_owned());
                    }
                    let expected_status = match terminal.kind {
                        E3EventKind::PublishCommitted => Some("SUCCEEDED"),
                        E3EventKind::QuarantineCommitted => Some("QUARANTINED"),
                        E3EventKind::BackoffCommitted | E3EventKind::ReleaseCommitted => {
                            Some("PENDING")
                        }
                        E3EventKind::LeaseLeftToExpire => Some("LEASED"),
                        _ => None,
                    };
                    let row_status_matches = match expected_status {
                        Some("LEASED") => matches!(row.status.as_str(), "LEASED" | "PENDING"),
                        Some(expected) => row.status == expected,
                        None => true,
                    };
                    if !row_status_matches {
                        event_status = EvidenceStatus::Unknown;
                        delta_unknown.insert("durable_status_mismatch".to_owned());
                    }
                }
            }
        }

        if let Some(last_attempt) = final_attempt {
            if last_attempt > max_attempts {
                event_status = EvidenceStatus::Unknown;
                attempt_bound_exceeded.push(key.clone());
                delta_unknown.insert("attempt_bound_exceeded".to_owned());
            }
        }
        if !delta_unknown.is_empty() {
            event_status = EvidenceStatus::Unknown;
            unknown.extend(
                delta_unknown
                    .into_iter()
                    .map(|reason| format!("{delta_id}:{reason}")),
            );
        }
        per_event.insert(
            key,
            PerEventReport {
                status: event_status,
                attempts: claims.len() as u32,
                last_attempt: final_attempt,
                terminal: Some(terminal.kind.as_str()),
                event_id: Some(terminal.event_id.clone()),
                paired_attempts: paired.keys().copied().collect(),
            },
        );
    }

    let mut cumulative_attempt_wall_ns = 0u128;
    let mut by_epoch = BTreeMap::<(String, String), Vec<&E3Event>>::new();
    for event in events {
        by_epoch
            .entry((event.node.clone(), event.process_observation_id.clone()))
            .or_default()
            .push(event);
    }
    for process_events in by_epoch.values_mut() {
        process_events.sort_by_key(|event| event.sequence);
        let mut open_claim: Option<&E3Event> = None;
        for event in process_events.iter().copied() {
            if event.kind == E3EventKind::EnqueueStaged {
                continue;
            }
            if event.kind == E3EventKind::ClaimCommitted {
                open_claim = Some(event);
            } else if let Some(claim) = open_claim {
                if event.kind.is_terminal() {
                    cumulative_attempt_wall_ns +=
                        u128::from(event.wall_unix_ns.saturating_sub(claim.wall_unix_ns));
                    open_claim = None;
                }
            }
        }
    }

    let mut status = if !unknown.is_empty() {
        EvidenceStatus::Unknown
    } else if pending {
        EvidenceStatus::Pending
    } else {
        EvidenceStatus::Pass
    };
    if durable_rows.is_none() && status == EvidenceStatus::Pass {
        status = EvidenceStatus::Blocked;
        unknown.insert("durable_row_reconciliation_unavailable".to_owned());
    }
    attempt_bound_exceeded.sort();
    attempt_bound_exceeded.dedup();
    AttemptHistoryReport {
        status,
        events: events.len(),
        attempts: attempts_total,
        per_event,
        unknown: unknown.into_iter().collect(),
        attempt_bound_exceeded,
        paired_attempts: paired_total,
        cumulative_attempt_wall_ns,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionClass {
    Allow,
    Pending,
    Deny,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestDecision {
    pub request_id: String,
    pub classification: DecisionClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestEventKind {
    DecisionReturn,
    HostAdmission,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContext {
    pub user_id: String,
    pub tenant_id: String,
    pub card_id: String,
    pub resource: String,
    pub action: String,
}

impl RequestContext {
    fn is_complete(&self) -> bool {
        [
            self.user_id.as_str(),
            self.tenant_id.as_str(),
            self.card_id.as_str(),
            self.resource.as_str(),
            self.action.as_str(),
        ]
        .iter()
        .all(|value| !value.trim().is_empty())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestEvent {
    pub request_id: String,
    pub kind: RequestEventKind,
    pub node: String,
    pub process_observation_id: String,
    pub sequence: u64,
    pub allowed: Option<bool>,
    pub reason: Option<String>,
    pub context: Option<RequestContext>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrosscheckQuality {
    pub invalid_request_ids: usize,
    pub duplicate_request_ids: Vec<String>,
    pub sample_stream_truncated: bool,
    pub logs_parsed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAdmissionReport {
    pub status: EvidenceStatus,
    pub checked: usize,
    pub confirmed: usize,
    pub verified_non_allow: usize,
    pub unverified: usize,
    pub truncated: bool,
    pub contradictions: Vec<(String, &'static str)>,
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        && value.as_bytes()[0].is_ascii_alphanumeric()
}

pub fn crosscheck_host_admissions(
    decisions: &[RequestDecision],
    events: &[RequestEvent],
    quality: &CrosscheckQuality,
) -> HostAdmissionReport {
    let truncated = quality.sample_stream_truncated || decisions.len() > MAX_CROSSCHECK_REQUEST_IDS;
    let decisions = decisions
        .iter()
        .take(MAX_CROSSCHECK_REQUEST_IDS)
        .collect::<Vec<_>>();
    let ids = decisions
        .iter()
        .map(|decision| decision.request_id.as_str())
        .collect::<Vec<_>>();
    let mut by_id = BTreeMap::<&str, Vec<&RequestEvent>>::new();
    for event in events {
        by_id
            .entry(event.request_id.as_str())
            .or_default()
            .push(event);
    }

    let mut contradictions = Vec::new();
    let mut confirmed = 0;
    let mut verified_non_allow = 0;
    let mut unverified = 0;
    for decision in &decisions {
        let request_id = decision.request_id.as_str();
        let Some(observations) = by_id.get(request_id) else {
            unverified += 1;
            continue;
        };
        let decision_returns = observations
            .iter()
            .copied()
            .filter(|event| event.kind == RequestEventKind::DecisionReturn)
            .collect::<Vec<_>>();
        let admissions = observations
            .iter()
            .copied()
            .filter(|event| event.kind == RequestEventKind::HostAdmission)
            .collect::<Vec<_>>();
        if decision_returns.len() != 1 {
            if decision_returns.len() > 1 {
                contradictions.push((request_id.to_owned(), "duplicate_decision_return"));
            } else {
                unverified += 1;
            }
            continue;
        }
        let returned = decision_returns[0];
        let Some(context) = returned
            .context
            .as_ref()
            .filter(|context| context.is_complete())
        else {
            unverified += 1;
            continue;
        };
        if decision.classification == DecisionClass::Unknown {
            unverified += 1;
            continue;
        }
        if decision.classification == DecisionClass::Allow {
            if returned.allowed != Some(true) {
                contradictions.push((request_id.to_owned(), "probe_allow_host_denial"));
            } else if admissions.len() > 1 {
                contradictions.push((request_id.to_owned(), "duplicate_host_admission"));
            } else if admissions.len() == 1 {
                let admission = admissions[0];
                let Some(admission_context) = admission
                    .context
                    .as_ref()
                    .filter(|value| value.is_complete())
                else {
                    unverified += 1;
                    continue;
                };
                if admission.node != returned.node
                    || admission.process_observation_id != returned.process_observation_id
                    || admission.sequence <= returned.sequence
                    || admission_context != context
                {
                    contradictions.push((
                        request_id.to_owned(),
                        "host_admission_identity_order_or_context_mismatch",
                    ));
                } else {
                    confirmed += 1;
                }
            } else {
                unverified += 1;
            }
        } else if returned.allowed == Some(true) || !admissions.is_empty() {
            contradictions.push((
                request_id.to_owned(),
                "probe_non_admission_with_host_admission",
            ));
        } else if returned.allowed.is_none()
            || returned
                .reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            unverified += 1;
        } else {
            let pending_reason = returned
                .reason
                .as_deref()
                .unwrap_or_default()
                .to_ascii_uppercase()
                .contains("AUTHORIZATION_PENDING");
            if (decision.classification == DecisionClass::Pending) != pending_reason {
                contradictions.push((request_id.to_owned(), "probe_host_decision_reason_mismatch"));
            } else {
                verified_non_allow += 1;
            }
        }
    }

    let duplicate_ids = !quality.duplicate_request_ids.is_empty()
        || ids.iter().collect::<BTreeSet<_>>().len() != ids.len();
    let invalid_count = quality.invalid_request_ids
        + decisions
            .iter()
            .filter(|decision| !valid_request_id(&decision.request_id))
            .count();
    let incomplete =
        invalid_count != 0 || duplicate_ids || truncated || unverified != 0 || ids.is_empty();
    let status = if !contradictions.is_empty() {
        EvidenceStatus::Fail
    } else if !quality.logs_parsed {
        EvidenceStatus::Unknown
    } else if incomplete {
        if !ids.is_empty() || invalid_count != 0 || duplicate_ids || truncated {
            EvidenceStatus::Unknown
        } else {
            EvidenceStatus::Blocked
        }
    } else if confirmed + verified_non_allow != ids.len() {
        EvidenceStatus::Unknown
    } else {
        EvidenceStatus::Pass
    };
    HostAdmissionReport {
        status,
        checked: ids.len(),
        confirmed,
        verified_non_allow,
        unverified,
        truncated,
        contradictions,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainSample {
    pub queue_reads_proven: bool,
    pub queue_depths: Vec<Option<u64>>,
    pub worker_ready: bool,
    pub publication_read_success: bool,
    pub indicators_unknown_or_blocked: bool,
}

impl DrainSample {
    fn proves_empty_and_ready(&self) -> bool {
        self.queue_reads_proven
            && !self.queue_depths.is_empty()
            && self.queue_depths.iter().all(|depth| *depth == Some(0))
            && self.worker_ready
    }
}

pub fn publication_drain_status(
    samples: &[DrainSample],
    per_event_status: EvidenceStatus,
) -> EvidenceStatus {
    if samples.is_empty() {
        return EvidenceStatus::Skip;
    }
    if per_event_status == EvidenceStatus::Pass
        && samples.iter().all(DrainSample::proves_empty_and_ready)
    {
        return EvidenceStatus::Pass;
    }
    if samples.iter().any(|sample| sample.publication_read_success)
        || samples
            .iter()
            .any(|sample| sample.indicators_unknown_or_blocked)
    {
        EvidenceStatus::Unknown
    } else {
        EvidenceStatus::Skip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        kind: E3EventKind,
        sequence: u64,
        attempt: Option<u32>,
        durable: Option<bool>,
        outcome: Option<&str>,
    ) -> E3Event {
        E3Event {
            kind,
            node: "node-a".into(),
            process_observation_id: "worker-a".into(),
            sequence,
            wall_unix_ns: 1_000 + sequence * 10,
            delta_event_id: 101,
            event_id: "evt-1".into(),
            operation_id: Some("op-1".into()),
            attempts: attempt,
            durable,
            outcome: outcome.map(str::to_owned),
        }
    }

    fn successful_history() -> Vec<E3Event> {
        vec![
            event(E3EventKind::ClaimCommitted, 1, Some(1), None, None),
            event(
                E3EventKind::PublishCommitted,
                2,
                Some(1),
                Some(true),
                Some("succeeded"),
            ),
        ]
    }

    fn row(status: &str, attempts: u32) -> BTreeMap<String, DurableRow> {
        BTreeMap::from([(
            "evt-1".into(),
            DurableRow {
                attempts,
                status: status.into(),
            },
        )])
    }

    fn context() -> RequestContext {
        RequestContext {
            user_id: "user-1".into(),
            tenant_id: "tenant-1".into(),
            card_id: "card-1".into(),
            resource: "monitor".into(),
            action: "read".into(),
        }
    }

    fn request_event(
        kind: RequestEventKind,
        sequence: u64,
        allowed: Option<bool>,
        reason: Option<&str>,
    ) -> RequestEvent {
        RequestEvent {
            request_id: "req-1".into(),
            kind,
            node: "gateway-a".into(),
            process_observation_id: "request-worker-a".into(),
            sequence,
            allowed,
            reason: reason.map(str::to_owned),
            context: Some(context()),
        }
    }

    fn quality() -> CrosscheckQuality {
        CrosscheckQuality {
            logs_parsed: true,
            ..CrosscheckQuality::default()
        }
    }

    #[test]
    fn durable_publish_history_passes_and_attempt_time_is_advisory() {
        let report = validate_attempt_history(&successful_history(), Some(&row("SUCCEEDED", 1)), 8);
        assert_eq!(report.status, EvidenceStatus::Pass);
        assert_eq!(report.attempts, 1);
        assert_eq!(report.paired_attempts, 1);
        assert_eq!(report.cumulative_attempt_wall_ns, 10);
        assert_eq!(report.per_event["101"].terminal, Some("publish_committed"));
    }

    #[test]
    fn drain_tail_remains_pending_and_unknown_ack_never_passes() {
        let mut backoff = event(
            E3EventKind::BackoffCommitted,
            2,
            Some(1),
            Some(true),
            Some("retry_scheduled"),
        );
        let claim = event(E3EventKind::ClaimCommitted, 1, Some(1), None, None);
        backoff.wall_unix_ns = 1_020;
        let pending = validate_attempt_history(&[claim, backoff], Some(&row("PENDING", 1)), 8);
        assert_eq!(pending.status, EvidenceStatus::Pending);

        let unknown = vec![
            event(E3EventKind::ClaimCommitted, 1, Some(1), None, None),
            event(
                E3EventKind::TerminalUnknown,
                2,
                Some(1),
                Some(true),
                Some("ack_unknown"),
            ),
        ];
        let report = validate_attempt_history(&unknown, Some(&row("UNKNOWN", 1)), 8);
        assert_eq!(report.status, EvidenceStatus::Unknown);
        assert!(report
            .unknown
            .iter()
            .any(|reason| reason == "101:attempt_1:outcome_unknown"));
    }

    #[test]
    fn exact_durable_row_is_required_for_a_passing_terminal() {
        let missing = validate_attempt_history(&successful_history(), Some(&BTreeMap::new()), 8);
        assert_eq!(missing.status, EvidenceStatus::Unknown);
        assert!(missing
            .unknown
            .iter()
            .any(|reason| reason == "101:missing_durable_row"));

        let mismatch =
            validate_attempt_history(&successful_history(), Some(&row("QUARANTINED", 1)), 8);
        assert_eq!(mismatch.status, EvidenceStatus::Unknown);
        assert!(mismatch
            .unknown
            .iter()
            .any(|reason| reason == "101:durable_status_mismatch"));

        let unavailable = validate_attempt_history(&successful_history(), None, 8);
        assert_eq!(unavailable.status, EvidenceStatus::Blocked);
        assert!(unavailable
            .unknown
            .contains(&"durable_row_reconciliation_unavailable".to_owned()));
    }

    #[test]
    fn a_new_process_cannot_hide_an_unterminated_prior_claim() {
        let mut events = vec![event(E3EventKind::ClaimCommitted, 1, Some(1), None, None)];
        let mut restarted = event(E3EventKind::ClaimCommitted, 1, Some(2), None, None);
        restarted.process_observation_id = "worker-b".into();
        restarted.wall_unix_ns = 2_000;
        events.push(restarted);
        let mut terminal = event(
            E3EventKind::PublishCommitted,
            2,
            Some(2),
            Some(true),
            Some("succeeded"),
        );
        terminal.process_observation_id = "worker-b".into();
        terminal.wall_unix_ns = 2_010;
        events.push(terminal);
        let report = validate_attempt_history(&events, Some(&row("SUCCEEDED", 2)), 8);
        assert_eq!(report.status, EvidenceStatus::Unknown);
        assert!(report
            .unknown
            .iter()
            .any(|reason| reason == "101:attempt_1:missing_process_local_terminal"));
    }

    #[test]
    fn identity_attempt_and_event_bounds_fail_closed() {
        let mut drift = successful_history();
        drift[1].operation_id = Some("op-other".into());
        let report = validate_attempt_history(&drift, Some(&row("SUCCEEDED", 1)), 8);
        assert_eq!(report.status, EvidenceStatus::Unknown);
        assert!(report
            .unknown
            .iter()
            .any(|reason| reason.contains("operation_identity_drift")));

        let over_attempt = vec![
            event(E3EventKind::ClaimCommitted, 1, Some(1), None, None),
            event(
                E3EventKind::BackoffCommitted,
                2,
                Some(1),
                Some(true),
                Some("retry_scheduled"),
            ),
            event(E3EventKind::ClaimCommitted, 3, Some(2), None, None),
            event(
                E3EventKind::PublishCommitted,
                4,
                Some(2),
                Some(true),
                Some("succeeded"),
            ),
        ];
        let over_attempt = validate_attempt_history(&over_attempt, Some(&row("SUCCEEDED", 2)), 1);
        assert_eq!(over_attempt.status, EvidenceStatus::Unknown);
        assert_eq!(over_attempt.attempt_bound_exceeded, ["101"]);

        let duplicate_sequence = vec![
            event(E3EventKind::ClaimCommitted, 1, Some(1), None, None),
            event(
                E3EventKind::PublishCommitted,
                1,
                Some(1),
                Some(true),
                Some("succeeded"),
            ),
        ];
        assert_eq!(
            validate_attempt_history(&duplicate_sequence, Some(&row("SUCCEEDED", 1)), 8).status,
            EvidenceStatus::Unknown
        );
    }

    #[test]
    fn attempt_pairs_stay_within_process_epoch() {
        let mut events = successful_history();
        let mut next_claim = event(E3EventKind::ClaimCommitted, 1, Some(2), None, None);
        next_claim.process_observation_id = "worker-b".into();
        let mut next_terminal = event(
            E3EventKind::BackoffCommitted,
            2,
            Some(2),
            Some(true),
            Some("retry_scheduled"),
        );
        next_terminal.process_observation_id = "worker-b".into();
        events.extend([next_claim, next_terminal]);
        let report = validate_attempt_history(&events, Some(&row("PENDING", 2)), 8);
        assert_eq!(report.cumulative_attempt_wall_ns, 20);
        assert_eq!(report.paired_attempts, 2);
        assert_eq!(report.status, EvidenceStatus::Unknown);
        assert!(report
            .unknown
            .iter()
            .any(|reason| reason.contains("terminal_state_precedes_later_claim")));
    }

    #[test]
    fn host_allow_requires_one_later_matching_admission() {
        let decisions = [RequestDecision {
            request_id: "req-1".into(),
            classification: DecisionClass::Allow,
        }];
        let mut logs = vec![request_event(
            RequestEventKind::DecisionReturn,
            5,
            Some(true),
            Some("RULE_MATCH"),
        )];
        logs.push(request_event(
            RequestEventKind::HostAdmission,
            6,
            Some(true),
            None,
        ));
        let report = crosscheck_host_admissions(&decisions, &logs, &quality());
        assert_eq!(report.status, EvidenceStatus::Pass);
        assert_eq!(report.confirmed, 1);

        logs.pop();
        let missing = crosscheck_host_admissions(&decisions, &logs, &quality());
        assert_eq!(missing.status, EvidenceStatus::Unknown);
        assert_eq!(missing.unverified, 1);
    }

    #[test]
    fn host_admission_contradictions_are_failures() {
        let allow = [RequestDecision {
            request_id: "req-1".into(),
            classification: DecisionClass::Allow,
        }];
        let denied = [request_event(
            RequestEventKind::DecisionReturn,
            5,
            Some(false),
            Some("NO_MATCH"),
        )];
        let report = crosscheck_host_admissions(&allow, &denied, &quality());
        assert_eq!(report.status, EvidenceStatus::Fail);
        assert_eq!(report.contradictions[0].1, "probe_allow_host_denial");

        let pending = [RequestDecision {
            request_id: "req-1".into(),
            classification: DecisionClass::Pending,
        }];
        let admission = vec![
            request_event(
                RequestEventKind::DecisionReturn,
                5,
                Some(false),
                Some("AUTHORIZATION_PENDING"),
            ),
            request_event(RequestEventKind::HostAdmission, 6, Some(true), None),
        ];
        let report = crosscheck_host_admissions(&pending, &admission, &quality());
        assert_eq!(report.status, EvidenceStatus::Fail);
        assert_eq!(
            report.contradictions[0].1,
            "probe_non_admission_with_host_admission"
        );
    }

    #[test]
    fn host_admission_requires_unique_context_and_complete_sampled_ids() {
        let decisions = [RequestDecision {
            request_id: "req-1".into(),
            classification: DecisionClass::Allow,
        }];
        let mut duplicate = vec![
            request_event(
                RequestEventKind::DecisionReturn,
                5,
                Some(true),
                Some("RULE_MATCH"),
            ),
            request_event(
                RequestEventKind::DecisionReturn,
                6,
                Some(true),
                Some("RULE_MATCH"),
            ),
            request_event(RequestEventKind::HostAdmission, 7, Some(true), None),
        ];
        let report = crosscheck_host_admissions(&decisions, &duplicate, &quality());
        assert_eq!(report.status, EvidenceStatus::Fail);
        assert_eq!(report.contradictions[0].1, "duplicate_decision_return");

        duplicate.truncate(2);
        duplicate[1].kind = RequestEventKind::HostAdmission;
        duplicate[1].context.as_mut().unwrap().card_id = "card-other".into();
        let report = crosscheck_host_admissions(&decisions, &duplicate, &quality());
        assert_eq!(report.status, EvidenceStatus::Fail);
        assert_eq!(
            report.contradictions[0].1,
            "host_admission_identity_order_or_context_mismatch"
        );

        let mut incomplete = quality();
        incomplete.sample_stream_truncated = true;
        let report = crosscheck_host_admissions(&decisions, &duplicate, &incomplete);
        assert_eq!(report.status, EvidenceStatus::Fail);
    }

    #[test]
    fn non_allow_reason_and_missing_logs_preserve_unknown_boundaries() {
        let decisions = [RequestDecision {
            request_id: "req-1".into(),
            classification: DecisionClass::Deny,
        }];
        let logs = [request_event(
            RequestEventKind::DecisionReturn,
            1,
            Some(false),
            Some("AUTHORIZATION_PENDING"),
        )];
        let report = crosscheck_host_admissions(&decisions, &logs, &quality());
        assert_eq!(report.status, EvidenceStatus::Fail);
        assert_eq!(
            report.contradictions[0].1,
            "probe_host_decision_reason_mismatch"
        );

        let consistent_logs = [request_event(
            RequestEventKind::DecisionReturn,
            1,
            Some(false),
            Some("NO_MATCH"),
        )];
        let mut no_parse = quality();
        no_parse.logs_parsed = false;
        assert_eq!(
            crosscheck_host_admissions(&decisions, &consistent_logs, &no_parse).status,
            EvidenceStatus::Unknown
        );
        assert_eq!(
            crosscheck_host_admissions(&[], &[], &quality()).status,
            EvidenceStatus::Blocked
        );
        let mut bad_ids = quality();
        bad_ids.invalid_request_ids = 1;
        assert_eq!(
            crosscheck_host_admissions(&decisions, &consistent_logs, &bad_ids).status,
            EvidenceStatus::Unknown
        );
    }

    #[test]
    fn queue_reads_alone_do_not_prove_publication_drain() {
        let read_only = [DrainSample {
            queue_reads_proven: true,
            queue_depths: vec![Some(3)],
            worker_ready: true,
            publication_read_success: true,
            indicators_unknown_or_blocked: false,
        }];
        assert_eq!(
            publication_drain_status(&read_only, EvidenceStatus::Pass),
            EvidenceStatus::Unknown
        );
        let proven = [DrainSample {
            queue_depths: vec![Some(0), Some(0)],
            ..read_only[0].clone()
        }];
        assert_eq!(
            publication_drain_status(&proven, EvidenceStatus::Pass),
            EvidenceStatus::Pass
        );
        assert_eq!(
            publication_drain_status(&proven, EvidenceStatus::Pending),
            EvidenceStatus::Unknown
        );
        assert_eq!(
            publication_drain_status(&[], EvidenceStatus::Pass),
            EvidenceStatus::Skip
        );
    }
}
