//! Pure Phase E invalidation recovery contract.
//!
//! Models the typed outbox / inbox / authority states, the exact message
//! provenance that every settlement decision must match, and a fail-closed
//! event reducer for the invalidation recovery pipeline. The model performs
//! no I/O: no DB, no MQ, no wall clock, no services or containers. `Tick` is
//! a caller-supplied logical clock and every event is applied atomically —
//! a rejected event leaves the world bit-for-bit unchanged.
//!
//! Fail-closed rules encoded here:
//! - Outbox `Processed` is reachable only with durable proof: the consumer's
//!   durable mark-applied, or an exact settlement that asserts durable
//!   publication evidence. A broker admission alone is transport-level and
//!   never settles.
//! - Broker/ACK `Unknown` outcomes force `InDoubt`; they never settle and
//!   never requeue by themselves. `InDoubt` resolves only through an exact
//!   settlement (provenance echo required) or a durable mark-applied.
//! - Requeue and quarantine are explicit settlement outcomes (quarantine is
//!   also an explicit event from non-terminal states); no unknown outcome
//!   implicitly discards or retries work.
//! - Inbox applies and mark-applied are strictly in-order against the
//!   authority watermark. Duplicates are idempotent no-ops; reorders and
//!   gaps never apply, never mark, and never advance the watermark.
//! - Watermarks and authority generations are monotonic; regressions are
//!   refused, not clamped. Stale-generation messages (older than the
//!   authority generation fence) are refused at apply time.
//! - Authorities boot `Suspect` and return to `Serving` only through a
//!   durable reconciliation that proves both durability and transport
//!   liveness at a current generation.

use std::collections::BTreeMap;

/// Logical, monotonic clock tick supplied by the caller (no wall clock).
pub type Tick = u64;

/// Lease length granted on every claim and heartbeat renewal, in ticks.
pub const LEASE_TICKS: Tick = 8;

/// Opaque SHA-256-sized digest of the published payload. Exact provenance
/// matching treats the digest as an integrity fence: any difference refuses
/// settlement instead of approximating a match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadDigest(pub [u8; 32]);

/// Ordering coordinates of a message inside the invalidation stream.
///
/// The watermark is tracked per `(tenant_id, partition)` so tenants can
/// never advance or observe each other's sequencing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderingKey {
    pub tenant_id: String,
    pub partition: u64,
    pub sequence: u64,
}

/// Exact provenance attached to every outbox and inbox record.
///
/// Every settlement decision must echo this record field-for-field before
/// the reducer accepts it; a mismatch is refused (`ProvenanceMismatch`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    pub operation_id: String,
    pub message_id: String,
    pub message_type: String,
    pub queue: String,
    pub ordering: OrderingKey,
    pub payload_digest: PayloadDigest,
    /// Publication identity (publisher instance that produced the message).
    pub publication_identity: String,
    /// Authority generation fence at publication time.
    pub generation: u64,
    /// Logical publication stamp (tick at publication).
    pub publication_stamp: Tick,
}

/// Lifecycle of an outbox (publish-side) record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboxState {
    /// Enqueued in the source transaction, not yet claimed.
    Pending,
    /// Claimed by a worker under a bounded lease.
    Processing { lease_until: Tick, owner: String },
    /// Outcome unknown (lost ACK, expired lease, broker unknown); requires
    /// exact settlement or durable mark-applied before any terminal state.
    InDoubt,
    /// Durable completion proven. Terminal.
    Processed,
    /// Explicitly parked for human review. Terminal.
    Quarantined,
}

impl OutboxState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing { .. } => "processing",
            Self::InDoubt => "in_doubt",
            Self::Processed => "processed",
            Self::Quarantined => "quarantined",
        }
    }
}

/// Lifecycle of an inbox (consume-side) record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboxState {
    /// No durable inbox row exists for the message.
    Absent,
    /// Known but not yet durably applied (in-order staging, gap buffering,
    /// or a failed apply awaiting retry).
    Pending,
    /// Durably applied. Terminal and idempotent.
    Applied,
}

impl InboxState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Pending => "pending",
            Self::Applied => "applied",
        }
    }
}

/// Lifecycle of the authority that serves authorization decisions for one
/// tenant/partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityState {
    /// Fail-closed: deny decisions until durable reconciliation proves otherwise.
    Suspect,
    /// Reconciliation in progress with the last observed evidence flags.
    Reconciling {
        durable_proven: bool,
        transport_alive: bool,
    },
    /// Serving decisions; reachable only from a reconciliation that proved
    /// durability and transport liveness at a current generation.
    Serving,
}

impl AuthorityState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Suspect => "suspect",
            Self::Reconciling { .. } => "reconciling",
            Self::Serving => "serving",
        }
    }
}

/// Transport-level outcome of a publish attempt. `Admitted` is a broker
/// confirmation only — it is never durable completion proof on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerOutcome {
    Admitted,
    Rejected,
    Unknown,
}

/// Consumer-side apply outcome for an invalidation message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Success,
    Failure,
}

/// Explicit resolution chosen by an exact settlement over an `InDoubt` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementOutcome {
    /// Mark processed; requires `durable_proven` evidence on the event.
    Processed,
    /// Return to `Pending` for a bounded retry (safe: worst case is a
    /// duplicate publish that the inbox deduplicates).
    Requeue,
    /// Park for human review.
    Quarantine,
}

/// Reducer events covering the Phase E invalidation recovery surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// Worker claims a pending outbox record under a bounded lease. A second
    /// claim while the lease is held is refused (CAS lease semantics).
    Claim {
        message_id: String,
        owner: String,
        now: Tick,
    },
    /// Lease owner renews its lease before expiry (heartbeat).
    Heartbeat {
        message_id: String,
        owner: String,
        now: Tick,
    },
    /// Observed lease expiry; the attempt becomes `InDoubt` because the
    /// publish outcome is unknown.
    LeaseExpired { message_id: String, now: Tick },
    /// Broker outcome for the publish attempt.
    Broker {
        message_id: String,
        outcome: BrokerOutcome,
    },
    /// The publish ACK was lost; the outcome is unknown.
    AckUnknown { message_id: String },
    /// Consumer-side apply of the invalidation.
    Apply {
        message_id: String,
        outcome: ApplyOutcome,
    },
    /// Durable inbox mark; advances the watermark in-order and settles the
    /// outbox to `Processed` with durable proof.
    MarkApplied { message_id: String },
    /// Redelivery of an already-applied message; must be an idempotent no-op.
    Duplicate { message_id: String },
    /// Late/redelivered observation for a known-but-unapplied message; must
    /// not change any state.
    Reorder { message_id: String },
    /// Delivery ahead of the expected sequence; buffered as `Pending`, never
    /// applied or marked until the gap fills.
    Gap { message_id: String },
    /// Explicit watermark advance by an operator/backfill that holds durable
    /// contiguous evidence. Monotonic; regressions are refused.
    WatermarkAdvance { authority: String, to: u64 },
    /// Operator settlement of an `InDoubt` record with an exact provenance
    /// echo. `Processed` additionally requires durable proof.
    ExactSettlement {
        message_id: String,
        echo: Provenance,
        outcome: SettlementOutcome,
        durable_proven: bool,
    },
    /// Explicit quarantine of a poison or unresolved record from a
    /// non-terminal state.
    Quarantine { message_id: String, reason: String },
    /// Authority flagged suspect; fail closed to deny.
    Suspect { authority: String, reason: String },
    /// Durable reconciliation evidence for an authority. Serving is restored
    /// only when durability and transport liveness are both proven at a
    /// current generation.
    DurableReconciliation {
        authority: String,
        durable_proven: bool,
        transport_alive: bool,
        generation: u64,
    },
}

/// Contract violations. Every variant is a refused transition; the reducer
/// never clamps, guesses, or partially applies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    UnknownMessage(String),
    UnknownAuthority(String),
    InvalidTransition {
        subject: String,
        state: String,
        event: &'static str,
    },
    /// The record is already claimed under a live lease (CAS refusal).
    LeaseHeld(String),
    /// A non-owner attempted to renew the lease.
    NotLeaseOwner(String),
    /// Expiry observed before the lease actually lapsed.
    PrematureLeaseExpiry(String),
    /// Apply/mark attempted out of turn (gap unresolved or sequence seen).
    OutOfOrderApply(String),
    /// Settlement echo did not match the record provenance exactly.
    ProvenanceMismatch(String),
    /// Settlement to `Processed` without durable proof.
    DurableProofRequired(String),
    WatermarkRegression {
        authority: String,
        current: u64,
        proposed: u64,
    },
    GenerationRegression {
        authority: String,
        current: u64,
        proposed: u64,
    },
    /// An event carried a logical time older than the current tick.
    ClockRegression,
    Overflow,
}

fn invalid(subject: &str, state: &str, event: &'static str) -> ContractError {
    ContractError::InvalidTransition {
        subject: subject.to_owned(),
        state: state.to_owned(),
        event,
    }
}

/// Authority identity derived from the ordering key: one watermark per
/// tenant/partition, never shared across tenants.
pub fn authority_key(ordering: &OrderingKey) -> String {
    format!("{}#{}", ordering.tenant_id, ordering.partition)
}

/// Outbox (publish-side) record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxRecord {
    pub provenance: Provenance,
    pub state: OutboxState,
    /// Number of accepted claims.
    pub attempts: u32,
    /// Broker confirmed the publish at least once in the current attempt.
    pub transport_confirmed: bool,
    /// Durable completion proof recorded (mark-applied or exact settlement).
    pub durable_proof: bool,
    pub quarantine_reason: Option<String>,
}

/// Inbox (consume-side) record. Present in the map only while `Pending` or
/// `Applied`; `InboxState::Absent` is the answer for unknown messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxRecord {
    pub state: InboxState,
    pub provenance: Provenance,
}

/// Authority record for one tenant/partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRecord {
    pub state: AuthorityState,
    /// Monotonic generation fence.
    pub generation: u64,
    /// Highest contiguously applied sequence (monotonic).
    pub watermark: u64,
    /// Last reconciliation evidence; `Serving` implies both are true.
    pub durable_proven: bool,
    pub transport_alive: bool,
}

/// The modeled world: outbox, inbox and authorities, driven only through
/// [`World::reduce`]. All mutation is atomic per event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct World {
    pub outbox: BTreeMap<String, OutboxRecord>,
    pub inbox: BTreeMap<String, InboxRecord>,
    pub authorities: BTreeMap<String, AuthorityRecord>,
    pub now: Tick,
}

impl World {
    /// Enqueue an outbox record as `Pending` (the durable source-transaction
    /// write). Idempotent for an identical provenance; a different provenance
    /// under the same message id is refused.
    pub fn enqueue(&mut self, provenance: Provenance) -> Result<(), ContractError> {
        let message_id = provenance.message_id.clone();
        match self.outbox.get(&message_id) {
            Some(existing) if existing.provenance == provenance => Ok(()),
            Some(_) => Err(ContractError::ProvenanceMismatch(message_id)),
            None => {
                self.outbox.insert(
                    message_id,
                    OutboxRecord {
                        provenance,
                        state: OutboxState::Pending,
                        attempts: 0,
                        transport_confirmed: false,
                        durable_proof: false,
                        quarantine_reason: None,
                    },
                );
                Ok(())
            }
        }
    }

    /// Register an authority. Boot state is `Suspect` (fail-closed default);
    /// decisions stay denied until a durable reconciliation proves otherwise.
    /// Re-registration with the same generation is idempotent.
    pub fn register_authority(
        &mut self,
        key: impl Into<String>,
        generation: u64,
    ) -> Result<(), ContractError> {
        let key = key.into();
        match self.authorities.get(&key) {
            Some(existing) if existing.generation == generation => Ok(()),
            Some(existing) => Err(ContractError::GenerationRegression {
                authority: key,
                current: existing.generation,
                proposed: generation,
            }),
            None => {
                self.authorities.insert(
                    key,
                    AuthorityRecord {
                        state: AuthorityState::Suspect,
                        generation,
                        watermark: 0,
                        durable_proven: false,
                        transport_alive: false,
                    },
                );
                Ok(())
            }
        }
    }

    pub fn authority(&self, key: &str) -> Option<&AuthorityRecord> {
        self.authorities.get(key)
    }

    /// Inbox state for a message; `Absent` when no durable row exists.
    pub fn inbox_state(&self, message_id: &str) -> InboxState {
        self.inbox
            .get(message_id)
            .map(|record| record.state.clone())
            .unwrap_or(InboxState::Absent)
    }

    fn outbox(&self, message_id: &str) -> Result<&OutboxRecord, ContractError> {
        self.outbox
            .get(message_id)
            .ok_or_else(|| ContractError::UnknownMessage(message_id.to_owned()))
    }

    fn outbox_mut(&mut self, message_id: &str) -> Result<&mut OutboxRecord, ContractError> {
        self.outbox
            .get_mut(message_id)
            .ok_or_else(|| ContractError::UnknownMessage(message_id.to_owned()))
    }

    fn require_authority(&self, key: &str) -> Result<&AuthorityRecord, ContractError> {
        self.authorities
            .get(key)
            .ok_or_else(|| ContractError::UnknownAuthority(key.to_owned()))
    }

    fn require_authority_mut(&mut self, key: &str) -> Result<&mut AuthorityRecord, ContractError> {
        self.authorities
            .get_mut(key)
            .ok_or_else(|| ContractError::UnknownAuthority(key.to_owned()))
    }

    /// Apply one event atomically. A rejected event leaves the world
    /// unchanged; an accepted event keeps every fail-closed invariant.
    pub fn reduce(&mut self, event: &Event) -> Result<(), ContractError> {
        match event {
            Event::Claim {
                message_id,
                owner,
                now,
            } => {
                if *now < self.now {
                    return Err(ContractError::ClockRegression);
                }
                let lease_until = now
                    .checked_add(LEASE_TICKS)
                    .ok_or(ContractError::Overflow)?;
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                match current {
                    OutboxState::Pending => {
                        record.state = OutboxState::Processing {
                            lease_until,
                            owner: owner.clone(),
                        };
                        record.attempts = record.attempts.saturating_add(1);
                        self.now = *now;
                        Ok(())
                    }
                    OutboxState::Processing { .. } => {
                        Err(ContractError::LeaseHeld(message_id.clone()))
                    }
                    state => Err(invalid(message_id, state.as_str(), "claim")),
                }
            }
            Event::Heartbeat {
                message_id,
                owner,
                now,
            } => {
                if *now < self.now {
                    return Err(ContractError::ClockRegression);
                }
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                match current {
                    OutboxState::Processing {
                        lease_until,
                        owner: holder,
                    } if holder == *owner => {
                        if *now >= lease_until {
                            return Err(invalid(message_id, "processing", "heartbeat"));
                        }
                        let renewed = now
                            .checked_add(LEASE_TICKS)
                            .ok_or(ContractError::Overflow)?;
                        record.state = OutboxState::Processing {
                            lease_until: renewed,
                            owner: holder,
                        };
                        self.now = *now;
                        Ok(())
                    }
                    OutboxState::Processing { .. } => {
                        Err(ContractError::NotLeaseOwner(message_id.clone()))
                    }
                    state => Err(invalid(message_id, state.as_str(), "heartbeat")),
                }
            }
            Event::LeaseExpired { message_id, now } => {
                if *now < self.now {
                    return Err(ContractError::ClockRegression);
                }
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                match current {
                    OutboxState::Processing { lease_until, .. } if *now >= lease_until => {
                        record.state = OutboxState::InDoubt;
                        self.now = *now;
                        Ok(())
                    }
                    OutboxState::Processing { .. } => {
                        Err(ContractError::PrematureLeaseExpiry(message_id.clone()))
                    }
                    state => Err(invalid(message_id, state.as_str(), "lease_expired")),
                }
            }
            Event::Broker {
                message_id,
                outcome,
            } => {
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                let OutboxState::Processing { .. } = current else {
                    return Err(invalid(message_id, current.as_str(), "broker"));
                };
                match outcome {
                    BrokerOutcome::Admitted => {
                        record.transport_confirmed = true;
                    }
                    BrokerOutcome::Rejected => {
                        // Definitive negative: nothing was published, so a
                        // bounded retry is safe.
                        record.state = OutboxState::Pending;
                        record.transport_confirmed = false;
                    }
                    BrokerOutcome::Unknown => {
                        record.state = OutboxState::InDoubt;
                    }
                }
                Ok(())
            }
            Event::AckUnknown { message_id } => {
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                match current {
                    OutboxState::Processing { .. } => {
                        record.state = OutboxState::InDoubt;
                        Ok(())
                    }
                    state => Err(invalid(message_id, state.as_str(), "ack_unknown")),
                }
            }
            Event::Apply {
                message_id,
                outcome,
            } => {
                let record = self.outbox(message_id)?;
                if record.state == OutboxState::Quarantined {
                    return Err(invalid(message_id, record.state.as_str(), "apply"));
                }
                let provenance = record.provenance.clone();
                let sequence = provenance.ordering.sequence;
                let key = authority_key(&provenance.ordering);
                let authority = self.require_authority(&key)?;
                if provenance.generation < authority.generation {
                    return Err(ContractError::GenerationRegression {
                        authority: key,
                        current: authority.generation,
                        proposed: provenance.generation,
                    });
                }
                let watermark = authority.watermark;
                match outcome {
                    ApplyOutcome::Success => {
                        if self.inbox_state(message_id) == InboxState::Applied {
                            return Ok(());
                        }
                        if sequence != watermark.checked_add(1).ok_or(ContractError::Overflow)? {
                            return Err(ContractError::OutOfOrderApply(message_id.clone()));
                        }
                        self.inbox.insert(
                            message_id.clone(),
                            InboxRecord {
                                state: InboxState::Pending,
                                provenance,
                            },
                        );
                        Ok(())
                    }
                    ApplyOutcome::Failure => {
                        // The attempt failed; keep the record pending for the
                        // in-order retry. Never un-apply a durable record.
                        self.inbox
                            .entry(message_id.clone())
                            .or_insert_with(|| InboxRecord {
                                state: InboxState::Pending,
                                provenance,
                            });
                        Ok(())
                    }
                }
            }
            Event::MarkApplied { message_id } => {
                if self.inbox_state(message_id) == InboxState::Applied {
                    return Ok(());
                }
                let inbox_record = self
                    .inbox
                    .get(message_id)
                    .ok_or_else(|| ContractError::UnknownMessage(message_id.to_owned()))?;
                let provenance = inbox_record.provenance.clone();
                let sequence = provenance.ordering.sequence;
                let key = authority_key(&provenance.ordering);
                let authority = self.require_authority(&key)?;
                if provenance.generation < authority.generation {
                    return Err(ContractError::GenerationRegression {
                        authority: key.clone(),
                        current: authority.generation,
                        proposed: provenance.generation,
                    });
                }
                if sequence
                    != authority
                        .watermark
                        .checked_add(1)
                        .ok_or(ContractError::Overflow)?
                {
                    return Err(ContractError::OutOfOrderApply(message_id.clone()));
                }
                if let Some(outbox) = self.outbox.get(message_id) {
                    if outbox.state == OutboxState::Quarantined {
                        return Err(invalid(message_id, outbox.state.as_str(), "mark_applied"));
                    }
                }
                self.inbox.get_mut(message_id).expect("checked above").state = InboxState::Applied;
                let authority = self.authorities.get_mut(&key).expect("checked above");
                authority.watermark = sequence;
                // The consumer's durable apply is durable completion evidence
                // for the publish side: settle any live outbox record.
                if let Some(outbox) = self.outbox.get_mut(message_id) {
                    if matches!(
                        outbox.state,
                        OutboxState::Pending
                            | OutboxState::Processing { .. }
                            | OutboxState::InDoubt
                    ) {
                        outbox.state = OutboxState::Processed;
                        outbox.durable_proof = true;
                    }
                }
                Ok(())
            }
            Event::Duplicate { message_id } => {
                let record = self
                    .inbox
                    .get(message_id)
                    .ok_or_else(|| ContractError::UnknownMessage(message_id.to_owned()))?;
                if record.state == InboxState::Applied {
                    Ok(())
                } else {
                    Err(invalid(message_id, record.state.as_str(), "duplicate"))
                }
            }
            Event::Reorder { message_id } => {
                let record = self
                    .inbox
                    .get(message_id)
                    .ok_or_else(|| ContractError::UnknownMessage(message_id.to_owned()))?;
                if record.state == InboxState::Pending {
                    // Late redelivery of a known-but-unapplied message: no
                    // state change, no watermark movement.
                    Ok(())
                } else {
                    Err(invalid(message_id, record.state.as_str(), "reorder"))
                }
            }
            Event::Gap { message_id } => {
                let record = self.outbox(message_id)?;
                if record.state == OutboxState::Quarantined {
                    return Err(invalid(message_id, record.state.as_str(), "gap"));
                }
                let provenance = record.provenance.clone();
                let sequence = provenance.ordering.sequence;
                let key = authority_key(&provenance.ordering);
                let authority = self.require_authority(&key)?;
                let expected = authority
                    .watermark
                    .checked_add(1)
                    .ok_or(ContractError::Overflow)?;
                if sequence <= expected {
                    return Err(invalid(
                        message_id,
                        self.inbox_state(message_id).as_str(),
                        "gap",
                    ));
                }
                self.inbox
                    .entry(message_id.clone())
                    .or_insert_with(|| InboxRecord {
                        state: InboxState::Pending,
                        provenance,
                    });
                Ok(())
            }
            Event::WatermarkAdvance { authority, to } => {
                let record = self.require_authority_mut(authority)?;
                if *to <= record.watermark {
                    return Err(ContractError::WatermarkRegression {
                        authority: authority.clone(),
                        current: record.watermark,
                        proposed: *to,
                    });
                }
                record.watermark = *to;
                Ok(())
            }
            Event::ExactSettlement {
                message_id,
                echo,
                outcome,
                durable_proven,
            } => {
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                if current != OutboxState::InDoubt {
                    return Err(invalid(message_id, current.as_str(), "exact_settlement"));
                }
                if *echo != record.provenance {
                    return Err(ContractError::ProvenanceMismatch(message_id.clone()));
                }
                match outcome {
                    SettlementOutcome::Processed if !*durable_proven => {
                        Err(ContractError::DurableProofRequired(message_id.clone()))
                    }
                    SettlementOutcome::Processed => {
                        record.state = OutboxState::Processed;
                        record.durable_proof = true;
                        Ok(())
                    }
                    SettlementOutcome::Requeue => {
                        record.state = OutboxState::Pending;
                        record.transport_confirmed = false;
                        Ok(())
                    }
                    SettlementOutcome::Quarantine => {
                        record.state = OutboxState::Quarantined;
                        Ok(())
                    }
                }
            }
            Event::Quarantine { message_id, reason } => {
                let record = self.outbox_mut(message_id)?;
                let current = record.state.clone();
                match current {
                    OutboxState::Pending
                    | OutboxState::Processing { .. }
                    | OutboxState::InDoubt => {
                        record.state = OutboxState::Quarantined;
                        record.quarantine_reason = Some(reason.clone());
                        Ok(())
                    }
                    state => Err(invalid(message_id, state.as_str(), "quarantine")),
                }
            }
            Event::Suspect { authority, .. } => {
                let record = self.require_authority_mut(authority)?;
                record.state = AuthorityState::Suspect;
                Ok(())
            }
            Event::DurableReconciliation {
                authority,
                durable_proven,
                transport_alive,
                generation,
            } => {
                let record = self.require_authority_mut(authority)?;
                if *generation < record.generation {
                    return Err(ContractError::GenerationRegression {
                        authority: authority.clone(),
                        current: record.generation,
                        proposed: *generation,
                    });
                }
                record.generation = *generation;
                record.durable_proven = *durable_proven;
                record.transport_alive = *transport_alive;
                record.state = if *durable_proven && *transport_alive {
                    AuthorityState::Serving
                } else {
                    AuthorityState::Reconciling {
                        durable_proven: *durable_proven,
                        transport_alive: *transport_alive,
                    }
                };
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    const AUTHORITY: &str = "tenant-a#1";

    fn digest(payload: &str) -> PayloadDigest {
        PayloadDigest(<[u8; 32]>::from(Sha256::digest(payload)))
    }

    fn provenance(sequence: u64) -> Provenance {
        Provenance {
            operation_id: format!("op-{sequence}"),
            message_id: format!("msg-{sequence}"),
            message_type: "AUTHORIZATION_INVALIDATION".to_owned(),
            queue: "astral.invalidation.fanout".to_owned(),
            ordering: OrderingKey {
                tenant_id: "tenant-a".to_owned(),
                partition: 1,
                sequence,
            },
            payload_digest: digest(&format!("payload-{sequence}")),
            publication_identity: "trustgraph#primary".to_owned(),
            generation: 7,
            publication_stamp: 100 + sequence,
        }
    }

    fn with_generation(mut provenance: Provenance, generation: u64) -> Provenance {
        provenance.generation = generation;
        provenance
    }

    fn with_message_id(mut provenance: Provenance, message_id: &str) -> Provenance {
        provenance.message_id = message_id.to_owned();
        provenance
    }

    fn world() -> World {
        let mut world = World::default();
        world.register_authority(AUTHORITY, 7).unwrap();
        world
    }

    fn staged(sequence: u64) -> World {
        let mut world = world();
        world.enqueue(provenance(sequence)).unwrap();
        world
            .reduce(&Event::Claim {
                message_id: format!("msg-{sequence}"),
                owner: "worker-1".to_owned(),
                now: 0,
            })
            .unwrap();
        world
    }

    /// Table-driven driver: applies events, asserts the expected outcome,
    /// asserts atomicity of rejections, and re-checks every fail-closed
    /// invariant after each accepted event.
    struct Driver {
        world: World,
        watermark_high: BTreeMap<String, u64>,
        applied_seen: BTreeSet<String>,
        processed_seen: BTreeSet<String>,
    }

    impl Driver {
        fn new(world: World) -> Self {
            let mut driver = Self {
                world,
                watermark_high: BTreeMap::new(),
                applied_seen: BTreeSet::new(),
                processed_seen: BTreeSet::new(),
            };
            driver.check_invariants("init");
            driver
        }

        fn drive(&mut self, name: &str, event: &Event, expected: &Result<(), ContractError>) {
            let before = self.world.clone();
            let actual = self.world.reduce(event);
            assert_eq!(
                &actual, expected,
                "case {name}: unexpected outcome for {event:?}"
            );
            if expected.is_err() {
                assert_eq!(
                    self.world, before,
                    "case {name}: rejected event must leave the world unchanged"
                );
                return;
            }
            self.check_invariants(name);
        }

        fn check_invariants(&mut self, name: &str) {
            for (key, authority) in &self.world.authorities {
                let high = self.watermark_high.entry(key.clone()).or_insert(0);
                assert!(
                    authority.watermark >= *high,
                    "case {name}: watermark regressed for {key}"
                );
                *high = authority.watermark;
                if authority.state == AuthorityState::Serving {
                    assert!(
                        authority.durable_proven && authority.transport_alive,
                        "case {name}: {key} serves without durable reconciliation proof"
                    );
                }
            }
            for (id, record) in &self.world.outbox {
                if self.processed_seen.contains(id) {
                    assert_eq!(
                        record.state,
                        OutboxState::Processed,
                        "case {name}: {id} left the terminal processed state"
                    );
                } else if record.state == OutboxState::Processed {
                    assert!(
                        record.durable_proof,
                        "case {name}: {id} processed without durable proof"
                    );
                    self.processed_seen.insert(id.clone());
                }
            }
            for (id, record) in &self.world.inbox {
                if self.applied_seen.contains(id) {
                    assert_eq!(
                        record.state,
                        InboxState::Applied,
                        "case {name}: {id} left the terminal applied state"
                    );
                } else if record.state == InboxState::Applied {
                    self.applied_seen.insert(id.clone());
                }
            }
        }
    }

    #[test]
    fn claim_lease_and_heartbeat_are_owner_scoped_and_bounded() {
        let mut driver = Driver::new(world());
        driver.world.enqueue(provenance(1)).unwrap();

        driver.drive(
            "claim",
            &Event::Claim {
                message_id: "msg-1".to_owned(),
                owner: "worker-1".to_owned(),
                now: 5,
            },
            &Ok(()),
        );
        assert_eq!(
            driver.world.outbox["msg-1"].state,
            OutboxState::Processing {
                lease_until: 13,
                owner: "worker-1".to_owned()
            },
            "lease is claim time plus LEASE_TICKS"
        );

        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "second-claim-is-refused",
                Event::Claim {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-2".to_owned(),
                    now: 6,
                },
                Err(ContractError::LeaseHeld("msg-1".to_owned())),
            ),
            (
                "foreign-heartbeat-is-refused",
                Event::Heartbeat {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-2".to_owned(),
                    now: 6,
                },
                Err(ContractError::NotLeaseOwner("msg-1".to_owned())),
            ),
            (
                "owner-heartbeat-renews",
                Event::Heartbeat {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-1".to_owned(),
                    now: 10,
                },
                Ok(()),
            ),
            (
                "clock-regression-is-refused",
                Event::Claim {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-2".to_owned(),
                    now: 4,
                },
                Err(ContractError::ClockRegression),
            ),
            (
                "premature-expiry-is-refused",
                Event::LeaseExpired {
                    message_id: "msg-1".to_owned(),
                    now: 17,
                },
                Err(ContractError::PrematureLeaseExpiry("msg-1".to_owned())),
            ),
            (
                "expiry-at-boundary-forces-in-doubt",
                Event::LeaseExpired {
                    message_id: "msg-1".to_owned(),
                    now: 18,
                },
                Ok(()),
            ),
            (
                "claim-from-in-doubt-is-refused",
                Event::Claim {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-3".to_owned(),
                    now: 19,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "in_doubt".to_owned(),
                    event: "claim",
                }),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
            if *name == "owner-heartbeat-renews" {
                assert_eq!(
                    driver.world.outbox["msg-1"].state,
                    OutboxState::Processing {
                        lease_until: 18,
                        owner: "worker-1".to_owned()
                    }
                );
            }
        }
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::InDoubt);
        assert_eq!(driver.world.outbox["msg-1"].attempts, 1);
    }

    #[test]
    fn unknown_outcomes_fail_closed_and_admission_is_not_durable_proof() {
        let mut driver = Driver::new(staged(2));
        driver.drive(
            "broker-admission-keeps-processing",
            &Event::Broker {
                message_id: "msg-2".to_owned(),
                outcome: BrokerOutcome::Admitted,
            },
            &Ok(()),
        );
        assert!(matches!(
            driver.world.outbox["msg-2"].state,
            OutboxState::Processing { .. }
        ));
        assert!(driver.world.outbox["msg-2"].transport_confirmed);

        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "broker-rejection-retries",
                Event::Broker {
                    message_id: "msg-2".to_owned(),
                    outcome: BrokerOutcome::Rejected,
                },
                Ok(()),
            ),
            (
                "reclaim-after-rejection",
                Event::Claim {
                    message_id: "msg-2".to_owned(),
                    owner: "worker-2".to_owned(),
                    now: 0,
                },
                Ok(()),
            ),
            (
                "broker-unknown-forces-in-doubt",
                Event::Broker {
                    message_id: "msg-2".to_owned(),
                    outcome: BrokerOutcome::Unknown,
                },
                Ok(()),
            ),
            (
                "broker-event-from-in-doubt-is-refused",
                Event::Broker {
                    message_id: "msg-2".to_owned(),
                    outcome: BrokerOutcome::Admitted,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-2".to_owned(),
                    state: "in_doubt".to_owned(),
                    event: "broker",
                }),
            ),
            (
                "claim-from-in-doubt-is-refused",
                Event::Claim {
                    message_id: "msg-2".to_owned(),
                    owner: "worker-3".to_owned(),
                    now: 1,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-2".to_owned(),
                    state: "in_doubt".to_owned(),
                    event: "claim",
                }),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
        }
        assert_eq!(driver.world.outbox["msg-2"].state, OutboxState::InDoubt);
        assert_eq!(driver.world.outbox["msg-2"].attempts, 2);

        // A lost ACK after an admission also fails closed, and the consumer's
        // durable mark-applied is what finally proves completion.
        let mut driver = Driver::new(staged(1));
        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "admitted",
                Event::Broker {
                    message_id: "msg-1".to_owned(),
                    outcome: BrokerOutcome::Admitted,
                },
                Ok(()),
            ),
            (
                "ack-unknown-forces-in-doubt",
                Event::AckUnknown {
                    message_id: "msg-1".to_owned(),
                },
                Ok(()),
            ),
            (
                "apply-after-ack-unknown",
                Event::Apply {
                    message_id: "msg-1".to_owned(),
                    outcome: ApplyOutcome::Success,
                },
                Ok(()),
            ),
            (
                "mark-applied-settles-with-proof",
                Event::MarkApplied {
                    message_id: "msg-1".to_owned(),
                },
                Ok(()),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
            if *name == "ack-unknown-forces-in-doubt" {
                assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::InDoubt);
            }
        }
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::Processed);
        assert!(driver.world.outbox["msg-1"].durable_proof);
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 1);
    }

    #[test]
    fn exact_settlement_requires_in_doubt_exact_echo_and_durable_proof() {
        let mut driver = Driver::new(staged(1));
        driver.drive(
            "ack-unknown",
            &Event::AckUnknown {
                message_id: "msg-1".to_owned(),
            },
            &Ok(()),
        );
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::InDoubt);

        let base = provenance(1);
        let mut echo_digest = base.clone();
        echo_digest.payload_digest = digest("tampered");
        let mut echo_ordering = base.clone();
        echo_ordering.ordering.sequence = 2;
        let mut echo_operation = base.clone();
        echo_operation.operation_id = "op-other".to_owned();
        let mut echo_type = base.clone();
        echo_type.message_type = "OTHER".to_owned();
        let mut echo_queue = base.clone();
        echo_queue.queue = "other.queue".to_owned();
        let mut echo_identity = base.clone();
        echo_identity.publication_identity = "trustgraph#replica".to_owned();
        let mut echo_generation = base.clone();
        echo_generation.generation = 6;
        let mut echo_stamp = base.clone();
        echo_stamp.publication_stamp = 999;

        let mismatches = [
            ("echo-digest", echo_digest),
            ("echo-ordering", echo_ordering),
            ("echo-operation", echo_operation),
            ("echo-type", echo_type),
            ("echo-queue", echo_queue),
            ("echo-identity", echo_identity),
            ("echo-generation", echo_generation),
            ("echo-stamp", echo_stamp),
        ];
        for (name, echo) in mismatches {
            driver.drive(
                name,
                &Event::ExactSettlement {
                    message_id: "msg-1".to_owned(),
                    echo,
                    outcome: SettlementOutcome::Processed,
                    durable_proven: true,
                },
                &Err(ContractError::ProvenanceMismatch("msg-1".to_owned())),
            );
            assert_eq!(
                driver.world.outbox["msg-1"].state,
                OutboxState::InDoubt,
                "case {name}: mismatched echo must not settle"
            );
        }

        driver.drive(
            "processed-without-proof-is-refused",
            &Event::ExactSettlement {
                message_id: "msg-1".to_owned(),
                echo: base.clone(),
                outcome: SettlementOutcome::Processed,
                durable_proven: false,
            },
            &Err(ContractError::DurableProofRequired("msg-1".to_owned())),
        );
        driver.drive(
            "requeue-is-explicit",
            &Event::ExactSettlement {
                message_id: "msg-1".to_owned(),
                echo: base.clone(),
                outcome: SettlementOutcome::Requeue,
                durable_proven: false,
            },
            &Ok(()),
        );
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::Pending);
        assert!(!driver.world.outbox["msg-1"].transport_confirmed);

        driver.drive(
            "reclaim-after-requeue",
            &Event::Claim {
                message_id: "msg-1".to_owned(),
                owner: "worker-2".to_owned(),
                now: 10,
            },
            &Ok(()),
        );
        driver.drive(
            "expire-again",
            &Event::LeaseExpired {
                message_id: "msg-1".to_owned(),
                now: 18,
            },
            &Ok(()),
        );
        driver.drive(
            "quarantine-settlement",
            &Event::ExactSettlement {
                message_id: "msg-1".to_owned(),
                echo: base.clone(),
                outcome: SettlementOutcome::Quarantine,
                durable_proven: false,
            },
            &Ok(()),
        );
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::Quarantined);
        assert_eq!(driver.world.outbox["msg-1"].attempts, 2);

        driver.drive(
            "settlement-from-terminal-is-refused",
            &Event::ExactSettlement {
                message_id: "msg-1".to_owned(),
                echo: base,
                outcome: SettlementOutcome::Processed,
                durable_proven: true,
            },
            &Err(ContractError::InvalidTransition {
                subject: "msg-1".to_owned(),
                state: "quarantined".to_owned(),
                event: "exact_settlement",
            }),
        );
    }

    #[test]
    fn apply_mark_duplicate_reorder_and_gap_respect_the_in_order_gate() {
        let mut driver = Driver::new(world());
        for sequence in 1..=3 {
            driver.world.enqueue(provenance(sequence)).unwrap();
        }

        // A gap is buffered and never applied or marked out of turn.
        driver.drive(
            "gap-buffers-without-applying",
            &Event::Gap {
                message_id: "msg-2".to_owned(),
            },
            &Ok(()),
        );
        assert_eq!(driver.world.inbox_state("msg-2"), InboxState::Pending);
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 0);

        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "gap-on-in-order-delivery-is-refused",
                Event::Gap {
                    message_id: "msg-1".to_owned(),
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "absent".to_owned(),
                    event: "gap",
                }),
            ),
            (
                "apply-on-gap-is-refused",
                Event::Apply {
                    message_id: "msg-2".to_owned(),
                    outcome: ApplyOutcome::Success,
                },
                Err(ContractError::OutOfOrderApply("msg-2".to_owned())),
            ),
            (
                "mark-on-gap-is-refused",
                Event::MarkApplied {
                    message_id: "msg-2".to_owned(),
                },
                Err(ContractError::OutOfOrderApply("msg-2".to_owned())),
            ),
            (
                "reorder-on-unknown-message-is-refused",
                Event::Reorder {
                    message_id: "msg-1".to_owned(),
                },
                Err(ContractError::UnknownMessage("msg-1".to_owned())),
            ),
            (
                "reorder-on-buffered-message-is-a-noop",
                Event::Reorder {
                    message_id: "msg-2".to_owned(),
                },
                Ok(()),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
        }
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 0);

        // In-order apply, durable mark, and idempotent duplicate handling.
        driver.drive(
            "apply-in-order",
            &Event::Apply {
                message_id: "msg-1".to_owned(),
                outcome: ApplyOutcome::Success,
            },
            &Ok(()),
        );
        driver.drive(
            "mark-in-order-advances-watermark",
            &Event::MarkApplied {
                message_id: "msg-1".to_owned(),
            },
            &Ok(()),
        );
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 1);
        assert_eq!(driver.world.inbox_state("msg-1"), InboxState::Applied);
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::Processed);
        assert!(driver.world.outbox["msg-1"].durable_proof);

        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "duplicate-applied-is-idempotent",
                Event::Duplicate {
                    message_id: "msg-1".to_owned(),
                },
                Ok(()),
            ),
            (
                "duplicate-pending-is-refused",
                Event::Duplicate {
                    message_id: "msg-2".to_owned(),
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-2".to_owned(),
                    state: "pending".to_owned(),
                    event: "duplicate",
                }),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
        }

        // The gap fills, then the buffered message applies and marks in turn.
        driver.drive(
            "apply-second-after-gap-fill",
            &Event::Apply {
                message_id: "msg-2".to_owned(),
                outcome: ApplyOutcome::Success,
            },
            &Ok(()),
        );
        driver.drive(
            "mark-second",
            &Event::MarkApplied {
                message_id: "msg-2".to_owned(),
            },
            &Ok(()),
        );
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 2);

        // A failed apply stays pending; the retry then applies in order.
        driver.drive(
            "apply-failure-stays-pending",
            &Event::Apply {
                message_id: "msg-3".to_owned(),
                outcome: ApplyOutcome::Failure,
            },
            &Ok(()),
        );
        assert_eq!(driver.world.inbox_state("msg-3"), InboxState::Pending);
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 2);
        driver.drive(
            "apply-retry-after-failure",
            &Event::Apply {
                message_id: "msg-3".to_owned(),
                outcome: ApplyOutcome::Success,
            },
            &Ok(()),
        );
        driver.drive(
            "mark-third",
            &Event::MarkApplied {
                message_id: "msg-3".to_owned(),
            },
            &Ok(()),
        );
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 3);
        assert_eq!(driver.world.inbox_state("msg-3"), InboxState::Applied);
        assert_eq!(driver.world.outbox["msg-3"].state, OutboxState::Processed);
    }

    #[test]
    fn watermark_advance_is_monotonic_and_tenant_scoped() {
        let mut world = world();
        world.register_authority("tenant-a#2", 7).unwrap();
        let mut driver = Driver::new(world);
        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "advance-first",
                Event::WatermarkAdvance {
                    authority: AUTHORITY.to_owned(),
                    to: 1,
                },
                Ok(()),
            ),
            (
                "advance-second-partition",
                Event::WatermarkAdvance {
                    authority: "tenant-a#2".to_owned(),
                    to: 5,
                },
                Ok(()),
            ),
            (
                "equal-advance-is-a-regression",
                Event::WatermarkAdvance {
                    authority: AUTHORITY.to_owned(),
                    to: 1,
                },
                Err(ContractError::WatermarkRegression {
                    authority: AUTHORITY.to_owned(),
                    current: 1,
                    proposed: 1,
                }),
            ),
            (
                "backwards-advance-is-a-regression",
                Event::WatermarkAdvance {
                    authority: AUTHORITY.to_owned(),
                    to: 0,
                },
                Err(ContractError::WatermarkRegression {
                    authority: AUTHORITY.to_owned(),
                    current: 1,
                    proposed: 0,
                }),
            ),
            (
                "unknown-authority-is-refused",
                Event::WatermarkAdvance {
                    authority: "tenant-z#1".to_owned(),
                    to: 9,
                },
                Err(ContractError::UnknownAuthority("tenant-z#1".to_owned())),
            ),
            (
                "forward-advance-still-accepted",
                Event::WatermarkAdvance {
                    authority: AUTHORITY.to_owned(),
                    to: 2,
                },
                Ok(()),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
        }
        assert_eq!(driver.world.authorities[AUTHORITY].watermark, 2);
        assert_eq!(driver.world.authorities["tenant-a#2"].watermark, 5);
    }

    #[test]
    fn authority_serving_requires_durable_reconciliation_proof() {
        let mut driver = Driver::new(world());
        let record = driver.world.authorities[AUTHORITY].clone();
        assert_eq!(record.state, AuthorityState::Suspect);
        assert!(!record.durable_proven && !record.transport_alive);

        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "unproven-reconciliation-stays-denied",
                Event::DurableReconciliation {
                    authority: AUTHORITY.to_owned(),
                    durable_proven: false,
                    transport_alive: true,
                    generation: 7,
                },
                Ok(()),
            ),
            (
                "transport-dead-stays-denied",
                Event::DurableReconciliation {
                    authority: AUTHORITY.to_owned(),
                    durable_proven: true,
                    transport_alive: false,
                    generation: 7,
                },
                Ok(()),
            ),
            (
                "full-proof-serves",
                Event::DurableReconciliation {
                    authority: AUTHORITY.to_owned(),
                    durable_proven: true,
                    transport_alive: true,
                    generation: 7,
                },
                Ok(()),
            ),
            (
                "suspect-demotes-immediately",
                Event::Suspect {
                    authority: AUTHORITY.to_owned(),
                    reason: "audit-gap".to_owned(),
                },
                Ok(()),
            ),
            (
                "unproven-recovery-stays-denied",
                Event::DurableReconciliation {
                    authority: AUTHORITY.to_owned(),
                    durable_proven: false,
                    transport_alive: true,
                    generation: 7,
                },
                Ok(()),
            ),
            (
                "generation-regression-is-refused",
                Event::DurableReconciliation {
                    authority: AUTHORITY.to_owned(),
                    durable_proven: true,
                    transport_alive: true,
                    generation: 6,
                },
                Err(ContractError::GenerationRegression {
                    authority: AUTHORITY.to_owned(),
                    current: 7,
                    proposed: 6,
                }),
            ),
            (
                "advanced-generation-with-proof-recovers",
                Event::DurableReconciliation {
                    authority: AUTHORITY.to_owned(),
                    durable_proven: true,
                    transport_alive: true,
                    generation: 8,
                },
                Ok(()),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
            if *name == "full-proof-serves" {
                assert_eq!(
                    driver.world.authorities[AUTHORITY].state,
                    AuthorityState::Serving
                );
            }
        }
        let record = driver.world.authorities[AUTHORITY].clone();
        assert_eq!(record.state, AuthorityState::Serving);
        assert_eq!(record.generation, 8);

        driver.world.enqueue(provenance(1)).unwrap();
        driver.drive(
            "stale-generation-message-is-refused",
            &Event::Apply {
                message_id: "msg-1".to_owned(),
                outcome: ApplyOutcome::Success,
            },
            &Err(ContractError::GenerationRegression {
                authority: AUTHORITY.to_owned(),
                current: 8,
                proposed: 7,
            }),
        );
        driver
            .world
            .enqueue(with_message_id(with_generation(provenance(1), 8), "msg-2"))
            .unwrap();
        driver.drive(
            "current-generation-message-applies",
            &Event::Apply {
                message_id: "msg-2".to_owned(),
                outcome: ApplyOutcome::Success,
            },
            &Ok(()),
        );
        assert_eq!(driver.world.inbox_state("msg-2"), InboxState::Pending);
    }

    #[test]
    fn quarantine_is_explicit_and_terminal() {
        let mut driver = Driver::new(staged(1));
        driver.drive(
            "quarantine-from-processing",
            &Event::Quarantine {
                message_id: "msg-1".to_owned(),
                reason: "poison_payload".to_owned(),
            },
            &Ok(()),
        );
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::Quarantined);
        assert_eq!(
            driver.world.outbox["msg-1"].quarantine_reason.as_deref(),
            Some("poison_payload")
        );

        let base = provenance(1);
        let table: Vec<(&str, Event, Result<(), ContractError>)> = vec![
            (
                "claim-quarantined-is-refused",
                Event::Claim {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-2".to_owned(),
                    now: 1,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "claim",
                }),
            ),
            (
                "heartbeat-quarantined-is-refused",
                Event::Heartbeat {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-1".to_owned(),
                    now: 1,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "heartbeat",
                }),
            ),
            (
                "broker-quarantined-is-refused",
                Event::Broker {
                    message_id: "msg-1".to_owned(),
                    outcome: BrokerOutcome::Admitted,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "broker",
                }),
            ),
            (
                "apply-quarantined-is-refused",
                Event::Apply {
                    message_id: "msg-1".to_owned(),
                    outcome: ApplyOutcome::Success,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "apply",
                }),
            ),
            (
                "settlement-quarantined-is-refused",
                Event::ExactSettlement {
                    message_id: "msg-1".to_owned(),
                    echo: base.clone(),
                    outcome: SettlementOutcome::Requeue,
                    durable_proven: false,
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "exact_settlement",
                }),
            ),
            (
                "re-quarantine-is-refused",
                Event::Quarantine {
                    message_id: "msg-1".to_owned(),
                    reason: "again".to_owned(),
                },
                Err(ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "quarantine",
                }),
            ),
            (
                "mark-applied-without-inbox-is-unknown",
                Event::MarkApplied {
                    message_id: "msg-1".to_owned(),
                },
                Err(ContractError::UnknownMessage("msg-1".to_owned())),
            ),
        ];
        for (name, event, expected) in &table {
            driver.drive(name, event, expected);
        }
        assert_eq!(driver.world.outbox["msg-1"].state, OutboxState::Quarantined);
    }

    #[test]
    fn rejected_events_never_mutate_the_world() {
        let mut world = world();
        // msg-1: full happy path -> Processed, watermark 1.
        world.enqueue(provenance(1)).unwrap();
        world
            .reduce(&Event::Claim {
                message_id: "msg-1".to_owned(),
                owner: "worker-1".to_owned(),
                now: 0,
            })
            .unwrap();
        world
            .reduce(&Event::Broker {
                message_id: "msg-1".to_owned(),
                outcome: BrokerOutcome::Admitted,
            })
            .unwrap();
        world
            .reduce(&Event::Apply {
                message_id: "msg-1".to_owned(),
                outcome: ApplyOutcome::Success,
            })
            .unwrap();
        world
            .reduce(&Event::MarkApplied {
                message_id: "msg-1".to_owned(),
            })
            .unwrap();
        // msg-2: pending.
        world.enqueue(provenance(2)).unwrap();
        // msg-3: processing.
        world.enqueue(provenance(3)).unwrap();
        world
            .reduce(&Event::Claim {
                message_id: "msg-3".to_owned(),
                owner: "worker-1".to_owned(),
                now: 0,
            })
            .unwrap();
        // msg-4: in doubt.
        world.enqueue(provenance(4)).unwrap();
        world
            .reduce(&Event::Claim {
                message_id: "msg-4".to_owned(),
                owner: "worker-1".to_owned(),
                now: 0,
            })
            .unwrap();
        world
            .reduce(&Event::AckUnknown {
                message_id: "msg-4".to_owned(),
            })
            .unwrap();
        // msg-5: quarantined.
        world.enqueue(provenance(5)).unwrap();
        world
            .reduce(&Event::Claim {
                message_id: "msg-5".to_owned(),
                owner: "worker-1".to_owned(),
                now: 0,
            })
            .unwrap();
        world
            .reduce(&Event::Quarantine {
                message_id: "msg-5".to_owned(),
                reason: "poison".to_owned(),
            })
            .unwrap();
        // msg-6: gap-buffered inbox pending.
        world.enqueue(provenance(6)).unwrap();
        world
            .reduce(&Event::Gap {
                message_id: "msg-6".to_owned(),
            })
            .unwrap();
        // msg-7: pending with a stale generation fence.
        world.enqueue(with_generation(provenance(7), 5)).unwrap();

        let snapshot = world.clone();
        let mut tampered = provenance(4);
        tampered.payload_digest = digest("tampered");
        let table: Vec<(&str, Event, ContractError)> = vec![
            (
                "claim-processed",
                Event::Claim {
                    message_id: "msg-1".to_owned(),
                    owner: "worker-2".to_owned(),
                    now: 1,
                },
                ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "processed".to_owned(),
                    event: "claim",
                },
            ),
            (
                "broker-pending",
                Event::Broker {
                    message_id: "msg-2".to_owned(),
                    outcome: BrokerOutcome::Admitted,
                },
                ContractError::InvalidTransition {
                    subject: "msg-2".to_owned(),
                    state: "pending".to_owned(),
                    event: "broker",
                },
            ),
            (
                "settlement-processing",
                Event::ExactSettlement {
                    message_id: "msg-3".to_owned(),
                    echo: provenance(3),
                    outcome: SettlementOutcome::Processed,
                    durable_proven: true,
                },
                ContractError::InvalidTransition {
                    subject: "msg-3".to_owned(),
                    state: "processing".to_owned(),
                    event: "exact_settlement",
                },
            ),
            (
                "mark-applied-without-inbox",
                Event::MarkApplied {
                    message_id: "msg-4".to_owned(),
                },
                ContractError::UnknownMessage("msg-4".to_owned()),
            ),
            (
                "settlement-with-mismatched-echo",
                Event::ExactSettlement {
                    message_id: "msg-4".to_owned(),
                    echo: tampered,
                    outcome: SettlementOutcome::Processed,
                    durable_proven: true,
                },
                ContractError::ProvenanceMismatch("msg-4".to_owned()),
            ),
            (
                "settlement-without-durable-proof",
                Event::ExactSettlement {
                    message_id: "msg-4".to_owned(),
                    echo: provenance(4),
                    outcome: SettlementOutcome::Processed,
                    durable_proven: false,
                },
                ContractError::DurableProofRequired("msg-4".to_owned()),
            ),
            (
                "quarantine-processed",
                Event::Quarantine {
                    message_id: "msg-1".to_owned(),
                    reason: "late".to_owned(),
                },
                ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "processed".to_owned(),
                    event: "quarantine",
                },
            ),
            (
                "apply-quarantined",
                Event::Apply {
                    message_id: "msg-5".to_owned(),
                    outcome: ApplyOutcome::Success,
                },
                ContractError::InvalidTransition {
                    subject: "msg-5".to_owned(),
                    state: "quarantined".to_owned(),
                    event: "apply",
                },
            ),
            (
                "duplicate-buffered-pending",
                Event::Duplicate {
                    message_id: "msg-6".to_owned(),
                },
                ContractError::InvalidTransition {
                    subject: "msg-6".to_owned(),
                    state: "pending".to_owned(),
                    event: "duplicate",
                },
            ),
            (
                "reorder-applied",
                Event::Reorder {
                    message_id: "msg-1".to_owned(),
                },
                ContractError::InvalidTransition {
                    subject: "msg-1".to_owned(),
                    state: "applied".to_owned(),
                    event: "reorder",
                },
            ),
            (
                "gap-on-in-order-sequence",
                Event::Gap {
                    message_id: "msg-2".to_owned(),
                },
                ContractError::InvalidTransition {
                    subject: "msg-2".to_owned(),
                    state: "absent".to_owned(),
                    event: "gap",
                },
            ),
            (
                "watermark-regression",
                Event::WatermarkAdvance {
                    authority: AUTHORITY.to_owned(),
                    to: 0,
                },
                ContractError::WatermarkRegression {
                    authority: AUTHORITY.to_owned(),
                    current: 1,
                    proposed: 0,
                },
            ),
            (
                "unknown-authority",
                Event::Suspect {
                    authority: "tenant-z#1".to_owned(),
                    reason: "probe".to_owned(),
                },
                ContractError::UnknownAuthority("tenant-z#1".to_owned()),
            ),
            (
                "unknown-message",
                Event::Heartbeat {
                    message_id: "msg-9".to_owned(),
                    owner: "worker-1".to_owned(),
                    now: 1,
                },
                ContractError::UnknownMessage("msg-9".to_owned()),
            ),
            (
                "stale-generation-apply",
                Event::Apply {
                    message_id: "msg-7".to_owned(),
                    outcome: ApplyOutcome::Success,
                },
                ContractError::GenerationRegression {
                    authority: AUTHORITY.to_owned(),
                    current: 7,
                    proposed: 5,
                },
            ),
        ];
        for (name, event, expected) in table {
            let error = world
                .reduce(&event)
                .expect_err("every row in this table must be rejected");
            assert_eq!(error, expected, "case {name}");
            assert_eq!(
                world, snapshot,
                "case {name}: rejected event must not mutate the world"
            );
        }
        assert_eq!(world, snapshot);
    }

    #[test]
    fn enqueue_and_registration_are_idempotent_on_exact_identity() {
        let mut world = world();
        assert_eq!(world.enqueue(provenance(1)), Ok(()));
        assert_eq!(world.enqueue(provenance(1)), Ok(()));
        let mut tampered = provenance(1);
        tampered.payload_digest = digest("other");
        assert_eq!(
            world.enqueue(tampered),
            Err(ContractError::ProvenanceMismatch("msg-1".to_owned()))
        );
        assert_eq!(world.outbox.len(), 1);
        assert_eq!(world.register_authority(AUTHORITY, 7), Ok(()));
        assert_eq!(
            world.register_authority(AUTHORITY, 6),
            Err(ContractError::GenerationRegression {
                authority: AUTHORITY.to_owned(),
                current: 7,
                proposed: 6,
            })
        );
        assert_eq!(world.authorities.len(), 1);
    }
}
