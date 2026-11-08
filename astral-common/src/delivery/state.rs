//! Typed delivery truth.
//!
//! The delivery subsystem reports provider truth, never optimism:
//! - A provider/MTA acknowledgement (HTTP 2xx, SMTP `250` after DATA) is at
//!   most [`DeliveryState::Accepted`] — the provider took the message into its
//!   queue. It is **not** a final delivery claim.
//! - [`DeliveryState::Delivered`] requires explicit receipt proof (a relay
//!   receipt field, or a synchronous webhook 2xx where the endpoint itself is
//!   the receiver).
//! - [`DeliveryState::InDoubt`] means dispatch began (bytes may have left this
//!   host) and the outcome is unknown. It must be reconciled explicitly and is
//!   never auto-retried; success must never be inferred from activity logs.

use std::fmt;

/// Durable/observable state of one delivery intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryState {
    /// Dispatch never started (configuration, endpoint policy, store, or lease
    /// refusal). Nothing left this host.
    NotAttempted,
    /// Durable intent recorded; awaiting or between attempts.
    Queued,
    /// Provider acknowledged receipt into its queue. No final delivery proof.
    Accepted,
    /// Explicit end-delivery proof was received.
    Delivered,
    /// Definitive refusal observed before any provider accepted the message.
    Failed,
    /// Dispatch began and the outcome is unknown; explicit reconciliation is
    /// required before any further attempt.
    InDoubt,
    /// Attempt budget exhausted while the message was still not accepted;
    /// the intent must be re-minted (new `message_id`) to try again.
    Expired,
}

impl DeliveryState {
    pub const fn as_str(self) -> &'static str {
        match self {
            DeliveryState::NotAttempted => "NOT_ATTEMPTED",
            DeliveryState::Queued => "QUEUED",
            DeliveryState::Accepted => "ACCEPTED",
            DeliveryState::Delivered => "DELIVERED",
            DeliveryState::Failed => "FAILED",
            DeliveryState::InDoubt => "IN_DOUBT",
            DeliveryState::Expired => "EXPIRED",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "NOT_ATTEMPTED" => DeliveryState::NotAttempted,
            "QUEUED" => DeliveryState::Queued,
            "ACCEPTED" => DeliveryState::Accepted,
            "DELIVERED" => DeliveryState::Delivered,
            "FAILED" => DeliveryState::Failed,
            "IN_DOUBT" => DeliveryState::InDoubt,
            "EXPIRED" => DeliveryState::Expired,
            _ => return None,
        })
    }

    /// Terminal states are settled truths that never move again.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            DeliveryState::Delivered | DeliveryState::Failed | DeliveryState::Expired
        )
    }
}

impl fmt::Display for DeliveryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed outcome of a delivery attempt or refusal.
///
/// `detail` is a sanitized, bounded human-readable explanation. It must never
/// contain credentials, tokens, message bodies, or raw provider secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryTruth {
    pub state: DeliveryState,
    /// Non-secret provider reference (provider message id) when offered.
    pub provider_reference: Option<String>,
    pub detail: String,
}

impl DeliveryTruth {
    /// Hard bound for `detail`; longer input is truncated.
    pub const MAX_DETAIL: usize = 512;

    pub fn delivered(reference: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::Delivered,
            provider_reference: bounded_reference(reference),
            detail: sanitize(detail.into()),
        }
    }

    pub fn accepted(reference: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::Accepted,
            provider_reference: bounded_reference(reference),
            detail: sanitize(detail.into()),
        }
    }

    /// Definitive refusal; nothing was accepted by any provider.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::Failed,
            provider_reference: None,
            detail: sanitize(detail.into()),
        }
    }

    /// Dispatch began; the outcome is unknown and requires reconciliation.
    pub fn in_doubt(detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::InDoubt,
            provider_reference: None,
            detail: sanitize(detail.into()),
        }
    }

    /// Dispatch never happened.
    pub fn not_attempted(detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::NotAttempted,
            provider_reference: None,
            detail: sanitize(detail.into()),
        }
    }

    /// A transient refusal was observed before acceptance; the durable intent
    /// stays queued and a later attempt may run within the attempt budget.
    pub fn retry_scheduled(detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::Queued,
            provider_reference: None,
            detail: sanitize(detail.into()),
        }
    }

    /// Another worker owns the live lease; this call made no attempt.
    pub fn contention(detail: impl Into<String>) -> Self {
        Self {
            state: DeliveryState::Queued,
            provider_reference: None,
            detail: sanitize(detail.into()),
        }
    }

    /// True only when this truth proves end delivery.
    pub fn is_delivered(&self) -> bool {
        self.state == DeliveryState::Delivered
    }
}

fn sanitize(mut detail: String) -> String {
    // Strip control characters (they can corrupt logs) and bound the length.
    detail.retain(|c| !c.is_control() || c == ' ');
    if detail.len() > DeliveryTruth::MAX_DETAIL {
        let mut cut = DeliveryTruth::MAX_DETAIL;
        while cut > 0 && !detail.is_char_boundary(cut) {
            cut -= 1;
        }
        detail.truncate(cut);
    }
    detail
}

fn bounded_reference(reference: Option<&str>) -> Option<String> {
    let raw = reference?.trim();
    if raw.is_empty() || raw.len() > 256 {
        return None;
    }
    let mut owned = raw.to_owned();
    owned.retain(|c| !c.is_control());
    if owned.is_empty() {
        None
    } else {
        Some(owned)
    }
}

/// Typed delivery errors. Text payloads are supplied by callers and must be
/// sanitized (no credentials, tokens, or message bodies).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    #[error("delivery message rejected: {0}")]
    Bounds(&'static str),
    #[error("delivery channel configuration invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("delivery channel configuration carries an inline secret; use protected env refs")]
    InlineSecretRejected,
    #[error("delivery endpoint blocked by policy: {0}")]
    EndpointBlocked(&'static str),
    #[error("delivery credential unavailable from protected env ref: {0}")]
    SecretUnavailable(String),
    #[error("durable delivery store unavailable: {0}")]
    Store(String),
    #[error("delivery intent unknown to the store: {0}")]
    UnknownIntent(String),
    #[error("delivery lease conflict: another worker owns the live attempt")]
    LeaseConflict,
    #[error("delivery lease expired before settlement; outcome must be reconciled")]
    LeaseExpired,
    #[error("delivery outcome unknown; explicit reconciliation required before any retry")]
    ReconciliationRequired,
    #[error("delivery attempt budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error(
        "delivery intent conflict for {0}: message id reused with different immutable metadata"
    )]
    IntentConflict(String),
    #[error("delivery transport failure: {0}")]
    Transport(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_is_not_a_final_delivery_claim() {
        let truth = DeliveryTruth::accepted(None, "MTA queued");
        assert_eq!(truth.state, DeliveryState::Accepted);
        assert!(!truth.is_delivered());
        assert!(!truth.state.is_terminal());
    }

    #[test]
    fn delivered_requires_explicit_constructor() {
        let truth = DeliveryTruth::delivered(Some("prov-1"), "receipt matched");
        assert!(truth.is_delivered());
        assert_eq!(truth.provider_reference.as_deref(), Some("prov-1"));
    }

    #[test]
    fn state_strings_round_trip() {
        for state in [
            DeliveryState::NotAttempted,
            DeliveryState::Queued,
            DeliveryState::Accepted,
            DeliveryState::Delivered,
            DeliveryState::Failed,
            DeliveryState::InDoubt,
            DeliveryState::Expired,
        ] {
            assert_eq!(DeliveryState::parse(state.as_str()), Some(state));
        }
        assert_eq!(DeliveryState::parse("SIMULATED"), None);
    }

    #[test]
    fn detail_is_sanitized_and_bounded() {
        let long = "x".repeat(DeliveryTruth::MAX_DETAIL + 64);
        let truth = DeliveryTruth::failed(long);
        assert_eq!(truth.detail.len(), DeliveryTruth::MAX_DETAIL);
        let truth = DeliveryTruth::in_doubt("bad\r\ncontrol\u{7}chars");
        assert!(!truth.detail.contains('\r'));
        assert!(!truth.detail.contains('\n'));
        assert!(!truth.detail.contains('\u{7}'));
    }

    #[test]
    fn provider_reference_is_bounded_and_control_free() {
        assert_eq!(bounded_reference(Some("  ")), None);
        assert_eq!(bounded_reference(Some(&"y".repeat(300))), None);
        let truth = DeliveryTruth::accepted(Some("a\nb"), "ok");
        assert_eq!(truth.provider_reference.as_deref(), Some("ab"));
    }
}
