//! Delivery message intent: stable identity, payload class, and bounds.
//!
//! A [`DeliveryMessage`] is an in-memory handoff only. The durable store keeps
//! metadata (ids, channel, recipient, subject, body digest) — never the body,
//! and for [`PayloadClass::EphemeralSecret`] not even a digest of the body
//! (the body carries the raw secret; hashing it without a protected key would
//! create an offline brute-force oracle).

use crate::delivery::state::DeliveryError;
use sha2::{Digest, Sha256};

/// Delivery channel family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    Email,
    Sms,
    DingTalk,
    WeChat,
    Webhook,
}

impl ChannelKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Email => "EMAIL",
            ChannelKind::Sms => "SMS",
            ChannelKind::DingTalk => "DINGTALK",
            ChannelKind::WeChat => "WECHAT",
            ChannelKind::Webhook => "WEBHOOK",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw.to_ascii_uppercase().as_str() {
            "EMAIL" => ChannelKind::Email,
            "SMS" => ChannelKind::Sms,
            "DINGTALK" => ChannelKind::DingTalk,
            "WECHAT" => ChannelKind::WeChat,
            "WEBHOOK" => ChannelKind::Webhook,
            _ => return None,
        })
    }
}

/// Payload classification controlling what may be persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadClass {
    /// Body is non-secret; its SHA-256 digest may be recorded for
    /// idempotency and reconciliation.
    Standard,
    /// Body carries a raw secret (reset token, OTP code). Only intent
    /// metadata is recorded — no body digest, no body, no encrypted queue.
    EphemeralSecret,
}

/// Hard message bounds. `max_recipient` covers webhook URLs (2048); email
/// recipients are additionally validated to the RFC-5321 style limit of 320.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryBounds {
    pub max_recipient: usize,
    pub max_subject: usize,
    pub max_body: usize,
    pub max_operation_id: usize,
    pub max_message_id: usize,
}

impl Default for DeliveryBounds {
    fn default() -> Self {
        Self {
            max_recipient: 2048,
            max_subject: 256,
            max_body: 65_536,
            max_operation_id: 128,
            max_message_id: 64,
        }
    }
}

/// One delivery message. `message_id` is the stable durable identity (CAS key);
/// `operation_id` is the stable, non-secret logical operation the message
/// belongs to. Neither may be derived from raw secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryMessage {
    pub message_id: String,
    pub operation_id: String,
    pub channel: ChannelKind,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub payload_class: PayloadClass,
}

impl std::fmt::Debug for DeliveryMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the body or subject: payloads may carry secrets.
        f.debug_struct("DeliveryMessage")
            .field("message_id", &self.message_id)
            .field("operation_id", &self.operation_id)
            .field("channel", &self.channel.as_str())
            .field("recipient", &self.recipient)
            .field("payload_class", &self.payload_class)
            .field("body", &"<redacted>")
            .field("subject", &self.subject.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl DeliveryMessage {
    /// Compose and validate a message. When `message_id` is `None` a fresh
    /// UUIDv7 is minted; callers that need cross-restart idempotency supply
    /// their own stable id.
    pub fn compose(
        channel: ChannelKind,
        operation_id: &str,
        message_id: Option<&str>,
        recipient: &str,
        subject: Option<&str>,
        body: &str,
        payload_class: PayloadClass,
    ) -> Result<Self, DeliveryError> {
        let bounds = DeliveryBounds::default();
        let operation_id = bound_text(operation_id, bounds.max_operation_id, "operation id", true)?;
        let message_id = match message_id {
            Some(id) => bound_text(id, bounds.max_message_id, "message id", true)?,
            None => uuid::Uuid::now_v7().to_string(),
        };
        let max_recipient = if channel == ChannelKind::Email {
            320
        } else {
            bounds.max_recipient
        };
        let recipient = bound_text(recipient, max_recipient, "recipient", true)?;
        let subject = match subject {
            None => None,
            Some(raw) => Some(bound_text(raw, bounds.max_subject, "subject", false)?),
        };
        let body = bound_body(body, bounds.max_body)?;

        Ok(Self {
            message_id,
            operation_id,
            channel,
            recipient,
            subject,
            body,
            payload_class,
        })
    }

    /// SHA-256 of the body. Only valid for [`PayloadClass::Standard`]:
    /// for [`PayloadClass::EphemeralSecret`] this would create an unsalted
    /// oracle over the raw secret, so the store records `None` instead.
    pub fn body_digest(&self) -> Option<[u8; 32]> {
        match self.payload_class {
            PayloadClass::Standard => Some(Sha256::digest(self.body.as_bytes()).into()),
            PayloadClass::EphemeralSecret => None,
        }
    }
}

/// Bound and validate the message body. The body is SMTP DATA content, not
/// a header: line breaks (\\n, \\r\\n) and tabs are legitimate and are
/// CRLF-normalized + dot-stuffed by the SMTP transport. Bare or exotic
/// control characters are still rejected.
fn bound_body(raw: &str, max: usize) -> Result<String, DeliveryError> {
    if raw.trim().is_empty() {
        return Err(DeliveryError::Bounds("body must not be empty"));
    }
    if raw.len() > max {
        return Err(DeliveryError::Bounds("body"));
    }
    if raw
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(DeliveryError::Bounds("body"));
    }
    Ok(raw.to_owned())
}

/// Bound and validate one text field. Control characters are rejected for
/// fields that feed protocols (CRLF injection into SMTP commands/headers or
/// HTTP headers), optionally allowing an empty value.
fn bound_text(
    raw: &str,
    max: usize,
    field: &'static str,
    non_empty: bool,
) -> Result<String, DeliveryError> {
    let trimmed_ok = raw;
    if non_empty && trimmed_ok.trim().is_empty() {
        return Err(DeliveryError::Bounds(field));
    }
    if trimmed_ok.len() > max {
        return Err(DeliveryError::Bounds(field));
    }
    if trimmed_ok.chars().any(|c| c.is_control()) {
        return Err(DeliveryError::Bounds(field));
    }
    Ok(trimmed_ok.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_generates_stable_uuid_when_absent() {
        let first = DeliveryMessage::compose(
            ChannelKind::Email,
            "op-1",
            None,
            "a@example.com",
            Some("hello"),
            "body",
            PayloadClass::Standard,
        )
        .unwrap();
        let second = DeliveryMessage::compose(
            ChannelKind::Email,
            "op-1",
            None,
            "a@example.com",
            Some("hello"),
            "body",
            PayloadClass::Standard,
        )
        .unwrap();
        assert_eq!(first.message_id.len(), 36);
        assert_ne!(first.message_id, second.message_id);
        let supplied = DeliveryMessage::compose(
            ChannelKind::Email,
            "op-1",
            Some("stable-id"),
            "a@example.com",
            None,
            "body",
            PayloadClass::Standard,
        )
        .unwrap();
        assert_eq!(supplied.message_id, "stable-id");
    }

    #[test]
    fn compose_enforces_bounds() {
        let long_body = "b".repeat(65_537);
        assert!(matches!(
            DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                "a@example.com",
                None,
                &long_body,
                PayloadClass::Standard
            ),
            Err(DeliveryError::Bounds("body"))
        ));
        let long_subject = "s".repeat(257);
        assert!(matches!(
            DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                "a@example.com",
                Some(&long_subject),
                "body",
                PayloadClass::Standard
            ),
            Err(DeliveryError::Bounds("subject"))
        ));
        let long_recipient = format!("{}@example.com", "a".repeat(321));
        assert!(matches!(
            DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                &long_recipient,
                None,
                "body",
                PayloadClass::Standard
            ),
            Err(DeliveryError::Bounds("recipient"))
        ));
    }

    #[test]
    fn compose_rejects_crlf_injection() {
        // SMTP/HTTP header injection must fail at composition time.
        assert!(matches!(
            DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                "a@example.com\r\nBCC: victim@example.com",
                None,
                "body",
                PayloadClass::Standard
            ),
            Err(DeliveryError::Bounds("recipient"))
        ));
        assert!(matches!(
            DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                "a@example.com",
                Some("subject\r\nX-Injected: 1"),
                "body",
                PayloadClass::Standard
            ),
            Err(DeliveryError::Bounds("subject"))
        ));
    }

    #[test]
    fn multiline_bodies_are_valid_content() {
        // Multi-line bodies are legitimate DATA content (reset email, alert
        // text): newlines and tabs pass; exotic control characters do not.
        let message = DeliveryMessage::compose(
            ChannelKind::Email,
            "op",
            None,
            "a@example.com",
            None,
            "line one\nline two\r\nline\tthree",
            PayloadClass::EphemeralSecret,
        )
        .unwrap();
        assert_eq!(message.body_digest(), None);
        assert!(matches!(
            DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                "a@example.com",
                None,
                "bad\u{7}control",
                PayloadClass::Standard
            ),
            Err(DeliveryError::Bounds("body"))
        ));
    }

    #[test]
    fn body_digest_is_refused_for_ephemeral_secrets() {
        let message = DeliveryMessage::compose(
            ChannelKind::Email,
            "op",
            None,
            "a@example.com",
            None,
            "raw-token-value",
            PayloadClass::EphemeralSecret,
        )
        .unwrap();
        assert_eq!(message.body_digest(), None);
        let standard = DeliveryMessage::compose(
            ChannelKind::Email,
            "op",
            None,
            "a@example.com",
            None,
            "plain alert text",
            PayloadClass::Standard,
        )
        .unwrap();
        assert_eq!(standard.body_digest().unwrap().len(), 32);
    }

    #[test]
    fn debug_output_never_renders_payload() {
        let message = DeliveryMessage::compose(
            ChannelKind::Email,
            "op",
            None,
            "a@example.com",
            Some("secret subject"),
            "raw-token-value",
            PayloadClass::EphemeralSecret,
        )
        .unwrap();
        let rendered = format!("{message:?}");
        assert!(!rendered.contains("raw-token-value"));
        assert!(!rendered.contains("secret subject"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn channel_kind_round_trip() {
        for kind in [
            ChannelKind::Email,
            ChannelKind::Sms,
            ChannelKind::DingTalk,
            ChannelKind::WeChat,
            ChannelKind::Webhook,
        ] {
            assert_eq!(ChannelKind::parse(kind.as_str()), Some(kind));
        }
    }
}
