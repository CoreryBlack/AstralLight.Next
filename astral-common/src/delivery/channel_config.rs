//! Channel configuration resolution.
//!
//! Notification-channel rows persist a small JSON config. This module turns
//! that JSON into a typed, policy-checked [`ResolvedChannel`] at dispatch
//! time:
//! - inline secrets are rejected (protected `<field>Env` env refs only);
//! - endpoints pass [`EndpointGuard`] policy (allowlist, SSRF ranges);
//! - SMTP security defaults to STARTTLS and downgrade is forbidden;
//! - HTTPS relays require an explicit receipt mapping for `DELIVERED`.

use serde_json::Value;

use crate::delivery::credential::{reject_inline_secrets, resolve_env_ref};
use crate::delivery::endpoint::EndpointGuard;
use crate::delivery::intent::ChannelKind;
use crate::delivery::state::DeliveryError;

/// SMTP transport security. `None` is only valid against loopback fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Implicit TLS from the first byte (typically port 465).
    Wrapper,
    /// Plain connect, then STARTTLS upgrade (typically port 587).
    StartTls,
    /// No TLS: loopback test fixtures only.
    None,
}

/// Resolved SMTP configuration (password already pulled from its env ref).
#[derive(Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: Option<String>,
    /// Resolved secret. `Debug` redacts it.
    pub password: Option<String>,
    pub sender: String,
    pub hello_name: String,
    pub guard: EndpointGuard,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("sender", &self.sender)
            .field("hello_name", &self.hello_name)
            .field("guard", &self.guard)
            .finish()
    }
}

/// Resolved HTTPS relay/webhook configuration (auth header already pulled
/// from its env ref).
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRelayConfig {
    pub url: String,
    /// JSON payload template with `{{recipient}}`/`{{subject}}`/`{{body}}`
    /// placeholders; `None` for webhooks (caller supplies the JSON body).
    pub payload_template: Option<String>,
    /// Receipt proof mapping: when this JSON pointer field equals
    /// `receipt_delivered_value`, the relay reported end delivery.
    pub receipt_field: Option<String>,
    pub receipt_delivered_value: Option<String>,
    pub auth_header_name: Option<String>,
    /// Resolved secret. `Debug` redacts it.
    pub auth_header_value: Option<String>,
    pub guard: EndpointGuard,
    /// Webhook endpoints are synchronous receivers: 2xx proves delivery.
    /// Exact assumption: the configured URL is the FINAL receiver of the
    /// event and its 2xx is its synchronous consumption receipt. A
    /// fronting/queueing endpoint must instead be modeled as a relay with an
    /// explicit receipt mapping (its 2xx is acceptance, not delivery).
    /// Relays are queueing providers: 2xx is at most ACCEPTED.
    pub delivered_on_2xx: bool,
}

impl std::fmt::Debug for HttpRelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRelayConfig")
            .field("url", &self.url)
            .field(
                "payload_template",
                &self.payload_template.as_ref().map(|_| "<present>"),
            )
            .field("receipt_field", &self.receipt_field)
            .field("receipt_delivered_value", &self.receipt_delivered_value)
            .field("auth_header_name", &self.auth_header_name)
            .field(
                "auth_header_value",
                &self.auth_header_value.as_ref().map(|_| "<redacted>"),
            )
            .field("delivered_on_2xx", &self.delivered_on_2xx)
            .finish()
    }
}

/// Typed channel ready for dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedChannel {
    Smtp(SmtpConfig),
    Relay(HttpRelayConfig),
    Webhook(HttpRelayConfig),
}

impl ResolvedChannel {
    pub fn channel_kind(&self) -> ChannelKind {
        match self {
            ResolvedChannel::Smtp(_) => ChannelKind::Email,
            ResolvedChannel::Relay(_) => ChannelKind::Sms, // refined by caller kind
            ResolvedChannel::Webhook(_) => ChannelKind::Webhook,
        }
    }
}

/// Parse and resolve a channel row's config JSON for the given kind.
///
/// Secrets are resolved from the protected environment now (dispatch time).
pub fn resolve_channel(
    kind: ChannelKind,
    config_json: Option<&str>,
) -> Result<ResolvedChannel, DeliveryError> {
    let value: Value = match config_json {
        None | Some("") => Value::Object(Default::default()),
        Some(raw) => serde_json::from_str(raw)
            .map_err(|_| DeliveryError::InvalidConfig("channel config is not valid JSON"))?,
    };
    reject_inline_secrets(&value)?;
    match kind {
        ChannelKind::Email => smtp_from_json(&value).map(ResolvedChannel::Smtp),
        ChannelKind::Sms | ChannelKind::DingTalk | ChannelKind::WeChat => {
            relay_from_json(&value, false).map(ResolvedChannel::Relay)
        }
        ChannelKind::Webhook => relay_from_json(&value, true).map(ResolvedChannel::Webhook),
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).map(str::trim)
}

fn smtp_from_json(value: &Value) -> Result<SmtpConfig, DeliveryError> {
    let host = string_field(value, "host")
        .filter(|h| !h.is_empty() && h.len() <= 253)
        .ok_or(DeliveryError::InvalidConfig("smtp host missing or invalid"))?
        .trim_end_matches('.')
        .to_owned();
    let port = match value.get("port") {
        None => 587,
        Some(raw) => {
            let port = raw
                .as_u64()
                .or_else(|| raw.as_str().and_then(|s| s.trim().parse().ok()))
                .ok_or(DeliveryError::InvalidConfig("smtp port"))?;
            u16::try_from(port).map_err(|_| DeliveryError::InvalidConfig("smtp port"))?
        }
    };
    let security = match string_field(value, "security")
        .unwrap_or("STARTTLS")
        .to_ascii_uppercase()
        .as_str()
    {
        "STARTTLS" => SmtpSecurity::StartTls,
        "TLS" | "WRAPPER" | "SSL" => SmtpSecurity::Wrapper,
        "NONE" => SmtpSecurity::None,
        _ => return Err(DeliveryError::InvalidConfig("smtp security")),
    };
    let sender = string_field(value, "from")
        .filter(|s| !s.is_empty())
        .ok_or(DeliveryError::InvalidConfig("smtp sender (from) missing"))?
        .to_owned();
    let username = string_field(value, "username")
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let password = resolve_env_ref(value, "password")?;
    if username.is_some() && password.is_none() {
        return Err(DeliveryError::InvalidConfig(
            "smtp username requires passwordEnv",
        ));
    }
    let hello_name = string_field(value, "helo")
        .filter(|s| !s.is_empty())
        .unwrap_or("astral-delivery")
        .to_owned();

    // TLS policy: no plaintext to public hosts. Security::None is admitted
    // only for the loopback fixture profile (its guard allows loopback).
    let allowed_hosts: Vec<String> = value
        .get("allowedHosts")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let guard = if security == SmtpSecurity::None {
        EndpointGuard::loopback_fixture(allowed_hosts)
    } else {
        EndpointGuard::public(allowed_hosts)
    };
    if security == SmtpSecurity::None {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let ip: std::net::IpAddr = bare.parse().map_err(|_| {
            DeliveryError::EndpointBlocked("smtp security NONE requires a loopback IP")
        })?;
        guard.validate_ip(ip)?;
    }

    Ok(SmtpConfig {
        host,
        port,
        security,
        username,
        password,
        sender,
        hello_name,
        guard,
    })
}

fn relay_from_json(
    value: &Value,
    delivered_on_2xx: bool,
) -> Result<HttpRelayConfig, DeliveryError> {
    let url = string_field(value, "url")
        .filter(|u| !u.is_empty())
        .ok_or(DeliveryError::InvalidConfig("relay url missing"))?
        .to_owned();
    let allowed_hosts: Vec<String> = value
        .get("allowedHosts")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let guard = EndpointGuard::public(allowed_hosts);
    guard
        .check_url(&url)
        .map_err(|_| DeliveryError::EndpointBlocked("relay url failed endpoint policy"))?;

    let payload_template = match string_field(value, "payloadTemplate") {
        None | Some("") => None,
        Some(template) => {
            if template.len() > 8192 {
                return Err(DeliveryError::Bounds("relay payload template"));
            }
            // The template must be valid JSON after placeholder substitution;
            // check the static shape now (placeholders live inside strings).
            serde_json::from_str::<Value>(template).map_err(|_| {
                DeliveryError::InvalidConfig("relay payload template is not valid JSON")
            })?;
            Some(template.to_owned())
        }
    };
    let receipt_field = string_field(value, "receiptField")
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let receipt_delivered_value = string_field(value, "receiptDeliveredValue")
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if (receipt_field.is_some()) != (receipt_delivered_value.is_some()) {
        return Err(DeliveryError::InvalidConfig(
            "relay receipt mapping requires both receiptField and receiptDeliveredValue",
        ));
    }
    // Without an explicit receipt mapping a relay can never prove delivery;
    // that is valid and simply caps observable truth at ACCEPTED forever.
    let auth_header_name = string_field(value, "authHeaderName")
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let auth_header_value = resolve_env_ref(value, "authHeader")?;
    if auth_header_name.is_some() != auth_header_value.is_some() {
        return Err(DeliveryError::InvalidConfig(
            "relay auth requires both authHeaderName and authHeaderEnv",
        ));
    }

    Ok(HttpRelayConfig {
        url,
        payload_template,
        receipt_field,
        receipt_delivered_value,
        auth_header_name,
        auth_header_value,
        guard,
        delivered_on_2xx,
    })
}

/// Render a relay payload template with JSON-escaped substitutions and
/// return the parsed JSON object. Placeholders: `{{recipient}}`,
/// `{{subject}}`, `{{body}}`.
pub fn render_relay_payload(
    template: &str,
    recipient: &str,
    subject: Option<&str>,
    body: &str,
) -> Result<Value, DeliveryError> {
    let rendered = template
        .replace("{{recipient}}", &json_escape(recipient))
        .replace("{{subject}}", &json_escape(subject.unwrap_or("")))
        .replace("{{body}}", &json_escape(body));
    if rendered.len() > 65_536 {
        return Err(DeliveryError::Bounds("rendered relay payload"));
    }
    let value: Value = serde_json::from_str(&rendered)
        .map_err(|_| DeliveryError::InvalidConfig("rendered relay payload is not valid JSON"))?;
    Ok(value)
}

fn json_escape(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len() + 8);
    for c in raw.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Loopback fixture config for transport tests.
    pub(crate) fn relay_config_for_test(url: &str, delivered_on_2xx: bool) -> HttpRelayConfig {
        HttpRelayConfig {
            url: url.to_owned(),
            payload_template: None,
            receipt_field: Some("status".to_owned()),
            receipt_delivered_value: Some("DELIVERED".to_owned()),
            auth_header_name: None,
            auth_header_value: None,
            guard: EndpointGuard::loopback_fixture(vec![]),
            delivered_on_2xx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_config_defaults_to_starttls_and_requires_env_secret() {
        let resolved = resolve_channel(
            ChannelKind::Email,
            Some(
                r#"{"host":"smtp.example.com","from":"noreply@example.com","username":"noreply@example.com","password":"inline"}"#,
            ),
        );
        assert_eq!(resolved.unwrap_err(), DeliveryError::InlineSecretRejected);

        let resolved = resolve_channel(
            ChannelKind::Email,
            Some(
                r#"{"host":"smtp.example.com","from":"noreply@example.com","username":"noreply@example.com"}"#,
            ),
        );
        assert!(matches!(
            resolved,
            Err(DeliveryError::InvalidConfig(
                "smtp username requires passwordEnv"
            ))
        ));
    }

    #[test]
    fn email_starttls_refuses_plaintext_none_profile() {
        let resolved = resolve_channel(
            ChannelKind::Email,
            Some(r#"{"host":"smtp.example.com","from":"a@b.c","security":"NONE"}"#),
        );
        assert!(matches!(
            resolved,
            Err(DeliveryError::EndpointBlocked(
                "smtp security NONE requires a loopback IP"
            ))
        ));
    }

    #[test]
    fn relay_2xx_without_receipt_mapping_is_accept_only() {
        let resolved = resolve_channel(
            ChannelKind::Sms,
            Some(r#"{"url":"https://sms.example.com/send","payloadTemplate":"{\"text\":\"{{body}}\"}"}"#),
        )
        .unwrap();
        let ResolvedChannel::Relay(config) = resolved else {
            panic!("relay expected");
        };
        assert!(!config.delivered_on_2xx);
        assert!(config.receipt_field.is_none());
    }

    #[test]
    fn webhook_is_delivered_on_2xx() {
        let resolved = resolve_channel(
            ChannelKind::Webhook,
            Some(r#"{"url":"https://hooks.example.com/x"}"#),
        )
        .unwrap();
        let ResolvedChannel::Webhook(config) = resolved else {
            panic!("webhook expected");
        };
        assert!(config.delivered_on_2xx);
    }

    #[test]
    fn relay_receipt_mapping_requires_both_fields() {
        assert!(matches!(
            resolve_channel(
                ChannelKind::Sms,
                Some(r#"{"url":"https://sms.example.com/send","receiptField":"status"}"#)
            ),
            Err(DeliveryError::InvalidConfig(
                "relay receipt mapping requires both receiptField and receiptDeliveredValue"
            ))
        ));
    }

    #[test]
    fn relay_url_must_pass_endpoint_policy() {
        assert!(matches!(
            resolve_channel(
                ChannelKind::Sms,
                Some(r#"{"url":"http://169.254.169.254/x"}"#)
            ),
            Err(DeliveryError::EndpointBlocked(
                "relay url failed endpoint policy"
            ))
        ));
    }

    #[test]
    fn relay_auth_requires_name_and_env_pair() {
        assert!(matches!(
            resolve_channel(
                ChannelKind::Sms,
                Some(r#"{"url":"https://sms.example.com/send","authHeaderName":"Authorization"}"#)
            ),
            Err(DeliveryError::InvalidConfig(
                "relay auth requires both authHeaderName and authHeaderEnv"
            ))
        ));
    }

    #[test]
    fn template_render_escapes_and_validates() {
        let payload = render_relay_payload(
            r#"{"msgtype":"text","text":{"content":"{{body}}","to":"{{recipient}}"}}"#,
            "13800000000",
            None,
            "line1\nline2 \"quoted\"",
        )
        .unwrap();
        assert_eq!(
            payload["text"]["content"].as_str().unwrap(),
            "line1\nline2 \"quoted\""
        );
        assert!(render_relay_payload(r#"{"a":"{{body}}"}"#, "r", None, "ok").is_ok());
        assert!(render_relay_payload("not json", "r", None, "b").is_err());
    }
}
