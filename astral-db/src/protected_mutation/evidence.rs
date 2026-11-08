//! Typed before/after source evidence for protected mutations.
//!
//! Everything in this module is bound to what the transaction ACTUALLY read
//! and wrote:
//! - [`TargetRowEvidence`] captures a locked target row's before/after state,
//!   both probes taken inside the mutation transaction (`Absent` is a real
//!   probe result and proves create/delete truth).
//! - [`SourceReceipt`] records the actual primary key, typed write kind, and
//!   row count of each durable statement — the statement label alone is never
//!   the durable identity.
//! - Possibly-secret fields never enter the artifact raw: they are replaced
//!   by a keyed HMAC fingerprint ([`fingerprint_secret`]) under a separately
//!   configured protected evidence key (fail-closed when absent), or omitted
//!   entirely together with an explicit limited-evidence marker. A fixed
//!   domain/label is NOT a salt and is never presented as one.
//!
//! The bundle serializes to the bounded canonical `staged_evidence_json` of
//! the authority source outcome and derives the before/after image digests
//! from the actual row images — never from the operation result alone and
//! never from an actor authorization snapshot.

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::authority_source_outcome::{
    AuthoritySourceOutcomeEvidence, AuthoritySourceReceiptIdentity,
};
use astral_types::AstralError;
use serde_json::Value;

/// Evidence serialization domain. This is NOT a secret-protection salt; the
/// secret-fingerprint path is keyed HMAC below.
pub const EVIDENCE_DOMAIN: &[u8] = b"ASTRAL_PROTECTED_EVIDENCE_V1";

/// Environment variable carrying the protected evidence key: hex (>=64 chars)
/// or raw bytes (>=32). It is read once per process and never logged,
/// debug-printed, or written into config artifacts.
const EVIDENCE_KEY_ENV: &str = "ASTRAL_PROTECTED_EVIDENCE_KEY";

/// Minimum key material length in bytes.
const MIN_KEY_BYTES: usize = 32;

/// Hard bound for the serialized evidence bundle (matches the authority
/// source outcome validator).
pub const MAX_EVIDENCE_JSON_BYTES: usize = 256 * 1024;

/// Maximum number of target rows / receipts in one bundle.
const MAX_TARGETS: usize = 64;
const MAX_RECEIPTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("protected evidence key is not configured; secret fingerprinting is unavailable")]
    KeyMissing,
    #[error("protected evidence key is shorter than the minimum length")]
    KeyTooShort,
    #[error("protected evidence bundle is unbounded or incomplete: {0}")]
    Bounds(&'static str),
    #[error("protected evidence serialization failed: {0}")]
    Serialization(String),
}

impl From<EvidenceError> for AstralError {
    fn from(error: EvidenceError) -> Self {
        // Fail-closed: a missing/malformed key or an unbounded artifact makes
        // the whole protected mutation PENDING, never a raw-secret artifact.
        AstralError::Pending(error.to_string())
    }
}

/// The protected evidence key, loaded once. `None` means not configured; any
/// secret fingerprint then fails closed. Key material never appears in Debug.
struct EvidenceKey(Option<Vec<u8>>);

impl std::fmt::Debug for EvidenceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(_) => f.write_str("EvidenceKey([REDACTED])"),
            None => f.write_str("EvidenceKey(unconfigured)"),
        }
    }
}

static EVIDENCE_KEY: std::sync::OnceLock<EvidenceKey> = std::sync::OnceLock::new();

fn load_key() -> EvidenceKey {
    parse_key(std::env::var(EVIDENCE_KEY_ENV).ok().as_deref())
}

fn parse_key(raw: Option<&str>) -> EvidenceKey {
    let Some(raw) = raw else {
        return EvidenceKey(None);
    };
    let trimmed = raw.trim();
    if trimmed.len() >= MIN_KEY_BYTES * 2 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        match hex::decode(trimmed) {
            Ok(key) if key.len() >= MIN_KEY_BYTES => return EvidenceKey(Some(key)),
            Ok(_) => return EvidenceKey(Some(Vec::new())), // present but too short
            Err(_) => return EvidenceKey(None),
        }
    }
    if trimmed.len() >= MIN_KEY_BYTES {
        EvidenceKey(Some(trimmed.as_bytes().to_vec()))
    } else {
        EvidenceKey(Some(Vec::new())) // present but too short
    }
}

fn evidence_key() -> Result<&'static [u8], EvidenceError> {
    EVIDENCE_KEY.get_or_init(load_key).validated()
}

impl EvidenceKey {
    fn validated(&self) -> Result<&[u8], EvidenceError> {
        let key = self.0.as_deref().ok_or(EvidenceError::KeyMissing)?;
        if key.len() < MIN_KEY_BYTES {
            return Err(EvidenceError::KeyTooShort);
        }
        Ok(key)
    }
}

/// Keyed-HMAC fingerprint of one possibly-secret field value.
///
/// Construction: HMAC-SHA256 under the separately configured protected
/// evidence key over `EVIDENCE_DOMAIN || 0x00 || "SECRET" || 0x00 || label ||
/// 0x00 || len64(value) || value` (canonical raw field bytes, exact). Fails
/// closed when the key is absent or too short. The fingerprint is a
/// commitment for correlation, not a salted hash: low-entropy secrets are
/// protected by the KEY, not by the fixed labels. The existing verifier HMAC
/// is a separate purpose with a separate key — no key reuse.
pub fn fingerprint_secret(label: &str, value: &[u8]) -> Result<String, EvidenceError> {
    fingerprint_with_key(evidence_key()?, label, value)
}

/// Pure keyed fingerprint over explicitly supplied key material (tests and
/// callers that already hold the key). Same construction as
/// [`fingerprint_secret`].
pub fn fingerprint_with_key(
    key: &[u8],
    label: &str,
    value: &[u8],
) -> Result<String, EvidenceError> {
    if key.len() < MIN_KEY_BYTES {
        return Err(EvidenceError::KeyTooShort);
    }
    if label.is_empty() || label.len() > 128 {
        return Err(EvidenceError::Bounds("evidence fingerprint label"));
    }
    let mut mac =
        <Hmac<Sha256> as hmac::Mac>::new_from_slice(key).map_err(|_| EvidenceError::KeyTooShort)?;
    mac.update(EVIDENCE_DOMAIN);
    mac.update(b"\0SECRET\0");
    mac.update(label.as_bytes());
    mac.update(b"\0");
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// JSON keys whose values must never enter evidence raw. Same policy family
/// as the delivery credential module.
const SECRET_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "auth",
    "apiKey",
    "api_key",
    "accessKey",
    "access_key",
    "secretKey",
    "secret_key",
    "authHeader",
    "authorization",
    "appSecret",
    "app_secret",
];

/// Rewrite a config JSON so secret-valued fields carry only keyed
/// fingerprints (fail-closed when the evidence key is missing). Non-secret
/// structure is preserved for the typed artifact.
pub fn redact_secrets(config: &Value) -> Result<Value, EvidenceError> {
    redact_secrets_with_key(evidence_key()?, config)
}

/// Pure keyed redaction (tests and callers that already hold the key).
pub fn redact_secrets_with_key(key: &[u8], config: &Value) -> Result<Value, EvidenceError> {
    if key.len() < MIN_KEY_BYTES {
        return Err(EvidenceError::KeyTooShort);
    }
    match config {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key_name, value) in map {
                if SECRET_KEYS
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(key_name))
                {
                    let encoded = canonical_json(value, "secret field")?;
                    let fingerprint = fingerprint_with_key(key, key_name, encoded.as_bytes())?;
                    out.insert(
                        key_name.clone(),
                        serde_json::json!({ "fingerprint": fingerprint, "redacted": true }),
                    );
                } else {
                    out.insert(key_name.clone(), redact_secrets_with_key(key, value)?);
                }
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(redact_secrets_with_key(key, item)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

/// Typed write kind of one durable statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteKind {
    Insert,
    Update,
    Delete,
    /// Absence/cleanup probe (a real statement the transaction ran).
    Probe,
}

impl WriteKind {
    pub const fn as_text(self) -> &'static str {
        match self {
            WriteKind::Insert => "INSERT",
            WriteKind::Update => "UPDATE",
            WriteKind::Delete => "DELETE",
            WriteKind::Probe => "PROBE",
        }
    }
}

/// One real durable write receipt: the actual primary key, the typed write
/// kind, and the affected row count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceReceipt {
    pub entity: &'static str,
    /// Actual primary-key fields of the affected row(s).
    pub key: Value,
    pub kind: WriteKind,
    pub rows_affected: u64,
}

/// Before/after presence of one locked target row. Both probes are read in
/// the mutation transaction; `Absent` is a real probe result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowPresence<T> {
    Absent,
    Present(T),
}

impl<T> RowPresence<T> {
    /// Real probe result -> presence (an absent probe is genuine evidence).
    pub fn from_option(option: Option<T>) -> Self {
        match option {
            Some(value) => RowPresence::Present(value),
            None => RowPresence::Absent,
        }
    }
}

/// Typed before/after evidence for one target row. Callers must not place
/// secret material in `T` — use [`fingerprint_secret`] / [`redact_secrets`]
/// for such fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetRowEvidence<T> {
    pub entity: &'static str,
    /// Actual primary-key fields.
    pub key: Value,
    pub before: RowPresence<T>,
    pub after: RowPresence<T>,
}

#[derive(Debug, Clone)]
struct TargetEntry {
    entity: &'static str,
    key: Value,
    /// Canonical JSON of `Present(T)`; `None` is a real Absent probe.
    before: Option<String>,
    after: Option<String>,
}

impl TargetEntry {
    fn render(&self) -> Value {
        let presence = |state: &Option<String>| match state {
            None => serde_json::json!({ "absent": true }),
            Some(json) => {
                let value: Value =
                    serde_json::from_str(json).unwrap_or(Value::String(json.clone()));
                serde_json::json!({ "present": value })
            }
        };
        serde_json::json!({
            "entity": self.entity,
            "key": self.key,
            "before": presence(&self.before),
            "after": presence(&self.after),
        })
    }

    fn image_bytes(&self, kind: &'static str, state: &Option<String>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(EVIDENCE_DOMAIN);
        for part in [kind, self.entity] {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part.as_bytes());
        }
        let key = self.key.to_string();
        bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
        bytes.extend_from_slice(key.as_bytes());
        match state {
            None => bytes.extend_from_slice(b"ABSENT"),
            Some(json) => bytes.extend_from_slice(json.as_bytes()),
        }
        bytes
    }
}

/// The complete typed evidence bundle for one protected mutation.
#[derive(Debug, Clone, Default)]
pub struct ProtectedSourceEvidence {
    targets: Vec<TargetEntry>,
    receipts: Vec<SourceReceipt>,
}

impl ProtectedSourceEvidence {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one typed before/after row capture.
    pub fn target_row<T: Serialize>(
        mut self,
        evidence: TargetRowEvidence<T>,
    ) -> Result<Self, EvidenceError> {
        if self.targets.len() >= MAX_TARGETS {
            return Err(EvidenceError::Bounds("evidence target count"));
        }
        let encode = |state: &RowPresence<T>| -> Result<Option<String>, EvidenceError> {
            Ok(match state {
                RowPresence::Absent => None,
                RowPresence::Present(row) => Some(canonical_json(row, evidence.entity)?),
            })
        };
        self.targets.push(TargetEntry {
            entity: evidence.entity,
            key: evidence.key,
            before: encode(&evidence.before)?,
            after: encode(&evidence.after)?,
        });
        self.enforce_bounds()?;
        Ok(self)
    }

    /// Add one real statement receipt.
    pub fn receipt(
        mut self,
        entity: &'static str,
        key: Value,
        kind: WriteKind,
        rows_affected: u64,
    ) -> Self {
        self.receipts.push(SourceReceipt {
            entity,
            key,
            kind,
            rows_affected,
        });
        self
    }

    pub fn receipts(&self) -> &[SourceReceipt] {
        &self.receipts
    }

    fn enforce_bounds(&self) -> Result<(), EvidenceError> {
        // Size/count bounds only: the receipts requirement is a FINAL
        // artifact rule (targets are added before receipts by every caller).
        if self.receipts.len() > MAX_RECEIPTS {
            return Err(EvidenceError::Bounds("evidence receipt count"));
        }
        let artifact = serde_json::json!({
            "targets": self.targets.iter().map(TargetEntry::render).collect::<Vec<_>>(),
            "receipts": self.receipts,
        });
        let json = canonical_json(&artifact, "evidence")?;
        if json.len() > MAX_EVIDENCE_JSON_BYTES {
            return Err(EvidenceError::Bounds("evidence artifact"));
        }
        Ok(())
    }

    /// Canonical bounded staged artifact. Requires at least one real receipt:
    /// a protected mutation without actual durable statement receipts is not
    /// a proven source outcome.
    pub fn to_staged_json(&self) -> Result<String, EvidenceError> {
        if self.receipts.is_empty() {
            return Err(EvidenceError::Bounds(
                "evidence requires the actual durable statement receipts",
            ));
        }
        if self.targets.is_empty() {
            return Err(EvidenceError::Bounds(
                "evidence requires actual target row probes",
            ));
        }
        self.enforce_bounds()?;
        let artifact = serde_json::json!({
            "targets": self.targets.iter().map(TargetEntry::render).collect::<Vec<_>>(),
            "receipts": self.receipts,
        });
        canonical_json(&artifact, "evidence")
    }

    /// Canonical before/after image digests over the ACTUAL row images
    /// (domain + kind + per-target length-prefixed bytes, registration order).
    pub fn image_digests(&self) -> (String, String) {
        fn image(
            kind: &'static str,
            entries: &[TargetEntry],
            side: fn(&TargetEntry) -> &Option<String>,
        ) -> String {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(EVIDENCE_DOMAIN);
            bytes.extend_from_slice(kind.as_bytes());
            bytes.extend_from_slice(b"\0");
            for entry in entries {
                let part = entry.image_bytes(kind, side(entry));
                bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
                bytes.extend_from_slice(&part);
            }
            hex::encode(Sha256::digest(&bytes))
        }
        (
            image("BEFORE", &self.targets, |entry| &entry.before),
            image("AFTER", &self.targets, |entry| &entry.after),
        )
    }

    /// Map the typed receipts onto the authority receipt identities: actual
    /// primary key + typed write kind + row count.
    pub(crate) fn authority_receipts(&self) -> Vec<AuthoritySourceReceiptIdentity> {
        self.receipts
            .iter()
            .map(|receipt| AuthoritySourceReceiptIdentity {
                identity_kind: format!("{}:{}", receipt.entity, receipt.kind.as_text()),
                identity: {
                    let mut digest = Sha256::new();
                    digest.update(EVIDENCE_DOMAIN);
                    digest.update(b"\0RECEIPT\0");
                    for part in [
                        receipt.entity,
                        receipt.kind.as_text(),
                        &receipt.key.to_string(),
                    ] {
                        digest.update((part.len() as u64).to_be_bytes());
                        digest.update(part.as_bytes());
                    }
                    digest.update(receipt.rows_affected.to_be_bytes());
                    hex::encode(digest.finalize())
                },
            })
            .collect()
    }
}

/// Canonical source-commit digest over the staged artifact AND the durable
/// operation result — deliberately never the result alone.
pub fn source_commit_digest(staged_evidence_json: &str, result_json: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    bytes.extend_from_slice(b"SOURCE_COMMIT\0");
    for part in [staged_evidence_json, result_json] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    hex::encode(Sha256::digest(&bytes))
}

/// Build the authority core evidence for this bundle.
pub fn core_evidence(
    evidence: &ProtectedSourceEvidence,
    staged_evidence_json: &str,
    result_json: &str,
) -> AuthoritySourceOutcomeEvidence {
    let (before_image_digest, after_image_digest) = evidence.image_digests();
    AuthoritySourceOutcomeEvidence {
        source_commit_digest: source_commit_digest(staged_evidence_json, result_json),
        before_image_digest,
        after_image_digest,
        source_receipts: evidence.authority_receipts(),
    }
}

fn canonical_json<T: Serialize>(value: &T, what: &'static str) -> Result<String, EvidenceError> {
    serde_json::to_string(value)
        .map_err(|error| EvidenceError::Serialization(format!("evidence {what}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprint_requires_a_valid_key_and_binds_label_value_and_key() {
        assert_eq!(parse_key(None).validated(), Err(EvidenceError::KeyMissing));
        assert_eq!(
            parse_key(Some("short")).validated(),
            Err(EvidenceError::KeyTooShort)
        );
        let raw = "a".repeat(64);
        let key = parse_key(Some(&raw));
        assert_eq!(key.validated().unwrap(), &[0xaa; 32]);
        let fingerprint =
            fingerprint_with_key(key.validated().unwrap(), "password", b"example").unwrap();
        assert_eq!(
            fingerprint,
            fingerprint_with_key(&[0xaa; 32], "password", b"example").unwrap()
        );
        assert_ne!(
            fingerprint,
            fingerprint_with_key(&[0xaa; 32], "token", b"example").unwrap()
        );
        assert_ne!(
            fingerprint,
            fingerprint_with_key(&[0xaa; 32], "password", b"changed").unwrap()
        );
        assert_ne!(
            fingerprint,
            fingerprint_with_key(&[0xbb; 32], "password", b"example").unwrap()
        );
        assert!(fingerprint_with_key(&[], "password", b"example").is_err());
    }

    #[test]
    fn redact_secrets_fingerprints_secret_fields_and_keeps_structure() {
        let key = [0xa5; 32];
        let config = json!({
            "host": "smtp.example.com",
            "password": "hunter2",
            "nested": { "apiKey": "abcd", "port": 587 },
            "passwordEnv": "ASTRAL_SMTP_PASSWORD",
        });
        let redacted = redact_secrets_with_key(&key, &config).unwrap();
        assert_eq!(redacted["host"], "smtp.example.com");
        assert_eq!(redacted["passwordEnv"], "ASTRAL_SMTP_PASSWORD");
        assert_eq!(redacted["nested"]["port"], 587);
        assert!(redacted["password"].get("fingerprint").is_some());
        assert_eq!(redacted["password"]["redacted"], true);
        let rendered = serde_json::to_string(&redacted).unwrap();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("abcd"), "{rendered}");
        for value in [
            json!(""),
            json!(123456),
            json!({"value": "nested-secret"}),
            json!(["array-secret"]),
            Value::Null,
        ] {
            let secret = json!({"PASSWORD": value});
            let redacted = redact_secrets_with_key(&key, &secret).unwrap();
            assert_eq!(redacted["PASSWORD"]["redacted"], true);
            assert!(redacted["PASSWORD"]["fingerprint"].as_str().is_some());
            assert!(!redacted.to_string().contains("nested-secret"));
            assert!(!redacted.to_string().contains("array-secret"));
        }
        assert!(redact_secrets_with_key(&[], &config).is_err());
    }

    #[test]
    fn evidence_bundle_requires_receipts_and_binds_images() {
        let evidence = ProtectedSourceEvidence::new();
        assert!(
            evidence.to_staged_json().is_err(),
            "no receipts = no artifact"
        );
        let row = json!({"cardId": 7, "status": "ACTIVE"});
        let evidence = evidence
            .target_row(TargetRowEvidence {
                entity: "async_operation",
                key: json!({"taskId": "uc_bind:t1"}),
                before: RowPresence::<serde_json::Value>::Absent,
                after: RowPresence::Present(row),
            })
            .unwrap()
            .receipt(
                "async_operation",
                json!({"taskId": "uc_bind:t1"}),
                WriteKind::Insert,
                1,
            );
        let staged = evidence.to_staged_json().unwrap();
        assert!(staged.contains("absent"), "{staged}");
        assert!(staged.contains("\"cardId\":7"), "{staged}");
        let (before, after) = evidence.image_digests();
        assert_ne!(before, after, "before/after image sets differ here");
        let (before2, after2) = evidence.image_digests();
        assert_eq!(before, before2);
        assert_eq!(after, after2);
        // BEFORE and AFTER use separate domains, including for a no-op.
        let noop = ProtectedSourceEvidence::new()
            .target_row(TargetRowEvidence {
                entity: "alert_rule",
                key: json!({"id": 1}),
                before: RowPresence::Present(json!({"id": 1, "enabled": true})),
                after: RowPresence::Present(json!({"id": 1, "enabled": true})),
            })
            .unwrap()
            .receipt("alert_rule", json!({"id": 1}), WriteKind::Update, 1);
        let (noop_before, noop_after) = noop.image_digests();
        assert_ne!(noop_before, noop_after);
        let mut other_target = noop.clone();
        other_target.targets[0].key = json!({"id": 2});
        assert_ne!(noop.image_digests(), other_target.image_digests());
        other_target = noop.clone();
        other_target.targets[0].entity = "other_rule";
        assert_ne!(noop.image_digests(), other_target.image_digests());
    }

    #[test]
    fn core_evidence_covers_artifact_and_result_not_result_alone() {
        let evidence = ProtectedSourceEvidence::new()
            .target_row(TargetRowEvidence {
                entity: "notification_channel",
                key: json!({"id": 3}),
                before: RowPresence::Absent,
                after: RowPresence::Present(json!({"id": 3, "name": "ops"})),
            })
            .unwrap()
            .receipt(
                "notification_channel",
                json!({"id": 3}),
                WriteKind::Insert,
                1,
            );
        let staged = evidence.to_staged_json().unwrap();
        let core_a = core_evidence(&evidence, &staged, r#"{"purchaseId": 9}"#);
        let core_b = core_evidence(&evidence, &staged, r#"{"purchaseId": 10}"#);
        assert_ne!(
            core_a.source_commit_digest, core_b.source_commit_digest,
            "the commit digest must bind the result too"
        );
        let core_c = core_evidence(
            &evidence,
            &staged.replace("ops", "ops2"),
            r#"{"purchaseId": 9}"#,
        );
        assert_ne!(
            core_a.source_commit_digest, core_c.source_commit_digest,
            "the commit digest must bind the staged artifact too"
        );
        assert_eq!(core_a.source_receipts.len(), 1);
        assert!(core_a.source_receipts[0]
            .identity_kind
            .contains("notification_channel:INSERT"));
        assert_eq!(core_a.source_receipts[0].identity.len(), 64);
        core_a.source_receipts[0].validate().unwrap();
        let mut changed_receipt = evidence.clone();
        changed_receipt.receipts[0].rows_affected = 2;
        assert_ne!(
            evidence.authority_receipts(),
            changed_receipt.authority_receipts()
        );
        changed_receipt = evidence.clone();
        changed_receipt.receipts[0].key = json!({"id": 4});
        assert_ne!(
            evidence.authority_receipts(),
            changed_receipt.authority_receipts()
        );
        let (before, after) = evidence.image_digests();
        assert_eq!(core_a.before_image_digest, before);
        assert_eq!(core_a.after_image_digest, after);
    }

    #[test]
    fn oversized_evidence_is_bounded() {
        let evidence = ProtectedSourceEvidence::new().target_row(TargetRowEvidence {
            entity: "notification_channel",
            key: json!({"id": 1}),
            before: RowPresence::Absent,
            after: RowPresence::Present(json!({ "blob": "x".repeat(MAX_EVIDENCE_JSON_BYTES) })),
        });
        assert!(matches!(evidence, Err(EvidenceError::Bounds(_))));
        let mut evidence = ProtectedSourceEvidence::new()
            .target_row(TargetRowEvidence {
                entity: "notification_channel",
                key: json!({"id": 1}),
                before: RowPresence::Absent,
                after: RowPresence::Present(json!({"id": 1})),
            })
            .unwrap();
        for id in 0..MAX_RECEIPTS {
            evidence = evidence.receipt(
                "notification_channel",
                json!({"id": id}),
                WriteKind::Insert,
                1,
            );
        }
        assert!(evidence.to_staged_json().is_ok());
        evidence = evidence.receipt(
            "notification_channel",
            json!({"id": 99}),
            WriteKind::Insert,
            1,
        );
        assert!(matches!(
            evidence.to_staged_json(),
            Err(EvidenceError::Bounds("evidence receipt count"))
        ));
    }

    #[test]
    fn debug_output_never_leaks_key_material() {
        let debugged = format!(
            "{:?}",
            EvidenceKey(Some(b"test-key-material-must-stay-private".to_vec()))
        );
        assert_eq!(debugged, "EvidenceKey([REDACTED])");
        assert_eq!(
            format!("{:?}", EvidenceKey(None)),
            "EvidenceKey(unconfigured)"
        );
    }
}
