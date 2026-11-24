//! memory—v1: Authentication of independent startup evidence. This module
//! verifies an operator-pinned public key; it does not issue evidence.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::memory_v1_registry::{RegistryDeclaration, RegistrySnapshot, RegistryStatus};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::JournalAnchor;

/// Boot-only observations supplied by the trusted composition, not the envelope.
pub struct StartupEvidenceContext<'a> {
    pub installation_id: MemoryId,
    pub database_scope: [u8; 32],
    pub epoch: MemoryId,
    pub checkpoint_tail: JournalAnchor,
    pub evidence: &'a AuthenticatedStartupEvidence,
}

const DOMAIN: &[u8] = b"astrallight/memory-v1/startup-evidence/1\0";
const MAX_VALIDITY_SECONDS: i64 = 900;
const VERSION: u16 = 1;

/// Maximum size of the externally supplied JSON envelope before decoding.
pub const MAX_STARTUP_EVIDENCE_BYTES: usize = 16 * 1024;

/// The exact startup state to which the independent issuer applied its checks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupEvidenceSubject {
    pub installation_id: MemoryId,
    pub database_scope: [u8; 32],
    pub schema_fingerprint: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub registry_digest: [u8; 32],
    pub journal_stream: MemoryId,
    pub journal_epoch: MemoryId,
    pub journal_sequence: u64,
    pub mutation_sequence: u64,
    pub journal_tail_hash: [u8; 32],
}

impl StartupEvidenceSubject {
    // memory—v1: Reject absent or internally inconsistent scope values.
    fn is_valid(&self) -> bool {
        [
            self.installation_id,
            self.journal_stream,
            self.journal_epoch,
        ]
        .iter()
        .all(|id| id.as_bytes() != &[0; 16])
            && [
                self.database_scope,
                self.schema_fingerprint,
                self.candidate_digest,
                self.registry_digest,
                self.journal_tail_hash,
            ]
            .iter()
            .all(|digest| digest != &[0; 32])
            && self.mutation_sequence <= self.journal_sequence
    }
}

/// Hashes of independently retained reports, not booleans or family names.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupEvidenceReports {
    pub source_provenance: [u8; 32],
    pub snapshot_identity: [u8; 32],
    pub lifecycle_and_validity: [u8; 32],
    pub confirmation_authority: [u8; 32],
    pub resource_ownership: [u8; 32],
    pub eligibility: [u8; 32],
    pub separation_of_duties: [u8; 32],
    pub writer_coverage: [u8; 32],
    pub audit_correlation: [u8; 32],
    pub persistence_recovery: [u8; 32],
}

impl StartupEvidenceReports {
    // memory—v1: All ten independent report references are mandatory.
    fn digests(&self) -> [[u8; 32]; 10] {
        [
            self.source_provenance,
            self.snapshot_identity,
            self.lifecycle_and_validity,
            self.confirmation_authority,
            self.resource_ownership,
            self.eligibility,
            self.separation_of_duties,
            self.writer_coverage,
            self.audit_correlation,
            self.persistence_recovery,
        ]
    }
}

/// Payload signed by the external evidence owner after checking its reports.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupEvidencePayload {
    pub version: u16,
    pub subject: StartupEvidenceSubject,
    pub issued_at: i64,
    pub expires_at: i64,
    pub reports: StartupEvidenceReports,
}

impl StartupEvidencePayload {
    /// memory—v1: V1 wire signature covers the domain and compact JSON of this
    /// ordered, fixed-field struct, not the transport envelope or its formatting.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = DOMAIN.to_vec();
        serde_json::to_writer(&mut bytes, self)?;
        Ok(bytes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: StartupEvidencePayload,
    signature: String,
}

/// Startup evidence verification failures; messages never include input bytes.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StartupEvidenceError {
    #[error("invalid memory-v1 startup evidence envelope")]
    InvalidEnvelope,
    #[error("invalid memory-v1 startup evidence signature")]
    InvalidSignature,
    #[error("memory-v1 startup evidence does not bind the captured startup state")]
    SubjectMismatch,
    #[error("memory-v1 startup evidence is stale, not yet valid, or outlives its startup window")]
    InvalidWindow,
    #[error("memory-v1 startup evidence has incomplete or duplicate report references")]
    InvalidReports,
}

/// Opaque result of verification against the operator's pinned verification key.
/// A valid signature authenticates the issuer's conclusions, not the reports'
/// truth; the issuer must verify and retain those reports out of process.
#[derive(Debug)]
pub(crate) struct VerifiedStartupEvidence {
    pub(super) trusted_time: i64,
    pub(crate) envelope_digest: [u8; 32],
}

/// A cryptographically authenticated envelope, not yet matched to any candidate.
/// It grants no admission and the full subject must still be rechecked at adoption.
pub struct AuthenticatedStartupEvidence {
    subject: StartupEvidenceSubject,
    issued_at: i64,
    expires_at: i64,
    digest: [u8; 32],
}

impl AuthenticatedStartupEvidence {
    /// memory—v1: Authenticate the independently retained reports before recovery I/O.
    pub fn authenticate(pinned_key: &[u8; 32], bytes: &[u8]) -> Result<Self, StartupEvidenceError> {
        use StartupEvidenceError as Error;
        if bytes.len() > MAX_STARTUP_EVIDENCE_BYTES {
            return Err(Error::InvalidEnvelope);
        }
        let envelope: Envelope =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidEnvelope)?;
        if envelope.payload.version != VERSION {
            return Err(Error::InvalidEnvelope);
        }
        let mut signature = [0u8; 64];
        hex::decode_to_slice(&envelope.signature, &mut signature)
            .map_err(|_| Error::InvalidEnvelope)?;
        if hex::encode(signature) != envelope.signature {
            return Err(Error::InvalidEnvelope);
        }
        let message = envelope
            .payload
            .signing_bytes()
            .map_err(|_| Error::InvalidEnvelope)?;
        UnparsedPublicKey::new(&ED25519, pinned_key)
            .verify(&message, &signature)
            .map_err(|_| Error::InvalidSignature)?;
        if !envelope.payload.subject.is_valid() {
            return Err(Error::SubjectMismatch);
        }
        let start = envelope.payload.issued_at;
        let end = envelope.payload.expires_at;
        if start <= 0 || end <= start || end - start > MAX_VALIDITY_SECONDS {
            return Err(Error::InvalidWindow);
        }
        let mut reports = envelope.payload.reports.digests();
        reports.sort_unstable();
        if reports[0] == [0; 32] || reports.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::InvalidReports);
        }
        Ok(Self {
            subject: envelope.payload.subject,
            issued_at: start,
            expires_at: end,
            digest: Sha256::new()
                .chain_update(message)
                .chain_update(signature)
                .finalize()
                .into(),
        })
    }

    /// memory—v1: Verify freshness without claiming that this state is present.
    pub fn check_window(&self, now: i64) -> Result<(), StartupEvidenceError> {
        if now < self.issued_at || now >= self.expires_at {
            return Err(StartupEvidenceError::InvalidWindow);
        }
        Ok(())
    }

    /// memory—v1: The whole kernel-reported UTC interval must lie inside
    /// the signed window before recovery, publication, binding or readiness.
    pub fn check_current_window(
        &self,
    ) -> Result<crate::memory_v1_policy_time::PolicyTime, StartupEvidenceError> {
        let sample = crate::memory_v1_policy_time::PolicyTime::sample_host()
            .ok_or(StartupEvidenceError::InvalidWindow)?;
        self.check_window(sample.earliest())?;
        self.check_window(sample.latest())?;
        Ok(sample)
    }

    /// memory—v1: Check the authenticated installation and checkpoint before recovery.
    pub fn check_checkpoint(
        &self,
        id: MemoryId,
        epoch: MemoryId,
        tail: JournalAnchor,
    ) -> Result<(), StartupEvidenceError> {
        let subject = &self.subject;
        if subject.installation_id != id
            || subject.journal_epoch != epoch
            || subject.journal_stream != tail.stream_id()
            || subject.journal_sequence != tail.journal_sequence()
            || subject.mutation_sequence != tail.mutation_sequence()
            || &subject.journal_tail_hash != tail.frame_hash()
        {
            return Err(StartupEvidenceError::SubjectMismatch);
        }
        Ok(())
    }

    /// memory—v1: Bind recovery to the database identity observed on its actual connection.
    pub fn check_database_scope(&self, scope: &[u8; 32]) -> Result<(), StartupEvidenceError> {
        if &self.subject.database_scope != scope {
            return Err(StartupEvidenceError::SubjectMismatch);
        }
        Ok(())
    }

    // memory—v1: Require the entire authenticated subject at root adoption.
    pub(crate) fn bind(
        &self,
        subject: &StartupEvidenceSubject,
        now: i64,
    ) -> Result<VerifiedStartupEvidence, StartupEvidenceError> {
        self.check_window(now)?;
        if &self.subject != subject {
            return Err(StartupEvidenceError::SubjectMismatch);
        }
        Ok(VerifiedStartupEvidence {
            trusted_time: now,
            envelope_digest: self.digest,
        })
    }
}

/// memory—v1: Canonical hash of the startup resource/action declarations.
/// The root separately validates the declarations before adopting any rules.
pub fn startup_registry_digest(declarations: &[RegistryDeclaration]) -> [u8; 32] {
    let mut ordered: Vec<_> = declarations
        .iter()
        .map(|entry| {
            let mut actions: Vec<_> = entry.actions.iter().map(String::as_str).collect();
            actions.sort_unstable();
            (entry.resource.as_str(), actions)
        })
        .collect();
    ordered.sort_unstable();
    let mut digest = Sha256::new().chain_update(b"astrallight/memory-v1/startup-registry/1\0");
    digest.update((ordered.len() as u64).to_be_bytes());
    for (resource, actions) in ordered {
        digest.update((resource.len() as u64).to_be_bytes());
        digest.update(resource.as_bytes());
        digest.update((actions.len() as u64).to_be_bytes());
        for action in actions {
            digest.update((action.len() as u64).to_be_bytes());
            digest.update(action.as_bytes());
        }
    }
    digest.finalize().into()
}

pub(crate) fn active_registry_digest(snapshot: &RegistrySnapshot) -> Option<[u8; 32]> {
    let declarations = snapshot
        .entries
        .iter()
        .map(|entry| {
            (entry.status == RegistryStatus::Active).then(|| RegistryDeclaration {
                resource: entry.resource.clone(),
                actions: entry.actions.clone(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(startup_registry_digest(&declarations))
}

#[cfg(test)]
mod tests;
