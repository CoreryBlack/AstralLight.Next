//! Experimental memory-v1 rule-set tuple and byte-integrity check.
//!
//! This isolated candidate is not connected to an authorization reader or writer.
//! Its SHA-256 encoding is an experiment, not a protocol or persistence format.
//! Version, content and timestamp are opaque caller-supplied bytes: this module
//! assigns them no ordering, time, rule-language, tenant or confirmation semantics.
//! In particular, receiving content bytes does not prove that content was loaded
//! completely. An empty byte string is a value, never a marker for missing input.
//!
//! The digest covers only the three fields below. It cannot establish provenance,
//! authorization, confirmation, completeness, freshness or durability, and does
//! not protect external identity, ownership, or other metadata. Do not use it as
//! evidence for an authorization decision or as a production wire format.

use sha2::{Digest, Sha256};

// The suffix identifies only this experimental encoding, not a business version.
const DOMAIN: &[u8] = b"astrallight/memory-v1/experimental-rule-set/1\0";
// An allocation and hashing budget for this experiment, not a business limit.
const MAX_FIELD_BYTES: usize = 16 * 1024 * 1024;

/// Failure to construct or check an experimental tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSetIntegrityError {
    /// A field exceeds this experiment's byte budget or cannot be length encoded.
    FieldTooLarge,
    /// The supplied digest does not match the three supplied fields.
    DigestMismatch,
}

/// Immutable candidate tuple; its fields have no authorization semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentalRuleSet {
    version: Vec<u8>,
    content: Vec<u8>,
    timestamp: Vec<u8>,
    hash: [u8; 32],
}

impl ExperimentalRuleSet {
    /// memory—v1: Compute the experimental digest for three opaque fields.
    ///
    /// The caller must supply all three fields; empty content is distinct from an
    /// absent or not-yet-loaded field, which this constructor cannot represent.
    pub fn new(
        version: Vec<u8>,
        content: Vec<u8>,
        timestamp: Vec<u8>,
    ) -> Result<Self, RuleSetIntegrityError> {
        let hash = experimental_digest(&version, &content, &timestamp)?;
        Ok(Self {
            version,
            content,
            timestamp,
            hash,
        })
    }

    /// memory—v1: Accept external fields only if their experimental digest matches.
    ///
    /// A matching digest proves only this encoding's byte relationship; callers
    /// must independently establish the origin and completeness of the fields.
    pub fn from_parts(
        version: Vec<u8>,
        content: Vec<u8>,
        timestamp: Vec<u8>,
        hash: [u8; 32],
    ) -> Result<Self, RuleSetIntegrityError> {
        let expected = experimental_digest(&version, &content, &timestamp)?;
        if expected != hash {
            return Err(RuleSetIntegrityError::DigestMismatch);
        }
        Ok(Self {
            version,
            content,
            timestamp,
            hash,
        })
    }

    /// memory—v1: Return the opaque version bytes.
    pub fn version(&self) -> &[u8] {
        &self.version
    }

    /// memory—v1: Return the supplied content bytes without interpreting them.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// memory—v1: Return the opaque timestamp bytes.
    pub fn timestamp(&self) -> &[u8] {
        &self.timestamp
    }

    /// memory—v1: Return this candidate's experimental SHA-256 digest.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// memory—v1: Recheck the stored fields against the stored digest.
    pub fn verify(&self) -> Result<(), RuleSetIntegrityError> {
        if experimental_digest(&self.version, &self.content, &self.timestamp)? != self.hash {
            return Err(RuleSetIntegrityError::DigestMismatch);
        }
        Ok(())
    }
}

// memory—v1: Hash domain || len(version) || version || len(content) || content
// || len(timestamp) || timestamp, with each length encoded as a big-endian u64.
// Fields are hashed exactly as supplied; no semantic normalization is performed.
fn experimental_digest(
    version: &[u8],
    content: &[u8],
    timestamp: &[u8],
) -> Result<[u8; 32], RuleSetIntegrityError> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for field in [version, content, timestamp] {
        if field.len() > MAX_FIELD_BYTES {
            return Err(RuleSetIntegrityError::FieldTooLarge);
        }
        let length =
            u64::try_from(field.len()).map_err(|_| RuleSetIntegrityError::FieldTooLarge)?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1: Construct a repeatable opaque test tuple.
    fn sample() -> ExperimentalRuleSet {
        ExperimentalRuleSet::new(b"v1".to_vec(), b"rules".to_vec(), b"t1".to_vec()).unwrap()
    }

    #[test]
    // memory—v1: Verify the precise experimental frame independently of the encoder.
    fn encoding_matches_explicit_frame() {
        let tuple = sample();
        let frame = b"astrallight/memory-v1/experimental-rule-set/1\0\
\x00\x00\x00\x00\x00\x00\x00\x02v1\
\x00\x00\x00\x00\x00\x00\x00\x05rules\
\x00\x00\x00\x00\x00\x00\x00\x02t1";
        assert_eq!(tuple.hash().as_slice(), Sha256::digest(frame).as_slice());
        assert_eq!(tuple.verify(), Ok(()));
        assert_eq!(sample(), tuple);
    }

    #[test]
    // memory—v1: Detect changes to every field and the supplied digest.
    fn rejects_modified_parts() {
        let tuple = sample();
        let digest = *tuple.hash();
        for (version, content, timestamp) in [
            (b"v2".as_slice(), b"rules".as_slice(), b"t1".as_slice()),
            (b"v1".as_slice(), b"ruleS".as_slice(), b"t1".as_slice()),
            (b"v1".as_slice(), b"rules".as_slice(), b"t2".as_slice()),
        ] {
            assert_eq!(
                ExperimentalRuleSet::from_parts(
                    version.to_vec(),
                    content.to_vec(),
                    timestamp.to_vec(),
                    digest,
                ),
                Err(RuleSetIntegrityError::DigestMismatch)
            );
        }
        let mut changed = digest;
        changed[0] ^= 1;
        assert_eq!(
            ExperimentalRuleSet::from_parts(
                tuple.version().to_vec(),
                tuple.content().to_vec(),
                tuple.timestamp().to_vec(),
                changed,
            ),
            Err(RuleSetIntegrityError::DigestMismatch)
        );
        assert_eq!(
            ExperimentalRuleSet::from_parts(
                tuple.version().to_vec(),
                tuple.content().to_vec(),
                tuple.timestamp().to_vec(),
                digest,
            ),
            Ok(tuple)
        );
    }

    #[test]
    // memory—v1: Length prefixes distinguish otherwise ambiguous concatenations.
    fn distinguishes_field_boundaries_and_empty_content() {
        let first = ExperimentalRuleSet::new(b"ab".to_vec(), b"c".to_vec(), vec![]).unwrap();
        let second = ExperimentalRuleSet::new(b"a".to_vec(), b"bc".to_vec(), vec![]).unwrap();
        let empty = ExperimentalRuleSet::new(b"a".to_vec(), vec![], b"bc".to_vec()).unwrap();
        assert_ne!(first.hash(), second.hash());
        assert_ne!(second.hash(), empty.hash());
        assert_eq!(empty.content(), b"");
        assert_eq!(empty.verify(), Ok(()));
    }

    #[test]
    // memory—v1: Enforce the experimental field limit at both entry points.
    fn rejects_oversized_fields() {
        let too_large = vec![0; MAX_FIELD_BYTES + 1];
        for position in 0..3 {
            let mut fields = [Vec::new(), Vec::new(), Vec::new()];
            fields[position] = too_large.clone();
            let [version, content, timestamp] = fields;
            assert_eq!(
                ExperimentalRuleSet::new(version.clone(), content.clone(), timestamp.clone()),
                Err(RuleSetIntegrityError::FieldTooLarge)
            );
            assert_eq!(
                ExperimentalRuleSet::from_parts(version, content, timestamp, [0; 32]),
                Err(RuleSetIntegrityError::FieldTooLarge)
            );
        }
        assert!(ExperimentalRuleSet::new(vec![], vec![0; MAX_FIELD_BYTES], vec![]).is_ok());
    }
}
