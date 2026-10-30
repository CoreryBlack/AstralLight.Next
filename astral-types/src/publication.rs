//! Shared publication metadata contracts.
//!
//! These value types are deliberately independent of storage and runtime clocks.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

/// Digest-versioned record of the first whole-second timestamp at which a publication was sealed.
///
/// The timestamp is always stored in UTC and constrained to MySQL's `DATETIME`
/// calendar range. Serde uses a strict camelCase wire shape and accepts only the
/// canonical RFC3339 UTC representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationSeal {
    digest_version: u16,
    #[serde(with = "time::serde::rfc3339")]
    sealed_at: OffsetDateTime,
}

/// Errors returned when constructing or validating a publication seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PublicationSealError {
    #[error("publication seal timestamp must have whole-second precision")]
    SubsecondPrecision,

    #[error("publication seal timestamp is outside MySQL UTC DATETIME years 1000 through 9999")]
    OutOfRange,

    #[error("publication seal timestamp must use canonical RFC3339 UTC form")]
    NonCanonicalTimestamp,

    #[error("publication seal digest version {actual} is unsupported; expected {expected}")]
    UnsupportedDigestVersion { expected: u16, actual: u16 },
}

/// The only supported publication-seal digest version.
pub const DIGEST_VERSION: u16 = crate::AUTHORIZATION_EDITION;

const MYSQL_DATETIME_MIN_UNIX_SECONDS: i64 = -30_610_224_000;
const MYSQL_DATETIME_MAX_UNIX_SECONDS: i64 = 253_402_300_799;

impl PublicationSeal {
    /// The only supported publication-seal digest version.
    pub const DIGEST_VERSION: u16 = crate::publication::DIGEST_VERSION;

    /// Construct a seal from a UTC Unix timestamp in whole seconds.
    pub fn from_unix_seconds(unix_seconds: i64) -> Result<Self, PublicationSealError> {
        if !(MYSQL_DATETIME_MIN_UNIX_SECONDS..=MYSQL_DATETIME_MAX_UNIX_SECONDS)
            .contains(&unix_seconds)
        {
            return Err(PublicationSealError::OutOfRange);
        }

        let sealed_at = OffsetDateTime::from_unix_timestamp(unix_seconds)
            .map_err(|_| PublicationSealError::OutOfRange)?;
        Ok(Self {
            digest_version: Self::DIGEST_VERSION,
            sealed_at,
        })
    }

    /// Construct a seal after normalizing the supplied instant to UTC.
    ///
    /// Subsecond timestamps are rejected rather than truncated.
    pub fn new(sealed_at: OffsetDateTime) -> Result<Self, PublicationSealError> {
        if sealed_at.nanosecond() != 0 {
            return Err(PublicationSealError::SubsecondPrecision);
        }

        let sealed_at = sealed_at
            .checked_to_offset(UtcOffset::UTC)
            .ok_or(PublicationSealError::OutOfRange)?;
        if !(1000..=9999).contains(&sealed_at.year()) {
            return Err(PublicationSealError::OutOfRange);
        }

        Ok(Self {
            digest_version: Self::DIGEST_VERSION,
            sealed_at,
        })
    }

    /// Return the digest version carried by this seal.
    pub const fn digest_version(self) -> u16 {
        self.digest_version
    }

    /// Return the sealed timestamp, normalized to UTC.
    pub const fn sealed_at(self) -> OffsetDateTime {
        self.sealed_at
    }

    /// Return the sealed timestamp as UTC Unix seconds.
    pub const fn unix_seconds(self) -> i64 {
        self.sealed_at.unix_timestamp()
    }

    /// Validate the private-field invariants before using this seal as evidence.
    pub fn validate(self) -> Result<(), PublicationSealError> {
        if self.digest_version != Self::DIGEST_VERSION {
            return Err(PublicationSealError::UnsupportedDigestVersion {
                expected: Self::DIGEST_VERSION,
                actual: self.digest_version,
            });
        }
        if self.sealed_at.offset() != UtcOffset::UTC || self.sealed_at.nanosecond() != 0 {
            return Err(PublicationSealError::NonCanonicalTimestamp);
        }
        if !(1000..=9999).contains(&self.sealed_at.year()) {
            return Err(PublicationSealError::OutOfRange);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationSealWire {
    digest_version: u16,
    sealed_at: String,
}

impl<'de> Deserialize<'de> for PublicationSeal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PublicationSealWire::deserialize(deserializer)?;
        if wire.digest_version != Self::DIGEST_VERSION {
            return Err(D::Error::custom(
                PublicationSealError::UnsupportedDigestVersion {
                    expected: Self::DIGEST_VERSION,
                    actual: wire.digest_version,
                },
            ));
        }

        let parsed = OffsetDateTime::parse(&wire.sealed_at, &Rfc3339)
            .map_err(|_| D::Error::custom(PublicationSealError::NonCanonicalTimestamp))?;
        if parsed.offset() != UtcOffset::UTC {
            return Err(D::Error::custom(
                PublicationSealError::NonCanonicalTimestamp,
            ));
        }
        if parsed.nanosecond() != 0 {
            return Err(D::Error::custom(PublicationSealError::SubsecondPrecision));
        }

        let seal = Self::new(parsed).map_err(D::Error::custom)?;
        let canonical = seal
            .sealed_at
            .format(&Rfc3339)
            .map_err(|_| D::Error::custom(PublicationSealError::NonCanonicalTimestamp))?;
        if canonical != wire.sealed_at {
            return Err(D::Error::custom(
                PublicationSealError::NonCanonicalTimestamp,
            ));
        }
        Ok(seal)
    }
}

/// Compact identity of one sealed publication; it never carries rule entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "PublicationStampWire")]
pub struct PublicationStamp {
    pub generation: u64,
    pub manifest_digest_hex: String,
    pub seal: PublicationSeal,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PublicationStampError {
    #[error("publication generation must be positive and fit the SQL BIGINT range")]
    InvalidGeneration,
    #[error("manifest digest must be a lowercase 64-character SHA-256 hex digest")]
    InvalidManifestDigest,
    #[error(transparent)]
    InvalidSeal(#[from] PublicationSealError),
}

impl PublicationStamp {
    pub fn new(
        generation: u64,
        manifest_digest_hex: String,
        seal: PublicationSeal,
    ) -> Result<Self, PublicationStampError> {
        let value = Self {
            generation,
            manifest_digest_hex,
            seal,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PublicationStampError> {
        if self.generation == 0 || self.generation > i64::MAX as u64 {
            return Err(PublicationStampError::InvalidGeneration);
        }
        if self.manifest_digest_hex.len() != 64
            || !self
                .manifest_digest_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PublicationStampError::InvalidManifestDigest);
        }
        self.seal.validate()?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationStampWire {
    generation: u64,
    manifest_digest_hex: String,
    seal: PublicationSeal,
}

impl TryFrom<PublicationStampWire> for PublicationStamp {
    type Error = PublicationStampError;

    fn try_from(value: PublicationStampWire) -> Result<Self, Self::Error> {
        Self::new(value.generation, value.manifest_digest_hex, value.seal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_UNIX_SECONDS: i64 = 1_700_000_000;

    #[test]
    fn publication_stamp_requires_all_three_identity_dimensions() {
        let seal = PublicationSeal::from_unix_seconds(FIXTURE_UNIX_SECONDS).unwrap();
        let stamp = PublicationStamp::new(7, "ab".repeat(32), seal).unwrap();
        let wire = serde_json::to_value(&stamp).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 3);
        assert_eq!(wire["generation"], 7);
        assert_eq!(wire["manifestDigestHex"], "ab".repeat(32));
        assert_eq!(wire["seal"]["digestVersion"], crate::AUTHORIZATION_EDITION);
        assert_eq!(wire["seal"]["sealedAt"], "2023-11-14T22:13:20Z");
        assert_eq!(
            serde_json::from_value::<PublicationStamp>(wire.clone()).unwrap(),
            stamp
        );
        for field in ["generation", "manifestDigestHex", "seal"] {
            let mut incomplete = wire.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<PublicationStamp>(incomplete).is_err());
        }
        let mut with_entries = wire.clone();
        with_entries["entries"] = serde_json::json!([]);
        assert!(serde_json::from_value::<PublicationStamp>(with_entries).is_err());
        for generation in [0, i64::MAX as u64 + 1] {
            let mut invalid = wire.clone();
            invalid["generation"] = serde_json::json!(generation);
            assert!(serde_json::from_value::<PublicationStamp>(invalid).is_err());
        }
        for digest in ["AB".repeat(32), "g".repeat(64), "ab".repeat(31)] {
            let mut invalid = wire.clone();
            invalid["manifestDigestHex"] = serde_json::json!(digest);
            assert!(serde_json::from_value::<PublicationStamp>(invalid).is_err());
        }
    }

    #[test]
    fn same_generation_hash_or_timestamp_drift_changes_publication_identity() {
        let seal = PublicationSeal::from_unix_seconds(FIXTURE_UNIX_SECONDS).unwrap();
        let base = PublicationStamp::new(7, "ab".repeat(32), seal).unwrap();
        let mut next = base.clone();
        next.generation += 1;
        assert_ne!(base, next);
        next = base.clone();
        next.manifest_digest_hex = "cd".repeat(32);
        assert_ne!(base, next);
        next = base.clone();
        next.seal = PublicationSeal::from_unix_seconds(FIXTURE_UNIX_SECONDS + 1).unwrap();
        assert_ne!(base, next);
    }

    #[test]
    fn constructors_enforce_mysql_utc_range_and_whole_seconds() {
        let seal = PublicationSeal::from_unix_seconds(FIXTURE_UNIX_SECONDS).unwrap();
        assert_eq!(seal.digest_version(), PublicationSeal::DIGEST_VERSION);
        assert_eq!(seal.unix_seconds(), FIXTURE_UNIX_SECONDS);
        assert_eq!(seal.sealed_at().offset(), UtcOffset::UTC);
        assert_eq!(
            PublicationSeal::from_unix_seconds(MYSQL_DATETIME_MIN_UNIX_SECONDS)
                .unwrap()
                .sealed_at()
                .year(),
            1000
        );
        assert_eq!(
            PublicationSeal::from_unix_seconds(MYSQL_DATETIME_MAX_UNIX_SECONDS)
                .unwrap()
                .sealed_at()
                .year(),
            9999
        );
        assert_eq!(
            PublicationSeal::from_unix_seconds(MYSQL_DATETIME_MIN_UNIX_SECONDS - 1),
            Err(PublicationSealError::OutOfRange)
        );
        assert_eq!(
            PublicationSeal::from_unix_seconds(MYSQL_DATETIME_MAX_UNIX_SECONDS + 1),
            Err(PublicationSealError::OutOfRange)
        );
        let with_subseconds = OffsetDateTime::from_unix_timestamp_nanos(
            (FIXTURE_UNIX_SECONDS as i128) * 1_000_000_000 + 1,
        )
        .unwrap();
        assert_eq!(
            PublicationSeal::new(with_subseconds),
            Err(PublicationSealError::SubsecondPrecision)
        );
    }

    #[test]
    fn new_normalizes_offsets_to_utc_without_changing_the_instant() {
        let local = OffsetDateTime::from_unix_timestamp(FIXTURE_UNIX_SECONDS)
            .unwrap()
            .to_offset(UtcOffset::from_hms(1, 0, 0).unwrap());
        let seal = PublicationSeal::new(local).unwrap();
        assert_eq!(seal.sealed_at().offset(), UtcOffset::UTC);
        assert_eq!(seal.unix_seconds(), FIXTURE_UNIX_SECONDS);
    }

    #[test]
    fn serde_uses_a_strict_current_edition_utc_shape() {
        let seal = PublicationSeal::from_unix_seconds(FIXTURE_UNIX_SECONDS).unwrap();
        let encoded = serde_json::to_string(&seal).unwrap();
        assert_eq!(
            encoded,
            format!(
                r#"{{"digestVersion":{},"sealedAt":"2023-11-14T22:13:20Z"}}"#,
                crate::AUTHORIZATION_EDITION
            )
        );
        assert_eq!(
            serde_json::from_str::<PublicationSeal>(&encoded).unwrap(),
            seal
        );

        for version in (0..crate::AUTHORIZATION_EDITION)
            .chain(std::iter::once(crate::AUTHORIZATION_EDITION + 1))
        {
            let wire = serde_json::json!({
                "digestVersion": version,
                "sealedAt": "2023-11-14T22:13:20Z"
            });
            assert!(serde_json::from_value::<PublicationSeal>(wire).is_err());
        }
        let mut missing_version = serde_json::to_value(seal).unwrap();
        missing_version
            .as_object_mut()
            .unwrap()
            .remove("digestVersion");
        assert!(serde_json::from_value::<PublicationSeal>(missing_version).is_err());
        let mut extra = serde_json::to_value(seal).unwrap();
        extra["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PublicationSeal>(extra).is_err());
        for timestamp in [
            "2023-11-14T22:13:20+00:00",
            "2023-11-14T23:13:20+01:00",
            "2023-11-14T22:13:20.0Z",
            "1000-01-01T00:00:00.1Z",
            "0999-12-31T23:59:59Z",
            "10000-01-01T00:00:00Z",
        ] {
            let wire = serde_json::json!({
                "digestVersion": crate::AUTHORIZATION_EDITION,
                "sealedAt": timestamp
            });
            assert!(
                serde_json::from_value::<PublicationSeal>(wire).is_err(),
                "{timestamp}"
            );
        }
    }
}
