//! Rust token v2 wire contract.
//!
//! This module owns token-purpose and identity-header contracts shared by
//! Gateway, Identity and Chat. Route credential classification
//! (`RouteCredentialPolicy` / `route_credential_policy`) is Gateway runtime
//! concern and now lives in `astral-gateway::middleware`.

use std::fmt;

pub const CLAIMS_VERSION: i32 = 2;
pub const ACCESS_TYP: &str = "astral-access+jwt";
pub const REFRESH_TYP: &str = "astral-refresh+jwt";
pub const ACCESS_AUDIENCE: &str = "astral-api";
pub const REFRESH_AUDIENCE: &str = "astral-session";

/// `auth_token_family.revoked_reason`, `auth_device_session.revoked_reason`,
/// outbox payloads, and audit rows all use this one bounded reason contract.
pub const MAX_REVOCATION_REASON_BYTES: usize = 256;

/// Canonicalize a user-supplied revocation reason once at the contract boundary.
/// Trimming is the only normalization: the original semantic text is preserved,
/// while control characters and oversized UTF-8 values are rejected.
pub fn normalize_revocation_reason(value: &str) -> Result<String, &'static str> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err("reason must not be empty");
    }
    if normalized.len() > MAX_REVOCATION_REASON_BYTES {
        return Err("reason exceeds the 256-byte limit");
    }
    if normalized.chars().any(char::is_control) {
        return Err("reason must not contain control characters");
    }
    Ok(normalized.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenUse {
    Access,
    Refresh,
}

impl TokenUse {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "ACCESS",
            Self::Refresh => "REFRESH",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ACCESS" => Some(Self::Access),
            "REFRESH" => Some(Self::Refresh),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalKind {
    PlatformUser,
    AppUser,
}

impl PrincipalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformUser => "PLATFORM_USER",
            Self::AppUser => "APP_USER",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "PLATFORM_USER" => Some(Self::PlatformUser),
            "APP_USER" => Some(Self::AppUser),
            _ => None,
        }
    }
}

impl fmt::Display for TokenUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const IDENTITY_CARD_ID_HEADER: &str = "x-identity-card-id";
pub const USER_CARD_ID_HEADER: &str = "x-user-card-id";
pub const USER_CARD_TENANT_ID_HEADER: &str = "x-user-card-tenant-id";
pub const USER_CARD_DOMAIN_ID_HEADER: &str = "x-user-card-domain-id";
pub const TOKEN_USE_HEADER: &str = "x-token-use";
pub const PRINCIPAL_KIND_HEADER: &str = "x-principal-kind";
pub const CLAIMS_VERSION_HEADER: &str = "x-claims-version";

#[cfg(test)]
mod tests {
    use super::{normalize_revocation_reason, MAX_REVOCATION_REASON_BYTES};

    #[test]
    fn revocation_reason_normalization_is_bounded_and_canonical() {
        assert_eq!(
            normalize_revocation_reason("  USER_REVOKED  ").unwrap(),
            "USER_REVOKED"
        );
        assert!(normalize_revocation_reason(" \t\n ").is_err());
        assert!(normalize_revocation_reason("reason\nwith-control").is_err());
        assert_eq!(
            normalize_revocation_reason(&"x".repeat(MAX_REVOCATION_REASON_BYTES))
                .unwrap()
                .len(),
            MAX_REVOCATION_REASON_BYTES
        );
        assert!(normalize_revocation_reason(&"x".repeat(MAX_REVOCATION_REASON_BYTES + 1)).is_err());
    }
}
