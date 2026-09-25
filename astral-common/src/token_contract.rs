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
pub const CHAT_WS_SUBPROTOCOL: &str = "astral-chat-v1";
pub const CHAT_WS_BEARER_SUBPROTOCOL_PREFIX: &str = "bearer.";

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
