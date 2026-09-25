//! Chat 请求的物理双卡上下文。
//!
//! 问题 1 修正：identity_card 不承担组织归属，ChatScope 只保留身份卡 ID，
//! 租户/域上下文全部来自 user-card。

use astral_common::token_contract::{
    PrincipalKind, IDENTITY_CARD_ID_HEADER, PRINCIPAL_KIND_HEADER, TOKEN_USE_HEADER,
    USER_CARD_DOMAIN_ID_HEADER, USER_CARD_ID_HEADER, USER_CARD_TENANT_ID_HEADER,
};
use axum::http::HeaderMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChatScope {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub user_card_tenant_id: i64,
    pub user_card_domain_id: i64,
    pub principal_kind: PrincipalKind,
    pub token_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChatScopeKey {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub user_card_tenant_id: i64,
    pub user_card_domain_id: i64,
}

impl ChatScope {
    pub fn key(&self) -> ChatScopeKey {
        ChatScopeKey {
            user_id: self.user_id,
            identity_card_id: self.identity_card_id,
            user_card_id: self.user_card_id,
            user_card_tenant_id: self.user_card_tenant_id,
            user_card_domain_id: self.user_card_domain_id,
        }
    }

    pub fn for_recipient(&self, user_id: i64, identity_card_id: i64, user_card_id: i64) -> Self {
        Self {
            user_id,
            identity_card_id,
            user_card_id,
            token_id: String::new(),
            ..self.clone()
        }
    }

    pub fn connection_device_id(&self, device_id: Option<&str>) -> String {
        let device = device_id.unwrap_or("web-unknown");
        format!("{device}:{}", self.token_id)
    }

    fn positive(headers: &HeaderMap, name: &str) -> Option<i64> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
    }

    pub fn from_headers(headers: &HeaderMap) -> Result<Self, &'static str> {
        let verified = headers
            .get("x-gateway-auth")
            .and_then(|value| value.to_str().ok())
            == Some("verified");
        if !verified {
            return Err("Gateway verification required");
        }
        let principal_kind = headers
            .get(PRINCIPAL_KIND_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(PrincipalKind::parse)
            .ok_or("Missing principal kind")?;
        if principal_kind != PrincipalKind::PlatformUser {
            return Err("Platform user card required");
        }
        let user_id = Self::positive(headers, "x-user-id").ok_or("Missing user identity")?;
        let identity_card_id =
            Self::positive(headers, IDENTITY_CARD_ID_HEADER).ok_or("Missing identity card")?;
        let user_card_id =
            Self::positive(headers, USER_CARD_ID_HEADER).ok_or("Missing user card")?;
        let user_card_tenant_id = Self::positive(headers, USER_CARD_TENANT_ID_HEADER)
            .ok_or("Missing user card tenant")?;
        let user_card_domain_id = Self::positive(headers, USER_CARD_DOMAIN_ID_HEADER)
            .ok_or("Missing user card domain")?;
        let token_id = headers
            .get("x-token-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("Missing token identity")?
            .to_string();
        if headers
            .get(TOKEN_USE_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("ACCESS")
        {
            return Err("Access token required");
        }
        Ok(Self {
            user_id,
            identity_card_id,
            user_card_id,
            user_card_tenant_id,
            user_card_domain_id,
            principal_kind,
            token_id,
        })
    }
}
