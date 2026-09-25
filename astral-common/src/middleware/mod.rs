//! 共享 Tower 中间件
//!
//! - `decode_v2_token` / `JwtClaims` — v2 JWT 解码与 claims 结构（Identity 与 Gateway 共享）
//! - `require_permission` — 权限检查工具函数
//! - `tenant_filter` — SQLx 自动 tenant_id 过滤工具（SQL 重写 + TenantScopedQuery）
//!
//! Gateway 专属运行时（`sanitize_internal_auth_headers`、`jwt_auth_middleware`、
//! 速率限制、路由凭证策略）已迁移至 `astral-gateway`。

pub mod gateway_signature;
pub mod internal_signature;
pub mod permission;
pub mod permission_check_shared;
pub mod tenant_context;
pub mod tenant_filter;

use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, JwtTokenProfile};
use crate::token_contract::{PrincipalKind, TokenUse, ACCESS_TYP, CLAIMS_VERSION, REFRESH_TYP};

fn jwt_algorithm(algorithm: &str) -> Option<jsonwebtoken::Algorithm> {
    match algorithm {
        "HS256" => Some(jsonwebtoken::Algorithm::HS256),
        "RS256" => Some(jsonwebtoken::Algorithm::RS256),
        _ => None,
    }
}

fn validate_v2_claims(claims: &JwtClaims, token_use: TokenUse) -> Result<(), &'static str> {
    if claims.claims_version != CLAIMS_VERSION {
        return Err("CLAIMS_VERSION_INVALID");
    }
    if claims.jti.trim().is_empty() {
        return Err("TOKEN_ID_REQUIRED");
    }
    if TokenUse::parse(&claims.token_use) != Some(token_use) {
        return Err("TOKEN_USE_INVALID");
    }
    if PrincipalKind::parse(&claims.principal_kind).is_none() {
        return Err("PRINCIPAL_KIND_INVALID");
    }
    if claims.sid.is_none_or(|value| value <= 0)
        || claims.family_id.is_none_or(|value| value <= 0)
        || claims.session_version.is_none_or(|value| value <= 0)
        || claims.sev.is_none_or(|value| value <= 0)
    {
        return Err("SESSION_CONTEXT_INVALID");
    }
    Ok(())
}

fn validated_access_claims(claims: &JwtClaims) -> Result<(), &'static str> {
    validate_v2_claims(claims, TokenUse::Access)?;
    if claims.issuer.trim().is_empty() || claims.audience.trim().is_empty() {
        return Err("TOKEN_PROFILE_INVALID");
    }
    if claims.identity_card_id.is_none_or(|value| value <= 0) {
        return Err("IDENTITY_CONTEXT_REQUIRED");
    }
    match PrincipalKind::parse(&claims.principal_kind) {
        Some(PrincipalKind::PlatformUser) => {
            if claims.user_card_id.is_none()
                || claims.user_card_tenant_id.is_none()
                || claims.user_card_domain_id.is_none()
            {
                return Err("USER_CARD_CONTEXT_REQUIRED");
            }
            if claims.user_card_id.is_some_and(|value| value <= 0)
                || claims.user_card_tenant_id.is_some_and(|value| value <= 0)
                || claims.user_card_domain_id.is_some_and(|value| value <= 0)
            {
                return Err("USER_CARD_CONTEXT_INVALID");
            }
        }
        Some(PrincipalKind::AppUser) => {
            if claims.user_card_id.is_some()
                || claims.user_card_tenant_id.is_some()
                || claims.user_card_domain_id.is_some()
            {
                return Err("APP_USER_CARD_CONTEXT_FORBIDDEN");
            }
        }
        None => return Err("PRINCIPAL_KIND_INVALID"),
    }
    Ok(())
}

fn validated_refresh_claims(claims: &JwtClaims) -> Result<(), &'static str> {
    validate_v2_claims(claims, TokenUse::Refresh)?;
    if PrincipalKind::parse(&claims.principal_kind).is_none()
        || claims.identity_card_id.is_some()
        || claims.user_card_id.is_some()
        || claims.user_card_tenant_id.is_some()
        || claims.user_card_domain_id.is_some()
        || claims.template_id.is_some()
        || claims.structure_node_id.is_some()
        || claims.tenant_status.is_some()
        || claims.permissions.is_some()
        || !claims.roles.is_empty()
    {
        return Err("REFRESH_AUTHORIZATION_CONTEXT_FORBIDDEN");
    }
    Ok(())
}

fn profile_for_token(config: &AppConfig, token_type: TokenUse) -> &JwtTokenProfile {
    match token_type {
        TokenUse::Access => &config.jwt.access,
        TokenUse::Refresh => &config.jwt.refresh,
    }
}

pub fn decode_v2_token(
    token: &str,
    config: &AppConfig,
) -> Result<(JwtClaims, TokenUse), &'static str> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| "TOKEN_HEADER_INVALID")?;
    let token_type = match header.typ.as_deref() {
        Some(ACCESS_TYP) => TokenUse::Access,
        Some(REFRESH_TYP) => TokenUse::Refresh,
        _ => return Err("TOKEN_TYPE_INVALID"),
    };
    let profile = profile_for_token(config, token_type);
    if header.kid.as_deref() != Some(profile.kid.as_str()) {
        return Err("TOKEN_KEY_ID_INVALID");
    }
    let algorithm = jwt_algorithm(&profile.algorithm).ok_or("TOKEN_ALGORITHM_INVALID")?;
    if header.alg != algorithm {
        return Err("TOKEN_ALGORITHM_INVALID");
    }
    let decoding_key = match algorithm {
        jsonwebtoken::Algorithm::HS256 => DecodingKey::from_secret(profile.secret.as_bytes()),
        jsonwebtoken::Algorithm::RS256 => {
            let path = profile
                .rsa_public_key_path
                .as_deref()
                .ok_or("TOKEN_KEY_UNAVAILABLE")?;
            let pem = std::fs::read(path).map_err(|_| "TOKEN_KEY_UNAVAILABLE")?;
            DecodingKey::from_rsa_pem(&pem).map_err(|_| "TOKEN_KEY_INVALID")?
        }
        _ => return Err("TOKEN_ALGORITHM_INVALID"),
    };
    let mut validation = Validation::new(algorithm);
    validation.algorithms = vec![algorithm];
    validation.leeway = 0;
    validation.set_issuer(&[profile.issuer.as_str()]);
    validation.set_audience(&[profile.audience.as_str()]);
    let claims = decode::<JwtClaims>(token, &decoding_key, &validation)
        .map_err(|_| "TOKEN_INVALID")?
        .claims;
    match token_type {
        TokenUse::Access => validated_access_claims(&claims)?,
        TokenUse::Refresh => validated_refresh_claims(&claims)?,
    }
    Ok((claims, token_type))
}

fn deserialize_roles<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(value) => Ok(value
            .split(',')
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .map(ToOwned::to_owned)
            .collect()),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| serde::de::Error::custom("roles must contain strings"))
            })
            .collect(),
        serde_json::Value::Null => Ok(Vec::new()),
        _ => Err(serde::de::Error::custom("roles must be a string or array")),
    }
}

/// JWT Claims v2 shared by Gateway and Rust Identity.
///
/// The non-default version/profile fields intentionally make legacy JWTs fail
/// deserialization instead of silently entering the v2 verifier.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtClaims {
    #[serde(rename = "claimsVersion")]
    pub claims_version: i32,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    pub sub: String,
    pub jti: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_roles"
    )]
    pub roles: Vec<String>,
    #[serde(rename = "tokenUse")]
    pub token_use: String,
    #[serde(rename = "principalKind")]
    pub principal_kind: String,
    #[serde(rename = "identityCardId", skip_serializing_if = "Option::is_none")]
    pub identity_card_id: Option<i64>,
    #[serde(rename = "userCardId", skip_serializing_if = "Option::is_none")]
    pub user_card_id: Option<i64>,
    #[serde(rename = "userCardTenantId", skip_serializing_if = "Option::is_none")]
    pub user_card_tenant_id: Option<i64>,
    #[serde(rename = "userCardDomainId", skip_serializing_if = "Option::is_none")]
    pub user_card_domain_id: Option<i64>,
    #[serde(rename = "templateId", skip_serializing_if = "Option::is_none")]
    pub template_id: Option<i64>,
    #[serde(rename = "structureNodeId", skip_serializing_if = "Option::is_none")]
    pub structure_node_id: Option<i64>,
    #[serde(rename = "tenantStatus", skip_serializing_if = "Option::is_none")]
    pub tenant_status: Option<String>,
    /// Deprecated in the v2 wire contract; retained internally only for the
    /// permission response path and never populated on REFRESH tokens.
    #[serde(default, skip_serializing)]
    pub permissions: Option<Vec<String>>,
    #[serde(rename = "sid")]
    pub sid: Option<i64>,
    #[serde(rename = "sessionVersion")]
    pub session_version: Option<i64>,
    #[serde(rename = "sessionEpoch")]
    pub sev: Option<i64>,
    #[serde(rename = "familyId")]
    pub family_id: Option<i64>,
    pub exp: usize,
    pub iat: usize,
    pub nbf: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_algorithm_rejects_everything_except_supported_algorithms() {
        assert_eq!(jwt_algorithm("HS256"), Some(jsonwebtoken::Algorithm::HS256));
        assert_eq!(jwt_algorithm("RS256"), Some(jsonwebtoken::Algorithm::RS256));
        assert_eq!(jwt_algorithm("HS512"), None);
        assert_eq!(jwt_algorithm("none"), None);
    }

    fn claims(sub: &str) -> JwtClaims {
        JwtClaims {
            claims_version: CLAIMS_VERSION,
            issuer: "identity".into(),
            audience: "astral-api".into(),
            sub: sub.into(),
            jti: "jti".into(),
            roles: vec![],
            token_use: "ACCESS".into(),
            principal_kind: "PLATFORM_USER".into(),
            identity_card_id: Some(10),
            user_card_id: Some(40),
            user_card_tenant_id: Some(20),
            user_card_domain_id: Some(30),
            template_id: None,
            structure_node_id: None,
            tenant_status: None,
            permissions: None,
            sid: Some(1),
            session_version: Some(1),
            sev: Some(1),
            family_id: Some(1),
            exp: usize::MAX,
            iat: 0,
            nbf: 0,
        }
    }

    #[test]
    fn validated_access_claims_accept_identity_only_app_user() {
        let mut claims = claims("42");
        claims.principal_kind = "APP_USER".into();
        claims.user_card_id = None;
        claims.user_card_tenant_id = None;
        claims.user_card_domain_id = None;
        assert!(validated_access_claims(&claims).is_ok());
    }

    #[test]
    fn validated_access_claims_reject_app_user_card_context() {
        for (label, user_card_id, user_card_domain_id, user_card_tenant_id) in [
            ("id", Some(40), None, None),
            ("domain", None, Some(30), None),
            ("tenant", None, None, Some(20)),
            ("all", Some(40), Some(30), Some(20)),
        ] {
            let mut claims = claims("42");
            claims.principal_kind = "APP_USER".into();
            claims.user_card_id = user_card_id;
            claims.user_card_domain_id = user_card_domain_id;
            claims.user_card_tenant_id = user_card_tenant_id;
            assert_eq!(
                validated_access_claims(&claims),
                Err("APP_USER_CARD_CONTEXT_FORBIDDEN"),
                "APP_USER user-card context must be rejected: {label}"
            );
        }
    }

    #[test]
    fn validated_access_claims_require_access_token_and_jti() {
        assert!(validated_access_claims(&claims("42")).is_ok());
        let mut refresh = claims("42");
        refresh.token_use = "REFRESH".into();
        assert_eq!(validated_access_claims(&refresh), Err("TOKEN_USE_INVALID"));
        let mut missing_jti = claims("42");
        missing_jti.jti.clear();
        assert_eq!(
            validated_access_claims(&missing_jti),
            Err("TOKEN_ID_REQUIRED")
        );
    }
}
