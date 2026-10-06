//! Session checks bind a Gateway-authenticated token ID to fresh durable facts.

use astral_common::session_projection_store::AccessSessionDurableFact;
use astral_db::load_active_platform_access_session_fact;
use astral_types::PolicyContext;
use sqlx::MySqlPool;

pub(crate) async fn read_session(
    db: &MySqlPool,
    token_id: &str,
    ctx: &PolicyContext,
) -> Result<AccessSessionDurableFact, &'static str> {
    let identity_card_id = ctx.identity_card_id.ok_or("IDENTITY_REQUIRED")?;
    let fact = load_active_platform_access_session_fact(db, token_id, identity_card_id)
        .await
        .map_err(|_| "AUTHORIZATION_PENDING")?
        .ok_or("SESSION_INVALID")?;
    if !matches_context(&fact, ctx, time::OffsetDateTime::now_utc().unix_timestamp()) {
        return Err("SESSION_INVALID");
    }
    Ok(fact)
}

fn matches_context(fact: &AccessSessionDurableFact, ctx: &PolicyContext, now: i64) -> bool {
    ctx.principal_kind.as_deref() == Some("PLATFORM_USER")
        && ctx.user_id == Some(fact.user_id)
        && ctx.card_id == fact.current_user_card_id
        && ctx.tenant_id == fact.user_card_tenant_id
        && ctx.domain_id == fact.user_card_domain_id
        && fact.jti_status == "ACTIVE"
        && fact.session_status == "ACTIVE"
        && fact.session_state == "ACTIVE"
        && fact.family_status.as_deref() == Some("ACTIVE")
        && fact.user_card_status.as_deref() == Some("ACTIVE")
        && fact
            .jti_expires_at_epoch_second
            .is_some_and(|expiry| expiry > now)
        && fact.session_id > 0
        && fact.session_version > 0
        && fact.session_epoch > 0
        && fact.family_id > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_or_foreign_session_never_matches() {
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_id(Some(1))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(2))
            .tenant_id(Some(3))
            .domain_id(Some(4))
            .build();
        let mut fact = AccessSessionDurableFact {
            session_id: 5,
            user_id: 1,
            session_version: 1,
            session_epoch: 1,
            family_id: 6,
            current_user_card_id: Some(2),
            user_card_tenant_id: Some(3),
            user_card_domain_id: Some(4),
            jti_status: "ACTIVE".into(),
            session_status: "ACTIVE".into(),
            session_state: "ACTIVE".into(),
            family_status: Some("ACTIVE".into()),
            user_card_status: Some("ACTIVE".into()),
            jti_expires_at_epoch_second: Some(20),
        };
        assert!(matches_context(&fact, &ctx, 10));
        fact.user_id = 9;
        assert!(!matches_context(&fact, &ctx, 10));
        fact.user_id = 1;
        fact.jti_status = "REVOKED".into();
        assert!(!matches_context(&fact, &ctx, 10));
    }
}
