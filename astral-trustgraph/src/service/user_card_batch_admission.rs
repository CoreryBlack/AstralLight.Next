//! Fresh policy admission for one immutable, durable batch item.

use astral_types::{AstralError, AuthorityMutationKind, AuthorizationAdmission, PolicyContext};
use sha2::{Digest, Sha256};

use crate::AppState;

pub(crate) async fn abort_after_admission_drift(
    provider: &astral_db::SqlxAuthorizationFenceProvider,
    abort: &astral_db::SourceReservationAbort,
    drift: &str,
) -> AstralError {
    match provider.abort_source_reservation(abort).await {
        Ok(report) => {
            let outcome = format!("{:?}", report.outcome);
            let certainty = if matches!(
                &report.outcome,
                astral_db::SourceAbortOutcome::Aborted
                    | astral_db::SourceAbortOutcome::AlreadyAborted
            ) {
                "ABORT_PROVEN"
            } else if matches!(
                &report.outcome,
                astral_db::SourceAbortOutcome::Unknown
                    | astral_db::SourceAbortOutcome::RemoteNotFound
                    | astral_db::SourceAbortOutcome::NoLocalTombstone
            ) {
                "UNKNOWN"
            } else {
                "ABORT_REFUSED"
            };
            tracing::warn!(
                operation_id = %report.operation_id,
                reservation_id = %report.reservation_id,
                outcome = %outcome,
                certainty,
                drift,
                "batch item admission drift after source reservation"
            );
            AstralError::Pending(format!(
                "batch item admission drift after source reservation; stable-id abort {certainty}; operation_id={}; reservation_id={}; outcome={outcome}; drift={drift}",
                report.operation_id, report.reservation_id
            ))
        }
        Err(error) => {
            tracing::warn!(
                operation_id = %abort.operation_id,
                reservation_id = %abort.reservation_id,
                drift,
                error = %error,
                "batch item source reservation abort outcome unknown"
            );
            AstralError::Pending(format!(
                "batch item admission drift after source reservation; stable-id abort UNKNOWN; operation_id={}; reservation_id={}; drift={drift}; abort_error={error}",
                abort.operation_id, abort.reservation_id
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn admit_item(
    state: &AppState,
    parent: &PolicyContext,
    task_id: &str,
    operation_id: &str,
    card_id: i64,
    target_user_id: i64,
    tenant_id: i64,
    domain_id: i64,
) -> Result<(AuthorizationAdmission, astral_db::SourceReservationAbort), AstralError> {
    let mut context = item_context(parent, task_id, operation_id, card_id, target_user_id)?;
    let fence = match astral_db::memory_projection_hub() {
        Some(hub) => Some(hub.capture_authority_fence().ok_or_else(|| {
            AstralError::Pending("batch item host authority fence is unavailable".into())
        })?),
        None => None,
    };
    let path = format!("/user-cards/{card_id}/bind");
    let read_surface = astral_db::authorization_read_surface()
        .ok_or_else(|| AstralError::Pending("authorization read surface unavailable".into()))?;
    let read_request = read_surface.begin_request().map_err(|error| {
        AstralError::Pending(format!(
            "batch item certified-memory request token unavailable: {error}"
        ))
    })?;
    read_request
        .resolve_ownership(
            "domain",
            &path,
            "POST",
            None,
            context.card_id,
            context.user_id,
        )
        .await
        .apply_to(&mut context);
    if context.target_id != Some(card_id)
        || context.resource_tenant_id != Some(tenant_id)
        || context.resource_domain_id != Some(domain_id)
    {
        return Err(AstralError::Permission(
            "batch item ownership changed from its immutable registration".into(),
        ));
    }
    let (decision, admission) = read_request
        .evaluate_with_admission(&state.engine, &context)
        .await
        .into_parts();
    if !decision.allowed {
        return Err(AstralError::Permission(format!(
            "batch item policy refused: {}",
            decision.reason
        )));
    }
    let sod = read_request
        .check_sod(&context, &decision)
        .await
        .map_err(|error| AstralError::Pending(format!("batch item SoD unavailable: {error}")))?;
    if sod.has_conflict {
        return Err(AstralError::Permission(
            "batch item conflicts with separation of duties".into(),
        ));
    }
    read_request.ensure_current().map_err(|error| {
        AstralError::Pending(format!(
            "batch item certified-memory request token changed before reservation: {error}"
        ))
    })?;
    if fence.is_some_and(|fence| {
        !astral_db::memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(fence))
    }) {
        return Err(AstralError::Pending(
            "batch item host authority fence changed before reservation".into(),
        ));
    }
    read_request
        .ensure_mutation_commit_fence()
        .map_err(|error| AstralError::Pending(error.to_string()))?;
    let admission = admission
        .ok_or_else(|| AstralError::Pending("batch item has no fresh admission".into()))?;
    let provider = state
        .authorization_fence_provider
        .as_ref()
        .ok_or_else(|| AstralError::Pending("batch item authority provider unavailable".into()))?;
    let abort = provider
        .reserve_mutation_with_abort(&context, &admission)
        .await
        .map_err(|error| {
            AstralError::Pending(format!(
                "batch item source reservation not proven; operation_id={operation_id}; {error}"
            ))
        })?;

    let token_error = read_request.ensure_current().err();
    let fence_holds = fence.is_none_or(|captured| {
        astral_db::memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(captured))
    });
    if let Some(error) = token_error {
        return Err(abort_after_admission_drift(
            provider,
            &abort,
            &format!("request_token={error}"),
        )
        .await);
    }
    if !fence_holds {
        return Err(abort_after_admission_drift(provider, &abort, "authority_fence=changed").await);
    }
    Ok((admission, abort))
}

fn item_context(
    parent: &PolicyContext,
    task_id: &str,
    operation_id: &str,
    card_id: i64,
    target_user_id: i64,
) -> Result<PolicyContext, AstralError> {
    if parent.request_mutation_kind != Some(AuthorityMutationKind::ProtectedBusiness)
        || parent.resource.as_deref() != Some("domain")
        || parent.action != "update"
        || card_id <= 0
        || target_user_id <= 0
        || task_id.is_empty()
        || task_id.len() > 64
    {
        return Err(AstralError::Permission(
            "batch item lacks a verified registration context".into(),
        ));
    }
    astral_db::grant_ledger::validated_request_operation_id(Some(operation_id))?
        .ok_or_else(|| AstralError::Validation("batch item operation missing".into()))?;
    let parent_digest = astral_types::authorization_request_digest(parent)?;
    let payload = serde_json::json!({
        "parentRequestDigest": parent_digest, "taskId": task_id,
        "operationId": operation_id, "cardId": card_id, "targetUserId": target_user_id,
    });
    let mut hash = Sha256::new();
    hash.update(b"ASTRAL_CARD_BIND_ITEM_V7\0");
    hash.update(
        serde_json::to_vec(&payload).map_err(|error| AstralError::Validation(error.to_string()))?,
    );
    let mut context = parent.clone();
    context.request_operation_id = Some(operation_id.to_owned());
    context.request_mutation_kind = Some(AuthorityMutationKind::AuthorizationSource);
    context.request_fingerprint = Some(hex::encode(hash.finalize()));
    context.request = Some(payload);
    context.target_id = Some(card_id);
    context.resource_tenant_id = None;
    context.resource_domain_id = None;
    context.resource_owner_id = None;
    context.resource_ownership_scope = astral_types::ResourceOwnershipScope::Unresolved;
    context.global_access_requirement = Default::default();
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{AuthorizationDomainScope, AuthorizationFenceProof, AUTHORIZATION_EDITION};

    /// 中间件为该精确路由签发的父上下文：ProtectedBusiness + domain/update +
    /// 已由服务端 resolver 落定的所有权（digest 要求 resolved ownership）。
    fn registered_parent() -> PolicyContext {
        astral_types::PolicyContext::builder()
            .principal_kind(Some("PLATFORM_USER".into()))
            .user_id(Some(30))
            .identity_card_id(Some(6))
            .card_id(Some(20))
            .tenant_id(Some(10))
            .domain_id(Some(40))
            .resource(Some("domain".into()))
            .action("update".into())
            .request_operation_id(Some("req-uc-batch".into()))
            .request_mutation_kind(Some(AuthorityMutationKind::ProtectedBusiness))
            .request_fingerprint(Some("ab".repeat(32)))
            .resource_ownership_scope(astral_types::ResourceOwnershipScope::TenantScoped)
            .resource_tenant_id(Some(10))
            .resource_domain_id(Some(40))
            .build()
    }

    #[test]
    fn item_commit_fence_precedes_reservation() {
        let source = include_str!("user_card_batch_admission.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let gate = production.find(".ensure_mutation_commit_fence()").unwrap();
        let reservation = production
            .find(".reserve_mutation_with_abort(&context, &admission)")
            .unwrap();
        assert!(gate < reservation);
    }

    #[test]
    fn item_context_is_an_independent_authorization_source_anchored_to_its_registration() {
        let parent = registered_parent();
        let context = item_context(&parent, "uc_bind:t1", "batch-bind:item-1", 7, 500)
            .expect("registered parent must yield a valid item context");
        // 每 item 是独立 AuthorizationSource，operation 与 item 一致。
        assert_eq!(
            context.request_mutation_kind,
            Some(AuthorityMutationKind::AuthorizationSource)
        );
        assert_eq!(
            context.request_operation_id.as_deref(),
            Some("batch-bind:item-1")
        );
        assert_eq!(context.target_id, Some(7));
        // 所有权字段重置为 Unresolved：由 admit_item 的服务端 owner 解析重填。
        assert_eq!(
            context.resource_ownership_scope,
            astral_types::ResourceOwnershipScope::Unresolved
        );
        assert_eq!(context.resource_tenant_id, None);
        // item 指纹绑定父请求 digest + 不可变注册事实，且逐 item 不同。
        let other = item_context(&parent, "uc_bind:t1", "batch-bind:item-2", 8, 500).unwrap();
        assert_ne!(context.request_fingerprint, other.request_fingerprint);
        let same = item_context(&parent, "uc_bind:t1", "batch-bind:item-1", 7, 500).unwrap();
        assert_eq!(
            context.request_fingerprint, same.request_fingerprint,
            "the item context is immutable across retries of the same registration item"
        );
    }

    #[test]
    fn item_context_refuses_unregistered_parent_kinds_and_bad_identities() {
        let parent = registered_parent();
        // 未注册为 ProtectedBusiness 的父上下文不能派生 item。
        let mut business_less = parent.clone();
        business_less.request_mutation_kind = None;
        assert!(item_context(&business_less, "uc_bind:t1", "batch-bind:item-1", 7, 500).is_err());
        // AuthorizationSource 父上下文同样拒绝（防嵌套派生）。
        let mut source = parent.clone();
        source.request_mutation_kind = Some(AuthorityMutationKind::AuthorizationSource);
        assert!(item_context(&source, "uc_bind:t1", "batch-bind:item-1", 7, 500).is_err());
        // 非法身份/越界字段全部拒绝。
        assert!(item_context(&parent, "uc_bind:t1", "batch-bind:item-1", 0, 500).is_err());
        assert!(item_context(&parent, "uc_bind:t1", "batch-bind:item-1", 7, 0).is_err());
        assert!(item_context(&parent, "uc_bind:t1", "batch-bind:item-1", 7, 500).is_ok());
        assert!(item_context(&parent, "", "batch-bind:item-1", 7, 500).is_err());
        assert!(item_context(&parent, &"x".repeat(65), "batch-bind:item-1", 7, 500).is_err());
        assert!(item_context(&parent, "uc_bind:t1", "", 7, 500).is_err());
    }

    #[test]
    fn item_fingerprint_binds_the_parent_request_digest() {
        let parent = registered_parent();
        let mut forged = parent.clone();
        // 不同 actor 的注册请求不能派生同一 item 上下文（digest 含父请求）。
        forged.user_id = Some(31);
        let context = item_context(&parent, "uc_bind:t1", "batch-bind:item-1", 7, 500).unwrap();
        let forged_context =
            item_context(&forged, "uc_bind:t1", "batch-bind:item-1", 7, 500).unwrap();
        assert_ne!(
            context.request_fingerprint, forged_context.request_fingerprint,
            "the item digest must bind the parent request digest"
        );
    }

    /// 证明构造 sanity：测试 proof 仅为结构校验（与其它仓库测试合同一致）。
    #[test]
    fn structurally_valid_proof_builds_an_admission() {
        let proof = AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-test".into(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: astral_types::AuthorizationAuthorityScope {
                tenant_id: 10,
                card_id: 20,
                user_id: Some(30),
                domain: AuthorizationDomainScope::Exact(40),
            },
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "a".repeat(64),
            parent_hash: None,
            operation_id: "batch-bind:item-1".into(),
            event_id: "batch-bind:item-1:commit".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-batch-bind:item-1".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-batch-bind:item-1".into(),
            signature: "ab".repeat(64),
        };
        let admission = astral_types::AuthorizationAdmission::from_verified_proof(proof)
            .expect("structurally valid proof");
        assert_eq!(admission.operation_id(), "batch-bind:item-1");
    }
}
