//! 用户卡编排 — UserCardService
//!
//! create/restore/bind 的 durable 投影事件编排；delete 级联事务在 repository。
//! delete 后 post-commit evict 对齐 Java 语义。

use std::sync::Arc;

use astral_types::{AstralError, AuthorizationAdmission};

use crate::repository::authorization_source_transaction::CommittedProjectionReceipts;
use crate::repository::user_card_repository::{
    DeleteCascadeResult, NewUserCard, UserCardPatch, UserCardRecord, UserCardRepository,
};
/// UserCardService
pub struct UserCardService {
    repo: Arc<dyn UserCardRepository>,
}

impl UserCardService {
    pub fn new(repo: Arc<dyn UserCardRepository>) -> Self {
        Self { repo }
    }

    /// 创建卡（含模板规则集绑定）→ 落 durable 投影事件，返回卡
    pub async fn create_card(
        &self,
        new: &NewUserCard,
        admission: AuthorizationAdmission,
    ) -> Result<UserCardRecord, AstralError> {
        let new_id = self.repo.create_card(new, admission).await?;
        let row = self.repo.get_card(new_id).await?.ok_or_else(|| {
            AstralError::Database(format!("user_card {new_id} not found after insert"))
        })?;
        tracing::info!(card_id = new_id, user_id = ?new.user_id, "user card created");
        Ok(row)
    }

    /// 更新卡（部分字段）
    ///
    /// 状态变更（禁用/挂起等离开 ACTIVE）是对有效授权的 source mutation：
    /// 落 durable 投影事件（REVOKE 语义，围栏递增）+ 清理 `perm:card:active` 缓存，
    /// 否则 `check_card_active` 正缓存命中会放行最长 ~300s（对齐 Java 用户卡状态回收）。
    pub async fn update_card(
        &self,
        card_id: i64,
        patch: &UserCardPatch,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        self.repo.update_card(card_id, patch, admission).await?;
        // Repository 已将 source mutation 与 projection append 放入同一事务。
        // 这里仅清理运行时状态缓存，不再重复追加 head/outbox 事件。
        astral_db::evict_l1_card_active_cache(card_id);
        Ok(())
    }

    /// 删除卡（级联事务）→ post-commit evict 缓存 + 落 durable 投影事件（对齐 Java evictCardCache）
    pub async fn delete_card(
        &self,
        card_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<DeleteCascadeResult, AstralError> {
        let result = self.repo.delete_with_cascade(card_id, admission).await?;
        astral_db::evict_l1_card_active_cache(card_id);
        tracing::warn!(
            card_id,
            permission_rule_deleted = result.permission_rule_deleted,
            snapshot_deleted = result.snapshot_deleted,
            rule_set_ref_deleted = result.rule_set_ref_deleted,
            "user card deleted (soft) + cascade cleanup"
        );
        Ok(result)
    }

    /// 恢复已删除卡 → 落 durable 投影事件
    pub async fn restore_card(
        &self,
        card_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<UserCardRecord, AstralError> {
        let restored = self.repo.restore_card(card_id, admission).await?;
        if !restored {
            return Err(AstralError::NotFound(format!(
                "user_card {card_id} (not found or not in DISABLED status)"
            )));
        }
        let row = self.repo.get_card(card_id).await?.ok_or_else(|| {
            AstralError::Database(format!("user_card {card_id} not found after restore"))
        })?;
        tracing::info!(card_id, "user card restored");
        Ok(row)
    }

    /// 绑定单卡 → 落 durable 投影事件
    pub async fn bind_card(
        &self,
        card_id: i64,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<UserCardRecord, AstralError> {
        let bound = self.repo.bind_card(card_id, user_id, admission).await?;
        if !bound {
            return Err(AstralError::NotFound(format!(
                "user_card {card_id} (not found or deleted)"
            )));
        }
        let row = self.repo.get_card(card_id).await?.ok_or_else(|| {
            AstralError::Database(format!("user_card {card_id} not found after bind"))
        })?;
        tracing::info!(card_id, user_id, "user card bound");
        Ok(row)
    }

    /// 异步绑定单卡（PENDING/INACTIVE → ACTIVE），命中才落 durable 投影事件。
    /// 卡不在可绑定状态（返回 false）时返回明确错误，避免异步 batch tracker
    /// 把失败计为完成（对齐 `bind_card` 的 not-found 语义）。
    pub async fn bind_card_async_one(
        &self,
        card_id: i64,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        let bound = self
            .repo
            .bind_card_async_one(card_id, user_id, admission)
            .await?;
        if !bound {
            return Err(AstralError::NotFound(format!(
                "user card {card_id} is not in a bindable state (PENDING/INACTIVE)"
            )));
        }
        Ok(())
    }

    /// Execute one item with ITS OWN freshly evaluated, reserved admission
    /// (from `service::user_card_batch_admission::admit_item`). The handle is
    /// taken by value and moved into the item's source transaction, which
    /// consumes it exactly once. This service never reconstructs, clones, or
    /// splits admissions: one proof becomes exactly one budget.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_card_async_batch_item(
        &self,
        card_id: i64,
        user_id: i64,
        actor_id: i64,
        actor_card_id: i64,
        actor_tenant_id: i64,
        actor_domain_id: i64,
        task_id: &str,
        operation_id: &str,
        expected_tenant_id: i64,
        expected_domain_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<CommittedProjectionReceipts, AstralError> {
        if admission.operation_id() != operation_id {
            return Err(AstralError::Permission(
                "batch item admission belongs to another operation".into(),
            ));
        }
        let receipts = self
            .repo
            .bind_card_async_batch_item(
                card_id,
                user_id,
                actor_id,
                actor_card_id,
                actor_tenant_id,
                actor_domain_id,
                task_id,
                operation_id,
                expected_tenant_id,
                expected_domain_id,
                admission,
            )
            .await?
            .ok_or_else(|| {
                AstralError::NotFound(format!(
                    "user card {card_id} is not in a bindable state (PENDING/INACTIVE)"
                ))
            })?;
        Ok(receipts)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use astral_types::{
        AuthorizationAuthorityError, AuthorizationDomainScope, AuthorizationFenceProof,
        AUTHORIZATION_EDITION,
    };

    use crate::repository::authorization_source_transaction::CommittedProjectionReceipts;
    use crate::repository::user_card_repository::{
        DeleteCascadeResult, NewUserCard, UserCardFilter, UserCardPatch, UserCardRepository,
    };

    use super::*;

    /// 测试专用 proof：只须通过结构校验（无签名验证；scope 对牌由每个 item 的
    /// source 事务在锁定行复核时完成），与 grading/permission_action 仓库测试
    /// 的 admission 构造合同一致。每个 item 的 admission 携带**各自的**
    /// operation/proof 身份 —— 正是 fresh 评估应产出的形态。
    fn item_admission_for_test(operation_id: &str) -> AuthorizationAdmission {
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
            operation_id: operation_id.to_owned(),
            event_id: format!("{operation_id}:commit"),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: format!("nonce-{operation_id}"),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: format!("proof-{operation_id}"),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 记录每次批量 item 调用实际收到的 admission handle，并恒以“不可绑定”
    /// （Ok(None)）返回 —— 派生语义测试只需要 handle 本身。
    struct RecordingBatchRepository {
        admissions: Mutex<Vec<AuthorizationAdmission>>,
    }

    impl RecordingBatchRepository {
        fn new() -> Self {
            Self {
                admissions: Mutex::new(Vec::new()),
            }
        }

        fn recorded(&self) -> Vec<AuthorizationAdmission> {
            self.admissions.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserCardRepository for RecordingBatchRepository {
        async fn count_cards(&self, _filter: &UserCardFilter) -> Result<i64, AstralError> {
            Ok(0)
        }
        async fn list_cards(
            &self,
            _filter: &UserCardFilter,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<UserCardRecord>, AstralError> {
            Ok(Vec::new())
        }
        async fn get_card(&self, _card_id: i64) -> Result<Option<UserCardRecord>, AstralError> {
            Ok(None)
        }
        async fn create_card(
            &self,
            _new: &NewUserCard,
            _admission: AuthorizationAdmission,
        ) -> Result<i64, AstralError> {
            Ok(0)
        }
        async fn update_card(
            &self,
            _card_id: i64,
            _patch: &UserCardPatch,
            _admission: AuthorizationAdmission,
        ) -> Result<(), AstralError> {
            Ok(())
        }
        async fn delete_with_cascade(
            &self,
            _card_id: i64,
            _admission: AuthorizationAdmission,
        ) -> Result<DeleteCascadeResult, AstralError> {
            Ok(DeleteCascadeResult {
                exists: false,
                permission_rule_deleted: 0,
                snapshot_deleted: 0,
                rule_set_ref_deleted: 0,
            })
        }
        async fn restore_card(
            &self,
            _card_id: i64,
            _admission: AuthorizationAdmission,
        ) -> Result<bool, AstralError> {
            Ok(false)
        }
        async fn bind_card(
            &self,
            _card_id: i64,
            _user_id: i64,
            _admission: AuthorizationAdmission,
        ) -> Result<bool, AstralError> {
            Ok(false)
        }
        async fn bind_card_async_one(
            &self,
            _card_id: i64,
            _user_id: i64,
            _admission: AuthorizationAdmission,
        ) -> Result<bool, AstralError> {
            Ok(false)
        }
        async fn bind_card_async_batch_item(
            &self,
            _card_id: i64,
            _user_id: i64,
            _actor_id: i64,
            _actor_card_id: i64,
            _actor_tenant_id: i64,
            _actor_domain_id: i64,
            _task_id: &str,
            _operation_id: &str,
            _expected_tenant_id: i64,
            _expected_domain_id: i64,
            admission: AuthorizationAdmission,
        ) -> Result<Option<CommittedProjectionReceipts>, AstralError> {
            self.admissions.lock().unwrap().push(admission);
            Ok(None)
        }
        async fn find_conflicts(
            &self,
            _filter: &UserCardFilter,
        ) -> Result<Vec<UserCardRecord>, AstralError> {
            Ok(Vec::new())
        }
        async fn find_active_card_for_user(
            &self,
            _user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }
    }

    fn batch_call(card_id: i64) -> (i64, i64, i64, i64, i64, i64, String, String, i64, i64) {
        (
            card_id,
            500,
            30,
            20,
            10,
            40,
            "uc_bind:test-task".into(),
            format!("batch-bind:item-{card_id}"),
            10,
            40,
        )
    }

    /// 核心回归：每个 item 收到的必须是**它自己**的 fresh admission 句柄 ——
    /// operation 与 proof 身份逐 item 不同（fresh 评估的产物），句柄按值
    /// 透传给仓库（不重建、不改写），且每个句柄拥有独立的一次性消费预算。
    #[tokio::test]
    async fn each_item_executes_its_own_fresh_admission_handle() {
        let repo = Arc::new(RecordingBatchRepository::new());
        let service = UserCardService::new(repo.clone());
        for card_id in [1, 2] {
            let (a, b, c, d, e, f, g, h, i, j) = batch_call(card_id);
            let admission = item_admission_for_test(&h);
            let provided_proof_id = admission.proof_id().to_owned();
            let result = service
                .bind_card_async_batch_item(a, b, c, d, e, f, &g, &h, i, j, admission)
                .await;
            // Ok(None) → 不可绑定语义保留为 NotFound（fail-closed 不伪装成功）。
            assert!(matches!(result, Err(AstralError::NotFound(_))));
            let recorded = repo.recorded();
            assert_eq!(
                recorded.len(),
                card_id as usize,
                "one handle per executed item"
            );
            assert_eq!(
                recorded.last().unwrap().operation_id(),
                h,
                "item {card_id} executed with its own operation admission"
            );
            assert_eq!(
                recorded.last().unwrap().proof_id(),
                provided_proof_id,
                "the handle must reach the repository untouched"
            );
        }
        let handles = repo.recorded();
        assert_eq!(handles.len(), 2);
        assert_ne!(
            handles[0].proof_id(),
            handles[1].proof_id(),
            "fresh per-item admissions must never share one proof identity"
        );
        // 每个句柄拥有独立的一次性预算：各自恰好可消费一次。
        for handle in &handles {
            handle
                .consume_once()
                .expect("each item admission keeps its own one-shot budget");
            assert!(matches!(
                handle.consume_once(),
                Err(AuthorizationAuthorityError::AdmissionConsumed)
            ));
        }
    }

    /// admission 与 durable item operation 不匹配时，service 必须在任何仓库
    /// 调用之前拒绝 —— 绝不把别的 operation 的能力消费在本 item 上。
    #[tokio::test]
    async fn admission_from_another_operation_is_refused_without_a_repository_call() {
        let repo = Arc::new(RecordingBatchRepository::new());
        let service = UserCardService::new(repo.clone());
        let (a, b, c, d, e, f, g, h, i, j) = batch_call(3);
        let admission = item_admission_for_test("batch-bind:some-other-item");
        let error = service
            .bind_card_async_batch_item(a, b, c, d, e, f, &g, &h, i, j, admission)
            .await
            .expect_err("foreign operation admission must be refused");
        assert!(matches!(error, AstralError::Permission(_)), "{error}");
        assert!(repo.recorded().is_empty(), "no source transaction may run");
    }

    /// 批量 item 不可绑定时 NotFound 语义保留（对齐 service 文档与 tracker
    /// 的 FAILED/IN_DOUBT 分类：NotFound 是确定性失败）。
    #[tokio::test]
    async fn non_bindable_item_maps_to_not_found() {
        let repo = Arc::new(RecordingBatchRepository::new());
        let service = UserCardService::new(repo);
        let (a, b, c, d, e, f, g, h, i, j) = batch_call(9);
        let result = service
            .bind_card_async_batch_item(a, b, c, d, e, f, &g, &h, i, j, item_admission_for_test(&h))
            .await;
        let error = result.expect_err("unbindable card must surface NotFound");
        assert!(error.to_string().contains("not in a bindable state"));
    }
}
