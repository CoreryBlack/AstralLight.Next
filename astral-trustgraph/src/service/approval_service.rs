//! 审批编排 — ApprovalService
//!
//! 对齐 Java `PermissionRequestServiceImpl.approve()`：审批通过 → 同一事务完成
//! 状态、ALLOW 规则与 authorization projection append。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::permission_request_repository::{NewRequest, PermissionRequestRepository};
use crate::service::side_effect::PermissionSideEffects;

/// 审批结果（approve 的 card_id，供响应使用）
#[derive(Debug, Clone)]
pub struct ApproveOutcome {
    pub card_id: Option<i64>,
}

/// ApprovalService
pub struct ApprovalService {
    repo: Arc<dyn PermissionRequestRepository>,
    side_effects: Arc<dyn PermissionSideEffects>,
}

impl ApprovalService {
    pub fn new(
        repo: Arc<dyn PermissionRequestRepository>,
        side_effects: Arc<dyn PermissionSideEffects>,
    ) -> Self {
        Self { repo, side_effects }
    }

    /// 新建请求：在写入 PENDING 前验证请求者拥有目标卡，且卡片 ACTIVE、当前有效。
    pub async fn create_request(&self, new: &NewRequest) -> Result<i64, AstralError> {
        if new.request_type == "RULE" {
            let content: RequestContent = parse_rule_content(&new.request_content)?;
            let card_id = content.card_id.ok_or_else(|| {
                AstralError::Validation("RULE permission request requires a target card".into())
            })?;
            self.repo
                .validate_card_for_user(new.user_id, card_id)
                .await?;
        }
        self.repo.create_request(new).await
    }

    /// 审批：状态 PENDING 校验 → 同一事务完成 APPROVED + 规则 + projection
    pub async fn approve(
        &self,
        request_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<ApproveOutcome, AstralError> {
        // 1. 读取请求详情（需在 UPDATE 前获取 request_content 以解析 resourceType/actionCode/cardId）
        let req_row = self
            .repo
            .get_request(request_id)
            .await?
            .ok_or_else(|| AstralError::Internal("Request not found".into()))?;

        if req_row.status != "PENDING" {
            return Err(AstralError::Validation("Request is not pending".into()));
        }

        if !matches!(
            req_row.request_type.as_str(),
            "RULE" | "LEVEL_UP" | "TEMP_PERMISSION"
        ) {
            return Err(AstralError::Validation(
                "unsupported permission request type".into(),
            ));
        }
        if req_row.request_type != "RULE" {
            return Err(AstralError::NotImplemented(format!(
                "permission request type {} approval is not implemented",
                req_row.request_type
            )));
        }

        // 解析 RULE request_content JSON 获取 canonical resourceType/actionCode/cardId。
        let content = parse_rule_content(req_row.request_content.as_deref().ok_or_else(|| {
            AstralError::Validation("Invalid or missing request_content".into())
        })?)?;

        let Some(card_id) = content.card_id else {
            return Err(AstralError::Validation(
                "permission request approval requires a target card".into(),
            ));
        };
        let condition_json = content
            .condition_json
            .as_ref()
            .map(|value| value.to_string());

        self.repo
            .approve_with_rule(
                request_id,
                reviewer_id,
                comment,
                card_id,
                &content.resource_type,
                &content.action_code,
                content.effect.as_deref().unwrap_or("ALLOW"),
                content.priority.unwrap_or(0),
                condition_json.as_deref(),
                content.valid_from.as_deref(),
                content.valid_to.as_deref(),
                request_id_header,
            )
            .await?;
        if !self.repo.writes_projection_in_transaction() {
            self.side_effects
                .request_card_projection(card_id, "APPROVED")
                .await?;
        }

        // approve_with_rule 已在同一事务内完成状态、规则与 projection append。
        // CARD projection outbox/worker 负责 canonical refresh，不能再从这里旁路发布 USER 刷新。
        Ok(ApproveOutcome {
            card_id: Some(card_id),
        })
    }

    /// 驳回：仅置 REJECTED，无副作用
    pub async fn reject(
        &self,
        request_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError> {
        self.repo
            .reject_request(request_id, reviewer_id, comment, request_id_header)
            .await
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestContent {
    resource_type: String,
    action_code: String,
    card_id: Option<i64>,
    effect: Option<String>,
    priority: Option<i32>,
    condition_json: Option<serde_json::Value>,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

fn parse_rule_content(value: &str) -> Result<RequestContent, AstralError> {
    let mut content: RequestContent = serde_json::from_str(value)
        .map_err(|_| AstralError::Validation("Invalid or missing request_content".into()))?;
    if content.resource_type.trim().is_empty() || content.action_code.trim().is_empty() {
        return Err(AstralError::Validation(
            "RULE resourceType and actionCode must not be empty".into(),
        ));
    }
    // fail-closed：未注册资源/动作不得进入审批授权链。与
    // `validate_canonical_grant_effect` 同一契约：去空白后必须命中
    // ResourceRegistry（资源已注册且动作属于该资源），否则 Validation 拒绝，
    // 不转换、不截断、不静默跳过。归一化（trim）值回写 content，使
    // create_request 与 approve 看到同一规范化二元组，approve 写入
    // permission_rule / ledger ADD 的 resource/action 与解析层同源，
    // 消除 raw/trim 漂移。
    let (resource_type, action_code) =
        crate::service::personal_permission_service::validate_registry_resource_action(
            &content.resource_type,
            &content.action_code,
        )?;
    content.resource_type = resource_type;
    content.action_code = action_code;
    // fail-closed：审批通过的 canonical grant 只接受 ALLOW（大小写归一后回写）。
    if let Some(effect) = content.effect.as_deref() {
        content.effect = Some(crate::service::validate_canonical_grant_effect(effect)?);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::permission_request_repository::PermissionRequestRecord;
    use crate::service::side_effect::PermissionSideEffects;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// no-op compatibility recorder for test-only legacy side effects
    struct RecordingSideEffects {
        events: Mutex<Vec<(i64, String)>>,
    }

    impl RecordingSideEffects {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<(i64, String)> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PermissionSideEffects for RecordingSideEffects {
        async fn request_card_projection(
            &self,
            card_id: i64,
            event_type: &str,
        ) -> Result<(), AstralError> {
            self.events
                .lock()
                .unwrap()
                .push((card_id, event_type.to_string()));
            Ok(())
        }

        async fn rebuild_card_snapshot(&self, _card_id: i64) {}
        async fn rebuild_rule_set_snapshot(&self, _rule_set_id: i64) -> Result<(), AstralError> {
            Ok(())
        }
        async fn evict_card_cache(&self, _card_id: i64) {}
    }

    #[derive(Debug, Clone)]
    struct ApproveTxArgs {
        request_id: i64,
        reviewer_id: i64,
        comment: Option<String>,
        card_id: i64,
        resource: String,
        action: String,
        effect: String,
        request_id_header: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct DecisionTxArgs {
        request_id: i64,
        reviewer_id: i64,
        comment: Option<String>,
        request_id_header: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct CancelTxArgs {
        request_id: i64,
        user_id: i64,
        comment: Option<String>,
        request_id_header: Option<String>,
    }

    /// Fake PermissionRequestRepository（记录 approve/reject/cancel 参数）
    struct FakeRequestRepository {
        record: Mutex<Option<PermissionRequestRecord>>,
        approve_tx: Mutex<Option<ApproveTxArgs>>,
        reject_tx: Mutex<Option<DecisionTxArgs>>,
        cancel_tx: Mutex<Option<CancelTxArgs>>,
    }

    impl FakeRequestRepository {
        fn new(record: Option<PermissionRequestRecord>) -> Self {
            Self {
                record: Mutex::new(record),
                approve_tx: Mutex::new(None),
                reject_tx: Mutex::new(None),
                cancel_tx: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl PermissionRequestRepository for FakeRequestRepository {
        async fn create_request(&self, _new: &NewRequest) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn validate_card_for_user(
            &self,
            _user_id: i64,
            _card_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn count_all(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_all(
            &self,
            _l: i64,
            _o: i64,
        ) -> Result<Vec<PermissionRequestRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get_request(
            &self,
            _request_id: i64,
        ) -> Result<Option<PermissionRequestRecord>, AstralError> {
            Ok(self.record.lock().unwrap().clone())
        }

        async fn count_for_user(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_for_user(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<PermissionRequestRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get_request_for_user(
            &self,
            _request_id: i64,
            _user_id: i64,
        ) -> Result<Option<PermissionRequestRecord>, AstralError> {
            Ok(None)
        }

        async fn cancel_request(
            &self,
            request_id: i64,
            user_id: i64,
            comment: Option<&str>,
            request_id_header: Option<&str>,
        ) -> Result<(), AstralError> {
            *self.cancel_tx.lock().unwrap() = Some(CancelTxArgs {
                request_id,
                user_id,
                comment: comment.map(String::from),
                request_id_header: request_id_header.map(String::from),
            });
            Ok(())
        }

        async fn count_pending(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_pending(
            &self,
            _l: i64,
            _o: i64,
        ) -> Result<Vec<PermissionRequestRecord>, AstralError> {
            Ok(vec![])
        }

        async fn approve_with_rule(
            &self,
            request_id: i64,
            reviewer_id: i64,
            comment: Option<&str>,
            card_id: i64,
            resource: &str,
            action: &str,
            effect: &str,
            _priority: i32,
            _condition_json: Option<&str>,
            _valid_from: Option<&str>,
            _valid_to: Option<&str>,
            request_id_header: Option<&str>,
        ) -> Result<(), AstralError> {
            *self.approve_tx.lock().unwrap() = Some(ApproveTxArgs {
                request_id,
                reviewer_id,
                comment: comment.map(String::from),
                card_id,
                resource: resource.to_string(),
                action: action.to_string(),
                effect: effect.to_string(),
                request_id_header: request_id_header.map(String::from),
            });
            Ok(())
        }

        async fn reject_request(
            &self,
            request_id: i64,
            reviewer_id: i64,
            comment: Option<&str>,
            request_id_header: Option<&str>,
        ) -> Result<(), AstralError> {
            *self.reject_tx.lock().unwrap() = Some(DecisionTxArgs {
                request_id,
                reviewer_id,
                comment: comment.map(String::from),
                request_id_header: request_id_header.map(String::from),
            });
            Ok(())
        }
    }

    fn pending_record() -> PermissionRequestRecord {
        PermissionRequestRecord {
            request_id: 5,
            user_id: 7,
            request_type: "RULE".into(),
            request_content: Some(
                r#"{"resourceType":"learn_course","actionCode":"read","cardId":3}"#.into(),
            ),
            reason: None,
            status: "PENDING".into(),
            approver_id: None,
            approve_comment: None,
            created_at: None,
        }
    }

    #[test]
    fn rule_metadata_is_parsed_without_loss() {
        let content = parse_rule_content(
            r#"{"resourceType":"learn_course","actionCode":"read","cardId":3,"effect":"allow","priority":9,"conditionJson":{"ownerOnly":true},"validFrom":"2026-01-01","validTo":"2026-12-31"}"#,
        )
        .expect("metadata should parse");
        // canonical grant 只接受 ALLOW；入参大小写归一后回写
        assert_eq!(content.effect.as_deref(), Some("ALLOW"));
        assert_eq!(content.priority, Some(9));
        assert_eq!(
            content.condition_json,
            Some(serde_json::json!({"ownerOnly": true}))
        );
        assert_eq!(content.valid_from.as_deref(), Some("2026-01-01"));
        assert_eq!(content.valid_to.as_deref(), Some("2026-12-31"));
    }

    #[test]
    fn rule_content_effect_is_allow_only() {
        for rejected in ["DENY", "deny", "GRANT", "", "   "] {
            let value = serde_json::json!({
                "resourceType": "learn_course",
                "actionCode": "read",
                "cardId": 3,
                "effect": rejected
            });
            let error = parse_rule_content(&value.to_string())
                .expect_err("non-ALLOW RULE effect must be rejected");
            assert!(
                matches!(&error, AstralError::Validation(message) if message.contains("ALLOW")),
                "rejected={rejected:?} unexpected={error:?}"
            );
        }
    }

    #[test]
    fn rule_content_resource_action_must_be_registered() {
        for (resource, action) in [
            ("no_such_resource", "read"),
            ("learn_course", "no_such_action"),
        ] {
            let value = serde_json::json!({
                "resourceType": resource,
                "actionCode": action,
                "cardId": 3
            });
            let error = parse_rule_content(&value.to_string())
                .expect_err("unregistered resource/action must be rejected fail-closed");
            assert!(
                matches!(&error, AstralError::Validation(message)
                    if message.contains("ResourceRegistry")),
                "rejected=({resource:?},{action:?}) unexpected={error:?}"
            );
        }
    }

    #[test]
    fn rule_content_blank_resource_action_is_rejected() {
        for (resource, action) in [
            ("", "read"),
            ("   ", "read"),
            ("learn_course", ""),
            ("learn_course", " \t "),
        ] {
            let value = serde_json::json!({
                "resourceType": resource,
                "actionCode": action,
                "cardId": 3
            });
            let error = parse_rule_content(&value.to_string())
                .expect_err("blank resource/action must be rejected fail-closed");
            assert!(
                matches!(error, AstralError::Validation(_)),
                "rejected=({resource:?},{action:?}) unexpected={error:?}"
            );
        }
    }

    #[test]
    fn rule_content_resource_action_is_trimmed() {
        let content = parse_rule_content(
            r#"{"resourceType":"  learn_course ","actionCode":" read ","cardId":3}"#,
        )
        .expect("registered resource/action with whitespace must be accepted");
        // 归一化（trim）值回写 content：approve 转发到事务写入的与解析层同源
        assert_eq!(content.resource_type, "learn_course");
        assert_eq!(content.action_code, "read");
    }
    #[tokio::test]
    async fn approve_rejects_non_pending() {
        let mut rec = pending_record();
        rec.status = "APPROVED".into();
        let repo = Arc::new(FakeRequestRepository::new(Some(rec)));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo, se);

        let err = svc.approve(5, 1, None, None).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[tokio::test]
    async fn approve_writes_rule_tx_and_rebuilds() {
        let repo = Arc::new(FakeRequestRepository::new(Some(pending_record())));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo.clone(), se.clone());

        let outcome = svc
            .approve(5, 1, Some("ok"), Some("request-5"))
            .await
            .unwrap();
        assert_eq!(outcome.card_id, Some(3));

        // 事务写（status + 规则）参数透传
        let tx = repo.approve_tx.lock().unwrap().clone().unwrap();
        assert_eq!(tx.request_id, 5);
        assert_eq!(tx.reviewer_id, 1);
        assert_eq!(tx.comment.as_deref(), Some("ok"));
        assert_eq!(tx.card_id, 3);
        assert_eq!(tx.resource, "learn_course");
        assert_eq!(tx.action, "read");
        // 请求未带 effect → 默认 ALLOW 写入
        assert_eq!(tx.effect, "ALLOW");
        assert_eq!(tx.request_id_header.as_deref(), Some("request-5"));
        // 异步副作用触发 durable 投影事件（tokio::spawn 已在当前 runtime 执行）
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(se.events(), vec![(3, "APPROVED".to_string())]);
    }

    #[tokio::test]
    async fn reject_and_cancel_forward_decision_parameters() {
        let repo = Arc::new(FakeRequestRepository::new(Some(pending_record())));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo.clone(), se);

        svc.reject(5, 11, Some("not enough scope"), Some("req-reject"))
            .await
            .unwrap();
        let reject = repo.reject_tx.lock().unwrap().clone().unwrap();
        assert_eq!(reject.request_id, 5);
        assert_eq!(reject.reviewer_id, 11);
        assert_eq!(reject.comment.as_deref(), Some("not enough scope"));
        assert_eq!(reject.request_id_header.as_deref(), Some("req-reject"));

        repo.cancel_tx.lock().unwrap().take();
        repo.record.lock().unwrap().as_mut().unwrap().user_id = 7;
        repo.cancel_request(5, 7, Some("changed my mind"), Some("req-cancel"))
            .await
            .unwrap();
        let cancel = repo.cancel_tx.lock().unwrap().clone().unwrap();
        assert_eq!(cancel.request_id, 5);
        assert_eq!(cancel.user_id, 7);
        assert_eq!(cancel.comment.as_deref(), Some("changed my mind"));
        assert_eq!(cancel.request_id_header.as_deref(), Some("req-cancel"));
    }

    #[test]
    fn legacy_rule_fields_are_rejected() {
        for legacy_field in [
            "resource",
            "action",
            "card_id",
            "condition_json",
            "valid_from",
            "valid_to",
        ] {
            let value = match legacy_field {
                "resource" => serde_json::json!({
                    "resource": "learn_course",
                    "actionCode": "read",
                    "cardId": 3
                }),
                "action" => serde_json::json!({
                    "resourceType": "learn_course",
                    "action": "read",
                    "cardId": 3
                }),
                "card_id" => serde_json::json!({
                    "resourceType": "learn_course",
                    "actionCode": "read",
                    "card_id": 3
                }),
                "condition_json" => serde_json::json!({
                    "resourceType": "learn_course",
                    "actionCode": "read",
                    "cardId": 3,
                    "condition_json": {"ownerOnly": true}
                }),
                "valid_from" => serde_json::json!({
                    "resourceType": "learn_course",
                    "actionCode": "read",
                    "cardId": 3,
                    "valid_from": "2026-01-01"
                }),
                "valid_to" => serde_json::json!({
                    "resourceType": "learn_course",
                    "actionCode": "read",
                    "cardId": 3,
                    "valid_to": "2026-12-31"
                }),
                _ => unreachable!("test field must be listed above"),
            };

            let error = parse_rule_content(&value.to_string())
                .expect_err("legacy RULE fields must be rejected");
            assert!(
                matches!(error, AstralError::Validation(_)),
                "{legacy_field}"
            );
        }
    }

    #[tokio::test]
    async fn approve_rejects_legacy_rule_fields() {
        for legacy_content in [
            r#"{"resource":"learn_course","actionCode":"read","cardId":3}"#,
            r#"{"resourceType":"learn_course","action":"read","cardId":3}"#,
            r#"{"resourceType":"learn_course","actionCode":"read","card_id":3}"#,
            r#"{"resourceType":"learn_course","actionCode":"read","cardId":3,"condition_json":{"ownerOnly":true}}"#,
            r#"{"resourceType":"learn_course","actionCode":"read","cardId":3,"valid_from":"2026-01-01"}"#,
            r#"{"resourceType":"learn_course","actionCode":"read","cardId":3,"valid_to":"2026-12-31"}"#,
        ] {
            let mut record = pending_record();
            record.request_content = Some(legacy_content.into());
            let repo = Arc::new(FakeRequestRepository::new(Some(record)));
            let se = Arc::new(RecordingSideEffects::new());
            let svc = ApprovalService::new(repo.clone(), se.clone());

            let error = svc
                .approve(5, 1, None, None)
                .await
                .expect_err("approval must reject legacy RULE fields");
            assert!(matches!(error, AstralError::Validation(_)));
            assert!(repo.approve_tx.lock().unwrap().is_none());
            assert!(se.events().is_empty());
        }
    }

    #[tokio::test]
    async fn approve_rejects_deny_effect_without_writing_source() {
        let mut rec = pending_record();
        rec.request_content = Some(
            r#"{"resourceType":"learn_course","actionCode":"read","cardId":3,"effect":"DENY"}"#
                .into(),
        );
        let repo = Arc::new(FakeRequestRepository::new(Some(rec)));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo.clone(), se.clone());

        let error = svc
            .approve(5, 1, None, None)
            .await
            .expect_err("DENY approval grant must be rejected");
        assert!(matches!(error, AstralError::Validation(message) if message.contains("ALLOW")));
        // 审计链：拒绝发生在事务前，无 source 写入、无审批副作用
        assert!(repo.approve_tx.lock().unwrap().is_none());
        assert!(se.events().is_empty());
    }

    #[tokio::test]
    async fn approve_rejects_unregistered_resource_without_writing_source() {
        for (resource, action) in [
            ("no_such_resource", "read"),
            ("learn_course", "no_such_action"),
        ] {
            let mut rec = pending_record();
            rec.request_content = Some(
                serde_json::json!({"resourceType": resource, "actionCode": action, "cardId": 3})
                    .to_string(),
            );
            let repo = Arc::new(FakeRequestRepository::new(Some(rec)));
            let se = Arc::new(RecordingSideEffects::new());
            let svc = ApprovalService::new(repo.clone(), se.clone());

            let error = svc
                .approve(5, 1, None, None)
                .await
                .expect_err("unregistered resource/action approval must fail closed");
            assert!(
                matches!(&error, AstralError::Validation(message)
                    if message.contains("ResourceRegistry")),
                "rejected=({resource:?},{action:?}) unexpected={error:?}"
            );
            // 审计链：拒绝发生在事务前，无 source 写入、无审批副作用
            assert!(repo.approve_tx.lock().unwrap().is_none());
            assert!(se.events().is_empty());
        }
    }

    #[tokio::test]
    async fn approve_trims_and_forwards_normalized_resource_action() {
        let repo = Arc::new(FakeRequestRepository::new(Some(PermissionRequestRecord {
            request_content: Some(
                r#"{"resourceType":"  learn_course ","actionCode":" read ","cardId":3}"#.into(),
            ),
            ..pending_record()
        })));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo.clone(), se);

        svc.approve(5, 1, None, None)
            .await
            .expect("registered resource/action with whitespace must be approved");
        let tx = repo.approve_tx.lock().unwrap().clone().unwrap();
        // 事务写入参数为归一化（trim）后的二元组，permission_rule 与 ledger ADD 同源
        assert_eq!(tx.resource, "learn_course");
        assert_eq!(tx.action, "read");
        assert_eq!(tx.effect, "ALLOW");
    }

    #[tokio::test]
    async fn approve_preserves_canonical_rule_metadata() {
        let repo = Arc::new(FakeRequestRepository::new(Some(PermissionRequestRecord {
            request_content: Some(
                r#"{"resourceType":"learn_course","actionCode":"read","cardId":3,"effect":"allow","conditionJson":{"ownerOnly":true},"validFrom":"2026-01-01","validTo":"2026-12-31"}"#.into(),
            ),
            ..pending_record()
        })));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo.clone(), se);

        svc.approve(5, 1, None, None)
            .await
            .expect("canonical metadata should be accepted");
        let tx = repo.approve_tx.lock().unwrap().clone().unwrap();
        assert_eq!(tx.card_id, 3);
        assert_eq!(tx.resource, "learn_course");
        assert_eq!(tx.action, "read");
        // 归一化后的 ALLOW 传入审批事务，而不是原始入参
        assert_eq!(tx.effect, "ALLOW");
    }

    #[tokio::test]
    async fn approve_without_card_rejects_request() {
        let mut rec = pending_record();
        rec.request_content =
            Some(r#"{"resourceType":"learn_course","actionCode":"read","cardId":null}"#.into());
        let repo = Arc::new(FakeRequestRepository::new(Some(rec)));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = ApprovalService::new(repo.clone(), se.clone());

        let err = svc.approve(5, 1, None, None).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
        assert!(repo.approve_tx.lock().unwrap().is_none());
        assert!(se.events().is_empty());
    }
}
