//! 当前用户查询应用服务
//!
//! 对齐 Java `AuthService` / `MenuService` 的只读编排边界。

use std::collections::BTreeSet;
use std::sync::Arc;

use astral_types::AstralError;

use super::me::{MenuItem, UserCardContext};
use super::me_repository::{MeRepository, PermissionRecord, ProfileRecord, UserCardRecord};

const ALWAYS_VISIBLE_MENUS: &[&str] = &[
    "dashboard",
    "chatPage",
    "identitySecurity",
    "helpDocs",
    "systemSettings",
    "userManagement",
    "studentManagement",
];

pub struct MeService {
    repository: Arc<dyn MeRepository>,
}

impl MeService {
    pub fn new(repository: Arc<dyn MeRepository>) -> Self {
        Self { repository }
    }

    pub async fn profile(&self, user_id: i64) -> Result<Option<ProfileRecord>, AstralError> {
        self.repository.find_profile(user_id).await
    }

    pub async fn cards(&self, user_id: i64) -> Result<Vec<UserCardContext>, AstralError> {
        Ok(self
            .repository
            .find_active_cards(user_id)
            .await?
            .into_iter()
            .map(card_to_context)
            .collect())
    }

    pub async fn identities(&self, user_id: i64) -> Result<Vec<serde_json::Value>, AstralError> {
        Ok(self
            .repository
            .find_identities(user_id)
            .await?
            .into_iter()
            .map(|identity| {
                serde_json::json!({
                    "id": identity.id,
                    "provider": identity.provider,
                    "subjectKey": identity.subject_key,
                    "accountKey": identity.account_key,
                    "verified": identity.verified,
                })
            })
            .collect())
    }

    pub async fn permissions(
        &self,
        user_id: i64,
        requested_card_id: Option<i64>,
    ) -> Result<Vec<String>, AstralError> {
        let Some(card_id) = self
            .repository
            .resolve_card(user_id, requested_card_id)
            .await?
        else {
            return Ok(vec![]);
        };
        let rules = self.repository.find_effective_permissions(card_id).await?;
        Ok(compact_or_full_permissions(rules))
    }

    pub async fn menus(
        &self,
        user_id: i64,
        requested_card_id: Option<i64>,
    ) -> Result<Vec<MenuItem>, AstralError> {
        let mut menus =
            BTreeSet::from_iter(ALWAYS_VISIBLE_MENUS.iter().map(|menu| (*menu).to_string()));
        let Some(card_id) = requested_card_id else {
            return Ok(menus.into_iter().collect());
        };

        if self
            .repository
            .resolve_card(user_id, Some(card_id))
            .await?
            .is_none()
        {
            return Err(AstralError::Auth("CARD_NOT_FOUND".into()));
        }

        menus.extend(
            self.repository
                .find_effective_permissions(card_id)
                .await?
                .into_iter()
                .filter_map(|rule| menu_for_resource(&rule.resource_type).map(str::to_string)),
        );
        Ok(menus.into_iter().collect())
    }
}

fn compact_or_full_permissions(rules: Vec<PermissionRecord>) -> Vec<String> {
    let compact: BTreeSet<String> = rules
        .iter()
        .filter_map(|rule| compact_permission(&rule.resource_type, &rule.action_code))
        .collect();
    if !compact.is_empty() {
        return compact.into_iter().collect();
    }

    rules
        .into_iter()
        .map(|rule| format!("{}:{}", rule.resource_type, rule.action_code))
        .collect()
}

fn compact_permission(resource: &str, action: &str) -> Option<String> {
    let resource = resource.trim().to_lowercase();
    let action = action.trim().to_lowercase();
    if resource.starts_with("learn:")
        || resource.starts_with("authz:")
        || resource.starts_with("platform:")
        || resource == "*"
    {
        return Some(format!("{resource}:{action}"));
    }

    let crud = |prefix: &str| match action.as_str() {
        "read" | "get" => Some(format!("{prefix}:read")),
        "create" | "update" | "delete" | "post" | "put" => Some(format!("{prefix}:write")),
        "import" => Some(format!("{prefix}:import")),
        "export" => Some(format!("{prefix}:export")),
        _ => None,
    };

    if resource.contains("learn_subject") {
        return crud("learn:subjects");
    }
    if resource.contains("learn_chapter") {
        return crud("learn:chapters");
    }
    if resource.contains("learn_level") {
        return crud("learn:levels");
    }
    if resource.contains("learn_question_bank") || resource.contains("learn_app_question") {
        return crud("learn:questions");
    }
    if resource.contains("learn_course") {
        return crud("learn:courses");
    }
    if resource.contains("learn_checkin") {
        return crud("learn:checkins");
    }
    if resource.contains("learn_statistics") && matches!(action.as_str(), "read" | "get") {
        return Some("learn:statistics:read".into());
    }
    None
}

fn menu_for_resource(resource: &str) -> Option<&'static str> {
    match resource {
        "learn_subject" | "learn_course" | "learn_chapter" | "learn_level" | "learn_level_play" => {
            Some("courseManagement")
        }
        "learn_question" | "learn_solution" | "learn_wrong_question" | "learn_exam" => {
            Some("contentManagement")
        }
        "learn_checkin" => Some("checkIn"),
        "learn_statistics" => Some("dataStatistics"),
        "learn_device" => Some("deviceStatus"),
        "learn_school" => Some("studentManagement"),
        "permission_rule"
        | "permission_request"
        | "domain"
        | "domain_resource_type"
        | "permission_action" => Some("permissionCenter"),
        "enterprise" => Some("enterprise"),
        "audit" => Some("auditLogs"),
        "user_profile" => Some("identitySecurity"),
        "platform_tenant" | "platform_tenant_member" => Some("tenantManagement"),
        "platform_package" => Some("packageManagement"),
        "platform_dept" => Some("departmentManagement"),
        "identity_users" => Some("userManagement"),
        "chat_message" | "chat_conversation" | "chat_offline_message" => Some("chatPage"),
        "permission_inheritance" | "cross_org_grant" | "enterprise_permission" => {
            Some("sodManagement")
        }
        "authorization" => Some("delegateManagement"),
        _ => None,
    }
}

fn card_to_context(record: UserCardRecord) -> UserCardContext {
    let is_starter = record.card_type == "STARTER_CARD";
    UserCardContext {
        card_id: record.card_id,
        card_name: record.card_name,
        card_type: record.card_type,
        domain_id: record.domain_id,
        tenant_id: record.tenant_id,
        status: record.card_status,
        template_code: record.template_code,
        token_version: None,
        expires_at: None,
        is_default: record.is_primary,
        is_starter: Some(is_starter),
        action_codes: parse_csv(record.action_codes),
        rule_set_ids: parse_csv_i64(record.rule_set_ids),
        overlay_rule_set_ids: parse_csv_i64(record.overlay_rule_set_ids),
        structure_node_id: None,
    }
}

fn parse_csv(value: Option<String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_csv_i64(value: Option<String>) -> Vec<i64> {
    value
        .map(|value| {
            value
                .split(',')
                .filter_map(|value| value.trim().parse::<i64>().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct FakeMeRepository {
        permissions: Vec<PermissionRecord>,
        card: Option<i64>,
        calls: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl MeRepository for FakeMeRepository {
        async fn find_profile(&self, _user_id: i64) -> Result<Option<ProfileRecord>, AstralError> {
            Ok(None)
        }

        async fn find_active_cards(
            &self,
            _user_id: i64,
        ) -> Result<Vec<UserCardRecord>, AstralError> {
            Ok(vec![])
        }

        async fn find_identities(
            &self,
            _user_id: i64,
        ) -> Result<Vec<super::super::me_repository::IdentityRecord>, AstralError> {
            Ok(vec![])
        }

        async fn resolve_card(
            &self,
            _user_id: i64,
            _requested_card_id: Option<i64>,
        ) -> Result<Option<i64>, AstralError> {
            self.calls.lock().unwrap().push("resolve");
            Ok(self.card)
        }

        async fn find_effective_permissions(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRecord>, AstralError> {
            self.calls.lock().unwrap().push("permissions");
            Ok(self.permissions.clone())
        }
    }

    #[tokio::test]
    async fn permissions_fall_back_to_full_when_no_compact_mapping_exists() {
        let repository = Arc::new(FakeMeRepository {
            permissions: vec![PermissionRecord {
                resource_type: "custom_resource".into(),
                action_code: "approve".into(),
            }],
            card: Some(7),
            calls: Mutex::new(vec![]),
        });
        let service = MeService::new(repository);
        assert_eq!(
            service.permissions(1, None).await.unwrap(),
            ["custom_resource:approve"]
        );
    }

    #[tokio::test]
    async fn menus_are_always_visible_without_card_context() {
        let repository = Arc::new(FakeMeRepository {
            permissions: vec![],
            card: None,
            calls: Mutex::new(vec![]),
        });
        let service = MeService::new(repository);
        let menus = service.menus(1, None).await.unwrap();
        assert!(menus.contains(&"dashboard".to_string()));
        assert!(menus.contains(&"studentManagement".to_string()));
    }
}
