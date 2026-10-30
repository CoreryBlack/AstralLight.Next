//! 规则集管理 API — HTTP adapter
//!
//! 对齐 platform_v4 真实表结构（rule_set / rule_set_entry / card_rule_set_ref）。
//! 数据访问在 `repository::rule_set_repository`；source mutation 与 durable
//! projection/audit correlation 由 repository 事务落盘，提交后的快照重建、缓存
//! 失效和消息发布由 projection worker 处理。
//! HTTP 层仅解析参数、组装 DTO、包装响应。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, RuleSetDefinition, RuleSetEntryDefinition};

use crate::api::require_platform_admin;
use crate::repository::audit_log_repository::RuleSetMutationContext;
use crate::repository::rule_set_repository::{CardRuleSetBindingView, RuleSetSummary};
use crate::service::rule_set_write_service::{
    AddEntryRequest, BindCardRequest, CreateRuleSetRequest, UpdateEntryRequest,
    UpdateRuleSetRequest,
};
use crate::AppState;

/// 完整规则集 source 的 HTTP 读视图。
///
/// `id`/`refType` 保留旧 wire 键；canonical `ruleSetId`/`sourceType` 与其来自
/// 同一 source row。旧键不参与 source_type 的 mutation。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetDto {
    pub id: Option<i64>,
    pub rule_set_id: Option<i64>,
    pub name: String,
    pub code: Option<String>,
    pub ref_type: String,
    pub source_type: Option<String>,
    pub source_id: Option<i64>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default, with = "astral_types::utc_rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(default, with = "astral_types::utc_rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
    pub tenant_id: Option<i64>,
    pub entry_count: i32,
    pub bound_card_count: i32,
}

impl From<RuleSetSummary> for RuleSetDto {
    fn from(s: RuleSetSummary) -> Self {
        let definition: RuleSetDefinition = s.definition;
        Self {
            id: Some(definition.rule_set_id),
            rule_set_id: Some(definition.rule_set_id),
            name: definition.name,
            code: Some(definition.code),
            ref_type: definition.source_type.clone(),
            source_type: Some(definition.source_type),
            source_id: definition.source_id,
            description: definition.description,
            enabled: Some(definition.enabled),
            created_at: Some(definition.created_at),
            updated_at: Some(definition.updated_at),
            tenant_id: definition.tenant_id,
            entry_count: s.entry_count as i32,
            bound_card_count: s.bound_card_count as i32,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardRuleSetBindingDto {
    pub id: Option<i64>,
    pub card_id: Option<i64>,
    pub rule_set_id: i64,
    pub ref_type: String,
    #[serde(with = "astral_types::utc_rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    pub tenant_id: Option<i64>,
    pub rule_set_name: String,
    pub rule_set_code: String,
}

impl From<CardRuleSetBindingView> for CardRuleSetBindingDto {
    fn from(view: CardRuleSetBindingView) -> Self {
        Self {
            id: Some(view.binding.id),
            card_id: Some(view.binding.card_id),
            rule_set_id: view.binding.rule_set_id,
            ref_type: view.binding.ref_type,
            created_at: Some(view.binding.created_at),
            tenant_id: view.binding.tenant_id,
            rule_set_name: view.rule_set_name,
            rule_set_code: view.rule_set_code,
        }
    }
}

/// 完整规则集条目的 HTTP 读视图。`resource`/`action`/`id` 保留旧键。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetEntryDto {
    pub id: Option<i64>,
    pub entry_id: Option<i64>,
    pub rule_set_id: Option<i64>,
    pub effect: String,
    pub resource: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,
    pub action: Option<String>,
    pub action_code: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub enabled: Option<bool>,
    #[serde(default, with = "astral_types::utc_rfc3339::option")]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(default, with = "astral_types::utc_rfc3339::option")]
    pub valid_to: Option<OffsetDateTime>,
    #[serde(default, with = "astral_types::utc_rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(default, with = "astral_types::utc_rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
    pub tenant_id: Option<i64>,
}

impl From<RuleSetEntryDefinition> for RuleSetEntryDto {
    fn from(entry: RuleSetEntryDefinition) -> Self {
        Self {
            id: Some(entry.entry_id),
            entry_id: Some(entry.entry_id),
            rule_set_id: Some(entry.rule_set_id),
            effect: entry.effect,
            resource: Some(entry.resource_type.clone()),
            resource_type: Some(entry.resource_type),
            resource_id: entry.resource_id,
            action: Some(entry.action_code.clone()),
            action_code: Some(entry.action_code),
            condition_json: entry.condition_json,
            priority: entry.priority,
            enabled: Some(entry.enabled),
            valid_from: entry.valid_from,
            valid_to: entry.valid_to,
            created_at: Some(entry.created_at),
            updated_at: Some(entry.updated_at),
            tenant_id: entry.tenant_id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateRuleSetRequestDto {
    name: String,
    ref_type: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateRuleSetRequestDto {
    name: String,
    description: Option<String>,
    ref_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleSetEntryRequestDto {
    effect: String,
    resource: Option<String>,
    resource_id: Option<i64>,
    action: Option<String>,
    condition_json: Option<String>,
    priority: i32,
}

fn mutation_context(headers: &HeaderMap) -> Result<RuleSetMutationContext, AppError> {
    let actor_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError(AstralError::Auth("verified actor is required".into())))?;
    let operation_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    RuleSetMutationContext::user(actor_id, operation_id).map_err(AppError::from)
}

fn require_card_context(headers: &HeaderMap, card_id: i64) -> Result<(), AppError> {
    let context_card_id = headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    if context_card_id != Some(card_id) {
        return Err(AppError(AstralError::Permission(
            "card context does not match requested card".into(),
        )));
    }
    // Gateway 已校验并签名 tenant/domain 头；卡片身份仍必须与路径 cardId 一致。
    Ok(())
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindCardRequestDto {
    pub rule_set_id: i64,
    pub ref_type: String,
}

pub fn rule_set_routes() -> Router<crate::AppState> {
    Router::new()
        .route("/rule-sets", get(list_rule_sets))
        .route("/rule-sets", post(create_rule_set))
        .route("/rule-sets/{id}", get(get_rule_set))
        .route("/rule-sets/{id}", put(update_rule_set))
        .route("/rule-sets/{id}", delete(delete_rule_set))
        .route("/rule-sets/{id}/entries", get(list_entries))
        .route("/rule-sets/{id}/entries", post(add_entry))
        .route("/rule-sets/{id}/entries/batch", put(replace_entries))
        .route("/rule-sets/{id}/entries/{entry_id}", put(update_entry))
        .route("/rule-sets/{id}/entries/{entry_id}", delete(delete_entry))
        .route("/rule-sets/card/{card_id}/bind", post(bind_card_canonical))
        .route(
            "/rule-sets/card/{card_id}/unbind/{rule_set_id}",
            delete(unbind_card_canonical),
        )
        .route(
            "/rule-sets/card/{card_id}/bindings",
            get(list_card_bindings),
        )
        .route("/rule-sets/templates", get(list_templates))
}

async fn list_rule_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<RuleSetDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let total = state.rule_set_repository.count_rule_sets().await?;
    let rows = state
        .rule_set_repository
        .list_rule_sets(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(RuleSetDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn create_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRuleSetRequestDto>,
) -> Result<Json<ApiResponse<RuleSetDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    // keeps the existing code=name behavior and only accepts the established fields.
    let new_id = state
        .rule_set_write_service
        .create_rule_set(
            &CreateRuleSetRequest {
                name: req.name,
                ref_type: req.ref_type,
                description: req.description,
            },
            &context,
        )
        .await?;
    let dto = state
        .rule_set_repository
        .get_rule_set(new_id)
        .await?
        .map(RuleSetDto::from)
        .ok_or_else(|| {
            AppError(AstralError::Internal(
                "created rule set could not be read back".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(dto)))
}

async fn get_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<RuleSetDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let dto = state
        .rule_set_repository
        .get_rule_set(id)
        .await?
        .map(RuleSetDto::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Internal(
                "Rule set not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(dto)))
}

async fn update_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleSetRequestDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    if let Some(requested_ref_type) = req.ref_type.as_deref() {
        let current = state
            .rule_set_repository
            .get_rule_set(id)
            .await?
            .ok_or_else(|| AppError(AstralError::NotFound("rule set not found".into())))?;
        let current_ref_type = current.definition.source_type;
        if requested_ref_type != current_ref_type {
            return Err(AppError(AstralError::Validation(
                "refType is immutable and must match the existing sourceType".into(),
            )));
        }
    }
    state
        .rule_set_write_service
        .update_rule_set(
            id,
            &UpdateRuleSetRequest {
                name: req.name,
                description: req.description,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    state
        .rule_set_write_service
        .delete_rule_set(id, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn replace_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rs_id): Path<i64>,
    Json(entries): Json<Vec<RuleSetEntryRequestDto>>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    let requests = entries
        .into_iter()
        .map(|entry| AddEntryRequest {
            effect: entry.effect,
            resource: entry.resource,
            resource_id: entry.resource_id,
            action: entry.action,
            condition_json: entry.condition_json,
            priority: entry.priority,
        })
        .collect::<Vec<_>>();
    state
        .rule_set_write_service
        .replace_entries(rs_id, &requests, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn bind_card_canonical(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(card_id): Path<i64>,
    Json(req): Json<BindCardRequestDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    require_card_context(&headers, card_id)?;
    state
        .rule_set_write_service
        .bind_card(
            req.rule_set_id,
            &BindCardRequest {
                card_id,
                ref_type: req.ref_type,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn unbind_card_canonical(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((card_id, rule_set_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    require_card_context(&headers, card_id)?;
    state
        .rule_set_write_service
        .unbind_card(
            rule_set_id,
            &BindCardRequest {
                card_id,
                ref_type: "BASE".into(),
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_card_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(card_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<CardRuleSetBindingDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    require_card_context(&headers, card_id)?;
    let rows = state
        .rule_set_write_service
        .list_card_bindings(card_id)
        .await?
        .into_iter()
        .map(CardRuleSetBindingDto::from)
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

async fn list_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rs_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<RuleSetEntryDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let rows = state
        .rule_set_repository
        .list_entries(rs_id)
        .await?
        .into_iter()
        .map(RuleSetEntryDto::from)
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

async fn add_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rs_id): Path<i64>,
    Json(req): Json<RuleSetEntryRequestDto>,
) -> Result<Json<ApiResponse<RuleSetEntryDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    let entry_id = state
        .rule_set_write_service
        .add_entry(
            rs_id,
            &AddEntryRequest {
                effect: req.effect,
                resource: req.resource,
                resource_id: req.resource_id,
                action: req.action,
                condition_json: req.condition_json,
                priority: req.priority,
            },
            &context,
        )
        .await?;
    let entry = state
        .rule_set_write_service
        .get_entry(rs_id, entry_id)
        .await?
        .ok_or_else(|| {
            AppError(AstralError::Internal(
                "created rule set entry could not be read back".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(RuleSetEntryDto::from(entry))))
}

async fn update_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((rs_id, eid)): Path<(i64, i64)>,
    Json(req): Json<RuleSetEntryRequestDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    state
        .rule_set_write_service
        .update_entry(
            rs_id,
            eid,
            &UpdateEntryRequest {
                effect: req.effect,
                resource: req.resource,
                resource_id: req.resource_id,
                action: req.action,
                condition_json: req.condition_json,
                priority: req.priority,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((rs_id, eid)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    state
        .rule_set_write_service
        .delete_entry(rs_id, eid, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<RuleSetDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let total = state.rule_set_repository.count_templates().await?;
    let rows = state
        .rule_set_repository
        .list_templates(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(RuleSetDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use serde_json::Value;
    use time::UtcOffset;

    #[test]
    fn canonical_user_card_context_must_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-card-id", HeaderValue::from_static("7"));
        assert!(require_card_context(&headers, 7).is_ok());
        assert!(matches!(
            require_card_context(&headers, 8),
            Err(AppError(AstralError::Permission(_)))
        ));
    }

    #[test]
    fn generated_rule_set_mutation_fields_are_rejected_by_narrow_dto() {
        let error = serde_json::from_str::<CreateRuleSetRequestDto>(
            r#"{"name":"rules","refType":"BASE","description":null,"code":"client-code"}"#,
        )
        .expect_err("database-owned code must be rejected as an unknown command field");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn generated_entry_mutation_fields_are_rejected_by_narrow_dto() {
        let error = serde_json::from_str::<RuleSetEntryRequestDto>(
            r#"{"effect":"ALLOW","resource":"learn_course","action":"read",
                "conditionJson":null,"priority":0,"validFrom":"2026-12-23T04:26:40Z"}"#,
        )
        .expect_err("validity is a canonical read-only field");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rule_set_dto_wire_contract_still_accepts_ref_type() {
        // refType remains a public read key and the update ownership assertion input.
        let dto: RuleSetDto = serde_json::from_str(
            r#"{"id":1,"name":"n","refType":"BASE","description":null,
                "entryCount":0,"boundCardCount":0}"#,
        )
        .expect("refType must remain part of the public wire contract");
        assert_eq!(dto.ref_type, "BASE");
        let serialized = serde_json::to_string(&dto).expect("dto must serialize");
        assert!(serialized.contains("\"refType\":\"BASE\""));
    }

    #[test]
    fn read_only_fields_are_rejected_even_when_null() {
        for field in [
            "id",
            "ruleSetId",
            "code",
            "sourceType",
            "sourceId",
            "enabled",
            "tenantId",
            "createdAt",
            "updatedAt",
        ] {
            let mut request =
                serde_json::json!({"name":"rules","refType":"CUSTOM","description":null});
            request[field] = Value::Null;
            assert!(
                serde_json::from_value::<CreateRuleSetRequestDto>(request.clone()).is_err(),
                "create {field}"
            );
            assert!(
                serde_json::from_value::<UpdateRuleSetRequestDto>(request).is_err(),
                "update {field}"
            );
        }
        for field in [
            "id",
            "entryId",
            "ruleSetId",
            "resourceType",
            "actionCode",
            "enabled",
            "validFrom",
            "validTo",
            "tenantId",
            "createdAt",
            "updatedAt",
        ] {
            let mut request = serde_json::json!({"effect":"ALLOW","resource":"learn_course","action":"read","priority":0});
            request[field] = Value::Null;
            assert!(
                serde_json::from_value::<RuleSetEntryRequestDto>(request).is_err(),
                "entry {field}"
            );
        }
        for field in ["id", "cardId", "tenantId", "createdAt"] {
            let mut request = serde_json::json!({"ruleSetId":7,"refType":"BASE"});
            request[field] = Value::Null;
            assert!(
                serde_json::from_value::<BindCardRequestDto>(request).is_err(),
                "bind {field}"
            );
        }
        assert!(serde_json::from_value::<UpdateRuleSetRequestDto>(
            serde_json::json!({"name":"rules","description":null})
        )
        .unwrap()
        .ref_type
        .is_none());
    }

    #[test]
    fn canonical_read_aliases_are_derived_from_the_same_source_values() {
        let created_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let dto = RuleSetDto::from(RuleSetSummary {
            definition: RuleSetDefinition {
                rule_set_id: 7,
                name: "source".into(),
                code: "source-code".into(),
                description: Some("description".into()),
                source_type: "CUSTOM".into(),
                source_id: Some(13),
                enabled: true,
                created_at,
                updated_at: created_at,
                tenant_id: Some(11),
            },
            id: 99,
            name: "stale alias".into(),
            ref_type: "stale alias".into(),
            description: None,
            entry_count: 2,
            bound_card_count: 3,
        });
        let value = serde_json::to_value(dto).unwrap();
        assert_eq!(value["id"], value["ruleSetId"]);
        assert_eq!(value["id"], 7);
        assert_eq!(value["refType"], value["sourceType"]);
        assert_eq!(value["name"], "source");
        assert_eq!(value["code"], "source-code");
        assert_eq!(value["createdAt"], "2023-11-14T22:13:20Z");
        let entry = RuleSetEntryDto::from(RuleSetEntryDefinition {
            entry_id: 3,
            rule_set_id: 7,
            resource_type: "learn_course".into(),
            resource_id: Some(17),
            action_code: "read".into(),
            effect: "ALLOW".into(),
            condition_json: None,
            priority: 4,
            enabled: true,
            valid_from: None,
            valid_to: None,
            created_at,
            updated_at: created_at,
            tenant_id: Some(11),
        });
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(value["id"], value["entryId"]);
        assert_eq!(value["resource"], value["resourceType"]);
        assert_eq!(value["action"], value["actionCode"]);
        assert_eq!(value["ruleSetId"], 7);
        assert_eq!(value["tenantId"], 11);
    }

    #[test]
    fn binding_created_at_uses_utc_rfc3339_wire_shape() {
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_798_000_000)
            .expect("test timestamp")
            .to_offset(UtcOffset::from_hms(5, 30, 0).expect("test offset"));
        let dto = CardRuleSetBindingDto {
            id: Some(9),
            card_id: Some(10),
            rule_set_id: 7,
            ref_type: "BASE".into(),
            created_at: Some(created_at),
            tenant_id: Some(11),
            rule_set_name: "rules".into(),
            rule_set_code: "rules-code".into(),
        };
        let value: Value = serde_json::to_value(dto).expect("binding dto must serialize");
        assert_eq!(
            value.get("createdAt").and_then(Value::as_str),
            Some("2026-12-23T04:26:40Z")
        );
    }
}
