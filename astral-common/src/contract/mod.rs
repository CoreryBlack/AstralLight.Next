//! 统一 API 响应契约
//!
//! 与 Java `ApiResponse` / `ApiContractSupport` 完全对齐。
//! 所有 HTTP 接口统一使用此格式响应。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

/// 统一 API 响应
///
/// 对齐 Java `ApiResponse` 全部字段：
/// - `code` (int) / `message` / `data`
/// - `errorType` — 错误类型（如 `"VALIDATION_ERROR"`, `"PERMISSION_DENIED"`）
/// - `decision` — 权限决策原因（如 `"DEFAULT_DENY"`, `"RULE_SET_ALLOW"`）
/// - `reasonCode` — 业务原因码（如 `"CARD_REQUIRED"`, `"AUTHN_REQUIRED"`）
/// - `timestamp` / `traceId` / `requestPath` / `requestMethod`
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse<T: Serialize> {
    /// 是否成功
    pub success: bool,
    /// 业务码（对齐 Java int code：200=成功，400=参数错误，401=认证，403=权限，500=内部错误）
    pub code: i32,
    /// 消息描述
    pub message: String,
    /// 数据载荷
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// 错误类型（Java `errorType`，权限相关时为 `"PERMISSION_DENIED"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    /// 权限决策原因（Java `decision`，如 `"DEFAULT_DENY"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// 业务原因码（Java `reasonCode`，如 `"CARD_REQUIRED"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// 所需权限（Java `requiredPermission`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_permission: Option<String>,
    /// 请求路径（Java `requestPath`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_path: Option<String>,
    /// 请求方法（Java `requestMethod`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    /// 时间戳
    pub timestamp: i64,
    /// 请求追踪 ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    /// 成功响应（code=200，对齐 Java ApiResponse.success()）
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            code: 200,
            message: "操作成功".into(),
            data: Some(data),
            error_type: None,
            decision: None,
            reason_code: None,
            required_permission: None,
            request_path: None,
            request_method: None,
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
            trace_id: None,
        }
    }

    /// 成功响应（无数据）
    pub fn ok() -> Self
    where
        T: Default,
    {
        Self {
            success: true,
            code: 200,
            message: "操作成功".into(),
            data: None,
            error_type: None,
            decision: None,
            reason_code: None,
            required_permission: None,
            request_path: None,
            request_method: None,
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
            trace_id: None,
        }
    }

    /// 失败响应（对齐 Java ApiResponse.error(code, message)）
    pub fn error(code: i32, message: impl Into<String>) -> Self
    where
        T: Default,
    {
        Self {
            success: false,
            code,
            message: message.into(),
            data: None,
            error_type: None,
            decision: None,
            reason_code: None,
            required_permission: None,
            request_path: None,
            request_method: None,
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
            trace_id: None,
        }
    }

    /// 创建权限拒绝响应（含 errorType / decision / reasonCode）
    pub fn permission_denied(reason: &str, message: impl Into<String>) -> Self
    where
        T: Default,
    {
        Self {
            success: false,
            code: 403,
            message: message.into(),
            data: None,
            error_type: Some("PERMISSION_DENIED".into()),
            decision: Some(reason.to_string()),
            reason_code: Some(reason.to_string()),
            required_permission: None,
            request_path: None,
            request_method: None,
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
            trace_id: None,
        }
    }

    /// 设置追踪 ID
    pub fn with_trace_id(mut self, trace_id: String) -> Self {
        self.trace_id = Some(trace_id);
        self
    }
}

impl<T: Serialize + Default> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        let status = if self.success {
            StatusCode::OK
        } else {
            StatusCode::from_u16(self.code as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        };
        (status, Json(self)).into_response()
    }
}

/// 分页响应（对齐 Java PageResult / Spring Data Page 格式）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub size: i64,
    /// 总页数
    pub total_pages: i64,
}

impl<T: Serialize> PageResponse<T> {
    pub fn new(items: Vec<T>, total: i64, page: i64, size: i64) -> Self {
        let total_pages = if size > 0 {
            (total + size - 1) / size
        } else {
            0
        };
        Self {
            items,
            total,
            page,
            size,
            total_pages,
        }
    }
}

/// 空响应体（用于 ApiResponse<T> 的 T 占位）
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EmptyResponse;

/// 分页查询参数（从 query string 提取）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams {
    /// 页码（从 1 开始，默认 1）
    #[serde(default = "default_page")]
    pub page: i64,
    /// 每页条数（默认 20，最大 100）
    #[serde(default = "default_size")]
    pub size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_size() -> i64 {
    20
}

impl PaginationParams {
    /// 获取安全的 offset（从 0 开始）
    pub fn offset(&self) -> i64 {
        (self.page.max(1) - 1) * self.effective_size()
    }

    /// 获取安全的每页条数（限制在 1..=100）
    pub fn effective_size(&self) -> i64 {
        self.size.clamp(1, 100)
    }
}
