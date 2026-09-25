//! 条件评估器
//!
//! 策略规则可以附加条件（如时间范围、IP 范围、设备类型等），只有条件
//! 满足时规则才生效。`ConditionEvaluator` trait 定义了条件评估接口。

use astral_types::{PolicyContext, ResourceOwnershipScope};

/// 条件评估器 trait
#[async_trait::async_trait]
pub trait ConditionEvaluator: Send + Sync {
    /// 返回此评估器支持的条件类型名称
    fn condition_type(&self) -> &'static str;

    /// 评估条件是否满足
    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError>;
}

/// 条件定义
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "conditionType", alias = "condition_type")]
    pub condition_type: String,
    /// 条件参数，例如 `{ "start": "08:00", "end": "18:00" }`
    pub params: serde_json::Value,
}

/// 条件错误
#[derive(Debug, thiserror::Error)]
pub enum ConditionError {
    #[error("Unknown condition type: {0}")]
    UnknownType(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Evaluation failed: {0}")]
    Evaluation(String),
}

/// 条件组（布尔组合）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConditionGroup {
    AllOf(Vec<Condition>),
    AnyOf(Vec<Condition>),
    Not(Box<Condition>),
}

// ===== 内置条件实现 =====

/// 时间范围条件：只在指定时间段内生效
pub struct TimeRangeCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for TimeRangeCondition {
    fn condition_type(&self) -> &'static str {
        "TimeRangeCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        _ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let start = condition
            .params
            .get("start")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'start'".into()))?;
        let end = condition
            .params
            .get("end")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'end'".into()))?;

        // 对齐 Java `isInTimeRange`：按 HH:mm 分钟精度比较，支持跨午夜（start > end 回绕）。
        let offset = condition
            .params
            .get("timezone")
            .or_else(|| condition.params.get("timeZone"))
            .map(parse_fixed_offset)
            .transpose()?;
        let now = time::OffsetDateTime::now_utc().to_offset(offset.unwrap_or(time::UtcOffset::UTC));
        let now_minutes = (now.hour() as i64) * 60 + now.minute() as i64;
        let parse_minutes = |value: &str| -> Result<i64, ConditionError> {
            let (h, m) = value
                .split_once(':')
                .ok_or_else(|| ConditionError::InvalidParams(format!("bad time '{value}'")))?;
            let hour: i64 = h
                .parse()
                .map_err(|_| ConditionError::InvalidParams(format!("bad hour in '{value}'")))?;
            let minute: i64 = m
                .parse()
                .map_err(|_| ConditionError::InvalidParams(format!("bad minute in '{value}'")))?;
            if !(0..24).contains(&hour) || !(0..60).contains(&minute) {
                return Err(ConditionError::InvalidParams(format!(
                    "out of range '{value}'"
                )));
            }
            Ok(hour * 60 + minute)
        };
        let start_minutes = parse_minutes(start)?;
        let end_minutes = parse_minutes(end)?;

        Ok(time_range_matches(now_minutes, start_minutes, end_minutes))
    }
}

/// 固定 UTC 偏移解析：仅支持 UTC、Z 和 `+/-HH:mm`/`+/-HHmm`。
/// 时区数据库名称需要外部 provider，当前 API 不具备该能力，故明确拒绝。
fn parse_fixed_offset(value: &serde_json::Value) -> Result<time::UtcOffset, ConditionError> {
    let value = value
        .as_str()
        .ok_or_else(|| ConditionError::InvalidParams("timezone must be a string".into()))?;
    if value.eq_ignore_ascii_case("UTC") || value == "Z" {
        return Ok(time::UtcOffset::UTC);
    }

    let (sign, digits) = match value.as_bytes().first() {
        Some(b'+') => (1, &value[1..]),
        Some(b'-') => (-1, &value[1..]),
        _ => {
            return Err(ConditionError::InvalidParams(format!(
                "unsupported timezone '{value}'; use UTC or a fixed offset"
            )))
        }
    };
    let (hours, minutes) = if let Some((hours, minutes)) = digits.split_once(':') {
        (hours, minutes)
    } else if digits.len() == 4 {
        (&digits[..2], &digits[2..])
    } else {
        return Err(ConditionError::InvalidParams(format!(
            "bad timezone offset '{value}'"
        )));
    };
    let hours: i8 = hours
        .parse()
        .map_err(|_| ConditionError::InvalidParams(format!("bad timezone offset '{value}'")))?;
    let minutes: i8 = minutes
        .parse()
        .map_err(|_| ConditionError::InvalidParams(format!("bad timezone offset '{value}'")))?;
    time::UtcOffset::from_hms(sign * hours, sign * minutes, 0).map_err(|_| {
        ConditionError::InvalidParams(format!("timezone offset out of range '{value}'"))
    })
}

fn time_range_matches(now_minutes: i64, start_minutes: i64, end_minutes: i64) -> bool {
    if start_minutes <= end_minutes {
        now_minutes >= start_minutes && now_minutes <= end_minutes
    } else {
        // 跨午夜：22:00-02:00 → now >= 22:00 || now <= 02:00
        now_minutes >= start_minutes || now_minutes <= end_minutes
    }
}

/// IP 范围条件
pub struct IpRangeCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for IpRangeCondition {
    fn condition_type(&self) -> &'static str {
        "IpRangeCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let allowed_ranges = condition
            .params
            .get("ranges")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'ranges'".into()))?;

        let client_ip = ctx
            .ip
            .as_deref()
            .ok_or_else(|| ConditionError::InvalidParams("no client IP in context".into()))?;

        for range in allowed_ranges {
            if let Some(ip) = range.as_str() {
                if ip == client_ip {
                    return Ok(true);
                }
                // 对齐 Java `ipMatchesCidr`：支持 1.2.3.0/24 形式
                if let Some((prefix, prefix_len)) = ip.split_once('/') {
                    if let Ok(mask_bits) = prefix_len.parse::<u8>() {
                        if (1..=32).contains(&mask_bits)
                            && ip_matches_cidr(client_ip, prefix, mask_bits)
                        {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

/// IPv4 CIDR 匹配（对齐 Java `ipToLong` + `ipMatchesCidr`）；非法输入返回 false（fail-closed）
fn ip_matches_cidr(ip: &str, prefix: &str, mask_bits: u8) -> bool {
    let (Some(ip_long), Some(prefix_long)) = (ipv4_to_u32(ip), ipv4_to_u32(prefix)) else {
        return false;
    };
    let mask = if mask_bits == 0 {
        0u32
    } else {
        u32::MAX << (32 - mask_bits)
    };
    (ip_long & mask) == (prefix_long & mask)
}

fn ipv4_to_u32(ip: &str) -> Option<u32> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut result: u32 = 0;
    for octet in octets {
        let value: u32 = octet.parse().ok()?;
        if value > 255 {
            return None;
        }
        result = (result << 8) | value;
    }
    Some(result)
}

/// 速率限制条件：检查请求频率是否在阈值内
///
/// 参数示例：`{ "max_requests": 100, "window_seconds": 60 }`
/// 实际限流由 governor + Redis 实现，此处仅做上下文校验
pub struct RateLimitCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for RateLimitCondition {
    fn condition_type(&self) -> &'static str {
        "RateLimitCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        _ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let max_requests = condition
            .params
            .get("max_requests")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'max_requests'".into()))?;

        if max_requests == 0 {
            return Ok(false); // 阈值为 0 直接拒绝
        }

        // 条件求值必须拿到当前窗口计数；Gateway 的全局 IP 限流并不等价于
        // 规则自己的 max_requests/window_seconds。未知计数不能按 ALLOW 处理。
        let current_count = _ctx
            .request
            .as_ref()
            .and_then(|request| request.get("rateLimitCount"))
            .and_then(|value| value.as_u64())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'rateLimitCount'".into()))?;
        Ok(current_count < max_requests)
    }
}

/// 设备类型条件：检查请求来源设备类型
///
/// 参数示例：`{ "allowed_devices": ["mobile", "desktop"] }`
pub struct DeviceTypeCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for DeviceTypeCondition {
    fn condition_type(&self) -> &'static str {
        "DeviceTypeCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let allowed = condition
            .params
            .get("allowed_devices")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'allowed_devices'".into()))?;

        let user_agent = ctx
            .user_agent
            .as_deref()
            .ok_or_else(|| ConditionError::InvalidParams("no user_agent in context".into()))?;

        let device_type = detect_device_type(user_agent).ok_or_else(|| {
            ConditionError::InvalidParams("unrecognized user_agent device type".into())
        })?;
        for device in allowed {
            if let Some(d) = device.as_str() {
                let normalized = d.trim().to_uppercase();
                if normalized == "*"
                    || normalized == device_type
                    || (normalized == "WEB" && device_type == "DESKTOP")
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// 根据 user-agent 猜测设备类型
fn detect_device_type(user_agent: &str) -> Option<&'static str> {
    let ua = user_agent.to_lowercase();
    if ua.contains("mobile")
        || ua.contains("android")
        || ua.contains("iphone")
        || ua.contains("ipad")
    {
        Some("MOBILE")
    } else if ua.contains("windows nt")
        || ua.contains("macintosh")
        || ua.contains("x11")
        || ua.contains("cros")
        || ua.contains("linux x86_64")
    {
        Some("DESKTOP")
    } else {
        None
    }
}

/// 资源属性条件：检查资源的特定属性是否满足条件
///
/// 参数示例：`{ "attribute": "sensitivity", "operator": "lte", "value": 2 }`。
/// Java `resourceProperty` 数组会归一化为 `conditions`，要求每一项都满足。
pub struct ResourcePropertyCondition;

impl ResourcePropertyCondition {
    fn evaluate_params(
        params: &serde_json::Value,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        if let Some(conditions) = params.get("conditions").and_then(|value| value.as_array()) {
            if conditions.is_empty() {
                return Err(ConditionError::InvalidParams(
                    "resourceProperty conditions must not be empty".into(),
                ));
            }
            for condition in conditions {
                if !Self::evaluate_single(condition, ctx)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        Self::evaluate_single(params, ctx)
    }

    fn evaluate_single(
        params: &serde_json::Value,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let attr = params
            .get("field")
            .or_else(|| params.get("attribute"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'field'".into()))?;
        let operator = params
            .get("op")
            .or_else(|| params.get("operator"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'op'".into()))?;
        let value = params
            .get("value")
            .ok_or_else(|| ConditionError::InvalidParams("missing 'value'".into()))?;

        match attr {
            "sensitivity" => {
                let sensitivity = ctx.sensitivity_level.ok_or_else(|| {
                    ConditionError::InvalidParams("missing resource sensitivity".into())
                })? as i64;
                let target = value.as_i64().ok_or_else(|| {
                    ConditionError::InvalidParams("sensitivity value must be integer".into())
                })?;
                Ok(match operator {
                    "eq" => sensitivity == target,
                    "lt" => sensitivity < target,
                    "lte" => sensitivity <= target,
                    "gt" => sensitivity > target,
                    "gte" => sensitivity >= target,
                    _ => {
                        return Err(ConditionError::InvalidParams(format!(
                            "unknown operator: {operator}"
                        )))
                    }
                })
            }
            _ => Err(ConditionError::UnknownType(format!(
                "unknown attribute: {attr}"
            ))),
        }
    }
}

#[async_trait::async_trait]
impl ConditionEvaluator for ResourcePropertyCondition {
    fn condition_type(&self) -> &'static str {
        "ResourcePropertyCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        Self::evaluate_params(&condition.params, ctx)
    }
}

/// 资源所有者条件：仅资源所属者允许访问
///
/// 参数：不需要额外参数（`{}`），通过 `ctx.user_id` 与资源关联判断
pub struct OwnerOnlyCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for OwnerOnlyCondition {
    fn condition_type(&self) -> &'static str {
        "OwnerOnlyCondition"
    }

    async fn evaluate(
        &self,
        _condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let user_id = ctx
            .user_id
            .ok_or_else(|| ConditionError::InvalidParams("no user_id in context".into()))?;
        // OwnerOnly 只接受由授权目标资源派生的 owner fact；缺失即拒绝。
        let owner_id = ctx.resource_owner_id.ok_or_else(|| {
            ConditionError::InvalidParams("no authoritative resource owner in context".into())
        })?;
        Ok(owner_id == user_id)
    }
}

/// 租户归属条件：检查资源是否属于请求者的租户
///
/// 参数：服务端规则中可选的固定 `resource_tenant_id`，或由权威 resolver
/// 写入 `ctx.resource_tenant_id`。请求 body/header 绝不能成为资源租户事实。
///
/// 评估逻辑：
/// 1. 尝试从服务端规则参数 `condition.params.resource_tenant_id` 读取固定目标租户；
/// 2. 否则只接受 `TenantScoped` context 的权威 `ctx.resource_tenant_id`；
/// 3. 与 `ctx.tenant_id`（请求者所属租户）比较。
pub struct BelongsToTenantCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for BelongsToTenantCondition {
    fn condition_type(&self) -> &'static str {
        "BelongsToTenantCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        // Java-compatible `belongsToTenant` remains a caller-context predicate
        // only for in-process typed compatibility calls. External HTTP requests
        // must compare the resolver's target tenant instead of treating the
        // actor tenant itself as resource ownership.
        if condition
            .params
            .get("java_semantics")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return match ctx.resource_ownership_scope {
                ResourceOwnershipScope::TenantScoped => Ok(ctx
                    .tenant_id
                    .is_some_and(|tenant_id| Some(tenant_id) == ctx.resource_tenant_id)),
                ResourceOwnershipScope::Internal => Ok(ctx.tenant_id.is_some()),
                ResourceOwnershipScope::Global
                | ResourceOwnershipScope::Unresolved
                | ResourceOwnershipScope::Unavailable => Ok(false),
            };
        }

        let user_tenant_id = ctx
            .tenant_id
            .ok_or_else(|| ConditionError::InvalidParams("no tenant_id in context".into()))?;

        // A rule-managed literal is trusted policy data. Otherwise the resource
        // tenant must be the server-side resolver's target fact; request body
        // values are deliberately never consulted.
        let resource_tenant_id = condition
            .params
            .get("resource_tenant_id")
            .and_then(|value| value.as_i64())
            .or_else(|| {
                matches!(
                    ctx.resource_ownership_scope,
                    ResourceOwnershipScope::TenantScoped
                )
                .then_some(ctx.resource_tenant_id)
                .flatten()
            })
            .ok_or_else(|| {
                ConditionError::InvalidParams(
                    "cannot determine authoritative resource tenant_id".into(),
                )
            })?;

        // 核心比较：用户租户 ID 必须等于资源租户 ID
        let belongs = user_tenant_id == resource_tenant_id;
        tracing::debug!(
            user_tenant_id,
            resource_tenant_id,
            belongs,
            "BelongsToTenantCondition evaluated"
        );
        Ok(belongs)
    }
}

/// 权限范围条件：OAuth 风格 scope 检查
///
/// 参数示例：`{ "required_scopes": ["learn:read", "learn:write"] }`
pub struct ScopeCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for ScopeCondition {
    fn condition_type(&self) -> &'static str {
        "ScopeCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        // Java 格式 `{"scope":"SELF"}` / `{"scope":"TENANT"}` 归一化后的语义：
        // SELF → 调用方已认证（有 userId）；TENANT → 调用方有 tenantId
        // （对齐 Java ConditionEvaluator）。Rust 原生 required_scopes 不受影响。
        if let Some(java_scope) = condition.params.get("java_scope").and_then(|v| v.as_str()) {
            return Ok(match java_scope.to_uppercase().as_str() {
                "SELF" => ctx.user_id.is_some(),
                "TENANT" => ctx.tenant_id.is_some(),
                _ => false, // 未知 scope 值 → deny（对齐 Java 默认 deny）
            });
        }

        let required = condition
            .params
            .get("required_scopes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'required_scopes'".into()))?;

        let granted = &ctx.action_codes;

        if granted.is_empty() {
            return Ok(false);
        }

        for scope in required {
            let scope_str = scope
                .as_str()
                .ok_or_else(|| ConditionError::InvalidParams("scope must be string".into()))?;
            // 通配符匹配：scope = "learn:*" 匹配 "learn:read", "learn:write" 等
            if let Some(prefix) = scope_str.strip_suffix(":*") {
                if !granted.iter().any(|g| g.starts_with(prefix)) {
                    return Ok(false);
                }
            } else if !granted.contains(&scope_str.to_string()) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// 条件注册表：根据条件类型名创建评估器实例
///
/// 同时支持 PascalCase（Rust 原生）和小写别名（Java 兼容）：
/// - `"timeRange"` / `"TimeRangeCondition"` → TimeRangeCondition
/// - `"ownerOnly"` / `"OwnerOnlyCondition"` → OwnerOnlyCondition
pub fn evaluator_for(condition_type: &str) -> Result<Box<dyn ConditionEvaluator>, ConditionError> {
    // 小写别名 → PascalCase 映射
    let normalized = match condition_type {
        "timeRange" | "TimeRangeCondition" => "TimeRangeCondition",
        "ipRange" | "IpRangeCondition" => "IpRangeCondition",
        "rateLimit" | "RateLimitCondition" => "RateLimitCondition",
        "deviceType" | "DeviceTypeCondition" => "DeviceTypeCondition",
        "resourceProperty" | "ResourcePropertyCondition" => "ResourcePropertyCondition",
        "ownerOnly" | "OwnerOnlyCondition" => "OwnerOnlyCondition",
        "belongsToTenant" | "BelongsToTenantCondition" => "BelongsToTenantCondition",
        "scope" | "ScopeCondition" => "ScopeCondition",
        _ => return Err(ConditionError::UnknownType(condition_type.to_string())),
    };

    match normalized {
        "TimeRangeCondition" => Ok(Box::new(TimeRangeCondition)),
        "IpRangeCondition" => Ok(Box::new(IpRangeCondition)),
        "RateLimitCondition" => Ok(Box::new(RateLimitCondition)),
        "DeviceTypeCondition" => Ok(Box::new(DeviceTypeCondition)),
        "ResourcePropertyCondition" => Ok(Box::new(ResourcePropertyCondition)),
        "OwnerOnlyCondition" => Ok(Box::new(OwnerOnlyCondition)),
        "BelongsToTenantCondition" => Ok(Box::new(BelongsToTenantCondition)),
        "ScopeCondition" => Ok(Box::new(ScopeCondition)),
        _ => unreachable!(),
    }
}

/// 条件 JSON 归一化（Java 顶层键格式 → Rust 内部格式）
///
/// Java 权威基线（`ConditionEvaluator.matches`）以**顶层键**存储条件 JSON：
/// - `{"timeRange":{"start":"09:00","end":"18:00"}}`
/// - `{"ownerOnly":true}`
/// - `{"ipRange":["1.2.3.4","10.0.0.0/8"]}`
/// - `{"deviceType":["mobile","desktop"]}`
/// - `{"rateLimit":{"maxRequests":100,"windowSeconds":60}}`
/// - `{"resourceProperty":[{"attribute":"sensitivity","operator":"lte","value":2}]}`
/// - `{"belongsToTenant":true}` / `{"scope":"SELF"}`
/// - `{"conditionGroup":{"allOf":[{"ownerOnly":true},...]}}`
///
/// Rust 内部格式为 `{"conditionType":"...","params":{...}}`。本函数把 Java 顶层键
/// 格式归一化为 Rust `ConditionGroup`，供 `evaluate_entry_condition_raw` /
/// `has_runtime_condition` 统一消费。无法识别时返回 `None`（fail-closed）。
pub fn normalize_condition_json(json: &serde_json::Value) -> Option<ConditionGroup> {
    let object = json.as_object()?;

    // Rust 内部单条件格式，必须只包含 conditionType/condition_type + params。
    if object.contains_key("conditionType") || object.contains_key("condition_type") {
        let allowed = ["conditionType", "condition_type", "params"];
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return None;
        }
        return serde_json::from_value::<Condition>(json.clone())
            .ok()
            .map(|cond| ConditionGroup::AllOf(vec![cond]));
    }

    // Rust 内部条件组格式：只接受恰好一个操作键。
    if object
        .keys()
        .any(|key| matches!(key.as_str(), "allOf" | "anyOf" | "not"))
    {
        return normalize_rust_group(json);
    }

    // Java `conditionGroup` 顶层键：{"allOf":[...]} / {"anyOf":[...]} / {"not":{...}}
    if let Some(group) = json.get("conditionGroup") {
        if object.len() != 1 {
            return None;
        }
        return normalize_java_group(group);
    }

    let known_keys = [
        "timeRange",
        "ipRange",
        "rateLimit",
        "deviceType",
        "resourceProperty",
        "ownerOnly",
        "belongsToTenant",
        "scope",
    ];
    // Java 顶层键格式：任何未知键都使整个条件无效，不能命中首项后丢弃其余约束。
    if object.keys().any(|key| !known_keys.contains(&key.as_str())) {
        return None;
    }

    // 多个已知顶层键按 Java 语义 AND。
    let mut conditions = Vec::new();
    for key in known_keys {
        if let Some(value) = json.get(key) {
            conditions.push(normalize_java_single(key, value)?);
        }
    }
    if !conditions.is_empty() {
        return Some(ConditionGroup::AllOf(conditions));
    }

    None
}

/// Java `conditionGroup` 内部：`{"allOf":[...]}` / `{"anyOf":[...]}` / `{"not":{...}}`
fn normalize_java_group(group: &serde_json::Value) -> Option<ConditionGroup> {
    let object = group.as_object()?;
    if object.len() != 1
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "allOf" | "anyOf" | "not"))
    {
        return None;
    }
    if let Some(items) = group.get("allOf").and_then(|v| v.as_array()) {
        if items.is_empty() {
            return None;
        }
        let conds = items
            .iter()
            .map(normalize_java_condition_item)
            .collect::<Option<Vec<Condition>>>()?;
        return Some(ConditionGroup::AllOf(conds));
    }
    if let Some(items) = group.get("anyOf").and_then(|v| v.as_array()) {
        if items.is_empty() {
            return None;
        }
        let conds = items
            .iter()
            .map(normalize_java_condition_item)
            .collect::<Option<Vec<Condition>>>()?;
        return Some(ConditionGroup::AnyOf(conds));
    }
    if let Some(item) = group.get("not") {
        let cond = normalize_java_condition_item(item)?;
        return Some(ConditionGroup::Not(Box::new(cond)));
    }
    None
}

fn normalize_rust_group(group: &serde_json::Value) -> Option<ConditionGroup> {
    let object = group.as_object()?;
    if object.len() != 1 {
        return None;
    }
    if object
        .get("allOf")
        .or_else(|| object.get("anyOf"))
        .and_then(|value| value.as_array())
        .is_some_and(Vec::is_empty)
    {
        return None;
    }
    serde_json::from_value(group.clone()).ok()
}

/// Java 组内单个条件条目（可能仍是顶层键形式，也可能是嵌套 conditionGroup）
fn normalize_java_condition_item(item: &serde_json::Value) -> Option<Condition> {
    let object = item.as_object()?;
    let known_keys = [
        "timeRange",
        "ipRange",
        "rateLimit",
        "deviceType",
        "resourceProperty",
        "ownerOnly",
        "belongsToTenant",
        "scope",
    ];
    // 当前内部 ConditionGroup 只能承载单条件；嵌套组和混合键必须拒绝。
    if object.len() != 1 {
        return None;
    }
    let (key, value) = object.iter().next()?;
    if !known_keys.contains(&key.as_str()) {
        return None;
    }
    normalize_java_single(key, value)
}

/// 单个 Java 顶层键条件 → Rust `Condition`
fn normalize_java_single(key: &str, value: &serde_json::Value) -> Option<Condition> {
    let (condition_type, params) = match key {
        "timeRange" => {
            let start = value.get("start").and_then(|v| v.as_str())?;
            let end = value.get("end").and_then(|v| v.as_str())?;
            (
                "TimeRangeCondition",
                serde_json::json!({ "start": start, "end": end }),
            )
        }
        "ownerOnly" => {
            if value.as_bool() != Some(true) {
                return None;
            }
            ("OwnerOnlyCondition", serde_json::json!({}))
        }
        "ipRange" => {
            let ranges = value.as_array()?;
            ("IpRangeCondition", serde_json::json!({ "ranges": ranges }))
        }
        "rateLimit" => {
            let max_requests = value.get("maxRequests").and_then(|v| v.as_u64())?;
            let window_seconds = value.get("windowSeconds").and_then(|v| v.as_u64())?;
            (
                "RateLimitCondition",
                serde_json::json!({ "max_requests": max_requests, "window_seconds": window_seconds }),
            )
        }
        "deviceType" => {
            let allowed = value.as_array()?;
            (
                "DeviceTypeCondition",
                serde_json::json!({ "allowed_devices": allowed }),
            )
        }
        "resourceProperty" => {
            // Java payload: [{"field":"status","op":"eq","value":"PUBLISHED"}].
            // 全部属性约束必须保留，并由 ResourcePropertyCondition 逐项 AND。
            let conditions = value.as_array()?;
            if conditions.is_empty() {
                return None;
            }
            (
                "ResourcePropertyCondition",
                serde_json::json!({ "conditions": conditions }),
            )
        }
        "belongsToTenant" => {
            if value.as_bool() != Some(true) {
                return None;
            }
            // Java 语义：仅要求调用方有 tenantId（java_semantics 标记短路精确比对）
            (
                "BelongsToTenantCondition",
                serde_json::json!({ "java_semantics": true }),
            )
        }
        "scope" => {
            let scope = value.as_str()?;
            // Java 语义：SELF → 有 userId；TENANT → 有 tenantId
            (
                "ScopeCondition",
                serde_json::json!({ "java_scope": scope.to_uppercase() }),
            )
        }
        _ => return None,
    };
    Some(Condition {
        condition_type: condition_type.to_string(),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_time_range() {
        let evaluator = TimeRangeCondition;
        let condition = Condition {
            condition_type: "TimeRangeCondition".into(),
            params: serde_json::json!({ "start": "00:00", "end": "23:59" }),
        };
        let ctx = PolicyContext::builder().action("read".into()).build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_ip_range_match() {
        let evaluator = IpRangeCondition;
        let condition = Condition {
            condition_type: "IpRangeCondition".into(),
            params: serde_json::json!({ "ranges": ["192.168.1.1", "10.0.0.1"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .ip(Some("192.168.1.1".into()))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_ip_range_no_match() {
        let evaluator = IpRangeCondition;
        let condition = Condition {
            condition_type: "IpRangeCondition".into(),
            params: serde_json::json!({ "ranges": ["192.168.1.1"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .ip(Some("10.0.0.1".into()))
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_rate_limit_zero_blocks() {
        let evaluator = RateLimitCondition;
        let condition = Condition {
            condition_type: "RateLimitCondition".into(),
            params: serde_json::json!({ "max_requests": 0 }),
        };
        let ctx = PolicyContext::builder().action("read".into()).build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_device_type_mobile() {
        let evaluator = DeviceTypeCondition;
        let condition = Condition {
            condition_type: "DeviceTypeCondition".into(),
            params: serde_json::json!({ "allowed_devices": ["mobile"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_agent(Some(
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36".into(),
            ))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_device_type_desktop_blocked() {
        let evaluator = DeviceTypeCondition;
        let condition = Condition {
            condition_type: "DeviceTypeCondition".into(),
            params: serde_json::json!({ "allowed_devices": ["mobile"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_agent(Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120".into(),
            ))
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_resource_property_sensitivity() {
        let evaluator = ResourcePropertyCondition;
        let condition = Condition {
            condition_type: "ResourcePropertyCondition".into(),
            params: serde_json::json!({ "attribute": "sensitivity", "operator": "lte", "value": 2 }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .sensitivity_level(Some(1))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_resource_property_array_requires_all_items() {
        let evaluator = ResourcePropertyCondition;
        let condition = Condition {
            condition_type: "ResourcePropertyCondition".into(),
            params: serde_json::json!({
                "conditions": [
                    {"field": "sensitivity", "op": "gte", "value": 1},
                    {"field": "sensitivity", "op": "eq", "value": 2}
                ]
            }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .sensitivity_level(Some(1))
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_owner_only_no_target_id() {
        let evaluator = OwnerOnlyCondition;
        let condition = Condition {
            condition_type: "OwnerOnlyCondition".into(),
            params: serde_json::json!({}),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_id(Some(42))
            .build();
        let error = evaluator.evaluate(&condition, &ctx).await.unwrap_err();
        assert!(matches!(
            error,
            ConditionError::InvalidParams(message)
                if message.contains("authoritative resource owner")
        ));
    }

    #[tokio::test]
    async fn test_owner_only_with_target_id() {
        let evaluator = OwnerOnlyCondition;
        let condition = Condition {
            condition_type: "OwnerOnlyCondition".into(),
            params: serde_json::json!({}),
        };
        // 对齐 Java ConditionEvaluator.ownerOnly：resourceOwnerId == currentUserId → allow
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_id(Some(42))
            .target_id(Some(100))
            .resource_owner_id(Some(42))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_owner_only_owner_mismatch_is_denied() {
        let evaluator = OwnerOnlyCondition;
        let condition = Condition {
            condition_type: "OwnerOnlyCondition".into(),
            params: serde_json::json!({}),
        };
        // 属主与当前用户不一致 → deny（fail-closed，此前仅查 target_id 存在属越权）
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_id(Some(42))
            .target_id(Some(100))
            .resource_owner_id(Some(43))
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_scope_exact_match() {
        let evaluator = ScopeCondition;
        let condition = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "required_scopes": ["learn:read"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .action_codes(vec!["learn:read".into(), "learn:write".into()])
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_scope_wildcard_match() {
        let evaluator = ScopeCondition;
        let condition = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "required_scopes": ["learn:*"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .action_codes(vec!["learn:read".into()])
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_scope_no_match() {
        let evaluator = ScopeCondition;
        let condition = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "required_scopes": ["admin:*"] }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .action_codes(vec!["learn:read".into()])
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_match() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({ "resource_tenant_id": 42 }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(42))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_mismatch() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({ "resource_tenant_id": 99 }),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(42))
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_no_tenant_in_ctx() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({ "resource_tenant_id": 42 }),
        };
        let ctx = PolicyContext::builder().action("read".into()).build();
        assert!(evaluator.evaluate(&condition, &ctx).await.is_err());
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_no_resource_tenant_id() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({}),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(42))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.is_err());
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_request_body_is_not_an_ownership_source() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({}),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(7))
            .request(Some(serde_json::json!({ "resource_tenant_id": 7 })))
            .build();
        let error = evaluator.evaluate(&condition, &ctx).await.unwrap_err();
        assert!(matches!(
            error,
            ConditionError::InvalidParams(message)
                if message.contains("authoritative resource tenant_id")
        ));
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_accepts_only_tenant_scoped_resolver_facts() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({}),
        };
        let matching = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(7))
            .resource_tenant_id(Some(7))
            .resource_ownership_scope(astral_types::ResourceOwnershipScope::TenantScoped)
            .request(Some(serde_json::json!({ "resource_tenant_id": 8 })))
            .build();
        assert!(evaluator.evaluate(&condition, &matching).await.unwrap());

        let mismatching = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(7))
            .resource_tenant_id(Some(8))
            .resource_ownership_scope(astral_types::ResourceOwnershipScope::TenantScoped)
            .request(Some(serde_json::json!({ "target_tenant_id": 7 })))
            .build();
        assert!(!evaluator.evaluate(&condition, &mismatching).await.unwrap());
    }

    #[tokio::test]
    async fn test_belongs_to_tenant_ignores_target_tenant_request_field() {
        let evaluator = BelongsToTenantCondition;
        let condition = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({}),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(5))
            .request(Some(serde_json::json!({ "target_tenant_id": 5 })))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.is_err());
    }

    #[tokio::test]
    async fn test_evaluator_registry() {
        assert!(evaluator_for("TimeRangeCondition").is_ok());
        assert!(evaluator_for("IpRangeCondition").is_ok());
        assert!(evaluator_for("RateLimitCondition").is_ok());
        assert!(evaluator_for("DeviceTypeCondition").is_ok());
        assert!(evaluator_for("ResourcePropertyCondition").is_ok());
        assert!(evaluator_for("OwnerOnlyCondition").is_ok());
        assert!(evaluator_for("BelongsToTenantCondition").is_ok());
        assert!(evaluator_for("ScopeCondition").is_ok());
        assert!(evaluator_for("UnknownCondition").is_err());
    }

    #[tokio::test]
    async fn test_evaluator_lowercase_aliases() {
        // Java 兼容的小写别名
        assert!(evaluator_for("timeRange").is_ok());
        assert!(evaluator_for("ipRange").is_ok());
        assert!(evaluator_for("rateLimit").is_ok());
        assert!(evaluator_for("deviceType").is_ok());
        assert!(evaluator_for("resourceProperty").is_ok());
        assert!(evaluator_for("ownerOnly").is_ok());
        assert!(evaluator_for("belongsToTenant").is_ok());
        assert!(evaluator_for("scope").is_ok());
    }

    // ===== Java 顶层键格式归一化 =====

    #[test]
    fn normalize_java_time_range() {
        let json = serde_json::json!({"timeRange": {"start": "09:00", "end": "18:00"}});
        let group = normalize_condition_json(&json).expect("Java timeRange must normalize");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds.len(), 1);
                assert_eq!(conds[0].condition_type, "TimeRangeCondition");
                assert_eq!(conds[0].params["start"], "09:00");
                assert_eq!(conds[0].params["end"], "18:00");
            }
            _ => panic!("expected AllOf"),
        }
    }

    #[test]
    fn normalize_java_owner_only() {
        let json = serde_json::json!({"ownerOnly": true});
        let group = normalize_condition_json(&json).expect("Java ownerOnly must normalize");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds[0].condition_type, "OwnerOnlyCondition");
            }
            _ => panic!("expected AllOf"),
        }
    }

    #[test]
    fn normalize_java_owner_only_false_is_none() {
        let json = serde_json::json!({"ownerOnly": false});
        assert!(normalize_condition_json(&json).is_none());
    }

    #[test]
    fn normalize_java_condition_group_all_of() {
        let json = serde_json::json!({
            "conditionGroup": {
                "allOf": [
                    {"ownerOnly": true},
                    {"timeRange": {"start": "00:00", "end": "23:59"}}
                ]
            }
        });
        let group = normalize_condition_json(&json).expect("Java conditionGroup must normalize");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds.len(), 2);
                assert_eq!(conds[0].condition_type, "OwnerOnlyCondition");
                assert_eq!(conds[1].condition_type, "TimeRangeCondition");
            }
            _ => panic!("expected AllOf"),
        }
    }

    #[test]
    fn normalize_java_ip_range_cidr() {
        let json = serde_json::json!({"ipRange": ["10.0.0.0/8", "1.2.3.4"]});
        let group = normalize_condition_json(&json).expect("Java ipRange must normalize");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds[0].condition_type, "IpRangeCondition");
                assert_eq!(conds[0].params["ranges"][0], "10.0.0.0/8");
            }
            _ => panic!("expected AllOf"),
        }
    }

    #[test]
    fn normalize_known_and_unknown_top_level_keys_is_none() {
        assert!(normalize_condition_json(&serde_json::json!({
            "timeRange": {"start": "09:00", "end": "18:00"},
            "unknownCondition": true
        }))
        .is_none());
    }

    #[test]
    fn normalize_condition_group_unknown_key_is_none() {
        assert!(normalize_condition_json(&serde_json::json!({
            "conditionGroup": {
                "allOf": [{"ownerOnly": true}],
                "unknownGroupKey": []
            }
        }))
        .is_none());
    }

    #[test]
    fn normalize_nested_condition_group_is_none() {
        assert!(normalize_condition_json(&serde_json::json!({
            "conditionGroup": {
                "allOf": [
                    {"conditionGroup": {"allOf": [{"ownerOnly": true}]}}
                ]
            }
        }))
        .is_none());
    }

    #[test]
    fn normalize_empty_condition_groups_is_none() {
        assert!(normalize_condition_json(&serde_json::json!({
            "conditionGroup": {"allOf": []}
        }))
        .is_none());
        assert!(normalize_condition_json(&serde_json::json!({"allOf": []})).is_none());
    }

    #[tokio::test]
    async fn ip_wildcard_does_not_match() {
        let evaluator = IpRangeCondition;
        let condition = Condition {
            condition_type: "IpRangeCondition".into(),
            params: serde_json::json!({"ranges": ["*"]}),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .ip(Some("192.0.2.1".into()))
            .build();
        assert!(!evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn unknown_user_agent_does_not_default_to_desktop() {
        let evaluator = DeviceTypeCondition;
        let condition = Condition {
            condition_type: "DeviceTypeCondition".into(),
            params: serde_json::json!({"allowed_devices": ["desktop"]}),
        };
        let ctx = PolicyContext::builder()
            .action("read".into())
            .user_agent(Some("SomeUnknownClient/1.0".into()))
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.is_err());
    }

    #[test]
    fn cross_midnight_and_minute_boundaries_are_preserved() {
        assert!(time_range_matches(22 * 60, 22 * 60, 2 * 60));
        assert!(time_range_matches(2 * 60, 22 * 60, 2 * 60));
        assert!(!time_range_matches(2 * 60 + 1, 22 * 60, 2 * 60));
        assert!(time_range_matches(12 * 60, 12 * 60, 12 * 60));
        assert!(!time_range_matches(12 * 60 + 1, 12 * 60, 12 * 60));
    }

    #[test]
    fn fixed_offset_timezone_is_supported_but_named_zone_is_not() {
        assert!(parse_fixed_offset(&serde_json::json!("+08:00")).is_ok());
        assert!(parse_fixed_offset(&serde_json::json!("Asia/Shanghai")).is_err());
    }

    #[test]
    fn normalize_rust_format_passthrough() {
        let json = serde_json::json!({
            "conditionType": "TimeRangeCondition",
            "params": {"start": "00:00", "end": "23:59"}
        });
        let group = normalize_condition_json(&json).expect("Rust format must pass through");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds[0].condition_type, "TimeRangeCondition");
            }
            _ => panic!("expected AllOf"),
        }
    }

    #[test]
    fn ip_cidr_matches() {
        assert!(ip_matches_cidr("10.1.2.3", "10.0.0.0", 8));
        assert!(ip_matches_cidr("192.168.1.100", "192.168.1.0", 24));
        assert!(!ip_matches_cidr("192.168.2.100", "192.168.1.0", 24));
        assert!(!ip_matches_cidr("not-an-ip", "10.0.0.0", 8));
    }

    // ===== Java 语义 scope / belongsToTenant =====

    #[tokio::test]
    async fn java_scope_self_requires_user_id() {
        let evaluator = ScopeCondition;
        let cond = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "java_scope": "SELF" }),
        };
        let with_user = PolicyContext::builder()
            .user_id(Some(1))
            .action("read".into())
            .build();
        assert!(evaluator.evaluate(&cond, &with_user).await.unwrap());
        let no_user = PolicyContext::builder().action("read".into()).build();
        assert!(!evaluator.evaluate(&cond, &no_user).await.unwrap());
    }

    #[tokio::test]
    async fn java_scope_tenant_requires_tenant_id() {
        let evaluator = ScopeCondition;
        let cond = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "java_scope": "TENANT" }),
        };
        let with_tenant = PolicyContext::builder()
            .tenant_id(Some(9))
            .action("read".into())
            .build();
        assert!(evaluator.evaluate(&cond, &with_tenant).await.unwrap());
        let no_tenant = PolicyContext::builder().action("read".into()).build();
        assert!(!evaluator.evaluate(&cond, &no_tenant).await.unwrap());
    }

    #[tokio::test]
    async fn java_scope_unknown_value_denies() {
        let evaluator = ScopeCondition;
        let cond = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "java_scope": "ORG" }),
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .tenant_id(Some(9))
            .action("read".into())
            .build();
        assert!(!evaluator.evaluate(&cond, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn java_belongs_to_tenant_requires_tenant_id() {
        let evaluator = BelongsToTenantCondition;
        let cond = Condition {
            condition_type: "BelongsToTenantCondition".into(),
            params: serde_json::json!({ "java_semantics": true }),
        };
        let with_tenant = PolicyContext::builder()
            .tenant_id(Some(9))
            .action("read".into())
            .build();
        assert!(evaluator.evaluate(&cond, &with_tenant).await.unwrap());
        let no_tenant = PolicyContext::builder().action("read".into()).build();
        assert!(!evaluator.evaluate(&cond, &no_tenant).await.unwrap());
    }

    #[test]
    fn normalize_java_scope_emits_java_semantics() {
        let json = serde_json::json!({"scope": "SELF"});
        let group = normalize_condition_json(&json).expect("scope must normalize");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds[0].condition_type, "ScopeCondition");
                assert_eq!(conds[0].params["java_scope"], "SELF");
            }
            _ => panic!("expected AllOf"),
        }
    }

    #[test]
    fn normalize_java_belongs_to_tenant_emits_java_semantics() {
        let json = serde_json::json!({"belongsToTenant": true});
        let group = normalize_condition_json(&json).expect("belongsToTenant must normalize");
        match group {
            ConditionGroup::AllOf(conds) => {
                assert_eq!(conds[0].condition_type, "BelongsToTenantCondition");
                assert_eq!(conds[0].params["java_semantics"], true);
            }
            _ => panic!("expected AllOf"),
        }
    }
}
