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
    #[serde(rename = "conditionType")]
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
        if condition.params.get("timeZone").is_some() {
            return Err(ConditionError::InvalidParams(
                "unsupported legacy parameter 'timeZone'; use 'timezone'".into(),
            ));
        }

        // 按 HH:mm 分钟精度比较，支持跨午夜（start > end 回绕）。
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
        let offset = condition
            .params
            .get("timezone")
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
                // 支持 1.2.3.0/24 形式
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

/// IPv4 CIDR 匹配；非法输入返回 false（fail-closed）
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

/// 速率限制条件：使用调用方提供的当前窗口计数校验规则阈值。
///
/// 参数示例：`{ "max_requests": 100, "window_seconds": 60 }`。调用方必须将
/// 服务端可信的当前窗口计数放入 context；缺少计数时 fail-closed。本评估器不
/// 创建计数器，也不把 Gateway 的全局限流视为规则窗口计数。
pub struct RateLimitCondition;

#[async_trait::async_trait]
impl ConditionEvaluator for RateLimitCondition {
    fn condition_type(&self) -> &'static str {
        "RateLimitCondition"
    }

    async fn evaluate(
        &self,
        condition: &Condition,
        ctx: &PolicyContext,
    ) -> Result<bool, ConditionError> {
        let max_requests = condition
            .params
            .get("max_requests")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ConditionError::InvalidParams("missing 'max_requests'".into()))?;

        if max_requests == 0 {
            return Ok(false); // 阈值为 0 直接拒绝
        }

        // 条件求值必须拿到可信调用方提供的当前窗口计数；Gateway 的全局 IP
        // 限流并不等价于规则自己的 max_requests/window_seconds。未知计数不能 ALLOW。
        let current_count = ctx
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
/// 多个原生属性谓词可放在 `conditions` 中，所有谓词都必须满足。
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
        if condition.params.get("java_semantics").is_some() {
            return Err(ConditionError::InvalidParams(
                "unsupported legacy parameter 'java_semantics'".into(),
            ));
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
        if condition.params.get("java_scope").is_some() {
            return Err(ConditionError::InvalidParams(
                "unsupported legacy parameter 'java_scope'".into(),
            ));
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

/// 条件注册表：根据原生 PascalCase 条件类型创建评估器；未知类型 fail-closed。
pub fn evaluator_for(condition_type: &str) -> Result<Box<dyn ConditionEvaluator>, ConditionError> {
    match condition_type {
        "TimeRangeCondition" => Ok(Box::new(TimeRangeCondition)),
        "IpRangeCondition" => Ok(Box::new(IpRangeCondition)),
        "RateLimitCondition" => Ok(Box::new(RateLimitCondition)),
        "DeviceTypeCondition" => Ok(Box::new(DeviceTypeCondition)),
        "ResourcePropertyCondition" => Ok(Box::new(ResourcePropertyCondition)),
        "OwnerOnlyCondition" => Ok(Box::new(OwnerOnlyCondition)),
        "BelongsToTenantCondition" => Ok(Box::new(BelongsToTenantCondition)),
        "ScopeCondition" => Ok(Box::new(ScopeCondition)),
        _ => Err(ConditionError::UnknownType(condition_type.to_string())),
    }
}

fn is_canonical_condition(condition: &Condition) -> bool {
    if evaluator_for(&condition.condition_type).is_err() {
        return false;
    }
    let Some(params) = condition.params.as_object() else {
        return true;
    };
    let retired_parameter = match condition.condition_type.as_str() {
        "TimeRangeCondition" => params.contains_key("timeZone"),
        "ScopeCondition" => params.contains_key("java_scope"),
        "BelongsToTenantCondition" => params.contains_key("java_semantics"),
        _ => false,
    };
    !retired_parameter
}

/// Validate and normalize the canonical Rust condition JSON shape.
///
/// Accepts one `conditionType`/`params` condition or a one-key `allOf`, `anyOf`,
/// or `not` group. All aliases and legacy wrappers are rejected.
pub fn normalize_condition_json(json: &serde_json::Value) -> Option<ConditionGroup> {
    let object = json.as_object()?;

    let group = if object.contains_key("conditionType") {
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "conditionType" | "params"))
        {
            return None;
        }
        let condition = serde_json::from_value::<Condition>(json.clone()).ok()?;
        ConditionGroup::AllOf(vec![condition])
    } else {
        if object.len() != 1 {
            return None;
        }
        let operation = object.keys().next()?.as_str();
        if !matches!(operation, "allOf" | "anyOf" | "not") {
            return None;
        }
        if matches!(operation, "allOf" | "anyOf")
            && object
                .get(operation)
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            return None;
        }
        serde_json::from_value::<ConditionGroup>(json.clone()).ok()?
    };

    let has_only_canonical_conditions = match &group {
        ConditionGroup::AllOf(conditions) | ConditionGroup::AnyOf(conditions) => {
            conditions.iter().all(is_canonical_condition)
        }
        ConditionGroup::Not(condition) => is_canonical_condition(condition),
    };
    has_only_canonical_conditions.then_some(group)
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
    async fn test_rate_limit_passes_under_and_rejects_at_the_limit() {
        let evaluator = RateLimitCondition;
        let condition = Condition {
            condition_type: "RateLimitCondition".into(),
            params: serde_json::json!({ "max_requests": 5 }),
        };
        let ctx = |count: u64| {
            PolicyContext::builder()
                .action("read".into())
                .request(Some(serde_json::json!({ "rateLimitCount": count })))
                .build()
        };
        // Under the window budget the condition refines the ALLOW.
        assert!(evaluator.evaluate(&condition, &ctx(4)).await.unwrap());
        // At and above the budget it rejects; unknown counts stay an error.
        assert!(!evaluator.evaluate(&condition, &ctx(5)).await.unwrap());
        assert!(!evaluator.evaluate(&condition, &ctx(6)).await.unwrap());
        let missing = evaluator
            .evaluate(
                &condition,
                &PolicyContext::builder().action("read".into()).build(),
            )
            .await;
        assert!(missing.is_err());
        let no_budget = evaluator
            .evaluate(
                &Condition {
                    condition_type: "RateLimitCondition".into(),
                    params: serde_json::json!({}),
                },
                &ctx(1),
            )
            .await;
        assert!(no_budget.is_err());
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
        // 目标资源属主与当前用户匹配时允许。
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

    #[test]
    fn evaluator_rejects_legacy_lowercase_aliases() {
        for legacy_name in [
            "timeRange",
            "ipRange",
            "rateLimit",
            "deviceType",
            "resourceProperty",
            "ownerOnly",
            "belongsToTenant",
            "scope",
            "TimeRangeCondition ",
            "timerangecondition",
        ] {
            assert!(
                evaluator_for(legacy_name).is_err(),
                "legacy_name={legacy_name}"
            );
        }
    }

    #[test]
    fn normalize_native_single_condition_and_groups() {
        let condition = serde_json::json!({
            "conditionType": "TimeRangeCondition",
            "params": {"start": "09:00", "end": "18:00"}
        });
        let native_case_alias = serde_json::json!({
            "conditionType": "TimeRangeCondition",
            "params": {"start": "09:00", "end": "18:00", "timeZone": "+08:00"}
        });
        assert!(normalize_condition_json(&native_case_alias).is_none());

        match normalize_condition_json(&condition).expect("native condition must normalize") {
            ConditionGroup::AllOf(conditions) => {
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0].condition_type, "TimeRangeCondition");
                assert_eq!(conditions[0].params["start"], "09:00");
                assert_eq!(conditions[0].params["end"], "18:00");
            }
            _ => panic!("single condition must normalize to AllOf"),
        }

        let all_of = serde_json::json!({"allOf": [condition.clone(), condition.clone()]});
        assert!(matches!(
            normalize_condition_json(&all_of),
            Some(ConditionGroup::AllOf(conditions)) if conditions.len() == 2
        ));

        let any_of = serde_json::json!({"anyOf": [condition.clone(), condition.clone()]});
        assert!(matches!(
            normalize_condition_json(&any_of),
            Some(ConditionGroup::AnyOf(conditions)) if conditions.len() == 2
        ));

        let not = serde_json::json!({"not": condition});
        assert!(matches!(
            normalize_condition_json(&not),
            Some(ConditionGroup::Not(_))
        ));
    }

    #[test]
    fn normalize_rejects_legacy_aliases_wrappers_and_mixed_forms() {
        for retired in [
            serde_json::json!({"condition_type": "OwnerOnlyCondition", "params": {}}),
            serde_json::json!({"conditionGroup": {"allOf": []}}),
            serde_json::json!({"ownerOnly": true}),
            serde_json::json!({"timeRange": {"start": "09:00", "end": "18:00"}}),
            serde_json::json!({"conditionType": "ownerOnly", "params": {}}),
            serde_json::json!({"conditionType": "UnknownCondition", "params": {}}),
            serde_json::json!({
                "conditionType": "TimeRangeCondition",
                "params": {"start": "09:00", "end": "18:00", "timeZone": "+08:00"}
            }),
            serde_json::json!({
                "conditionType": "OwnerOnlyCondition",
                "params": {},
                "ownerOnly": true
            }),
            serde_json::json!({
                "allOf": [{"conditionType": "OwnerOnlyCondition", "params": {}}],
                "anyOf": [{"conditionType": "OwnerOnlyCondition", "params": {}}]
            }),
        ] {
            assert!(
                normalize_condition_json(&retired).is_none(),
                "retired or mixed form accepted: {retired}"
            );
        }
    }

    #[test]
    fn normalize_rejects_invalid_legacy_and_unknown_conditions_inside_not() {
        for invalid in [
            serde_json::json!({"not": {"ownerOnly": true}}),
            serde_json::json!({
                "not": {"condition_type": "OwnerOnlyCondition", "params": {}}
            }),
            serde_json::json!({"not": {"conditionType": "ownerOnly", "params": {}}}),
            serde_json::json!({"not": {"conditionType": "UnknownCondition", "params": {}}}),
            serde_json::json!({
                "not": {
                    "conditionType": "OwnerOnlyCondition",
                    "params": {},
                    "ownerOnly": true
                }
            }),
            serde_json::json!({
                "not": {
                    "conditionType": "BelongsToTenantCondition",
                    "params": {"java_semantics": true}
                }
            }),
        ] {
            assert!(
                normalize_condition_json(&invalid).is_none(),
                "invalid negated condition accepted: {invalid}"
            );
        }
    }

    #[test]
    fn normalize_rejects_unknown_condition_types_and_empty_groups() {
        assert!(normalize_condition_json(&serde_json::json!({
            "conditionType": "UnknownCondition",
            "params": {}
        }))
        .is_none());
        assert!(normalize_condition_json(&serde_json::json!({"allOf": []})).is_none());
        assert!(normalize_condition_json(&serde_json::json!({"anyOf": []})).is_none());
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

    // ===== Native scope / tenant semantics =====

    #[tokio::test]
    async fn native_scope_uses_registered_action_codes() {
        let evaluator = ScopeCondition;
        let condition = Condition {
            condition_type: "ScopeCondition".into(),
            params: serde_json::json!({ "required_scopes": ["learn:read"] }),
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .action("read".into())
            .action_codes(vec!["learn:read".into()])
            .build();
        assert!(evaluator.evaluate(&condition, &ctx).await.unwrap());
    }

    #[tokio::test]
    async fn retired_parameters_do_not_bypass_native_checks() {
        let scope = ScopeCondition
            .evaluate(
                &Condition {
                    condition_type: "ScopeCondition".into(),
                    params: serde_json::json!({ "java_scope": "SELF" }),
                },
                &PolicyContext::builder()
                    .user_id(Some(1))
                    .action("read".into())
                    .build(),
            )
            .await;
        assert!(scope.is_err());

        let tenant = BelongsToTenantCondition
            .evaluate(
                &Condition {
                    condition_type: "BelongsToTenantCondition".into(),
                    params: serde_json::json!({ "java_semantics": true }),
                },
                &PolicyContext::builder()
                    .tenant_id(Some(9))
                    .action("read".into())
                    .build(),
            )
            .await;
        assert!(tenant.is_err());
    }
}
