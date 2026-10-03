//! 租户编排 — TenantService
//!
//! 对齐 Java `TenantService`：path/depth 计算、邀请 token 生成、到期推算、
//! role 枚举校验等内嵌逻辑从 handler 移出；事务性写收口在 repository 聚合方法。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::tenant_repository::{
    NewPurchase, NewTenant, TenantMutationContext, TenantRepository,
};

/// 新建租户结果
#[derive(Debug, Clone)]
pub struct CreateTenantOutcome {
    pub tenant_id: i64,
}

/// 购买套餐结果
#[derive(Debug, Clone)]
pub struct PurchaseOutcome {
    pub purchase_id: i64,
}

/// 使用邀请码结果
#[derive(Debug, Clone)]
pub struct UseInvitationOutcome {
    pub tenant_id: i64,
}

/// TenantService
pub struct TenantService {
    repo: Arc<dyn TenantRepository>,
}

impl TenantService {
    pub fn new(repo: Arc<dyn TenantRepository>) -> Self {
        Self { repo }
    }

    /// 创建租户：path/depth 推算（单事务，修复崩溃中间态）
    pub async fn create_tenant(
        &self,
        name: &str,
        parent_tenant_id: Option<i64>,
    ) -> Result<CreateTenantOutcome, AstralError> {
        let _ = (name, parent_tenant_id);
        Err(AstralError::Auth(
            "tenant creation requires Gateway-verified mutation context".into(),
        ))
    }

    pub async fn create_tenant_with_context(
        &self,
        name: &str,
        parent_tenant_id: Option<i64>,
        context: &TenantMutationContext,
    ) -> Result<CreateTenantOutcome, AstralError> {
        let (parent_path, parent_depth) = if let Some(parent_id) = parent_tenant_id {
            let (path, depth) = self
                .repo
                .get_tenant_path_depth(parent_id)
                .await?
                .ok_or_else(|| {
                    AstralError::NotFound(format!("parent tenant {parent_id} not found"))
                })?;
            (path, depth + 1)
        } else {
            (String::new(), 0)
        };

        let tenant_id = self
            .repo
            .create_tenant_with_context(
                &NewTenant {
                    name: name.to_string(),
                    parent_tenant_id,
                    path: parent_path,
                    depth: parent_depth,
                },
                context,
            )
            .await?;

        tracing::info!(id = tenant_id, name, "tenant created");
        Ok(CreateTenantOutcome { tenant_id })
    }

    /// 创建子租户：以父 path 前缀 + 父 depth+1
    pub async fn create_sub_tenant(
        &self,
        parent_id: i64,
        name: &str,
    ) -> Result<CreateTenantOutcome, AstralError> {
        let _ = (parent_id, name);
        Err(AstralError::Auth(
            "sub-tenant creation requires Gateway-verified mutation context".into(),
        ))
    }

    pub async fn create_sub_tenant_with_context(
        &self,
        parent_id: i64,
        name: &str,
        context: &TenantMutationContext,
    ) -> Result<CreateTenantOutcome, AstralError> {
        let parent = self
            .repo
            .get_tenant(parent_id)
            .await?
            .ok_or_else(|| AstralError::NotFound(format!("parent tenant {parent_id}")))?;

        let tenant_id = self
            .repo
            .create_tenant_with_context(
                &NewTenant {
                    name: name.to_string(),
                    parent_tenant_id: Some(parent_id),
                    path: parent.path,
                    depth: parent.depth + 1,
                },
                context,
            )
            .await?;

        tracing::info!(parent_id, new_id = tenant_id, "sub-tenant created");
        Ok(CreateTenantOutcome { tenant_id })
    }

    /// 创建邀请：token 生成 + 7 天过期 + role 校验
    pub async fn create_invitation(
        &self,
        tenant_id: i64,
        role: &str,
    ) -> Result<crate::repository::tenant_repository::TenantInvitationRecord, AstralError> {
        let role_upper = role.to_uppercase();
        if !["ADMIN", "MEMBER", "GUEST"].contains(&role_upper.as_str()) {
            return Err(AstralError::Validation(
                "role must be ADMIN, MEMBER, or GUEST".into(),
            ));
        }
        let token = generate_invite_token();
        let expires_secs = now_secs() + 7 * 24 * 3600; // 7 天过期
        self.repo
            .create_invitation(tenant_id, &token, &role_upper, 1, expires_secs)
            .await
    }

    /// 使用邀请码：校验 + 过期标记 + 事务接受
    pub async fn use_invitation_code(
        &self,
        code: &str,
        user_id: i64,
    ) -> Result<UseInvitationOutcome, AstralError> {
        let inv = self
            .repo
            .get_invitation_by_code_active(code)
            .await?
            .ok_or_else(|| AstralError::Validation("invalid or expired invitation".into()))?;

        // 检查过期
        if let Some(expires) = inv.expires_at {
            if now_secs() > expires {
                self.repo.mark_invitation_expired(inv.id).await?;
                return Err(AstralError::Validation("invitation expired".into()));
            }
        }

        self.repo
            .accept_invitation(inv.id, inv.tenant_id, user_id, &inv.role)
            .await?;
        tracing::info!(
            tenant_id = inv.tenant_id,
            user_id,
            "invitation used, member added"
        );
        Ok(UseInvitationOutcome {
            tenant_id: inv.tenant_id,
        })
    }

    /// 购买套餐：billing_cycle 校验 + 到期推算
    pub async fn purchase_package(
        &self,
        tenant_id: i64,
        plan_id: i64,
        billing_cycle: Option<&str>,
    ) -> Result<PurchaseOutcome, AstralError> {
        let billing_cycle = billing_cycle.unwrap_or("MONTHLY");
        let valid_cycles = ["MONTHLY", "QUARTERLY", "YEARLY", "ONETIME"];
        if !valid_cycles.contains(&billing_cycle) {
            return Err(AstralError::Validation(format!(
                "billing_cycle must be one of {valid_cycles:?}"
            )));
        }

        let expired_secs = compute_expiry_for_cycle(billing_cycle, now_secs());
        let purchase_id = self
            .repo
            .create_purchase(&NewPurchase {
                tenant_id,
                plan_id,
                expired_secs,
            })
            .await?;
        tracing::info!(tenant_id, plan_id, "purchase created");
        Ok(PurchaseOutcome { purchase_id })
    }
}

/// 邀请 token 生成（密码学随机，防枚举预测）。
///
/// 原实现为时间戳 + LCG 线性同余（可预测，可被枚举）。改为 `uuid::Uuid::new_v4()`
/// 密码学随机 128 位；保留 `inv_` 前缀与 `inv_` + 十六进制段的既有测试形状。
pub fn generate_invite_token() -> String {
    let uuid = uuid::Uuid::new_v4();
    let hex = uuid.simple().to_string();
    // 保持 inv_<16hex>_<16hex> 双段形状，兼容既有契约与测试
    format!("inv_{}_{}", &hex[..16], &hex[16..])
}

/// 按 billing_cycle 推算到期时间（ONETIME 永不过期 → None）。
pub fn compute_expiry_for_cycle(billing_cycle: &str, now_secs: i64) -> Option<i64> {
    let duration_secs: i64 = match billing_cycle {
        "MONTHLY" => 30 * 24 * 3600,
        "QUARTERLY" => 90 * 24 * 3600,
        "YEARLY" => 365 * 24 * 3600,
        _ => 0, // ONETIME 永不过期
    };
    if duration_secs > 0 {
        Some(now_secs + duration_secs)
    } else {
        None
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_for_monthly_is_30_days() {
        assert_eq!(
            compute_expiry_for_cycle("MONTHLY", 1_000_000),
            Some(1_000_000 + 30 * 24 * 3600)
        );
    }

    #[test]
    fn expiry_for_yearly_is_365_days() {
        assert_eq!(
            compute_expiry_for_cycle("YEARLY", 1_000_000),
            Some(1_000_000 + 365 * 24 * 3600)
        );
    }

    #[test]
    fn expiry_for_onetime_is_none() {
        assert_eq!(compute_expiry_for_cycle("ONETIME", 1_000_000), None);
    }

    #[test]
    fn invite_token_has_expected_shape() {
        let token = generate_invite_token();
        assert!(token.starts_with("inv_"));
        // inv_ + 两个下划线分隔的十六进制段（时间戳高位可能缺前导零，长度 ≥ 下界）
        let parts: Vec<&str> = token.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "inv");
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(parts[1].len() >= 8 && parts[2].len() >= 8);
    }
}
