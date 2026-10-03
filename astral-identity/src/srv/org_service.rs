//! 组织/域/租户应用服务 — 对应 Java `TenantService` / `DomainControlService` 编排。
//!
//! `tenant`（tenant_type='ENTERPRISE' 承载组织）、`platform_domain` 的
//! record→DTO 映射和 not-found 语义集中在 service，HTTP handler 仅做包装。

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use astral_common::error::AppError;
use astral_types::AstralError;

use crate::srv::org_repository::{OrgMutationContext, OrgRepository};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: Option<i64>,
    pub name: String,
    pub code: String,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
    pub address: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub id: Option<i64>,
    /// platform_v4 无 org_id 列，保留为 Option 用于前端兼容（始终为 None）。
    pub org_id: Option<i64>,
    pub name: String,
    pub code: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub id: Option<i64>,
    /// platform_v4.tenant 无 domain_id 列，保留为 i64 占位（始终为 0）。
    pub domain_id: i64,
    pub name: String,
    pub code: String,
    /// platform_v4.tenant 无 org_id 列，保留为 Option 用于前端兼容。
    pub org_id: Option<i64>,
    pub status: String,
    pub created_at: Option<String>,
}

pub struct OrgService {
    repository: Arc<dyn OrgRepository>,
}

impl OrgService {
    pub fn new(repository: Arc<dyn OrgRepository>) -> Self {
        Self { repository }
    }

    pub async fn list_orgs(&self) -> Result<Vec<Organization>, AppError> {
        Ok(self
            .repository
            .list_orgs()
            .await?
            .into_iter()
            .map(organization_from_record)
            .collect())
    }

    pub async fn create_org(&self, req: &Organization) -> Result<Organization, AppError> {
        let id = self.repository.create_org(&req.name, &req.status).await?;
        Ok(Organization {
            id: Some(id),
            created_at: Some(now_rfc3339()),
            ..req.clone()
        })
    }

    pub async fn create_org_with_context(
        &self,
        req: &Organization,
        context: &OrgMutationContext,
    ) -> Result<Organization, AppError> {
        let id = self
            .repository
            .create_org_with_context(&req.name, &req.status, context)
            .await?;
        Ok(Organization {
            id: Some(id),
            created_at: Some(now_rfc3339()),
            ..req.clone()
        })
    }

    pub async fn get_org(&self, id: i64) -> Result<Organization, AppError> {
        self.repository
            .get_org(id)
            .await?
            .map(organization_from_record)
            .ok_or_else(|| AppError(AstralError::Internal("Organization not found".into())))
    }

    pub async fn update_org(&self, id: i64, req: &Organization) -> Result<(), AppError> {
        self.repository
            .update_org(id, &req.name, &req.code, &req.status)
            .await?;
        Ok(())
    }

    pub async fn update_org_with_context(
        &self,
        id: i64,
        req: &Organization,
        context: &OrgMutationContext,
    ) -> Result<(), AppError> {
        self.repository
            .update_org_with_context(id, &req.name, &req.code, &req.status, context)
            .await?;
        Ok(())
    }

    pub async fn delete_org(&self, id: i64) -> Result<(), AppError> {
        self.repository.delete_org(id).await.map_err(AppError::from)
    }

    pub async fn delete_org_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AppError> {
        self.repository.delete_org_with_context(id, context).await?;
        Ok(())
    }

    pub async fn list_org_domains(&self, org_id: i64) -> Result<Vec<Domain>, AppError> {
        Ok(self
            .repository
            .list_org_domains(org_id)
            .await?
            .into_iter()
            .map(domain_from_record)
            .collect())
    }

    pub async fn list_all_domains(&self) -> Result<Vec<Domain>, AppError> {
        Ok(self
            .repository
            .list_all_domains()
            .await?
            .into_iter()
            .map(domain_from_record)
            .collect())
    }

    pub async fn create_domain(&self, req: &Domain) -> Result<Domain, AppError> {
        let id = self
            .repository
            .create_domain(&req.name, req.code.as_deref(), &req.status)
            .await?;
        Ok(Domain {
            id: Some(id),
            org_id: None,
            created_at: Some(now_rfc3339()),
            ..req.clone()
        })
    }

    pub async fn create_domain_with_context(
        &self,
        req: &Domain,
        context: &OrgMutationContext,
    ) -> Result<Domain, AppError> {
        let id = self
            .repository
            .create_domain_with_context(&req.name, req.code.as_deref(), &req.status, context)
            .await?;
        Ok(Domain {
            id: Some(id),
            org_id: None,
            created_at: Some(now_rfc3339()),
            ..req.clone()
        })
    }

    pub async fn get_domain(&self, id: i64) -> Result<Domain, AppError> {
        self.repository
            .get_domain(id)
            .await?
            .map(domain_from_record)
            .ok_or_else(|| AppError(AstralError::Internal("Domain not found".into())))
    }

    pub async fn update_domain(&self, id: i64, req: &Domain) -> Result<(), AppError> {
        self.repository
            .update_domain(id, &req.name, req.code.as_deref(), &req.status)
            .await?;
        Ok(())
    }

    pub async fn update_domain_with_context(
        &self,
        id: i64,
        req: &Domain,
        context: &OrgMutationContext,
    ) -> Result<(), AppError> {
        self.repository
            .update_domain_with_context(id, &req.name, req.code.as_deref(), &req.status, context)
            .await?;
        Ok(())
    }

    pub async fn delete_domain(&self, id: i64) -> Result<(), AppError> {
        self.repository
            .delete_domain(id)
            .await
            .map_err(AppError::from)
    }

    pub async fn delete_domain_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AppError> {
        self.repository
            .delete_domain_with_context(id, context)
            .await?;
        Ok(())
    }

    pub async fn list_domain_tenants(&self, domain_id: i64) -> Result<Vec<Tenant>, AppError> {
        Ok(self
            .repository
            .list_domain_tenants(domain_id)
            .await?
            .into_iter()
            .map(tenant_from_record)
            .collect())
    }

    pub async fn list_all_tenants(&self) -> Result<Vec<Tenant>, AppError> {
        Ok(self
            .repository
            .list_all_tenants()
            .await?
            .into_iter()
            .map(tenant_from_record)
            .collect())
    }

    pub async fn create_tenant(&self, req: &Tenant) -> Result<Tenant, AppError> {
        let id = self
            .repository
            .create_tenant(&req.name, &req.status)
            .await?;
        Ok(Tenant {
            id: Some(id),
            created_at: Some(now_rfc3339()),
            ..req.clone()
        })
    }

    pub async fn create_tenant_with_context(
        &self,
        req: &Tenant,
        context: &OrgMutationContext,
    ) -> Result<Tenant, AppError> {
        let id = self
            .repository
            .create_tenant_with_context(&req.name, &req.status, context)
            .await?;
        Ok(Tenant {
            id: Some(id),
            created_at: Some(now_rfc3339()),
            ..req.clone()
        })
    }

    pub async fn get_tenant(&self, id: i64) -> Result<Tenant, AppError> {
        self.repository
            .get_tenant(id)
            .await?
            .map(tenant_from_record)
            .ok_or_else(|| AppError(AstralError::Internal("Tenant not found".into())))
    }

    pub async fn update_tenant(&self, id: i64, req: &Tenant) -> Result<(), AppError> {
        self.repository
            .update_tenant(id, &req.name, &req.code, &req.status)
            .await?;
        Ok(())
    }

    pub async fn update_tenant_with_context(
        &self,
        id: i64,
        req: &Tenant,
        context: &OrgMutationContext,
    ) -> Result<(), AppError> {
        self.repository
            .update_tenant_with_context(id, &req.name, &req.code, &req.status, context)
            .await?;
        Ok(())
    }

    pub async fn delete_tenant(&self, id: i64) -> Result<(), AppError> {
        self.repository
            .delete_tenant(id)
            .await
            .map_err(AppError::from)
    }

    pub async fn delete_tenant_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AppError> {
        self.repository
            .delete_tenant_with_context(id, context)
            .await?;
        Ok(())
    }
}

fn organization_from_record(r: crate::srv::org_repository::OrganizationRecord) -> Organization {
    Organization {
        id: Some(r.id),
        name: r.name,
        code: r.code,
        contact_email: None,
        contact_phone: None,
        address: None,
        status: r.status,
        created_at: r.created_at,
    }
}

fn domain_from_record(r: crate::srv::org_repository::DomainRecord) -> Domain {
    Domain {
        id: Some(r.id),
        org_id: None,
        name: r.name,
        code: r.code,
        status: r.status,
        created_at: r.created_at,
    }
}

fn tenant_from_record(r: crate::srv::org_repository::TenantRecord) -> Tenant {
    Tenant {
        id: Some(r.id),
        domain_id: 0,
        name: r.name,
        code: r.code,
        org_id: None,
        status: r.status,
        created_at: r.created_at,
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
