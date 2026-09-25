//! ORG_SCOPE 准入证据读取（DB reader 切片）。
//!
//! 合同要点：
//! - 从 **current 已封存 publication**（含 segments）+ **fresh membership** +
//!   **fresh 绑定 id 依赖校验**构造 `OrgAdmissionEvidence`；绝不运行时遍历祖先
//!   图做授权推导，也绝不回退 source grants。
//! - current 指针身份复验：指针行的 generation/revoke_fence/manifest_digest 是
//!   worker 在发布事务内从 publication 逐字复制的摘要副本，必须与取回的 sealed
//!   publication **逐项相等**；任一漂移/部分写 → PENDING（PublicationMissing），
//!   绝不在不一致指针上准入。
//! - 每个钉住依赖按 bound-id 逐项校验祖先 source head：
//!   **active + root + generation + revoke_fence + relationship_revision**
//!   ——祖先撤销/停用/移树立即令旧发布不可读（PENDING），不等待 fan-out。
//! - 业务缺失/漂移一律 `Ok(OrgAdmissionResult::Pending{code, detail})`（冻结
//!   12 项 DB 侧机码）；`Err` 仅用于参数错误与基础设施失败，main 的
//!   `load_org_authorization` hook 必须把 `Err` 映射为 `Unavailable` 并 fail-closed，
//!   不能把依赖故障伪装成业务 Pending。

use sqlx::Row;

use super::mutations::{
    membership_from_row, membership_physical_binding_sql, typed_membership, OrgMembershipRow,
};
use super::*;
use astral_types::org_scope::{OrgAdmissionEvidence, OrgDependency, OrgPublication, OrgSegment};

const READER_TABLE_PROBE_SQL: &str = "SELECT COUNT(*) FROM information_schema.TABLES \
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_scope_node'";
const READER_NODE_SQL: &str = "SELECT tenant_id, root_tenant_id, parent_tenant_id, \
     generation, revoke_fence, relationship_revision, active, created_request_id, \
     created_operation_id, last_operation_id, activation_operator_user_id, \
     activation_approval_operation_id \
     FROM org_scope_node WHERE tenant_id = ?";
const READER_CURRENT_SQL: &str = "SELECT publication_id, generation, manifest_digest, \
     revoke_fence, cas_version FROM org_scope_current WHERE tenant_id = ?";
const READER_PUBLICATION_SQL: &str = "SELECT publication_id, tenant_id, root_tenant_id, \
     generation, relationship_revision, revoke_fence, dependencies_json, manifest_digest, \
     compiler_version, segment_count, status, operation_id FROM org_scope_publication \
     WHERE publication_id = ?";
const READER_SEGMENTS_SQL: &str = "SELECT segment_index, segment_digest, content_json \
     FROM org_scope_segment WHERE publication_id = ? ORDER BY segment_index";
const READER_MEMBERSHIP_SQL: &str = "SELECT membership_id, tenant_id, root_tenant_id, user_id, \
     identity_card_id, card_id, revision, active, valid_from, valid_until, operation_id \
     FROM org_scope_membership WHERE tenant_id = ? AND user_id = ? AND active = 1";

/// 装载准入证据（pool 版；trait 方法委托至此）。
pub(crate) async fn load_admission_evidence_in_pool(
    pool: &MySqlPool,
    query: &OrgAdmissionQuery,
) -> Result<OrgAdmissionResult, AstralError> {
    positive_i64(query.tenant_id, "tenant_id")?;
    positive_i64(query.user_id, "user_id")?;
    positive_i64(query.card_id, "card_id")?;
    if let Some(identity_card_id) = query.identity_card_id {
        positive_i64(identity_card_id, "identity_card_id")?;
    }

    // schema presence：确知表不存在 → Unmanaged（main 据此走 legacy）。
    let table_present = sqlx::query_scalar::<_, i64>(READER_TABLE_PROBE_SQL)
        .fetch_one(pool)
        .await
        .map_err(db_err)?
        > 0;
    if !table_present {
        return Ok(pending(
            OrgPendingCode::SchemaUnmanaged,
            "org_scope schema has never been activated",
        ));
    }

    // 本单元 node（fresh source head）。
    let node_row = sqlx::query(READER_NODE_SQL)
        .bind(query.tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    let Some(node_row) = node_row else {
        return Ok(pending(
            OrgPendingCode::NodeMissing,
            "unit node row is absent",
        ));
    };
    let node_row = node_row_from_row(&node_row)?;
    let node = match typed_node(&node_row) {
        Ok(node) => node,
        Err(error) => {
            return Ok(pending(
                OrgPendingCode::RootMismatch,
                format!("node state is not a provable typed node: {error}"),
            ))
        }
    };
    if !node.active {
        return Ok(pending(
            OrgPendingCode::NodeInactive,
            "unit node is inactive",
        ));
    }

    // current 指针 + 封存 publication（immutable）。
    let current = sqlx::query(READER_CURRENT_SQL)
        .bind(query.tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    let Some(current) = current else {
        return Ok(pending(
            OrgPendingCode::CurrentPointerMissing,
            "no sealed publication pointer for this unit",
        ));
    };
    let publication_id: i64 = current.try_get("publication_id").map_err(db_err)?;
    let pointer_generation: i64 = current.try_get("generation").map_err(db_err)?;
    let pointer_revoke_fence: i64 = current.try_get("revoke_fence").map_err(db_err)?;
    let pointer_manifest: Vec<u8> = current.try_get("manifest_digest").map_err(db_err)?;
    let publication_row = sqlx::query(READER_PUBLICATION_SQL)
        .bind(publication_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    let Some(publication_row) = publication_row else {
        return Ok(pending(
            OrgPendingCode::CurrentPointerMissing,
            "current pointer does not resolve to a publication",
        ));
    };
    let status: String = publication_row.try_get("status").map_err(db_err)?;
    let publication = read_publication(&publication_row, pool).await?;
    let pointer_generation = row_generation(pointer_generation, "current.generation")?;
    let pointer_revoke_fence = row_generation(pointer_revoke_fence, "current.revoke_fence")?;
    let pointer_manifest_hex = hex::encode(pointer_manifest);
    if status != "SEALED" {
        return Ok(pending(
            OrgPendingCode::PublicationMissing,
            "current pointer is inconsistent with its sealed publication",
        ));
    }
    // 指针身份复验：任一字段与 sealed publication 不一致（部分写/陈旧覆盖/
    // 字节损坏）→ PENDING，绝不在不可证明的指针上准入。
    if let Some(detail) = pointer_publication_mismatch(
        pointer_generation,
        pointer_revoke_fence,
        &pointer_manifest_hex,
        &publication,
    ) {
        return Ok(pending(OrgPendingCode::PublicationMissing, detail));
    }
    // 封存载荷合同复验（manifest/segment digest、依赖排序、贡献归属）：
    // 任何失配 → PENDING，绝不在损坏字节上准入。
    if let Err(error) = publication.validate() {
        return Ok(pending(OrgPendingCode::PublicationMissing, error.message));
    }

    // 本单元 source 新鲜度：node 头栅栏与 publication 逐项相等。
    if node.root_tenant_id != publication.root_tenant_id {
        return Ok(pending(
            OrgPendingCode::RootMismatch,
            "unit node root moved",
        ));
    }
    if node.generation != publication.generation
        || node.revoke_fence != publication.revoke_fence
        || node.relationship_revision != publication.relationship_revision
    {
        return Ok(pending(
            OrgPendingCode::SourceGenerationAdvanced,
            "unit source head advanced past the sealed publication",
        ));
    }

    // 依赖钉逐项 fresh 校验（active + root + generation + fence + relationship）。
    for dependency in &publication.dependencies {
        if let Some(detail) =
            dependency_is_stale(pool, dependency, publication.root_tenant_id).await?
        {
            return Ok(pending(OrgPendingCode::DependencyStale, detail));
        }
    }

    // fresh membership：active + card 绑定 + 有效期 + 同 root。
    let membership_rows = sqlx::query(READER_MEMBERSHIP_SQL)
        .bind(query.tenant_id)
        .bind(query.user_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    if membership_rows.is_empty() {
        return Ok(pending(
            OrgPendingCode::MembershipMissing,
            "no active membership binds this user to the unit",
        ));
    }
    let mut card_mismatch = false;
    let mut expired = false;
    let mut best: Option<OrgMembershipRow> = None;
    for row in &membership_rows {
        let membership = membership_from_row(row)?;
        let card_matches = membership.card_id == query.card_id
            && query
                .identity_card_id
                .map(|identity| membership.identity_card_id == identity)
                .unwrap_or(true);
        if !card_matches {
            card_mismatch = true;
            continue;
        }
        if membership.root_tenant_id != node.root_tenant_id {
            return Ok(pending(
                OrgPendingCode::RootMismatch,
                "membership authority root does not match the unit root",
            ));
        }
        if membership.revision <= 0 {
            return Ok(pending(
                OrgPendingCode::MembershipMissing,
                "membership row carries a non-positive revision",
            ));
        }
        let typed = match typed_membership(&membership) {
            Ok(typed) => typed,
            Err(error) => {
                return Ok(pending(
                    OrgPendingCode::MembershipMissing,
                    format!("membership row is not provable: {error}"),
                ))
            }
        };
        if !typed.is_valid_at(query.now_unix_seconds) {
            expired = true;
            continue;
        }
        if best
            .as_ref()
            .map(|current_row| membership.revision > current_row.revision)
            .unwrap_or(true)
        {
            best = Some(membership);
        }
    }
    let Some(membership_row) = best else {
        if card_mismatch {
            return Ok(pending(
                OrgPendingCode::MembershipCardMismatch,
                "active memberships exist but none binds the presented card pair",
            ));
        }
        if expired {
            return Ok(pending(
                OrgPendingCode::MembershipExpired,
                "membership validity window excludes the read clock",
            ));
        }
        return Ok(pending(
            OrgPendingCode::MembershipMissing,
            "no usable membership for this subject",
        ));
    };
    let membership = match typed_membership(&membership_row) {
        Ok(membership) => membership,
        Err(error) => {
            return Ok(pending(
                OrgPendingCode::MembershipMissing,
                format!("membership row is not provable: {error}"),
            ))
        }
    };
    if !physical_membership_binding_is_current(pool, &membership_row).await? {
        return Ok(pending(
            OrgPendingCode::MembershipCardMismatch,
            "membership physical card binding is no longer active",
        ));
    }

    let evidence = OrgAdmissionEvidence {
        publication,
        node,
        membership,
        checked_at_unix: query.now_unix_seconds,
    };
    if let Err(error) = evidence.validate() {
        return Ok(pending(
            OrgPendingCode::PublicationMissing,
            format!(
                "assembled evidence failed contract validation: {}",
                error.message
            ),
        ));
    }
    Ok(OrgAdmissionResult::Evidence(Box::new(evidence)))
}

/// Freshly prove the physical card pair behind a selected membership. The query
/// intentionally mirrors membership creation/approval and has no cache fallback.
async fn physical_membership_binding_is_current(
    pool: &MySqlPool,
    membership: &OrgMembershipRow,
) -> Result<bool, AstralError> {
    let row = sqlx::query(&membership_physical_binding_sql(false))
        .bind(membership.card_id)
        .bind(membership.user_id)
        .bind(membership.tenant_id)
        .bind(membership.identity_card_id)
        .bind(membership.user_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    Ok(row.is_some())
}

/// current 指针与封存 publication 的身份一致性（纯函数；单测覆盖）。
///
/// 指针行的 generation/revoke_fence/manifest_digest 必须与取回的 sealed
/// publication **逐项相等**。任一字段漂移（部分写、陈旧覆盖、字节损坏）返回
/// `Some(明细)`，调用方据此返回 `Pending(PublicationMissing)`；完全一致返回
/// `None`。绝不放宽为成功路径。
fn pointer_publication_mismatch(
    pointer_generation: u64,
    pointer_revoke_fence: u64,
    pointer_manifest_hex: &str,
    publication: &OrgPublication,
) -> Option<String> {
    let mut divergent: Vec<&'static str> = Vec::new();
    if publication.generation != pointer_generation {
        divergent.push("generation");
    }
    if publication.revoke_fence != pointer_revoke_fence {
        divergent.push("revoke_fence");
    }
    if publication.manifest_digest_hex != pointer_manifest_hex {
        divergent.push("manifest_digest");
    }
    if divergent.is_empty() {
        return None;
    }
    Some(format!(
        "current pointer identity diverges from its sealed publication: {}",
        divergent.join("/")
    ))
}

/// 单个依赖钉的新鲜度校验；返回 `Some(detail)` = 陈旧（祖先撤销/停用/移树）。
async fn dependency_is_stale(
    pool: &MySqlPool,
    dependency: &OrgDependency,
    publication_root_tenant_id: i64,
) -> Result<Option<String>, AstralError> {
    let row = sqlx::query(READER_NODE_SQL)
        .bind(dependency.tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    let Some(row) = row else {
        return Ok(Some(format!(
            "dependency ancestor {} is missing",
            dependency.tenant_id
        )));
    };
    let ancestor = node_row_from_row(&row)?;
    if !ancestor.active {
        return Ok(Some(format!(
            "dependency ancestor {} is inactive",
            dependency.tenant_id
        )));
    }
    if ancestor.root_tenant_id != publication_root_tenant_id {
        return Ok(Some(format!(
            "dependency ancestor {} left the authority root",
            dependency.tenant_id
        )));
    }
    let generation = match row_generation(ancestor.generation, "ancestor.generation") {
        Ok(value) => value,
        Err(error) => return Ok(Some(format!("ancestor generation unprovable: {error}"))),
    };
    let fence = match row_generation(ancestor.revoke_fence, "ancestor.revoke_fence") {
        Ok(value) => value,
        Err(error) => return Ok(Some(format!("ancestor fence unprovable: {error}"))),
    };
    let relationship = match row_generation(
        ancestor.relationship_revision,
        "ancestor.relationship_revision",
    ) {
        Ok(value) => value,
        Err(error) => return Ok(Some(format!("ancestor relationship unprovable: {error}"))),
    };
    if generation != dependency.generation
        || fence != dependency.revoke_fence
        || relationship != dependency.relationship_revision
    {
        return Ok(Some(format!(
            "dependency ancestor {} head advanced past its pinned fences",
            dependency.tenant_id
        )));
    }
    Ok(None)
}

/// 行 → 类型化 publication（含全部 sealed segments）。
async fn read_publication(
    row: &sqlx::mysql::MySqlRow,
    pool: &MySqlPool,
) -> Result<OrgPublication, AstralError> {
    let publication_id: i64 = row.try_get("publication_id").map_err(db_err)?;
    let dependencies_json: String = row.try_get("dependencies_json").map_err(db_err)?;
    let segment_rows = sqlx::query(READER_SEGMENTS_SQL)
        .bind(publication_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    let mut segments = Vec::with_capacity(segment_rows.len());
    for segment_row in &segment_rows {
        segments.push(OrgSegment {
            index: u32::try_from(
                segment_row
                    .try_get::<i64, _>("segment_index")
                    .map_err(db_err)?,
            )
            .map_err(|_| AstralError::Database("code=org_scope.segment_index_invalid".into()))?,
            digest_hex: hex::encode(
                segment_row
                    .try_get::<Vec<u8>, _>("segment_digest")
                    .map_err(db_err)?,
            ),
            content: serde_json::from_str(
                &segment_row
                    .try_get::<String, _>("content_json")
                    .map_err(db_err)?,
            )
            .map_err(|error| {
                AstralError::Database(format!(
                    "code=org_scope.segment_content_unreadable;detail={error}"
                ))
            })?,
        });
    }
    Ok(OrgPublication {
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        root_tenant_id: row.try_get("root_tenant_id").map_err(db_err)?,
        generation: row_generation(
            row.try_get("generation").map_err(db_err)?,
            "publication.generation",
        )?,
        relationship_revision: row_generation(
            row.try_get("relationship_revision").map_err(db_err)?,
            "publication.relationship_revision",
        )?,
        revoke_fence: row_generation(
            row.try_get("revoke_fence").map_err(db_err)?,
            "publication.revoke_fence",
        )?,
        dependencies: serde_json::from_str(&dependencies_json).map_err(|error| {
            AstralError::Database(format!(
                "code=org_scope.dependencies_unreadable;detail={error}"
            ))
        })?,
        manifest_digest_hex: hex::encode(
            row.try_get::<Vec<u8>, _>("manifest_digest")
                .map_err(db_err)?,
        ),
        compiler_version: row.try_get("compiler_version").map_err(db_err)?,
        segments,
        operation_id: row.try_get("operation_id").map_err(db_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_source_requires_fresh_physical_binding_before_evidence() {
        let source = include_str!("reader.rs");
        let evidence = source
            .find("let evidence = OrgAdmissionEvidence {")
            .expect("reader evidence assembly must remain");
        let before_evidence = &source[..evidence];
        let physical = before_evidence
            .find("physical_membership_binding_is_current(pool, &membership_row)")
            .expect("reader must fresh-check physical binding before evidence");
        assert!(physical < before_evidence.len());
        assert!(source.contains("membership_physical_binding_sql(false)"));
        assert!(source.contains("no cache fallback"));
    }

    /// current 指针身份三字段的最小 publication（helper 不调用 validate，
    /// 其余字段用占位值即可）。
    fn publication_for_identity(
        generation: u64,
        revoke_fence: u64,
        manifest_digest_hex: &str,
    ) -> OrgPublication {
        OrgPublication {
            tenant_id: 10,
            root_tenant_id: 10,
            generation,
            relationship_revision: 1,
            revoke_fence,
            dependencies: Vec::new(),
            manifest_digest_hex: manifest_digest_hex.to_owned(),
            compiler_version: "test-compiler".to_owned(),
            segments: Vec::new(),
            operation_id: "op-test".to_owned(),
        }
    }

    const TEST_MANIFEST_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn pointer_identity_equal_is_accepted() {
        let publication = publication_for_identity(7, 3, TEST_MANIFEST_HEX);
        let mismatch = pointer_publication_mismatch(7, 3, TEST_MANIFEST_HEX, &publication);
        assert!(
            mismatch.is_none(),
            "exact pointer identity must be accepted"
        );
    }

    #[test]
    fn pointer_generation_mismatch_is_rejected() {
        let publication = publication_for_identity(8, 3, TEST_MANIFEST_HEX);
        let detail = pointer_publication_mismatch(7, 3, TEST_MANIFEST_HEX, &publication)
            .expect("generation divergence must be rejected");
        assert!(detail.contains("generation"));
    }

    #[test]
    fn pointer_revoke_fence_mismatch_is_rejected() {
        let publication = publication_for_identity(7, 4, TEST_MANIFEST_HEX);
        let detail = pointer_publication_mismatch(7, 3, TEST_MANIFEST_HEX, &publication)
            .expect("revoke_fence divergence must be rejected");
        assert!(detail.contains("revoke_fence"));
    }

    #[test]
    fn pointer_manifest_digest_mismatch_is_rejected() {
        let publication = publication_for_identity(7, 3, TEST_MANIFEST_HEX);
        let other_manifest_hex = "f".repeat(64);
        let detail = pointer_publication_mismatch(7, 3, &other_manifest_hex, &publication)
            .expect("manifest_digest divergence must be rejected");
        assert!(detail.contains("manifest_digest"));
    }

    #[test]
    fn pointer_manifest_length_divergence_is_rejected() {
        let publication = publication_for_identity(7, 3, TEST_MANIFEST_HEX);
        let short_manifest_hex = "abcd";
        let detail = pointer_publication_mismatch(7, 3, short_manifest_hex, &publication)
            .expect("truncated manifest digest must be rejected");
        assert!(detail.contains("manifest_digest"));
    }

    #[test]
    fn pointer_multi_field_divergence_lists_all_fields() {
        let publication = publication_for_identity(9, 5, TEST_MANIFEST_HEX);
        let detail = pointer_publication_mismatch(7, 3, "aa", &publication)
            .expect("multi-field divergence must be rejected");
        assert!(detail.contains("generation"));
        assert!(detail.contains("revoke_fence"));
        assert!(detail.contains("manifest_digest"));
    }
}
