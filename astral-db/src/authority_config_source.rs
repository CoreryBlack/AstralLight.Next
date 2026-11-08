//! Typed config source-row image capture delegate for TrustGraph config
//! writers (batch 1: sod_policy / admin_group / admin_group_member /
//! identity_user_grading / permission_action / resource_type_registry).
//!
//! 用户面 config mutation 是影响有效授权判定输入的 source mutation：在
//! V7 source-outcome 合同下，typed（config）owner 必须在**同一 source
//! 事务**内提供真实的 before/after 行镜像证据与同事务 audit 关联，绝不
//! 允许 writer 用自报 digest、请求标签或派生快照冒充源事实。本模块是该
//! 证据的**唯一捕获委托**：
//!
//! - **single-transaction binding is structural**：[`TypedSourceRowCapture`]
//!   在 `begin_in_tx` 即持有 `&mut Transaction<'static, MySql>`，writer 的
//!   mutation SQL 只能经 [`TypedSourceRowCapture::with_tx_mut`] 在被绑定的
//!   事务上执行；生命周期使 before/after 捕获与 mutation 物理上不可能跨
//!   事务（不依赖任何运行期连接号或环境/inode 身份）。
//! - **opaque capture**：镜像字节与 digest 全部在本模块内从实际
//!   `SELECT ... FOR UPDATE` 读回值构造，writer 无法注入或自报。before
//!   镜像在行锁下捕获，after 镜像在 mutation 后回读，同一 lookup 前后
//!   一致，两侧主键必须相同。
//! - **closed allowlists**：表名、列名、lookup 全部是本文件的编译期闭集；
//!   所有 SQL 一律绑定参数，绝不拼接调用方输入。
//! - **absence 显式成帧**：缺失行不是空串/省略，而是 canonical typed
//!   marker `{table, lookup, presence:"ABSENT"}` bytes（闭集 table + lookup，
//!   phase 无关）；同一行的 before/after 缺失侧内容一致，不同表/键绝不
//!   共享同一 hash。
//! - **digest 合同**：`digest = hex(sha256(实际 canonical image bytes))`，
//!   无额外 hash 域前缀；present 侧 bytes 是固定字段序的行镜像 JSON（含
//!   结构/列名与真实列值），absent 侧 bytes 是 typed marker JSON。stage
//!   侧对 retained bytes 重新 sha256 即可与 digest 对账。
//! - **seal 是 receipt 的唯一构造点**：[`TypedSourceRowImageReceipt`] 无
//!   `Deserialize`、无 pub 字段，只能由 [`seal_typed_source_row_capture_tx`]
//!   产出；操作性不变式（Insert/Upsert after 必在、Update 前后必在、
//!   Delete after 必缺、前后 PK 一致）在 seal 处 fail-closed。
//! - before==after（no-op 更新/幂等 INSERT IGNORE 命中既有行）按事实保留
//!   相等镜像对；no-op 的 abort/Reserved 收口属于独立 owner，本模块不扩
//!   协议终态、不改判 ProtectedBusiness。

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};

use astral_types::AstralError;

/// Structured errors from the closed typed source reader.
///
/// The compatibility reader below still exposes [`AstralError`] to existing
/// source writers. The completion worker must use the typed entry point so a
/// SQL decode/schema failure cannot be confused with a durable source fact.
#[derive(Debug, thiserror::Error)]
pub enum TypedSourceReadError {
    #[error("typed source validation failed: {0}")]
    Validation(String),
    #[error("typed source durable fact is pending or contradictory: {0}")]
    Pending(String),
    #[error("typed source image serialization failed: {0}")]
    Serialization(String),
    #[error("typed source SQL transient failure at {context}: {source}")]
    SqlxTransient {
        context: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("typed source SQL schema/decode failure at {context}: {source}")]
    SqlxSchema {
        context: &'static str,
        #[source]
        source: sqlx::Error,
    },
}

impl TypedSourceReadError {
    pub fn from_sqlx(context: &'static str, error: sqlx::Error) -> Self {
        let transient = match &error {
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => true,
            sqlx::Error::Database(database) => database
                .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .is_some_and(|mysql| matches!(mysql.number(), 1040 | 1205 | 1213 | 2006 | 2013)),
            _ => false,
        };
        if transient {
            Self::SqlxTransient {
                context,
                source: error,
            }
        } else {
            Self::SqlxSchema {
                context,
                source: error,
            }
        }
    }
}

impl From<TypedSourceReadError> for AstralError {
    fn from(error: TypedSourceReadError) -> Self {
        let message = error.to_string();
        match error {
            TypedSourceReadError::Validation(message) => AstralError::Validation(message),
            TypedSourceReadError::Pending(message) => AstralError::Pending(message),
            TypedSourceReadError::Serialization(_)
            | TypedSourceReadError::SqlxTransient { .. }
            | TypedSourceReadError::SqlxSchema { .. } => AstralError::Database(message),
        }
    }
}

/// The authority-types module is the only long-lived config source contract.
/// These aliases preserve the DB capture API without duplicating its wire schema.
pub use astral_types::{
    AuthorityConfigSourceLookup as TypedSourceRowLookup,
    AuthorityConfigSourceOperation as TypedRowOperation,
    AuthorityConfigSourceTable as TypedSourceTable,
};

fn lookup_canonical(
    lookup: &TypedSourceRowLookup,
    table: TypedSourceTable,
) -> Result<String, AstralError> {
    lookup.validate_for_table(table).map_err(|error| {
        AstralError::Validation(format!(
            "typed source lookup is invalid for {}: {error:?}",
            table.as_str()
        ))
    })?;
    serde_json::to_string(lookup).map_err(|error| {
        AstralError::Validation(format!("typed source lookup serialization failed: {error}"))
    })
}

fn operation_text(operation: TypedRowOperation) -> Result<String, AstralError> {
    serde_json::to_string(&operation)
        .map(|encoded| encoded.trim_matches('"').to_owned())
        .map_err(|error| {
            AstralError::Validation(format!(
                "typed source operation serialization failed: {error}"
            ))
        })
}

impl From<AstralError> for TypedSourceReadError {
    fn from(error: AstralError) -> Self {
        match error {
            AstralError::Validation(message) => Self::Validation(message),
            AstralError::Pending(message) => Self::Pending(message),
            other => Self::Serialization(other.to_string()),
        }
    }
}

/// A row captured from the physical source database.
#[derive(Debug, Clone)]
pub(super) struct CapturedRow {
    pub(super) pk: i64,
    pub(super) image_json: String,
}

/// Explicitly framed missing-row marker, phase independent and bound to typed identity.
#[derive(Serialize)]
struct TypedAbsentMarker<'a> {
    table: &'a str,
    lookup: &'a str,
    presence: &'static str,
}

const ABSENT_PRESENCE: &str = "ABSENT";

pub fn typed_source_absent_image(
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<String, AstralError> {
    let lookup_json = lookup_canonical(lookup, table)?;
    Ok(absent_marker_bytes(table, &lookup_json))
}

pub async fn read_typed_source_row_image_in_tx(
    tx: &mut Transaction<'_, MySql>,
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<(i64, String)>, AstralError> {
    read_typed_source_row_image_in_tx_typed(tx, table, lookup)
        .await
        .map_err(AstralError::from)
}

/// Structured reader entry for completion/proof verification callers.
pub async fn read_typed_source_row_image_in_tx_typed(
    tx: &mut Transaction<'_, MySql>,
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<(i64, String)>, TypedSourceReadError> {
    lookup.validate_for_table(table).map_err(|error| {
        TypedSourceReadError::Validation(format!(
            "typed source lookup is invalid for {}: {error:?}",
            table.as_str()
        ))
    })?;
    read_row_image_in_tx_typed(tx, table, lookup)
        .await
        .map(|row| row.map(|row| (row.pk, row.image_json)))
}

fn absent_marker_bytes(table: TypedSourceTable, lookup_json: &str) -> String {
    serde_json::to_string(&TypedAbsentMarker {
        table: table.as_str(),
        lookup: lookup_json,
        presence: ABSENT_PRESENCE,
    })
    .expect("serializing typed absent marker cannot fail")
}

fn image_digest_hex(image_json: &str) -> String {
    hex::encode(Sha256::digest(image_json.as_bytes()))
}

// ===== per-table allowlisted readback rows（固定字段序 = canonical bytes 序）=====

macro_rules! allowlisted_image_row {
    ($(#[$meta:meta])* struct $name:ident { $(pub $field:ident : $ty:ty),+ $(,)? }) => {
        #[derive(Debug, sqlx::FromRow, Serialize)]
        $(#[$meta])*
        struct $name { $(pub $field: $ty),+ }
    };
}

allowlisted_image_row! {
    struct SodPolicyImageRow {
        pub policy_id: i64,
        pub policy_name: Option<String>,
        pub description: Option<String>,
        pub conflict_type: Option<String>,
        pub resource_type: Option<String>,
        pub action_code: Option<String>,
        pub permission_a: Option<String>,
        pub permission_b: Option<String>,
        pub condition_script: Option<String>,
        pub limit_count: Option<i64>,
        pub limit_window: Option<String>,
        pub status: Option<String>,
        pub created_at: Option<String>,
        pub updated_at: Option<String>,
    }
}

allowlisted_image_row! {
    struct AdminGroupImageRow {
        pub id: i64,
        pub name: Option<String>,
        pub description: Option<String>,
        pub scope: Option<String>,
        pub created_at: Option<String>,
    }
}

allowlisted_image_row! {
    struct AdminGroupMemberImageRow {
        pub id: i64,
        pub group_id: Option<i64>,
        pub user_id: Option<i64>,
        pub created_at: Option<String>,
    }
}

allowlisted_image_row! {
    struct GradingImageRow {
        pub id: i64,
        pub user_id: Option<i64>,
        pub level_id: Option<i64>,
        pub domain_id: Option<i64>,
        pub created_at: Option<String>,
        pub updated_at: Option<String>,
    }
}

allowlisted_image_row! {
    struct PermissionActionImageRow {
        pub action_id: i64,
        pub domain_id: Option<i64>,
        pub resource_type_id: Option<i64>,
        pub action_code: Option<String>,
        pub action_name: Option<String>,
        pub action_description: Option<String>,
        pub created_at: Option<String>,
        pub updated_at: Option<String>,
    }
}

allowlisted_image_row! {
    struct ResourceTypeImageRow {
        pub id: i64,
        pub resource_type: Option<String>,
        pub actions_json: Option<String>,
        pub description: Option<String>,
        pub created_at: Option<String>,
        pub updated_at: Option<String>,
    }
}

/// 每表 allowlisted SELECT：列清单是编译期常量，值全部绑定参数；
/// CAST AS CHAR 保证文本/时间列统一成确定性文本（NULL 保持 NULL）。
const SOD_POLICY_IMAGE_SELECT: &str = "SELECT policy_id, CAST(policy_name AS CHAR) AS policy_name, \
     CAST(description AS CHAR) AS description, CAST(conflict_type AS CHAR) AS conflict_type, \
     CAST(resource_type AS CHAR) AS resource_type, CAST(action_code AS CHAR) AS action_code, \
     CAST(permission_a AS CHAR) AS permission_a, CAST(permission_b AS CHAR) AS permission_b, \
     CAST(condition_script AS CHAR) AS condition_script, limit_count, \
     CAST(limit_window AS CHAR) AS limit_window, CAST(status AS CHAR) AS status, \
     CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at FROM sod_policy";
const ADMIN_GROUP_IMAGE_SELECT: &str = "SELECT id, CAST(name AS CHAR) AS name, \
     CAST(description AS CHAR) AS description, CAST(scope AS CHAR) AS scope, \
     CAST(created_at AS CHAR) AS created_at FROM admin_group";
const ADMIN_GROUP_MEMBER_IMAGE_SELECT: &str = "SELECT id, group_id, user_id, \
     CAST(created_at AS CHAR) AS created_at FROM admin_group_member";
const GRADING_IMAGE_SELECT: &str = "SELECT id, user_id, level_id, domain_id, \
     CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at FROM identity_user_grading";
const PERMISSION_ACTION_IMAGE_SELECT: &str = "SELECT action_id, domain_id, resource_type_id, \
     CAST(action_code AS CHAR) AS action_code, CAST(action_name AS CHAR) AS action_name, \
     CAST(action_description AS CHAR) AS action_description, CAST(created_at AS CHAR) AS created_at, \
     CAST(updated_at AS CHAR) AS updated_at FROM permission_action";
const RESOURCE_TYPE_IMAGE_SELECT: &str = "SELECT id, CAST(resource_type AS CHAR) AS resource_type, \
     CAST(actions_json AS CHAR) AS actions_json, CAST(description AS CHAR) AS description, \
     CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at FROM resource_type_registry";

mod identity_config;
mod ruleset;
mod tenant_domain;

fn image_select_sql(
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<String, AstralError> {
    lookup_canonical(lookup, table)?;
    let predicate = match (table, lookup) {
        (TypedSourceTable::SodPolicy, TypedSourceRowLookup::PrimaryId { .. }) => "policy_id = ?",
        (TypedSourceTable::SodPolicy, TypedSourceRowLookup::SodPolicyName { .. }) => {
            "policy_name = ?"
        }
        (TypedSourceTable::AdminGroup, TypedSourceRowLookup::PrimaryId { .. }) => "id = ?",
        (TypedSourceTable::AdminGroup, TypedSourceRowLookup::AdminGroupInsertIntent { id, .. }) => {
            if *id <= 0 {
                return Err(AstralError::Validation(
                    "admin group capture lookup requires observed positive id".into(),
                ));
            }
            "id = ?"
        }
        (TypedSourceTable::AdminGroupMember, TypedSourceRowLookup::AdminGroupMember { .. }) => {
            "group_id = ? AND user_id = ?"
        }
        (TypedSourceTable::Grading, TypedSourceRowLookup::PrimaryId { .. }) => "id = ?",
        (TypedSourceTable::Grading, TypedSourceRowLookup::GradingUserDomain { .. }) => {
            "user_id = ? AND domain_id = ?"
        }
        (TypedSourceTable::PermissionAction, TypedSourceRowLookup::PrimaryId { .. }) => {
            "action_id = ?"
        }
        (TypedSourceTable::PermissionAction, TypedSourceRowLookup::PermissionActionCode { .. }) => {
            "resource_type_id = ? AND action_code = ?"
        }
        (TypedSourceTable::ResourceType, TypedSourceRowLookup::PrimaryId { .. }) => "id = ?",
        (TypedSourceTable::ResourceType, TypedSourceRowLookup::ResourceTypeCode { .. }) => {
            "resource_type = ?"
        }
        _ => {
            return Err(AstralError::Validation(format!(
                "typed source lookup is invalid for {}",
                table.as_str()
            )))
        }
    };
    let base = match table {
        TypedSourceTable::SodPolicy => SOD_POLICY_IMAGE_SELECT,
        TypedSourceTable::AdminGroup => ADMIN_GROUP_IMAGE_SELECT,
        TypedSourceTable::AdminGroupMember => ADMIN_GROUP_MEMBER_IMAGE_SELECT,
        TypedSourceTable::Grading => GRADING_IMAGE_SELECT,
        TypedSourceTable::PermissionAction => PERMISSION_ACTION_IMAGE_SELECT,
        TypedSourceTable::ResourceType => RESOURCE_TYPE_IMAGE_SELECT,
        _ => {
            return Err(AstralError::Validation(format!(
                "typed source table {} is handled by a dedicated capture module",
                table.as_str()
            )))
        }
    };
    Ok(format!("{base} WHERE {predicate} FOR UPDATE"))
}

/// 每个镜像行的主键字段名不同，用统一 trait 取 PK。
trait PkColumn {
    fn pk_column(&self) -> i64;
}

impl PkColumn for SodPolicyImageRow {
    fn pk_column(&self) -> i64 {
        self.policy_id
    }
}
impl PkColumn for AdminGroupImageRow {
    fn pk_column(&self) -> i64 {
        self.id
    }
}
impl PkColumn for AdminGroupMemberImageRow {
    fn pk_column(&self) -> i64 {
        self.id
    }
}
impl PkColumn for GradingImageRow {
    fn pk_column(&self) -> i64 {
        self.id
    }
}
impl PkColumn for PermissionActionImageRow {
    fn pk_column(&self) -> i64 {
        self.action_id
    }
}
impl PkColumn for ResourceTypeImageRow {
    fn pk_column(&self) -> i64 {
        self.id
    }
}

async fn read_legacy_row_image_in_tx(
    tx: &mut Transaction<'_, MySql>,
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let sql = image_select_sql(table, lookup)?;
    macro_rules! fetch {
        ($row:ty, $($bind:expr),+ $(,)?) => {{
            let mut query = sqlx::query_as::<_, $row>(&sql);
            $(query = query.bind($bind);)+
            query
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| TypedSourceReadError::from_sqlx("typed config source image readback", error))?
                .map(|row| {
                    let image_json = serde_json::to_string(&row).map_err(|error| {
                        TypedSourceReadError::Serialization(format!(
                            "typed config source image serialization failed: {error}"
                        ))
                    })?;
                    Ok::<CapturedRow, TypedSourceReadError>(CapturedRow {
                        pk: PkColumn::pk_column(&row),
                        image_json,
                    })
                })
                .transpose()?
        }};
    }
    Ok(match (table, lookup) {
        (TypedSourceTable::SodPolicy, TypedSourceRowLookup::PrimaryId { id }) => {
            fetch!(SodPolicyImageRow, id)
        }
        (TypedSourceTable::SodPolicy, TypedSourceRowLookup::SodPolicyName { name }) => {
            fetch!(SodPolicyImageRow, name)
        }
        (TypedSourceTable::AdminGroup, TypedSourceRowLookup::PrimaryId { id }) => {
            fetch!(AdminGroupImageRow, id)
        }
        (
            TypedSourceTable::AdminGroupMember,
            TypedSourceRowLookup::AdminGroupMember { group_id, user_id },
        ) => {
            fetch!(AdminGroupMemberImageRow, group_id, user_id)
        }
        (TypedSourceTable::Grading, TypedSourceRowLookup::PrimaryId { id }) => {
            fetch!(GradingImageRow, id)
        }
        (
            TypedSourceTable::Grading,
            TypedSourceRowLookup::GradingUserDomain { user_id, domain_id },
        ) => {
            fetch!(GradingImageRow, user_id, domain_id)
        }
        (TypedSourceTable::PermissionAction, TypedSourceRowLookup::PrimaryId { id }) => {
            fetch!(PermissionActionImageRow, id)
        }
        (
            TypedSourceTable::PermissionAction,
            TypedSourceRowLookup::PermissionActionCode {
                resource_type_id,
                action_code,
            },
        ) => {
            fetch!(PermissionActionImageRow, resource_type_id, action_code)
        }
        (TypedSourceTable::ResourceType, TypedSourceRowLookup::PrimaryId { id }) => {
            fetch!(ResourceTypeImageRow, id)
        }
        (TypedSourceTable::ResourceType, TypedSourceRowLookup::ResourceTypeCode { code }) => {
            fetch!(ResourceTypeImageRow, code)
        }
        (
            TypedSourceTable::AdminGroup,
            TypedSourceRowLookup::AdminGroupInsertIntent {
                id,
                name,
                description,
                scope,
            },
        ) if *id > 0 => {
            let row: Option<AdminGroupImageRow> = sqlx::query_as(&sql)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| {
                    TypedSourceReadError::from_sqlx("typed admin group image readback", error)
                })?;
            match row {
                Some(row)
                    if row.id == *id
                        && row.name.as_deref() == Some(name.as_str())
                        && row.description.as_deref() == description.as_deref()
                        && row.scope.as_deref() == scope.as_deref() =>
                {
                    let image_json = serde_json::to_string(&row).map_err(|error| {
                        TypedSourceReadError::Serialization(format!(
                            "typed admin group image serialization failed: {error}"
                        ))
                    })?;
                    Some(CapturedRow {
                        pk: row.id,
                        image_json,
                    })
                }
                Some(_) => {
                    return Err(TypedSourceReadError::Pending(
                        "typed admin group inserted row differs from its immutable insert intent"
                            .into(),
                    ))
                }
                None => None,
            }
        }
        (TypedSourceTable::AdminGroup, TypedSourceRowLookup::AdminGroupInsertIntent { .. }) => None,
        _ => {
            return Err(TypedSourceReadError::Validation(format!(
                "typed source lookup is not compatible with table {}",
                table.as_str()
            )))
        }
    })
}

async fn read_row_image_in_tx_typed(
    tx: &mut Transaction<'_, MySql>,
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    lookup.validate_for_table(table).map_err(|error| {
        TypedSourceReadError::Validation(format!(
            "typed source lookup is invalid for {}: {error:?}",
            table.as_str()
        ))
    })?;
    match table {
        TypedSourceTable::UserCardLevelDefinition
        | TypedSourceTable::IdentityLevelTemplate
        | TypedSourceTable::UserCardTemplate
        | TypedSourceTable::InheritanceConfig => {
            identity_config::capture_row_image_in_tx_typed(tx, table, lookup).await
        }
        TypedSourceTable::Department | TypedSourceTable::Domain | TypedSourceTable::Tenant => {
            tenant_domain::capture_row_image_in_tx_typed(tx, table, lookup).await
        }
        TypedSourceTable::RuleSet | TypedSourceTable::PermissionRuleTemplate => {
            ruleset::capture_row_image_in_tx_typed(tx, table, lookup).await
        }
        _ => read_legacy_row_image_in_tx(tx, table, lookup).await,
    }
}

async fn read_row_image_in_tx(
    tx: &mut Transaction<'_, MySql>,
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, AstralError> {
    read_row_image_in_tx_typed(tx, table, lookup)
        .await
        .map_err(AstralError::from)
}

/// capture 的纯状态部分（与事务借用解耦，便于无 DB 的不变式单测）。
#[derive(Debug)]
struct TypedSourceRowCaptureState {
    table: TypedSourceTable,
    operation: TypedRowOperation,
    before_lookup: Option<TypedSourceRowLookup>,
    after_lookup: Option<TypedSourceRowLookup>,
    before: Option<CapturedRow>,
    /// before 侧显式缺失（lookup 已记录）。
    before_absent: bool,
    after: Option<CapturedRow>,
    /// after 侧显式缺失（lookup 已记录）。
    after_absent: bool,
}

impl TypedSourceRowCaptureState {
    fn begin(table: TypedSourceTable, operation: TypedRowOperation) -> Self {
        Self {
            table,
            operation,
            before_lookup: None,
            after_lookup: None,
            before: None,
            before_absent: false,
            after: None,
            after_absent: false,
        }
    }

    fn bind_before_lookup(&mut self, lookup: &TypedSourceRowLookup) -> Result<(), AstralError> {
        if self.before_lookup.is_some() {
            return Err(AstralError::Validation(
                "typed config source capture already recorded its before lookup".into(),
            ));
        }
        if self.table == TypedSourceTable::AdminGroup && self.operation == TypedRowOperation::Insert
        {
            match lookup {
                TypedSourceRowLookup::AdminGroupInsertIntent {
                    id: 0,
                    name,
                    description,
                    scope,
                } => {
                    // Validate every caller-controlled intent field through the shared closed
                    // schema while keeping generated identity explicitly unresolved internally.
                    lookup_canonical(
                        &TypedSourceRowLookup::AdminGroupInsertIntent {
                            id: 1,
                            name: name.clone(),
                            description: description.clone(),
                            scope: scope.clone(),
                        },
                        self.table,
                    )?;
                }
                _ => {
                    lookup_canonical(lookup, self.table)?;
                }
            }
        } else {
            lookup_canonical(lookup, self.table)?;
        }
        self.before_lookup = Some(lookup.clone());
        Ok(())
    }

    fn bind_after_lookup(&mut self, lookup: &TypedSourceRowLookup) -> Result<(), AstralError> {
        lookup_canonical(lookup, self.table)?;
        let resolved_admin_insert = self.table == TypedSourceTable::AdminGroup
            && self.operation == TypedRowOperation::Insert
            && matches!(
                (self.before_lookup.as_ref(), lookup),
                (
                    Some(TypedSourceRowLookup::AdminGroupInsertIntent {
                        id: 0,
                        name: before_name,
                        description: before_description,
                        scope: before_scope,
                    }),
                    TypedSourceRowLookup::AdminGroupInsertIntent {
                        id: after_id,
                        name: after_name,
                        description: after_description,
                        scope: after_scope,
                    }
                ) if *after_id > 0
                    && before_name == after_name
                    && before_description == after_description
                    && before_scope == after_scope
            );
        if let Some(before) = self.before_lookup.as_ref() {
            if before != lookup && !resolved_admin_insert {
                return Err(AstralError::Validation(
                    "typed config source capture changed its row lookup between captures".into(),
                ));
            }
        } else {
            return Err(AstralError::Validation(
                "typed config source capture has no matching before lookup".into(),
            ));
        }
        if self.after_lookup.is_some() {
            return Err(AstralError::Validation(
                "typed config source capture already recorded its after lookup".into(),
            ));
        }
        self.after_lookup = Some(lookup.clone());
        Ok(())
    }

    fn record_before(&mut self, row: Option<CapturedRow>) -> Result<(), AstralError> {
        if self.before.is_some() || self.before_absent {
            return Err(AstralError::Validation(
                "typed config source capture already recorded its before image".into(),
            ));
        }
        match row {
            Some(row) => {
                self.before = Some(row);
            }
            None => {
                if matches!(
                    self.operation,
                    TypedRowOperation::Update | TypedRowOperation::Delete
                ) {
                    return Err(AstralError::Validation(format!(
                        "typed {} {} capture requires an existing row",
                        operation_text(self.operation).unwrap_or_else(|_| "UNKNOWN".into()),
                        self.table.as_str()
                    )));
                }
                self.before_absent = true;
            }
        }
        Ok(())
    }

    fn record_after(&mut self, row: Option<CapturedRow>) -> Result<(), AstralError> {
        if self.after.is_some() || self.after_absent {
            return Err(AstralError::Validation(
                "typed config source capture already recorded its after image".into(),
            ));
        }
        match row {
            Some(row) => {
                if matches!(self.operation, TypedRowOperation::Delete) {
                    return Err(AstralError::Validation(format!(
                        "typed DELETE of {} still sees its row after the mutation",
                        self.table.as_str()
                    )));
                }
                self.after = Some(row);
            }
            None => {
                if matches!(self.operation, TypedRowOperation::Delete) {
                    self.after_absent = true;
                } else {
                    return Err(AstralError::Validation(format!(
                        "typed {} of {} did not materialize its row",
                        operation_text(self.operation).unwrap_or_else(|_| "UNKNOWN".into()),
                        self.table.as_str()
                    )));
                }
            }
        }
        Ok(())
    }

    fn seal(self) -> Result<TypedSourceRowImageReceipt, AstralError> {
        let before_lookup = self
            .before_lookup
            .ok_or_else(|| AstralError::Validation("typed capture has no before lookup".into()))?;
        let after_lookup = self
            .after_lookup
            .ok_or_else(|| AstralError::Validation("typed capture has no after lookup".into()))?;
        let after_lookup_json = lookup_canonical(&after_lookup, self.table)?;
        let before_lookup_json = if self.table == TypedSourceTable::AdminGroup
            && self.operation == TypedRowOperation::Insert
            && matches!(
                before_lookup,
                TypedSourceRowLookup::AdminGroupInsertIntent { id: 0, .. }
            ) {
            // Generated-key absence is proven by the fixed auto-increment INSERT
            // returning this actual id; bind the ABSENT side to the same final
            // closed intent (including the observed key), not a caller-built PK.
            after_lookup_json.clone()
        } else {
            lookup_canonical(&before_lookup, self.table)?
        };
        let lookup_json = match self.operation {
            TypedRowOperation::Delete => before_lookup_json.clone(),
            _ => after_lookup_json.clone(),
        };
        // before 侧 bytes：真实行镜像 > 显式缺失 marker；fresh Insert 未做
        // before 捕获时按闭集事实合成 ABSENT marker（新主键必然先前不存在）。
        let before_image = match (&self.before, self.before_absent, self.operation) {
            (Some(row), _, _) => row.image_json.clone(),
            (None, true, _) => absent_marker_bytes(self.table, &before_lookup_json),
            (None, false, TypedRowOperation::Insert) => {
                absent_marker_bytes(self.table, &before_lookup_json)
            }
            (None, false, _) => {
                return Err(AstralError::Validation(format!(
                    "typed {} of {} requires a captured before image",
                    operation_text(self.operation).unwrap_or_else(|_| "UNKNOWN".into()),
                    self.table.as_str()
                )))
            }
        };
        // after 侧 bytes：真实行镜像 > 显式缺失 marker（仅 Delete）。
        let after_image = match (&self.after, self.after_absent) {
            (Some(row), _) => row.image_json.clone(),
            (None, true) => absent_marker_bytes(self.table, &after_lookup_json),
            (None, false) => {
                return Err(AstralError::Validation(format!(
                    "typed {} of {} requires a captured after image",
                    operation_text(self.operation).unwrap_or_else(|_| "UNKNOWN".into()),
                    self.table.as_str()
                )))
            }
        };
        // PK 一致性：两侧都命中真实行时必须同主键。
        match (&self.before, &self.after) {
            (Some(before), Some(after)) if before.pk != after.pk => {
                return Err(AstralError::Validation(
                    "typed config source capture read two different rows for before and after"
                        .into(),
                ));
            }
            _ => {}
        }
        let key = match (&self.after, &self.before) {
            (Some(after), _) => after.pk,
            (None, Some(before)) => before.pk,
            // Delete：after 缺失，key 取 before 行主键；两侧皆缺已不可达。
            (None, None) => {
                return Err(AstralError::Validation(
                    "typed config source capture has no actual row identity".into(),
                ))
            }
        };
        Ok(TypedSourceRowImageReceipt {
            table: self.table,
            key,
            operation: self.operation,
            lookup: lookup_json,
            before_image_digest: image_digest_hex(&before_image),
            after_image_digest: image_digest_hex(&after_image),
            before_image,
            after_image,
        })
    }
}

/// opaque 捕获句柄：**结构性地绑定单一 SQL 事务**。
///
/// `begin_in_tx` 取得 source 事务的独占可变借用；writer 的 mutation SQL
/// 只能经 [`TypedSourceRowCapture::with_tx_mut`] 在该事务上执行，因此
/// before 捕获、mutation、after 捕获在类型与生命周期上不可能跨事务
/// （不需要运行期 CONNECTION_ID 或环境身份）。writer 在 `seal` 消费本
/// 句柄后重新获得事务借用，继续 audit 关联与 receipt 登记。
pub struct TypedSourceRowCapture<'a> {
    tx: &'a mut Transaction<'static, MySql>,
    state: TypedSourceRowCaptureState,
}

impl<'a> TypedSourceRowCapture<'a> {
    /// 绑定 source 事务开始捕获。事务的独占借用随本句柄存续。
    pub fn begin_in_tx(
        tx: &'a mut Transaction<'static, MySql>,
        table: TypedSourceTable,
        operation: TypedRowOperation,
    ) -> Self {
        Self {
            tx,
            state: TypedSourceRowCaptureState::begin(table, operation),
        }
    }

    /// mutation 前捕获：`SELECT ... FOR UPDATE` 行锁下读回真实 before 镜像。
    ///
    /// Update/Delete 必须命中（缺失即 fail-closed）；Insert/Upsert 允许缺失，
    /// 缺失记录为显式 typed ABSENT marker。
    pub fn table(&self) -> TypedSourceTable {
        self.state.table
    }

    pub fn operation(&self) -> TypedRowOperation {
        self.state.operation
    }

    pub async fn capture_before_in_tx(
        &mut self,
        lookup: &TypedSourceRowLookup,
    ) -> Result<(), AstralError> {
        if matches!(lookup, TypedSourceRowLookup::AdminGroupInsertIntent { .. }) {
            return Err(AstralError::Validation(
                "admin group auto-id insert intent must use the delegate-owned insert capture"
                    .into(),
            ));
        }
        let row = read_row_image_in_tx(self.tx, self.state.table, lookup).await?;
        self.state.bind_before_lookup(lookup)?;
        self.state.record_before(row)
    }

    /// Execute the fixed admin_group auto-ID INSERT on the bound transaction and
    /// capture its exact generated identity and after row. This table has no
    /// unique natural key, so callers cannot safely pre-query or invent its id.
    /// The omitted auto-increment primary key guarantees the generated identity
    /// was absent before this INSERT; the immutable typed insert intent is
    /// retained in the ABSENT marker. Only the observed positive last_insert_id
    /// is then used for the locked after readback.
    pub async fn insert_admin_group_and_capture_in_tx(
        &mut self,
        intent: &TypedSourceRowLookup,
    ) -> Result<i64, AstralError> {
        let TypedSourceRowLookup::AdminGroupInsertIntent {
            id: intent_id,
            name,
            description,
            scope,
        } = intent
        else {
            return Err(AstralError::Validation(
                "admin group auto-id insert requires its typed immutable insert intent".into(),
            ));
        };
        if self.state.table != TypedSourceTable::AdminGroup
            || self.state.operation != TypedRowOperation::Insert
        {
            return Err(AstralError::Validation(
                "admin group delegate insert requires an INSERT capture for admin_group".into(),
            ));
        }
        if *intent_id != 0 {
            return Err(AstralError::Validation(
                "admin group insert intent must not claim an auto-generated id".into(),
            ));
        }
        self.state.bind_before_lookup(intent)?;
        self.state.record_before(None)?;
        let intent_name = name.clone();
        let intent_description = description.clone();
        let intent_scope = scope.clone();
        let name = intent_name.clone();
        let description = intent_description.clone();
        let scope = intent_scope.clone();
        let result = self
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO admin_group (name, description, scope) VALUES (?, ?, ?)",
                    )
                    .bind(name)
                    .bind(description)
                    .bind(scope)
                    .execute(&mut **tx)
                    .await
                    .map_err(|error| {
                        AstralError::Database(format!("typed admin group insert failed: {error}"))
                    })
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Validation(format!(
                "typed admin group insert affected {} rows; refusing an unproven source row",
                result.rows_affected()
            )));
        }
        let id = i64::try_from(result.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Database(
                    "typed admin group insert returned an unusable auto-id".into(),
                )
            })?;
        let resolved_lookup = TypedSourceRowLookup::AdminGroupInsertIntent {
            id,
            name: intent_name,
            description: intent_description,
            scope: intent_scope,
        };
        let row = read_row_image_in_tx(self.tx, self.state.table, &resolved_lookup)
            .await?
            .ok_or_else(|| {
                AstralError::Pending(
                    "typed admin group insert has no matching locked after row".into(),
                )
            })?;
        if row.pk != id {
            return Err(AstralError::Pending(
                "typed admin group insert after row differs from its generated auto-id".into(),
            ));
        }
        let _after_lookup_json = lookup_canonical(&resolved_lookup, self.state.table)?;
        self.state.bind_after_lookup(&resolved_lookup)?;
        self.state.record_after(Some(row))?;
        Ok(id)
    }

    fn record_generated_insert(
        &mut self,
        table: TypedSourceTable,
        lookup: TypedSourceRowLookup,
        row: CapturedRow,
    ) -> Result<i64, AstralError> {
        if self.state.table != table || self.state.operation != TypedRowOperation::Insert {
            return Err(AstralError::Validation(
                "generated insert capture has a different table or operation".into(),
            ));
        }
        let id = row.pk;
        self.state.bind_before_lookup(&lookup)?;
        self.state.record_before(None)?;
        self.state.bind_after_lookup(&lookup)?;
        self.state.record_after(Some(row))?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_department_and_capture_in_tx(
        &mut self,
        tenant_id: i64,
        sub_tenant_id: Option<i64>,
        name: String,
        code: Option<String>,
        parent_id: Option<i64>,
        sort_order: i32,
        description: Option<String>,
    ) -> Result<i64, AstralError> {
        if self.state.table != TypedSourceTable::Department
            || self.state.operation != TypedRowOperation::Insert
        {
            return Err(AstralError::Validation(
                "department insert requires its INSERT capture".into(),
            ));
        }
        let (id, row) = tenant_domain::insert_department_and_capture_in_tx(
            self.tx,
            tenant_domain::DepartmentInsert {
                tenant_id,
                sub_tenant_id,
                name: name.clone(),
                code: code.clone(),
                parent_id,
                sort_order,
                description: description.clone(),
            },
        )
        .await?;
        self.record_generated_insert(
            TypedSourceTable::Department,
            TypedSourceRowLookup::DepartmentInsertIntent {
                id,
                tenant_id,
                sub_tenant_id,
                dept_name: name,
                dept_code: code,
                parent_dept_id: parent_id,
                sort_order,
                description,
            },
            row,
        )
    }

    pub async fn insert_domain_and_capture_in_tx(
        &mut self,
        code: Option<String>,
        name: String,
        description: Option<String>,
        status: String,
    ) -> Result<i64, AstralError> {
        if self.state.table != TypedSourceTable::Domain
            || self.state.operation != TypedRowOperation::Insert
        {
            return Err(AstralError::Validation(
                "domain insert requires its INSERT capture".into(),
            ));
        }
        let (id, row) = tenant_domain::insert_domain_and_capture_in_tx(
            self.tx,
            code.clone(),
            name.clone(),
            description.clone(),
            status.clone(),
        )
        .await?;
        self.record_generated_insert(
            TypedSourceTable::Domain,
            TypedSourceRowLookup::DomainInsertIntent {
                id,
                domain_code: code,
                domain_name: name,
                domain_description: description,
                status,
            },
            row,
        )
    }

    pub async fn insert_tenant_and_capture_in_tx(
        &mut self,
        tenant_code: String,
        name: String,
        parent_id: Option<i64>,
        path: String,
        depth: i32,
    ) -> Result<i64, AstralError> {
        if self.state.table != TypedSourceTable::Tenant
            || self.state.operation != TypedRowOperation::Insert
        {
            return Err(AstralError::Validation(
                "tenant insert requires its INSERT capture".into(),
            ));
        }
        let (id, row) = tenant_domain::insert_tenant_and_capture_in_tx(
            self.tx,
            tenant_code.clone(),
            name.clone(),
            parent_id,
            path.clone(),
            depth,
        )
        .await?;
        let final_path = if depth == 0 {
            format!("/{id}")
        } else {
            format!("{}/{id}", path.trim_end_matches('/'))
        };
        self.record_generated_insert(
            TypedSourceTable::Tenant,
            TypedSourceRowLookup::TenantInsertIntent {
                id,
                tenant_code,
                tenant_name: name,
                tenant_type: "ENTERPRISE".into(),
                parent_tenant_id: parent_id,
                path: final_path,
                depth,
            },
            row,
        )
    }

    /// mutation 后回读：同一 lookup 的真实 after 镜像。
    ///
    /// Insert/Upsert/Update 必须命中；Delete 必须证明缺失。
    pub async fn capture_after_in_tx(
        &mut self,
        lookup: &TypedSourceRowLookup,
    ) -> Result<(), AstralError> {
        let row = read_row_image_in_tx(self.tx, self.state.table, lookup).await?;
        self.state.bind_after_lookup(lookup)?;
        self.state.record_after(row)
    }

    /// 在被绑定的 source 事务上执行一段 writer SQL（唯一的事务访问通道）。
    ///
    /// 典型用途：执行 mutation 语句并同事务读回物理 id。 future 经
    /// `Box::pin` 借用事务，生命周期由签名约束到本次调用。
    pub async fn with_tx_mut<R: Send>(
        &mut self,
        run: impl for<'t> FnOnce(
                &'t mut Transaction<'static, MySql>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<R, AstralError>> + Send + 't>,
            > + Send,
    ) -> Result<R, AstralError> {
        run(&mut *self.tx).await
    }
}

/// 密封捕获：receipt 的**唯一**构造点。
///
/// 密封本身不做 IO：镜像 bytes 已由 `capture_*_in_tx` 在被绑定的事务内
/// 读回；seal 只做不变式核验与 digest 派生（`sha256(bytes)`）。消费句柄
/// 即释放事务借用。
pub fn seal_typed_source_row_capture_tx(
    capture: TypedSourceRowCapture<'_>,
) -> Result<TypedSourceRowImageReceipt, AstralError> {
    capture.state.seal()
}

/// 密封后的 typed config 行镜像 receipt（opaque）。
///
/// Serialize-only（供诊断），**没有** `Deserialize`、没有 pub 字段：唯一
/// 构造点是 [`seal_typed_source_row_capture_tx`]，其他 Rust 调用方无法伪造。
/// digest 是 `sha256(本 receipt 暴露的 image bytes)`，stage 侧对 retained
/// bytes 重算即可对账。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedSourceRowImageReceipt {
    table: TypedSourceTable,
    key: i64,
    operation: TypedRowOperation,
    lookup: String,
    before_image: String,
    after_image: String,
    before_image_digest: String,
    after_image_digest: String,
}

impl TypedSourceRowImageReceipt {
    pub fn table(&self) -> TypedSourceTable {
        self.table
    }

    /// 实际回读行主键（Delete 取 before 行主键）。
    pub fn key(&self) -> i64 {
        self.key
    }

    pub fn operation(&self) -> TypedRowOperation {
        self.operation
    }

    /// The canonical compact JSON representation of the closed shared lookup enum.
    pub fn lookup(&self) -> &str {
        &self.lookup
    }

    /// 实际 before 镜像 bytes（缺失侧为 canonical ABSENT marker bytes）。
    pub fn before_image(&self) -> &str {
        &self.before_image
    }

    /// 实际 after 镜像 bytes（Delete 侧为 canonical ABSENT marker bytes）。
    pub fn after_image(&self) -> &str {
        &self.after_image
    }

    pub fn before_image_digest(&self) -> &str {
        &self.before_image_digest
    }

    pub fn after_image_digest(&self) -> &str {
        &self.after_image_digest
    }
}

/// 同事务 audit_log 关联 receipt（Serialize-only，无 Deserialize/pub 字段）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedSourceAuditReceipt {
    audit_log_id: i64,
}

impl TypedSourceAuditReceipt {
    /// 用同一事务内 audit INSERT 的真实 `last_insert_id` 构造。
    pub fn from_same_tx_insert_id(audit_log_id: i64) -> Result<Self, AstralError> {
        if audit_log_id <= 0 {
            return Err(AstralError::Validation(
                "typed source audit receipt requires a positive audit_log id".into(),
            ));
        }
        Ok(Self { audit_log_id })
    }

    pub fn audit_log_id(&self) -> i64 {
        self.audit_log_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(table: TypedSourceTable, operation: TypedRowOperation) -> TypedSourceRowCaptureState {
        TypedSourceRowCaptureState::begin(table, operation)
    }

    fn row(pk: i64, body: &str) -> CapturedRow {
        CapturedRow {
            pk,
            image_json: format!("{{\"id\":{pk},\"body\":\"{body}\"}}"),
        }
    }

    #[test]
    fn absent_marker_is_phase_independent_and_table_key_injective() {
        let sod_lookup = TypedSourceRowLookup::PrimaryId { id: 5 };
        let a = typed_source_absent_image(TypedSourceTable::SodPolicy, &sod_lookup).unwrap();
        let b = typed_source_absent_image(TypedSourceTable::SodPolicy, &sod_lookup).unwrap();
        assert_eq!(a, b, "same absent content must stay byte-stable");
        let other_key = typed_source_absent_image(
            TypedSourceTable::SodPolicy,
            &TypedSourceRowLookup::PrimaryId { id: 6 },
        )
        .unwrap();
        assert_ne!(image_digest_hex(&a), image_digest_hex(&other_key));
        let other_table = typed_source_absent_image(
            TypedSourceTable::ResourceType,
            &TypedSourceRowLookup::PrimaryId { id: 5 },
        )
        .unwrap();
        assert_ne!(image_digest_hex(&a), image_digest_hex(&other_table));
        let lookup_json = serde_json::to_string(&sod_lookup).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&a).expect("marker is canonical JSON");
        assert_eq!(parsed["table"], "sod_policy");
        assert_eq!(parsed["lookup"], lookup_json);
        assert_eq!(parsed["presence"], "ABSENT");
    }

    #[test]
    fn digest_is_sha256_of_the_exact_image_bytes_without_extra_domain() {
        let bytes = "{\"id\":1}".to_string();
        assert_eq!(
            image_digest_hex(&bytes),
            hex::encode(Sha256::digest(bytes.as_bytes()))
        );
    }

    #[test]
    fn fresh_insert_seal_binds_the_absent_marker_to_the_after_lookup() {
        let mut capture = state(TypedSourceTable::SodPolicy, TypedRowOperation::Insert);
        let lookup = TypedSourceRowLookup::PrimaryId { id: 7 };
        capture.bind_before_lookup(&lookup).expect("lookup ok");
        capture.record_before(None).expect("insert before absent");
        capture.bind_after_lookup(&lookup).expect("after lookup ok");
        capture
            .record_after(Some(row(7, "after")))
            .expect("after ok");
        let receipt = capture.seal().expect("fresh insert seal");
        assert_eq!(receipt.key(), 7);
        assert_eq!(
            receipt.before_image(),
            typed_source_absent_image(TypedSourceTable::SodPolicy, &lookup).unwrap()
        );
        assert_eq!(receipt.after_image(), row(7, "after").image_json);
        assert_eq!(
            receipt.before_image_digest(),
            image_digest_hex(receipt.before_image())
        );
        assert_eq!(
            receipt.after_image_digest(),
            image_digest_hex(receipt.after_image())
        );
    }

    #[test]
    fn update_and_delete_seals_keep_full_image_pairs() {
        let grading_lookup = TypedSourceRowLookup::PrimaryId { id: 9 };
        let mut update = state(TypedSourceTable::Grading, TypedRowOperation::Update);
        update
            .bind_before_lookup(&grading_lookup)
            .expect("lookup ok");
        update
            .record_before(Some(row(9, "before")))
            .expect("before ok");
        update
            .bind_after_lookup(&grading_lookup)
            .expect("after lookup ok");
        update
            .record_after(Some(row(9, "after")))
            .expect("after ok");
        let receipt = update.seal().expect("update seal");
        assert_eq!(receipt.before_image(), row(9, "before").image_json);
        assert_eq!(receipt.after_image(), row(9, "after").image_json);

        let mut delete = state(TypedSourceTable::Grading, TypedRowOperation::Delete);
        delete
            .bind_before_lookup(&grading_lookup)
            .expect("lookup ok");
        delete
            .record_before(Some(row(9, "before")))
            .expect("before ok");
        delete
            .bind_after_lookup(&grading_lookup)
            .expect("after lookup ok");
        delete.record_after(None).expect("absent after ok");
        let receipt = delete.seal().expect("delete seal");
        assert_eq!(receipt.key(), 9);
        assert_eq!(
            receipt.after_image(),
            absent_marker_bytes(
                TypedSourceTable::Grading,
                &lookup_canonical(&grading_lookup, TypedSourceTable::Grading).unwrap(),
            )
        );
    }

    #[test]
    fn seal_rejects_missing_sides_pk_drift_and_unbound_capture() {
        // Update without a before capture。
        let lookup = TypedSourceRowLookup::PrimaryId { id: 9 };
        let mut missing_before = state(TypedSourceTable::Grading, TypedRowOperation::Update);
        missing_before
            .bind_before_lookup(&lookup)
            .expect("lookup ok");
        missing_before
            .bind_after_lookup(&lookup)
            .expect("after lookup ok");
        missing_before
            .record_after(Some(row(9, "after")))
            .expect("after ok");
        assert!(missing_before.seal().is_err());
        // Insert without an after capture。
        let mut missing_after = state(TypedSourceTable::Grading, TypedRowOperation::Insert);
        missing_after
            .bind_before_lookup(&lookup)
            .expect("lookup ok");
        missing_after
            .record_before(Some(row(9, "before")))
            .expect("before ok");
        assert!(missing_after.seal().is_err());
        // Delete with a still-present after row。
        let mut delete_present = state(TypedSourceTable::Grading, TypedRowOperation::Delete);
        delete_present
            .bind_before_lookup(&lookup)
            .expect("lookup ok");
        delete_present
            .record_before(Some(row(9, "before")))
            .expect("before ok");
        delete_present
            .bind_after_lookup(&lookup)
            .expect("after lookup ok");
        delete_present
            .record_after(Some(row(9, "after")))
            .expect_err("present after must fail");
        // PK drift between before and after。
        let mut drifted = state(TypedSourceTable::Grading, TypedRowOperation::Update);
        drifted.bind_before_lookup(&lookup).expect("lookup ok");
        drifted
            .record_before(Some(row(9, "before")))
            .expect("before ok");
        drifted.bind_after_lookup(&lookup).expect("after lookup ok");
        drifted
            .record_after(Some(row(10, "after")))
            .expect("after ok");
        assert!(drifted.seal().is_err());
        // 从未绑定 lookup 的 capture 不可密封。
        assert!(state(TypedSourceTable::Grading, TypedRowOperation::Delete)
            .seal()
            .is_err());
        // Update/Delete 的 before 缺失必须在捕获时被拒绝。
        let mut absent_before = state(TypedSourceTable::Grading, TypedRowOperation::Update);
        absent_before
            .bind_before_lookup(&lookup)
            .expect("lookup ok");
        assert!(absent_before.record_before(None).is_err());
    }

    #[test]
    fn lookups_are_validated_against_their_table_and_bounds() {
        assert!(lookup_canonical(
            &TypedSourceRowLookup::PrimaryId { id: 0 },
            TypedSourceTable::SodPolicy,
        )
        .is_err());
        assert!(lookup_canonical(
            &TypedSourceRowLookup::ResourceTypeCode { code: " ".into() },
            TypedSourceTable::ResourceType,
        )
        .is_err());
        assert!(lookup_canonical(
            &TypedSourceRowLookup::PrimaryId { id: 5 },
            TypedSourceTable::SodPolicy,
        )
        .is_ok());
        assert!(lookup_canonical(
            &TypedSourceRowLookup::PrimaryId { id: 5 },
            TypedSourceTable::AdminGroupMember,
        )
        .is_err());
        let member = TypedSourceRowLookup::AdminGroupMember {
            group_id: 1,
            user_id: 2,
        };
        assert!(lookup_canonical(&member, TypedSourceTable::AdminGroupMember).is_ok());
        assert_eq!(
            lookup_canonical(
                &TypedSourceRowLookup::PrimaryId { id: 5 },
                TypedSourceTable::SodPolicy
            )
            .expect("ok"),
            r#"{"kind":"primary_id","id":5}"#
        );
    }

    #[test]
    fn audit_receipt_rejects_non_positive_ids() {
        assert!(TypedSourceAuditReceipt::from_same_tx_insert_id(0).is_err());
        let receipt = TypedSourceAuditReceipt::from_same_tx_insert_id(42).expect("ok");
        assert_eq!(receipt.audit_log_id(), 42);
    }

    #[test]
    fn table_and_operation_serialization_follow_the_allowlist_strings() {
        let table_json = serde_json::to_string(&TypedSourceTable::Grading).expect("ok");
        assert_eq!(table_json, "\"identity_user_grading\"");
        let operation_json = serde_json::to_string(&TypedRowOperation::Upsert).expect("ok");
        assert_eq!(operation_json, "\"UPSERT\"");
    }
}
