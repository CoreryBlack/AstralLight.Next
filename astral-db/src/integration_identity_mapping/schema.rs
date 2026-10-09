use super::{
    db_error, IntegrationIdentityMappingError, MAPPING_CARD_FK, MAPPING_CARD_INDEX,
    MAPPING_IDENTITY_UNIQUE_INDEX, MAPPING_TABLE, MAPPING_USER_FK, MAPPING_USER_INDEX,
    OPERATION_TABLE,
};
use sqlx::mysql::{MySqlPool, MySqlRow};
use sqlx::Row;

/// Read-only preflight for the feature-gated mapping repository. It validates
/// engines, full column shape/types, exact indexes, key/FK contracts, and table
/// collation; it never creates or repairs schema.
pub async fn validate_integration_mapping_schema(
    pool: &MySqlPool,
) -> Result<(), IntegrationIdentityMappingError> {
    validate_table_contract(pool, MAPPING_TABLE).await?;
    validate_table_contract(pool, OPERATION_TABLE).await?;
    validate_columns(pool, MAPPING_TABLE, MAPPING_COLUMNS).await?;
    validate_columns(pool, OPERATION_TABLE, OPERATION_COLUMNS).await?;
    validate_indexes(pool, MAPPING_TABLE, MAPPING_INDEXES).await?;
    validate_indexes(pool, OPERATION_TABLE, OPERATION_INDEXES).await?;
    validate_foreign_keys(pool).await?;
    validate_audit_columns(pool).await?;
    validate_audit_engine(pool).await?;
    Ok(())
}

/// information_schema 文本列按 `CAST(... AS BINARY)` 读取后做严格 UTF-8 解码：
/// 与 session_state_repository 的元数据契约同形态——部分 sqlx 结果路径下
/// information_schema 列的预处理元数据报 BINARY，String 解码会被拒；
/// 任何解码/解析失败一律 fail-closed 报错而非放行。
fn mapping_utf8_column(
    raw: Vec<u8>,
    context: &'static str,
) -> Result<String, IntegrationIdentityMappingError> {
    String::from_utf8(raw)
        .map_err(|error| IntegrationIdentityMappingError::Database(format!("{context}: {error}")))
}

fn mapping_utf8_column_opt(
    raw: Option<Vec<u8>>,
    context: &'static str,
) -> Result<Option<String>, IntegrationIdentityMappingError> {
    raw.map(|value| mapping_utf8_column(value, context))
        .transpose()
}

fn mapping_utf8_field(
    row: &MySqlRow,
    column: &'static str,
    context: &'static str,
) -> Result<String, IntegrationIdentityMappingError> {
    let raw: Vec<u8> = row
        .try_get(column)
        .map_err(|error| db_error(context, error))?;
    mapping_utf8_column(raw, context)
}

fn mapping_utf8_field_opt(
    row: &MySqlRow,
    column: &'static str,
    context: &'static str,
) -> Result<Option<String>, IntegrationIdentityMappingError> {
    let raw: Option<Vec<u8>> = row
        .try_get(column)
        .map_err(|error| db_error(context, error))?;
    mapping_utf8_column_opt(raw, context)
}

/// `information_schema.TABLES` 行的 BINARY 解码形态（ENGINE、TABLE_COLLATION、TABLE_TYPE）。
type TableMetadata = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);

async fn validate_table_contract(
    pool: &MySqlPool,
    table: &'static str,
) -> Result<(), IntegrationIdentityMappingError> {
    let metadata: Option<TableMetadata> = sqlx::query_as(
        "SELECT CAST(ENGINE AS BINARY), CAST(TABLE_COLLATION AS BINARY), \
                CAST(TABLE_TYPE AS BINARY) FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
    )
    .bind(table)
    .fetch_optional(pool)
    .await
    .map_err(|error| db_error("inspect integration mapping table", error))?;
    let Some((engine, collation, table_type)) = metadata else {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
            "missing {table} base table"
        )));
    };
    let engine = mapping_utf8_column(engine, "decode integration mapping engine")?;
    let collation =
        mapping_utf8_column_opt(collation, "decode integration mapping table collation")?;
    let table_type = mapping_utf8_column(table_type, "decode integration mapping table type")?;
    if engine != "InnoDB"
        || table_type != "BASE TABLE"
        || collation.as_deref() != Some("utf8mb4_bin")
    {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
            "{table} must be an InnoDB BASE TABLE with utf8mb4_bin collation"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnShape {
    name: &'static str,
    column_type: &'static str,
    nullable: &'static str,
    charset: Option<&'static str>,
    collation: Option<&'static str>,
    extra: &'static str,
}

const MAPPING_COLUMNS: &[ColumnShape] = &[
    ColumnShape {
        name: "mapping_id",
        column_type: "bigint unsigned",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "auto_increment",
    },
    ColumnShape {
        name: "app_id",
        column_type: "varbinary(64)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "issuer",
        column_type: "varbinary(512)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "subject",
        column_type: "varbinary(512)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "user_id",
        column_type: "bigint",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "identity_card_id",
        column_type: "bigint",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "status",
        column_type: "enum('active','disabled','revoked')",
        nullable: "NO",
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
        extra: "",
    },
    ColumnShape {
        name: "revision",
        column_type: "bigint unsigned",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "created_by",
        column_type: "bigint",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "updated_by",
        column_type: "bigint",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "operation_id",
        column_type: "varbinary(64)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "created_at",
        column_type: "timestamp(6)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "updated_at",
        column_type: "timestamp(6)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "on update current_timestamp(6)",
    },
];

const OPERATION_COLUMNS: &[ColumnShape] = &[
    ColumnShape {
        name: "operation_id",
        column_type: "varbinary(64)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "request_digest",
        column_type: "binary(32)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "actor_id",
        column_type: "bigint",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "status",
        column_type: "enum('pending','completed')",
        nullable: "NO",
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
        extra: "",
    },
    ColumnShape {
        name: "result_revision",
        column_type: "bigint unsigned",
        nullable: "YES",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "claim_token",
        column_type: "binary(16)",
        nullable: "YES",
        charset: None,
        collation: None,
        extra: "",
    },
    ColumnShape {
        name: "created_at",
        column_type: "timestamp(6)",
        nullable: "NO",
        charset: None,
        collation: None,
        extra: "",
    },
];

async fn validate_columns(
    pool: &MySqlPool,
    table: &'static str,
    expected: &[ColumnShape],
) -> Result<(), IntegrationIdentityMappingError> {
    let rows = sqlx::query(
        "SELECT CAST(COLUMN_NAME AS BINARY) AS COLUMN_NAME, \
                CAST(COLUMN_TYPE AS BINARY) AS COLUMN_TYPE, \
                CAST(IS_NULLABLE AS BINARY) AS IS_NULLABLE, \
                CAST(CHARACTER_SET_NAME AS BINARY) AS CHARACTER_SET_NAME, \
                CAST(COLLATION_NAME AS BINARY) AS COLLATION_NAME, \
                CAST(EXTRA AS BINARY) AS EXTRA \
         FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? \
         ORDER BY ORDINAL_POSITION",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .map_err(|error| db_error("inspect integration mapping columns", error))?;

    if rows.len() != expected.len() {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
            "{table} has {} columns; expected exactly {}",
            rows.len(),
            expected.len()
        )));
    }
    for (row, contract) in rows.iter().zip(expected) {
        let name: String =
            mapping_utf8_field(row, "COLUMN_NAME", "decode integration mapping column name")?;
        let column_type: String =
            mapping_utf8_field(row, "COLUMN_TYPE", "decode integration mapping column type")?;
        let nullable: String =
            mapping_utf8_field(row, "IS_NULLABLE", "decode integration mapping nullability")?;
        let charset: Option<String> = mapping_utf8_field_opt(
            row,
            "CHARACTER_SET_NAME",
            "decode integration mapping charset",
        )?;
        let collation: Option<String> = mapping_utf8_field_opt(
            row,
            "COLLATION_NAME",
            "decode integration mapping collation",
        )?;
        let extra: String =
            mapping_utf8_field(row, "EXTRA", "decode integration mapping column extra")?;
        if name != contract.name
            || column_type.to_ascii_lowercase() != contract.column_type
            || nullable != contract.nullable
            || charset.as_deref().map(str::to_ascii_lowercase).as_deref() != contract.charset
            || collation.as_deref().map(str::to_ascii_lowercase).as_deref() != contract.collation
            || extra
                .to_ascii_lowercase()
                .replace("default_generated", "")
                .trim()
                != contract.extra
        {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "{table}.{name} does not match the exact column contract"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexPart {
    index_name: String,
    non_unique: i64,
    sequence: u32,
    column_name: String,
    sub_part: Option<i64>,
    index_type: String,
}

#[derive(Debug, Clone, Copy)]
struct IndexShape {
    name: &'static str,
    unique: bool,
    columns: &'static [&'static str],
}

const MAPPING_INDEXES: &[IndexShape] = &[
    IndexShape {
        name: "PRIMARY",
        unique: true,
        columns: &["mapping_id"],
    },
    IndexShape {
        name: MAPPING_IDENTITY_UNIQUE_INDEX,
        unique: true,
        columns: &["app_id", "issuer", "subject"],
    },
    IndexShape {
        name: MAPPING_USER_INDEX,
        unique: false,
        columns: &["user_id"],
    },
    IndexShape {
        name: MAPPING_CARD_INDEX,
        unique: false,
        columns: &["identity_card_id"],
    },
];
const OPERATION_INDEXES: &[IndexShape] = &[IndexShape {
    name: "PRIMARY",
    unique: true,
    columns: &["operation_id"],
}];

async fn validate_indexes(
    pool: &MySqlPool,
    table: &'static str,
    expected: &[IndexShape],
) -> Result<(), IntegrationIdentityMappingError> {
    let rows = sqlx::query(
        "SELECT CAST(INDEX_NAME AS BINARY) AS INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, \
                CAST(COLUMN_NAME AS BINARY) AS COLUMN_NAME, SUB_PART, \
                CAST(INDEX_TYPE AS BINARY) AS INDEX_TYPE \
         FROM information_schema.STATISTICS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? \
         ORDER BY INDEX_NAME, SEQ_IN_INDEX",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .map_err(|error| db_error("inspect integration mapping indexes", error))?;
    let mut actual = Vec::with_capacity(rows.len());
    for row in rows {
        actual.push(IndexPart {
            index_name: mapping_utf8_field(
                &row,
                "INDEX_NAME",
                "decode integration mapping index name",
            )?,
            non_unique: row
                .try_get("NON_UNIQUE")
                .map_err(|error| db_error("decode integration mapping index uniqueness", error))?,
            sequence: row
                .try_get("SEQ_IN_INDEX")
                .map_err(|error| db_error("decode integration mapping index sequence", error))?,
            column_name: mapping_utf8_field(
                &row,
                "COLUMN_NAME",
                "decode integration mapping index column",
            )?,
            sub_part: row
                .try_get("SUB_PART")
                .map_err(|error| db_error("decode integration mapping index prefix", error))?,
            index_type: mapping_utf8_field(
                &row,
                "INDEX_TYPE",
                "decode integration mapping index type",
            )?,
        });
    }
    let expected_parts: usize = expected.iter().map(|index| index.columns.len()).sum();
    if actual.len() != expected_parts {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
            "{table} has {} index parts; expected exactly {expected_parts}",
            actual.len()
        )));
    }
    for contract in expected {
        let parts: Vec<_> = actual
            .iter()
            .filter(|part| part.index_name == contract.name)
            .collect();
        if parts.len() != contract.columns.len()
            || parts.iter().enumerate().any(|(offset, part)| {
                part.non_unique != i64::from(!contract.unique)
                    || part.sequence != (offset + 1) as u32
                    || part.column_name != contract.columns[offset]
                    || part.sub_part.is_some()
                    || !part.index_type.eq_ignore_ascii_case("BTREE")
            })
        {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "{table}.{index} has a non-canonical index contract",
                index = contract.name
            )));
        }
    }
    let expected_names: std::collections::BTreeSet<_> =
        expected.iter().map(|index| index.name).collect();
    let actual_names: std::collections::BTreeSet<_> =
        actual.iter().map(|part| part.index_name.as_str()).collect();
    if expected_names != actual_names {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
            "{table} index names differ from the exact contract"
        )));
    }
    Ok(())
}

async fn validate_foreign_keys(pool: &MySqlPool) -> Result<(), IntegrationIdentityMappingError> {
    let rows = sqlx::query(
        "SELECT CAST(k.CONSTRAINT_NAME AS BINARY) AS CONSTRAINT_NAME, \
                CAST(k.COLUMN_NAME AS BINARY) AS COLUMN_NAME, \
                CAST(k.REFERENCED_TABLE_SCHEMA AS BINARY) AS REFERENCED_TABLE_SCHEMA, \
                CAST(k.REFERENCED_TABLE_NAME AS BINARY) AS REFERENCED_TABLE_NAME, \
                CAST(k.REFERENCED_COLUMN_NAME AS BINARY) AS REFERENCED_COLUMN_NAME, \
                k.ORDINAL_POSITION, \
                CAST(r.DELETE_RULE AS BINARY) AS DELETE_RULE, \
                CAST(r.UPDATE_RULE AS BINARY) AS UPDATE_RULE \
         FROM information_schema.KEY_COLUMN_USAGE AS k \
         INNER JOIN information_schema.REFERENTIAL_CONSTRAINTS AS r \
           ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA \
          AND r.TABLE_NAME = k.TABLE_NAME AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME \
         WHERE k.CONSTRAINT_SCHEMA = DATABASE() \
           AND k.TABLE_NAME = 'integration_identity_mapping' \
           AND k.REFERENCED_TABLE_NAME IS NOT NULL \
         ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| db_error("inspect integration mapping foreign keys", error))?;
    if rows.len() != 2 {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(
            "mapping table must have exactly two source identity foreign keys".into(),
        ));
    }
    let current_schema: Vec<u8> = sqlx::query_scalar("SELECT CAST(DATABASE() AS BINARY)")
        .fetch_one(pool)
        .await
        .map_err(|error| db_error("resolve current database for mapping foreign keys", error))?;
    let current_schema =
        mapping_utf8_column(current_schema, "decode mapping foreign key database")?;
    for (row, (name, column, referenced_table, referenced_column)) in rows.iter().zip([
        (
            MAPPING_CARD_FK,
            "identity_card_id",
            "identity_card",
            "card_id",
        ),
        (MAPPING_USER_FK, "user_id", "platform_user", "user_id"),
    ]) {
        let actual_name: String =
            mapping_utf8_field(row, "CONSTRAINT_NAME", "decode mapping foreign key name")?;
        let actual_column: String =
            mapping_utf8_field(row, "COLUMN_NAME", "decode mapping foreign key column")?;
        let actual_schema: String = mapping_utf8_field(
            row,
            "REFERENCED_TABLE_SCHEMA",
            "decode mapping foreign key schema",
        )?;
        let actual_table: String = mapping_utf8_field(
            row,
            "REFERENCED_TABLE_NAME",
            "decode mapping foreign key table",
        )?;
        let actual_ref_column: String = mapping_utf8_field(
            row,
            "REFERENCED_COLUMN_NAME",
            "decode mapping foreign key target",
        )?;
        let ordinal: u32 = row
            .try_get("ORDINAL_POSITION")
            .map_err(|error| db_error("decode mapping foreign key ordinal", error))?;
        let delete_rule: String =
            mapping_utf8_field(row, "DELETE_RULE", "decode mapping foreign key delete rule")?;
        let update_rule: String =
            mapping_utf8_field(row, "UPDATE_RULE", "decode mapping foreign key update rule")?;
        if actual_name != name
            || actual_column != column
            || actual_schema != current_schema
            || actual_table != referenced_table
            || actual_ref_column != referenced_column
            || ordinal != 1
            || delete_rule != "RESTRICT"
            || update_rule != "RESTRICT"
        {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "mapping foreign key {name} does not match the source binding contract"
            )));
        }
    }
    Ok(())
}

async fn validate_audit_engine(pool: &MySqlPool) -> Result<(), IntegrationIdentityMappingError> {
    let shape: Option<(Option<Vec<u8>>, Vec<u8>)> = sqlx::query_as(
        "SELECT CAST(ENGINE AS BINARY), CAST(TABLE_TYPE AS BINARY) \
         FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_log'",
    )
    .fetch_optional(pool)
    .await
    .map_err(|error| db_error("inspect mapping audit engine", error))?;
    let shape = match shape {
        Some((engine, table_type)) => Some((
            mapping_utf8_column_opt(engine, "decode mapping audit engine")?,
            mapping_utf8_column(table_type, "decode mapping audit table type")?,
        )),
        None => None,
    };
    if !matches!(shape.as_ref(), Some((Some(engine), kind)) if engine == "InnoDB" && kind == "BASE TABLE")
    {
        return Err(IntegrationIdentityMappingError::SchemaMismatch(
            "audit_log must be a transactional InnoDB BASE TABLE".into(),
        ));
    }
    Ok(())
}

async fn validate_audit_columns(pool: &MySqlPool) -> Result<(), IntegrationIdentityMappingError> {
    const REQUIRED: &[(&str, &str, &str)] = &[
        ("user_id", "bigint", "NO"),
        ("action", "varchar(64)", "NO"),
        ("resource", "varchar(256)", "NO"),
        ("decision", "varchar(16)", "NO"),
        ("reason", "varchar(256)", "YES"),
        ("card_id", "bigint", "YES"),
        ("event_type", "varchar(32)", "YES"),
        ("request_id", "varchar(64)", "YES"),
        ("detail", "text", "YES"),
        ("tenant_id", "bigint", "YES"),
        ("domain_id", "bigint", "YES"),
        ("created_at", "timestamp", "YES"),
    ];
    for (name, column_type, nullable) in REQUIRED {
        let metadata: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT CAST(COLUMN_TYPE AS BINARY), CAST(IS_NULLABLE AS BINARY) \
             FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_log' \
               AND COLUMN_NAME = ?",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(|error| db_error("inspect mapping audit column", error))?;
        let Some((raw_type, raw_nullable)) = metadata else {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "audit_log.{name} is missing"
            )));
        };
        let actual_type = mapping_utf8_column(raw_type, "decode mapping audit column type")?;
        let actual_nullable =
            mapping_utf8_column(raw_nullable, "decode mapping audit column nullability")?;
        if actual_type.to_ascii_lowercase() != *column_type || actual_nullable != *nullable {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "audit_log.{name} does not match the mutation audit contract"
            )));
        }
    }
    Ok(())
}
