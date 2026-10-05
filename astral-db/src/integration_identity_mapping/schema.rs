use super::{
    db_error, IntegrationIdentityMappingError, MAPPING_CARD_FK, MAPPING_CARD_INDEX,
    MAPPING_IDENTITY_UNIQUE_INDEX, MAPPING_TABLE, MAPPING_USER_FK, MAPPING_USER_INDEX,
    OPERATION_TABLE,
};
use sqlx::mysql::MySqlPool;
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

async fn validate_table_contract(
    pool: &MySqlPool,
    table: &'static str,
) -> Result<(), IntegrationIdentityMappingError> {
    let metadata: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT ENGINE, TABLE_COLLATION, TABLE_TYPE FROM information_schema.TABLES \
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
        "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, CHARACTER_SET_NAME, \
                COLLATION_NAME, EXTRA \
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
        let name: String = row
            .try_get("COLUMN_NAME")
            .map_err(|error| db_error("decode integration mapping column name", error))?;
        let column_type: String = row
            .try_get("COLUMN_TYPE")
            .map_err(|error| db_error("decode integration mapping column type", error))?;
        let nullable: String = row
            .try_get("IS_NULLABLE")
            .map_err(|error| db_error("decode integration mapping nullability", error))?;
        let charset: Option<String> = row
            .try_get("CHARACTER_SET_NAME")
            .map_err(|error| db_error("decode integration mapping charset", error))?;
        let collation: Option<String> = row
            .try_get("COLLATION_NAME")
            .map_err(|error| db_error("decode integration mapping collation", error))?;
        let extra: String = row
            .try_get("EXTRA")
            .map_err(|error| db_error("decode integration mapping column extra", error))?;
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
    sequence: i64,
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
        "SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, SUB_PART, INDEX_TYPE \
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
            index_name: row
                .try_get("INDEX_NAME")
                .map_err(|error| db_error("decode integration mapping index name", error))?,
            non_unique: row
                .try_get("NON_UNIQUE")
                .map_err(|error| db_error("decode integration mapping index uniqueness", error))?,
            sequence: row
                .try_get("SEQ_IN_INDEX")
                .map_err(|error| db_error("decode integration mapping index sequence", error))?,
            column_name: row
                .try_get("COLUMN_NAME")
                .map_err(|error| db_error("decode integration mapping index column", error))?,
            sub_part: row
                .try_get("SUB_PART")
                .map_err(|error| db_error("decode integration mapping index prefix", error))?,
            index_type: row
                .try_get("INDEX_TYPE")
                .map_err(|error| db_error("decode integration mapping index type", error))?,
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
                    || part.sequence != (offset + 1) as i64
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
        "SELECT k.CONSTRAINT_NAME, k.COLUMN_NAME, k.REFERENCED_TABLE_SCHEMA, \
                k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, k.ORDINAL_POSITION, \
                r.DELETE_RULE, r.UPDATE_RULE \
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
    let current_schema: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(pool)
        .await
        .map_err(|error| db_error("resolve current database for mapping foreign keys", error))?;
    for (row, (name, column, referenced_table, referenced_column)) in rows.iter().zip([
        (
            MAPPING_CARD_FK,
            "identity_card_id",
            "identity_card",
            "card_id",
        ),
        (MAPPING_USER_FK, "user_id", "platform_user", "user_id"),
    ]) {
        let actual_name: String = row
            .try_get("CONSTRAINT_NAME")
            .map_err(|error| db_error("decode mapping foreign key name", error))?;
        let actual_column: String = row
            .try_get("COLUMN_NAME")
            .map_err(|error| db_error("decode mapping foreign key column", error))?;
        let actual_schema: String = row
            .try_get("REFERENCED_TABLE_SCHEMA")
            .map_err(|error| db_error("decode mapping foreign key schema", error))?;
        let actual_table: String = row
            .try_get("REFERENCED_TABLE_NAME")
            .map_err(|error| db_error("decode mapping foreign key table", error))?;
        let actual_ref_column: String = row
            .try_get("REFERENCED_COLUMN_NAME")
            .map_err(|error| db_error("decode mapping foreign key target", error))?;
        let ordinal: i64 = row
            .try_get("ORDINAL_POSITION")
            .map_err(|error| db_error("decode mapping foreign key ordinal", error))?;
        let delete_rule: String = row
            .try_get("DELETE_RULE")
            .map_err(|error| db_error("decode mapping foreign key delete rule", error))?;
        let update_rule: String = row
            .try_get("UPDATE_RULE")
            .map_err(|error| db_error("decode mapping foreign key update rule", error))?;
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
    let shape: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT ENGINE, TABLE_TYPE FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_log'",
    )
    .fetch_optional(pool)
    .await
    .map_err(|error| db_error("inspect mapping audit engine", error))?;
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
        let metadata: Option<(String, String)> = sqlx::query_as(
            "SELECT COLUMN_TYPE, IS_NULLABLE FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_log' \
               AND COLUMN_NAME = ?",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(|error| db_error("inspect mapping audit column", error))?;
        let Some((actual_type, actual_nullable)) = metadata else {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "audit_log.{name} is missing"
            )));
        };
        if actual_type.to_ascii_lowercase() != *column_type || actual_nullable != *nullable {
            return Err(IntegrationIdentityMappingError::SchemaMismatch(format!(
                "audit_log.{name} does not match the mutation audit contract"
            )));
        }
    }
    Ok(())
}
