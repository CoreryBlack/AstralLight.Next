//! memory—v1: Candidate schema contract and pure manifest validation.
//!
//! This module freezes the byte-oriented shape expected by the current nine-table
//! candidate reader. It is deliberately smaller than the serving-adoption
//! contract: a matching manifest proves only that the observed tables and
//! columns have the candidate shape. It does not prove provenance, complete
//! coverage, currentness, lifecycle, confirmation authority, writer coverage,
//! audit durability, or recovery.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Version of the UUID-native nine-table candidate shape.
pub const MEMORY_V1_CANDIDATE_SCHEMA_VERSION: u16 = 2;

/// The exact storage kind and length reported by MySQL metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedColumn {
    pub name: String,
    pub data_type: String,
    pub max_length: Option<u64>,
    pub nullable: bool,
    pub character_set: Option<String>,
    pub collation: Option<String>,
}

/// The metadata needed to compare one candidate table with the frozen shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedTable {
    pub name: String,
    pub table_type: String,
    pub engine: Option<String>,
    pub columns: Vec<ObservedColumn>,
}

/// A deterministic identity of the observed candidate schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateSchemaFingerprint([u8; 32]);

impl CandidateSchemaFingerprint {
    pub fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Result of validating the candidate schema metadata.
///
/// This value is diagnostic input to a future snapshot verifier. It cannot be
/// converted into root adoption evidence and it carries no database contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateSchemaObservation {
    pub contract_version: u16,
    pub table_count: usize,
    pub fingerprint: CandidateSchemaFingerprint,
}

impl CandidateSchemaObservation {
    /// The candidate shape is never sufficient for a serving root by itself.
    pub const fn is_adoption_ready(self) -> bool {
        false
    }
}

#[derive(Clone, Copy)]
struct ColumnContract {
    name: &'static str,
    data_type: &'static str,
    max_length: Option<u64>,
    nullable: bool,
    character_set: Option<&'static str>,
    collation: Option<&'static str>,
}

struct TableContract {
    name: &'static str,
    columns: &'static [ColumnContract],
}

const BINARY_ID: ColumnContract = ColumnContract {
    name: "",
    data_type: "binary",
    max_length: Some(16),
    nullable: false,
    character_set: None,
    collation: None,
};

const CANDIDATE_TABLES: &[TableContract] = &[
    TableContract {
        name: "memory_user",
        columns: &[ColumnContract {
            name: "user_id",
            ..BINARY_ID
        }],
    },
    TableContract {
        name: "memory_identity_card",
        columns: &[
            ColumnContract {
                name: "identity_card_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "user_id",
                ..BINARY_ID
            },
        ],
    },
    TableContract {
        name: "memory_tenant",
        columns: &[
            ColumnContract {
                name: "tenant_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "parent_tenant_id",
                nullable: true,
                ..BINARY_ID
            },
        ],
    },
    TableContract {
        name: "memory_user_card",
        columns: &[
            ColumnContract {
                name: "user_card_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "user_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "tenant_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "status",
                data_type: "varchar",
                max_length: Some(16),
                nullable: false,
                character_set: Some("ascii"),
                collation: Some("ascii_bin"),
            },
        ],
    },
    TableContract {
        name: "memory_rule_set",
        columns: &[
            ColumnContract {
                name: "rule_set_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "owner_tenant_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "current_version_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
        ],
    },
    TableContract {
        name: "memory_rule_set_version",
        columns: &[
            ColumnContract {
                name: "rule_set_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "version_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "content_bytes",
                data_type: "longblob",
                max_length: Some(u32::MAX as u64),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "timestamp_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "hash_input_bytes",
                data_type: "longblob",
                max_length: Some(u32::MAX as u64),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "hash_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
        ],
    },
    TableContract {
        name: "memory_card_rule_set_binding",
        columns: &[
            ColumnContract {
                name: "binding_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "user_card_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "rule_set_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "binding_layer",
                data_type: "varchar",
                max_length: Some(7),
                nullable: false,
                character_set: Some("ascii"),
                collation: Some("ascii_bin"),
            },
            ColumnContract {
                name: "valid_from",
                data_type: "bigint",
                max_length: None,
                nullable: true,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "valid_until",
                data_type: "bigint",
                max_length: None,
                nullable: true,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "owner_scope",
                data_type: "varchar",
                max_length: Some(24),
                nullable: true,
                character_set: Some("ascii"),
                collation: Some("ascii_bin"),
            },
            ColumnContract {
                name: "tenant_scope",
                data_type: "varchar",
                max_length: Some(24),
                nullable: true,
                character_set: Some("ascii"),
                collation: Some("ascii_bin"),
            },
            ColumnContract {
                name: "removed_at",
                data_type: "bigint",
                max_length: None,
                nullable: true,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "removed_by",
                data_type: "varbinary",
                max_length: Some(16),
                nullable: true,
                character_set: None,
                collation: None,
            },
        ],
    },
    TableContract {
        name: "memory_binding_confirmation",
        columns: &[
            ColumnContract {
                name: "confirmation_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "binding_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "rule_set_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "version_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "confirmer_user_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "scope_bytes",
                data_type: "longblob",
                max_length: Some(u32::MAX as u64),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "operation_id",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "confirmed_at_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "revoked_at",
                data_type: "bigint",
                max_length: None,
                nullable: true,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "revoked_by",
                data_type: "varbinary",
                max_length: Some(16),
                nullable: true,
                character_set: None,
                collation: None,
            },
        ],
    },
    TableContract {
        name: "memory_rule_set_change_confirmation",
        columns: &[
            ColumnContract {
                name: "confirmation_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "rule_set_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "version_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "confirmer_user_id",
                ..BINARY_ID
            },
            ColumnContract {
                name: "affected_scope_bytes",
                data_type: "longblob",
                max_length: Some(u32::MAX as u64),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "operation_id",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "confirmed_at_bytes",
                data_type: "varbinary",
                max_length: Some(255),
                nullable: false,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "revoked_at",
                data_type: "bigint",
                max_length: None,
                nullable: true,
                character_set: None,
                collation: None,
            },
            ColumnContract {
                name: "revoked_by",
                data_type: "varbinary",
                max_length: Some(16),
                nullable: true,
                character_set: None,
                collation: None,
            },
        ],
    },
];

/// Reasons why observed metadata cannot be treated as the candidate shape.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CandidateSchemaError {
    #[error("memory-v1 candidate schema has an unexpected table: {0}")]
    UnexpectedTable(String),
    #[error("memory-v1 candidate schema is missing table: {0}")]
    MissingTable(&'static str),
    #[error("memory-v1 candidate schema table {table} has invalid table type")]
    InvalidTableType { table: String },
    #[error("memory-v1 candidate schema table {table} has invalid engine")]
    InvalidEngine { table: String },
    #[error("memory-v1 candidate schema repeats table: {0}")]
    DuplicateTable(String),
    #[error("memory-v1 candidate schema table {table} repeats column: {column}")]
    DuplicateColumn { table: String, column: String },
    #[error("memory-v1 candidate schema table {table} has an unexpected column: {column}")]
    UnexpectedColumn { table: String, column: String },
    #[error("memory-v1 candidate schema table {table} is missing column: {column}")]
    MissingColumn {
        table: &'static str,
        column: &'static str,
    },
    #[error("memory-v1 candidate schema column {table}.{column} has invalid type")]
    InvalidColumnType { table: String, column: String },
}

/// Validate an exact metadata snapshot of the nine-table candidate shape.
///
/// The input should come from one transaction-scoped metadata read. This pure
/// function intentionally does not query MySQL and does not infer any row or
/// authorization fact from the metadata.
pub fn validate_candidate_schema(
    observed: &[ObservedTable],
) -> Result<CandidateSchemaObservation, CandidateSchemaError> {
    for table in observed {
        if !CANDIDATE_TABLES
            .iter()
            .any(|expected| expected.name == table.name)
        {
            return Err(CandidateSchemaError::UnexpectedTable(table.name.clone()));
        }
    }
    if let Some(table) = observed.iter().find(|table| {
        observed
            .iter()
            .filter(|other| other.name == table.name)
            .count()
            > 1
    }) {
        return Err(CandidateSchemaError::DuplicateTable(table.name.clone()));
    }
    for expected in CANDIDATE_TABLES {
        let actual = observed
            .iter()
            .find(|table| table.name == expected.name)
            .ok_or(CandidateSchemaError::MissingTable(expected.name))?;
        if actual.table_type != "BASE TABLE" {
            return Err(CandidateSchemaError::InvalidTableType {
                table: actual.name.clone(),
            });
        }
        if !actual
            .engine
            .as_deref()
            .is_some_and(|engine| engine.eq_ignore_ascii_case("InnoDB"))
        {
            return Err(CandidateSchemaError::InvalidEngine {
                table: actual.name.clone(),
            });
        }
        for column in &actual.columns {
            if actual
                .columns
                .iter()
                .filter(|candidate| candidate.name == column.name)
                .count()
                > 1
            {
                return Err(CandidateSchemaError::DuplicateColumn {
                    table: actual.name.clone(),
                    column: column.name.clone(),
                });
            }
            if !expected
                .columns
                .iter()
                .any(|candidate| candidate.name == column.name)
            {
                return Err(CandidateSchemaError::UnexpectedColumn {
                    table: actual.name.clone(),
                    column: column.name.clone(),
                });
            }
        }
        for column in expected.columns {
            let actual_column = actual
                .columns
                .iter()
                .find(|candidate| candidate.name == column.name)
                .ok_or(CandidateSchemaError::MissingColumn {
                    table: expected.name,
                    column: column.name,
                })?;
            if actual_column.data_type != column.data_type
                || actual_column.max_length != column.max_length
                || actual_column.nullable != column.nullable
                || actual_column.character_set.as_deref() != column.character_set
                || actual_column.collation.as_deref() != column.collation
            {
                return Err(CandidateSchemaError::InvalidColumnType {
                    table: actual.name.clone(),
                    column: actual_column.name.clone(),
                });
            }
        }
    }

    let fingerprint = schema_fingerprint(observed);
    Ok(CandidateSchemaObservation {
        contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
        table_count: observed.len(),
        fingerprint,
    })
}

fn schema_fingerprint(observed: &[ObservedTable]) -> CandidateSchemaFingerprint {
    let mut tables = observed.to_vec();
    tables.sort_by(|left, right| left.name.cmp(&right.name));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"astrallight/memory-v1/candidate-schema/1\0");
    for table in tables {
        frame(&mut bytes, table.name.as_bytes());
        frame(&mut bytes, table.table_type.as_bytes());
        frame(
            &mut bytes,
            table.engine.as_deref().unwrap_or("<null>").as_bytes(),
        );
        let mut columns = table.columns;
        columns.sort_by(|left, right| left.name.cmp(&right.name));
        for column in columns {
            frame(&mut bytes, column.name.as_bytes());
            frame(&mut bytes, column.data_type.as_bytes());
            bytes.push(u8::from(column.nullable));
            match column.max_length {
                Some(length) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&length.to_be_bytes());
                }
                None => bytes.push(0),
            }
            frame(
                &mut bytes,
                column
                    .character_set
                    .as_deref()
                    .unwrap_or("<null>")
                    .as_bytes(),
            );
            frame(
                &mut bytes,
                column.collation.as_deref().unwrap_or("<null>").as_bytes(),
            );
        }
        bytes.push(0xff);
    }
    CandidateSchemaFingerprint(Sha256::digest(bytes).into())
}

fn frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> Vec<ObservedTable> {
        CANDIDATE_TABLES
            .iter()
            .map(|table| ObservedTable {
                name: table.name.to_owned(),
                table_type: "BASE TABLE".to_owned(),
                engine: Some("InnoDB".to_owned()),
                columns: table
                    .columns
                    .iter()
                    .map(|column| ObservedColumn {
                        name: column.name.to_owned(),
                        data_type: column.data_type.to_owned(),
                        max_length: column.max_length,
                        nullable: column.nullable,
                        character_set: column.character_set.map(str::to_owned),
                        collation: column.collation.map(str::to_owned),
                    })
                    .collect(),
            })
            .collect()
    }

    #[test]
    fn exact_candidate_shape_has_stable_observation() {
        let observed = schema();
        let first = validate_candidate_schema(&observed).unwrap();
        let mut reordered = observed;
        reordered.reverse();
        reordered[0].columns.reverse();
        assert_eq!(validate_candidate_schema(&reordered).unwrap(), first);
        assert!(!first.is_adoption_ready());
    }

    #[test]
    // memory—v1: MySQL reports the byte capacity for every LONGBLOB column.
    fn mysql_longblob_metadata_requires_its_reported_capacity() {
        let mut observed = schema();
        for (table_name, column_name) in [
            ("memory_rule_set_version", "content_bytes"),
            ("memory_rule_set_version", "hash_input_bytes"),
            ("memory_binding_confirmation", "scope_bytes"),
            (
                "memory_rule_set_change_confirmation",
                "affected_scope_bytes",
            ),
        ] {
            let column = observed
                .iter_mut()
                .find(|table| table.name == table_name)
                .unwrap()
                .columns
                .iter_mut()
                .find(|column| column.name == column_name)
                .unwrap();
            column.max_length = Some(4_294_967_295);
        }
        assert!(validate_candidate_schema(&observed).is_ok());
        for (table_name, column_name) in [
            ("memory_rule_set_version", "content_bytes"),
            ("memory_rule_set_version", "hash_input_bytes"),
            ("memory_binding_confirmation", "scope_bytes"),
            (
                "memory_rule_set_change_confirmation",
                "affected_scope_bytes",
            ),
        ] {
            let mut drifted = observed.clone();
            let column = drifted
                .iter_mut()
                .find(|table| table.name == table_name)
                .unwrap()
                .columns
                .iter_mut()
                .find(|column| column.name == column_name)
                .unwrap();
            column.max_length = None;
            assert!(matches!(
                validate_candidate_schema(&drifted),
                Err(CandidateSchemaError::InvalidColumnType { table, column })
                    if table == table_name && column == column_name
            ));
        }
    }

    #[test]
    fn schema_drift_stays_fail_closed() {
        let mut observed = schema();
        observed[0].columns[0].max_length = Some(15);
        assert!(matches!(
            validate_candidate_schema(&observed),
            Err(CandidateSchemaError::InvalidColumnType { .. })
        ));

        let mut observed = schema();
        observed.push(observed[0].clone());
        assert!(matches!(
            validate_candidate_schema(&observed),
            Err(CandidateSchemaError::DuplicateTable(_))
        ));

        let mut observed = schema();
        let duplicate_column = observed[0].columns[0].clone();
        observed[0].columns.push(duplicate_column);
        assert!(matches!(
            validate_candidate_schema(&observed),
            Err(CandidateSchemaError::DuplicateColumn { .. })
        ));
    }
}
