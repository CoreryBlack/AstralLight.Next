//! memory—v1: Candidate schema contract and pure manifest validation.
//!
//! This module freezes the byte-oriented shape expected by the current nine-table
//! candidate reader. It is deliberately smaller than the serving-adoption
//! contract: a matching manifest proves only that the observed tables and
//! columns have the candidate shape. It does not prove provenance, complete
//! coverage, currentness, lifecycle, confirmation authority, writer coverage,
//! audit durability, or recovery.

pub use astral_authorization_root::memory_v1_adoption::MEMORY_V1_CANDIDATE_SCHEMA_VERSION;
use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use thiserror::Error;

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

/// One row from `information_schema.STATISTICS` for a candidate table.
///
/// The fields that are nullable in MySQL metadata remain nullable here. In
/// particular, a functional index has no `COLUMN_NAME` and instead exposes an
/// `EXPRESSION`; accepting either as a column would make a functional or
/// otherwise partial index look like the required ordinary-column key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedIndex {
    pub table: String,
    pub name: String,
    pub non_unique: i64,
    pub sequence: u64,
    pub column_name: Option<String>,
    pub sub_part: Option<u64>,
    pub expression: Option<String>,
    pub index_type: String,
    pub is_visible: bool,
}

/// One candidate generated-column metadata row from `information_schema.COLUMNS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedGeneratedColumn {
    pub table: String,
    pub column: String,
    pub extra: String,
    pub generation_expression: Option<String>,
}

/// The storage mode that was observed for the overlay guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratedColumnStorage {
    Stored,
}

/// The expression matched the frozen memory-v1 OVERLAY guard contract using the
/// closed parser in this module. This is a pure observation of metadata text; it
/// does not prove that a live MySQL server evaluated the expression or enforced
/// the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratedExpressionVerification {
    MatchesFrozenContract,
}

/// Independent constraint evidence for the candidate schema.
///
/// This is intentionally separate from [`CandidateSchemaObservation`], whose
/// public shape remains the legacy column/table observation. A successful value
/// proves the physical key shape and the generated-column storage mode only;
/// `expression_verification` makes the remaining expression limitation explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateSchemaConstraintObservation {
    pub binding_pair_unique_index: String,
    pub overlay_guard_unique_index: String,
    pub overlay_guard_storage: GeneratedColumnStorage,
    pub overlay_guard_expression: GeneratedExpressionVerification,
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

/// Versioned diagnostic of the table/column manifest and every binding-table
/// index and generated-column expression checked by the candidate adapter.
/// It does not authenticate the source or prove live MySQL enforcement or DDL
/// stability. The existing table/column fingerprint retains its original meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateSchemaDiagnostic {
    contract_version: u16,
    fingerprint: [u8; 32],
}

impl CandidateSchemaDiagnostic {
    /// memory—v1: Return the candidate schema contract version in this diagnostic.
    pub const fn contract_version(self) -> u16 {
        self.contract_version
    }

    /// memory—v1: Return the domain-separated combined diagnostic fingerprint.
    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
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

// memory—v1: Bound schema metadata before materializing information_schema rows.
// The complete exact contract is smaller than these ceilings; an extra row is
// fetched as a sentinel so an oversized observation is never treated as complete.
pub(crate) const CANDIDATE_TABLE_METADATA_LIMIT: i64 = 16;
pub(crate) const CANDIDATE_COLUMN_METADATA_LIMIT: i64 = 128;

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
            ColumnContract {
                name: ACTIVE_CARD_COLUMN,
                nullable: true,
                ..BINARY_ID
            },
            ColumnContract {
                name: ACTIVE_RULE_SET_COLUMN,
                nullable: true,
                ..BINARY_ID
            },
            ColumnContract {
                name: OVERLAY_GUARD_COLUMN,
                nullable: true,
                ..BINARY_ID
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

/// Reasons why the candidate's independent constraint metadata cannot be treated
/// as the required physical constraints.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CandidateSchemaConstraintError {
    #[error("memory-v1 candidate schema is missing unique index {index} on {table}")]
    MissingIndex {
        table: &'static str,
        index: &'static str,
    },
    #[error("memory-v1 candidate schema index {index} has invalid {reason}")]
    InvalidIndex { index: String, reason: &'static str },
    #[error(
        "memory-v1 candidate schema has duplicate generated-column metadata for {table}.{column}"
    )]
    DuplicateGeneratedColumn {
        table: &'static str,
        column: &'static str,
    },
    #[error("memory-v1 candidate schema is missing generated column {table}.{column}")]
    MissingGeneratedColumn {
        table: &'static str,
        column: &'static str,
    },
    #[error(
        "memory-v1 candidate schema generated column {table}.{column} is not STORED GENERATED"
    )]
    InvalidGeneratedColumnStorage {
        table: &'static str,
        column: &'static str,
    },
    #[error("memory-v1 candidate schema generated column {table}.{column} has no usable generation expression")]
    MissingGenerationExpression {
        table: &'static str,
        column: &'static str,
    },
    #[error("memory-v1 candidate schema generated column {table}.{column} has an unsupported generation expression")]
    InvalidGenerationExpression {
        table: &'static str,
        column: &'static str,
    },
    #[error("memory-v1 candidate schema has an unexpected index on {table}: {index}")]
    UnexpectedIndex { table: &'static str, index: String },
    #[error("memory-v1 candidate schema has too many {kind} metadata rows")]
    MetadataLimitExceeded { kind: &'static str },
    #[error("memory-v1 candidate schema has an unexpected generated column {table}.{column}")]
    UnexpectedGeneratedColumn { table: &'static str, column: String },
}

pub(crate) const BINDING_TABLE: &str = "memory_card_rule_set_binding";
pub(crate) const BINDING_PAIR_INDEX: &str = "uq_binding_card_ruleset_active";
pub(crate) const OVERLAY_GUARD_INDEX: &str = "uq_binding_one_overlay_active";
pub(crate) const ACTIVE_CARD_COLUMN: &str = "active_user_card_id";
pub(crate) const ACTIVE_RULE_SET_COLUMN: &str = "active_rule_set_id";
pub(crate) const OVERLAY_GUARD_COLUMN: &str = "overlay_guard";

pub(crate) const BINDING_INDEX_METADATA_LIMIT: i64 = 64;
pub(crate) const BINDING_GENERATED_METADATA_LIMIT: i64 = 16;

const BINDING_PAIR_COLUMNS: &[&str] = &[ACTIVE_CARD_COLUMN, ACTIVE_RULE_SET_COLUMN];
const OVERLAY_GUARD_COLUMNS: &[&str] = &[OVERLAY_GUARD_COLUMN];

#[derive(Clone, Copy)]
struct IndexContract {
    name: &'static str,
    columns: &'static [&'static str],
    non_unique: i64,
}

const CANDIDATE_INDEXES: &[IndexContract] = &[
    IndexContract {
        name: "PRIMARY",
        columns: &["binding_id"],
        non_unique: 0,
    },
    IndexContract {
        name: BINDING_PAIR_INDEX,
        columns: BINDING_PAIR_COLUMNS,
        non_unique: 0,
    },
    IndexContract {
        name: OVERLAY_GUARD_INDEX,
        columns: OVERLAY_GUARD_COLUMNS,
        non_unique: 0,
    },
    IndexContract {
        name: "uq_memory_binding_rule_set",
        columns: &["binding_id", "rule_set_id"],
        non_unique: 0,
    },
    IndexContract {
        name: "ix_memory_binding_card",
        columns: &["user_card_id"],
        non_unique: 1,
    },
    IndexContract {
        name: "ix_memory_binding_rule_set",
        columns: &["rule_set_id"],
        non_unique: 1,
    },
];

const EXPECTED_GENERATED_COLUMNS: &[(&str, &str)] = &[
    (
        ACTIVE_CARD_COLUMN,
        "CASE WHEN removed_at IS NULL THEN user_card_id ELSE NULL END",
    ),
    (
        ACTIVE_RULE_SET_COLUMN,
        "CASE WHEN removed_at IS NULL THEN rule_set_id ELSE NULL END",
    ),
    (
        OVERLAY_GUARD_COLUMN,
        "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN user_card_id ELSE NULL END",
    ),
];

pub(crate) const MAX_GENERATION_EXPRESSION_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
enum GenerationToken {
    Word(String),
    StringLiteral(String),
    Equals,
    LeftParen,
    RightParen,
}

fn tokenize_generation_expression(expression: &str) -> Option<Vec<GenerationToken>> {
    if expression.len() > MAX_GENERATION_EXPRESSION_BYTES || expression.trim().is_empty() {
        return None;
    }

    let bytes = expression.as_bytes();
    let mut tokens = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            byte if byte.is_ascii_whitespace() => offset += 1,
            b'(' => {
                tokens.push(GenerationToken::LeftParen);
                offset += 1;
            }
            b')' => {
                tokens.push(GenerationToken::RightParen);
                offset += 1;
            }
            b'=' => {
                tokens.push(GenerationToken::Equals);
                offset += 1;
            }
            b'`' => {
                let start = offset + 1;
                offset = start;
                while offset < bytes.len() && bytes[offset] != b'`' {
                    offset += 1;
                }
                if offset == bytes.len() || offset == start {
                    return None;
                }
                tokens.push(GenerationToken::Word(
                    expression[start..offset].to_ascii_lowercase(),
                ));
                offset += 1;
            }
            b'\'' => {
                let value = read_single_quoted_literal(expression, offset, false)?;
                tokens.push(GenerationToken::StringLiteral(value));
                // Skip past the closing quote of the resolved literal.
                offset += 1;
                while offset < bytes.len() {
                    match bytes[offset] {
                        b'\\' => offset += 2,
                        b'\'' => break,
                        byte if byte >= 0x80 => return None,
                        _ => offset += 1,
                    }
                }
                if offset == bytes.len() {
                    return None;
                }
                offset += 1;
            }
            // MySQL 8 normalizes a plain string literal with a character-set
            // introducer such as `_utf8mb4'OVERLAY'`. The introducer itself is
            // not part of the compared value, so accept `_word` immediately
            // followed by the quoted literal and emit only the literal. The
            // server may also escape the opening quote (`_utf8mb4\'OVERLAY\'`),
            // so one backslash before the quote is part of that normalization.
            b'_' => {
                let start = offset;
                offset += 1;
                while offset < bytes.len()
                    && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
                {
                    offset += 1;
                }
                let escaped_opening =
                    bytes.get(offset) == Some(&b'\\') && bytes.get(offset + 1) == Some(&b'\'');
                if escaped_opening {
                    offset += 1;
                }
                if offset < bytes.len() && bytes[offset] == b'\'' {
                    let value = read_single_quoted_literal(expression, offset, escaped_opening)?;
                    tokens.push(GenerationToken::StringLiteral(value));
                    // Move past the closing quote: an escaped opening closes
                    // with `\'`, a plain opening with `'`.
                    offset = if escaped_opening {
                        skip_escaped_literal_tail(expression, offset)?
                    } else {
                        offset += 1;
                        while offset < bytes.len() {
                            match bytes[offset] {
                                b'\\' => offset += 2,
                                b'\'' => break,
                                byte if byte >= 0x80 => return None,
                                _ => offset += 1,
                            }
                        }
                        if offset == bytes.len() {
                            return None;
                        }
                        offset + 1
                    };
                } else {
                    tokens.push(GenerationToken::Word(
                        expression[start..offset].to_ascii_lowercase(),
                    ));
                }
            }
            byte if byte.is_ascii_alphanumeric() => {
                let start = offset;
                offset += 1;
                while offset < bytes.len()
                    && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
                {
                    offset += 1;
                }
                tokens.push(GenerationToken::Word(
                    expression[start..offset].to_ascii_lowercase(),
                ));
            }
            _ => return None,
        }
    }
    Some(tokens)
}

// memory—v1: Read one single-quoted literal starting at `offset`. The reader
// accepts the two MySQL normalizations of a quote inside the value: a
// backslash escape (`\'`) and a doubled quote (`''`). When the opening quote
// itself was backslash-escaped (`_utf8mb4\'OVERLAY\'`), the closing quote is
// escaped the same way; the introducer branch then skips that closing pair
// itself, and `escaped_opening` makes the reader stop on it. The returned
// value is the semantic text with escapes resolved.
fn read_single_quoted_literal(
    expression: &str,
    offset: usize,
    escaped_opening: bool,
) -> Option<String> {
    let bytes = expression.as_bytes();
    debug_assert_eq!(bytes[offset], b'\'');
    let mut value = String::new();
    let mut cursor = offset + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                if escaped_opening && bytes.get(cursor + 1) == Some(&b'\'') && !value.is_empty() {
                    // The escaped opening literal closes with the same
                    // escaped-quote form; the introducer branch consumes it.
                    return Some(value);
                }
                let next = bytes.get(cursor + 1).copied()?;
                value.push(next as char);
                cursor += 2;
            }
            b'\'' => {
                if bytes.get(cursor + 1) == Some(&b'\'') {
                    value.push('\'');
                    cursor += 2;
                } else {
                    return Some(value);
                }
            }
            byte => {
                // The frozen contracts use ASCII only; a non-ASCII byte is not
                // representable here and is rejected rather than lossily kept.
                if byte >= 0x80 {
                    return None;
                }
                value.push(byte as char);
                cursor += 1;
            }
        }
    }
    None
}

// memory—v1: Skip the remainder of one literal whose opening quote was
// backslash-escaped, stopping just past its escaped closing quote.
fn skip_escaped_literal_tail(expression: &str, offset: usize) -> Option<usize> {
    let bytes = expression.as_bytes();
    debug_assert_eq!(bytes[offset], b'\'');
    let mut cursor = offset + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                if bytes.get(cursor + 1) == Some(&b'\'') {
                    return Some(cursor + 2);
                }
                cursor += 2;
            }
            b'\'' => {
                if bytes.get(cursor + 1) == Some(&b'\'') {
                    cursor += 2;
                } else {
                    return None;
                }
            }
            byte if byte >= 0x80 => return None,
            _ => cursor += 1,
        }
    }
    None
}

fn strip_parentheses(tokens: &[GenerationToken]) -> &[GenerationToken] {
    let mut current = tokens;
    loop {
        if current.len() < 2
            || !matches!(current.first(), Some(GenerationToken::LeftParen))
            || !matches!(current.last(), Some(GenerationToken::RightParen))
        {
            return current;
        }
        let mut depth = 0usize;
        let mut closes_at_end = true;
        for (index, token) in current.iter().enumerate() {
            match token {
                GenerationToken::LeftParen => depth += 1,
                GenerationToken::RightParen => {
                    depth = match depth.checked_sub(1) {
                        Some(depth) => depth,
                        None => return current,
                    };
                    if depth == 0 && index != current.len() - 1 {
                        closes_at_end = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if closes_at_end {
            current = &current[1..current.len() - 1];
        } else {
            return current;
        }
    }
}

fn is_word(token: &GenerationToken, expected: &str) -> bool {
    matches!(token, GenerationToken::Word(value) if value == expected)
}

fn is_identifier(token: &GenerationToken, expected: &str) -> bool {
    is_word(token, expected)
}

fn is_equals(token: &GenerationToken) -> bool {
    matches!(token, GenerationToken::Equals)
}

fn matches_removed_is_null(tokens: &[GenerationToken]) -> bool {
    let tokens = strip_parentheses(tokens);
    tokens.len() == 3
        && is_identifier(&tokens[0], "removed_at")
        && is_word(&tokens[1], "is")
        && is_word(&tokens[2], "null")
}

fn matches_overlay_clause(tokens: &[GenerationToken]) -> bool {
    let tokens = strip_parentheses(tokens);
    tokens.len() == 3
        && is_identifier(&tokens[0], "binding_layer")
        && is_equals(&tokens[1])
        && matches!(
            &tokens[2],
            GenerationToken::StringLiteral(value) if value == "OVERLAY"
        )
}

fn matches_overlay_condition(tokens: &[GenerationToken]) -> bool {
    let tokens = strip_parentheses(tokens);
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            GenerationToken::LeftParen => depth += 1,
            GenerationToken::RightParen => {
                depth = match depth.checked_sub(1) {
                    Some(depth) => depth,
                    None => return false,
                };
            }
            _ if depth == 0 && is_word(token, "and") => {
                return matches_removed_is_null(&tokens[..index])
                    && matches_overlay_clause(&tokens[index + 1..]);
            }
            _ => {}
        }
    }
    false
}

fn expected_generation_target(generated_column: &str) -> Option<(&'static str, bool)> {
    match generated_column {
        ACTIVE_CARD_COLUMN => Some(("user_card_id", false)),
        ACTIVE_RULE_SET_COLUMN => Some(("rule_set_id", false)),
        OVERLAY_GUARD_COLUMN => Some(("user_card_id", true)),
        _ => None,
    }
}

fn matches_generation_expression(expression: &str, generated_column: &str) -> bool {
    let Some((expected_target, requires_overlay)) = expected_generation_target(generated_column)
    else {
        return false;
    };
    let Some(tokens) = tokenize_generation_expression(expression) else {
        return false;
    };
    let tokens = strip_parentheses(&tokens);
    if tokens.len() < 7 || !is_word(&tokens[0], "case") || !is_word(&tokens[1], "when") {
        return false;
    }
    let then_position = tokens.iter().position(|token| is_word(token, "then"));
    let else_position = tokens.iter().position(|token| is_word(token, "else"));
    let end_position = tokens.len().checked_sub(1);
    let (Some(then_position), Some(else_position), Some(end_position)) =
        (then_position, else_position, end_position)
    else {
        return false;
    };
    if then_position <= 2
        || else_position <= then_position + 1
        || end_position <= else_position
        || !is_word(&tokens[end_position], "end")
    {
        return false;
    }
    let result = strip_parentheses(&tokens[then_position + 1..else_position]);
    let fallback = strip_parentheses(&tokens[else_position + 1..end_position]);
    let condition = &tokens[2..then_position];
    let expected_condition = if requires_overlay {
        matches_overlay_condition(condition)
    } else {
        matches_removed_is_null(condition)
    };
    result.len() == 1
        && is_identifier(&result[0], expected_target)
        && fallback.len() == 1
        && is_word(&fallback[0], "null")
        && expected_condition
}

/// memory—v1: Validate the candidate's physical uniqueness and generated-column metadata.
///
/// The validator requires the complete binding-table index set, not merely the
/// two indexes that enforce uniqueness. This rejects a legacy full-table unique
/// key or an unfiltered overlay guard left beside the active-row keys. Every
/// generated expression is matched as a closed, exact contract; metadata text
/// alone does not prove live MySQL evaluation or enforcement.
pub fn validate_candidate_schema_constraints(
    indexes: &[ObservedIndex],
    generated_columns: &[ObservedGeneratedColumn],
) -> Result<CandidateSchemaConstraintObservation, CandidateSchemaConstraintError> {
    if let Some(unexpected) = indexes.iter().find(|index| index.table != BINDING_TABLE) {
        return Err(CandidateSchemaConstraintError::UnexpectedIndex {
            table: BINDING_TABLE,
            index: unexpected.name.clone(),
        });
    }
    let expected_names: BTreeSet<&str> = CANDIDATE_INDEXES
        .iter()
        .map(|contract| contract.name)
        .collect();
    let binding_indexes: Vec<&ObservedIndex> = indexes.iter().collect();
    let observed_names: BTreeSet<&str> = binding_indexes
        .iter()
        .map(|index| index.name.as_str())
        .collect();
    if let Some(index) = binding_indexes
        .iter()
        .find(|index| !expected_names.contains(index.name.as_str()))
    {
        return Err(CandidateSchemaConstraintError::UnexpectedIndex {
            table: BINDING_TABLE,
            index: index.name.clone(),
        });
    }
    if observed_names.len() != expected_names.len() {
        let missing = CANDIDATE_INDEXES
            .iter()
            .find(|contract| !observed_names.contains(contract.name))
            .expect("the name-set length differs only when an expected name is missing");
        return Err(CandidateSchemaConstraintError::MissingIndex {
            table: BINDING_TABLE,
            index: missing.name,
        });
    }

    let mut index_names = Vec::with_capacity(CANDIDATE_INDEXES.len());
    for contract in CANDIDATE_INDEXES {
        let mut parts: Vec<&ObservedIndex> = binding_indexes
            .iter()
            .copied()
            .filter(|index| index.name == contract.name)
            .collect();
        if parts.is_empty() {
            return Err(CandidateSchemaConstraintError::MissingIndex {
                table: BINDING_TABLE,
                index: contract.name,
            });
        }
        parts.sort_by_key(|part| part.sequence);
        if parts.len() != contract.columns.len() {
            return Err(CandidateSchemaConstraintError::InvalidIndex {
                index: contract.name.to_owned(),
                reason: "wrong number of index parts",
            });
        }
        for (offset, part) in parts.iter().enumerate() {
            if part.non_unique != contract.non_unique {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "NON_UNIQUE does not match the candidate contract",
                });
            }
            if part.sequence != (offset + 1) as u64 {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "SEQ_IN_INDEX is not contiguous and ordered",
                });
            }
            let Some(column) = part.column_name.as_deref() else {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "COLUMN_NAME is NULL",
                });
            };
            if column.trim().is_empty() {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "COLUMN_NAME is empty",
                });
            }
            if column != contract.columns[offset] {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "column order or prefix does not match",
                });
            }
            if part.sub_part.is_some() {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "SUB_PART is present",
                });
            }
            if part.expression.is_some() {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "EXPRESSION is present",
                });
            }
            if !part.index_type.eq_ignore_ascii_case("BTREE") {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "index type is not BTREE",
                });
            }
            if !part.is_visible {
                return Err(CandidateSchemaConstraintError::InvalidIndex {
                    index: contract.name.to_owned(),
                    reason: "index is invisible",
                });
            }
        }
        index_names.push(contract.name.to_owned());
    }

    let mut generated_candidates = Vec::new();
    for column in generated_columns {
        if column.table != BINDING_TABLE {
            return Err(CandidateSchemaConstraintError::UnexpectedGeneratedColumn {
                table: BINDING_TABLE,
                column: column.column.clone(),
            });
        }
        let is_generated = column
            .generation_expression
            .as_deref()
            .is_some_and(|expression| !expression.is_empty())
            || column.extra.eq_ignore_ascii_case("STORED GENERATED")
            || column.extra.eq_ignore_ascii_case("VIRTUAL GENERATED");
        if is_generated {
            generated_candidates.push(column);
        }
    }

    if generated_candidates.is_empty() {
        return Err(CandidateSchemaConstraintError::MissingGeneratedColumn {
            table: BINDING_TABLE,
            column: EXPECTED_GENERATED_COLUMNS[0].0,
        });
    }
    for column in &generated_candidates {
        if column.table != BINDING_TABLE
            || !EXPECTED_GENERATED_COLUMNS
                .iter()
                .any(|(name, _)| *name == column.column)
        {
            return Err(CandidateSchemaConstraintError::UnexpectedGeneratedColumn {
                table: BINDING_TABLE,
                column: column.column.clone(),
            });
        }
    }

    for (expected_column, _expected_expression) in EXPECTED_GENERATED_COLUMNS {
        let matches: Vec<&ObservedGeneratedColumn> = generated_candidates
            .iter()
            .copied()
            .filter(|column| column.table == BINDING_TABLE && column.column == *expected_column)
            .collect();
        if matches.is_empty() {
            return Err(CandidateSchemaConstraintError::MissingGeneratedColumn {
                table: BINDING_TABLE,
                column: expected_column,
            });
        }
        if matches.len() != 1 {
            return Err(CandidateSchemaConstraintError::DuplicateGeneratedColumn {
                table: BINDING_TABLE,
                column: expected_column,
            });
        }
        let column = matches[0];
        if !column.extra.eq_ignore_ascii_case("STORED GENERATED") {
            return Err(
                CandidateSchemaConstraintError::InvalidGeneratedColumnStorage {
                    table: BINDING_TABLE,
                    column: expected_column,
                },
            );
        }
        let Some(expression) = column
            .generation_expression
            .as_deref()
            .filter(|expression| !expression.trim().is_empty())
        else {
            return Err(
                CandidateSchemaConstraintError::MissingGenerationExpression {
                    table: BINDING_TABLE,
                    column: expected_column,
                },
            );
        };
        if !matches_generation_expression(expression, expected_column) {
            return Err(
                CandidateSchemaConstraintError::InvalidGenerationExpression {
                    table: BINDING_TABLE,
                    column: expected_column,
                },
            );
        }
    }

    Ok(CandidateSchemaConstraintObservation {
        binding_pair_unique_index: index_names
            .iter()
            .find(|name| name.as_str() == BINDING_PAIR_INDEX)
            .expect("the binding pair index was validated")
            .clone(),
        overlay_guard_unique_index: index_names
            .iter()
            .find(|name| name.as_str() == OVERLAY_GUARD_INDEX)
            .expect("the overlay guard index was validated")
            .clone(),
        overlay_guard_storage: GeneratedColumnStorage::Stored,
        overlay_guard_expression: GeneratedExpressionVerification::MatchesFrozenContract,
    })
}

// memory—v1: Bind successful validation to a versioned diagnostic covering
// the complete validated index contract and all three generated expressions.
// Equivalent accepted SQL spellings map to the frozen semantic contract.
pub(crate) fn candidate_schema_diagnostic(
    schema: CandidateSchemaObservation,
    indexes: &[ObservedIndex],
    generated_columns: &[ObservedGeneratedColumn],
) -> Result<CandidateSchemaDiagnostic, CandidateSchemaConstraintError> {
    validate_candidate_schema_constraints(indexes, generated_columns)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"astrallight/memory-v1/candidate-schema-diagnostic/1\0");
    bytes.extend_from_slice(&schema.contract_version.to_be_bytes());
    bytes.extend_from_slice(&schema.fingerprint.as_bytes());
    frame(&mut bytes, BINDING_TABLE.as_bytes());
    bytes.extend_from_slice(&(CANDIDATE_INDEXES.len() as u64).to_be_bytes());
    for index in CANDIDATE_INDEXES {
        frame(&mut bytes, index.name.as_bytes());
        bytes.extend_from_slice(&index.non_unique.to_be_bytes());
        bytes.extend_from_slice(&(index.columns.len() as u64).to_be_bytes());
        for (offset, column) in index.columns.iter().enumerate() {
            bytes.extend_from_slice(&((offset + 1) as u64).to_be_bytes());
            frame(&mut bytes, column.as_bytes());
        }
        // Every accepted index has no prefix or expression and is visible BTREE.
        bytes.extend_from_slice(&[0, 0, 1]);
        frame(&mut bytes, b"BTREE");
    }
    bytes.extend_from_slice(&(EXPECTED_GENERATED_COLUMNS.len() as u64).to_be_bytes());
    for (column, expression) in EXPECTED_GENERATED_COLUMNS {
        frame(&mut bytes, column.as_bytes());
        frame(&mut bytes, b"STORED GENERATED");
        frame(&mut bytes, expression.as_bytes());
    }
    Ok(CandidateSchemaDiagnostic {
        contract_version: schema.contract_version,
        fingerprint: Sha256::digest(bytes).into(),
    })
}

/// Validate an exact metadata snapshot of the nine-table candidate shape.
///
/// Constraint metadata is not folded into `CandidateSchemaFingerprint`; that
/// fingerprint covers the table/column manifest only. Constraint validation is
/// a separate fail-closed prerequisite of row capture.
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
    // memory—v1: Capture limits must fit every row of the exact v4 manifest.
    fn schema_metadata_limits_cover_the_complete_manifest() {
        assert!(CANDIDATE_TABLES.len() <= CANDIDATE_TABLE_METADATA_LIMIT as usize);
        assert!(
            CANDIDATE_TABLES
                .iter()
                .map(|table| table.columns.len())
                .sum::<usize>()
                <= CANDIDATE_COLUMN_METADATA_LIMIT as usize
        );
        assert!(
            CANDIDATE_INDEXES
                .iter()
                .map(|index| index.columns.len())
                .sum::<usize>()
                <= BINDING_INDEX_METADATA_LIMIT as usize
        );
        assert!(
            CANDIDATE_TABLES
                .iter()
                .find(|table| table.name == BINDING_TABLE)
                .unwrap()
                .columns
                .len()
                <= BINDING_GENERATED_METADATA_LIMIT as usize
        );
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
    // memory—v1: v3 lacks the required rule-set lifecycle column.
    fn v4_rule_set_status_requires_exact_column_metadata() {
        let mut missing = schema();
        let rule_set = missing
            .iter_mut()
            .find(|table| table.name == "memory_rule_set")
            .unwrap();
        rule_set.columns.retain(|column| column.name != "status");
        assert!(matches!(
            validate_candidate_schema(&missing),
            Err(CandidateSchemaError::MissingColumn {
                table: "memory_rule_set",
                column: "status"
            })
        ));

        for invalid in 0..5 {
            let mut observed = schema();
            let status = observed
                .iter_mut()
                .find(|table| table.name == "memory_rule_set")
                .unwrap()
                .columns
                .iter_mut()
                .find(|column| column.name == "status")
                .unwrap();
            match invalid {
                0 => status.data_type = "binary".to_owned(),
                1 => status.max_length = Some(15),
                2 => status.nullable = true,
                3 => status.character_set = None,
                _ => status.collation = Some("ascii_general_ci".to_owned()),
            }
            assert!(matches!(
                validate_candidate_schema(&observed),
                Err(CandidateSchemaError::InvalidColumnType { table, column })
                    if table == "memory_rule_set" && column == "status"
            ));
        }
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
    // memory—v1: The candidate DDL's generated OVERLAY guard is part of v3.
    fn candidate_overlay_guard_has_exact_binary_shape() {
        let mut observed = schema();
        let binding = observed
            .iter_mut()
            .find(|table| table.name == "memory_card_rule_set_binding")
            .unwrap();
        let guard = binding
            .columns
            .iter_mut()
            .find(|column| column.name == "overlay_guard")
            .unwrap();
        assert_eq!(guard.data_type, "binary");
        assert_eq!(guard.max_length, Some(16));
        assert!(guard.nullable);
        guard.nullable = false;
        assert!(matches!(
            validate_candidate_schema(&observed),
            Err(CandidateSchemaError::InvalidColumnType { table, column })
                if table == "memory_card_rule_set_binding" && column == "overlay_guard"
        ));
    }

    fn constraint_indexes() -> Vec<ObservedIndex> {
        let index = |name: &str, non_unique: i64, sequence: u64, column: &str| ObservedIndex {
            table: BINDING_TABLE.to_owned(),
            name: name.to_owned(),
            non_unique,
            sequence,
            column_name: Some(column.to_owned()),
            sub_part: None,
            expression: None,
            index_type: "BTREE".to_owned(),
            is_visible: true,
        };
        vec![
            index("PRIMARY", 0, 1, "binding_id"),
            index(BINDING_PAIR_INDEX, 0, 1, ACTIVE_CARD_COLUMN),
            index(BINDING_PAIR_INDEX, 0, 2, ACTIVE_RULE_SET_COLUMN),
            index(OVERLAY_GUARD_INDEX, 0, 1, OVERLAY_GUARD_COLUMN),
            index("uq_memory_binding_rule_set", 0, 1, "binding_id"),
            index("uq_memory_binding_rule_set", 0, 2, "rule_set_id"),
            index("ix_memory_binding_card", 1, 1, "user_card_id"),
            index("ix_memory_binding_rule_set", 1, 1, "rule_set_id"),
        ]
    }

    fn generated_overlay_guard() -> Vec<ObservedGeneratedColumn> {
        EXPECTED_GENERATED_COLUMNS
            .iter()
            .map(|(column, expression)| ObservedGeneratedColumn {
                table: BINDING_TABLE.to_owned(),
                column: (*column).to_owned(),
                extra: "STORED GENERATED".to_owned(),
                generation_expression: Some((*expression).to_owned()),
            })
            .collect()
    }

    #[test]
    // memory—v1: The combined diagnostic binds all validated constraint classes
    // while preserving the existing table/column fingerprint's meaning.
    fn combined_diagnostic_requires_the_complete_constraint_contract() {
        let observation = validate_candidate_schema(&schema()).unwrap();
        let indexes = constraint_indexes();
        let generated = generated_overlay_guard();
        let diagnostic = candidate_schema_diagnostic(observation, &indexes, &generated).unwrap();
        assert_eq!(
            diagnostic.contract_version(),
            MEMORY_V1_CANDIDATE_SCHEMA_VERSION
        );
        assert_ne!(diagnostic.fingerprint(), observation.fingerprint.as_bytes());
        assert_ne!(diagnostic.fingerprint(), [0; 32]);

        let mut reordered_indexes = indexes.clone();
        reordered_indexes.reverse();
        let mut reordered_generated = generated.clone();
        reordered_generated.reverse();
        reordered_generated[0].generation_expression = Some(
            "(case when ((`removed_at` is null) and (`binding_layer` = 'OVERLAY')) then (`user_card_id`) else null end)".to_owned(),
        );
        assert_eq!(
            candidate_schema_diagnostic(observation, &reordered_indexes, &reordered_generated),
            Ok(diagnostic)
        );
        for (column, _) in EXPECTED_GENERATED_COLUMNS {
            let mut invalid = generated.clone();
            invalid
                .iter_mut()
                .find(|item| item.column == *column)
                .unwrap()
                .generation_expression = Some("NULL".to_owned());
            assert!(candidate_schema_diagnostic(observation, &indexes, &invalid).is_err());
        }
        for contract in CANDIDATE_INDEXES {
            let mut invalid = indexes.clone();
            invalid.retain(|index| index.name != contract.name);
            assert!(candidate_schema_diagnostic(observation, &invalid, &generated).is_err());
        }
        let different_manifest = CandidateSchemaObservation {
            fingerprint: CandidateSchemaFingerprint([8; 32]),
            ..observation
        };
        assert_ne!(
            candidate_schema_diagnostic(different_manifest, &indexes, &generated)
                .unwrap()
                .fingerprint(),
            diagnostic.fingerprint()
        );
    }

    #[test]
    // memory—v1: Each generated key accepts only its own active-row expression.
    fn generated_expressions_match_only_their_frozen_semantics() {
        for (column, expression) in EXPECTED_GENERATED_COLUMNS {
            assert!(
                matches_generation_expression(expression, column),
                "{column}"
            );
        }
        for (column, expression) in [
            (ACTIVE_CARD_COLUMN, " ( case when (`removed_at` is null) then (`user_card_id`) else null end ) "),
            (ACTIVE_RULE_SET_COLUMN, "CASE WHEN (removed_at IS NULL) THEN rule_set_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "(case when ((`removed_at` is null) and (`binding_layer` = 'OVERLAY')) then (`user_card_id`) else null end)"),
            // MySQL 8 normalization of the same frozen semantics: the literal
            // gains a character-set introducer, identifier quoting, and an
            // escaped quote inside the literal. The compared value is still
            // exactly "OVERLAY".
            (
                OVERLAY_GUARD_COLUMN,
                "(case when ((`removed_at` is null) and (`binding_layer` = _utf8mb4\\'OVERLAY\\')) then `user_card_id` else NULL end)",
            ),
            (
                OVERLAY_GUARD_COLUMN,
                "(case when ((`removed_at` is null) and (`binding_layer` = _utf8mb4'OVERLAY')) then `user_card_id` else NULL end)",
            ),
        ] {
            assert!(matches_generation_expression(expression, column), "{column}");
        }
        for (column, expression) in [
            (ACTIVE_CARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN user_card_id ELSE NULL END"),
            (ACTIVE_RULE_SET_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN rule_set_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL THEN user_card_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'overlay' THEN user_card_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'BASE' THEN user_card_id ELSE NULL END"),
            // A doubled quote is a different value than the frozen literal.
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVER''LAY' THEN user_card_id ELSE NULL END"),
            // A backslash-escaped quote is also a different value.
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVER\\'LAY' THEN user_card_id ELSE NULL END"),
            (ACTIVE_CARD_COLUMN, "CASE WHEN removed_at IS NULL THEN rule_set_id ELSE NULL END"),
            (ACTIVE_RULE_SET_COLUMN, "CASE WHEN removed_at IS NULL THEN user_card_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN rule_set_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL OR binding_layer = 'OVERLAY' THEN user_card_id ELSE NULL END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN NULL ELSE user_card_id END"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN user_card_id ELSE NULL END + 0"),
            (OVERLAY_GUARD_COLUMN, "CASE WHEN removed_at IS NULL AND binding_layer = 'OVERLAY' THEN user_card_id ELSE NULL"),
        ] {
            assert!(!matches_generation_expression(expression, column), "{column}: {expression}");
        }
        assert!(!matches_generation_expression(
            &" ".repeat(MAX_GENERATION_EXPRESSION_BYTES + 1),
            ACTIVE_CARD_COLUMN
        ));
        assert!(!matches_generation_expression(
            EXPECTED_GENERATED_COLUMNS[0].1,
            "unknown"
        ));
    }

    #[test]
    // memory—v1: A syntactically present but semantically unknown expression
    // fails the constraint loader before any candidate rows are accepted.
    fn overlay_guard_unknown_expression_fails_closed() {
        let mut unknown = generated_overlay_guard();
        unknown[2].generation_expression = Some("NULL".to_owned());
        assert!(matches!(
            validate_candidate_schema_constraints(&constraint_indexes(), &unknown),
            Err(
                CandidateSchemaConstraintError::InvalidGenerationExpression {
                    table: BINDING_TABLE,
                    column: OVERLAY_GUARD_COLUMN,
                }
            )
        ));
    }

    #[test]
    // memory—v1: Uniqueness cannot be inferred from a non-unique, partial, empty,
    // reordered, invisible, non-BTREE, or functional index shape.
    fn candidate_constraints_reject_ambiguous_index_shapes() {
        type IndexMutation = fn(&mut Vec<ObservedIndex>);
        let cases: [(&str, IndexMutation); 8] = [
            ("non_unique", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].non_unique = 1;
            }),
            ("sequence", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].sequence = 3;
            }),
            ("empty_column", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].column_name = Some("  ".to_owned());
            }),
            ("null_column", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].column_name = None;
            }),
            ("prefix", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].sub_part = Some(8);
            }),
            ("functional", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].expression = Some("(rule_set_id)".to_owned());
            }),
            ("invisible", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].is_visible = false;
            }),
            ("index_type", |indexes: &mut Vec<ObservedIndex>| {
                indexes[0].index_type = "HASH".to_owned();
            }),
        ];
        for (name, mutate) in cases {
            let mut indexes = constraint_indexes();
            mutate(&mut indexes);
            assert!(
                matches!(
                    validate_candidate_schema_constraints(&indexes, &generated_overlay_guard()),
                    Err(CandidateSchemaConstraintError::InvalidIndex { .. })
                ),
                "case {name} unexpectedly passed"
            );
        }

        for missing_name in [BINDING_PAIR_INDEX, OVERLAY_GUARD_INDEX] {
            let mut missing = constraint_indexes();
            missing.retain(|index| index.name != missing_name);
            assert!(matches!(
                validate_candidate_schema_constraints(&missing, &generated_overlay_guard()),
                Err(CandidateSchemaConstraintError::MissingIndex { index, .. })
                    if index == missing_name
            ));
        }

        let mut reordered = constraint_indexes();
        reordered[0].column_name = Some("user_card_id".to_owned());
        reordered[1].column_name = Some("rule_set_id".to_owned());
        assert!(matches!(
            validate_candidate_schema_constraints(&reordered, &generated_overlay_guard()),
            Err(CandidateSchemaConstraintError::InvalidIndex { .. })
        ));

        let mut incomplete = constraint_indexes();
        incomplete.retain(|index| !(index.name == BINDING_PAIR_INDEX && index.sequence == 2));
        assert!(matches!(
            validate_candidate_schema_constraints(&incomplete, &generated_overlay_guard()),
            Err(CandidateSchemaConstraintError::InvalidIndex { .. })
        ));
    }

    #[test]
    // memory—v1: Legacy full-table uniqueness and foreign metadata are refused.
    fn candidate_constraints_reject_legacy_and_foreign_indexes() {
        for legacy in [
            "uq_binding_card_ruleset",
            "uq_binding_one_overlay",
            "unexpected",
        ] {
            let mut indexes = constraint_indexes();
            indexes.push(ObservedIndex {
                table: BINDING_TABLE.to_owned(),
                name: legacy.to_owned(),
                non_unique: 0,
                sequence: 1,
                column_name: Some("user_card_id".to_owned()),
                sub_part: None,
                expression: None,
                index_type: "BTREE".to_owned(),
                is_visible: true,
            });
            assert!(matches!(
                validate_candidate_schema_constraints(&indexes, &generated_overlay_guard()),
                Err(CandidateSchemaConstraintError::UnexpectedIndex { .. })
            ));
        }
        let mut indexes = constraint_indexes();
        indexes[0].table = "foreign_table".to_owned();
        assert!(matches!(
            validate_candidate_schema_constraints(&indexes, &generated_overlay_guard()),
            Err(CandidateSchemaConstraintError::UnexpectedIndex { .. })
        ));
    }

    #[test]
    // memory—v1: MySQL may report an empty expression on ordinary columns.
    fn ordinary_columns_with_empty_generation_metadata_are_not_generated() {
        let mut columns = generated_overlay_guard();
        columns.push(ObservedGeneratedColumn {
            table: BINDING_TABLE.to_owned(),
            column: "binding_id".to_owned(),
            extra: String::new(),
            generation_expression: Some(String::new()),
        });
        assert!(validate_candidate_schema_constraints(&constraint_indexes(), &columns).is_ok());
        columns.last_mut().unwrap().generation_expression = Some(" ".to_owned());
        assert!(matches!(
            validate_candidate_schema_constraints(&constraint_indexes(), &columns),
            Err(CandidateSchemaConstraintError::UnexpectedGeneratedColumn { .. })
        ));
        columns.last_mut().unwrap().generation_expression = Some(String::new());
        columns.last_mut().unwrap().table = "foreign_table".to_owned();
        assert!(matches!(
            validate_candidate_schema_constraints(&constraint_indexes(), &columns),
            Err(CandidateSchemaConstraintError::UnexpectedGeneratedColumn { .. })
        ));
    }

    #[test]
    // memory—v1: Only STORED GENERATED with a frozen-contract expression is
    // accepted; text matching does not prove live MySQL expression semantics.
    fn overlay_guard_generation_metadata_fails_closed() {
        assert!(matches!(
            validate_candidate_schema_constraints(&constraint_indexes(), &[]),
            Err(CandidateSchemaConstraintError::MissingGeneratedColumn { .. })
        ));

        let mut virtual_column = generated_overlay_guard();
        virtual_column[0].extra = "VIRTUAL GENERATED".to_owned();
        assert!(matches!(
            validate_candidate_schema_constraints(&constraint_indexes(), &virtual_column),
            Err(CandidateSchemaConstraintError::InvalidGeneratedColumnStorage { .. })
        ));

        for expression in [None, Some(" ".to_owned())] {
            let mut missing_expression = generated_overlay_guard();
            missing_expression[0].generation_expression = expression;
            assert!(matches!(
                validate_candidate_schema_constraints(&constraint_indexes(), &missing_expression),
                Err(CandidateSchemaConstraintError::MissingGenerationExpression { .. })
            ));
        }

        let mut duplicate = generated_overlay_guard();
        duplicate.extend(generated_overlay_guard());
        assert!(matches!(
            validate_candidate_schema_constraints(&constraint_indexes(), &duplicate),
            Err(CandidateSchemaConstraintError::DuplicateGeneratedColumn { .. })
        ));
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
