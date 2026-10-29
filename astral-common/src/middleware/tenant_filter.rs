//! Conservative tenant-scope query builder.
//!
//! This helper is not an automatic SQL rewriter. It accepts only a deliberately
//! small grammar: a single-table `SELECT`, simple selected columns, and an
//! optional conjunction of simple predicates. It rejects OR, joins, subqueries,
//! comments, quoted literals, statement tails (ORDER/GROUP/LIMIT/etc.) and all
//! other SQL. Use a SQL parser or a query-specific explicitly grouped predicate
//! for broader SQL. Missing tenant scope fails closed unless a separate explicit
//! global authorization capability is supplied.

use astral_types::{GlobalAccessRequirement, PolicyContext, ResourceOwnershipScope};
use policy_engine::{PolicyEngine, RuleRepository};

#[cfg(test)]
use astral_types::{
    BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, GrantValidity, PublishedAggregateManifestSummary,
    PublishedCardAuthorization, PublishedCardAuthorizationGate, PublishedEvidenceGateStatus,
    TenantScope, VerifiedPublishedGrantRecord,
};

const MAX_SQL_BYTES: usize = 4096;
const MAX_TOKENS: usize = 512;

/// Restricted-query validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantScopeQueryError {
    ScopeRequired,
    GlobalAuthorizationRequired,
    UnsupportedSql,
    InvalidAlias,
    InvalidScopeId,
}

impl std::fmt::Display for TenantScopeQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ScopeRequired => "a positive tenant scope or explicit global authorization is required",
            Self::GlobalAuthorizationRequired => "global authorization must come from an ALLOW decision for a resolver-classified global resource",
            Self::UnsupportedSql => "SQL is outside the restricted single-table SELECT grammar",
            Self::InvalidAlias => "query alias is invalid or does not name the selected table",
            Self::InvalidScopeId => "tenant, domain and user scope IDs must be positive",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TenantScopeQueryError {}

/// Capability token for an explicitly authorized, resolver-classified global query.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedGlobalScope {
    resource: String,
}

impl AuthorizedGlobalScope {
    pub async fn evaluate_and_authorize<R: RuleRepository>(
        context: &PolicyContext,
        engine: &PolicyEngine,
        repository: &R,
    ) -> Result<Self, TenantScopeQueryError> {
        if context.resource_ownership_scope != ResourceOwnershipScope::Global
            || context.global_access_requirement == GlobalAccessRequirement::Unspecified
            || context.resource.is_none()
            || context.target_id.is_none_or(|id| id <= 0)
            || context.resource_tenant_id.is_some()
            || context.resource_domain_id.is_some()
            || context.resource_owner_id.is_some()
        {
            return Err(TenantScopeQueryError::GlobalAuthorizationRequired);
        }
        let decision = engine.evaluate(context, repository).await;
        if !decision.allowed {
            return Err(TenantScopeQueryError::GlobalAuthorizationRequired);
        }
        Ok(Self {
            resource: context.resource.clone().expect("checked above"),
        })
    }
}

/// Restricted parameterized tenant-scope SELECT builder.
/// Invalid scope or unsupported SQL returns an explicit validation error.
#[derive(Debug, Clone)]
pub struct TenantScopedQuery {
    base_sql: String,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    user_id: Option<i64>,
    table_alias: String,
    authorized_global: bool,
    authorized_resource: Option<String>,
    target_resource: Option<String>,
}

impl TenantScopedQuery {
    /// Create a query from trusted static SQL in the documented restricted grammar.
    pub fn new(base_sql: impl Into<String>) -> Self {
        Self {
            base_sql: base_sql.into(),
            tenant_id: None,
            domain_id: None,
            user_id: None,
            table_alias: String::new(),
            authorized_global: false,
            authorized_resource: None,
            target_resource: None,
        }
    }

    /// Set the selected table name/alias used to qualify appended scope clauses.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.table_alias = alias.into();
        self
    }

    pub fn with_tenant(mut self, tenant_id: i64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    pub fn with_domain(mut self, domain_id: i64) -> Self {
        self.domain_id = Some(domain_id);
        self
    }

    pub fn with_user(mut self, user_id: i64) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Supply a separate policy-ALLOW capability for a resolver-classified global target.
    pub fn with_authorized_global_scope(
        mut self,
        resource: &str,
        authorization: &AuthorizedGlobalScope,
    ) -> Self {
        self.authorized_global = true;
        self.authorized_resource = Some(authorization.resource.clone());
        self.target_resource = Some(resource.to_owned());
        self
    }

    /// Apply the supported policy scope fields to this query.
    pub fn with_filter(mut self, filter: &impl DataFrameScopeFilter) -> Self {
        if let Some(value) = filter.tenant_id() {
            self.tenant_id = Some(value);
        }
        if let Some(value) = filter.domain_id() {
            self.domain_id = Some(value);
        }
        if let Some(value) = filter.user_id() {
            self.user_id = Some(value);
        }
        self
    }

    /// Validate SQL and return the query and appended scope bind values.
    /// Existing placeholders in `base_sql` remain the caller's responsibility.
    pub fn try_build(&self) -> Result<(String, Vec<String>), TenantScopeQueryError> {
        if self.tenant_id.is_none()
            && (!self.authorized_global
                || self.authorized_resource.as_deref() != self.target_resource.as_deref())
        {
            return Err(if self.authorized_global {
                TenantScopeQueryError::GlobalAuthorizationRequired
            } else {
                TenantScopeQueryError::ScopeRequired
            });
        }
        if self.tenant_id.is_some_and(|value| value <= 0)
            || self.domain_id.is_some_and(|value| value <= 0)
            || self.user_id.is_some_and(|value| value <= 0)
        {
            return Err(TenantScopeQueryError::InvalidScopeId);
        }

        let parsed = parse_restricted_select(&self.base_sql)?;
        if self.tenant_id.is_none()
            && self.authorized_resource.as_deref() != Some(parsed.table_name.as_str())
        {
            return Err(TenantScopeQueryError::GlobalAuthorizationRequired);
        }
        let table_alias = if self.table_alias.is_empty() {
            parsed.table_alias.as_str()
        } else if is_identifier(&self.table_alias)
            && self
                .table_alias
                .eq_ignore_ascii_case(parsed.table_alias.as_str())
        {
            self.table_alias.as_str()
        } else {
            return Err(TenantScopeQueryError::InvalidAlias);
        };
        let prefix = format!("{table_alias}.");
        let mut clauses = Vec::new();
        let mut params = Vec::new();
        if let Some(value) = self.tenant_id {
            clauses.push(format!("{prefix}tenant_id = ?"));
            params.push(value.to_string());
        }
        if let Some(value) = self.domain_id {
            clauses.push(format!("{prefix}domain_id = ?"));
            params.push(value.to_string());
        }
        if let Some(value) = self.user_id {
            clauses.push(format!("{prefix}user_id = ?"));
            params.push(value.to_string());
        }

        let sql = if clauses.is_empty() {
            self.base_sql.trim().to_owned()
        } else if parsed.has_where {
            format!("{} AND {}", self.base_sql.trim(), clauses.join(" AND "))
        } else {
            format!("{} WHERE {}", self.base_sql.trim(), clauses.join(" AND "))
        };
        Ok((sql, params))
    }

    pub fn try_build_sql(&self) -> Result<String, TenantScopeQueryError> {
        self.try_build().map(|(sql, _)| sql)
    }

    pub fn try_params(&self) -> Result<Vec<String>, TenantScopeQueryError> {
        self.try_build().map(|(_, params)| params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Number,
    Bind,
    Star,
    Comma,
    Dot,
    Operator(String),
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position)?.clone();
        self.position += 1;
        Some(token)
    }

    fn eat_keyword(&mut self, keyword: &str) -> bool {
        match self.peek() {
            Some(Token::Word(value)) if value.eq_ignore_ascii_case(keyword) => {
                self.position += 1;
                true
            }
            _ => false,
        }
    }

    fn next_word(&mut self) -> Result<String, TenantScopeQueryError> {
        match self.take() {
            Some(Token::Word(value)) if !is_reserved_word(&value) => Ok(value),
            _ => Err(TenantScopeQueryError::UnsupportedSql),
        }
    }

    fn parse_column(&mut self, allow_star: bool) -> Result<String, TenantScopeQueryError> {
        let first = self.next_word()?;
        if self.peek() == Some(&Token::Dot) {
            self.take();
            if allow_star && self.peek() == Some(&Token::Star) {
                self.take();
                return Ok(first);
            }
            return self.next_word();
        }
        Ok(first)
    }

    fn parse_predicate(&mut self) -> Result<(), TenantScopeQueryError> {
        self.parse_column(false)?;
        match self.take() {
            Some(Token::Operator(operator))
                if matches!(
                    operator.as_str(),
                    "=" | "<>" | "!=" | "<" | "<=" | ">" | ">="
                ) => {}
            _ => return Err(TenantScopeQueryError::UnsupportedSql),
        }
        match self.take() {
            Some(Token::Word(value))
                if !is_reserved_word(&value) || value.eq_ignore_ascii_case("NULL") => {}
            Some(Token::Number) | Some(Token::Bind) => {}
            _ => return Err(TenantScopeQueryError::UnsupportedSql),
        }
        Ok(())
    }
}

struct ParsedSelect {
    table_name: String,
    table_alias: String,
    has_where: bool,
}

fn parse_restricted_select(sql: &str) -> Result<ParsedSelect, TenantScopeQueryError> {
    if sql.trim().is_empty() || sql.len() > MAX_SQL_BYTES || !sql.is_ascii() {
        return Err(TenantScopeQueryError::UnsupportedSql);
    }
    let mut parser = Parser {
        tokens: tokenize(sql)?,
        position: 0,
    };
    if !parser.eat_keyword("SELECT") {
        return Err(TenantScopeQueryError::UnsupportedSql);
    }
    loop {
        if parser.peek() == Some(&Token::Star) {
            parser.take();
        } else {
            parser.parse_column(true)?;
        }
        if parser.peek() == Some(&Token::Comma) {
            parser.take();
            continue;
        }
        break;
    }
    if !parser.eat_keyword("FROM") {
        return Err(TenantScopeQueryError::UnsupportedSql);
    }
    let first_table_part = parser.next_word()?;
    let (table_name, mut table_alias) = if parser.peek() == Some(&Token::Dot) {
        parser.take();
        let table_part = parser.next_word()?;
        (format!("{first_table_part}.{table_part}"), table_part)
    } else {
        (first_table_part.clone(), first_table_part)
    };
    if parser.eat_keyword("AS")
        || matches!(parser.peek(), Some(Token::Word(word)) if !is_reserved_word(word))
    {
        table_alias = parser.next_word()?;
    }
    let has_where = parser.eat_keyword("WHERE");
    if has_where {
        parser.parse_predicate()?;
        while parser.eat_keyword("AND") {
            parser.parse_predicate()?;
        }
    }
    if parser.peek().is_some() {
        return Err(TenantScopeQueryError::UnsupportedSql);
    }
    Ok(ParsedSelect {
        table_name,
        table_alias,
        has_where,
    })
}

fn tokenize(sql: &str) -> Result<Vec<Token>, TenantScopeQueryError> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let byte = bytes[position];
        if byte.is_ascii_whitespace() {
            position += 1;
            continue;
        }
        let token = if is_ident_start(byte) {
            let start = position;
            position += 1;
            while position < bytes.len() && is_ident_continue(bytes[position]) {
                position += 1;
            }
            Token::Word(sql[start..position].to_owned())
        } else if byte.is_ascii_digit()
            || (byte == b'-' && bytes.get(position + 1).is_some_and(u8::is_ascii_digit))
        {
            position += 1;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                position += 1;
            }
            if bytes.get(position) == Some(&b'.') {
                position += 1;
                let fractional_start = position;
                while position < bytes.len() && bytes[position].is_ascii_digit() {
                    position += 1;
                }
                if position == fractional_start {
                    return Err(TenantScopeQueryError::UnsupportedSql);
                }
            }
            Token::Number
        } else if byte == b'?' {
            position += 1;
            Token::Bind
        } else if byte == b'*' {
            position += 1;
            Token::Star
        } else if byte == b',' {
            position += 1;
            Token::Comma
        } else if byte == b'.' {
            position += 1;
            Token::Dot
        } else if matches!(byte, b'=' | b'<' | b'>' | b'!') {
            let start = position;
            position += 1;
            if position < bytes.len()
                && ((byte == b'<' && matches!(bytes[position], b'=' | b'>'))
                    || (byte == b'>' && bytes[position] == b'=')
                    || (byte == b'!' && bytes[position] == b'='))
            {
                position += 1;
            }
            let operator = &sql[start..position];
            if byte == b'!' && operator != "!=" {
                return Err(TenantScopeQueryError::UnsupportedSql);
            }
            Token::Operator(operator.into())
        } else {
            // Quotes, comments, semicolons, parentheses and unsupported tokens
            // must fail before the caller can issue a scoped query.
            return Err(TenantScopeQueryError::UnsupportedSql);
        };
        tokens.push(token);
        if tokens.len() > MAX_TOKENS {
            return Err(TenantScopeQueryError::UnsupportedSql);
        }
    }
    Ok(tokens)
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(is_ident_start) && bytes.all(is_ident_continue)
}

fn is_reserved_word(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "SELECT"
            | "FROM"
            | "WHERE"
            | "AND"
            | "OR"
            | "AS"
            | "ORDER"
            | "BY"
            | "GROUP"
            | "HAVING"
            | "LIMIT"
            | "OFFSET"
            | "UNION"
            | "JOIN"
            | "LEFT"
            | "RIGHT"
            | "INNER"
            | "OUTER"
            | "CROSS"
            | "ON"
            | "FOR"
            | "LOCK"
            | "RETURNING"
            | "INTO"
            | "PROCEDURE"
            | "WITH"
            | "NULL"
    )
}

pub trait DataFrameScopeFilter {
    fn tenant_id(&self) -> Option<i64>;
    fn domain_id(&self) -> Option<i64>;
    fn user_id(&self) -> Option<i64>;
    fn org_id(&self) -> Option<i64>;
}

pub async fn try_apply_tenant_scope(
    base_sql: &str,
    filter: &impl DataFrameScopeFilter,
) -> Result<(String, Vec<String>), TenantScopeQueryError> {
    TenantScopedQuery::new(base_sql)
        .with_filter(filter)
        .try_build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Filter {
        tenant: Option<i64>,
        domain: Option<i64>,
        user: Option<i64>,
    }

    impl DataFrameScopeFilter for Filter {
        fn tenant_id(&self) -> Option<i64> {
            self.tenant
        }
        fn domain_id(&self) -> Option<i64> {
            self.domain
        }
        fn user_id(&self) -> Option<i64> {
            self.user
        }
        fn org_id(&self) -> Option<i64> {
            None
        }
    }

    struct AllowGlobalRepository;

    #[async_trait::async_trait]
    impl RuleRepository for AllowGlobalRepository {
        async fn check_card_active(
            &self,
            _ctx: &PolicyContext,
        ) -> Result<bool, astral_types::PolicyError> {
            Ok(true)
        }

        async fn is_active_global_admin(
            &self,
            _user_id: i64,
        ) -> Result<bool, astral_types::PolicyError> {
            Ok(false)
        }

        async fn load_published_card_authorization(
            &self,
            scope: &astral_types::PublishedCardEvidenceScope,
        ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, astral_types::PolicyError>
        {
            let grant = CanonicalGrant {
                grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440000")
                    .expect("fixture grant id is valid"),
                revision: GrantRevision::new(1).expect("fixture revision is positive"),
                state: GrantState::Active,
                source_kind: GrantSourceKind::Direct,
                binding_layer: BindingLayer::None,
                tenant: TenantScope::new(scope.tenant_id, None)
                    .expect("fixture evidence tenant is positive"),
                card_id: scope.card_id,
                user_id: scope.user_filter.unwrap_or(1),
                resource: "global_resource".into(),
                action: "read".into(),
                effect: GrantEffect::Allow,
                validity: GrantValidity::perpetual(),
                provenance: GrantProvenance {
                    source_id: "user-card-1".into(),
                    source_entry: Some("permission-1".into()),
                    binding_id: None,
                    delegation_id: None,
                    operation_id: "operation-1".into(),
                    event_id: Some("event-1".into()),
                    actor_user_id: None,
                },
            };
            let compiler_version = astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned();
            let semantic_hash = "a".repeat(64);
            let dependency_hash = "b".repeat(64);
            let manifest_digest = "c".repeat(64);
            let manifest = PublishedAggregateManifestSummary {
                seal: astral_types::PublicationSeal::from_unix_seconds(1_700_000_000)
                    .expect("fixture seal is in range"),
                tenant_id: scope.tenant_id,
                card_id: scope.card_id,
                aggregate_type: "CARD".into(),
                aggregate_id: scope.card_id,
                manifest_id: 1,
                generation: 1,
                source_generation: 1,
                projected_generation: 1,
                revoke_fence: 0,
                cas_version: 1,
                semantic_hash_hex: semantic_hash.clone(),
                dependency_hash_hex: dependency_hash.clone(),
                manifest_digest_hex: manifest_digest,
                compiler_version: compiler_version.clone(),
                event_id: "event-1".into(),
                operation_id: "operation-1".into(),
                parent_manifest_id: None,
                segment_count: 1,
                declared_grant_row_count: 1,
            };
            let record = VerifiedPublishedGrantRecord {
                aggregate_type: "CARD".into(),
                aggregate_id: scope.card_id,
                publication_generation: 1,
                revoke_fence: 0,
                manifest_id: 1,
                event_id: "event-1".into(),
                operation_id: "operation-1".into(),
                semantic_hash_hex: semantic_hash,
                dependency_hash_hex: dependency_hash,
                compiler_version,
                segment_ordinal: 0,
                position_in_segment: 0,
                grant: grant.clone(),
                accepted_into_effective_set: true,
                unaccepted_reason: None,
            };
            Ok(Some(std::sync::Arc::new(PublishedCardAuthorization {
                tenant_id: scope.tenant_id,
                card_id: scope.card_id,
                read_unix_seconds: 1_700_000_000,
                gate: PublishedCardAuthorizationGate {
                    status: PublishedEvidenceGateStatus::Ready,
                    aggregate_manifest_count: 1,
                    verified_record_count: 1,
                    effective_grant_count: 1,
                    not_in_effective_count: 0,
                    equivalent_duplicate_collapsed_count: 0,
                },
                manifests: vec![manifest],
                records: vec![record],
                effective_grants: vec![grant],
            })))
        }

        async fn load_org_authorization(
            &self,
            _ctx: &PolicyContext,
        ) -> Result<policy_engine::OrgAuthorityRead, astral_types::PolicyError> {
            // This fixture models an authoritative owner that has established
            // the tenant is not under durable ORG_SCOPE management.
            Ok(policy_engine::OrgAuthorityRead::Unmanaged)
        }
    }

    async fn authorized_global_scope() -> AuthorizedGlobalScope {
        let context = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .tenant_id(Some(10))
            .action("read".into())
            .resource(Some("global_resource".into()))
            .target_id(Some(1))
            .resource_ownership_scope(ResourceOwnershipScope::Global)
            .global_access_requirement(GlobalAccessRequirement::PolicyEvidence)
            .build();
        AuthorizedGlobalScope::evaluate_and_authorize(
            &context,
            &PolicyEngine::new(),
            &AllowGlobalRepository,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn scopes_select_and_conjoins_existing_predicate() {
        let (sql, params) = TenantScopedQuery::new("SELECT * FROM resources WHERE deleted = 0")
            .with_tenant(42)
            .with_domain(10)
            .try_build()
            .unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM resources WHERE deleted = 0 AND resources.tenant_id = ? AND resources.domain_id = ?"
        );
        assert_eq!(params, vec!["42", "10"]);

        let (sql, params) = TenantScopedQuery::new("SELECT id, name FROM resources r")
            .with_tenant(42)
            .try_build()
            .unwrap();
        assert_eq!(
            sql,
            "SELECT id, name FROM resources r WHERE r.tenant_id = ?"
        );
        assert_eq!(params, vec!["42"]);
    }

    #[tokio::test]
    async fn missing_tenant_rejects_every_fallible_query_view() {
        let query = TenantScopedQuery::new("SELECT * FROM resources");
        assert_eq!(query.try_build(), Err(TenantScopeQueryError::ScopeRequired));
        assert_eq!(
            query.try_build_sql(),
            Err(TenantScopeQueryError::ScopeRequired)
        );
        assert_eq!(
            query.try_params(),
            Err(TenantScopeQueryError::ScopeRequired)
        );
        assert_eq!(
            try_apply_tenant_scope("SELECT * FROM resources", &Filter::default()).await,
            Err(TenantScopeQueryError::ScopeRequired)
        );
    }

    #[tokio::test]
    async fn explicit_global_authorization_is_separate_from_missing_scope() {
        let query = TenantScopedQuery::new("SELECT id FROM global_resource")
            .with_authorized_global_scope("global_resource", &authorized_global_scope().await);
        assert_eq!(
            query.try_build().unwrap(),
            ("SELECT id FROM global_resource".into(), vec![])
        );

        let denied_context = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("write".into())
            .resource(Some("global_resource".into()))
            .target_id(Some(1))
            .resource_ownership_scope(ResourceOwnershipScope::Global)
            .global_access_requirement(GlobalAccessRequirement::PolicyEvidence)
            .build();
        assert_eq!(
            AuthorizedGlobalScope::evaluate_and_authorize(
                &denied_context,
                &PolicyEngine::new(),
                &AllowGlobalRepository
            )
            .await,
            Err(TenantScopeQueryError::GlobalAuthorizationRequired)
        );
    }

    #[tokio::test]
    async fn rejects_or_sql_tails_joins_comments_and_multiple_statements() {
        for sql in [
            "SELECT * FROM resources WHERE tenant_id = 1 OR 1 = 1",
            "SELECT * FROM resources ORDER BY id",
            "SELECT * FROM resources LIMIT 5",
            "SELECT * FROM resources r JOIN other o ON r.id = o.id",
            "SELECT * FROM resources /* comment */",
            "SELECT * FROM resources; DELETE FROM resources",
            "SELECT * FROM resources WHERE name = 'x'",
            "WITH rows AS (SELECT * FROM resources) SELECT * FROM rows",
        ] {
            let query = TenantScopedQuery::new(sql).with_tenant(42);
            assert_eq!(
                query.try_build(),
                Err(TenantScopeQueryError::UnsupportedSql),
                "{sql}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_alias_and_non_positive_scope() {
        assert_eq!(
            TenantScopedQuery::new("SELECT * FROM resources r")
                .with_tenant(42)
                .with_alias("r WHERE 1=1")
                .try_build(),
            Err(TenantScopeQueryError::InvalidAlias)
        );
        assert_eq!(
            TenantScopedQuery::new("SELECT * FROM resources")
                .with_tenant(0)
                .try_build(),
            Err(TenantScopeQueryError::InvalidScopeId)
        );
    }

    #[tokio::test]
    async fn policy_filter_requires_tenant_unless_explicit_global_capability_exists() {
        let query = TenantScopedQuery::new("SELECT id FROM resources").with_filter(&Filter {
            domain: Some(3),
            ..Default::default()
        });
        assert_eq!(query.try_build(), Err(TenantScopeQueryError::ScopeRequired));
        let query =
            query.with_authorized_global_scope("global_resource", &authorized_global_scope().await);
        assert_eq!(
            query.try_build(),
            Err(TenantScopeQueryError::GlobalAuthorizationRequired)
        );
        let query = TenantScopedQuery::new("SELECT id FROM global_resource")
            .with_filter(&Filter {
                domain: Some(3),
                ..Default::default()
            })
            .with_authorized_global_scope("global_resource", &authorized_global_scope().await);
        assert_eq!(
            query.try_build().unwrap(),
            (
                "SELECT id FROM global_resource WHERE global_resource.domain_id = ?".into(),
                vec!["3".into()]
            )
        );
    }
}
