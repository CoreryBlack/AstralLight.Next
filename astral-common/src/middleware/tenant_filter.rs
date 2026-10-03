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
use policy_engine::{PermissionRule, RuleSetSnapshot};

const FAIL_CLOSED_SQL: &str = "SELECT NULL WHERE 1 = 0";
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
///
/// `new`, `build`, `build_sql`, and `params` preserve the previous signatures.
/// Legacy infallible builders now return a fixed zero-row SELECT on invalid
/// scope/SQL; use `try_build`/`try_build_sql` to inspect validation failures.
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

    /// Legacy infallible API. Invalid input returns a fixed query that returns no rows.
    pub fn build(&self) -> (String, Vec<String>) {
        self.try_build()
            .unwrap_or_else(|_| (FAIL_CLOSED_SQL.to_owned(), Vec::new()))
    }

    pub fn try_build_sql(&self) -> Result<String, TenantScopeQueryError> {
        self.try_build().map(|(sql, _)| sql)
    }

    /// Legacy infallible API; invalid input returns `SELECT NULL WHERE 1 = 0`.
    pub fn build_sql(&self) -> String {
        self.build().0
    }

    /// Legacy infallible API; invalid input has no bind values.
    pub fn params(&self) -> Vec<String> {
        self.build().1
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
            // Quotes, comments, semicolons, parenthesis and all unsupported tokens
            // are rejected: legacy builder will return a fixed zero-row SELECT.
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

/// Legacy compatibility helper. Invalid input returns a fixed no-rows SELECT.
pub async fn apply_tenant_scope(
    base_sql: &str,
    filter: &impl DataFrameScopeFilter,
) -> (String, Vec<String>) {
    TenantScopedQuery::new(base_sql).with_filter(filter).build()
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
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, astral_types::PolicyError> {
            Ok(vec![])
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
            Ok(vec![PermissionRule {
                id: 1,
                effect: astral_types::Effect::Allow,
                resource: "global_resource".into(),
                action: "read".into(),
                condition: None,
            }])
        }
    }

    async fn authorized_global_scope() -> AuthorizedGlobalScope {
        let context = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
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
    async fn missing_tenant_rejects_and_legacy_build_returns_constant_zero_rows_query() {
        let query = TenantScopedQuery::new("SELECT * FROM resources");
        assert_eq!(query.try_build(), Err(TenantScopeQueryError::ScopeRequired));
        assert_eq!(query.build(), (FAIL_CLOSED_SQL.into(), vec![]));
        assert_eq!(query.build_sql(), FAIL_CLOSED_SQL);
        assert!(query.params().is_empty());
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
            assert_eq!(query.build(), (FAIL_CLOSED_SQL.into(), vec![]), "{sql}");
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
