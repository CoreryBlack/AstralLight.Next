use thiserror::Error;

/// AstralLight 系统级错误
#[derive(Debug, Error)]
pub enum AstralError {
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// 资源注册表错误
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Unregistered resource type: {0}")]
    UnregisteredResource(String),

    #[error("Invalid action '{action}' for resource '{resource}'")]
    InvalidAction { resource: String, action: String },

    #[error("Condition '{condition}' is not supported for resource '{resource}'")]
    UnsupportedCondition { resource: String, condition: String },
}

/// 权限评估错误
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Invalid policy context: {0}")]
    InvalidContext(String),

    #[error("Repository error: {0}")]
    Repository(String),

    #[error("Circuit breaker open")]
    CircuitBreakerOpen,

    #[error("Rule evaluation error: {0}")]
    Evaluation(String),

    #[error("Card pair not eligible: {0}")]
    NotEligible(String),
}

impl From<PolicyError> for AstralError {
    fn from(e: PolicyError) -> Self {
        AstralError::Permission(e.to_string())
    }
}
