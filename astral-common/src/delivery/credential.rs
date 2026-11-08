//! Protected credential resolution.
//!
//! Channel configuration JSON must never carry secret values. Secrets are
//! referenced by environment variable name (`"<field>Env"` keys) and resolved
//! from the protected environment at dispatch time. Values are never logged,
//! never embedded in errors, and never persisted.

use serde_json::Value;

use crate::delivery::state::DeliveryError;

/// JSON keys that must never hold a raw secret value.
const SECRET_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "auth",
    "apiKey",
    "api_key",
    "accessKey",
    "access_key",
    "secretKey",
    "secret_key",
    "authHeader",
    "authorization",
    "appSecret",
    "app_secret",
];

/// Reject channel configs that embed raw secret values inline. Empty strings
/// are tolerated only as absent (legacy rows) and must be removed on update.
pub fn reject_inline_secrets(config: &Value) -> Result<(), DeliveryError> {
    let Some(object) = config.as_object() else {
        return Ok(());
    };
    for key in object.keys() {
        if SECRET_KEYS.contains(&key.as_str()) {
            if let Some(value) = object.get(key).and_then(Value::as_str) {
                if !value.trim().is_empty() {
                    return Err(DeliveryError::InlineSecretRejected);
                }
            }
        }
    }
    Ok(())
}

/// Resolve `<field>Env`-style environment reference from the channel config.
///
/// `field` is the logical name (e.g. `password` looks up `passwordEnv`). The
/// referenced environment variable must exist and be non-empty at dispatch
/// time. The resolved value is returned to the caller only; it is never
/// logged by this module.
pub fn resolve_env_ref(config: &Value, field: &str) -> Result<Option<String>, DeliveryError> {
    let env_key = format!("{field}Env");
    let Some(reference) = config.get(&env_key).and_then(Value::as_str) else {
        return Ok(None);
    };
    let reference = reference.trim();
    if reference.is_empty() {
        return Ok(None);
    }
    validate_env_name(reference, field)?;
    match std::env::var(reference) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
        // Only the env var NAME lands in the error (names are not secret);
        // the value itself never does.
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            Err(DeliveryError::SecretUnavailable(reference.to_owned()))
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(DeliveryError::SecretUnavailable(reference.to_owned()))
        }
    }
}

fn validate_env_name(name: &str, _field: &str) -> Result<(), DeliveryError> {
    let mut chars = name.chars();
    let ok = match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    };
    if !ok || name.len() > 64 {
        return Err(DeliveryError::InvalidConfig("env ref name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inline_secrets_are_rejected() {
        assert_eq!(
            reject_inline_secrets(&json!({"password": "hunter2"})),
            Err(DeliveryError::InlineSecretRejected)
        );
        assert_eq!(
            reject_inline_secrets(&json!({"apiKey": "abcd"})),
            Err(DeliveryError::InlineSecretRejected)
        );
        // Env references are the approved shape.
        assert_eq!(
            reject_inline_secrets(&json!({"passwordEnv": "ASTRAL_SMTP_PASSWORD"})),
            Ok(())
        );
        // Empty strings treated as absent.
        assert_eq!(reject_inline_secrets(&json!({"password": ""})), Ok(()));
        assert_eq!(
            reject_inline_secrets(&json!({"host": "smtp.example.com"})),
            Ok(())
        );
    }

    #[test]
    fn env_ref_is_resolved_at_dispatch_time() {
        let key = "ASTRAL_TEST_DELIVERY_SECRET_REF";
        std::env::set_var(key, "resolved-value");
        let config = json!({"passwordEnv": key});
        assert_eq!(
            resolve_env_ref(&config, "password").unwrap(),
            Some("resolved-value".to_owned())
        );
        std::env::remove_var(key);
        assert_eq!(
            resolve_env_ref(&config, "password").unwrap_err(),
            DeliveryError::SecretUnavailable(key.to_owned())
        );
    }

    #[test]
    fn env_ref_names_are_validated() {
        let config = json!({"passwordEnv": "with-dash"});
        assert!(matches!(
            resolve_env_ref(&config, "password"),
            Err(DeliveryError::InvalidConfig("env ref name"))
        ));
        let config = json!({"passwordEnv": "9STARTS_WITH_DIGIT"});
        assert!(matches!(
            resolve_env_ref(&config, "password"),
            Err(DeliveryError::InvalidConfig("env ref name"))
        ));
        // Absent reference is not an error: the field is optional.
        assert_eq!(resolve_env_ref(&json!({}), "password").unwrap(), None);
    }
}
