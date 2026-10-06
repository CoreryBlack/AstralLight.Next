use crate::types::{invalid, ContractError};

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_OPAQUE_IDENTIFIER_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 2_048;
const MAX_REVISION_BYTES: usize = 128;

/// Validate a short ASCII identifier used for resource types, actions, and app/key IDs.
pub fn identifier(value: &str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invalid("identifier", "length must be 1..=128 bytes"));
    }
    if value.len() > 1 && value.starts_with('_')
        || !value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        || !value
            .bytes()
            .skip(1)
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return Err(invalid(
            "identifier",
            "must use lowercase ASCII letters, digits, underscore, or hyphen",
        ));
    }
    Ok(())
}

pub(crate) fn bounded_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    identifier(value).map_err(|_| invalid(field, "invalid identifier"))?;
    if value.len() > max_bytes {
        return Err(invalid(field, "identifier exceeds its storage width"));
    }
    Ok(())
}

/// Validate an external identifier preserved byte-for-byte, without whitespace/control chars.
pub fn opaque_identifier(value: &str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > MAX_OPAQUE_IDENTIFIER_BYTES {
        return Err(invalid("opaque_identifier", "length must be 1..=256 bytes"));
    }
    if !value.is_ascii() || value.bytes().any(|b| !(b'!'..=b'~').contains(&b)) {
        return Err(invalid(
            "opaque_identifier",
            "must contain visible ASCII without whitespace",
        ));
    }
    Ok(())
}

pub(crate) fn validate_revision(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > MAX_REVISION_BYTES
        || !value.is_ascii()
        || value.bytes().any(|b| !(b'!'..=b'~').contains(&b))
    {
        return Err(invalid(field, "must be 1..=128 visible ASCII bytes"));
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            field,
            "must be a lowercase 64-character SHA-256 hex digest",
        ));
    }
    Ok(())
}

pub(crate) fn validate_path(path: &str, allow_query: bool) -> Result<(), ContractError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || !path.starts_with('/') {
        return Err(invalid("path", "must be an absolute bounded path"));
    }
    if path.contains('#') || path.contains('\\') || path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(invalid("path", "contains a forbidden character"));
    }
    let (pathname, query) = match path.split_once('?') {
        Some((pathname, query)) if allow_query && !query.is_empty() => (pathname, Some(query)),
        Some(_) => return Err(invalid("path", "query string is not allowed here")),
        None => (path, None),
    };
    if pathname.contains("//") {
        return Err(invalid("path", "repeated slash is not allowed"));
    }
    if pathname
        .split('/')
        .any(|segment| segment == "." || segment == ".." || segment.contains('%'))
    {
        return Err(invalid(
            "path",
            "dot or percent-encoded path segments are not allowed",
        ));
    }
    for segment in pathname.split('/').skip(1) {
        if segment.starts_with('{') || segment.ends_with('}') {
            if !segment.starts_with('{')
                || !segment.ends_with('}')
                || segment.len() < 3
                || identifier(&segment[1..segment.len() - 1]).is_err()
            {
                return Err(invalid("path", "invalid named path parameter"));
            }
        } else if segment
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~')))
        {
            return Err(invalid("path", "contains an invalid path segment"));
        }
    }
    if let Some(query) = query {
        if query.len() > 1_024 || query.contains('#') || !query.is_ascii() {
            return Err(invalid(
                "path",
                "query string exceeds its limit or contains invalid bytes",
            ));
        }
    }
    Ok(())
}
