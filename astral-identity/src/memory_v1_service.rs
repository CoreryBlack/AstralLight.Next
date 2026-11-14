//! memory—v1: Identity's credential source and HTTP surface for the experimental
//! single-node service profile.
//!
//! The credential source is an operator-provisioned file of Argon2id password
//! hashes, because the memory—v1 candidate schema has no credential table and this
//! module does not invent one. The HTTP surface is exactly login and logout:
//!
//! * `POST /api/v1/auth/sessions` — a public bootstrap route. The body names a
//!   credential identifier, a password and the user card to act as. The request's
//!   own root scope (injected by the in-process Gateway dispatch) is the only
//!   reader used to check that card; nothing is read from client-supplied
//!   identity headers or legacy state.
//! * `POST /api/v1/auth/sessions/logout` — revokes the presented opaque session.
//!
//! Every other `/api/v1/auth/**` path is unrouted here, so no legacy integer/JWT
//! Identity handler is reachable through this router. Passwords and hashes are
//! never logged, formatted or echoed.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError;
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_types::memory_v1::MemoryId;

use crate::runtime::memory_v1::{
    normalize_identifier, MemoryV1CredentialAuthenticator, MemoryV1CredentialRecord,
    MemoryV1CredentialRepository, MemoryV1CredentialRepositoryError, MemoryV1CredentialStatus,
    MemoryV1IdentitySession, MemoryV1LoginError, MemoryV1LoginRequest,
};

/// The only credential-file layout this build accepts.
pub const MEMORY_V1_CREDENTIAL_FILE_VERSION: u32 = 1;

const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CREDENTIALS: usize = 10_000;
const MAX_PASSWORD_HASH_BYTES: usize = 512;
const MAX_LOGIN_BODY_BYTES: usize = 8 * 1024;

/// Failures while loading the operator-provisioned credential file. Messages never
/// quote a credential value: a parse failure reports only its class and location, and an
/// invalid entry is reported by its position in the file.
#[derive(Debug, Error)]
pub enum MemoryV1CredentialFileError {
    #[error("memory-v1 credential file cannot be read: {0}")]
    Read(#[from] std::io::Error),
    #[error("memory-v1 credential file is not a regular file")]
    NotRegularFile,
    #[error("memory-v1 credential file exceeds {MAX_CREDENTIAL_FILE_BYTES} bytes")]
    TooLarge,
    #[error("memory-v1 credential file mode bits grant group or other access (use mode 0600)")]
    InsecurePermissions,
    #[error("memory-v1 credential file permissions cannot be verified on this platform; use a Unix host with mode 0600")]
    UnverifiablePermissions,
    #[error("memory-v1 credential file is not valid: {0}")]
    Parse(String),
    #[error("memory-v1 credential file version {0} is unsupported")]
    UnsupportedVersion(u32),
    #[error("memory-v1 credential file lists no credentials")]
    Empty,
    #[error("memory-v1 credential file lists more than {MAX_CREDENTIALS} credentials")]
    TooMany,
    #[error("memory-v1 credential entry {0} has an invalid identifier")]
    InvalidIdentifier(usize),
    #[error("memory-v1 credential entry {0} repeats an identifier listed earlier")]
    DuplicateIdentifier(usize),
    #[error("memory-v1 credential entry {0} has an invalid password hash")]
    InvalidPasswordHash(usize),
    #[error("memory-v1 credential entry {0} has revision 0")]
    InvalidRevision(usize),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialFile {
    version: u32,
    credentials: Vec<CredentialEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialEntry {
    identifier: String,
    user_id: MemoryId,
    password_hash: String,
    status: EntryStatus,
    revision: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum EntryStatus {
    Active,
    Disabled,
    Revoked,
}

impl From<EntryStatus> for MemoryV1CredentialStatus {
    fn from(status: EntryStatus) -> Self {
        match status {
            EntryStatus::Active => Self::Active,
            EntryStatus::Disabled => Self::Disabled,
            EntryStatus::Revoked => Self::Revoked,
        }
    }
}

/// memory—v1: Serde quotes the offending value in its messages, which can be a misplaced
/// password hash, so a parse failure keeps only the class of the error. Its location is
/// reported beside it.
fn parse_failure_class(category: serde_json::error::Category) -> &'static str {
    use serde_json::error::Category;
    match category {
        Category::Io => "file cannot be read",
        Category::Syntax => "invalid JSON",
        Category::Data => "value does not match the credential schema",
        Category::Eof => "document ends early",
    }
}

/// memory—v1: Refuse a credential file whose Unix mode bits grant group or other access.
/// Only those mode bits are inspected. ACL grants are not, so where an ACL can grant read
/// access without changing the mode bits (for example macOS extended ACLs), a file with
/// mode 0600 can still be readable by another local user. Without Unix mode bits the
/// readers of a file cannot be verified, so it is refused rather than trusted unchecked.
#[cfg(unix)]
fn ensure_private_mode(metadata: &std::fs::Metadata) -> Result<(), MemoryV1CredentialFileError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(MemoryV1CredentialFileError::InsecurePermissions);
    }
    Ok(())
}

/// memory—v1: Without Unix mode bits the permissions of a credential file are unverifiable.
#[cfg(not(unix))]
fn ensure_private_mode(_metadata: &std::fs::Metadata) -> Result<(), MemoryV1CredentialFileError> {
    Err(MemoryV1CredentialFileError::UnverifiablePermissions)
}

/// memory—v1: A read-only credential repository loaded once from a private file.
///
/// It holds Argon2id hashes only and never accepts plaintext. It is a source of
/// authentication input, not of card, tenant or authorization facts.
pub struct MemoryV1FileCredentials {
    records: HashMap<String, MemoryV1CredentialRecord>,
}

impl fmt::Debug for MemoryV1FileCredentials {
    // memory—v1: Report only the count, never an identifier or a hash.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryV1FileCredentials")
            .field("credentials", &self.records.len())
            .finish()
    }
}

impl MemoryV1FileCredentials {
    /// memory—v1: Load the credential file, refusing anything but a private,
    /// bounded, regular file.
    pub fn load(path: &Path) -> Result<Self, MemoryV1CredentialFileError> {
        let file = std::fs::File::open(path)?;
        // Inspect the opened handle, not the path, so the checks and the read see
        // the same file.
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(MemoryV1CredentialFileError::NotRegularFile);
        }
        if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
            return Err(MemoryV1CredentialFileError::TooLarge);
        }
        ensure_private_mode(&metadata)?;
        let mut text = String::new();
        file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::InvalidData => {
                    MemoryV1CredentialFileError::Parse("file is not UTF-8".into())
                }
                _ => MemoryV1CredentialFileError::Read(error),
            })?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CREDENTIAL_FILE_BYTES {
            return Err(MemoryV1CredentialFileError::TooLarge);
        }
        Self::from_json(&text)
    }

    /// memory—v1: Parse and validate the credential document.
    pub fn from_json(text: &str) -> Result<Self, MemoryV1CredentialFileError> {
        let file: CredentialFile = serde_json::from_str(text).map_err(|error| {
            MemoryV1CredentialFileError::Parse(format!(
                "{} at line {}, column {}",
                parse_failure_class(error.classify()),
                error.line(),
                error.column()
            ))
        })?;
        if file.version != MEMORY_V1_CREDENTIAL_FILE_VERSION {
            return Err(MemoryV1CredentialFileError::UnsupportedVersion(
                file.version,
            ));
        }
        if file.credentials.is_empty() {
            return Err(MemoryV1CredentialFileError::Empty);
        }
        if file.credentials.len() > MAX_CREDENTIALS {
            return Err(MemoryV1CredentialFileError::TooMany);
        }
        let mut records = HashMap::with_capacity(file.credentials.len());
        for (position, entry) in file.credentials.into_iter().enumerate() {
            // Entries are named by position: an identifier is printable ASCII, so it could
            // hold a misplaced password hash, and no message may quote it.
            let entry_number = position + 1;
            let identifier = normalize_identifier(&entry.identifier)
                .map_err(|_| MemoryV1CredentialFileError::InvalidIdentifier(entry_number))?;
            if entry.password_hash.len() > MAX_PASSWORD_HASH_BYTES
                || !entry.password_hash.starts_with("$argon2id$")
            {
                return Err(MemoryV1CredentialFileError::InvalidPasswordHash(
                    entry_number,
                ));
            }
            if entry.revision == 0 {
                return Err(MemoryV1CredentialFileError::InvalidRevision(entry_number));
            }
            let record = MemoryV1CredentialRecord::new(
                entry.user_id,
                entry.password_hash,
                entry.status.into(),
                entry.revision,
            );
            if records.insert(identifier, record).is_some() {
                return Err(MemoryV1CredentialFileError::DuplicateIdentifier(
                    entry_number,
                ));
            }
        }
        Ok(Self { records })
    }

    /// memory—v1: Number of loaded credentials (diagnostic).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// memory—v1: Whether no credential was loaded (never true for a loaded file).
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[async_trait]
impl MemoryV1CredentialRepository for MemoryV1FileCredentials {
    // memory—v1: The identifier is already normalized by the authenticator.
    async fn find_by_identifier(
        &self,
        normalized_identifier: &str,
    ) -> Result<Option<MemoryV1CredentialRecord>, MemoryV1CredentialRepositoryError> {
        Ok(self.records.get(normalized_identifier).cloned())
    }
}

#[derive(Clone)]
struct AuthRouteState {
    session: Arc<MemoryV1IdentitySession>,
    authenticator: MemoryV1CredentialAuthenticator,
    session_lifetime_seconds: i64,
}

/// memory—v1: Identity's login and logout router for the experimental profile.
///
/// `session_lifetime_seconds` is server-controlled; the client cannot request a
/// lifetime. The Identity session authority still enforces its own maximum.
pub fn memory_v1_auth_router(
    session: Arc<MemoryV1IdentitySession>,
    authenticator: MemoryV1CredentialAuthenticator,
    session_lifetime_seconds: i64,
) -> Router {
    Router::new()
        .route("/api/v1/auth/sessions", post(login))
        .route("/api/v1/auth/sessions/logout", post(logout))
        .with_state(AuthRouteState {
            session,
            authenticator,
            session_lifetime_seconds,
        })
}

/// The login request body. Deliberately not `Debug`, so the password cannot be
/// logged by formatting.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginBody {
    identifier: String,
    password: String,
    user_card_id: MemoryId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginData {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
}

// memory—v1: The Gateway's clock source; one clock keeps issue and verify consistent.
fn now_unix_seconds() -> Option<i64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(elapsed.as_secs()).ok()
}

// memory—v1: One failure envelope with a machine-readable reason, no internals.
fn failure(status: StatusCode, reason_code: &'static str, message: &'static str) -> Response {
    let mut body = ApiResponse::<EmptyResponse>::error(i32::from(status.as_u16()), message);
    body.reason_code = Some(reason_code.to_owned());
    (
        status,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response()
}

// memory—v1: Map a login failure to a status without separating cause detail that
// would help enumerate users or cards.
fn login_failure(error: MemoryV1LoginError) -> Response {
    match error {
        MemoryV1LoginError::InvalidIdentifier => failure(
            StatusCode::BAD_REQUEST,
            "INVALID_IDENTIFIER",
            "credential identifier is invalid",
        ),
        MemoryV1LoginError::InvalidCredentials => failure(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "credentials are invalid",
        ),
        MemoryV1LoginError::CardNotOwned => failure(
            StatusCode::FORBIDDEN,
            "CARD_NOT_OWNED",
            "the selected user card is not available to this user",
        ),
        MemoryV1LoginError::Unavailable => unavailable(),
    }
}

fn unavailable() -> Response {
    failure(
        StatusCode::SERVICE_UNAVAILABLE,
        "IDENTITY_UNAVAILABLE",
        "identity dependencies are unavailable",
    )
}

async fn login(State(state): State<AuthRouteState>, request: Request) -> Response {
    let Some(root) = request.extensions().get::<RequestRootExtension>().cloned() else {
        // Only the in-process Gateway dispatch creates a request scope.
        return unavailable();
    };
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_LOGIN_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "BODY_TOO_LARGE",
                "request body is too large",
            )
        }
    };
    let body: LoginBody = match serde_json::from_slice(&bytes) {
        Ok(body) => body,
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST_BODY",
                "expected identifier, password and userCardId",
            )
        }
    };
    let Some(now) = now_unix_seconds() else {
        return unavailable();
    };
    match state
        .session
        .login(
            &state.authenticator,
            &root,
            MemoryV1LoginRequest {
                identifier: &body.identifier,
                password: &body.password,
                user_card_id: body.user_card_id,
                now_unix_seconds: now,
                lifetime_seconds: state.session_lifetime_seconds,
            },
        )
        .await
    {
        Ok(issued) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(ApiResponse::success(LoginData {
                access_token: issued.credential().to_owned(),
                token_type: "Bearer",
                expires_in: state.session_lifetime_seconds,
            })),
        )
            .into_response(),
        Err(error) => login_failure(error),
    }
}

// memory—v1: Extract a non-empty bearer credential; any other scheme yields none.
fn bearer_credential(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|credential| !credential.is_empty())
}

async fn logout(State(state): State<AuthRouteState>, headers: HeaderMap) -> Response {
    let Some(credential) = bearer_credential(&headers) else {
        return failure(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "a bearer session credential is required",
        );
    };
    match state.session.revoke(credential) {
        Ok(()) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(ApiResponse::<EmptyResponse>::success(EmptyResponse)),
        )
            .into_response(),
        Err(
            MemoryV1SessionAuthorityError::InvalidCredential
            | MemoryV1SessionAuthorityError::Expired,
        ) => failure(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "the session credential is not valid",
        ),
        Err(_) => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use axum::body::{to_bytes, Body};
    use tower::ServiceExt;

    const USER: &str = "1a2b3c4d-1111-4111-8111-111111111111";

    fn hash() -> String {
        crate::auth::hash_password("correct-horse").unwrap()
    }

    fn document(hash: &str, extra: &str) -> String {
        format!(
            r#"{{"version":1,"credentials":[{{"identifier":"Alice","userId":"{USER}","passwordHash":"{hash}","status":"active","revision":1{extra}}}]}}"#
        )
    }

    #[test]
    fn credential_file_normalizes_identifiers_and_keeps_only_hashes() {
        let credentials = MemoryV1FileCredentials::from_json(&document(&hash(), "")).unwrap();
        assert_eq!(credentials.len(), 1);
        assert!(!credentials.is_empty());
        assert!(credentials.records.contains_key("alice"));
        let debug = format!("{credentials:?}");
        assert!(debug.contains("credentials: 1"));
        assert!(!debug.contains("argon2"));
        assert!(!debug.contains("alice"));
    }

    #[test]
    fn credential_file_rejects_every_malformed_shape() {
        let good = hash();
        let cases: Vec<(String, &str)> = vec![
            (document(&good, r#","extra":1"#), "unknown field"),
            (document("plaintext-password", ""), "not an argon2id hash"),
            (document("$argon2i$v=19$x", ""), "wrong argon2 variant"),
            (
                document(&format!("$argon2id${}", "x".repeat(600)), ""),
                "oversized hash",
            ),
            (
                document(&good, "").replace(r#""revision":1"#, r#""revision":0"#),
                "revision 0",
            ),
            (
                document(&good, "").replace("active", "enabled"),
                "unknown status",
            ),
            (
                document(&good, "").replace(USER, "not-a-uuid"),
                "bad user id",
            ),
            (
                document(&good, "").replace(USER, &USER.to_ascii_uppercase()),
                "non-canonical user id",
            ),
            (
                document(&good, "").replace("Alice", "  "),
                "empty identifier",
            ),
            (
                document(&good, "").replace("Alice", "al\u{0}ice"),
                "control byte",
            ),
            (
                document(&good, "").replace(r#""version":1"#, r#""version":2"#),
                "version 2",
            ),
            (r#"{"version":1,"credentials":[]}"#.to_owned(), "empty list"),
            ("not json".to_owned(), "not json"),
            (String::new(), "empty document"),
        ];
        for (text, name) in cases {
            assert!(
                MemoryV1FileCredentials::from_json(&text).is_err(),
                "{name} must be refused"
            );
        }
        // Identifiers differing only by case are the same credential.
        let entry = |identifier: &str| {
            format!(
                r#"{{"identifier":"{identifier}","userId":"{USER}","passwordHash":"{good}","status":"active","revision":1}}"#
            )
        };
        let duplicated = format!(
            r#"{{"version":1,"credentials":[{},{}]}}"#,
            entry("alice"),
            entry("ALICE")
        );
        assert!(matches!(
            MemoryV1FileCredentials::from_json(&duplicated),
            Err(MemoryV1CredentialFileError::DuplicateIdentifier(_))
        ));
    }

    #[test]
    fn credential_file_errors_never_echo_a_hash() {
        let secret = hash();
        // A misplaced hash in each field. Serde quotes typed values and unknown variants, and
        // the identifier, user id and revision errors must not quote it either.
        let misplaced = [
            document(&secret, "").replace(r#""revision":1"#, r#""revision":0"#),
            document(&secret, r#","extra":1"#),
            document(&secret, "")
                .replace(r#""status":"active""#, &format!(r#""status":"{secret}""#)),
            document(&secret, "").replace(r#""revision":1"#, &format!(r#""revision":"{secret}""#)),
            document(&secret, "").replace(USER, &secret),
            document("plaintext-password", "").replace("Alice", &secret),
        ];
        for text in misplaced {
            let error = MemoryV1FileCredentials::from_json(&text).unwrap_err();
            assert!(!error.to_string().contains(&secret), "{error}");
            assert!(!format!("{error:?}").contains(&secret), "{error:?}");
        }
    }

    fn temp_file(name: &str, contents: &str, mode: u32) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("astral-mv1-cred-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn credential_file_load_requires_a_private_regular_file() {
        let text = document(&hash(), "");
        let private = temp_file("credentials.json", &text, 0o600);
        #[cfg(unix)]
        {
            assert_eq!(MemoryV1FileCredentials::load(&private).unwrap().len(), 1);
            let open = temp_file("credentials.json", &text, 0o644);
            assert!(matches!(
                MemoryV1FileCredentials::load(&open),
                Err(MemoryV1CredentialFileError::InsecurePermissions)
            ));
            std::fs::remove_dir_all(open.parent().unwrap()).unwrap();
        }
        #[cfg(not(unix))]
        {
            assert!(matches!(
                MemoryV1FileCredentials::load(&private),
                Err(MemoryV1CredentialFileError::UnverifiablePermissions)
            ));
        }
        let directory = private.parent().unwrap().to_path_buf();
        assert!(matches!(
            MemoryV1FileCredentials::load(&directory),
            Err(MemoryV1CredentialFileError::NotRegularFile | MemoryV1CredentialFileError::Read(_))
        ));
        assert!(matches!(
            MemoryV1FileCredentials::load(&directory.join("missing.json")),
            Err(MemoryV1CredentialFileError::Read(_))
        ));
        let oversized = temp_file(
            "big.json",
            &" ".repeat(usize::try_from(MAX_CREDENTIAL_FILE_BYTES).unwrap() + 1),
            0o600,
        );
        assert!(matches!(
            MemoryV1FileCredentials::load(&oversized),
            Err(MemoryV1CredentialFileError::TooLarge)
        ));
        std::fs::remove_dir_all(directory).unwrap();
        std::fs::remove_dir_all(oversized.parent().unwrap()).unwrap();
    }

    #[test]
    fn bearer_credentials_are_extracted_only_from_the_bearer_scheme() {
        let headers = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            headers
        };
        assert_eq!(bearer_credential(&headers("Bearer m1.abc")), Some("m1.abc"));
        assert_eq!(
            bearer_credential(&headers("Bearer   m1.abc ")),
            Some("m1.abc")
        );
        assert_eq!(bearer_credential(&headers("Bearer ")), None);
        assert_eq!(bearer_credential(&headers("Basic dXNlcjpwdw==")), None);
        assert_eq!(bearer_credential(&headers("bearer m1.abc")), None);
        assert_eq!(bearer_credential(&HeaderMap::new()), None);
    }

    #[test]
    fn login_failures_map_to_distinct_statuses_without_internals() {
        for (error, status) in [
            (
                MemoryV1LoginError::InvalidIdentifier,
                StatusCode::BAD_REQUEST,
            ),
            (
                MemoryV1LoginError::InvalidCredentials,
                StatusCode::UNAUTHORIZED,
            ),
            (MemoryV1LoginError::CardNotOwned, StatusCode::FORBIDDEN),
            (
                MemoryV1LoginError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let response = login_failure(error);
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    fn router() -> Router {
        let authority = MemoryV1SessionAuthority::new();
        let session = Arc::new(MemoryV1IdentitySession::from_session_adapter(
            authority.identity_session_adapter(),
        ));
        let credentials =
            Arc::new(MemoryV1FileCredentials::from_json(&document(&hash(), "")).unwrap());
        memory_v1_auth_router(
            session,
            MemoryV1CredentialAuthenticator::new(credentials),
            60,
        )
    }

    async fn call(router: &Router, request: Request) -> (StatusCode, serde_json::Value) {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    fn post_json(path: &str, body: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn login_without_a_request_scope_is_unavailable_and_unrouted_paths_do_not_exist() {
        let router = router();
        let body =
            format!(r#"{{"identifier":"alice","password":"correct-horse","userCardId":"{USER}"}}"#);
        // Only the in-process Gateway dispatch injects a request root scope.
        let (status, body) = call(&router, post_json("/api/v1/auth/sessions", &body)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reasonCode"], "IDENTITY_UNAVAILABLE");
        assert_eq!(body["success"], false);

        // No legacy Identity route is mounted on this router.
        for (method, path) in [
            ("POST", "/api/v1/auth/register"),
            ("POST", "/api/v1/auth/sessions/refresh"),
            ("POST", "/api/v1/auth/sessions/switch-card"),
            ("GET", "/api/v1/auth/me"),
            ("GET", "/api/v1/auth/profile"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let (status, _) = call(&router, request).await;
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path} must not be served: {status}"
            );
        }
    }

    #[tokio::test]
    async fn logout_requires_a_known_bearer_session() {
        let router = router();
        let no_bearer = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/sessions/logout")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(&router, no_bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["reasonCode"], "INVALID_CREDENTIALS");

        for credential in ["m1.not-a-session", "not.a.jwt"] {
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/auth/sessions/logout")
                .header(header::AUTHORIZATION, format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap();
            let (status, _) = call(&router, request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{credential}");
        }
    }
}
