//! Axum middleware for manifest-bound SDK authorization.

use astral_sdk::{AccessToken, SdkClient};
use astral_sdk_contracts::{
    ApplicationManifest, AuthorizationRequest, ContractError, DecisionOutcome, ExternalSubject,
    ManifestRoute, ResourceFacts, ResourceOperation, ResourceResolver, SignedAuthorizationRequest,
    VerifiedAuthorizationDecision,
};
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDeclaration {
    pub method: String,
    pub path: String,
    pub resource_type: String,
    pub action: String,
    pub operation: ResourceOperation,
    pub resolver: ResourceResolver,
}

#[derive(Clone, Debug, Default)]
pub struct ManifestBuilder {
    app_id: String,
    revision: String,
    routes: Vec<RouteDeclaration>,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("invalid route declaration: {0}")]
    Contract(#[from] ContractError),
    #[error("special actions must be explicit")]
    MissingSpecialAction,
    #[error("duplicate route declaration")]
    DuplicateRoute,
    #[error("route declarations exceed the configured maximum")]
    TooManyRoutes,
    #[error("a registered route has no explicit authorization declaration")]
    UndeclaredRoute,
    #[error("route declarations do not match the approved application")]
    RouterMismatch,
    #[error("authorization proof has already been taken or is missing")]
    ProofMissing,
    #[error("trusted resource resolver is unavailable")]
    ResolverUnavailable,
    #[error("trusted actor resolver rejected the session")]
    ActorUnauthenticated,
}

impl ManifestBuilder {
    pub fn new(app_id: impl Into<String>, revision: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            revision: revision.into(),
            routes: Vec::new(),
        }
    }

    /// Ordinary actions may use only the explicit conventional mapping for
    /// GET/POST/PUT/PATCH/DELETE; other methods require a caller-supplied action.
    pub fn ordinary(
        &mut self,
        method: impl Into<String>,
        path: impl Into<String>,
        resource_type: impl Into<String>,
        action: Option<&str>,
        operation: ResourceOperation,
        resolver: ResourceResolver,
    ) -> Result<(), AdapterError> {
        let method = method.into();
        let action = action
            .map(str::to_owned)
            .or_else(|| match method.as_str() {
                "GET" => Some("read".into()),
                "POST" => Some("create".into()),
                "PUT" | "PATCH" => Some("update".into()),
                "DELETE" => Some("delete".into()),
                _ => None,
            })
            .ok_or(AdapterError::MissingSpecialAction)?;
        self.insert(RouteDeclaration {
            method,
            path: path.into(),
            resource_type: resource_type.into(),
            action,
            operation,
            resolver,
        })
    }

    /// Special actions such as publish/export/approve must be supplied explicitly.
    pub fn special(
        &mut self,
        method: impl Into<String>,
        path: impl Into<String>,
        resource_type: impl Into<String>,
        action: &str,
        operation: ResourceOperation,
        resolver: ResourceResolver,
    ) -> Result<(), AdapterError> {
        if action.is_empty() {
            return Err(AdapterError::MissingSpecialAction);
        }
        self.insert(RouteDeclaration {
            method: method.into(),
            path: path.into(),
            resource_type: resource_type.into(),
            action: action.into(),
            operation,
            resolver,
        })
    }

    fn insert(&mut self, route: RouteDeclaration) -> Result<(), AdapterError> {
        if self.routes.len() >= astral_sdk_contracts::MAX_MANIFEST_ROUTES {
            return Err(AdapterError::TooManyRoutes);
        }
        if self
            .routes
            .iter()
            .any(|existing| existing.method == route.method && existing.path == route.path)
        {
            return Err(AdapterError::DuplicateRoute);
        }
        self.routes.push(route);
        Ok(())
    }

    pub fn build(self) -> Result<ApplicationManifest, AdapterError> {
        if self.routes.is_empty() {
            return Err(AdapterError::UndeclaredRoute);
        }
        let manifest = ApplicationManifest {
            app_id: self.app_id,
            revision: self.revision,
            routes: self
                .routes
                .into_iter()
                .map(|route| ManifestRoute {
                    method: route.method,
                    path: route.path,
                    resource_type: route.resource_type,
                    action: route.action,
                    operation: route.operation,
                    resolver: route.resolver,
                })
                .collect(),
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Trusted local app registration. Its app/key/manifest are selected at
/// assembly/startup, never from request body or arbitrary IdP tokens.
pub struct ApplicationBinding {
    pub app_id: String,
    pub key_id: String,
    pub manifest: Arc<ApplicationManifest>,
    pub signing_key: ed25519_dalek::SigningKey,
}

/// Resolved only by the host application's trusted local authenticated session.
pub struct AuthenticatedActor {
    pub subject: ExternalSubject,
    pub session_token_id: String,
    pub gateway_access_token: AccessToken,
}

impl std::fmt::Debug for AuthenticatedActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedActor")
            .field("subject", &self.subject)
            .field("session_token_id", &self.session_token_id)
            .field("gateway_access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    Unauthenticated,
    Unavailable,
}

/// Trust boundary: derive actor identity from a pre-existing local session.
/// Implementations must not exchange arbitrary IdP tokens or use client-supplied
/// platform user/card/role IDs.
pub trait ActorResolver: Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        headers: &'a HeaderMap,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedActor, ResolveError>> + Send + 'a>>;
}

pub struct ResourceRequest {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: HeaderMap,
}

/// Resolve resource facts from trusted app-local state. Request metadata supplies
/// selectors, not authoritative tenant/domain/owner/revision facts.
pub trait ResourceFactsResolver: Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        route: &'a ManifestRoute,
        request: &'a ResourceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ResourceFacts, ResolveError>> + Send + 'a>>;
}

/// One-shot request proof attached to extensions. Handler-local code can inspect
/// scope/revision and must recheck it immediately before its own CAS/commit.
pub struct AuthorizedRequest {
    pub request: AuthorizationRequest,
    pub proof: VerifiedAuthorizationDecision,
}

impl AuthorizedRequest {
    pub fn require_allow_current(&self) -> Result<(), AdapterError> {
        self.proof.require_allow_current(&self.request)?;
        Ok(())
    }

    pub fn into_parts(self) -> (AuthorizationRequest, VerifiedAuthorizationDecision) {
        (self.request, self.proof)
    }
}

impl std::fmt::Debug for AuthorizedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedRequest")
            .field("request_id", &self.request.request_id)
            .field("scope", self.proof.scope())
            .field("outcome", self.proof.outcome())
            .finish()
    }
}

#[derive(Clone)]
pub struct ProofSlot(Arc<Mutex<Option<AuthorizedRequest>>>);

pub struct AuthorizedRequestExtension(pub ProofSlot);

impl<S> axum::extract::FromRequestParts<S> for AuthorizedRequestExtension
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ProofSlot>()
            .cloned()
            .map(Self)
            .ok_or((StatusCode::FORBIDDEN, "AUTHORIZATION_PROOF_REQUIRED"))
    }
}

impl AuthorizedRequestExtension {
    pub fn take(&self) -> Result<AuthorizedRequest, AdapterError> {
        self.0
             .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(AdapterError::ProofMissing)
    }
}

/// Take the handler proof once. The Arc extension is cloneable for Axum, but the
/// proof itself is non-Clone and can be consumed by only one request handler.
pub fn take_authorized_request(request: &Request) -> Result<AuthorizedRequest, AdapterError> {
    let slot = request
        .extensions()
        .get::<ProofSlot>()
        .ok_or(AdapterError::ProofMissing)?;
    slot.0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or(AdapterError::ProofMissing)
}

struct MiddlewareState<A, F> {
    client: Arc<SdkClient>,
    application: Arc<ApplicationBinding>,
    actor_resolver: Arc<A>,
    facts_resolver: Arc<F>,
    public_routes: Vec<(String, String)>,
}

impl<A, F> Clone for MiddlewareState<A, F> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            application: self.application.clone(),
            actor_resolver: self.actor_resolver.clone(),
            facts_resolver: self.facts_resolver.clone(),
            public_routes: self.public_routes.clone(),
        }
    }
}

pub struct AuthorizationLayer<A, F> {
    state: MiddlewareState<A, F>,
}

impl<A, F> AuthorizationLayer<A, F>
where
    A: ActorResolver,
    F: ResourceFactsResolver,
{
    pub fn new(
        client: Arc<SdkClient>,
        application: Arc<ApplicationBinding>,
        actor_resolver: Arc<A>,
        facts_resolver: Arc<F>,
    ) -> Result<Self, AdapterError> {
        application.manifest.validate()?;
        if application.app_id != application.manifest.app_id {
            return Err(AdapterError::RouterMismatch);
        }
        Ok(Self {
            state: MiddlewareState {
                client,
                application,
                actor_resolver,
                facts_resolver,
                public_routes: Vec::new(),
            },
        })
    }

    pub fn public_route(mut self, method: &str, path: &str) -> Result<Self, AdapterError> {
        if self.state.public_routes.len() >= 128
            || !matches!(method, "GET" | "HEAD" | "OPTIONS")
            || !path.starts_with('/')
            || path.len() > 2048
            || !path.is_ascii()
            || path
                .bytes()
                .any(|b| b <= b' ' || matches!(b, b'{' | b'}' | b'*' | b'%' | b'?' | b'#' | b'\\'))
            || path.contains("//")
            || path.split('/').any(|s| s == "." || s == "..")
            || self
                .state
                .public_routes
                .iter()
                .any(|r| r.0 == method && r.1 == path)
            || self
                .state
                .application
                .manifest
                .routes
                .iter()
                .any(|r| r.method == method && route_matches(&r.path, path))
        {
            return Err(AdapterError::RouterMismatch);
        }
        self.state.public_routes.push((method.into(), path.into()));
        Ok(self)
    }

    /// Apply once, after assembling all business routes. Routes installed later
    /// are outside this layer; hosts must not merge unprotected business routers.
    pub fn layer(&self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(
            self.state.clone(),
            authorize_middleware::<A, F>,
        ))
    }
}

async fn authorize_middleware<A, F>(
    axum::extract::State(state): axum::extract::State<MiddlewareState<A, F>>,
    mut request: Request,
    next: Next,
) -> Response
where
    A: ActorResolver,
    F: ResourceFactsResolver,
{
    let method = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_owned();
    if request.uri().query().is_some() {
        return (
            StatusCode::BAD_REQUEST,
            "QUERY_NOT_SUPPORTED_FOR_AUTHORIZED_ROUTE",
        )
            .into_response();
    }
    if state
        .public_routes
        .iter()
        .any(|r| r.0 == method && r.1 == request.uri().path())
    {
        return next.run(request).await;
    }
    let Some(route) =
        state.application.manifest.routes.iter().find(|route| {
            route.method == method && route_matches(&route.path, request.uri().path())
        })
    else {
        return (StatusCode::FORBIDDEN, "UNDECLARED_ROUTE").into_response();
    };
    let actor = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.actor_resolver.resolve(request.headers()),
    )
    .await
    {
        Ok(Ok(actor)) => actor,
        Ok(Err(ResolveError::Unauthenticated)) => {
            return (StatusCode::UNAUTHORIZED, "IDENTITY_REQUIRED").into_response();
        }
        Ok(Err(ResolveError::Unavailable)) | Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING").into_response();
        }
    };
    let metadata = ResourceRequest {
        method: request.method().clone(),
        uri: request.uri().clone(),
        headers: request.headers().clone(),
    };
    let facts = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.facts_resolver.resolve(route, &metadata),
    )
    .await
    {
        Ok(Ok(facts)) => facts,
        Ok(Err(ResolveError::Unauthenticated)) => {
            return (StatusCode::FORBIDDEN, "INVALID_RESOURCE_FACTS").into_response();
        }
        Ok(Err(ResolveError::Unavailable)) | Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING").into_response();
        }
    };
    if facts.validate().is_err()
        || facts.resource_type != route.resource_type
        || facts.operation != route.operation
    {
        return (StatusCode::FORBIDDEN, "INVALID_RESOURCE_FACTS").into_response();
    }
    let request_id = match header_identifier(request.headers(), "x-request-id") {
        Ok(Some(value)) => value,
        Ok(None) => format!("req-{}", uuid::Uuid::new_v4()),
        Err(()) => return (StatusCode::BAD_REQUEST, "INVALID_INTEGRATION_REQUEST").into_response(),
    };
    let operation_id = match header_identifier(request.headers(), "x-operation-id") {
        Ok(Some(value)) => value,
        Ok(None) if matches!(request.method().as_str(), "GET" | "HEAD" | "OPTIONS") => {
            format!("read-{}", uuid::Uuid::new_v4())
        }
        Ok(None) => return (StatusCode::BAD_REQUEST, "OPERATION_ID_REQUIRED").into_response(),
        Err(()) => return (StatusCode::BAD_REQUEST, "INVALID_INTEGRATION_REQUEST").into_response(),
    };
    let nonce = match random_nonce() {
        Ok(nonce) => nonce,
        Err(()) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING").into_response()
        }
    };
    let timestamp = match unix_millis() {
        Ok(timestamp) => timestamp,
        Err(()) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING").into_response()
        }
    };
    let unsigned = AuthorizationRequest {
        app_id: state.application.app_id.clone(),
        key_id: state.application.key_id.clone(),
        manifest_digest: match state.application.manifest.digest() {
            Ok(digest) => digest,
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING").into_response()
            }
        },
        revision: state.application.manifest.revision.clone(),
        request_id,
        nonce,
        timestamp,
        session_token_id: actor.session_token_id,
        subject: actor.subject,
        method,
        path,
        action: route.action.clone(),
        operation_id,
        facts,
    };
    if unsigned.validate().is_err() || !state.application.manifest.permits_request(&unsigned) {
        return (StatusCode::BAD_REQUEST, "INVALID_INTEGRATION_REQUEST").into_response();
    }
    let signed =
        match SignedAuthorizationRequest::sign(&state.application.signing_key, unsigned.clone()) {
            Ok(signed) => signed,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "INVALID_INTEGRATION_REQUEST").into_response()
            }
        };
    let proof = match state
        .client
        .authorize(&signed, &actor.gateway_access_token)
        .await
    {
        Ok(proof) => proof,
        Err(astral_sdk::SdkError::NotAllowed) => {
            return (StatusCode::FORBIDDEN, "PERMISSION_DENIED").into_response();
        }
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING").into_response()
        }
    };
    if !proof.matches_request(&unsigned) {
        return (StatusCode::FORBIDDEN, "PERMISSION_DENIED").into_response();
    }
    if let Err(error) = proof.require_allow_current(&unsigned) {
        let status = if matches!(error, ContractError::DecisionNotAllowed)
            && matches!(proof.outcome(), DecisionOutcome::Pending)
        {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        };
        return (status, "PERMISSION_DENIED").into_response();
    }
    request
        .extensions_mut()
        .insert(ProofSlot(Arc::new(Mutex::new(Some(AuthorizedRequest {
            request: unsigned,
            proof,
        })))));
    next.run(request).await
}

fn header_identifier(headers: &HeaderMap, name: &'static str) -> Result<Option<String>, ()> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    astral_sdk_contracts::identifier(value).map_err(|_| ())?;
    if value.len() > 64 {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn route_matches(template: &str, path: &str) -> bool {
    let template: Vec<_> = template.split('/').collect();
    let path: Vec<_> = path.split('/').collect();
    template.len() == path.len()
        && template.iter().zip(path.iter()).all(|(expected, actual)| {
            if expected.starts_with('{') && expected.ends_with('}') {
                !actual.is_empty()
            } else {
                expected == actual
            }
        })
}

fn random_nonce() -> Result<String, ()> {
    use base64::Engine as _;
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn unix_millis() -> Result<u64, ()> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis(),
    )
    .map_err(|_| ())
}
