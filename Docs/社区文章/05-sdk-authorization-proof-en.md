# A Rust authorization proof should be a value, not a reusable boolean

*Ed25519 request binding, verified types, Axum middleware, and local commit checks.*

A remote service returning `ALLOW` does not mean an application has acquired a permission token that can be reused for any handler, resource, or time. The decision was made for particular request facts, a particular scope, a mapping revision, and a short validity window.

The Rust SDK in this project treats authorization as a signed proof bound to those inputs. Its contracts distinguish signed wire data from a verified decision, while an Axum adapter resolves trusted local facts and hands the proof to one request handler. The application still has to check its own resource state before committing a write.

## 1. Sign the protocol context as well as the body

An `AuthorizationRequest` carries the app/key identifiers, manifest digest and revision, request ID, nonce, timestamp, Gateway session token ID, external subject, business method/path/action, operation ID, and resource facts. Validation rejects unknown fields and bounds identifiers, nonce, timestamp skew, and payload size.

The request-signing helper validates the request and creates a domain-separated payload:

```rust
fn request_signing_bytes(
    request: &AuthorizationRequest,
) -> Result<Vec<u8>, ContractError> {
    request.validate()?;
    let body = serde_json::to_vec(request).map_err(serialize_error)?;
    let payload = RequestSignaturePayload {
        domain: REQUEST_SIGNATURE_DOMAIN,
        http_method: AUTHORIZATION_HTTP_METHOD,
        http_path: AUTHORIZATION_PATH,
        method: &request.method,
        path: &request.path,
        body_sha256: &digest_hex(&body),
        app_id: &request.app_id,
        key_id: &request.key_id,
        manifest_digest: &request.manifest_digest,
        nonce: &request.nonce,
        session_token_id: &request.session_token_id,
    };
    serde_json::to_vec(&payload).map_err(serialize_error)
}
```

`SignedAuthorizationRequest::sign` signs those bytes with Ed25519 and encodes the signature as unpadded base64url. The domain tag prevents accidental cross-protocol signature reuse; the business method/path, body digest, manifest, nonce, and Gateway session are all bound into the signature.

The verifier must select the public key from a trusted app/key registry. A key supplied by the request itself cannot establish that the request came from a trusted application.

## 2. Make “verified” a different Rust type

The signed decision response includes the request digest, facts digest, request ID, decision scope, mapping revision, outcome, and issue/expiry timestamps. The contract limits a decision to at most five seconds and allows at most thirty seconds of request timestamp clock skew.

After signature, key-ID, request/scope, and time checks, the SDK returns a `VerifiedAuthorizationDecision`. Its inner decision is private, the verified wrapper is not `Clone`, and its construction is kept inside the contracts crate. Consumers can inspect the verified scope and outcome, but cannot turn an arbitrary JSON response into a verified object through a public constructor.

Before use, the wrapper can recheck that the proof still matches the request and is both current and allowed:

```rust
pub fn require_allow_current(
    &self,
    request: &AuthorizationRequest,
) -> Result<(), ContractError> {
    self.validate_current(request)?;
    if !self.matches_request(request) || !self.is_allow() {
        return Err(ContractError::DecisionNotAllowed);
    }
    Ok(())
}
```

This is a type boundary that makes accidental misuse harder; it is not a formal proof that the whole application is secure. The caller still needs to supply trustworthy facts and enforce the result at the correct business boundary.

## 3. Resolve identity and resource facts inside the Axum service

`AuthorizationLayer` validates the application manifest at construction. A business route not declared in the manifest is rejected; public routes have to be explicitly allowlisted.

The adapter uses an `ActorResolver` to recover the actor from an existing local session and a `ResourceFactsResolver` to load facts from the service's own state. Request headers and path parameters can select a resource, but they are not trusted sources for tenant, owner, domain, membership, or revision. Resolver errors and timeouts fail closed rather than filling missing facts from client input.

For a write request, the adapter requires a stable `x-operation-id`. It constructs and signs the authorization request, calls the SDK, checks that the returned proof matches the request, and requires a current `ALLOW` before attaching it to the Axum request extensions.

## 4. Use `Mutex<Option<T>>` for one-shot consumption in one request

Axum request extensions can be observed through multiple extractors. The adapter places the non-`Clone` `AuthorizedRequest` in a shared optional slot:

```rust
#[derive(Clone)]
pub struct ProofSlot(Arc<Mutex<Option<AuthorizedRequest>>>);

pub fn take_authorized_request(
    request: &Request,
) -> Result<AuthorizedRequest, AdapterError> {
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
```

The `Arc` lets cloned extractor handles refer to the same slot. `Option::take()` transfers the proof once; a second consumer gets `ProofMissing`. The mutex here only protects this in-memory request-local handoff. It is not a database lock, a cross-request token store, or a distributed exactly-once mechanism.

## 5. Recheck facts at the local commit boundary

Resource ownership, course revision, or chat membership can change while the remote authorization call is in flight. A signature proves that the authorization service made a short-lived decision over a particular request. It does not promise that the resource will remain unchanged until a later database commit.

A production consumer should persist a stable operation ID, payload digest, and request/facts receipt with its own transaction or outbox. Immediately before its CAS/commit, it should re-read the relevant local revision and ownership facts. If the facts changed, reject the write; if a prior commit result is unknown, reconcile before retrying.

The repository's Learn/Chat integration examples exercise stale-fact rejection, operation/payload conflict detection, and per-frame WebSocket authorization. They use bounded in-memory stores, though, so they do not prove production SQL transaction behavior, crash recovery, real platform identity mapping, or cross-process exactly-once processing.

The design split is intentional: signatures and verified types bind the remote decision; middleware resolves trusted request facts and limits proof consumption; the business service owns durable idempotency and its final state check.

*If you expose a central authorization service through an SDK, where do you enforce the last freshness check: in middleware, in the repository transaction, or both?*
