# astral-sdk-contracts

Platform-independent wire contracts and Ed25519 helpers for the AstralLight SDK. This crate has a self-contained Cargo manifest so it can be built while the platform team integrates the SDK.

The decision endpoint is `AUTHORIZATION_DECISIONS_PATH` (`/main/api/v1/integrations/authorization-decisions`). Contracts reject unknown fields and bound body/manifest sizes. Requests bind the authenticated Gateway session token ID, HTTP method/path, body digest, app/key IDs, manifest digest, nonce, external resource facts and operation IDs. Platform user/card/role identifiers are deliberately absent.

Use `SignedAuthorizationRequest::sign` and `verify_request` with keys selected from a trusted app/key registry. Decisions must be verified with `verify_decision` before use; it returns `VerifiedAuthorizationDecision`, not an unverified boolean. Only `DecisionOutcome::Allow` is an allow; `Deny` and `Pending` remain distinct non-allow outcomes.

`ApplicationManifest::permits_request` is the complete deny-by-default route check: method, path, resource, action and operation must match, and the named resolver parameter must equal `facts.target_id`. `permits` is only the route-shape helper and is insufficient on its own for admission. Resolver paths are `/{id}` or another single named parameter; both object and scoped-collection routes must bind a positive decimal i64 target. No identifier normalization is performed.
