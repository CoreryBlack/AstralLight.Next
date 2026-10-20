# Preventing stale ALLOWs in a Rust authorization projector

*A practical look at generations, revoke fences, SQLx transactions, and compare-and-swap publication.*

Suppose a worker reads an authorization ledger and starts compiling a new projection. While it is compiling, another request revokes a grant. Could the older candidate still be published, and could a reader then return the revoked grant as `ALLOW`? The answer requires two separate checks: publication must not overwrite a pointer that has already advanced, and the read path must not trust evidence while a newer revoke is still pending.

A queue acknowledgment cannot answer that question. Neither can “the worker ran” or “the cache was refreshed.” The relevant question is whether the candidate still has a valid relationship to the durable state at the moment it becomes current.

This Rust implementation separates the work into four stages: append-only source facts, pure compilation outside a transaction, a short publication transaction guarded by versions and fences, and a strict read path that rechecks evidence before returning `ALLOW`.

## 1. Keep source mutation separate from projection work

The source-side transaction records the grant revision and its durable delta event. It does not perform the full projection build. After commit, a Tokio worker claims the event with a lease, reads the relevant ledger, verifies the claimed input, and compiles a candidate outside the publication transaction.

```text
source transaction:
  append grant revision + durable delta event

worker, outside the publish transaction:
  claim lease -> read ledger -> verify -> compile candidate

publish transaction:
  recheck lease + current pointer + generation + revoke fence
  stage manifest/segments -> CAS current pointer -> complete event
```

Moving compilation outside the transaction avoids holding database locks while doing potentially expensive work. It also means the publish step cannot assume that the world has stayed still since the candidate was built. It has to prove that assumption again.

Each claim uses a run-scoped lease token. The repository stores a hash of the token rather than treating the raw token as durable metadata, and its `Debug` output redacts the secret. After installing a claim, it reads back the server-generated expiration time and the incremented attempt count; the worker does not make ownership or retry decisions from a stale pre-claim snapshot.

## 2. Publish only if the observed base is still current

The publication transaction locks and verifies the claimed event lease, then locks the current pointer. It checks that the impact plan's base generation matches the generation observed under that lock. The previous revoke fence must come from the durable pointer itself; it is not reconstructed from caller-held history.

The transaction stages and validates the target manifest and its segment references. It then advances the current pointer with a compare-and-swap update. The update is pinned to the observed tenant/aggregate/card scope, generation, manifest ID, CAS version, and previous revoke fence. Exactly one row must change.

The important shape of the SQLx call is:

```rust
let cas_update = sqlx::query(POINTER_CAS_UPDATE_SQL)
    .bind(bind_u64(request.target_generation, "publish.current_generation")?)
    .bind(request.card_id)
    .bind(request.target_manifest_id)
    .bind(&target.event_id)
    .bind(&target.operation_id)
    .bind(target_semantic.as_bytes().to_vec())
    .bind(target_dependency.as_bytes().to_vec())
    .bind(&request.expected_target_compiler_version)
    .bind(bind_u64(request.fences.new_revoke_fence, "publish.cas_revoke_fence")?)
    .bind(previous.identity.tenant_id)
    .bind(&previous.identity.aggregate_type)
    .bind(previous.identity.aggregate_id)
    .bind(request.card_id)
    .bind(bind_u64(previous.current_generation, "publish.expected_current_generation")?)
    .bind(previous.manifest_id)
    .bind(previous.cas_version)
    .bind(bind_u64(previous.revoke_fence, "publish.expected_previous_revoke_fence")?)
    .execute(&mut **tx)
    .await?;

if cas_update.rows_affected() != 1 {
    return Err(AuthorizationProjectionError::CurrentPointerCasConflict(format!(
        "code=authorization_projection.pointer_cas_zero_rows;expected_manifest={};expected_generation={};expected_cas={}",
        previous.manifest_id, previous.current_generation, previous.cas_version
    )));
}
```

The SQL statement's `WHERE` clause carries the old pointer and fence expectations; its `SET` clause writes the candidate's generation, manifest, hashes, compiler version, and new fence. A zero-row result is a conflict, not an “already succeeded” shortcut. The caller rolls back the publication transaction and the worker classifies the outcome.

One important nuance: this CAS proves that the candidate is replacing the pointer version it observed. It does not, by itself, prove that no newer source mutation is waiting to be projected. Pending or unproven revoke deltas remain a source-freshness/readiness blocker; the strict reader must return pending/deny until the evidence is ready. The safety property is the combination of a fenced pointer update and a fail-closed read gate, not CAS alone.

The pointer move, impact-plan completion, and delta completion are committed in the same transaction. A parent manifest is marked superseded only after the pointer CAS succeeds; old evidence is retained rather than deleted to make the new state look consistent.

## 3. Make the production read path explicit in Rust

`PolicyEngine` depends on a repository trait, not SQLx. A capability method tells the engine whether this repository requires the published-evidence path:

```rust
#[async_trait::async_trait]
pub trait RuleRepository: Send + Sync {
    fn requires_published_card_evidence(&self) -> bool {
        false
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        Ok(None)
    }
}
```

The production SQLx repository overrides the capability to `true`. After authentication, card-context, and resource/action checks, the formal evaluation loads published evidence. Missing evidence, a read error, a non-Ready gate, a scope mismatch, or malformed evidence fails closed. The strict path does not fall back to legacy snapshots, raw source tables, or an unproven cache entry.

Even a matching grant is not enough by itself. Before returning `ALLOW`, the engine reloads the evidence and checks that the tenant/card, gate, manifest summaries, and matched grant still agree with the initial read. If that identity changed during evaluation, the result becomes `AUTHORIZATION_PENDING` rather than reusing the stale decision.

This re-read is not a global lock and cannot prevent a later mutation. It establishes a narrower guarantee: the engine does not return `ALLOW` when its final evidence check shows that the decision no longer matches the published state it evaluated.

## 4. A database commit error is not proof of rollback

The worker, SQL transaction, and message system do not provide distributed exactly-once execution. Internal consistency comes from stable event/operation IDs, lease ownership, CAS, generation and revoke fences, idempotent writes, and durable-state reconciliation.

If the client loses its connection while waiting for `COMMIT`, it may not know whether the database committed. The worker records an unknown outcome and does not blindly release, fail, or republish the event. Publication and event completion share a transaction, so a committed publication also commits the terminal event state. If the transaction did not commit, the database lease must expire before another worker can safely claim the event.

## 5. What this implementation does—and does not—claim

The canonical projection chain and production strict gate are wired in code. That is not the same thing as a completed production cutover. Existing-data backfill and rehearsal, cache/read-side migration, real MySQL integration acceptance, and deployment postconditions still require separate evidence.

The useful design lesson is modest but powerful: compile without holding source locks, then revalidate the candidate against durable generations and fences inside the publication transaction. On the read side, consume only published evidence and recheck it before returning `ALLOW`. When the system cannot prove freshness, return pending/deny instead of guessing.

*How do you handle a projection worker that loses its connection during `COMMIT`? Do you reconcile immediately, or let a fenced lease-expiry path take over?*
