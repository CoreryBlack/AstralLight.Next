# When a Rust Tokio worker times out, should it retry?

*Leases, SQLx transaction boundaries, bounded backoff, and the meaning of UNKNOWN.*

“Fetch a job, process it, retry on error” works until the job advances durable state. If a worker loses its database connection while waiting for `COMMIT`, it may not know whether the transaction committed. Retrying immediately can be unsafe; doing nothing forever is not acceptable either.

The authorization projector in this Rust codebase treats that as a state-machine problem. It distinguishes a proven publish, a retryable failure, a deterministic divergence, a concurrent pointer move that can be replanned, and an unknown outcome where the worker has no proof that another mutation is safe.

## 1. A claim is an expiring, token-fenced lease

The repository claims a delta event inside a SQL transaction. It installs an owner, an expiry based on database time, a CAS version, and a fresh run-scoped lease token. The database stores the token hash; the raw token stays with the worker and is redacted from `Debug` output.

After the install, the repository reads back the server-side expiry and post-install attempt count. The worker does not base ownership or retry-budget decisions on the candidate row's pre-claim counter.

```rust
let token = DeltaLeaseToken::new_run_scoped();
let install = sqlx::query(DELTA_CLAIM_INSTALL_SQL)
    .bind(lease_owner)
    .bind(token.token_hash().as_bytes().to_vec())
    .bind(lease_seconds)
    .bind(candidate.delta_event_id)
    .execute(&mut **tx)
    .await?;
if install.rows_affected() != 1 {
    return Err(GrantRepositoryError::ClaimRace);
}

let (expires_at, installed_attempts): (Option<PrimitiveDateTime>, i64) =
    sqlx::query_as(DELTA_CLAIM_READBACK_SQL)
        .bind(candidate.delta_event_id)
        .fetch_one(&mut **tx)
        .await?;
```

The actual repository also validates the expiry and maps the locked row into `DeltaEventClaim`. The key detail is that `attempts`, expiry, owner, and token all describe the installed lease, rather than a prior observation of the row.

## 2. Keep reads and compilation out of the publish transaction

One event follows roughly this pipeline:

1. Read back the claimed row to prove the lease is still live.
2. Observe the published frontier and parent references in a short read transaction.
3. Load the complete scope ledger.
4. Verify, partition, compile, and plan outside the publish transaction.
5. Open a publish transaction, renew the lease, recheck pointer/fence state, stage the manifest, and perform the CAS publication.

The pure planning/compile future does not hold database locks. If another publisher advances the pointer between planning and publish, the CAS detects `PointerMoved`. The worker retains its current claim lease and performs a bounded fresh-world replan. Only after that allowance is exhausted does it enter the ordinary retry budget.

This separates CPU work and observation from durable mutation. It also ensures that “my earlier read was correct” is not accepted as proof that the base pointer is still current.

## 3. `tokio::time::timeout` cancels a future; it does not prove rollback

The worker applies a deadline to processing one event:

```rust
let processing = tokio::time::timeout(
    config.event_deadline,
    process_one_event(
        &runtime,
        &config,
        &lease_owner,
        &cancellation,
        &claimed,
        &mut summary,
    ),
)
.await;

if processing.is_err() {
    summary.events_deadline_exceeded += 1;
    record_projector_event(ProjectorEventOutcome::DeadlineExceeded);
    // No lease mutation here: the publish outcome may be UNKNOWN.
}
```

When the deadline elapses, Tokio drops the future it was waiting on. If a SQLx transaction has not committed, dropping it rolls back the unfinished transaction. But if `COMMIT` reached the server and the response was lost, the caller cannot infer from the timeout that the commit failed. A timeout is evidence about local waiting, not a rollback proof.

That is why the timeout path does not release or fail the event. If publication committed, the pointer move and event completion were in the same transaction, so the row is no longer claimable. If it did not commit, the lease left by the rolled-back transaction must expire in the database before a new claim can take over. The worker must not bypass that fence because its local future timed out.

Shutdown follows the same idea. If cancellation arrives after a claim, the worker leaves the lease to expire rather than racing a release mutation against an operation whose durable outcome may be unknown.

## 4. Different failures need different state transitions

Not every error should go through `retry()`:

- **Transient I/O failure or a blocked prerequisite:** use the shared retry scheduler and a bounded backoff based on the durable attempt count. When the budget is exhausted, the row remains `PENDING` under the maximum backoff; it is not mislabeled as terminal.
- **Pointer moved:** keep the live lease and replan from the new committed pointer, but only within a bounded allowance.
- **Deterministic divergence:** make one live-lease-guarded CAS attempt to mark the event `QUARANTINED`. If that mutation itself has an unknown result, issue no follow-up fail/release/retry mutation.
- **Lease lost or publication commit unknown:** the worker no longer has proven authority to mutate the event. Record `UNKNOWN` and issue no follow-up mutation. A later claim may proceed only after the database lease is safely reclaimable; that claim path reads back durable state before processing again.

Retryable failures flow through one `fail_with_budget` mutation funnel. Quarantine and unknown outcomes deliberately stay outside it. This makes the number and type of durable state transitions auditable instead of scattering retry writes across error branches.

The worker also reports phase timings, attempt counts, deadline overruns, lease losses, unknown publication results, and unknown quarantine outcomes separately. “Failed” is not a useful operational category if the operator needs to know whether the event should back off, be repaired, or first be reconciled.

## 5. The key question is not “how many times can I retry?”

After a timeout or cancellation, ask:

- Which durable effects might already have happened?
- Who currently owns the lease?
- Can the worker prove the transaction committed or rolled back?
- Which one state transition is still safe?

If those questions have no proven answer, the safe state is `UNKNOWN`, not an eager retry. A Tokio worker becomes recoverable when the lease, transaction, attempt budget, and reconciliation path together define ownership—not when its loop simply runs again.

*How do you model “commit response lost” in your workers? Do you have an explicit UNKNOWN state, or does it get folded into a retry?*
