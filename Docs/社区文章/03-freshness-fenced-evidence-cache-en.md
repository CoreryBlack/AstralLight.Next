# A freshness fence for Rust authorization caches: `ReadToken` plus a final check

*Why an authorization cache needs more than a short TTL.*

The dangerous cache race is not necessarily a long expiration. A reader can observe a valid-looking in-memory projection, another task can begin a source mutation or install a new publication, and the first reader can return its evidence after that change began.

This project has an optional in-process `MemoryProjectionHub`. It is not a second authorization engine and does not bypass `PolicyEngine`. It is a repository-side read optimization: the hub may assemble evidence from an installed immutable publication, but it must first prove the mirror is usable and then recheck a version token before returning. If the hub cannot serve safely, the request follows the configured strict-refill or inner-repository path.

## 1. Turn invalidation state into a comparable token

The hub builds a small scope-specific token from four revision/epoch values:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadToken {
    health: u64,
    source: u64,
    tenant: u64,
    card: u64,
}
```

`health` changes when the hub's health view changes. `source` tracks source-writer or source-state changes. The tenant and card epochs scope invalidation to the corresponding part of the mirror. `ReadToken::for_scope` captures these values while the hub state is read-locked.

The token does not replace durable evidence. It makes changes that happen during one in-process read detectable by comparing the initial token with a later one.

## 2. Check mirror eligibility before looking in the cache

`try_memory_evidence` first validates the request scope and checks mirror state under the hub's read lock. Warmup, an unavailable authority fence, active source writers, an uncertain source outcome, a blocking channel state, a pending invalidation, a missing card index, or an expired mirror state all return `DeferToDurable` before a cache result can be considered.

For an eligible scope, the hub snapshots the immutable published states, creates a `ReadToken`, and builds an `AssemblyStamp`. The cache key, `RefillScope`, includes tenant, card, optional user filter, and domain. The stamp also includes the read-time bucket and sorted publication identities: current pointer, manifest, generation, source/projected generation, revoke fence, and manifest digest.

So two requests for different scopes cannot reuse the same entry, and a publication/fence change invalidates an otherwise matching scope entry.

## 3. Recheck after assembling or hitting the cache

On a miss, the hub assembles evidence from the installed immutable states. On a hit, it reuses the cached `Arc<PublishedCardAuthorization>`. Both paths reach the same final check:

```rust
if token != ReadToken::for_scope(&maps, scope)
    || maps.warming_up
    || maps.authority_fence_unavailable()
    || maps.active_source_writers != 0
    || maps.uncertain_source
    || channel_blocks(&maps.channel, Instant::now())
{
    return MemoryEvidenceOutcome::DeferToDurable;
}
```

This is the essential freshness fence. If a source writer, invalidation, or health transition changed the token between the initial snapshot and this check, the in-memory result is not served. The repository can then try a configured strict refill or use its inner durable evidence reader.

This is not a transaction spanning memory and MySQL, and it cannot prevent a new mutation after the evidence has been returned. It provides a narrower guarantee: changes visible to the hub during this read prevent this read from serving its old in-memory snapshot.

## 4. The cache is bounded—and it uses a mutex

The current `AssemblyCache` uses a `Mutex<Entries>`. Inside it, a `HashMap` stores entries and a `BTreeMap` tracks least-recently-used order. A hit updates that order, so this is not a lock-free read path.

The limits are explicit: 1,024 entries, an estimated 32 MiB total retained size, at most 8 MiB for one entry, and a one-second cache TTL. Expired entries are periodically removed; insertion evicts the oldest entries until the count and byte budget fit. An oversized evidence object simply is not cached. The byte count is an estimate of retained heap data, not exact process RSS.

There is also a separate mirror TTL. Passing either TTL does not override the pending-invalidation, source-writer, channel, or token checks. TTL is one guardrail, not the proof that an authorization is current.

## 5. A miss is a performance outcome, not an authorization outcome

A poisoned cache mutex or a stamp mismatch becomes a cache miss. If the immutable mirror still passes the hub's eligibility checks, the evidence can be assembled again. If mirror state is unsuitable or assembly fails, the decorator defers to the configured strict refill or inner repository. A failed mirror refresh leaves pending state in place; it does not manufacture an empty Ready result.

The design goal is not “never hit the database.” It is “a cache hit cannot create authorization facts or bypass the durable published-evidence contract.” The cache avoids repeated assembly when the same evidence remains valid; the token, scope, pending gate, and durable fallback define what is safe to serve.

*For a permission cache, would you prefer version-token rechecks like this, database pointer double-reads, or a different freshness contract?*
