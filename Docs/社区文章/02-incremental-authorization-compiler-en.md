# Incremental authorization compilation in Rust with `im::HashMap` and `Arc`

*Rebuilding only affected segments while keeping version and grant semantics intact.*

Imagine an authorization ledger with tens of thousands of grants. One mutation changes a single `(resource, action)` key. If every update clones the entire ledger, rebuilds every segment, and recomputes all derived data, the cost tracks total state size rather than the change.

The Rust compiler in this project attacks that problem at two levels: persistent maps share the unchanged parts of a version, and the compiler rebuilds only segments for keys touched by the delta. The optimization is constrained by explicit base-version, compiler-version, and dependency checks; it is not permission to skip validation.

## 1. Model compilation as a pure decision

The compiler takes an immutable `HotState` plus a `CompileRequest`. It does not read the database, publish a pointer, or perform durable writes. Its result is explicit:

```rust
pub enum CompileOutcome {
    Applied(CompiledProjection),
    FullRebuildRequired(FullRebuildRequired),
    Conflict(CompilerConflict),
}
```

The request carries the base version and semantic hash observed by the caller, a target version, a dependency vector, an optional expected dependency hash, and stable-ID grant deltas. A stale base is a conflict. A changed compiler version, changed dependencies, a wildcard impact, or an oversized delta batch may make incremental compilation unsafe, in which case the compiler reports `FullRebuildRequired` instead of pretending to have produced a candidate.

```rust
if let Some(conflict) = request_base_conflict(base, request) {
    return Ok(CompileOutcome::Conflict(conflict));
}

if base.compiler_version != self.compiler_version {
    let known_keys = known_affected_keys(base, &request.deltas)?;
    return Ok(full_rebuild_outcome(
        base,
        &request.deltas,
        known_keys,
        FullRebuildReason::CompilerVersionMismatch,
    ));
}
```

This separation is useful beyond authorization: the pure kernel decides what can be computed from this base, while an orchestrator decides whether and how to run the full path.

## 2. Keep versions cheap with persistent data structures

`HotState` is a versioned candidate, not a mutable singleton. It contains the tenant and version identity, the grant ledger, exact-key segments, semantic/dependency hashes, and compiler version. Its collection fields use `im::HashMap`, a persistent HAMT. Cloning the map shares its trie structure; an update copies the paths it changes rather than deep-copying every entry. Segment payloads are additionally held behind `Arc` so untouched segments can be shared between base and candidate.

The RULE_SET portion of the ledger is factored into layers:

- a shared content layer for rule-set entry data, keyed by content hash;
- a binding layer for card-to-rule-set relationships;
- a record layer retaining per-grant revision, state, and CAS identity;
- a private layer for grants that belong to one card, such as direct or delegated grants.

Why keep a per-grant record layer if there is already a binding map? Because the delta contract operates on individual `GrantId`s. Two entries bound to the same card can have different revisions and one can be revoked while the other remains active. Sharing duplicate content must not erase those identities or lifecycles.

## 3. Rebuild only affected keys

The candidate starts with a structurally shared segment map. For every affected key, the compiler takes that key's base contributions, filters grant IDs removed or moved by the current batch, adds the new active contributions, and rebuilds that segment alone:

```rust
let mut segments: im::HashMap<ProjectionKey, Arc<SegmentContent>> =
    base.segments.clone();

for key in affected_keys {
    let mut contributions: Vec<CanonicalGrant> = match base.segments.get(key) {
        Some(segment) => segment
            .grants
            .iter()
            .filter(|grant| !removed_ids.contains(&grant.grant_id))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    if let Some(added) = added_by_key.get(key) {
        contributions.extend(added.iter().cloned());
    }
    if contributions.is_empty() {
        segments.remove(key);
        continue;
    }
    let segment = build_single_segment(key, contributions, &compiler_version)?;
    segments.insert(key.clone(), segment);
}
```

This is the production candidate-building loop; the preceding code groups and validates the deltas. The complete algorithm must include both the old key and new key for an update that moves a grant, keep tombstones out of active segments, and sort any iteration that affects a durable digest. HAMT iteration order is not a serialization order.

## 4. Test sharing structurally, not with allocator folklore

For a one-grant Add, the tests assert that exactly one key/segment is affected, the candidate version advances, the active grant count increases by one, and the base remains unchanged. They also test physical reuse of an untouched segment:

```rust
let untouched_in_base = base
    .segment_content(&untouched_key)
    .expect("untouched key must exist in base");
let untouched_in_candidate = candidate
    .state
    .segment_content(&untouched_key)
    .expect("untouched key must survive the Add");
assert!(
    Arc::ptr_eq(&untouched_in_base, &untouched_in_candidate),
    "untouched segment must be physically reused"
);
```

That proves the candidate and base point to the same immutable segment; it does not depend on process-global allocator counters. Allocation counts and byte totals are useful observations, but warm-up, reuse, and parallel tests make them poor deterministic gates.

One fixture contains 4,050 active grants and 81 shared rule-set entries. That demonstrates content factoring for that input shape. It is not a promise that every workload gets the same ratio, nor a general memory or throughput benchmark.

## 5. The orchestrator owns the full-rebuild decision

When the compiler returns `FullRebuildRequired`, the projector explicitly invokes `full_rebuild` and records the reason in its candidate summary. If the full path still cannot produce an applied candidate, the event is handled as a failure. The pure compiler reports the boundary; the orchestrator performs the fallback.

This factored optimization changes the in-memory `HotState` representation and candidate construction. It does not make durable segments card-agnostic, nor does it remove per-card manifests, current pointers, or CAS generations. The persisted contract remains unchanged.

The general pattern is: use structural sharing to reduce unnecessary work, make the affected set explicit, return a typed “cannot do this incrementally” outcome, and test identity reuse directly. A persistent collection is useful here because it makes old and new versions coexist cheaply—not because it eliminates the need to prove which version a candidate came from.

*When you implement an incremental compiler or index, what do you use as the stable correctness signal: content hashes, pointer identity, an oracle rebuild, or all three?*
