# Independent SDK Consumers

This nested workspace consumes only the public SDK crates and standard business libraries. It does not depend on platform database, PolicyEngine, shared middleware, MQ or internal entity crates. Existing `astral-chat` / `astral-learn` remain excluded and unchanged.

- `learn`: bounded course/scope store, parent revision, exact collection filtering, stable business-operation digest, and local commit receipts.
- `chat`: bounded membership/message store, per-target inbound/outbound proof, handshake separation, deduplication, backpressure, and local receipts.
- `test-support`: run-scoped loopback protocol runner with signature/request/nonce checks and injectable faults. It is a test fixture, not a platform authorization implementation.

From the repository root:

```sh
cargo test --manifest-path integrations/Cargo.toml --offline --locked
cargo clippy --manifest-path integrations/Cargo.toml --workspace --all-targets --offline --locked -- -D warnings
cargo fmt --manifest-path integrations/Cargo.toml --all -- --check
```

The transport suites include a real loopback HTTP SDK round trip, an Axum authorization layer with one-shot proof consumption, and a real loopback WebSocket handshake/frame/reconnect test. Runners close or abort on completion/drop and are timeout-bounded. HTTP opt-in is allowed only for loopback IP literals; normal deployments require HTTPS.

These samples use bounded in-memory state, not production SQL transactions. Local proof object consumption is not a distributed exactly-once guarantee. A production consumer must persist the stable operation ID, business payload digest and request/facts receipt in its own transaction/outbox, recheck facts/revision immediately before commit, and reconcile unknown results before retrying. Do not hold locks across authorization RPCs.

The tests do not prove real platform identity mapping, Gateway/JWT, MySQL, projection, MQ, crash recovery or production deployment. See [SDK V1](../Docs/SDK接入V1.md) and [implementation evidence](../Docs/SDK接入V1_实施证据.md). All project-owned code retains the repository's AGPL-3.0-or-later license; no crates were published.
