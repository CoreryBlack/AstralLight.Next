//! Single-node composition binary.
//!
//! memory—v1 is this branch's one production route: the binary runs the
//! memory-v1 composition service directly (cold load → adoption → serving).
//! There is no separate formal or experimental startup mode; every startup
//! gate the service enforces (credentials file, acknowledged limits,
//! loopback-only listener in this branch) applies to the one and only path.
//! The former legacy single-node assembly and its listener refusal were
//! removed together with the experimental/production startup split
//! (user decision, 2026-11-14).

mod memory_v1_composition;
mod memory_v1_service;

use astral_common::tracing::init_tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    memory_v1_service::run().await
}
