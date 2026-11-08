//! Global authorization authority control plane.
//!
//! This crate is the production service plus client library for the external
//! authority quorum described by `astral_types::authority_protocol`. It has no
//! database dependency by design: source-side owners integrate through the
//! client library and the protocol types only.
//!
//! Layout:
//! - [`signing`]: the protected signing owner (`ProtectedAuthoritySigner`).
//!   It is not `Clone`, exposes no key access, zeroizes on drop, and refuses
//!   to sign unless the instance is the quorum leader. It is never placed in
//!   generic shared request state.
//! - [`store`]: the durable store contract with an etcd implementation
//!   (linearizable reads + atomic Txn Compare CAS) and an in-memory
//!   implementation used by store-contract tests.
//! - [`service`]: the authority business logic: fence reads that never
//!   advance the frontier, intent acceptance/reservation, source commit
//!   records, publication certification with verify-before-sign, and
//!   reconciliation. All unknown outcomes are surfaced, never retried.
//! - [`http`]: the authenticated bounded internal HTTP listener. TLS with
//!   client-certificate authentication is mandatory; the listener refuses to
//!   start without it.
//! - [`client`]: the internal client library. It contains no signing
//!   capability whatsoever; it verifies the startup attestation against the
//!   pinned trust root before first use.
//! - [`runtime`]: startup assembly and the root-owned `genesis`/`rotate-key`
//!   tooling entry points.

pub mod client;
pub mod error;

// 服务端模块仅在 `service` 特性下编译：业务进程（astral-db）只依赖客户端库，
// 绝不编译存储、签名者或监听代码。
#[cfg(feature = "service")]
pub mod bootstrap;
#[cfg(feature = "service")]
pub mod config;
#[cfg(feature = "service")]
pub mod http;
#[cfg(feature = "service")]
pub mod runtime;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "service")]
pub mod signing;
#[cfg(feature = "service")]
pub mod store;

pub use client::AuthorityClient;
pub use error::AuthorityClientError;

#[cfg(feature = "service")]
pub use config::AuthorityServiceConfig;
#[cfg(feature = "service")]
pub use error::{AuthorityServiceError, AuthorityStoreError};
#[cfg(feature = "service")]
pub use service::bootstrap::{
    AuthorityBootstrapOutcome, StoredBootstrapOperation, StoredBootstrapReceipt,
};
#[cfg(feature = "service")]
pub use service::AuthorityService;
#[cfg(feature = "service")]
pub use signing::ProtectedAuthoritySigner;
#[cfg(feature = "service")]
pub use store::memory::MemoryAuthorityStore;
#[cfg(feature = "service")]
pub use store::AuthorityStore;
