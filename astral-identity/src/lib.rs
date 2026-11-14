#![allow(dead_code)]

pub mod memory_v1_service;
pub mod runtime;

pub use runtime::memory_v1::MemoryV1IdentitySession;
pub use runtime::{api, auth, middleware, srv};
pub use runtime::{
    build_router, build_router_with_memory_v1_session, run,
    run_with_config_and_listen_addr_and_shutdown,
    run_with_config_and_listen_addr_and_shutdown_and_drain, run_with_listen_addr,
    run_with_listen_addr_and_shutdown, run_with_listen_addr_and_shutdown_and_drain,
    run_with_memory_v1_session_and_config_and_listen_addr_and_shutdown,
    run_with_memory_v1_session_and_config_and_listen_addr_and_shutdown_and_drain, AppState,
};
