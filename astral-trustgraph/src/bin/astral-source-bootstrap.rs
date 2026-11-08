//! Explicit source-bootstrap operator entry point.
//!
//! This binary is intentionally disconnected from startup, business HTTP, and
//! the normal request admission path. It only orchestrates the signed ROOT
//! source-bootstrap contract through the already verified authority and DB
//! owners. It never writes the ticket or credential files.

#[path = "astral-source-bootstrap/operator.rs"]
mod operator;

#[tokio::main]
async fn main() {
    let code = operator::run(std::env::args().skip(1).collect()).await;
    std::process::exit(code);
}
