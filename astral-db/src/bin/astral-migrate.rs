//! Explicit Rust-owned schema migration entry point.

use astral_db::{
    apply_migrations, freeze_projection_execution_mode_from_env, school_tenant_cutover_report,
};

const APPLY_FLAG: &str = "--apply";
const ISOLATED_ENV: &str = "isolated";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    require_explicit_apply()?;
    freeze_projection_execution_mode_from_env()?;

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required for the explicit migration job")?;
    let pool = apply_migrations(&database_url).await?;
    let report = school_tenant_cutover_report(&pool).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    pool.close().await;
    Ok(())
}

fn require_explicit_apply() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() != Some(APPLY_FLAG) {
        return Err("pass --apply to execute schema migrations".into());
    }
    if std::env::var("ASTRAL_MIGRATION_ENV").as_deref() != Ok(ISOLATED_ENV) {
        return Err("ASTRAL_MIGRATION_ENV=isolated is required for schema migrations".into());
    }
    Ok(())
}
