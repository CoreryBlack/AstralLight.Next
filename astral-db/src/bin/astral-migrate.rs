//! Explicit Rust-owned schema migration entry point.

use astral_db::{apply_migrations, connect_configured_pool, school_tenant_cutover_report};

const APPLY_FLAG: &str = "--apply";
const ISOLATED_ENV: &str = "isolated";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    require_explicit_apply()?;

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required for the explicit migration job")?;
    ensure_isolated_database(&database_url).await?;

    let pool = apply_migrations(&database_url).await?;
    let report = school_tenant_cutover_report(&pool).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
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

async fn ensure_isolated_database(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect_configured_pool(database_url).await?;
    let database: Option<String> = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&pool)
        .await?;
    pool.close().await;

    let database = database.ok_or("DATABASE_URL must select a database")?;
    if !is_isolated_database_name(&database) {
        return Err(format!(
            "refusing migration for database {database:?}; use an astral_* test or rehearsal database"
        )
        .into());
    }
    Ok(())
}

fn is_isolated_database_name(database: &str) -> bool {
    let database = database.to_ascii_lowercase();
    database.starts_with("astral_") && (database.contains("test") || database.contains("rehearsal"))
}

#[cfg(test)]
mod tests {
    use super::is_isolated_database_name;

    #[test]
    fn only_allows_isolated_astral_database_names() {
        assert!(is_isolated_database_name("astral_test"));
        assert!(is_isolated_database_name("astral_tenant_rehearsal"));
        assert!(!is_isolated_database_name("platform_v4"));
        assert!(!is_isolated_database_name("astral_production"));
    }
}
