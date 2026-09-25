//! MySQL 查询示例：连接 platform_v4 数据库，查询 platform_user 和 user_local_credential 表。

use sqlx::mysql::MySqlPoolOptions;
use sqlx::Row;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required for this example")?;

    println!("=== MySQL 查询示例 ===");
    println!("连接数据库: platform_v4\n");

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;
    println!("✓ 数据库连接成功!\n");

    // ---- 1. 查询 platform_user ----
    println!("========== platform_user (LIMIT 10) ==========");
    let rows = sqlx::query(
        "SELECT user_id, display_name, user_no, status, created_at FROM platform_user LIMIT 10",
    )
    .fetch_all(&pool)
    .await?;

    if rows.is_empty() {
        println!("(无数据)");
    } else {
        for row in &rows {
            let user_id: i64 = row.get("user_id");
            let display_name: String = row.get("display_name");
            let user_no: String = row.get("user_no");
            let status: String = row.get("status");
            let created_at: Option<time::OffsetDateTime> = row.get("created_at");

            let created_at_str = match created_at {
                Some(dt) => {
                    let t = dt.unix_timestamp();
                    format!(
                        "{} (unix: {})",
                        dt.format(
                            &time::format_description::parse_borrowed::<1>(
                                "[year]-[month]-[day] [hour]:[minute]:[second]"
                            )
                            .unwrap()
                        )
                        .unwrap_or_else(|_| "N/A".to_string()),
                        t
                    )
                }
                None => "NULL".to_string(),
            };

            println!(
                "  user_id={}, display_name={}, user_no={}, status={}, created_at={}",
                user_id, display_name, user_no, status, created_at_str
            );
        }
    }
    println!();

    // ---- 2. 查询 user_local_credential ----
    println!("========== user_local_credential (LIMIT 10) ==========");
    let rows = sqlx::query(
        "SELECT credential_id, login_name, user_id, status FROM user_local_credential LIMIT 10",
    )
    .fetch_all(&pool)
    .await?;

    if rows.is_empty() {
        println!("(无数据)");
    } else {
        for row in &rows {
            let credential_id: i64 = row.get("credential_id");
            let login_name: String = row.get("login_name");
            let user_id: i64 = row.get("user_id");
            let status: String = row.get("status");

            println!(
                "  credential_id={}, login_name={}, user_id={}, status={}",
                credential_id, login_name, user_id, status
            );
        }
    }

    println!("\n✓ 查询完成!");
    pool.close().await;
    Ok(())
}
