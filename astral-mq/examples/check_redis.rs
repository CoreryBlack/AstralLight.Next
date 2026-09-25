use redis::AsyncCommands;
#[tokio::main]
async fn main() {
    let redis_url = match std::env::var("REDIS_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("REDIS_URL is required for this example");
            return;
        }
    };
    let client = redis::Client::open(redis_url).unwrap();
    let mut conn = client.get_connection_manager().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("jwt:jti:*")
        .query_async(&mut conn)
        .await
        .unwrap();
    println!("Found {} jti keys:", keys.len());
    for k in &keys {
        let ttl: i64 = conn.ttl(k).await.unwrap_or(-1);
        println!("  {} (TTL: {}s)", k, ttl);
    }
    // Also check if the exists command returns what we expect
    if !keys.is_empty() {
        let exists: bool = conn.exists::<String, bool>(keys[0].clone()).await.unwrap();
        println!("exists({}) = {}", keys[0], exists);
    }
}
