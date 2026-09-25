//! Full MQ test with declare_all after fix

use lapin::Connection;

#[tokio::main]
async fn main() {
    let url = match std::env::var("RABBITMQ_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("RABBITMQ_URL is required for this example");
            return;
        }
    };
    println!("=== Full MQ Test (with fixed declare_all) ===");

    let props = lapin::ConnectionProperties::default().enable_auto_recover();

    match Connection::connect(&url, props).await {
        Ok(conn) => {
            println!("1. Connection OK!");

            match conn.create_channel().await {
                Ok(ch) => {
                    println!("2. Channel {} created!", ch.id());
                    if let Err(error) = astral_mq::producer::Producer::enable_confirms(&ch).await {
                        println!("2. publisher confirms FAILED: {error}");
                    }

                    println!("3. Calling declare_all()...");
                    match astral_mq::config::declare_all(&ch).await {
                        Ok(_) => println!("4. declare_all() OK!"),
                        Err(e) => println!("4. declare_all() FAILED: {}", e),
                    }

                    println!("5. connected={}", conn.status().connected());

                    // Test publish
                    let producer = astral_mq::producer::Producer::new(ch.clone());
                    let payload = astral_mq::producer::LoginEventPayload {
                        message_id: None,
                        user_id: 12345,
                        card_id: Some(12345),
                        login_type: "PASSWORD".into(),
                        ip_address: None,
                        user_agent: None,
                        success: true,
                    };
                    match producer.publish_login_event(payload).await {
                        Ok(_) => println!("6. publish OK!"),
                        Err(e) => println!("6. publish FAILED: {}", e),
                    }

                    println!("7. connected={}", conn.status().connected());

                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    println!("8. After 3s, connected={}", conn.status().connected());
                }
                Err(e) => {
                    println!("Channel creation FAILED: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Connection FAILED: {}", e);
        }
    }
}
