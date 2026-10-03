use astral_common::tracing::init_tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    astral_gateway::run().await
}
