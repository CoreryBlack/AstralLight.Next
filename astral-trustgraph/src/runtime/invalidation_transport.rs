use std::sync::Arc;
use std::time::Duration;

use astral_common::config::AppConfig;
use astral_db::invalidation_delivery::InvalidationDeliveryContext;
use astral_mq::invalidation_delivery_transport::{
    start_invalidation_transport, InvalidationTransportStartSpec, OwnedInvalidationTransportHandles,
};
use lapin::Connection;

use crate::service::invalidation_runtime::{
    ConsumerDispatchInvalidationApply, InvalidationFanoutRuntime, RabbitMqRuntime,
};

/// TrustGraph owns network delivery for its node, including the composite host.
/// Identity shares the frozen producer context without starting another receiver.
pub(super) struct InvalidationTransportRuntime {
    fanout: Option<InvalidationFanoutRuntime>,
    transport: Option<OwnedInvalidationTransportHandles>,
    connection: Option<Arc<Connection>>,
}

impl InvalidationTransportRuntime {
    pub(super) fn new(fanout: Option<InvalidationFanoutRuntime>) -> Self {
        Self {
            fanout,
            transport: None,
            connection: None,
        }
    }

    pub(super) async fn start_delivery(
        &mut self,
        config: &AppConfig,
        delivery: &InvalidationDeliveryContext,
        pool: sqlx::MySqlPool,
        rabbit: Option<&RabbitMqRuntime>,
    ) -> Result<(), String> {
        if self.transport.is_some() || self.connection.is_some() {
            return Err("invalidation network owner is already started".into());
        }
        let connection = match rabbit {
            Some(runtime) => runtime.connection_handle(),
            None => {
                let connection = tokio::time::timeout(
                    Duration::from_secs(10),
                    Connection::connect(
                        &config.rabbitmq_url,
                        lapin::ConnectionProperties::default().enable_auto_recover(),
                    ),
                )
                .await
                .map_err(|_| "invalidation Rabbit connection timed out".to_owned())?
                .map_err(|_| "invalidation Rabbit connection failed".to_owned())?;
                let connection = Arc::new(connection);
                self.connection = Some(Arc::clone(&connection));
                connection
            }
        };
        self.transport = Some(
            start_invalidation_transport(InvalidationTransportStartSpec {
                config,
                delivery,
                pool,
                rabbit_connection: connection,
                owner: format!("invalidation-delivery-{}", uuid::Uuid::new_v4()),
                poll_interval: Duration::from_millis(250),
                apply: Arc::new(ConsumerDispatchInvalidationApply),
            })
            .await?,
        );
        Ok(())
    }

    pub(super) async fn wait_until_ready(&self, timeout: Duration) -> Result<(), String> {
        match self.transport.as_ref() {
            Some(transport) => transport.wait_until_ready(timeout).await,
            None => Err("invalidation network owner has not started".into()),
        }
    }

    pub(super) fn lifecycle(
        &self,
    ) -> Option<astral_mq::invalidation_delivery_transport::InvalidationTransportLifecycle> {
        self.transport
            .as_ref()
            .map(OwnedInvalidationTransportHandles::lifecycle)
    }

    pub(super) async fn shutdown_fanout(&mut self, timeout: Duration) -> Result<(), String> {
        match self.fanout.take() {
            Some(fanout) => fanout.shutdown(timeout).await,
            None => Ok(()),
        }
    }

    pub(super) async fn shutdown_transport(&mut self, timeout: Duration) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Some(transport) = self.transport.take() {
            if let Err(error) = transport.shutdown(timeout).await {
                failures.push(error);
            }
        }
        if let Err(error) = self.shutdown_fanout(timeout).await {
            failures.push(error);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    pub(super) async fn shutdown(mut self, timeout: Duration) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Err(error) = self.shutdown_transport(timeout).await {
            failures.push(error);
        }
        if let Some(connection) = self.connection.take() {
            if let Err(error) = close_connection(connection, timeout).await {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

async fn close_connection(connection: Arc<Connection>, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(
        timeout,
        connection.close(200, "invalidation delivery shutdown".into()),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err("invalidation Rabbit connection close failed".into()),
        Err(_) => Err("invalidation Rabbit connection close timed out; outcome unknown".into()),
    }
}

impl Drop for InvalidationTransportRuntime {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = close_connection(connection, Duration::from_secs(5)).await {
                    tracing::warn!(reason = %error, "invalidation connection cleanup is unproven");
                }
            });
        }
    }
}
