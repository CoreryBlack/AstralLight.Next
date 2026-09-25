//! MQ 错误类型

use lapin::Error as LapinError;

#[derive(Debug, thiserror::Error)]
pub enum MqError {
    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Channel failed: {0}")]
    Channel(String),

    #[error("Publish failed: {0}")]
    Publish(String),

    #[error("Consume failed: {0}")]
    Consume(String),

    #[error("Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Idempotent check failed: {0}")]
    Idempotent(String),
}

impl From<LapinError> for MqError {
    fn from(e: LapinError) -> Self {
        MqError::Channel(e.to_string())
    }
}
