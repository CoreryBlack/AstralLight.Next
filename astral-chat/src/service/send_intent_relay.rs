//! Bounded owner for the Chat durable send-intent relay.
//!
//! The relay republishes only the exact committed MQ envelope with its stable
//! message id. Publisher confirmation is recorded as PUBLISHED admission; it is
//! never delivery/read proof. Ambiguous publish/settlement outcomes are durably
//! fenced as IN_DOUBT and never replayed without explicit reconciliation.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use astral_mq::error::MqError;
use astral_mq::producer::{ChatMessagePayload, MqMessage, Producer};
use tokio::sync::watch;
use uuid::Uuid;

use crate::repository::message_repository::{MessageRepository, SendIntentClaim};
use crate::scope::ChatScope;
use crate::srv::realtime::ConnectionPool;

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const ERROR_POLL_INTERVAL: Duration = Duration::from_secs(2);
const PUBLISH_DEADLINE: Duration = Duration::from_secs(3);
const JOIN_DEADLINE: Duration = Duration::from_secs(5);
const REAP_DEADLINE: Duration = Duration::from_secs(1);

/// RAII owner for a single Chat send-intent relay loop.
#[must_use]
pub struct SendIntentRelayHandle {
    stop: watch::Sender<bool>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
    death: watch::Receiver<Option<String>>,
}

/// Owns the taken worker join handle across shutdown future cancellation.
struct RelayJoinGuard {
    stop: watch::Sender<bool>,
    join: Option<tokio::task::JoinHandle<()>>,
    complete: bool,
}

impl RelayJoinGuard {
    async fn join(&mut self) -> Result<(), String> {
        let join = self
            .join
            .as_mut()
            .ok_or_else(|| "Chat relay join handle already taken".to_owned())?;
        match tokio::time::timeout(JOIN_DEADLINE, &mut *join).await {
            Ok(Ok(())) => {
                self.complete = true;
                self.join.take();
                Ok(())
            }
            Ok(Err(error)) => {
                self.complete = true;
                self.join.take();
                Err(format!("Chat send-intent relay failed: {error}"))
            }
            Err(_) => {
                if let Some(join) = self.join.as_ref() {
                    join.abort();
                }
                if let Some(mut join) = self.join.take() {
                    let _ = tokio::time::timeout(REAP_DEADLINE, &mut join).await;
                }
                self.complete = true;
                Err("Chat relay stop timed out; active publish outcome unknown".into())
            }
        }
    }
}

impl Drop for RelayJoinGuard {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        let _ = self.stop.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let mut join = join;
                    let _ = tokio::time::timeout(REAP_DEADLINE, &mut join).await;
                });
            }
        }
    }
}

impl SendIntentRelayHandle {
    /// Request stop without consuming the process owner.
    pub fn request_stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Observe the terminal state of the owned worker.
    pub fn death_signal(&self) -> watch::Receiver<Option<String>> {
        self.death.clone()
    }

    /// Request cooperative stop and reap the worker under a bounded deadline.
    pub async fn shutdown_join(&self) -> Result<(), String> {
        let _ = self.stop.send(true);
        let join = self
            .join
            .lock()
            .map_err(|_| "Chat relay join lock poisoned".to_owned())?
            .take()
            .ok_or_else(|| "Chat relay join handle already taken".to_owned())?;
        RelayJoinGuard {
            stop: self.stop.clone(),
            join: Some(join),
            complete: false,
        }
        .join()
        .await
    }
}

impl Drop for SendIntentRelayHandle {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Ok(mut join) = self.join.lock() {
            if let Some(join) = join.take() {
                join.abort();
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let mut join = join;
                        let _ = tokio::time::timeout(REAP_DEADLINE, &mut join).await;
                    });
                }
            }
        }
    }
}

/// Start the required durable relay with a process-unique lease owner.
pub fn spawn_owned(
    repository: Arc<dyn MessageRepository>,
    producer: Arc<OnceLock<Producer>>,
    connections: Arc<ConnectionPool>,
) -> SendIntentRelayHandle {
    let owner = format!("chat-{}", Uuid::new_v4());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (death_tx, death_rx) = watch::channel(None);
    let join = tokio::spawn(run_relay(
        repository,
        producer,
        connections,
        owner,
        stop_rx,
        death_tx,
    ));
    SendIntentRelayHandle {
        stop: stop_tx,
        join: Mutex::new(Some(join)),
        death: death_rx,
    }
}

async fn run_relay(
    repository: Arc<dyn MessageRepository>,
    producer: Arc<OnceLock<Producer>>,
    connections: Arc<ConnectionPool>,
    owner: String,
    mut stop: watch::Receiver<bool>,
    death: watch::Sender<Option<String>>,
) {
    loop {
        if *stop.borrow() {
            let _ = death.send(Some("Chat send-intent relay stopped cooperatively".into()));
            return;
        }
        let claims = match tokio::time::timeout(
            Duration::from_secs(3),
            repository.claim_send_intents(&owner, 1),
        )
        .await
        {
            Ok(Ok(claims)) => claims,
            Ok(Err(error)) => {
                tracing::error!(worker_id = %owner, error = %error, "Chat send-intent claim failed");
                if stop_aware_sleep(&mut stop, ERROR_POLL_INTERVAL).await {
                    let _ = death.send(Some("Chat send-intent relay stopped cooperatively".into()));
                    return;
                }
                continue;
            }
            Err(_) => {
                tracing::error!(worker_id = %owner, "Chat send-intent claim deadline elapsed; lease state is unknown");
                if stop_aware_sleep(&mut stop, ERROR_POLL_INTERVAL).await {
                    let _ = death.send(Some("Chat send-intent relay stopped cooperatively".into()));
                    return;
                }
                continue;
            }
        };
        if claims.is_empty() {
            if stop_aware_sleep(&mut stop, POLL_INTERVAL).await {
                let _ = death.send(Some("Chat send-intent relay stopped cooperatively".into()));
                return;
            }
            continue;
        }

        for claim in claims {
            if *stop.borrow() {
                // An unstarted claim has no admission proof. Expiry fences it for
                // explicit reconciliation, never lease-only replay.
                let _ = death.send(Some("Chat send-intent relay stopped cooperatively".into()));
                return;
            }
            match tokio::time::timeout(
                Duration::from_secs(4),
                publish_committed(&claim, producer.get()),
            )
            .await
            .unwrap_or_else(|_| {
                Err(PublishFailure::UnknownOutcome(
                    "Chat relay publish deadline elapsed".into(),
                ))
            }) {
                Ok(()) => {
                    let settlement = tokio::time::timeout(
                        Duration::from_secs(3),
                        repository.complete_send_intent(&claim),
                    )
                    .await;
                    match settlement {
                        Ok(Ok(())) => {
                            if let Err(error) =
                                push_published_snapshot(&repository, &connections, &claim).await
                            {
                                tracing::warn!(intent_id = %claim.intent_id, error = %error, "Chat PUBLISHED intent has no realtime fan-out; durable MQ admission remains recorded");
                            }
                        }
                        Ok(Err(error)) => {
                            mark_unknown(&repository, &claim, &error.to_string()).await
                        }
                        Err(_) => {
                            mark_unknown(&repository, &claim, "PUBLISHED CAS deadline elapsed")
                                .await
                        }
                    }
                }
                Err(PublishFailure::KnownNotAdmitted(error)) => {
                    if let Err(settle_error) = tokio::time::timeout(
                        Duration::from_secs(3),
                        repository.retry_known_not_admitted(&claim, &error),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        Err(astral_types::AstralError::Database(
                            "known-not-admitted settlement deadline elapsed".into(),
                        ))
                    }) {
                        tracing::error!(intent_id = %claim.intent_id, error = %settle_error, "Chat known publish failure settlement is unknown; lease expiry will fence IN_DOUBT");
                    }
                }
                Err(PublishFailure::UnknownOutcome(error)) => {
                    mark_unknown(&repository, &claim, &error).await;
                }
            }
        }
    }
}

enum PublishFailure {
    KnownNotAdmitted(String),
    UnknownOutcome(String),
}

async fn publish_committed(
    claim: &SendIntentClaim,
    producer: Option<&Producer>,
) -> Result<(), PublishFailure> {
    let envelope: MqMessage<ChatMessagePayload> = serde_json::from_str(&claim.payload_json)
        .map_err(|error| {
            PublishFailure::UnknownOutcome(format!("invalid committed envelope: {error}"))
        })?;
    let canonical = serde_json::to_string(&envelope).map_err(|error| {
        PublishFailure::UnknownOutcome(format!("cannot canonicalize envelope: {error}"))
    })?;
    if canonical != claim.payload_json
        || envelope.message_id != claim.message_uuid
        || Uuid::parse_str(&claim.message_uuid).is_err()
        || envelope.payload.id != claim.message_id
        || envelope.payload.conversation_id != claim.conversation_id
        || envelope.payload.sender_id != claim.sender_id
    {
        return Err(PublishFailure::UnknownOutcome(
            "committed Chat envelope identity or canonical bytes mismatch".into(),
        ));
    }
    let producer = producer.ok_or_else(|| {
        PublishFailure::KnownNotAdmitted("Chat MQ producer unavailable before publish call".into())
    })?;
    match tokio::time::timeout(
        PUBLISH_DEADLINE,
        producer.publish_committed_chat_message(&envelope),
    )
    .await
    {
        Err(_) => Err(PublishFailure::UnknownOutcome(
            "Chat MQ publish deadline elapsed; final admission outcome unknown".into(),
        )),
        Ok(Ok(())) => Ok(()),
        // Lapin Channel/Connection errors and most producer errors can occur after
        // write/admission. Only protocol results proven to reject admission retry.
        Ok(Err(MqError::Publish(message))) if message.contains("publisher NACK") => {
            Err(PublishFailure::KnownNotAdmitted(message))
        }
        Ok(Err(error)) => Err(PublishFailure::UnknownOutcome(format!(
            "Chat MQ publish outcome unknown: {error}"
        ))),
    }
}

async fn mark_unknown(
    repository: &Arc<dyn MessageRepository>,
    claim: &SendIntentClaim,
    error: &str,
) {
    match tokio::time::timeout(
        Duration::from_secs(3),
        repository.mark_send_intent_in_doubt(claim, error),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(settle_error)) => {
            tracing::error!(intent_id = %claim.intent_id, error = %settle_error, "Chat IN_DOUBT CAS failed; expired lease transition still fences replay")
        }
        Err(_) => {
            tracing::error!(intent_id = %claim.intent_id, "Chat IN_DOUBT CAS deadline elapsed; expired lease transition still fences replay")
        }
    }
}

async fn push_published_snapshot(
    repository: &Arc<dyn MessageRepository>,
    connections: &Arc<ConnectionPool>,
    claim: &SendIntentClaim,
) -> Result<(), String> {
    let recipients = tokio::time::timeout(
        Duration::from_secs(3),
        repository.send_intent_recipients(claim),
    )
    .await
    .map_err(|_| "Chat recipient snapshot query deadline elapsed".to_owned())?
    .map_err(|error| format!("Chat recipient snapshot read failed: {error}"))?;
    if recipients.len()
        > crate::repository::message_repository::MAX_CHAT_MEMBERS_PER_CONVERSATION as usize
    {
        return Err("Chat recipient snapshot exceeds relay fan-out bound".into());
    }
    let envelope: MqMessage<ChatMessagePayload> = serde_json::from_str(&claim.payload_json)
        .map_err(|error| format!("committed Chat payload is not a valid envelope: {error}"))?;
    let scopes = recipient_scopes(claim, recipients)?;
    let push = serde_json::json!({
        "message_type": "NEW_MESSAGE", "conversation_id": claim.conversation_id,
        "sender_id": claim.sender_id, "message_id": claim.message_id,
        "message_uuid": claim.message_uuid, "client_msg_id": claim.client_msg_id,
        "content": envelope.payload.content, "timestamp": envelope.timestamp,
    })
    .to_string();
    let _ = connections.try_send_to_member_scopes(&scopes, &push).await;
    Ok(())
}

fn recipient_scopes(
    claim: &SendIntentClaim,
    recipients: Vec<crate::repository::message_repository::SendIntentRecipient>,
) -> Result<Vec<ChatScope>, String> {
    let sender_scope = ChatScope {
        user_id: claim.sender_id,
        identity_card_id: claim.identity_card_id,
        user_card_id: claim.user_card_id,
        user_card_tenant_id: claim.tenant_id,
        user_card_domain_id: claim.domain_id,
        principal_kind: astral_common::token_contract::PrincipalKind::PlatformUser,
        token_id: String::new(),
    };
    let mut scopes = Vec::with_capacity(recipients.len());
    let mut seen = std::collections::HashSet::with_capacity(recipients.len());
    for recipient in recipients {
        if recipient.tenant_id != claim.tenant_id
            || recipient.domain_id != claim.domain_id
            || recipient.recipient_id <= 0
            || recipient.identity_card_id <= 0
            || recipient.user_card_id <= 0
        {
            return Err("Chat recipient snapshot contains invalid physical scope".into());
        }
        let scope = sender_scope.for_recipient(
            recipient.recipient_id,
            recipient.identity_card_id,
            recipient.user_card_id,
        );
        if seen.insert(scope.key()) {
            scopes.push(scope);
        }
    }
    Ok(scopes)
}

async fn stop_aware_sleep(stop: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        changed = stop.changed() => changed.is_ok() && *stop.borrow(),
        _ = tokio::time::sleep(duration) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::message_repository::SendIntentRecipient;

    #[test]
    fn recipient_fanout_keeps_distinct_cards_for_the_same_user() {
        let claim = SendIntentClaim {
            intent_id: "intent-1".into(),
            message_uuid: "message-1".into(),
            message_id: 1,
            payload_json: String::new(),
            conversation_id: 9,
            sender_id: 1,
            identity_card_id: 10,
            user_card_id: 11,
            tenant_id: 20,
            domain_id: 30,
            client_msg_id: "client-1".into(),
            attempts: 1,
            lease_owner: "owner-1".into(),
            lease_generation: 1,
        };
        let first = SendIntentRecipient {
            recipient_id: 2,
            identity_card_id: 12,
            user_card_id: 13,
            tenant_id: 20,
            domain_id: 30,
        };
        let mut other_card = first.clone();
        other_card.user_card_id = 14;
        let scopes = recipient_scopes(&claim, vec![first.clone(), first.clone(), other_card])
            .expect("distinct physical scopes must be preserved");
        assert_eq!(scopes.len(), 2);
        assert_ne!(scopes[0].key(), scopes[1].key());
        let mut foreign = first;
        foreign.tenant_id = 21;
        assert!(recipient_scopes(&claim, vec![foreign]).is_err());
    }
}
