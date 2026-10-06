//! Per-frame chat admission with local membership/version checks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use astral_sdk_contracts::{
    ApplicationManifest, AuthorizationRequest, ExternalSubject, ManifestRoute, ResourceFacts,
    ResourceOperation, ResourceResolver, VerifiedAuthorizationDecision,
};
use sha2::{Digest, Sha256};

pub struct Conversation {
    pub id: i64,
    pub tenant: String,
    pub domain: String,
    pub revision: u64,
    pub members: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct MessageReceipt {
    pub operation_id: String,
    pub request_digest: String,
    pub facts_digest: String,
}

#[derive(Default)]
pub struct ChatStore {
    conversations: BTreeMap<i64, Conversation>,
    messages: BTreeMap<(String, String), ([u8; 32], MessageReceipt)>,
    delivery: VecDeque<(i64, String)>,
}

impl ChatStore {
    pub fn insert(&mut self, conversation: Conversation) -> Result<(), &'static str> {
        if conversation.id <= 0
            || conversation.revision == 0
            || conversation.members.len() > 256
            || self.conversations.len() >= 1024
            || self.conversations.contains_key(&conversation.id)
        {
            return Err("INVALID_CONVERSATION");
        }
        self.conversations.insert(conversation.id, conversation);
        Ok(())
    }

    pub fn receipt(&self, subject: &str, operation_id: &str) -> Option<&MessageReceipt> {
        self.messages
            .get(&(subject.into(), operation_id.into()))
            .map(|(_, receipt)| receipt)
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn facts(&self, id: i64) -> Result<ResourceFacts, &'static str> {
        self.resource_facts(id, "chat_message")
    }

    pub fn handshake_facts(&self, id: i64) -> Result<ResourceFacts, &'static str> {
        self.resource_facts(id, "chat_conversation")
    }

    fn resource_facts(&self, id: i64, resource: &str) -> Result<ResourceFacts, &'static str> {
        let conversation = self.conversations.get(&id).ok_or("NOT_FOUND")?;
        Ok(ResourceFacts {
            resource_type: resource.into(),
            target_id: id.to_string(),
            external_tenant_id: conversation.tenant.clone(),
            external_domain_id: conversation.domain.clone(),
            owner: None,
            revision: conversation.revision.to_string(),
            operation: ResourceOperation::Object,
        })
    }

    pub fn revoke_member(&mut self, id: i64, subject: &str) -> Result<(), &'static str> {
        let conversation = self.conversations.get_mut(&id).ok_or("NOT_FOUND")?;
        conversation.revision = conversation
            .revision
            .checked_add(1)
            .ok_or("REVISION_EXHAUSTED")?;
        conversation.members.remove(subject);
        Ok(())
    }

    pub fn handshake(
        &self,
        request: &AuthorizationRequest,
        proof: VerifiedAuthorizationDecision,
    ) -> Result<(), &'static str> {
        proof.require_allow_current(request).map_err(|_| "DENIED")?;
        let id = request
            .facts
            .target_id
            .parse::<i64>()
            .map_err(|_| "INVALID_TARGET")?;
        if request.action != "read"
            || request.method != "GET"
            || request.path != format!("/conversations/{id}/socket")
            || self.handshake_facts(id)? != request.facts
        {
            return Err("DENIED");
        }
        self.require_member(id, request)
    }

    fn require_member(&self, id: i64, request: &AuthorizationRequest) -> Result<(), &'static str> {
        let conversation = self.conversations.get(&id).ok_or("NOT_FOUND")?;
        if request.app_id != "astral-chat"
            || request.subject.issuer != "chat-local"
            || !conversation.members.contains(&request.subject.subject)
        {
            return Err("MEMBERSHIP_CHANGED");
        }
        Ok(())
    }

    /// Sender is the authenticated actor, never an untrusted message field.
    pub fn send(
        &mut self,
        request: &AuthorizationRequest,
        proof: VerifiedAuthorizationDecision,
        content: &str,
    ) -> Result<(), &'static str> {
        proof.require_allow_current(request).map_err(|_| "DENIED")?;
        let id = request
            .facts
            .target_id
            .parse::<i64>()
            .map_err(|_| "INVALID_TARGET")?;
        if request.action != "create"
            || request.method != "POST"
            || content.is_empty()
            || content.len() > 4096
            || request.path != format!("/conversations/{id}/messages")
            || request.facts.resource_type != "chat_message"
            || self.facts(id)? != request.facts
        {
            return Err("MEMBERSHIP_CHANGED");
        }
        self.require_member(id, request)?;
        let operation = (
            request.subject.subject.clone(),
            request.operation_id.clone(),
        );
        let payload = serde_json::to_vec(&(
            id,
            &request.facts.external_tenant_id,
            &request.facts.external_domain_id,
            content,
        ))
        .map_err(|_| "INVALID_MESSAGE")?;
        let digest: [u8; 32] = Sha256::digest(payload).into();
        if let Some(previous) = self.messages.get(&operation) {
            return if previous.0 == digest {
                Ok(())
            } else {
                Err("MESSAGE_CONFLICT")
            };
        }
        if self.messages.len() >= 4096 {
            return Err("CAPACITY");
        }
        if self.delivery.len() >= 64 {
            return Err("BACKPRESSURE");
        }
        let receipt = MessageReceipt {
            operation_id: request.operation_id.clone(),
            request_digest: request.digest().map_err(|_| "INVALID_MESSAGE")?,
            facts_digest: request.facts_digest().map_err(|_| "INVALID_MESSAGE")?,
        };
        self.messages.insert(operation, (digest, receipt));
        self.delivery.push_back((id, content.into()));
        Ok(())
    }

    pub fn receive(
        &self,
        request: &AuthorizationRequest,
        proof: VerifiedAuthorizationDecision,
    ) -> Result<Vec<String>, &'static str> {
        proof.require_allow_current(request).map_err(|_| "DENIED")?;
        let id = request
            .facts
            .target_id
            .parse::<i64>()
            .map_err(|_| "INVALID_TARGET")?;
        if request.action != "read"
            || request.method != "GET"
            || request.path != format!("/conversations/{id}/messages")
            || self.facts(id)? != request.facts
        {
            return Err("DENIED");
        }
        self.require_member(id, request)?;
        Ok(self
            .delivery
            .iter()
            .filter(|(target, _)| *target == id)
            .map(|(_, content)| content.clone())
            .collect())
    }

    /// A successful transport acknowledgment frees queue capacity; it does not
    /// remove the bounded idempotency record or grant recipient authorization.
    pub fn acknowledge_delivery(&mut self) {
        self.delivery.pop_front();
    }
}

pub fn manifest() -> ApplicationManifest {
    ApplicationManifest {
        app_id: "astral-chat".into(),
        revision: "1".into(),
        routes: vec![
            ManifestRoute {
                method: "GET".into(),
                path: "/conversations/{id}/socket".into(),
                resource_type: "chat_conversation".into(),
                action: "read".into(),
                operation: ResourceOperation::Object,
                resolver: ResourceResolver::Object {
                    target_id_path: "/{id}".into(),
                },
            },
            ManifestRoute {
                method: "POST".into(),
                path: "/conversations/{id}/messages".into(),
                resource_type: "chat_message".into(),
                action: "create".into(),
                operation: ResourceOperation::Object,
                resolver: ResourceResolver::Object {
                    target_id_path: "/{id}".into(),
                },
            },
            ManifestRoute {
                method: "GET".into(),
                path: "/conversations/{id}/messages".into(),
                resource_type: "chat_message".into(),
                action: "read".into(),
                operation: ResourceOperation::Object,
                resolver: ResourceResolver::Object {
                    target_id_path: "/{id}".into(),
                },
            },
        ],
    }
}

pub fn actor(subject: &str) -> ExternalSubject {
    ExternalSubject {
        issuer: "chat-local".into(),
        subject: subject.into(),
    }
}
