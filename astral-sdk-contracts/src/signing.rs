use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::types::{
    invalid, validate_decision_shape, AuthorizationDecision, AuthorizationRequest, ContractError,
    SignedAuthorizationDecision, SignedAuthorizationRequest, VerifiedAuthorizationDecision,
};
use crate::validation::identifier;
use crate::{AUTHORIZATION_HTTP_METHOD, AUTHORIZATION_PATH};

const REQUEST_SIGNATURE_DOMAIN: &str = "astral-sdk-authorization-request-v1";
const DECISION_SIGNATURE_DOMAIN: &str = "astral-sdk-authorization-decision-v1";

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn serialize_error(error: serde_json::Error) -> ContractError {
    ContractError::Serialization(error.to_string())
}

pub(crate) fn request_digest(request: &AuthorizationRequest) -> Result<String, ContractError> {
    let body = serde_json::to_vec(request).map_err(serialize_error)?;
    Ok(digest_hex(&body))
}

pub(crate) fn request_facts_digest(
    request: &AuthorizationRequest,
) -> Result<String, ContractError> {
    let bytes = serde_json::to_vec(&request.facts).map_err(serialize_error)?;
    Ok(digest_hex(&bytes))
}

fn request_signing_bytes(request: &AuthorizationRequest) -> Result<Vec<u8>, ContractError> {
    request.validate()?;
    let body = serde_json::to_vec(request).map_err(serialize_error)?;
    let payload = RequestSignaturePayload {
        domain: REQUEST_SIGNATURE_DOMAIN,
        http_method: AUTHORIZATION_HTTP_METHOD,
        http_path: AUTHORIZATION_PATH,
        method: &request.method,
        path: &request.path,
        body_sha256: &digest_hex(&body),
        app_id: &request.app_id,
        key_id: &request.key_id,
        manifest_digest: &request.manifest_digest,
        nonce: &request.nonce,
        session_token_id: &request.session_token_id,
    };
    serde_json::to_vec(&payload).map_err(serialize_error)
}

#[derive(Serialize)]
struct RequestSignaturePayload<'a> {
    domain: &'static str,
    http_method: &'static str,
    http_path: &'static str,
    method: &'a str,
    path: &'a str,
    body_sha256: &'a str,
    app_id: &'a str,
    key_id: &'a str,
    manifest_digest: &'a str,
    nonce: &'a str,
    session_token_id: &'a str,
}

impl SignedAuthorizationRequest {
    pub fn sign(key: &SigningKey, request: AuthorizationRequest) -> Result<Self, ContractError> {
        request.validate()?;
        let signature = key.sign(&request_signing_bytes(&request)?);
        Ok(Self {
            request,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ContractError> {
        verify_request(key, &self.request, &self.signature)
    }
}

/// Verify with the public key already selected from the trusted app/key registry.
pub fn verify_request(
    key: &VerifyingKey,
    request: &AuthorizationRequest,
    signature: &str,
) -> Result<(), ContractError> {
    request.validate()?;
    let bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ContractError::InvalidSignature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| ContractError::InvalidSignature)?;
    key.verify_strict(&request_signing_bytes(request)?, &signature)
        .map_err(|_| ContractError::InvalidSignature)
}

impl SignedAuthorizationDecision {
    pub fn sign(
        key_id: impl Into<String>,
        key: &SigningKey,
        decision: AuthorizationDecision,
    ) -> Result<Self, ContractError> {
        let key_id = key_id.into();
        identifier(&key_id).map_err(|_| invalid("key_id", "invalid identifier"))?;
        validate_decision_shape(&decision)?;
        let signature = key.sign(&decision_signing_bytes(&key_id, &decision)?);
        Ok(Self {
            key_id,
            decision,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        expected_key_id: &str,
        request: &AuthorizationRequest,
        now_ms: u64,
    ) -> Result<VerifiedAuthorizationDecision, ContractError> {
        verify_decision(key, expected_key_id, request, self, now_ms)
    }
}

pub fn sign_decision(
    key_id: impl Into<String>,
    key: &SigningKey,
    decision: AuthorizationDecision,
) -> Result<SignedAuthorizationDecision, ContractError> {
    SignedAuthorizationDecision::sign(key_id, key, decision)
}

pub fn verify_decision(
    key: &VerifyingKey,
    expected_key_id: &str,
    request: &AuthorizationRequest,
    signed: &SignedAuthorizationDecision,
    now_ms: u64,
) -> Result<VerifiedAuthorizationDecision, ContractError> {
    if signed.key_id != expected_key_id {
        return Err(ContractError::KeyIdMismatch);
    }
    identifier(expected_key_id).map_err(|_| invalid("key_id", "invalid identifier"))?;
    signed.decision.validate_for(request, now_ms)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| ContractError::InvalidSignature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| ContractError::InvalidSignature)?;
    key.verify_strict(
        &decision_signing_bytes(&signed.key_id, &signed.decision)?,
        &signature,
    )
    .map_err(|_| ContractError::InvalidSignature)?;
    Ok(VerifiedAuthorizationDecision::new(signed.decision.clone()))
}

fn decision_signing_bytes(
    key_id: &str,
    decision: &AuthorizationDecision,
) -> Result<Vec<u8>, ContractError> {
    identifier(key_id).map_err(|_| invalid("key_id", "invalid identifier"))?;
    validate_decision_shape(decision)?;
    serde_json::to_vec(&DecisionSignaturePayload {
        domain: DECISION_SIGNATURE_DOMAIN,
        key_id,
        decision,
    })
    .map_err(serialize_error)
}

#[derive(Serialize)]
struct DecisionSignaturePayload<'a> {
    domain: &'static str,
    key_id: &'a str,
    decision: &'a AuthorizationDecision,
}
