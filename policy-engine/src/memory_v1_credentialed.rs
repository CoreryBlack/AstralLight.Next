//! memory—v1: Opaque envelopes for the actual result and inputs of one call.
//!
//! These envelopes do not validate a later request, prevent replay, prove scope or
//! session freshness, trusted time, mutation watermarks, complete audit, durable
//! state, or justify a 403 response. The borrowed inputs are the values supplied
//! to the evaluator, not independently verified provenance. Consuming an envelope
//! yields the existing publicly constructible result, which loses this packaging.
//!
//! External code cannot construct an envelope from an arbitrary result, clone it,
//! or serialize it. For example:
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1EvaluationEnvelope;
//! use policy_engine::memory_v1_formal::MemoryV1Evaluation;
//! fn forge(result: MemoryV1Evaluation) -> MemoryV1EvaluationEnvelope<'static, 'static> {
//!     result.into()
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1EvaluationEnvelope;
//! fn duplicate(envelope: MemoryV1EvaluationEnvelope<'_, '_>) {
//!     let _ = envelope.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1EvaluationEnvelope;
//! fn serialize(envelope: &MemoryV1EvaluationEnvelope<'_, '_>) {
//!     let _ = serde_json::to_string(envelope);
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1EvaluationEnvelope;
//! fn forge() {
//!     let _ = MemoryV1EvaluationEnvelope { root: todo!(), session: todo!(),
//!         request: todo!(), intent: None, evaluation: todo!() };
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1CompoundEvaluationEnvelope;
//! fn forge() {
//!     let _ = MemoryV1CompoundEvaluationEnvelope { root: todo!(), session: todo!(),
//!         request: todo!(), evaluation: todo!() };
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1BatchEvaluationEnvelope;
//! fn forge() {
//!     let _ = MemoryV1BatchEvaluationEnvelope { root: todo!(), session: todo!(),
//!         request: todo!(), evaluation: todo!() };
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1CompoundEvaluationEnvelope;
//! fn duplicate(envelope: MemoryV1CompoundEvaluationEnvelope<'_, '_>) {
//!     let _ = envelope.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1BatchEvaluationEnvelope;
//! fn duplicate(envelope: MemoryV1BatchEvaluationEnvelope<'_, '_>) {
//!     let _ = envelope.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1CompoundEvaluationEnvelope;
//! fn serialize(envelope: &MemoryV1CompoundEvaluationEnvelope<'_, '_>) {
//!     let _ = serde_json::to_string(envelope);
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1BatchEvaluationEnvelope;
//! fn serialize(envelope: &MemoryV1BatchEvaluationEnvelope<'_, '_>) {
//!     let _ = serde_json::to_string(envelope);
//! }
//! ```
//!
//! ```compile_fail
//! use policy_engine::memory_v1_credentialed::MemoryV1EvaluationEnvelope;
//! fn use_after_consumption(envelope: MemoryV1EvaluationEnvelope<'_, '_>) {
//!     let _result = envelope.into_evaluation();
//!     let _ = envelope.evaluation();
//! }
//! ```

use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_session::RequestSessionExtension;

use crate::memory_v1_batch::{MemoryV1BatchEvaluation, MemoryV1BatchRequest};
use crate::memory_v1_compound::{MemoryV1CompoundEvaluation, MemoryV1CompoundRequest};
use crate::memory_v1_formal::{MemoryV1Evaluation, MemoryV1Request, MemoryV1RuleSetChangeIntent};
use crate::PolicyEngine;

/// One ordinary or rule-set evaluation and the exact inputs passed to that call.
///
/// `intent()` distinguishes rule-set change evaluation from an ordinary call.
/// Retaining or reusing this object does not establish a current request binding.
#[must_use]
pub struct MemoryV1EvaluationEnvelope<'call, 'data> {
    root: &'call RequestRootExtension,
    session: &'call RequestSessionExtension,
    request: &'call MemoryV1Request<'data>,
    intent: Option<MemoryV1RuleSetChangeIntent>,
    evaluation: MemoryV1Evaluation,
}

impl<'call, 'data> MemoryV1EvaluationEnvelope<'call, 'data> {
    /// memory—v1: Borrow the complete, unmodified result of this call.
    pub fn evaluation(&self) -> &MemoryV1Evaluation {
        &self.evaluation
    }

    /// memory—v1: Consume the envelope and return its complete result.
    pub fn into_evaluation(self) -> MemoryV1Evaluation {
        self.evaluation
    }

    /// memory—v1: Borrow the root extension supplied to this call.
    pub fn root(&self) -> &RequestRootExtension {
        self.root
    }

    /// memory—v1: Borrow the session extension supplied to this call.
    pub fn session(&self) -> &RequestSessionExtension {
        self.session
    }

    /// memory—v1: Borrow the request supplied to this call.
    pub fn request(&self) -> &MemoryV1Request<'data> {
        self.request
    }

    /// memory—v1: Return the supplied rule-set intent, or none for ordinary evaluation.
    pub fn intent(&self) -> Option<MemoryV1RuleSetChangeIntent> {
        self.intent
    }
}

/// One compound evaluation and its exact ordered call inputs.
#[must_use]
pub struct MemoryV1CompoundEvaluationEnvelope<'call, 'data> {
    root: &'call RequestRootExtension,
    session: &'call RequestSessionExtension,
    request: &'call MemoryV1CompoundRequest<'data>,
    evaluation: MemoryV1CompoundEvaluation,
}

impl<'call, 'data> MemoryV1CompoundEvaluationEnvelope<'call, 'data> {
    /// memory—v1: Borrow the complete, unmodified result of this call.
    pub fn evaluation(&self) -> &MemoryV1CompoundEvaluation {
        &self.evaluation
    }

    /// memory—v1: Consume the envelope and return its complete result.
    pub fn into_evaluation(self) -> MemoryV1CompoundEvaluation {
        self.evaluation
    }

    /// memory—v1: Borrow the root extension supplied to this call.
    pub fn root(&self) -> &RequestRootExtension {
        self.root
    }

    /// memory—v1: Borrow the session extension supplied to this call.
    pub fn session(&self) -> &RequestSessionExtension {
        self.session
    }

    /// memory—v1: Borrow the complete ordered request supplied to this call.
    pub fn request(&self) -> &MemoryV1CompoundRequest<'data> {
        self.request
    }
}

/// One batch evaluation and its exact ordered call inputs.
#[must_use]
pub struct MemoryV1BatchEvaluationEnvelope<'call, 'data> {
    root: &'call RequestRootExtension,
    session: &'call RequestSessionExtension,
    request: &'call MemoryV1BatchRequest<'data>,
    evaluation: MemoryV1BatchEvaluation,
}

impl<'call, 'data> MemoryV1BatchEvaluationEnvelope<'call, 'data> {
    /// memory—v1: Borrow the complete, unmodified result of this call.
    pub fn evaluation(&self) -> &MemoryV1BatchEvaluation {
        &self.evaluation
    }

    /// memory—v1: Consume the envelope and return its complete result.
    pub fn into_evaluation(self) -> MemoryV1BatchEvaluation {
        self.evaluation
    }

    /// memory—v1: Borrow the root extension supplied to this call.
    pub fn root(&self) -> &RequestRootExtension {
        self.root
    }

    /// memory—v1: Borrow the session extension supplied to this call.
    pub fn session(&self) -> &RequestSessionExtension {
        self.session
    }

    /// memory—v1: Borrow the complete ordered request supplied to this call.
    pub fn request(&self) -> &MemoryV1BatchRequest<'data> {
        self.request
    }
}

impl PolicyEngine {
    /// memory—v1: Evaluate once using the existing ordinary entry and wrap its result.
    pub fn evaluate_memory_v1_enveloped<'call, 'data>(
        &self,
        root: &'call RequestRootExtension,
        session: &'call RequestSessionExtension,
        request: &'call MemoryV1Request<'data>,
    ) -> MemoryV1EvaluationEnvelope<'call, 'data> {
        MemoryV1EvaluationEnvelope {
            root,
            session,
            request,
            intent: None,
            evaluation: self.evaluate_memory_v1(root, session, request),
        }
    }

    /// memory—v1: Evaluate once using the existing rule-set change entry.
    pub fn evaluate_memory_v1_rule_set_change_enveloped<'call, 'data>(
        &self,
        root: &'call RequestRootExtension,
        session: &'call RequestSessionExtension,
        request: &'call MemoryV1Request<'data>,
        intent: MemoryV1RuleSetChangeIntent,
    ) -> MemoryV1EvaluationEnvelope<'call, 'data> {
        MemoryV1EvaluationEnvelope {
            root,
            session,
            request,
            intent: Some(intent),
            evaluation: self.evaluate_memory_v1_rule_set_change(root, session, request, intent),
        }
    }

    /// memory—v1: Evaluate once using the existing compound entry.
    pub fn evaluate_memory_v1_compound_enveloped<'call, 'data>(
        &self,
        root: &'call RequestRootExtension,
        session: &'call RequestSessionExtension,
        request: &'call MemoryV1CompoundRequest<'data>,
    ) -> MemoryV1CompoundEvaluationEnvelope<'call, 'data> {
        MemoryV1CompoundEvaluationEnvelope {
            root,
            session,
            request,
            evaluation: self.evaluate_memory_v1_compound(root, session, request),
        }
    }

    /// memory—v1: Evaluate once using the existing confirmation batch entry.
    pub fn evaluate_memory_v1_confirmation_batch_enveloped<'call, 'data>(
        &self,
        root: &'call RequestRootExtension,
        session: &'call RequestSessionExtension,
        request: &'call MemoryV1BatchRequest<'data>,
    ) -> MemoryV1BatchEvaluationEnvelope<'call, 'data> {
        MemoryV1BatchEvaluationEnvelope {
            root,
            session,
            request,
            evaluation: self.evaluate_memory_v1_confirmation_batch(root, session, request),
        }
    }
}
