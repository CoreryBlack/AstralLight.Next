//! memory—v1: Independent expected rows for the 23-fact MySQL paper fixture.

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, IdentityCardRow,
    RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow, TableCounts,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
use sha2::{Digest, Sha256};

pub(super) const COUNTS: TableCounts = TableCounts {
    users: 2,
    identity_cards: 2,
    tenants: 1,
    user_cards: 4,
    rule_sets: 2,
    rule_set_versions: 2,
    bindings: 4,
    binding_confirmations: 4,
    rule_set_change_confirmations: 2,
};

// Kept independent of the SQL seed, the loader and the production encoder.
fn expected_version(id: u8, content: &[u8]) -> RuleSetVersionRow {
    let mut encoded = b"astrallight/memory-v1/rule-set-version/1\0".to_vec();
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.push(1);
    encoded.extend_from_slice(&(content.len() as u64).to_be_bytes());
    encoded.extend_from_slice(content);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.push(1);
    RuleSetVersionRow {
        rule_set_id: [id; 16],
        version_bytes: vec![1],
        content_bytes: content.to_vec(),
        timestamp_bytes: vec![1],
        hash_bytes: Sha256::digest(&encoded).to_vec(),
        hash_input_bytes: encoded,
    }
}

pub(super) fn expected_rows() -> CandidateRows {
    let card = |card, user| UserCardRow {
        user_card_id: [card; 16],
        user_id: [user; 16],
        tenant_id: [0x13; 16],
        status: UserCardStatus::Active,
    };
    let binding = |id, card, rule_set, layer| BindingRow {
        binding_id: [id; 16],
        user_card_id: [card; 16],
        rule_set_id: [rule_set; 16],
        binding_layer: layer,
        valid_from: None,
        valid_until: None,
        owner_scope: MemoryV1OwnerScope::SelfUser,
        tenant_scope: MemoryV1TenantScope::SelfTenant,
        removed_at: None,
        removed_by: None,
    };
    let confirmation = |id, binding_id, rule_set| BindingConfirmationRow {
        confirmation_id: [id; 16],
        binding_id: [binding_id; 16],
        rule_set_id: [rule_set; 16],
        version_bytes: vec![1],
        confirmer_user_id: [0x11; 16],
        scope_bytes: vec![1],
        operation_id: vec![1],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    };
    let change = |id, rule_set| RuleSetChangeConfirmationRow {
        confirmation_id: [id; 16],
        rule_set_id: [rule_set; 16],
        version_bytes: vec![1],
        confirmer_user_id: [0x21; 16],
        affected_scope_bytes: vec![1],
        operation_id: vec![1],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    };
    CandidateRows {
        users: vec![UserRow { user_id: [0x11; 16] }, UserRow { user_id: [0x21; 16] }],
        identity_cards: vec![
            IdentityCardRow { identity_card_id: [0x12; 16], user_id: [0x11; 16] },
            IdentityCardRow { identity_card_id: [0x22; 16], user_id: [0x21; 16] },
        ],
        tenants: vec![TenantRow { tenant_id: [0x13; 16], parent_tenant_id: None }],
        user_cards: vec![card(0x31, 0x11), card(0x32, 0x11), card(0x33, 0x11), card(0x34, 0x21)],
        rule_sets: [0x41, 0x42].map(|id| RuleSetRow {
            rule_set_id: [id; 16],
            owner_tenant_id: [0x13; 16],
            current_version_bytes: vec![1],
            status: RuleSetStatus::Active,
        }).into(),
        rule_set_versions: vec![
            expected_version(0x41, concat!(
                r#"{"rules":[{"ruleId":"R5","resource":"permission_rule","action":"read","effect":"ALLOW"},"#,
                r#"{"ruleId":"G1","resource":"user_card","action":"create","effect":"ALLOW"},"#,
                r#"{"ruleId":"G2","resource":"binding","action":"remove","effect":"ALLOW"}]}"#,
            ).as_bytes()),
            expected_version(0x42, br#"{"rules":[{"ruleId":"R6","resource":"permission_rule","action":"read","effect":"DENY"}]}"#),
        ],
        bindings: vec![
            binding(0x51, 0x31, 0x41, BindingLayer::Base),
            binding(0x52, 0x32, 0x41, BindingLayer::Base),
            binding(0x53, 0x32, 0x42, BindingLayer::Overlay),
            binding(0x54, 0x34, 0x41, BindingLayer::Base),
        ],
        binding_confirmations: vec![
            confirmation(0x61, 0x51, 0x41), confirmation(0x62, 0x52, 0x41),
            confirmation(0x63, 0x53, 0x42), confirmation(0x64, 0x54, 0x41),
        ],
        rule_set_change_confirmations: vec![change(0x90, 0x41), change(0x91, 0x42)],
    }
}
