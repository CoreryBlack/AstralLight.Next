use super::*;

fn image(
    table: AuthorityConfigSourceTable,
    key: i64,
    lookup: &AuthorityConfigSourceLookup,
    operation: AuthorityConfigSourceOperation,
    before: &str,
    after: &str,
) -> AuthorityConfigSourceImage {
    AuthorityConfigSourceImage {
        table,
        key,
        lookup: serde_json::to_string(lookup).unwrap(),
        operation,
        before_image_digest: super::super::authority_sha256_hex(before.as_bytes()),
        after_image_digest: super::super::authority_sha256_hex(after.as_bytes()),
        before_image: before.to_owned(),
        after_image: after.to_owned(),
    }
}

fn group(id: i64, name: &str) -> String {
    serde_json::to_string(&AdminGroupImage {
        id,
        name: Some(name.into()),
        description: None,
        scope: None,
        created_at: None,
    })
    .unwrap()
}

fn absent(table: AuthorityConfigSourceTable, lookup: &AuthorityConfigSourceLookup) -> String {
    #[derive(Serialize)]
    struct Marker {
        table: &'static str,
        lookup: String,
        presence: &'static str,
    }
    serde_json::to_string(&Marker {
        table: table.as_str(),
        lookup: serde_json::to_string(lookup).unwrap(),
        presence: "ABSENT",
    })
    .unwrap()
}

fn evidence(images: Vec<AuthorityConfigSourceImage>) -> AuthorityConfigCompletionEvidence {
    AuthorityConfigCompletionEvidence {
        kind: AuthorityConfigCompletionKind::ConfigCompletion,
        gate_contract: AuthorityConfigGateContract::DurableConfigV7,
        source_batch: AuthorityConfigSourceBatch {
            delta: None,
            source_images: images,
            audits: vec![AuthorityConfigAudit {
                audit_log_id: 2,
                user_id: 3,
                action: "UPDATE".into(),
                resource: "admin-group".into(),
                decision: "ALLOW".into(),
                event_type: "CONFIG_MUTATION".into(),
                request_id: Some("op-1".into()),
            }],
            source_projection: vec![],
            invalidations: vec![],
        },
    }
}

fn update_group(id: i64, before: &str, after: &str) -> AuthorityConfigSourceImage {
    image(
        AuthorityConfigSourceTable::AdminGroup,
        id,
        &AuthorityConfigSourceLookup::PrimaryId { id },
        AuthorityConfigSourceOperation::Update,
        &group(id, before),
        &group(id, after),
    )
}

#[test]
fn config_completion_rejects_non_config_or_unbound_evidence() {
    let valid = evidence(vec![update_group(1, "before", "after")]);
    valid.validate("op-1").unwrap();
    let mut projection = valid.clone();
    projection
        .source_batch
        .source_projection
        .push(serde_json::json!({"id": 1}));
    assert!(projection.validate("op-1").is_err());
    let mut delta = valid.clone();
    delta.source_batch.delta = Some(serde_json::json!({"invented": true}));
    assert!(delta.validate("op-1").is_err());
    let mut invalidation = valid.clone();
    invalidation
        .source_batch
        .invalidations
        .push(serde_json::json!({"id": 1}));
    assert!(invalidation.validate("op-1").is_err());
    let mut audit = valid.clone();
    audit.source_batch.audits[0].request_id = Some("other-op".into());
    assert!(audit.validate("op-1").is_err());
    let mut fake = valid.clone();
    fake.source_batch.source_images[0].after_image_digest = "00".repeat(32);
    assert!(fake.validate("op-1").is_err());
    let mut wrong_key = valid.clone();
    wrong_key.source_batch.source_images[0].key = 9;
    assert!(wrong_key.validate("op-1").is_err());
    let mut negative_audit = valid;
    negative_audit.source_batch.audits[0].audit_log_id = -2;
    assert!(negative_audit.validate("op-1").is_err());
    let wrong_insert = AuthorityConfigSourceLookup::AdminGroupInsertIntent {
        id: 12,
        name: "g".into(),
        description: None,
        scope: None,
    };
    wrong_insert
        .validate_for_table(AuthorityConfigSourceTable::AdminGroup)
        .unwrap();
    assert!(wrong_insert
        .validate_for_table(AuthorityConfigSourceTable::ResourceType)
        .is_err());
}

#[test]
fn delete_validates_the_before_row_and_the_exact_after_absence() {
    let table = AuthorityConfigSourceTable::AdminGroup;
    let lookup = AuthorityConfigSourceLookup::PrimaryId { id: 7 };
    let before = group(7, "deleted group");
    let after = absent(table, &lookup);
    let deletion = image(
        table,
        7,
        &lookup,
        AuthorityConfigSourceOperation::Delete,
        &before,
        &after,
    );
    evidence(vec![deletion.clone()]).validate("op-1").unwrap();

    for malformed_before in [
        r#"{"id":7,"invented":"field"}"#,
        r#"{"id":7,"name":7,"description":null,"scope":null,"created_at":null}"#,
    ] {
        let mut malformed = deletion.clone();
        malformed.before_image = malformed_before.into();
        malformed.before_image_digest =
            super::super::authority_sha256_hex(malformed_before.as_bytes());
        assert!(evidence(vec![malformed]).validate("op-1").is_err());
    }
    let mut wrong_owner = deletion.clone();
    wrong_owner.before_image = group(8, "another group");
    wrong_owner.before_image_digest =
        super::super::authority_sha256_hex(wrong_owner.before_image.as_bytes());
    assert!(evidence(vec![wrong_owner]).validate("op-1").is_err());

    let mut after_present = deletion;
    after_present.after_image = group(7, "still present");
    after_present.after_image_digest =
        super::super::authority_sha256_hex(after_present.after_image.as_bytes());
    assert!(evidence(vec![after_present]).validate("op-1").is_err());
}

#[test]
fn absent_markers_bind_lookup_table_side_and_canonical_bytes() {
    let table = AuthorityConfigSourceTable::AdminGroup;
    let lookup = AuthorityConfigSourceLookup::AdminGroupInsertIntent {
        id: 7,
        name: "actual insert".into(),
        description: None,
        scope: None,
    };
    let marker = absent(table, &lookup);
    let insertion = image(
        table,
        7,
        &lookup,
        AuthorityConfigSourceOperation::Insert,
        &marker,
        &group(7, "actual insert"),
    );
    evidence(vec![insertion.clone()]).validate("op-1").unwrap();

    let other_lookup = AuthorityConfigSourceLookup::PrimaryId { id: 8 };
    for wrong_marker in [
        absent(table, &other_lookup),
        absent(AuthorityConfigSourceTable::ResourceType, &lookup),
        format!(" {marker}"),
        marker.replacen("{", "{\"extra\":true,", 1),
    ] {
        let mut wrong = insertion.clone();
        wrong.before_image = wrong_marker;
        wrong.before_image_digest =
            super::super::authority_sha256_hex(wrong.before_image.as_bytes());
        assert!(evidence(vec![wrong]).validate("op-1").is_err());
    }
    let mut wrong_after = insertion.clone();
    wrong_after.after_image = marker;
    wrong_after.after_image_digest =
        super::super::authority_sha256_hex(wrong_after.after_image.as_bytes());
    assert!(evidence(vec![wrong_after]).validate("op-1").is_err());

    let mut wrong_intent = insertion;
    wrong_intent.after_image = group(7, "different insert payload");
    wrong_intent.after_image_digest =
        super::super::authority_sha256_hex(wrong_intent.after_image.as_bytes());
    assert!(evidence(vec![wrong_intent]).validate("op-1").is_err());
}

#[test]
fn every_row_in_a_batch_is_validated_even_when_another_row_changed() {
    let changed = update_group(1, "before", "after");
    let unchanged = update_group(2, "same", "same");
    evidence(vec![changed.clone(), unchanged.clone()])
        .validate("op-1")
        .unwrap();
    assert!(
        evidence(vec![update_group(1, "same", "same"), unchanged.clone()])
            .validate("op-1")
            .is_err()
    );
    assert!(evidence(vec![unchanged.clone(), changed.clone()])
        .validate("op-1")
        .is_err());
    assert!(evidence(vec![changed.clone(), changed.clone()])
        .validate("op-1")
        .is_err());

    let mut malformed = unchanged;
    malformed.before_image = r#"{"id":2}"#.into();
    malformed.before_image_digest =
        super::super::authority_sha256_hex(malformed.before_image.as_bytes());
    assert!(evidence(vec![changed, malformed]).validate("op-1").is_err());
}

fn level_template() -> IdentityLevelTemplateImage {
    IdentityLevelTemplateImage {
        template_id: 9,
        template_code: "level-1".into(),
        template_name: "First level".into(),
        domain_id: 4,
        principal_type: "USER".into(),
        grant_type: "MANUAL".into(),
        level_no: 1,
        user_card_template_id: Some(8),
        status: "ACTIVE".into(),
        version_no: 1,
        force_cover: false,
        description: None,
        created_at: None,
        updated_at: None,
        resource_maps: vec![
            LevelTemplateResourceMapImage {
                id: 11,
                template_id: 9,
                resource_type_id: 31,
                priority: 0,
                created_at: None,
                updated_at: None,
            },
            LevelTemplateResourceMapImage {
                id: 12,
                template_id: 9,
                resource_type_id: 32,
                priority: 1,
                created_at: None,
                updated_at: None,
            },
        ],
        action_maps: vec![LevelTemplateActionMapImage {
            id: 21,
            template_id: 9,
            action_id: 41,
            effect: "ALLOW".into(),
            created_at: None,
            updated_at: None,
        }],
    }
}

#[test]
fn level_template_images_bind_all_child_owners_and_ordering() {
    let before = serde_json::to_string(&level_template()).unwrap();
    let mut after = level_template();
    after.template_name = "Changed level".into();
    let after = serde_json::to_string(&after).unwrap();
    let receipt = image(
        AuthorityConfigSourceTable::IdentityLevelTemplate,
        9,
        &AuthorityConfigSourceLookup::PrimaryId { id: 9 },
        AuthorityConfigSourceOperation::Update,
        &before,
        &after,
    );
    evidence(vec![receipt.clone()]).validate("op-1").unwrap();

    let mut foreign_resource = level_template();
    foreign_resource.resource_maps[0].template_id = 10;
    let mut foreign_action = level_template();
    foreign_action.action_maps[0].template_id = 10;
    let mut reversed = level_template();
    reversed.resource_maps.reverse();
    let mut duplicated = level_template();
    duplicated.resource_maps[1].id = 11;
    for invalid_before in [foreign_resource, foreign_action, reversed, duplicated] {
        let mut invalid = receipt.clone();
        invalid.before_image = serde_json::to_string(&invalid_before).unwrap();
        invalid.before_image_digest =
            super::super::authority_sha256_hex(invalid.before_image.as_bytes());
        assert!(evidence(vec![invalid]).validate("op-1").is_err());
    }
}

fn rule_set() -> RuleSetAggregateImage {
    RuleSetAggregateImage {
        root: RuleSetRootImage {
            rule_set_id: 7,
            name: "rules".into(),
            code: "rules-7".into(),
            description: None,
            source_type: "TEMPLATE".into(),
            source_id: Some(8),
            enabled: 1,
            created_at: None,
            updated_at: None,
            tenant_id: Some(3),
        },
        entries: vec![RuleSetEntryImage {
            entry_id: 9,
            rule_set_id: 7,
            resource_type: "monitor".into(),
            resource_id: None,
            action_code: "read".into(),
            effect: "ALLOW".into(),
            condition_json: None,
            priority: 1,
            enabled: 1,
            valid_from: None,
            valid_to: None,
            created_at: None,
            updated_at: None,
            tenant_id: Some(3),
        }],
        bindings: vec![RuleSetBindingImage {
            id: 11,
            card_id: 13,
            rule_set_id: 7,
            ref_type: "TEMPLATE".into(),
            created_at: None,
            tenant_id: Some(3),
        }],
    }
}

#[test]
fn rule_set_images_reject_foreign_entries_bindings_and_nonunique_lookup() {
    let before = serde_json::to_string(&rule_set()).unwrap();
    let mut after = rule_set();
    after.root.name = "changed".into();
    let receipt = image(
        AuthorityConfigSourceTable::RuleSet,
        7,
        &AuthorityConfigSourceLookup::RuleSetCode {
            code: "rules-7".into(),
        },
        AuthorityConfigSourceOperation::Update,
        &before,
        &serde_json::to_string(&after).unwrap(),
    );
    evidence(vec![receipt.clone()]).validate("op-1").unwrap();
    let mut foreign_entry = rule_set();
    foreign_entry.entries[0].rule_set_id = 8;
    let mut foreign_binding = rule_set();
    foreign_binding.bindings[0].rule_set_id = 8;
    for invalid_before in [foreign_entry, foreign_binding] {
        let mut invalid = receipt.clone();
        invalid.before_image = serde_json::to_string(&invalid_before).unwrap();
        invalid.before_image_digest =
            super::super::authority_sha256_hex(invalid.before_image.as_bytes());
        assert!(evidence(vec![invalid]).validate("op-1").is_err());
    }
    let mut ambiguous = receipt;
    ambiguous.lookup =
        r#"{"kind":"rule_set_source","tenantId":3,"sourceType":"TEMPLATE","sourceId":8}"#.into();
    assert!(evidence(vec![ambiguous]).validate("op-1").is_err());
}

fn permission_template() -> PermissionRuleTemplateAggregateImage {
    PermissionRuleTemplateAggregateImage {
        template_root: UserCardTemplateRootImage {
            template_id: 8,
            domain_id: 4,
            tenant_id: Some(3),
            parent_template_id: None,
            template_code: "template-8".into(),
            template_name: "Card template".into(),
            card_type: "USER".into(),
            template_scope: "TENANT".into(),
            version_no: 1,
            default_priority: 0,
            default_roles_json: None,
            resource_scope_json: None,
            status: "ACTIVE".into(),
            created_at: None,
            updated_at: None,
        },
        permission_rules: vec![PermissionRuleTemplateRowImage {
            template_rule_id: 19,
            template_id: 8,
            effect: "ALLOW".into(),
            resource_type: Some("monitor".into()),
            resource_id: None,
            action_code: Some("read".into()),
            condition_json: None,
            priority: 1,
            enabled: 1,
            created_at: None,
            updated_at: None,
        }],
        linked_rule_set: rule_set(),
    }
}

#[test]
fn deleting_the_last_template_rule_keeps_the_template_aggregate_identity() {
    let before = permission_template();
    let mut after = permission_template();
    after.permission_rules.clear();
    after.linked_rule_set.entries.clear();
    let receipt = image(
        AuthorityConfigSourceTable::PermissionRuleTemplate,
        8,
        &AuthorityConfigSourceLookup::PermissionRuleTemplateAggregate { template_id: 8 },
        AuthorityConfigSourceOperation::Update,
        &serde_json::to_string(&before).unwrap(),
        &serde_json::to_string(&after).unwrap(),
    );
    evidence(vec![receipt.clone()]).validate("op-1").unwrap();

    let mut wrong_child = permission_template();
    wrong_child.permission_rules[0].template_id = 9;
    let mut wrong_source = permission_template();
    wrong_source.linked_rule_set.root.source_id = Some(9);
    let mut wrong_kind = permission_template();
    wrong_kind.linked_rule_set.root.source_type = "MANUAL".into();
    let mut wrong_tenant = permission_template();
    wrong_tenant.linked_rule_set.root.tenant_id = Some(4);
    for invalid_before in [wrong_child, wrong_source, wrong_kind, wrong_tenant] {
        let mut invalid = receipt.clone();
        invalid.before_image = serde_json::to_string(&invalid_before).unwrap();
        invalid.before_image_digest =
            super::super::authority_sha256_hex(invalid.before_image.as_bytes());
        assert!(evidence(vec![invalid]).validate("op-1").is_err());
    }
    let mut rule_key = receipt.clone();
    rule_key.key = 19;
    rule_key.lookup = serde_json::to_string(
        &AuthorityConfigSourceLookup::PermissionRuleTemplateAggregate { template_id: 19 },
    )
    .unwrap();
    assert!(evidence(vec![rule_key]).validate("op-1").is_err());
    let mut root_disappeared = receipt;
    root_disappeared.after_image = absent(
        AuthorityConfigSourceTable::PermissionRuleTemplate,
        &AuthorityConfigSourceLookup::PermissionRuleTemplateAggregate { template_id: 8 },
    );
    root_disappeared.after_image_digest =
        super::super::authority_sha256_hex(root_disappeared.after_image.as_bytes());
    assert!(evidence(vec![root_disappeared]).validate("op-1").is_err());
}

#[test]
fn configuration_primary_keys_match_the_four_owned_readers() {
    for table in [
        AuthorityConfigSourceTable::UserCardLevelDefinition,
        AuthorityConfigSourceTable::IdentityLevelTemplate,
        AuthorityConfigSourceTable::UserCardTemplate,
        AuthorityConfigSourceTable::InheritanceConfig,
    ] {
        AuthorityConfigSourceLookup::PrimaryId { id: 9 }
            .validate_for_table(table)
            .unwrap();
        for id in [0, -1] {
            assert!(AuthorityConfigSourceLookup::PrimaryId { id }
                .validate_for_table(table)
                .is_err());
        }
    }
}

#[test]
fn shared_config_commit_digest_binds_the_complete_wrapper_and_nul_domain() {
    let completion = evidence(vec![update_group(1, "before", "after")]);
    completion.validate("op-1").unwrap();
    let envelope = super::super::AuthorityStagedSourceEvidence {
        coverage: None,
        evidence: serde_json::to_value(&completion).unwrap(),
    };
    let canonical = serde_json::to_vec(&envelope).unwrap();
    let mut exact = b"ASTRAL_TRUSTGRAPH_SOURCE_BATCH_V7\0".to_vec();
    exact.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    exact.extend_from_slice(&canonical);
    let digest = config_source_commit_digest(&completion).unwrap();
    assert_eq!(digest, hex::encode(Sha256::digest(&exact)));
    let mut escaped_domain = b"ASTRAL_TRUSTGRAPH_SOURCE_BATCH_V7\\0".to_vec();
    escaped_domain.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    escaped_domain.extend_from_slice(&canonical);
    assert_ne!(digest, hex::encode(Sha256::digest(escaped_domain)));

    let inner = serde_json::to_vec(&completion).unwrap();
    let mut inner_only = b"ASTRAL_TRUSTGRAPH_SOURCE_BATCH_V7\0".to_vec();
    inner_only.extend_from_slice(&(inner.len() as u64).to_be_bytes());
    inner_only.extend_from_slice(&inner);
    assert_ne!(digest, hex::encode(Sha256::digest(inner_only)));
    let mut changed_audit = completion.clone();
    changed_audit.source_batch.audits[0].audit_log_id += 1;
    assert_ne!(digest, config_source_commit_digest(&changed_audit).unwrap());
    let normalized: AuthorityConfigCompletionEvidence =
        serde_json::from_value(serde_json::to_value(&completion).unwrap()).unwrap();
    assert_eq!(digest, config_source_commit_digest(&normalized).unwrap());
}

#[test]
fn shared_config_image_digests_bind_real_bytes_with_distinct_side_domains() {
    let images = vec![
        update_group(1, "before one", "after one"),
        update_group(2, "before two", "after two"),
    ];
    let actual = config_image_digests(&images).unwrap();
    for (domain, mut digests, expected) in [
        (
            b"ASTRAL_TRUSTGRAPH_TYPED_BEFORE_V7\0".as_slice(),
            images
                .iter()
                .map(|image| image.before_image_digest.clone())
                .collect::<Vec<_>>(),
            &actual.0,
        ),
        (
            b"ASTRAL_TRUSTGRAPH_TYPED_AFTER_V7\0".as_slice(),
            images
                .iter()
                .map(|image| image.after_image_digest.clone())
                .collect::<Vec<_>>(),
            &actual.1,
        ),
    ] {
        digests.sort();
        let mut exact = domain.to_vec();
        exact.extend_from_slice(&2_u64.to_be_bytes());
        for digest in digests {
            exact.extend_from_slice(&64_u64.to_be_bytes());
            exact.extend_from_slice(digest.as_bytes());
        }
        assert_eq!(*expected, hex::encode(Sha256::digest(exact)));
    }
    let mut reversed = images.clone();
    reversed.reverse();
    assert_eq!(actual, config_image_digests(&reversed).unwrap());
    let mut corrupt = images.clone();
    corrupt[0].after_image.push(' ');
    assert!(config_image_digests(&corrupt).is_err());
    let unchanged = vec![update_group(1, "same", "same")];
    let (before, after) = config_image_digests(&unchanged).unwrap();
    assert_ne!(before, after);
}

#[test]
fn config_request_recomputes_all_source_content_bindings() {
    let completion = evidence(vec![update_group(1, "before", "after")]);
    let envelope = AuthorityStagedSourceEvidence {
        coverage: None,
        evidence: serde_json::to_value(&completion).unwrap(),
    };
    let retained = AuthorityRetainedStagedEvidence::new(serde_json::to_string(&envelope).unwrap());
    let (before, after) = config_image_digests(&completion.source_batch.source_images).unwrap();
    let request = AuthorityConfigCompletionRequest {
        caller: AuthorityCallerIdentity {
            service_id: "source-1".into(),
            request_nonce: "nonce-1".into(),
            issued_at: 1_000,
        },
        binding: AuthorityCommitBinding {
            reservation_id: "reservation-1".into(),
            operation_id: "op-1".into(),
            event_id: "event-1".into(),
            admission_proof_id: "proof-1".into(),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            service_id: "source-1".into(),
            database_id: "database-1".into(),
            request_digest: "ab".repeat(32),
            source_commit_digest: config_source_commit_digest(&completion).unwrap(),
            before_image_digest: Some(before),
            after_image_digest: after,
            source_outcome_digest: "cd".repeat(32),
            staged_evidence_digest: retained.canonical_digest().unwrap(),
        },
        completion,
        retained_staged_evidence: retained,
    };
    request.validate().unwrap();
    for field in ["source", "before", "missing_before", "after"] {
        let mut invalid = request.clone();
        match field {
            "source" => invalid.binding.source_commit_digest = "00".repeat(32),
            "before" => invalid.binding.before_image_digest = Some("00".repeat(32)),
            "missing_before" => invalid.binding.before_image_digest = None,
            "after" => invalid.binding.after_image_digest = "00".repeat(32),
            _ => unreachable!(),
        }
        assert!(
            invalid.validate().is_err(),
            "accepted a wrong {field} binding"
        );
    }
    let mut changed_audit = request;
    changed_audit.completion.source_batch.audits[0].audit_log_id += 1;
    let changed_envelope = AuthorityStagedSourceEvidence {
        coverage: None,
        evidence: serde_json::to_value(&changed_audit.completion).unwrap(),
    };
    changed_audit.retained_staged_evidence =
        AuthorityRetainedStagedEvidence::new(serde_json::to_string(&changed_envelope).unwrap());
    changed_audit.binding.staged_evidence_digest = changed_audit
        .retained_staged_evidence
        .canonical_digest()
        .unwrap();
    assert!(changed_audit.validate().is_err());
}

#[test]
fn sensitive_commitment_pins_exact_field_tenant_and_utf8_bytes() {
    let digest =
        authority_config_sensitive_field_digest(17, "contact_email", "a@example.test").unwrap();
    let exact = b"ASTRAL_CONFIG_SENSITIVE_FIELD_V7\0\0\0\0\0\0\0\0\x11\0\0\0\x0dcontact_email\0\0\0\0\0\0\0\x0ea@example.test";
    assert_eq!(digest, hex::encode(Sha256::digest(exact)));
    assert_ne!(
        digest,
        authority_config_sensitive_field_digest(18, "contact_email", "a@example.test").unwrap()
    );
    assert_ne!(
        digest,
        authority_config_sensitive_field_digest(17, "contact_person", "a@example.test").unwrap()
    );
    assert_ne!(
        digest,
        authority_config_sensitive_field_digest(17, "contact_email", "a@example.test ").unwrap()
    );
    assert_ne!(
        authority_config_sensitive_field_digest(17, "contact_person", "用户").unwrap(),
        authority_config_sensitive_field_digest(17, "contact_person", "用户甲").unwrap()
    );
    assert!(authority_config_sensitive_field_digest(0, "contact_email", "value").is_err());
    assert!(authority_config_sensitive_field_digest(17, "password", "value").is_err());
}
