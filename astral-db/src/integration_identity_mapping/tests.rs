use super::*;

#[test]
fn key_validation_matches_sdk_and_preserves_valid_bytes() {
    assert_ne!(
        IntegrationIdentityKey::new("app", "ISSUER", "Subject").unwrap(),
        IntegrationIdentityKey::new("app", "issuer", "Subject").unwrap()
    );
    for bad in ["", "issuer ", "two words", "\u{e9}", "\n", "\u{7f}"] {
        assert!(IntegrationIdentityKey::new("app", bad, "subject").is_err());
        assert!(IntegrationIdentityKey::new("app", "issuer", bad).is_err());
    }
    for bad in ["APP", "1app", "app.name", "app:owner", " app"] {
        assert!(IntegrationIdentityKey::new(bad, "issuer", "subject").is_err());
    }
    assert!(IntegrationIdentityKey::new("a".repeat(64), "i".repeat(256), "s".repeat(256)).is_ok());
    assert!(IntegrationIdentityKey::new("a".repeat(65), "issuer", "subject").is_err());
    assert!(IntegrationIdentityKey::new("app", "i".repeat(257), "subject").is_err());
}

#[test]
fn status_transitions_are_forward_only_and_revoke_is_terminal() {
    use IntegrationIdentityMappingStatus::{Active, Disabled, Revoked};
    assert!(valid_forward_transition(Active, Disabled));
    assert!(valid_forward_transition(Active, Revoked));
    assert!(valid_forward_transition(Disabled, Revoked));
    assert!(!valid_forward_transition(Disabled, Active));
    assert!(!valid_forward_transition(Disabled, Disabled));
    assert!(!valid_forward_transition(Revoked, Active));
    assert!(!valid_forward_transition(Revoked, Disabled));
    assert!(!valid_forward_transition(Revoked, Revoked));
    assert!(matches!(
        validate_status_command(&SetIntegrationIdentityMappingStatus {
            key: IntegrationIdentityKey::new("app", "issuer", "subject").unwrap(),
            expected_revision: 1,
            status: Active,
            operation_id: "operation-1".into(),
            actor_id: 1,
        }),
        Err(IntegrationIdentityMappingError::InvalidInput {
            field: "status",
            ..
        })
    ));
}

#[test]
fn operation_digest_binds_actor_command_key_and_content() {
    let key = IntegrationIdentityKey::new("app", "issuer", "subject").unwrap();
    let base = CreateIntegrationIdentityMapping {
        key: key.clone(),
        user_id: 10,
        identity_card_id: 20,
        operation_id: "operation-1".into(),
        actor_id: 30,
    };
    let same = base.clone();
    let mut different_actor = base.clone();
    different_actor.actor_id += 1;
    let mut different_binding = base.clone();
    different_binding.identity_card_id += 1;
    let mut different_case = base.clone();
    different_case.key.issuer = "Issuer".into();
    assert_eq!(create_request_digest(&base), create_request_digest(&same));
    assert_ne!(
        create_request_digest(&base),
        create_request_digest(&different_actor)
    );
    assert_ne!(
        create_request_digest(&base),
        create_request_digest(&different_binding)
    );
    assert_ne!(
        create_request_digest(&base),
        create_request_digest(&different_case)
    );

    let status = SetIntegrationIdentityMappingStatus {
        key,
        expected_revision: 1,
        status: IntegrationIdentityMappingStatus::Disabled,
        operation_id: "operation-2".into(),
        actor_id: 30,
    };
    let mut different_revision = status.clone();
    different_revision.expected_revision += 1;
    assert_ne!(
        status_request_digest(&status),
        status_request_digest(&different_revision)
    );
}

#[test]
fn sql_and_migration_preserve_the_mapping_contract() {
    assert!(MAPPING_READ_ACTIVE_SQL.contains("m.app_id = ? AND m.issuer = ? AND m.subject = ?"));
    assert!(MAPPING_READ_ACTIVE_SQL.contains("pu.status = 'ACTIVE' AND pu.deleted_at IS NULL"));
    assert!(MAPPING_READ_ACTIVE_SQL.contains("ic.user_id = m.user_id AND ic.status = 'ACTIVE'"));
    assert!(MAPPING_READ_ACTIVE_SQL
        .contains("ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()"));
    assert!(MAPPING_READ_ACTIVE_SQL.contains("m.status = 'ACTIVE'"));
    assert!(!MAPPING_READ_ACTIVE_SQL.contains("user_card"));
    assert!(OPERATION_COMPLETE_SQL.contains("request_digest = ? AND actor_id = ?"));
    assert!(MAPPING_AUDIT_INSERT_SQL.contains("IDENTITY_INTEGRATION_MAPPING"));

    let schema = include_str!("schema.rs");
    assert!(schema.contains("audit_log must be a transactional InnoDB BASE TABLE"));
    assert!(schema.contains("validate_audit_engine(pool).await?"));
    assert!(schema.contains("on update current_timestamp(6)"));
    let migration =
        include_str!("../../migrations/20261005000001_integration_identity_mapping.sql")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
    assert!(migration.contains("app_id VARBINARY(64) NOT NULL"));
    assert!(migration.contains("issuer VARBINARY(512) NOT NULL"));
    assert!(migration.contains("subject VARBINARY(512) NOT NULL"));
    assert!(migration.contains("UNIQUE KEY uq_iim_external_identity (app_id, issuer, subject)"));
    assert!(migration.contains("ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"));
    assert!(migration.contains("FOREIGN KEY (user_id) REFERENCES platform_user (user_id)"));
    assert!(migration.contains("FOREIGN KEY (identity_card_id) REFERENCES identity_card (card_id)"));
}
