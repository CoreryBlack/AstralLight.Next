use super::*;

fn source_artifacts(
    version: i64,
) -> (
    &'static ExactMigrationArtifactContract,
    Vec<MigrationArtifact>,
) {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == version)
        .unwrap();
    let contract = exact_migration_artifact_contract(migration).unwrap();
    let artifacts = parsed_migration_artifacts(migration).unwrap();
    (contract, artifacts)
}

#[test]
fn exact_source_constraints_include_checks_and_composite_foreign_keys() {
    for version in [empty_card_origin::VERSION, invalidation_delivery::VERSION] {
        let (contract, artifacts) = source_artifacts(version);
        assert!(exact_contract_artifacts_match_source(contract, &artifacts));
        assert_eq!(
            artifacts
                .iter()
                .filter(|artifact| artifact.kind == MigrationArtifactKind::Constraint)
                .count(),
            2
        );
        assert!(!artifacts.iter().any(|artifact| {
            artifact.kind == MigrationArtifactKind::CreateColumn && artifact.name == "CONSTRAINT"
        }));
    }
    let (_, artifacts) = source_artifacts(invalidation_delivery::VERSION);
    let composite = artifacts
        .iter()
        .find(|artifact| artifact.name == "FK_AIDR_LEG")
        .unwrap();
    assert_eq!(
        composite.constraint,
        Some(MigrationConstraint::ForeignKey {
            columns: vec!["MESSAGE_ID".into(), "LEG_ID".into()],
            referenced_table: "AUTHORIZATION_INVALIDATION_DELIVERY_LEG".into(),
            referenced_columns: vec!["MESSAGE_ID".into(), "LEG_ID".into()],
            on_delete: "RESTRICT".into(),
        })
    );
}

#[test]
fn exact_source_constraints_reject_missing_extra_and_definition_drift() {
    for version in [empty_card_origin::VERSION, invalidation_delivery::VERSION] {
        let (contract, artifacts) = source_artifacts(version);
        let index = artifacts
            .iter()
            .position(|artifact| artifact.kind == MigrationArtifactKind::Constraint)
            .unwrap();
        let mut missing = artifacts.clone();
        missing.remove(index);
        assert!(!exact_contract_artifacts_match_source(contract, &missing));
        let mut extra = artifacts.clone();
        extra.push(artifacts[index].clone());
        assert!(!exact_contract_artifacts_match_source(contract, &extra));
        let mut drifted = artifacts.clone();
        match drifted[index].constraint.as_mut().unwrap() {
            MigrationConstraint::ForeignKey { on_delete, .. } => *on_delete = "CASCADE".into(),
            MigrationConstraint::Check { expression } => *expression = "1 = 1".into(),
        }
        assert!(!exact_contract_artifacts_match_source(contract, &drifted));
    }
    let (contract, mut artifacts) = source_artifacts(invalidation_delivery::VERSION);
    let composite = artifacts
        .iter_mut()
        .find(|artifact| artifact.name == "FK_AIDR_LEG")
        .unwrap();
    if let Some(MigrationConstraint::ForeignKey {
        referenced_columns, ..
    }) = &mut composite.constraint
    {
        referenced_columns.reverse();
    }
    assert!(!exact_contract_artifacts_match_source(contract, &artifacts));
}

#[test]
fn constraint_parser_rejects_unsupported_or_incomplete_definitions() {
    for definition in [
        "CONSTRAINT FK FOREIGN KEY (A, B) REFERENCES PARENT (A)",
        "CONSTRAINT FK FOREIGN KEY (A) REFERENCES PARENT (A) ON DELETE CASCADE EXTRA",
        "CONSTRAINT FK FOREIGN KEY (A) REFERENCES PARENT (A) ON UPDATE CASCADE",
        "CONSTRAINT CK CHECK (A > 0) EXTRA",
        "CONSTRAINT CK UNIQUE (A)",
    ] {
        assert!(parse_constraint(definition).is_none(), "{definition}");
    }
    assert!(parse_create_table("CREATE TABLE T (A BIGINT, CONSTRAINT CK UNIQUE (A))").is_none());
    let (_, constraint) = parse_constraint(
        "CONSTRAINT FK FOREIGN KEY (A, B) REFERENCES PARENT (A, B) ON DELETE SET NULL",
    )
    .unwrap();
    assert!(
        matches!(constraint, MigrationConstraint::ForeignKey { on_delete, .. } if on_delete == "SET NULL")
    );
}
