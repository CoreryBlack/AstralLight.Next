-- memory-v1: OFFLINE CANDIDATE ONLY; not a migration and not an adoption decision.
-- INCOMPLETE: deliberately no production integration or authorization evaluator.
-- Target dialect: MySQL 8.0.16+ / InnoDB (enforced CHECK constraints).
-- Do not execute against an existing database. No data conversion is specified.
-- All DATETIME values are UTC. IDs and statuses are supplied explicitly.
-- Tenant parentage records organization only: no inheritance or cross-tenant access.
-- Source rows, bindings, operation records, and audit records are not ALLOW proofs.
-- Formal adoption requires the applicable policy, eligibility, owner, freshness and
-- fail-closed gates. Legacy publication is not a memory-v1 target dependency.
-- Rule/condition interpretation, precedence, approval, delegation, durability order,
-- recovery and import of historical data require separate contracts.
-- CHECK does not detect multi-row tenant cycles; validate acyclicity in the owner.
-- No cascade deletes: retention, revocation and lifecycle workflows remain undefined.

-- memory-v1: A global principal; existence alone does not establish identity eligibility.
CREATE TABLE memory_v1_user (
    user_id BIGINT NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (user_id),
    CONSTRAINT ck_mv1_user_id CHECK (user_id > 0),
    CONSTRAINT ck_mv1_user_status CHECK (status IN ('ACTIVE', 'DISABLED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: At most one identity card per user, independent of tenant.
-- A user without a card is representable and must not pass identity eligibility.
CREATE TABLE memory_v1_identity_card (
    identity_card_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    valid_from DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NULL,
    PRIMARY KEY (identity_card_id),
    UNIQUE KEY uk_mv1_identity_user (user_id),
    CONSTRAINT fk_mv1_identity_user FOREIGN KEY (user_id)
        REFERENCES memory_v1_user (user_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_identity_id CHECK (identity_card_id > 0),
    CONSTRAINT ck_mv1_identity_status CHECK (status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
    CONSTRAINT ck_mv1_identity_window CHECK (valid_until IS NULL OR valid_until > valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Company, department and team can each be represented as a tenant.
-- A parent link grants no rights; type combinations and tree policy are unspecified.
CREATE TABLE memory_v1_tenant (
    tenant_id BIGINT NOT NULL,
    parent_tenant_id BIGINT NULL,
    tenant_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    tenant_name VARCHAR(128) NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (tenant_id),
    UNIQUE KEY uk_mv1_tenant_code (tenant_code),
    KEY ix_mv1_tenant_parent (parent_tenant_id),
    CONSTRAINT fk_mv1_tenant_parent FOREIGN KEY (parent_tenant_id)
        REFERENCES memory_v1_tenant (tenant_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_tenant_id CHECK (tenant_id > 0),
    CONSTRAINT ck_mv1_tenant_parent CHECK (parent_tenant_id IS NULL OR parent_tenant_id <> tenant_id),
    CONSTRAINT ck_mv1_tenant_code CHECK (CHAR_LENGTH(TRIM(tenant_code)) > 0),
    CONSTRAINT ck_mv1_tenant_name CHECK (CHAR_LENGTH(TRIM(tenant_name)) > 0),
    CONSTRAINT ck_mv1_tenant_status CHECK (status IN ('ACTIVE', 'DISABLED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: A user can have multiple cards, including cards in different tenants.
-- The identity card is resolved by user_id; no identity card grants tenant access.
CREATE TABLE memory_v1_user_card (
    user_card_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    valid_from DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NULL,
    PRIMARY KEY (user_card_id),
    UNIQUE KEY uk_mv1_card_tenant_id (tenant_id, user_card_id),
    KEY ix_mv1_card_user (user_id),
    CONSTRAINT fk_mv1_card_tenant FOREIGN KEY (tenant_id)
        REFERENCES memory_v1_tenant (tenant_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_card_user FOREIGN KEY (user_id)
        REFERENCES memory_v1_user (user_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_card_id CHECK (user_card_id > 0),
    CONSTRAINT ck_mv1_card_status CHECK (status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
    CONSTRAINT ck_mv1_card_window CHECK (valid_until IS NULL OR valid_until > valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Registered resource/action vocabulary; registration grants nothing.
CREATE TABLE memory_v1_resource_action (
    resource_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    action_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (resource_type, action_code),
    CONSTRAINT ck_mv1_ra_resource CHECK (CHAR_LENGTH(TRIM(resource_type)) > 0),
    CONSTRAINT ck_mv1_ra_action CHECK (CHAR_LENGTH(TRIM(action_code)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Tenant-local resource identity, not an ownership-resolution proof.
CREATE TABLE memory_v1_resource (
    tenant_id BIGINT NOT NULL,
    resource_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    resource_id BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, resource_type, resource_id),
    CONSTRAINT fk_mv1_resource_tenant FOREIGN KEY (tenant_id)
        REFERENCES memory_v1_tenant (tenant_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_resource_type CHECK (CHAR_LENGTH(TRIM(resource_type)) > 0),
    CONSTRAINT ck_mv1_resource_id CHECK (resource_id > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Operation identity for correlation only; no commit or approval semantics.
CREATE TABLE memory_v1_operation (
    operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    tenant_id BIGINT NOT NULL,
    actor_user_id BIGINT NULL,
    operation_kind VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recorded_at DATETIME(6) NOT NULL,
    PRIMARY KEY (operation_id),
    UNIQUE KEY uk_mv1_operation_tenant (tenant_id, operation_id),
    KEY ix_mv1_operation_actor (actor_user_id),
    CONSTRAINT fk_mv1_operation_tenant FOREIGN KEY (tenant_id)
        REFERENCES memory_v1_tenant (tenant_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_operation_actor FOREIGN KEY (actor_user_id)
        REFERENCES memory_v1_user (user_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_operation_id CHECK (CHAR_LENGTH(TRIM(operation_id)) > 0),
    CONSTRAINT ck_mv1_operation_kind CHECK (CHAR_LENGTH(TRIM(operation_kind)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: The definition is distinct from its entries and card bindings.
-- source_type/source_id are provenance fields, never the BASE/OVERLAY binding role.
CREATE TABLE memory_v1_rule_set (
    rule_set_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512) NULL,
    source_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    enabled TINYINT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (rule_set_id),
    UNIQUE KEY uk_mv1_ruleset_tenant_id (tenant_id, rule_set_id),
    UNIQUE KEY uk_mv1_ruleset_code (tenant_id, code),
    CONSTRAINT fk_mv1_ruleset_tenant FOREIGN KEY (tenant_id)
        REFERENCES memory_v1_tenant (tenant_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_ruleset_id CHECK (rule_set_id > 0),
    CONSTRAINT ck_mv1_ruleset_code CHECK (CHAR_LENGTH(TRIM(code)) > 0),
    CONSTRAINT ck_mv1_ruleset_name CHECK (CHAR_LENGTH(TRIM(name)) > 0),
    CONSTRAINT ck_mv1_ruleset_source CHECK (CHAR_LENGTH(TRIM(source_type)) > 0),
    CONSTRAINT ck_mv1_ruleset_source_id CHECK (source_id IS NULL OR CHAR_LENGTH(TRIM(source_id)) > 0),
    CONSTRAINT ck_mv1_ruleset_enabled CHECK (enabled IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Explicit scope distinguishes a whole resource type from an instance.
-- NULL condition means no condition is recorded; parsing and support are separate gates.
CREATE TABLE memory_v1_rule_set_entry (
    entry_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    rule_set_id BIGINT NOT NULL,
    resource_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    action_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    resource_id BIGINT NULL,
    effect VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    condition_json JSON NULL,
    priority INT NOT NULL,
    enabled TINYINT NOT NULL,
    valid_from DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NULL,
    PRIMARY KEY (entry_id),
    KEY ix_mv1_entry_set (tenant_id, rule_set_id),
    KEY ix_mv1_entry_action (resource_type, action_code),
    KEY ix_mv1_entry_resource (tenant_id, resource_type, resource_id),
    CONSTRAINT fk_mv1_entry_set FOREIGN KEY (tenant_id, rule_set_id)
        REFERENCES memory_v1_rule_set (tenant_id, rule_set_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_entry_action FOREIGN KEY (resource_type, action_code)
        REFERENCES memory_v1_resource_action (resource_type, action_code) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_entry_resource FOREIGN KEY (tenant_id, resource_type, resource_id)
        REFERENCES memory_v1_resource (tenant_id, resource_type, resource_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_entry_id CHECK (entry_id > 0),
    CONSTRAINT ck_mv1_entry_scope CHECK ((scope_kind = 'TYPE' AND resource_id IS NULL) OR
                                         (scope_kind = 'INSTANCE' AND resource_id IS NOT NULL)),
    CONSTRAINT ck_mv1_entry_effect CHECK (effect IN ('ALLOW', 'DENY')),
    CONSTRAINT ck_mv1_entry_enabled CHECK (enabled IN (0, 1)),
    CONSTRAINT ck_mv1_entry_window CHECK (valid_until IS NULL OR valid_until > valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Binding identity and layer are separate from rule-set provenance.
-- Both ends must belong to exactly this tenant; no cross-tenant sharing is modeled.
CREATE TABLE memory_v1_card_rule_set_ref (
    binding_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    user_card_id BIGINT NOT NULL,
    rule_set_id BIGINT NOT NULL,
    ref_type VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (binding_id),
    UNIQUE KEY uk_mv1_binding_pair (tenant_id, user_card_id, rule_set_id),
    KEY ix_mv1_binding_set (tenant_id, rule_set_id),
    CONSTRAINT fk_mv1_binding_card FOREIGN KEY (tenant_id, user_card_id)
        REFERENCES memory_v1_user_card (tenant_id, user_card_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_binding_set FOREIGN KEY (tenant_id, rule_set_id)
        REFERENCES memory_v1_rule_set (tenant_id, rule_set_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_binding_id CHECK (binding_id > 0),
    CONSTRAINT ck_mv1_binding_type CHECK (ref_type IN ('BASE', 'OVERLAY'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Direct authorization source fact, not an effective grant or proof.
-- Operation linkage is provenance only and does not imply approval or commit order.
CREATE TABLE memory_v1_direct_grant (
    direct_grant_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    user_card_id BIGINT NOT NULL,
    operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    resource_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    action_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    resource_id BIGINT NULL,
    effect VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    condition_json JSON NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    valid_from DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NULL,
    PRIMARY KEY (direct_grant_id),
    KEY ix_mv1_grant_card (tenant_id, user_card_id),
    KEY ix_mv1_grant_operation (tenant_id, operation_id),
    KEY ix_mv1_grant_action (resource_type, action_code),
    KEY ix_mv1_grant_resource (tenant_id, resource_type, resource_id),
    CONSTRAINT fk_mv1_grant_card FOREIGN KEY (tenant_id, user_card_id)
        REFERENCES memory_v1_user_card (tenant_id, user_card_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_grant_operation FOREIGN KEY (tenant_id, operation_id)
        REFERENCES memory_v1_operation (tenant_id, operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_grant_action FOREIGN KEY (resource_type, action_code)
        REFERENCES memory_v1_resource_action (resource_type, action_code) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_mv1_grant_resource FOREIGN KEY (tenant_id, resource_type, resource_id)
        REFERENCES memory_v1_resource (tenant_id, resource_type, resource_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_grant_id CHECK (direct_grant_id > 0),
    CONSTRAINT ck_mv1_grant_scope CHECK ((scope_kind = 'TYPE' AND resource_id IS NULL) OR
                                         (scope_kind = 'INSTANCE' AND resource_id IS NOT NULL)),
    CONSTRAINT ck_mv1_grant_effect CHECK (effect IN ('ALLOW', 'DENY')),
    CONSTRAINT ck_mv1_grant_status CHECK (status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
    CONSTRAINT ck_mv1_grant_window CHECK (valid_until IS NULL OR valid_until > valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- memory-v1: Audit correlation; event completeness and durability are not established.
CREATE TABLE memory_v1_audit_event (
    audit_event_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_data JSON NOT NULL,
    recorded_at DATETIME(6) NOT NULL,
    PRIMARY KEY (audit_event_id),
    KEY ix_mv1_audit_operation (tenant_id, operation_id),
    CONSTRAINT fk_mv1_audit_operation FOREIGN KEY (tenant_id, operation_id)
        REFERENCES memory_v1_operation (tenant_id, operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT ck_mv1_audit_id CHECK (audit_event_id > 0),
    CONSTRAINT ck_mv1_audit_type CHECK (CHAR_LENGTH(TRIM(event_type)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
