-- Rust-owned Phase 1 additive schema for versioned mutable authorization hot state.
--
-- This migration only creates the durable records needed by the future
-- incremental projector and asynchronous archive worker. It does not backfill,
-- alter, or delete any existing source/projection data. Every statement is an
-- idempotent creator so the explicit Rust migration job can safely retry after
-- an interrupted DDL batch; application startup remains read-only.
--
-- Foreign keys are intentionally omitted. Projection and archive evidence must
-- remain queryable after a source aggregate is deleted, and the worker uses
-- tenant/card/aggregate identities plus generation/CAS fences instead.
--
-- Canonical identity and hash boundary (must match astral-types contracts):
-- 1. grant_id columns store the canonical text form of a typed GrantId UUID:
--    lowercase hyphenated 36-character string, exactly as produced by
--    GrantId::as_str(). Never uppercase, braced, urn: or binary re-encodings.
-- 2. All *_hash / *_digest / lease_token_hash BINARY(32) columns store raw
--    SHA-256 digests. Their canonical wire form inside Rust typed contracts is
--    the lowercase 64-character hex string of the same bytes; writers decode the
--    hex to 32 raw bytes, readers re-encode to compare. No other algorithm or
--    length may be stored in these columns.
-- 3. grant_payload / before_image_json carry validity windows as UTC Unix
--    seconds with not_before inclusive and expires_at exclusive, matching the
--    ValidityWindow contract; not_before >= expires_at never validates.

CREATE TABLE IF NOT EXISTS authorization_grant_revision (
    revision_id       BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    grant_id          CHAR(36) NOT NULL COMMENT 'canonical GrantId: lowercase hyphenated UUID',
    revision_no       BIGINT NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    is_tombstone      TINYINT NOT NULL DEFAULT 0,
    grant_payload     JSON NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (revision_id),
    UNIQUE KEY uk_agr_revision_version (tenant_id, aggregate_type, aggregate_id, grant_id, revision_no),
    KEY idx_agr_revision_aggregate (tenant_id, aggregate_type, aggregate_id, revision_no),
    KEY idx_agr_revision_card (tenant_id, card_id, revision_no),
    KEY idx_agr_revision_tombstone (tenant_id, aggregate_type, aggregate_id, is_tombstone, revision_no),
    KEY idx_agr_revision_event (event_id),
    KEY idx_agr_revision_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Versioned Rust-owned grant revisions, including tombstones';

CREATE TABLE IF NOT EXISTS authorization_delta_event (
    delta_event_id    BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    grant_id          CHAR(36) NOT NULL COMMENT 'canonical GrantId: lowercase hyphenated UUID',
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    event_type        VARCHAR(32) NOT NULL,
    base_version      BIGINT NOT NULL,
    target_version    BIGINT NOT NULL,
    source_generation BIGINT NOT NULL,
    revoke_fence      BIGINT NOT NULL DEFAULT 0,
    before_image_json JSON NULL,
    before_digest     BINARY(32) NULL,
    delta_json        JSON NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts          INT NOT NULL DEFAULT 0,
    next_attempt_at   DATETIME NULL,
    lease_owner       VARCHAR(128) NULL,
    lease_token_hash  BINARY(32) NULL,
    lease_expires_at  DATETIME NULL,
    cas_version       BIGINT NOT NULL DEFAULT 0,
    last_error        VARCHAR(512) NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (delta_event_id),
    UNIQUE KEY uk_ade_event (event_id),
    UNIQUE KEY uk_ade_target_version (tenant_id, aggregate_type, aggregate_id, grant_id, target_version),
    KEY idx_ade_aggregate (tenant_id, aggregate_type, aggregate_id, target_version),
    KEY idx_ade_card (tenant_id, card_id, target_version),
    KEY idx_ade_pending (status, next_attempt_at, created_at),
    KEY idx_ade_lease (status, lease_expires_at, delta_event_id),
    KEY idx_ade_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Typed grant delta events with version, before-image, digest and CAS state';

CREATE TABLE IF NOT EXISTS authorization_impact_plan (
    plan_id           BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    base_generation   BIGINT NOT NULL,
    target_generation BIGINT NOT NULL,
    base_version      BIGINT NOT NULL,
    target_version    BIGINT NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts          INT NOT NULL DEFAULT 0,
    next_attempt_at   DATETIME NULL,
    lease_owner       VARCHAR(128) NULL,
    lease_token_hash  BINARY(32) NULL,
    lease_expires_at  DATETIME NULL,
    cas_version       BIGINT NOT NULL DEFAULT 0,
    last_error        VARCHAR(512) NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (plan_id),
    UNIQUE KEY uk_aip_event (event_id),
    UNIQUE KEY uk_aip_target_generation (tenant_id, aggregate_type, aggregate_id, target_generation),
    KEY idx_aip_aggregate (tenant_id, aggregate_type, aggregate_id, target_generation),
    KEY idx_aip_card (tenant_id, card_id, target_generation),
    KEY idx_aip_pending (status, next_attempt_at, created_at),
    KEY idx_aip_lease (status, lease_expires_at, plan_id),
    KEY idx_aip_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable impact-plan root for an incremental projection generation';

CREATE TABLE IF NOT EXISTS authorization_impact_plan_item (
    item_id           BIGINT NOT NULL AUTO_INCREMENT,
    plan_id           BIGINT NOT NULL,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    projection_key    VARCHAR(191) NOT NULL,
    item_type         VARCHAR(32) NOT NULL,
    grant_id          CHAR(36) NULL COMMENT 'canonical GrantId: lowercase hyphenated UUID',
    base_version      BIGINT NOT NULL,
    target_version    BIGINT NOT NULL,
    before_digest     BINARY(32) NULL,
    after_digest      BINARY(32) NULL,
    dependency_hash   BINARY(32) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    cas_version       BIGINT NOT NULL DEFAULT 0,
    last_error        VARCHAR(512) NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (item_id),
    UNIQUE KEY uk_aipi_plan_key (plan_id, projection_key),
    KEY idx_aipi_plan_status (plan_id, status, item_id),
    KEY idx_aipi_aggregate (tenant_id, aggregate_type, aggregate_id, target_version),
    KEY idx_aipi_card (tenant_id, card_id, target_version),
    KEY idx_aipi_event (event_id),
    KEY idx_aipi_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable impact-plan items keyed by affected projection identity';

CREATE TABLE IF NOT EXISTS authorization_projection_manifest (
    manifest_id       BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    generation        BIGINT NOT NULL,
    source_generation BIGINT NOT NULL,
    projected_generation BIGINT NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    manifest_digest   BINARY(32) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'BUILDING',
    cas_version       BIGINT NOT NULL DEFAULT 0,
    lease_owner       VARCHAR(128) NULL,
    lease_token_hash  BINARY(32) NULL,
    lease_expires_at  DATETIME NULL,
    last_error        VARCHAR(512) NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (manifest_id),
    UNIQUE KEY uk_apm_generation (tenant_id, aggregate_type, aggregate_id, generation),
    UNIQUE KEY uk_apm_digest (tenant_id, manifest_digest),
    KEY idx_apm_aggregate (tenant_id, aggregate_type, aggregate_id, generation),
    KEY idx_apm_card (tenant_id, card_id, generation),
    KEY idx_apm_status (status, lease_expires_at, manifest_id),
    KEY idx_apm_event (event_id),
    KEY idx_apm_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Generation-scoped projection manifest and semantic proof';

CREATE TABLE IF NOT EXISTS authorization_projection_segment (
    segment_id        BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    content_digest    BINARY(32) NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    segment_format    VARCHAR(32) NOT NULL,
    row_count         BIGINT NOT NULL DEFAULT 0,
    byte_size         BIGINT NOT NULL DEFAULT 0,
    segment_payload   MEDIUMBLOB NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'READY',
    cas_version       BIGINT NOT NULL DEFAULT 0,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (segment_id),
    UNIQUE KEY uk_aps_content (tenant_id, content_digest),
    KEY idx_aps_aggregate (tenant_id, aggregate_type, aggregate_id, segment_id),
    KEY idx_aps_card (tenant_id, card_id, segment_id),
    KEY idx_aps_semantic (tenant_id, semantic_hash, compiler_version),
    KEY idx_aps_status (status, segment_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Content-addressed immutable projection segment';

CREATE TABLE IF NOT EXISTS authorization_projection_manifest_segment (
    reference_id      BIGINT NOT NULL AUTO_INCREMENT,
    manifest_id       BIGINT NOT NULL,
    segment_id        BIGINT NOT NULL,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    generation        BIGINT NOT NULL,
    segment_ordinal   INT NOT NULL,
    content_digest    BINARY(32) NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'READY',
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (reference_id),
    UNIQUE KEY uk_apms_ordinal (manifest_id, segment_ordinal),
    UNIQUE KEY uk_apms_segment (manifest_id, segment_id),
    KEY idx_apms_manifest (tenant_id, manifest_id, generation),
    KEY idx_apms_segment (tenant_id, segment_id),
    KEY idx_apms_aggregate (tenant_id, aggregate_type, aggregate_id, generation),
    KEY idx_apms_event (event_id),
    KEY idx_apms_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Manifest-to-segment references scoped to a projection generation';

CREATE TABLE IF NOT EXISTS authorization_projection_current (
    pointer_id        BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    current_generation BIGINT NOT NULL,
    manifest_id       BIGINT NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'READY',
    cas_version       BIGINT NOT NULL DEFAULT 0,
    last_error        VARCHAR(512) NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (pointer_id),
    UNIQUE KEY uk_apc_aggregate (tenant_id, aggregate_type, aggregate_id),
    KEY idx_apc_generation (tenant_id, aggregate_type, aggregate_id, current_generation),
    KEY idx_apc_card (tenant_id, card_id, current_generation),
    KEY idx_apc_manifest (manifest_id),
    KEY idx_apc_event (event_id),
    KEY idx_apc_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='CAS-updated current projection manifest pointer';

CREATE TABLE IF NOT EXISTS authorization_archive_outbox (
    archive_outbox_id BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id         BIGINT NOT NULL,
    card_id           BIGINT NULL,
    aggregate_type    VARCHAR(32) NOT NULL,
    aggregate_id      BIGINT NOT NULL,
    manifest_id       BIGINT NOT NULL,
    generation        BIGINT NOT NULL,
    event_id          VARCHAR(128) NOT NULL,
    operation_id      VARCHAR(128) NOT NULL,
    archive_key       VARCHAR(512) NOT NULL,
    semantic_hash     BINARY(32) NOT NULL,
    dependency_hash   BINARY(32) NOT NULL,
    compiler_version  VARCHAR(64) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts          INT NOT NULL DEFAULT 0,
    next_attempt_at   DATETIME NULL,
    lease_owner       VARCHAR(128) NULL,
    lease_token_hash  BINARY(32) NULL,
    lease_expires_at  DATETIME NULL,
    cas_version       BIGINT NOT NULL DEFAULT 0,
    archived_at       DATETIME NULL,
    last_error        VARCHAR(512) NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (archive_outbox_id),
    UNIQUE KEY uk_aao_event (event_id),
    UNIQUE KEY uk_aao_generation (tenant_id, aggregate_type, aggregate_id, generation),
    KEY idx_aao_aggregate (tenant_id, aggregate_type, aggregate_id, generation),
    KEY idx_aao_card (tenant_id, card_id, generation),
    KEY idx_aao_pending (status, next_attempt_at, created_at),
    KEY idx_aao_lease (status, lease_expires_at, archive_outbox_id),
    KEY idx_aao_manifest (manifest_id),
    KEY idx_aao_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable asynchronous archive work item for a projection manifest';

CREATE TABLE IF NOT EXISTS authorization_archive_manifest (
    archive_manifest_id BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id           BIGINT NOT NULL,
    card_id             BIGINT NULL,
    aggregate_type      VARCHAR(32) NOT NULL,
    aggregate_id        BIGINT NOT NULL,
    manifest_id         BIGINT NOT NULL,
    generation          BIGINT NOT NULL,
    event_id            VARCHAR(128) NOT NULL,
    operation_id        VARCHAR(128) NOT NULL,
    archive_key         VARCHAR(512) NOT NULL,
    archive_digest      BINARY(32) NOT NULL,
    semantic_hash       BINARY(32) NOT NULL,
    dependency_hash     BINARY(32) NOT NULL,
    compiler_version    VARCHAR(64) NOT NULL,
    status              VARCHAR(32) NOT NULL DEFAULT 'STAGED',
    cas_version         BIGINT NOT NULL DEFAULT 0,
    archived_at         DATETIME NULL,
    last_error          VARCHAR(512) NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (archive_manifest_id),
    UNIQUE KEY uk_aam_generation (tenant_id, aggregate_type, aggregate_id, generation),
    UNIQUE KEY uk_aam_archive_digest (tenant_id, archive_digest),
    KEY idx_aam_aggregate (tenant_id, aggregate_type, aggregate_id, generation),
    KEY idx_aam_card (tenant_id, card_id, generation),
    KEY idx_aam_status (status, archived_at, archive_manifest_id),
    KEY idx_aam_manifest (manifest_id),
    KEY idx_aam_event (event_id),
    KEY idx_aam_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Archive evidence manifest for a generation-scoped projection';
