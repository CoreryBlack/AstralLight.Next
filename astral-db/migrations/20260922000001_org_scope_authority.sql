-- ORG_SCOPE administrative authority source tables (multi-tenant redesign Phase 2).
--
-- Design: Docs/架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md §4/§7 and
-- the MT run shared implementation contract (DB owner slice).
--
-- What this migration is:
--   A fully ADDITIVE set of new tables for the independent, separately versioned
--   org-scope authority chain: administrative nodes, approval requests, grants,
--   masks, memberships, an append-only revision ledger, an org-owned outbox for
--   the NEW org worker, immutable sealed publications with segments and a
--   current pointer, durable dependency pins, an operation-idempotency ledger
--   and an org audit trail.
--
-- What this migration deliberately does NOT do:
--   - It does NOT touch any existing table (no ALTER, no backfill, no drop).
--     The existing v4 `identity_card.uk_ic_user(user_id)` uniqueness contract is
--     a precondition: membership creation locks that one physical row per user
--     before counting active memberships, but this additive migration does not
--     create or repair the baseline identity-card index.
--   - It does NOT write authorization_delta_event / authorization_grant_revision:
--     the legacy worker claims those rows and decodes them with CanonicalGrant,
--     which is user_id-bound. Org payloads use their own typed contracts and
--     their own tables; mixing them would let the old worker misread org facts.
--   - Applying this migration does NOT activate the feature. Runtime stays
--     default-off behind ASTRAL_ORG_SCOPE_ENABLED (strict bool, default false);
--     a tenant becomes org-managed only when an approved ROOT_INIT request
--     creates its org_scope_node row. Managed tenants must never fall back to
--     legacy grants, including while the flag is off.
--
-- Rollback: there is NO dedicated rollback script. The only supported rollback
-- path is `bash scripts/org_scope_preflight.sh rollback --i-understand-data-loss`,
-- which DROPs every org_scope_* table together with its data. That is DESTRUCTIVE
-- and permitted only after Exec-L3 approval, a completed backup/recovery rehearsal,
-- and only while every org_scope_* table is empty (zero managed tenants, no
-- PENDING/LEASED org_scope_outbox events) — the preflight script refuses to issue
-- any DROP otherwise. Runbook:
-- Docs/迁移/ORG_SCOPE迁移与回滚操作手册_V0.1.md.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Administrative tree node. One unit aggregate per tenant: the node row IS
--    the (tenant_id, 'ORG_SCOPE', tenant_id) aggregate root state.
--    generation advances on every relevant grant/mask/tree mutation of the
--    tenant; revoke_fence advances on relationship invalidation; the
--    relationship_revision pins the tree topology version for CAS.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_node (
    tenant_id             BIGINT       NOT NULL,
    root_tenant_id        BIGINT       NOT NULL,
    parent_tenant_id      BIGINT       NULL,
    generation            BIGINT       NOT NULL DEFAULT 1,
    revoke_fence          BIGINT       NOT NULL DEFAULT 0,
    relationship_revision BIGINT       NOT NULL DEFAULT 1,
    active                TINYINT      NOT NULL DEFAULT 1,
    created_request_id    BIGINT       NOT NULL,
    created_operation_id  VARCHAR(128) NOT NULL,
    last_operation_id     VARCHAR(64)  NOT NULL,
    activation_operator_user_id      BIGINT      NULL,
    activation_approval_operation_id VARCHAR(64) NULL,
    created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id),
    KEY idx_osn_root (root_tenant_id),
    KEY idx_osn_parent (parent_tenant_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Org-scope administrative tree node; one unit aggregate per tenant';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Approval requests. Every authority mutation (root init, root grant,
--    attach, move, detach, scope grant) is a typed request payload approved by
--    the immediate administrative parent or the registered meta-permission.
--    payload_json round-trips astral_types::org_scope::OrgRequestPayload.
--    Payload columns are MEDIUMTEXT, not native JSON: the repository decodes
--    them as String (serde_json::from_str) mirroring authorization_projection,
--    and sqlx rejects decoding a native JSON column into String. JSON_EXTRACT
--    predicates still parse the text server-side.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_request (
    request_id           BIGINT       NOT NULL AUTO_INCREMENT,
    request_kind         VARCHAR(32)  NOT NULL,
    requester_tenant_id  BIGINT       NOT NULL,
    requester_user_id    BIGINT       NOT NULL,
    target_tenant_id     BIGINT       NOT NULL,
    parent_tenant_id     BIGINT       NULL,
    payload_json         MEDIUMTEXT   NOT NULL,
    status               VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    revision             BIGINT       NOT NULL DEFAULT 1,
    operation_id         VARCHAR(128) NOT NULL,
    operation_digest     BINARY(32)   NOT NULL,
    decided_by           BIGINT       NULL,
    decided_at           DATETIME(6)  NULL,
    decision_note        VARCHAR(512) NULL,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (request_id),
    UNIQUE KEY uk_osr_operation (operation_id),
    KEY idx_osr_target_status (target_tenant_id, status),
    KEY idx_osr_status (status, request_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Org-scope approval requests; source of truth for authority mutations';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Grants (current state). Origin/immutability: receiving/origin/root tenant,
--    parent provenance and scope identity never change across revisions — a
--    revision only flips active/revision/delegable-of-new-rows. subject_kind
--    UNIT = shared unit contribution (subject columns NULL); PERSONAL binds an
--    explicit user/card pair. No user_id is ever fabricated for UNIT rows.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_grant (
    grant_id             CHAR(36)     NOT NULL,
    revision             BIGINT       NOT NULL DEFAULT 1,
    receiving_tenant_id  BIGINT       NOT NULL,
    origin_tenant_id     BIGINT       NOT NULL,
    root_tenant_id       BIGINT       NOT NULL,
    resource_tenant_id   BIGINT       NOT NULL,
    domain_id            BIGINT       NULL,
    resource             VARCHAR(255) NOT NULL,
    action               VARCHAR(191) NOT NULL,
    valid_from           BIGINT       NULL,
    valid_until          BIGINT       NULL,
    delegable            TINYINT      NOT NULL DEFAULT 0,
    parent_tenant_id     BIGINT       NULL,
    parent_grant_id      CHAR(36)     NULL,
    parent_grant_revision BIGINT      NULL,
    subject_kind         VARCHAR(16)  NOT NULL,
    subject_user_id      BIGINT       NULL,
    subject_card_id      BIGINT       NULL,
    active               TINYINT      NOT NULL DEFAULT 1,
    operation_id         VARCHAR(128) NOT NULL,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT chk_osg_subject CHECK (
        (subject_kind = 'UNIT' AND subject_user_id IS NULL AND subject_card_id IS NULL)
        OR (subject_kind = 'PERSONAL' AND subject_user_id IS NOT NULL AND subject_card_id IS NOT NULL
            AND subject_user_id > 0 AND subject_card_id > 0)
    ),
    CONSTRAINT chk_osg_parent CHECK (
        (parent_tenant_id IS NULL AND parent_grant_id IS NULL AND parent_grant_revision IS NULL)
        OR (parent_tenant_id IS NOT NULL AND parent_grant_id IS NOT NULL AND parent_grant_revision IS NOT NULL
            AND parent_tenant_id = origin_tenant_id AND parent_grant_id <> grant_id)
    ),
    PRIMARY KEY (grant_id),
    KEY idx_osg_receiving (receiving_tenant_id, active),
    KEY idx_osg_origin (origin_tenant_id, active),
    KEY idx_osg_root (root_tenant_id, active),
    KEY idx_osg_resource (resource_tenant_id, resource, action)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Org-scope approved scope grants (current state)';

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Append-only revision ledger for NODE / GRANT / MASK / MEMBERSHIP subjects.
--    payload_json is the full typed subject at that revision; digest binds the
--    exact bytes. History is never updated or deleted.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_revision (
    revision_row_id BIGINT       NOT NULL AUTO_INCREMENT,
    subject_kind    VARCHAR(16)  NOT NULL,
    tenant_id       BIGINT       NOT NULL,
    subject_id      VARCHAR(64)  NOT NULL,
    revision        BIGINT       NOT NULL,
    payload_json    MEDIUMTEXT   NOT NULL,
    payload_digest  BINARY(32)   NOT NULL,
    operation_id    VARCHAR(128) NOT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (revision_row_id),
    UNIQUE KEY uk_osv_subject (subject_kind, subject_id, revision),
    KEY idx_osv_tenant (tenant_id, subject_kind, created_at),
    KEY idx_osv_operation (operation_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Append-only typed revision ledger for org-scope subjects';

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Local exact-origin masks. A mask blocks ONE target grant revision inside
--    the masking unit; it never deletes or rewrites the source grant, and a
--    same-source reissue cannot launder it. If the target grant revision
--    advances beyond target_grant_revision, the mask is unreconciled and the
--    compiler must keep contributions through that source PENDING.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_mask (
    mask_id              CHAR(36)     NOT NULL,
    tenant_id            BIGINT       NOT NULL,
    target_tenant_id     BIGINT       NOT NULL,
    target_grant_id      CHAR(36)     NOT NULL,
    target_grant_revision BIGINT      NOT NULL,
    revision             BIGINT       NOT NULL DEFAULT 1,
    active               TINYINT      NOT NULL DEFAULT 1,
    active_flag          TINYINT      GENERATED ALWAYS AS (IF(active = 1, 1, NULL)) STORED,
    operation_id         VARCHAR(128) NOT NULL,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (mask_id),
    UNIQUE KEY uk_osm_active (tenant_id, target_grant_id, active_flag),
    KEY idx_osm_target (target_grant_id, active),
    KEY idx_osm_tenant (tenant_id, active)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Local exact-origin grant masks; local overlay, not source deletion';

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. Memberships. Independent versioned facts binding a physical card pair to
--    a managed unit. Membership health is checked fresh at read time and never
--    inferred from unit evidence; membership changes do not require rule
--    recompilation and do not advance the node generation.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_membership (
    membership_id    CHAR(36)     NOT NULL,
    tenant_id        BIGINT       NOT NULL,
    root_tenant_id   BIGINT       NOT NULL,
    user_id          BIGINT       NOT NULL,
    identity_card_id BIGINT       NOT NULL,
    card_id          BIGINT       NOT NULL,
    revision         BIGINT       NOT NULL DEFAULT 1,
    active           TINYINT      NOT NULL DEFAULT 1,
    active_card_flag TINYINT      GENERATED ALWAYS AS (IF(active = 1, 1, NULL)) STORED,
    valid_from       BIGINT       NULL,
    valid_until      BIGINT       NULL,
    operation_id     VARCHAR(128) NOT NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (membership_id),
    UNIQUE KEY uk_osmem_active_card (card_id, active_card_flag),
    KEY idx_osmem_unit (tenant_id, user_id, active),
    KEY idx_osmem_card (card_id, active),
    KEY idx_osmem_root (root_tenant_id),
    KEY idx_osmem_user_active (user_id, active)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Org-scope memberships binding card pairs to managed units';

-- ─────────────────────────────────────────────────────────────────────────────
-- 7-9. Immutable sealed publications, their segments and the current pointer.
--    Publications are insert-only (status never leaves SEALED; no UPDATE ever
--    touches content columns). The current pointer advances only forward via
--    the generation-monotonic CAS in complete_publish. Segments carry compiled
--    contribution content — never a fabricated user_id.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_publication (
    publication_id         BIGINT       NOT NULL AUTO_INCREMENT,
    tenant_id              BIGINT       NOT NULL,
    root_tenant_id         BIGINT       NOT NULL,
    generation             BIGINT       NOT NULL,
    relationship_revision  BIGINT       NOT NULL,
    revoke_fence           BIGINT       NOT NULL,
    dependencies_json      MEDIUMTEXT   NOT NULL,
    dependency_digest      BINARY(32)   NOT NULL,
    manifest_digest        BINARY(32)   NOT NULL,
    compiler_version       VARCHAR(64)  NOT NULL,
    segment_count          INT          NOT NULL DEFAULT 0,
    status                 VARCHAR(16)  NOT NULL DEFAULT 'SEALED',
    operation_id           VARCHAR(128) NOT NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (publication_id),
    UNIQUE KEY uk_osp_generation (tenant_id, generation),
    KEY idx_osp_tenant (tenant_id, created_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Immutable sealed org-scope publications (insert-only)';

CREATE TABLE IF NOT EXISTS org_scope_segment (
    segment_id     BIGINT       NOT NULL AUTO_INCREMENT,
    publication_id BIGINT       NOT NULL,
    segment_index  INT          NOT NULL,
    segment_digest BINARY(32)   NOT NULL,
    content_json   MEDIUMTEXT   NOT NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (segment_id),
    UNIQUE KEY uk_oss_position (publication_id, segment_index)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Sealed segments of one org-scope publication (insert-only)';

CREATE TABLE IF NOT EXISTS org_scope_current (
    tenant_id        BIGINT      NOT NULL,
    publication_id   BIGINT      NOT NULL,
    generation       BIGINT      NOT NULL,
    manifest_digest  BINARY(32)  NOT NULL,
    revoke_fence     BIGINT      NOT NULL,
    cas_version      BIGINT      NOT NULL DEFAULT 0,
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Current sealed publication pointer per managed unit (generation CAS)';

-- ─────────────────────────────────────────────────────────────────────────────
-- 10. Org-owned outbox for the NEW org worker. Deliberately separate from
--    authorization_delta_event: different payload contract (typed org facts,
--    no CanonicalGrant), different consumer, same lease discipline
--    (owner + token-hash + expiry + CAS, finite retry).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_outbox (
    org_event_id     BIGINT       NOT NULL AUTO_INCREMENT,
    event_id         VARCHAR(128) NOT NULL,
    tenant_id        BIGINT       NOT NULL,
    event_kind       VARCHAR(48)  NOT NULL,
    operation_id     VARCHAR(128) NOT NULL,
    payload_json     MEDIUMTEXT   NOT NULL,
    status           VARCHAR(16)  NOT NULL DEFAULT 'PENDING',
    attempts         INT          NOT NULL DEFAULT 0,
    next_attempt_at  DATETIME(6)  NULL,
    lease_owner      VARCHAR(128) NULL,
    lease_token_hash BINARY(32)   NULL,
    lease_expires_at DATETIME(6)  NULL,
    cas_version      BIGINT       NOT NULL DEFAULT 0,
    last_error       VARCHAR(512) NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (org_event_id),
    UNIQUE KEY uk_oso_event (event_id),
    KEY idx_oso_due (status, next_attempt_at, created_at),
    KEY idx_oso_tenant (tenant_id, status),
    KEY idx_oso_operation (operation_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Org-scope outbox events for the new org worker (org payload contract)';

-- ─────────────────────────────────────────────────────────────────────────────
-- 11. Durable dependency pins written atomically with each publication. Fan-out
--    targets are computed from this table (complete, reconcilable), never from
--    in-process caches. A dependent publication is fresh only while every pin
--    still matches the pinned node row exactly.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_dependency (
    dependency_id        BIGINT      NOT NULL AUTO_INCREMENT,
    dependent_tenant_id  BIGINT      NOT NULL,
    depends_on_tenant_id BIGINT      NOT NULL,
    publication_id       BIGINT      NOT NULL,
    pinned_generation    BIGINT      NOT NULL,
    pinned_revoke_fence  BIGINT      NOT NULL,
    pinned_relationship_revision BIGINT NOT NULL,
    created_at           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (dependency_id),
    UNIQUE KEY uk_osd_pin (dependent_tenant_id, depends_on_tenant_id, publication_id),
    KEY idx_osd_fanout (depends_on_tenant_id, dependent_tenant_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Durable dependency pins for fan-out and freshness validation';

-- ─────────────────────────────────────────────────────────────────────────────
-- 12. Operation idempotency ledger. operation_id is the stable business
--    identity; input_digest binds the exact canonical command bytes. Same id +
--    same digest replays the recorded outcome; same id + different digest is a
--    hard conflict (never silently widened).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_operation (
    operation_id   VARCHAR(128) NOT NULL,
    operation_kind VARCHAR(32)  NOT NULL,
    tenant_id      BIGINT       NOT NULL,
    input_digest   BINARY(32)   NOT NULL,
    outcome_json   MEDIUMTEXT   NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (operation_id),
    KEY idx_osop_tenant (tenant_id, created_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Operation-id idempotency ledger with exact input digest binding';

-- ─────────────────────────────────────────────────────────────────────────────
-- 13. Org audit trail. One row per durable mutation inside the same source
--    transaction; correlates actor, request, operation and subject.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_scope_audit (
    audit_id      BIGINT       NOT NULL AUTO_INCREMENT,
    tenant_id     BIGINT       NOT NULL,
    actor_user_id BIGINT       NOT NULL,
    actor_tenant_id BIGINT     NULL,
    action        VARCHAR(64)  NOT NULL,
    subject_kind  VARCHAR(32)  NOT NULL,
    subject_id    VARCHAR(64)  NOT NULL,
    request_id    BIGINT       NULL,
    operation_id  VARCHAR(128) NOT NULL,
    detail_json   MEDIUMTEXT   NULL,
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (audit_id),
    KEY idx_osau_tenant (tenant_id, created_at),
    KEY idx_osau_operation (operation_id),
    KEY idx_osau_request (request_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Org-scope durable audit trail correlated per operation';
