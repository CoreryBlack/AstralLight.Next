-- Authorization projection PARTITION lease table (multi-tenant redesign Phase 1).
--
-- Design: Docs/架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md §3.3.
--
-- The partitioned scheduler replaces tenant-serial polling with
-- (tenant_id, aggregate_type, aggregate_id) partitions. Each partition grants
-- ONE worker an exclusive, renewable lease so that:
--   - per-partition publication stays strictly serial (the existing pointer
--     CAS already forces this; the lease makes the scheduler honor it), and
--   - different partitions drain fully in parallel.
--
-- Takeover contract (fail-closed):
--   - A fresh partition is claimed by plain INSERT (generation starts at 1).
--   - An existing row may only transition under
--       lease_expires_at <= UTC_TIMESTAMP()          (expired -> reclaim)
--       OR (lease_owner + lease_token_hash match)    (self -> renew)
--     every transition bumps generation and cas_version.
--   - A live lease held by another owner matches NOTHING: the loser observes
--     zero affected rows and must skip the partition. No lock waits, no
--     retries, no hot loop.
--
-- The lease is an INTERNAL scheduling primitive only: it never authorizes a
-- source mutation, never substitutes for the per-event delta lease, and never
-- widens authorization. Release is best-effort; expiry is the safety net
-- (crashed workers reclaim after lease_expires_at).generation/token fencing
-- follows the same discipline as the delta event lease (owner + token hash
-- matched by value, BINARY(32) digest).
--
-- Additive table only; no existing table, row, or column changes. Default-off
-- at runtime: the partitioned scheduler activates only under the explicit
-- `scheduling_mode = partitioned` projector configuration.

CREATE TABLE authorization_projection_partition_lease (
    tenant_id       BIGINT       NOT NULL,
    aggregate_type  VARCHAR(32)  NOT NULL,
    aggregate_id    BIGINT       NOT NULL,
    lease_owner     VARCHAR(128) NOT NULL,
    lease_token_hash BINARY(32)  NOT NULL,
    lease_expires_at DATETIME(6) NOT NULL,
    generation      BIGINT       NOT NULL DEFAULT 1,
    cas_version     BIGINT       NOT NULL DEFAULT 0,
    acquired_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_renewed_at DATETIME(6)  NULL,
    PRIMARY KEY (tenant_id, aggregate_type, aggregate_id),
    KEY idx_appl_expiry (lease_expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
