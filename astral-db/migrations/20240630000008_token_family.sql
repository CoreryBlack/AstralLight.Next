-- Phase 8: Token family and canonical auth session contract.
--
-- Fresh databases get the canonical platform_v4 schema below.  Existing
-- installations are repaired by 20260714000001_auth_family_schema_contract.sql;
-- that migration deliberately converts legacy VARCHAR business identifiers to
-- the BIGINT family_id PK plus unique family_key contract before adding FKs.

CREATE TABLE IF NOT EXISTS auth_token_family (
    family_id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    family_key VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    revoked_reason VARCHAR(512) DEFAULT NULL,
    metadata_json JSON DEFAULT NULL,
    PRIMARY KEY (family_id),
    UNIQUE KEY uk_atf_family_key (family_key),
    KEY idx_atf_status (status),
    KEY idx_atf_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The family FK is added by the canonical forward migration after legacy
-- VARCHAR family identifiers have been converted to BIGINT. This ordering is
-- required for existing installations and keeps this historical migration
-- safe when its table already exists.