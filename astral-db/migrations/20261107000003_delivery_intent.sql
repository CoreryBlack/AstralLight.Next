-- Durable delivery intent rows for the production delivery subsystem
-- (astral-common/src/delivery). Rows carry intent METADATA ONLY:
--
--   * message bodies are never persisted (in-memory handoff only);
--   * EPHEMERAL_SECRET payloads (password reset tokens, OTP codes) record
--     body_sha256 = NULL — no unsalted digest of raw secret material is ever
--     stored, so the table cannot become an offline brute-force oracle;
--   * the row still blocks UNKNOWN replay across replicas/restarts via the
--     CAS lease/generation columns: a lost attempt lands in IN_DOUBT and
--     only explicit reconciliation may settle it.
--
-- Message id is the stable identity (uuid v5 of the caller operation id or
-- uuid v7); operation_id correlates the intent to its owning operation
-- (e.g. monitor:notification-test:<id>, password-reset:<uuid>).
--
-- The statement is conditional so an interrupted additive batch can be rerun
-- by the explicit migration job without rewriting historical rows.
SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'al_delivery_intent'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'CREATE TABLE al_delivery_intent (\
       id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
       message_id VARCHAR(64) NOT NULL,\
       operation_id VARCHAR(192) NOT NULL,\
       channel_kind VARCHAR(16) NOT NULL,\
       recipient VARCHAR(2048) NOT NULL,\
       subject VARCHAR(512) NULL,\
       body_sha256 CHAR(64) NULL,\
       payload_class VARCHAR(16) NOT NULL DEFAULT ''STANDARD'',\
       state VARCHAR(16) NOT NULL DEFAULT ''QUEUED'',\
       attempts INT NOT NULL DEFAULT 0,\
       max_attempts INT NOT NULL DEFAULT 3,\
       generation BIGINT NOT NULL DEFAULT 0,\
       lease_owner VARCHAR(128) NULL,\
       lease_expires_at DATETIME(6) NULL,\
       provider_reference VARCHAR(256) NULL,\
       last_detail VARCHAR(512) NULL,\
       settled_at DATETIME(6) NULL,\
       created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),\
       updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),\
       PRIMARY KEY (id),\
       UNIQUE KEY uq_delivery_intent_message (message_id),\
       KEY idx_delivery_intent_operation (operation_id),\
       KEY idx_delivery_intent_state (state, lease_expires_at)\
     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
