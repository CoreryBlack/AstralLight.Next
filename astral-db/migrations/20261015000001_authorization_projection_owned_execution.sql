-- Aggregate-owned execution is default-off. Stop and reconcile all legacy
-- publishers before enabling it; binaries using the two protocols must not mix.
-- Each additive DDL is independently guarded for explicit forward recovery.
SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_projection_partition_lease' AND column_name = 'execution_epoch') = 0,
    'ALTER TABLE authorization_projection_partition_lease ADD COLUMN execution_epoch BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_projection_partition_lease' AND column_name = 'active_delta_event_id') = 0,
    'ALTER TABLE authorization_projection_partition_lease ADD COLUMN active_delta_event_id BIGINT NULL',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_projection_partition_lease' AND column_name = 'active_delta_token_hash') = 0,
    'ALTER TABLE authorization_projection_partition_lease ADD COLUMN active_delta_token_hash BINARY(32) NULL',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_delta_event' AND column_name = 'execution_attempts') = 0,
    'ALTER TABLE authorization_delta_event ADD COLUMN execution_attempts BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_delta_event' AND column_name = 'execution_failures') = 0,
    'ALTER TABLE authorization_delta_event ADD COLUMN execution_failures BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_delta_event' AND column_name = 'execution_episode_token_hash') = 0,
    'ALTER TABLE authorization_delta_event ADD COLUMN execution_episode_token_hash BINARY(32) NULL',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_delta_event' AND column_name = 'failure_recorded_token_hash') = 0,
    'ALTER TABLE authorization_delta_event ADD COLUMN failure_recorded_token_hash BINARY(32) NULL',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_delta_event' AND column_name = 'execution_accounting_version') = 0,
    'ALTER TABLE authorization_delta_event ADD COLUMN execution_accounting_version INT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;

-- Historical claims cannot be reconstructed as proven execution failures.
-- Conservatively retain their full budget cost once; never reset old attempts.
UPDATE authorization_delta_event
SET execution_attempts = GREATEST(execution_attempts, attempts),
    execution_failures = GREATEST(execution_failures, attempts),
    execution_accounting_version = 1
WHERE execution_accounting_version = 0
  AND attempts >= 0
  AND execution_attempts >= 0
  AND execution_failures >= 0
  AND execution_failures <= execution_attempts;
ALTER TABLE authorization_delta_event
    ALTER COLUMN execution_accounting_version SET DEFAULT 1;

SET @owned_execution_ddl = IF(
    (SELECT COUNT(*) FROM information_schema.statistics WHERE CAST(table_schema AS BINARY) = CAST(DATABASE() AS BINARY) AND table_name = 'authorization_projection_partition_lease' AND index_name = 'idx_appl_active_delta_event') = 0,
    'ALTER TABLE authorization_projection_partition_lease ADD KEY idx_appl_active_delta_event (active_delta_event_id)',
    'SELECT 1'
);
PREPARE owned_execution_stmt FROM @owned_execution_ddl;
EXECUTE owned_execution_stmt;
DEALLOCATE PREPARE owned_execution_stmt;
