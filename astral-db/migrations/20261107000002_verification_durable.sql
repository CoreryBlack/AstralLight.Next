-- Durable cross-replica verification storage: challenges, one-shot proofs and
-- subject budgets (taskId global-authority-20261107-verification).
--
-- This migration creates tables only. It issues no code, no proof and no
-- budget. All semantics are owned by the Identity verification service:
-- - `verification_challenge`: HMAC-SHA256 code digests only — no plaintext
--   code is ever persisted. One open challenge per (target_hash, purpose);
--   supersession and one-shot consume are CAS updates performed by the
--   service inside short transactions.
-- - `verification_proof`: opaque one-shot verification proofs bound to
--   (purpose, target_hash) with an independent short TTL. Only the HMAC
--   digest of a random proof token is stored; the token itself never
--   touches the database.
-- - `verification_budget`: atomic per-window send/verify budgets keyed by
--   HMAC(subject) for the verification target and the resolved client IP.
--   Cross-replica bounds are enforced by InnoDB row locks on the primary
--   key; rejected increments are rolled back with the caller's transaction.
--
-- Delivery intentionally has NO table here: outbox/intent/lease state is
-- owned by the shared astral_common::delivery stack
-- (`DeliveryOwner` + `SqlxDeliveryIntentRepository` over `al_delivery_intent`);
-- verification only supplies purpose/target context and a stable operation id.
--
-- Machine-valued VARCHAR columns declare ascii/ascii_bin explicitly so the
-- exact column contracts are version-stable; free-text columns declare
-- utf8mb4/utf8mb4_bin. All statements are rerunnable additive DDL
-- (CREATE TABLE IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS verification_challenge (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    purpose VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_hash BINARY(32) NOT NULL,
    code_digest BINARY(32) NOT NULL,
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    closed_at DATETIME NULL,
    close_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_vch_operation (operation_id, purpose),
    KEY idx_vch_open (target_hash, purpose, closed_at, expires_at),
    KEY idx_vch_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS verification_proof (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    purpose VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_hash BINARY(32) NOT NULL,
    proof_hash BINARY(32) NOT NULL,
    challenge_id BIGINT UNSIGNED NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    consumed_ref VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_vpf_hash (proof_hash),
    KEY idx_vpf_open (purpose, target_hash, consumed_at, expires_at),
    KEY idx_vpf_expires (expires_at),
    KEY idx_vpf_challenge (challenge_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS verification_budget (
    scope VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_kind VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_hash BINARY(32) NOT NULL,
    purpose VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    window_start DATETIME NOT NULL,
    hit_count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, subject_kind, subject_hash, purpose, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
