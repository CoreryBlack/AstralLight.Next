# SDK Identity Mapping Migration

This runbook accompanies `20261005000001_integration_identity_mapping.sql`. The implementation task does not execute it and does not authorize a production source mutation.

## Preflight

- Confirm the target database and approved `runId`/operator, stop integration admission, and retain all mapping and audit evidence.
- Verify existing `platform_user`, `identity_card`, tenant/domain, session, authorization evidence and audit contracts on the target version.
- Inspect the migration definitions and existing integration tables. This migration uses `CREATE TABLE`, not `IF NOT EXISTS`; an existing table requires reconciliation before apply, and a conflicting shape must fail the explicit integration schema check.
- Back up affected schema/data and verify restoration or a forward-fix on an isolated rehearsal database. Do not alter historical migrations.
- Prepare exact application/issuer/manifest/tenant allowlists and application public keys. Decision signing private material must come from an environment/secret store, not a tracked configuration.

## Apply and Postcondition

Apply the additive migration through the approved Rust migration entry. Verify binary-exact subject uniqueness, unsigned monotonic revision, operation ledger uniqueness and all necessary indexes/engines. Mapping writes must include a stable operation ID, validated actor and same-transaction audit evidence.

Run `validate_integration_mapping_schema` and request-guard schema validation before enabling the feature. Create only approved mappings to existing active platform users/identity cards; registration does not issue grants or user cards. Verify mapping create/replay/conflict, disable/revoke/CAS, session/eligibility and audit correlation in the isolated environment.

Enable Identity mapping management and remote SDK admission only after the independent gates pass. The relevant runtime switches are default-off:

```text
ASTRAL_SDK_IDENTITY_MAPPING_ENABLED
ASTRAL_SDK_INTEGRATION_ENABLED
ASTRAL_SDK_APPLICATIONS_JSON
ASTRAL_SDK_DECISION_KEY_ID
ASTRAL_SDK_DECISION_SEED_HEX
```

The SDK requires HTTPS in normal operation. Loopback-only HTTP is an explicit test option and is not a deployment mode.

## Recovery

Disable integration admission, stop new mapping mutations, and reconcile operation IDs, mapping revision/status and audit records before retrying any unknown write. A failed or interrupted COMMIT must remain unknown until durable state is inspected. Do not infer failure from a missing client response.

Prefer a forward-fix that preserves mapping/operation/audit rows. Do not delete revoked mappings to re-enable the same external subject, rewrite the target user, clear nonce guards, restore an old ALLOW response or bypass the current session/projection/fence checks. Rollback of code means feature-off and retained evidence, not a return to role-based authorization.

## Acceptance Status

Real migration, backfill, MySQL/MQ, crash, multi-node and deployment acceptance are not proven by compiling the SDK or by its mock tests. Record exact cwd, commands, environment, exit codes, ignored/SKIP tests and durable postconditions for each approved rehearsal.
