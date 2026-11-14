//! Root-owned bootstrap CLI tooling (V7 §15.9.4 genesis contract).
//!
//! Two explicit operator actions, no automatic path anywhere:
//! - [`run_sign_bootstrap`]: sign the operator-approved unsigned preflight
//!   artifact with the ROOT key and write the signed artifact locally. This
//!   step is offline: no quorum connection, no signer binding, and nothing
//!   secret is printed (only the artifact digest).
//! - [`run_install_bootstrap`]: connect the etcd quorum, load the durable
//!   trust chain and the configured protected signer through the existing
//!   runtime assembly, acquire a one-term leadership through the shared
//!   `crate::service::leadership::EphemeralLeadership` path (real lease,
//!   lease-attached canonical leader key, production
//!   `bind_leadership_token` install), and apply the artifact via
//!   [`crate::service::AuthorityService::install_bootstrap`]. The WHOLE
//!   operation — acquire elapsed time INCLUDED — is bounded strictly below
//!   the lease TTL; the durable leadership fence refuses the final
//!   transaction past the term instead of extending it. Dropping the
//!   guard explicitly releases the term (bounded async lease revoke; the
//!   lease TTL stays the hard bound). An unknown outcome is reconciled by
//!   stable identity (operation id / artifact digest read-back); it is
//!   never resent. The in-process leader flag is never self-asserted here.
//!
//! The artifact signature is always verified at install time against the
//! ROOT-role verifying key of the attested durable registry; a caller can
//! never pass a verifying key. There is no configuration flag that triggers
//! bootstrap: both functions exist only behind explicit CLI subcommands.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;

use astral_types::AuthorityBootstrapArtifact;

use crate::config::AuthorityServiceConfig;
use crate::error::AuthorityServiceError;
use crate::service::bootstrap::AuthorityBootstrapOutcome;
use crate::service::leadership::EphemeralLeadership;
use crate::service::AuthorityService;
use crate::store::etcd::EtcdAuthorityStore;
use crate::store::AuthorityStore;

/// Sign the approved unsigned artifact with the ROOT signing key and write
/// the signed artifact to `output_path` as JSON. Returns the artifact digest.
///
/// `unsigned` must already carry the intended `root_key_id`; the signature is
/// verified at install time against the durable registry's ROOT-role key with
/// exactly that id, so signing with the wrong key fails closed at install.
pub fn run_sign_bootstrap(
    config: &AuthorityServiceConfig,
    unsigned: AuthorityBootstrapArtifact,
    root_signing_key: &SigningKey,
    output_path: &Path,
) -> Result<String, String> {
    config
        .validate()
        .map_err(|error| format!("configuration: {error}"))?;
    unsigned
        .validate_unsigned()
        .map_err(|error| format!("artifact: {error}"))?;
    if unsigned.authority_id != config.identity.authority_id {
        return Err(format!(
            "artifact authority_id {} does not match the configured authority {}",
            unsigned.authority_id, config.identity.authority_id
        ));
    }
    let mut artifact = unsigned;
    artifact
        .sign(root_signing_key)
        .map_err(|error| format!("sign bootstrap artifact: {error}"))?;
    let digest = artifact
        .artifact_digest()
        .map_err(|error| format!("artifact digest: {error}"))?;
    let encoded = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| format!("encode artifact: {error}"))?;
    // Create-new: never silently overwrite an existing signed artifact, and
    // keep the operator-controlled file private (0600) — it is the root
    // approval document and must not become group/world readable.
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            format!(
                "create {} (an existing artifact is never overwritten): {error}",
                output_path.display()
            )
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("permissions {}: {error}", output_path.display()))?;
    }
    output
        .write_all(&encoded)
        .map_err(|error| format!("write {}: {error}", output_path.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("sync {}: {error}", output_path.display()))?;
    Ok(digest)
}

/// Install the signed artifact on the quorum and return the durable outcome.
///
/// Leadership is a one-term `EphemeralLeadership`: the WHOLE operation —
/// acquire elapsed time INCLUDED — is bounded strictly below the lease TTL
/// (`deadline_seconds = ttl - 1`); the acquire itself reports its elapsed
/// time and it is deducted from the remaining install budget, never ignored.
/// Past the budget the durable leadership fence refuses the final
/// transaction (fail-closed), and the bounded install timeout surfaces the
/// outcome as unknown, which is reconciled by stable identity — never
/// resent. The term is released explicitly on EVERY exit path (awaited,
/// bounded revoke whose error is surfaced); the in-process leader flag is
/// never self-asserted here — it is published only by the verified
/// `bind_leadership_token` inside the shared acquire path.
pub async fn run_install_bootstrap(
    config: AuthorityServiceConfig,
    artifact: AuthorityBootstrapArtifact,
) -> Result<AuthorityBootstrapOutcome, String> {
    config
        .validate()
        .map_err(|error| format!("configuration: {error}"))?;
    artifact
        .validate()
        .map_err(|error| format!("artifact: {error}"))?;
    let store = Arc::new(
        EtcdAuthorityStore::connect(
            &config.quorum.endpoints,
            config.quorum.tls_enabled,
            config.quorum.tls_ca_path.as_deref(),
            config.quorum.tls_client_cert_path.as_deref(),
            config.quorum.tls_client_key_path.as_deref(),
            config.quorum.tls_domain_name.as_deref(),
        )
        .await
        .map_err(|error| format!("quorum store: {error}"))?,
    );
    let dyn_store: Arc<dyn AuthorityStore> = store.clone();
    let (_trust_root, _frontier, signer) =
        crate::runtime::load_trust_root_and_signer(&config, &dyn_store)
            .await
            .map_err(|error| format!("trust chain: {error}"))?;
    let service = Arc::new(AuthorityService::new(config.clone(), dyn_store, signer));

    // The operation deadline is strictly below the lease TTL; the acquire
    // phase may consume at most the whole budget (its internal loop never
    // exceeds it and self-cleans the lease on any failure).
    let ttl_seconds = config.quorum.lease_ttl_seconds.max(5);
    let deadline_seconds = (ttl_seconds - 1).max(1);
    let total_budget = Duration::from_secs(deadline_seconds as u64);
    let instance = uuid::Uuid::new_v4().simple().to_string();

    let (leadership, acquire_elapsed) = EphemeralLeadership::acquire(
        &service,
        store.as_ref(),
        &instance,
        ttl_seconds,
        deadline_seconds,
        total_budget,
    )
    .await
    .map_err(|error| format!("leadership acquisition: {error}"))?;

    // Deduct the acquire elapsed time from the install budget — never
    // ignored.
    let remaining_budget = total_budget.saturating_sub(acquire_elapsed);
    let outcome =
        match tokio::time::timeout(remaining_budget, service.install_bootstrap(&artifact)).await {
            // The bounded deadline expired mid-install: the durable outcome
            // cannot be observed from here. Reconcile by stable identity;
            // nothing is resent.
            Err(_expired) => {
                reconcile_after_unknown(
                    &service,
                    &artifact,
                    "operation deadline exceeded mid-install",
                )
                .await
            }
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(AuthorityServiceError::UnknownOutcome { operation_hint })) => {
                reconcile_after_unknown(
                    &service,
                    &artifact,
                    &format!("unknown store outcome (hint: {operation_hint})"),
                )
                .await
            }
            Ok(Err(error)) => Err(error.to_string()),
        };

    // Explicit release on EVERY exit path (awaited, bounded, error surfaced).
    // A failed revoke never turns a durable install into a failure, but it
    // is always operator-visible; the term stays bounded by the lease TTL.
    match leadership.release().await {
        Ok(()) => outcome,
        Err(release_error) => match outcome {
            Ok(installed) => {
                eprintln!(
                    "warning: leadership release failed (the term remains bounded by the \
                     lease TTL): {release_error}"
                );
                Ok(installed)
            }
            Err(install_error) => Err(format!(
                "{install_error}; leadership release also failed: {release_error}"
            )),
        },
    }
}

/// Reconcile an unknown install outcome by stable identity (operation id and
/// artifact digest read-back). Read-only: never retries, never re-issues.
async fn reconcile_after_unknown(
    service: &AuthorityService,
    artifact: &AuthorityBootstrapArtifact,
    cause: &str,
) -> Result<AuthorityBootstrapOutcome, String> {
    match service.reconcile_bootstrap(artifact).await {
        Ok(Some(outcome)) => {
            eprintln!(
                "bootstrap install outcome was unknown ({cause}); \
                 reconciled by operation id read-back"
            );
            Ok(outcome)
        }
        Ok(None) => Err(format!(
            "bootstrap install outcome is unknown ({cause}); \
             no durable record was found; reconcile by operation id before \
             any new attempt"
        )),
        Err(error) => Err(format!(
            "bootstrap install outcome is unknown ({cause}); read-back failed: {error}"
        )),
    }
}
