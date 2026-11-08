//! `astral-authority` executable.
//!
//! Subcommands:
//! - `serve <config.toml>` — run the authority mTLS service (leader election,
//!   fence/reservation/certification HTTP surface).
//! - `genesis <config.toml> --keys <trust-root-keys.json> [--genesis-key-file <pem/seed>]`
//!   — root-owned tool: write the explicitly signed genesis record once.
//!   The trust root digest must equal the configuration pin.
//! - `rotate-key <config.toml> --new-key <root-key.json> [--root-key-file <path>] [--new-signer-key-file <path>]`
//!   — root-owned tool: sign and apply one root-authorized key rotation.
//! - `sign-bootstrap <config.toml> --input <unsigned-artifact.json> --output <signed-artifact.json> [--root-key-file <path>]`
//!   — root-owned tool: sign the approved unsigned bootstrap preflight
//!   artifact with the ROOT key and write the signed artifact locally
//!   (offline; the artifact digest is the only output, never key material).
//! - `install-bootstrap <config.toml> --artifact <signed-artifact.json>`
//!   — root-owned tool: verify and install the signed bootstrap artifact on
//!   the quorum with leader fencing; unknown outcomes are reconciled by
//!   stable identity, never resent.
//!
//! Signing key material for `serve` comes from the configuration (file or
//! environment variable); it is never placed on the command line.

use std::path::{Path, PathBuf};

use astral_types::{AuthorityBootstrapArtifact, AuthorityRootKey, AuthorityTrustRoot};
use ed25519_dalek::SigningKey;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit_code = match run(args).await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("astral-authority: {error}");
            1
        }
    };
    std::process::exit(exit_code);
}

async fn run(args: Vec<String>) -> Result<(), String> {
    let mut iterator = args.into_iter();
    let command = iterator.next().ok_or(
        "usage: astral-authority <serve|genesis|rotate-key|sign-bootstrap|install-bootstrap> <config.toml> [options]",
    )?;
    let config_path = PathBuf::from(iterator.next().ok_or("missing <config.toml> argument")?);
    let config = astral_authority::AuthorityServiceConfig::load(&config_path)
        .map_err(|error| format!("load config {}: {error}", config_path.display()))?;
    let options: Vec<String> = iterator.collect();

    match command.as_str() {
        "serve" => astral_authority::runtime::run_serve(config).await,
        "genesis" => {
            let keys_path = option_value(&options, "--keys")
                .ok_or("genesis requires --keys <trust-root-keys.json>")?;
            let trust_root = load_trust_root_keys(&keys_path)?;
            let genesis_key = load_signing_key(
                option_value(&options, "--genesis-key-file").map(PathBuf::from),
                "ASTRAL_AUTHORITY_GENESIS_KEY",
            )?;
            let created =
                astral_authority::runtime::run_genesis(config, trust_root, &genesis_key).await?;
            if created {
                println!("genesis record created");
            } else {
                println!("genesis record already exists; nothing changed");
            }
            Ok(())
        }
        "rotate-key" => {
            let new_key_path = option_value(&options, "--new-key")
                .ok_or("rotate-key requires --new-key <root-key.json>")?;
            let new_key: AuthorityRootKey = serde_json::from_str(
                &std::fs::read_to_string(&new_key_path)
                    .map_err(|error| format!("read {new_key_path}: {error}"))?,
            )
            .map_err(|error| format!("parse new key: {error}"))?;
            new_key
                .validate()
                .map_err(|error| format!("new key invalid: {error}"))?;
            let root_key = load_signing_key(
                option_value(&options, "--root-key-file").map(PathBuf::from),
                "ASTRAL_AUTHORITY_ROOT_KEY",
            )?;
            let new_signer_seed = load_seed(
                option_value(&options, "--new-signer-key-file").map(PathBuf::from),
                "ASTRAL_AUTHORITY_NEW_SIGNER_KEY",
            )?;
            astral_authority::runtime::run_rotate_key(config, new_key, &root_key, new_signer_seed)
                .await?;
            println!("key rotation applied");
            Ok(())
        }
        "sign-bootstrap" => {
            let input = option_value(&options, "--input")
                .ok_or("sign-bootstrap requires --input <unsigned-artifact.json>")?;
            let output = option_value(&options, "--output")
                .ok_or("sign-bootstrap requires --output <signed-artifact.json>")?;
            let unsigned: AuthorityBootstrapArtifact = serde_json::from_str(
                &std::fs::read_to_string(&input)
                    .map_err(|error| format!("read {input}: {error}"))?,
            )
            .map_err(|error| format!("parse unsigned artifact: {error}"))?;
            let root_key = load_signing_key(
                option_value(&options, "--root-key-file").map(PathBuf::from),
                "ASTRAL_AUTHORITY_ROOT_KEY",
            )?;
            let digest = astral_authority::bootstrap::run_sign_bootstrap(
                &config,
                unsigned,
                &root_key,
                Path::new(&output),
            )?;
            println!("bootstrap artifact signed; artifact digest {digest}");
            println!("signed artifact written to {output}");
            Ok(())
        }
        "install-bootstrap" => {
            let artifact_path = option_value(&options, "--artifact")
                .ok_or("install-bootstrap requires --artifact <signed-artifact.json>")?;
            let artifact: AuthorityBootstrapArtifact = serde_json::from_str(
                &std::fs::read_to_string(&artifact_path)
                    .map_err(|error| format!("read {artifact_path}: {error}"))?,
            )
            .map_err(|error| format!("parse artifact: {error}"))?;
            let outcome =
                astral_authority::bootstrap::run_install_bootstrap(config, artifact).await?;
            println!(
                "bootstrap artifact {} ; operation {}",
                outcome.receipt.artifact_digest, outcome.receipt.operation_id
            );
            println!(
                "certificates installed: {}",
                outcome.receipt.certificate_hashes.len()
            );
            if outcome.newly_applied {
                println!("bootstrap applied");
            } else {
                println!("bootstrap already installed; reconciled by read-back");
            }
            Ok(())
        }
        other => Err(format!(
            "unknown command {other}; expected serve, genesis, rotate-key, sign-bootstrap, or install-bootstrap"
        )),
    }
}

fn option_value(options: &[String], flag: &str) -> Option<String> {
    options
        .iter()
        .position(|value| value == flag)
        .and_then(|index| options.get(index + 1))
        .cloned()
}

/// Load a trust-root key set definition (JSON array of AuthorityRootKey).
fn load_trust_root_keys(path: &str) -> Result<AuthorityTrustRoot, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("read {path}: {error}"))?;
    let keys: Vec<AuthorityRootKey> =
        serde_json::from_str(&text).map_err(|error| format!("parse keys: {error}"))?;
    let root = AuthorityTrustRoot {
        root_id: option_root_id_from_keys(&keys),
        keys,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_secs() as i64)
            .unwrap_or(0),
    };
    root.validate()
        .map_err(|error| format!("trust root invalid: {error}"))?;
    Ok(root)
}

/// The root id is derived from the key set: `root-<first key id>` unless the
/// operator pins one via the ASTAL_AUTHORITY_ROOT_ID environment variable.
fn option_root_id_from_keys(keys: &[AuthorityRootKey]) -> String {
    std::env::var("ASTRAL_AUTHORITY_ROOT_ID").unwrap_or_else(|_| {
        format!(
            "root-{}",
            keys.first()
                .map(|key| key.key_id.clone())
                .unwrap_or_default()
        )
    })
}

/// Load a signing key from a seed file (preferred) or an env hex seed.
fn load_signing_key(path: Option<PathBuf>, env_name: &str) -> Result<SigningKey, String> {
    let seed = load_seed(path, env_name)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_seed(path: Option<PathBuf>, env_name: &str) -> Result<[u8; 32], String> {
    if let Some(path) = path {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .map_err(|error| format!("seed {}: {error}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(format!(
                    "seed file {} must not be group/world accessible",
                    path.display()
                ));
            }
        }
        let raw = std::fs::read(&path).map_err(|error| format!("read seed: {error}"))?;
        if raw.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            return Ok(seed);
        }
        if raw.len() == 64 {
            let text = String::from_utf8(raw).map_err(|_| "seed file not utf-8".to_owned())?;
            return parse_seed_hex(text.trim());
        }
        return Err("seed file must be 32 raw bytes or 64 hex chars".to_owned());
    }
    let value = std::env::var(env_name)
        .map_err(|_| format!("set {env_name} or pass the corresponding --*-key-file option"))?;
    parse_seed_hex(value.trim())
}

fn parse_seed_hex(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("seed must be 64 lowercase hex characters".to_owned());
    }
    let mut seed = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or("invalid seed hex")? as u8;
        let low = (pair[1] as char).to_digit(16).ok_or("invalid seed hex")? as u8;
        seed[index] = (high << 4) | low;
    }
    Ok(seed)
}
