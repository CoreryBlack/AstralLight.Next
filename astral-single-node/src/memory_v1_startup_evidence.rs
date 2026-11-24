//! memory—v1: Read boot evidence once, with the public key pinned separately.

use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use astral_authorization_root::memory_v1_adoption::startup::{
    AuthenticatedStartupEvidence, MAX_STARTUP_EVIDENCE_BYTES,
};

const PUBLIC_KEY_ENV: &str = "ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_PUBLIC_KEY";
const ENVELOPE_ENV: &str = "ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_FILE";

// memory—v1: The service gets only an out-of-band public key. There is no
// signer key, trust-on-first-use, default key, or trust in envelope metadata.
pub(super) fn load(get: impl Fn(&str) -> Option<String>) -> Result<AuthenticatedStartupEvidence> {
    let key = get(PUBLIC_KEY_ENV)
        .ok_or_else(|| anyhow!("{PUBLIC_KEY_ENV} must pin the independent startup issuer"))?;
    let mut pinned = [0; 32];
    hex::decode_to_slice(&key, &mut pinned)
        .ok()
        .filter(|_| hex::encode(pinned) == key && pinned != [0; 32])
        .ok_or_else(|| {
            anyhow!("{PUBLIC_KEY_ENV} must be a nonzero lowercase hex Ed25519 public key")
        })?;
    let path = get(ENVELOPE_ENV)
        .ok_or_else(|| anyhow!("{ENVELOPE_ENV} must name the signed startup evidence"))?;
    let path = Path::new(&path);
    if !path.is_absolute() {
        bail!("{ENVELOPE_ENV} must be absolute");
    }
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_STARTUP_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read signed startup evidence")?;
    let evidence = AuthenticatedStartupEvidence::authenticate(&pinned, &bytes)?;
    evidence.check_current_window()?;
    Ok(evidence)
}

// memory—v1: Do not follow a symlink or block opening a replaced FIFO.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_regular(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{open, Mode, OFlags};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("open signed startup evidence")?;
    let file = std::fs::File::from(fd);
    if !file
        .metadata()
        .context("inspect signed startup evidence")?
        .is_file()
    {
        bail!("the signed startup evidence must be a regular file");
    }
    Ok(file)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_regular(_path: &Path) -> Result<std::fs::File> {
    bail!("secure startup evidence file handling is not supported on this host")
}
