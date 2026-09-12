//! The only module of the operator tools that writes files (design §14.1, §19.17; ADR-26 point 7).
//! Its named outputs: the custody secret and the schedule key (`keygen`), public key entries and
//! sealed key files (`keygen`), the key load file (`keys-seal`), the signed schedule
//! (`schedule-sign`) and Tor onion service key sets (`onion-keygen`). Every file is created new
//! (an existing file is never replaced), written in full, flushed to disk, and on Unix readable by
//! its owner only.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ghost_entitlement::schedule::KeyContent;
use ghost_entitlement::Kind;
use ghost_issuer::custody::{self, CustodySecret};

use crate::input::io_error;
use crate::onion_keygen::{self, KeySet};
use crate::public_entry;
use crate::Failure;

fn create_new(path: &Path, bytes: &[u8], flag: &'static str) -> Result<(), Failure> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => io_error(flag, "exists"),
        _ => io_error(flag, "write"),
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| io_error(flag, "write"))
}

/// Creates an output directory (and its parents) if it does not exist.
pub fn create_dir(path: &Path, flag: &'static str) -> Result<(), Failure> {
    std::fs::create_dir_all(path).map_err(|_| io_error(flag, "create-dir"))
}

pub fn write_custody_secret(
    path: &Path,
    secret: &CustodySecret,
    flag: &'static str,
) -> Result<(), Failure> {
    create_new(path, secret.as_bytes(), flag)
}

pub fn write_schedule_key(path: &Path, seed: &[u8; 32], flag: &'static str) -> Result<(), Failure> {
    create_new(path, seed, flag)
}

pub fn write_sealed_key(
    dir: &Path,
    kind: Kind,
    epoch: u64,
    sealed: &[u8],
    flag: &'static str,
) -> Result<(), Failure> {
    create_new(
        &dir.join(custody::sealed_file_name(kind, epoch)),
        sealed,
        flag,
    )
}

pub fn write_public_entry(
    dir: &Path,
    entry: &KeyContent,
    flag: &'static str,
) -> Result<(), Failure> {
    let path = dir.join(public_entry::file_name(entry.kind, entry.epoch));
    create_new(&path, public_entry::encode(entry).as_bytes(), flag)
}

/// Writes the key load file, then wipes `load` (every `k_seal` of the window in plaintext), also
/// when the write was refused.
pub fn write_seal_load(path: &Path, load: &mut [u8], flag: &'static str) -> Result<(), Failure> {
    let written = create_new(path, load, flag);
    load.fill(0);
    written
}

pub fn write_schedule(path: &Path, schedule: &[u8], flag: &'static str) -> Result<(), Failure> {
    create_new(path, schedule, flag)
}

/// Creates a Tor `HiddenServiceDir` (and its parents) if it does not exist; on Unix readable by
/// its owner only, as Tor requires of the directory.
fn create_private_dir(path: &Path, flag: &'static str) -> Result<(), Failure> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| io_error(flag, "create-dir"))
}

/// Writes an onion service key set into `dir`: the secret key first and the host name last, so a
/// present `hostname` means a complete set.
pub fn write_onion_keys(dir: &Path, keys: &KeySet, flag: &'static str) -> Result<(), Failure> {
    create_private_dir(dir, flag)?;
    create_new(
        &dir.join(onion_keygen::SECRET_KEY_FILE),
        &keys.secret_key_file,
        flag,
    )?;
    create_new(
        &dir.join(onion_keygen::PUBLIC_KEY_FILE),
        &keys.public_key_file,
        flag,
    )?;
    create_new(
        &dir.join(onion_keygen::HOSTNAME_FILE),
        keys.hostname_file.as_bytes(),
        flag,
    )
}
