//! The only module of the operator tools that writes files (design §14.1, §19.17; ADR-26 point 7).
//! Its named outputs: the custody secret, the schedule key and the ops key (`keygen`), public key
//! entries and sealed key files (`keygen`), the key load file (`keys-seal`), the signed schedule
//! (`schedule-sign`), Tor onion service key sets (`onion-keygen`), the payout workstation's ledger
//! (`payout-check` creates it; `payout-check`, `payout-entry` and `payout-ack` append records) and
//! acknowledgement files (`payout-ack`). Every file but the ledger is created new (an existing
//! file is never replaced); the ledger is only ever appended to. Each write is complete and
//! flushed to disk, and on Unix a created file is readable by its owner only.

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

/// The issuer's ops key seed (it signs payout batch files, design §9.5).
pub fn write_ops_key(path: &Path, seed: &[u8; 32], flag: &'static str) -> Result<(), Failure> {
    create_new(path, seed, flag)
}

/// Creates the payout ledger with its first records.
pub fn create_ledger(path: &Path, text: &str, flag: &'static str) -> Result<(), Failure> {
    create_new(path, text.as_bytes(), flag)
}

/// Appends records to an existing payout ledger and flushes them to disk.
pub fn append_ledger(path: &Path, text: &str, flag: &'static str) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|_| io_error(flag, "write"))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| io_error(flag, "write"))
}

/// A payout acknowledgement file for the issuer (design §9.5 step 4).
pub fn write_ack(path: &Path, bytes: &[u8], flag: &'static str) -> Result<(), Failure> {
    create_new(path, bytes, flag)
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
