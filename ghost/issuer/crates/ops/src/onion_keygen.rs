//! `onion-keygen` (design §19.10 point 3, §19.17 point 1): a Tor v3 onion service key set for a
//! new `HiddenServiceDir`, generated before the service first starts so the slot table of the
//! Entitlement Schedule can name the real onion (Tor loads an existing key set instead of
//! generating one).
//!
//! ```text
//! hs_ed25519_secret_key := "== ed25519v1-secret: type0 ==" NUL-padded to 32 bytes
//!                          || expanded secret key (64): SHA-512(seed), bytes 0..32 clamped
//! hs_ed25519_public_key := "== ed25519v1-public: type0 ==" NUL-padded to 32 bytes
//!                          || Ed25519 public key (32)
//! hostname              := "<56 base32>.onion" "\n"
//! ```
//!
//! Sources. C Tor: `src/lib/crypt_ops/crypto_format.c` (`crypto_write_tagged_contents_to_file`:
//! the header `"== %s: %s =="` NUL-padded to 32 bytes, then the key bytes);
//! `src/lib/crypt_ops/crypto_ed25519.c` (`ed25519_seckey_write_to_file` with the tags
//! `ed25519v1-secret` / `type0`, `ed25519_pubkey_write_to_file` with `ed25519v1-public` /
//! `type0`); `src/ext/ed25519/ref10/keypair.c` (`ed25519_ref10_seckey_expand`: SHA-512 of the
//! 32-byte seed, then `sk[0] &= 248; sk[31] &= 63; sk[31] |= 64`); `src/feature/hs/hs_service.c`
//! (the key files `hs_ed25519_secret_key` and `hs_ed25519_public_key`; `write_address_to_file`
//! writes `"<address>.onion\n"` to `hostname`). The address itself is rend-spec-v3 §6
//! [ONIONADDRESS] (`ghost_entitlement::onion::hostname`). Arti reads the same two key files
//! (`tor-keymgr` 0.46.0, `keystore/ctor/service.rs`: the tags above, then 64 bytes for
//! `ExpandedKeypair::from_secret_key_bytes` and 32 for the public key); the tests load every
//! generated set there and check a C Tor-generated set shipped with it.

use ghost_entitlement::onion;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha512};

use crate::args::Flags;
use crate::input::{input_refused, io_error};
use crate::report::{Code, Field, Line, Sink};
use crate::{output, Failure};

pub const SECRET_KEY_FILE: &str = "hs_ed25519_secret_key";
pub const PUBLIC_KEY_FILE: &str = "hs_ed25519_public_key";
pub const HOSTNAME_FILE: &str = "hostname";
/// The files of one key set, in the order they are written.
pub const FILES: [&str; 3] = [SECRET_KEY_FILE, PUBLIC_KEY_FILE, HOSTNAME_FILE];

/// Length of the tagged-file header.
pub const HEADER_LEN: usize = 32;
const SECRET_TAG: &[u8] = b"== ed25519v1-secret: type0 ==";
const PUBLIC_TAG: &[u8] = b"== ed25519v1-public: type0 ==";
pub const SECRET_KEY_FILE_LEN: usize = HEADER_LEN + 64;
pub const PUBLIC_KEY_FILE_LEN: usize = HEADER_LEN + 32;

const FLAGS: [&str; 1] = ["hs-dir"];

/// The 32-byte header of a tagged key file: the tag, NUL-padded.
fn header(tag: &[u8]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..tag.len()].copy_from_slice(tag);
    h
}

/// The header of `hs_ed25519_secret_key`.
pub fn secret_header() -> [u8; HEADER_LEN] {
    header(SECRET_TAG)
}

/// The header of `hs_ed25519_public_key`.
pub fn public_header() -> [u8; HEADER_LEN] {
    header(PUBLIC_TAG)
}

/// The three files of one onion service key set. The secret key file is wiped when the set is
/// dropped; `Debug` never shows it.
pub struct KeySet {
    pub secret_key_file: [u8; SECRET_KEY_FILE_LEN],
    pub public_key_file: [u8; PUBLIC_KEY_FILE_LEN],
    pub hostname_file: String,
    pub public_key: [u8; 32],
}

impl Drop for KeySet {
    fn drop(&mut self) {
        self.secret_key_file.fill(0);
    }
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySet(redacted)")
    }
}

/// The key set of the Ed25519 seed `seed`, as C Tor writes it.
pub fn key_set(seed: &[u8; 32]) -> KeySet {
    let mut expanded: [u8; 64] = Sha512::digest(seed).into();
    expanded[0] &= 248;
    expanded[31] &= 63;
    expanded[31] |= 64;
    let public_key = ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes();
    let mut secret_key_file = [0u8; SECRET_KEY_FILE_LEN];
    secret_key_file[..HEADER_LEN].copy_from_slice(&secret_header());
    secret_key_file[HEADER_LEN..].copy_from_slice(&expanded);
    expanded.fill(0);
    let mut public_key_file = [0u8; PUBLIC_KEY_FILE_LEN];
    public_key_file[..HEADER_LEN].copy_from_slice(&public_header());
    public_key_file[HEADER_LEN..].copy_from_slice(&public_key);
    KeySet {
        secret_key_file,
        public_key_file,
        hostname_file: format!("{}\n", onion::hostname(&public_key)),
        public_key,
    }
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &FLAGS)?;
    let dir = flags.path("hs-dir")?;
    // Refuse before drawing a key if any file of a set exists: a key set is never replaced.
    if FILES.iter().any(|name| dir.join(name).exists()) {
        return Err(io_error("hs-dir", "exists"));
    }
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| Failure::refused(input_refused("hs-dir", "random")))?;
    let keys = key_set(&seed);
    seed.fill(0);
    output::write_onion_keys(&dir, &keys, "hs-dir")?;
    // The host name is the base32 form of this key (`hostname` in the directory).
    sink.emit(Line::new(Code::OnionKeyCreated).hex(Field::Public, &keys.public_key));
    Ok(())
}
