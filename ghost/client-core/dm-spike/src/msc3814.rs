//! GHOST's own encoder of the MSC3814 dehydrated-device pickle (design §2.2), written from the
//! layout, not from vodozemac's types:
//!
//! ```text
//! u32_be(version = 1) || curve25519_secret(32) || ed25519_seed(32)
//!     || u32_be(one-time key count = 0) || u8(fallback present) || [fallback_secret(32)]
//! ```
//!
//! sealed with ChaCha20-Poly1305 for `Account::from_dehydrated_device`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

pub const PICKLE_VERSION: u32 = 1;

/// The secrets an Olm account needs: the identity, the unused signing seed and at most one
/// fallback key (the generation a PreKey message names).
#[derive(Clone)]
pub struct DehydratedSecrets {
    pub curve25519: [u8; 32],
    pub ed25519_seed: [u8; 32],
    pub fallback: Option<[u8; 32]>,
}

pub fn encode(secrets: &DehydratedSecrets) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 32 + 4 + 1 + 32);
    out.extend_from_slice(&PICKLE_VERSION.to_be_bytes());
    out.extend_from_slice(&secrets.curve25519);
    out.extend_from_slice(&secrets.ed25519_seed);
    out.extend_from_slice(&0u32.to_be_bytes());
    match &secrets.fallback {
        None => out.push(0),
        Some(key) => {
            out.push(1);
            out.extend_from_slice(key);
        }
    }
    out
}

/// Strict decoder for the layout above (tests only compare with it).
pub fn decode(bytes: &[u8]) -> Option<DehydratedSecrets> {
    if bytes.len() != 73 && bytes.len() != 105 {
        return None;
    }
    if bytes[0..4] != PICKLE_VERSION.to_be_bytes() || bytes[68..72] != [0, 0, 0, 0] {
        return None;
    }
    let mut curve25519 = [0u8; 32];
    curve25519.copy_from_slice(&bytes[4..36]);
    let mut ed25519_seed = [0u8; 32];
    ed25519_seed.copy_from_slice(&bytes[36..68]);
    let fallback = match (bytes[72], bytes.len()) {
        (0, 73) => None,
        (1, 105) => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[73..105]);
            Some(key)
        }
        _ => return None,
    };
    Some(DehydratedSecrets {
        curve25519,
        ed25519_seed,
        fallback,
    })
}

pub fn seal(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(*nonce);
    cipher.encrypt(&nonce, plaintext).unwrap_or_default()
}

pub fn open(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(*nonce);
    cipher.decrypt(&nonce, ciphertext).ok()
}
