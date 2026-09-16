//! Olm's documented message-key schedule (Olm specification; `vz:src/olm/session/chain_key.rs`,
//! `vz:src/cipher/key.rs`), implemented outside vodozemac. The spikes use it to re-authenticate a
//! message whose header they changed, which is what a malicious peer can do; it is also the seed
//! of the key-schedule oracle of design §15.2 item 3.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
        mac.update(data);
        out.copy_from_slice(&mac.finalize().into_bytes());
    }
    out
}

/// `M_{i,j} = HMAC-SHA256(C_{i,j}, 0x01)`.
pub fn message_key(chain_key: &[u8; 32]) -> [u8; 32] {
    hmac(chain_key, &[0x01])
}

/// `C_{i,j+1} = HMAC-SHA256(C_{i,j}, 0x02)`.
pub fn next_chain_key(chain_key: &[u8; 32]) -> [u8; 32] {
    hmac(chain_key, &[0x02])
}

/// `HKDF-SHA256(salt = 0x00, M, "OLM_KEYS", 80)` = AES key (32) ‖ MAC key (32) ‖ IV (16).
pub fn expand(message_key: &[u8; 32]) -> [u8; 80] {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), message_key);
    let mut out = [0u8; 80];
    if hkdf.expand(b"OLM_KEYS", &mut out).is_err() {
        out = [0u8; 80];
    }
    out
}

/// The V1 (8-byte) MAC of an encoded normal message (everything before the MAC).
pub fn truncated_mac(message_key: &[u8; 32], encoded_without_mac: &[u8]) -> [u8; 8] {
    let expanded = expand(message_key);
    let full = hmac(&expanded[32..64], encoded_without_mac);
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}
