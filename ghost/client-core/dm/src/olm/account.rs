//! Throwaway Olm accounts from GHOST-held secrets (design §2.2, §8.1; evidence V-1).
//!
//! vodozemac has no constructor from given identity keys, and GHOST's identity is seed-derived
//! (§3.1, C-1). The only specified and versioned public route into an `Account` is
//! `Account::from_dehydrated_device`, which decrypts a ChaCha20-Poly1305 blob holding the MSC3814
//! pickle. GHOST therefore encodes that pickle itself:
//!
//! ```text
//! u32_be(version = 1) || curve25519_secret(32) || ed25519_seed(32)
//!     || u32_be(one-time key count = 0) || u8(fallback present) || [fallback_secret(32)]
//! ```
//!
//! 105 bytes with a fallback key, 73 without (V-1: byte for byte against `to_dehydrated_device`
//! on 0.11.0 and 0.10.0, on 64 of 64 exports). It is sealed under a **fresh random key** that
//! never leaves this module and dies with the call, so the pickle exists only as ciphertext in a
//! buffer this function owns.
//!
//! `Account::from_pickle` (vodozemac's own undocumented serde layout) and
//! `from_decrypted_dehydrated_device` (`#[doc(hidden)]`, "public for fuzzing") are **not used**.
//!
//! An account is built for exactly one call and dropped: it holds no session and is never
//! persisted, so the "at most two fallback key slots" limit of the library does not bind GHOST —
//! every generation's fallback secret is GHOST state (`olm_prekey_gen.secrets_env`) and the
//! account built for a PreKey message holds exactly the generation that message names (§2.2).

use crate::derive::{MessagingBranch, OlmSecret, SECRET_BYTES};
use crate::pq;
use crate::result::{DmCode, DmResult};
use vodozemac::olm::Account;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The MSC3814 pickle version GHOST writes and vodozemac accepts.
pub const PICKLE_VERSION: u32 = 1;
/// Encoded pickle length without a fallback key.
pub const PICKLE_LEN_WITHOUT_FALLBACK: usize = 4 + 32 + 32 + 4 + 1;
/// Encoded pickle length with one fallback key.
pub const PICKLE_LEN_WITH_FALLBACK: usize = PICKLE_LEN_WITHOUT_FALLBACK + 32;

/// The secrets one throwaway account is built from: the seed-derived Olm identity, the seed-derived
/// signing seed the layout requires and never uses, and at most one fallback secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccountSecrets {
    curve25519: [u8; SECRET_BYTES],
    ed25519_seed: [u8; SECRET_BYTES],
    fallback: Option<[u8; SECRET_BYTES]>,
}

impl AccountSecrets {
    /// The own identity without a fallback key: the `sessionOutbound` shape.
    pub fn identity(identity: &OlmSecret, signing_seed: &OlmSecret) -> Self {
        Self {
            curve25519: *identity.as_bytes(),
            ed25519_seed: *signing_seed.as_bytes(),
            fallback: None,
        }
    }

    /// The own identity holding exactly one generation's fallback secret: the `sessionInbound`
    /// shape, where the PreKey message names the generation whose secret is loaded.
    pub fn with_fallback(
        identity: &OlmSecret,
        signing_seed: &OlmSecret,
        fallback: [u8; SECRET_BYTES],
    ) -> Self {
        Self {
            curve25519: *identity.as_bytes(),
            ed25519_seed: *signing_seed.as_bytes(),
            fallback: Some(fallback),
        }
    }

    /// Derives both seed-level secrets of the DM context from the MESSAGING branch (§3.1).
    pub fn from_branch(m: &MessagingBranch, fallback: Option<[u8; SECRET_BYTES]>) -> Self {
        let identity = crate::derive::derive_olm_identity(m);
        let signing_seed = crate::derive::derive_olm_account_signing(m);
        Self {
            curve25519: *identity.as_bytes(),
            ed25519_seed: *signing_seed.as_bytes(),
            fallback,
        }
    }

    /// The X25519 public identity key these secrets carry, computed outside vodozemac.
    pub fn identity_public(&self) -> [u8; SECRET_BYTES] {
        crate::derive::olm_identity_public(&OlmSecret::from_bytes(self.curve25519))
    }

    /// The MSC3814 pickle bytes of §2.2. The buffer is the caller's to zeroise.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PICKLE_LEN_WITH_FALLBACK);
        out.extend_from_slice(&PICKLE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.curve25519);
        out.extend_from_slice(&self.ed25519_seed);
        out.extend_from_slice(&0u32.to_be_bytes());
        match &self.fallback {
            None => out.push(0),
            Some(secret) => {
                out.push(1);
                out.extend_from_slice(secret);
            }
        }
        out
    }
}

/// Decodes the layout [`AccountSecrets::encode`] writes. Used by the encoder check of §15.2 item 4,
/// which decrypts vodozemac's own `to_dehydrated_device` output and compares field by field.
pub fn decode_pickle(bytes: &[u8]) -> DmResult<AccountSecrets> {
    if bytes.len() != PICKLE_LEN_WITHOUT_FALLBACK && bytes.len() != PICKLE_LEN_WITH_FALLBACK {
        return Err(DmCode::StateCorrupt);
    }
    if bytes[0..4] != PICKLE_VERSION.to_be_bytes() || bytes[68..72] != [0, 0, 0, 0] {
        return Err(DmCode::StateCorrupt);
    }
    let mut curve25519 = [0u8; SECRET_BYTES];
    curve25519.copy_from_slice(&bytes[4..36]);
    let mut ed25519_seed = [0u8; SECRET_BYTES];
    ed25519_seed.copy_from_slice(&bytes[36..68]);
    let fallback = match (bytes[72], bytes.len()) {
        (0, PICKLE_LEN_WITHOUT_FALLBACK) => None,
        (1, PICKLE_LEN_WITH_FALLBACK) => {
            let mut secret = [0u8; SECRET_BYTES];
            secret.copy_from_slice(&bytes[73..]);
            Some(secret)
        }
        _ => return Err(DmCode::StateCorrupt),
    };
    Ok(AccountSecrets {
        curve25519,
        ed25519_seed,
        fallback,
    })
}

/// Builds the throwaway `Account` of §2.2 and hands it to `use_it`, which is the only code that
/// ever sees it: the account, the pickle bytes and the one-shot pickle key all die here.
///
/// A failure of the library constructor is [`DmCode::StateCorrupt`]: GHOST wrote the pickle, so
/// only a layout change at a bump or memory corruption can make it unreadable, and G-R7 pins the
/// encoder at every pin (§2.8).
pub fn with_account<T>(
    secrets: &AccountSecrets,
    use_it: impl FnOnce(&mut Account) -> DmResult<T>,
) -> DmResult<T> {
    let mut plaintext = secrets.encode();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    pq::fill_random(&mut key);
    pq::fill_random(&mut nonce);

    let sealed = seal_pickle(&plaintext, &key, &nonce);
    plaintext.zeroize();
    let sealed = match sealed {
        Ok(bytes) => bytes,
        Err(code) => {
            key.zeroize();
            return Err(code);
        }
    };

    let account = Account::from_dehydrated_device(
        &vodozemac::base64_encode(&sealed),
        &vodozemac::base64_encode(nonce),
        &key,
    );
    key.zeroize();
    let mut account = account.map_err(|_| DmCode::StateCorrupt)?;
    use_it(&mut account)
}

fn seal_pickle(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> DmResult<Vec<u8>> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DmCode::StateCorrupt)?
        .encrypt(&Nonce::from(*nonce), plaintext)
        .map_err(|_| DmCode::StateCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(fallback: Option<[u8; 32]>) -> AccountSecrets {
        AccountSecrets {
            curve25519: [0x11; 32],
            ed25519_seed: [0x22; 32],
            fallback,
        }
    }

    #[test]
    fn the_pickle_has_the_two_pinned_lengths_and_round_trips() {
        let without = secrets(None).encode();
        assert_eq!(without.len(), 73);
        assert_eq!(&without[0..4], &[0, 0, 0, 1]);
        assert_eq!(without[72], 0);
        let with = secrets(Some([0x33; 32])).encode();
        assert_eq!(with.len(), 105);
        assert_eq!(with[72], 1);

        assert_eq!(decode_pickle(&without).expect("decode").fallback, None);
        assert_eq!(
            decode_pickle(&with).expect("decode").fallback,
            Some([0x33; 32])
        );
    }

    #[test]
    fn a_pickle_of_any_other_shape_is_state_corrupt() {
        let encoded = secrets(Some([0x33; 32])).encode();
        for len in 0..encoded.len() {
            assert_eq!(
                decode_pickle(&encoded[..len]).err(),
                Some(DmCode::StateCorrupt)
            );
        }
        let mut wrong_version = encoded.clone();
        wrong_version[3] = 2;
        assert_eq!(
            decode_pickle(&wrong_version).err(),
            Some(DmCode::StateCorrupt)
        );
        let mut with_one_time_keys = encoded.clone();
        with_one_time_keys[71] = 1;
        assert_eq!(
            decode_pickle(&with_one_time_keys).err(),
            Some(DmCode::StateCorrupt)
        );
        let mut flag_without_key = encoded[..73].to_vec();
        flag_without_key[72] = 1;
        assert_eq!(
            decode_pickle(&flag_without_key).err(),
            Some(DmCode::StateCorrupt)
        );
    }

    /// V-1: the account vodozemac builds from GHOST's pickle carries GHOST's identity key.
    #[test]
    fn the_account_carries_the_encoded_identity() {
        let secrets = secrets(None);
        let expected = secrets.identity_public();
        let reported = with_account(&secrets, |account| {
            Ok(account.identity_keys().curve25519.to_bytes())
        })
        .expect("account");
        assert_eq!(reported, expected);
    }

    /// §15.2 item 4: an account exported by vodozemac re-encodes byte for byte through GHOST's
    /// encoder, including the `opt_fallback_key` branch.
    #[test]
    fn ghost_reencodes_vodozemacs_own_dehydrated_device() {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

        for with_fallback in [false, true] {
            let mut account = Account::new();
            if with_fallback {
                account.generate_fallback_key();
            }
            let key = [0x5a; 32];
            let exported = account.to_dehydrated_device(&key).expect("export");
            let ciphertext = vodozemac::base64_decode(&exported.ciphertext).expect("ciphertext");
            let nonce = vodozemac::base64_decode(&exported.nonce).expect("nonce");
            let nonce: [u8; 12] = nonce.as_slice().try_into().expect("nonce length");
            let plaintext = ChaCha20Poly1305::new_from_slice(&key)
                .expect("cipher")
                .decrypt(&Nonce::from(nonce), ciphertext.as_slice())
                .expect("decrypt");

            let decoded = decode_pickle(&plaintext).expect("GHOST decodes vodozemac's pickle");
            assert_eq!(decoded.fallback.is_some(), with_fallback);
            assert_eq!(decoded.encode(), plaintext, "byte-for-byte re-encoding");
        }
    }
}
