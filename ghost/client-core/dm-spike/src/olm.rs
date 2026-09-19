//! Olm through vodozemac's public API only, generated once per compared pin (0.11.0 and 0.10.0).
//!
//! Value semantics (design §7.9): every session call takes stored JSON pickle bytes, builds a
//! fresh `Session`, and returns new pickle bytes only on success. Accounts are throwaway objects
//! built from GHOST-encoded MSC3814 pickles (§2.2) and dropped after one call.

use rand::Rng;

/// The fields GHOST reads from an Olm message before any session call (the facade's `L1.parse`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum L1Header {
    PreKey {
        identity_key: [u8; 32],
        base_key: [u8; 32],
        one_time_key: [u8; 32],
        session_id: String,
        ratchet_key: [u8; 32],
        chain_index: u64,
    },
    Normal {
        ratchet_key: [u8; 32],
        chain_index: u64,
    },
}

impl L1Header {
    pub fn chain_index(&self) -> u64 {
        match self {
            L1Header::PreKey { chain_index, .. } | L1Header::Normal { chain_index, .. } => {
                *chain_index
            }
        }
    }

    pub fn ratchet_key(&self) -> [u8; 32] {
        match self {
            L1Header::PreKey { ratchet_key, .. } | L1Header::Normal { ratchet_key, .. } => {
                *ratchet_key
            }
        }
    }
}

pub struct Inbound {
    pub pickle: Vec<u8>,
    pub session_id: String,
    pub plaintext: Vec<u8>,
}

pub struct Encrypted {
    pub l1: Vec<u8>,
    pub is_prekey: bool,
    pub pickle: Vec<u8>,
}

pub struct Decrypted {
    pub plaintext: Vec<u8>,
    pub pickle: Vec<u8>,
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

/// A trial X25519 agreement of a fresh scalar with `key` is contributory (design §22.8.2 rule 1).
pub fn contributory(key: &[u8; 32]) -> bool {
    let secret = x25519_dalek::StaticSecret::from(random_bytes::<32>());
    secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(*key))
        .was_contributory()
}

/// The X25519 public key of a secret, computed outside vodozemac.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

macro_rules! olm_version {
    ($module:ident, $vz:ident, $label:literal) => {
        pub mod $module {
            use super::{contributory, random_bytes, Decrypted, Encrypted, Inbound, L1Header};
            use crate::codes::Code;
            use crate::msc3814::{self, DehydratedSecrets};
            use $vz::olm::{
                Account, DecryptionError, EncryptionError, OlmMessage, Session, SessionConfig,
                SessionCreationError, SessionPickle,
            };
            use $vz::Curve25519PublicKey;

            pub const VERSION: &str = $label;

            /// An account from GHOST-encoded secrets through `Account::from_dehydrated_device`,
            /// sealed under a fresh random key.
            pub fn account(secrets: &DehydratedSecrets) -> Result<Account, Code> {
                let key: [u8; 32] = random_bytes();
                let nonce: [u8; 12] = random_bytes();
                let sealed = msc3814::seal(&msc3814::encode(secrets), &key, &nonce);
                Account::from_dehydrated_device(
                    &$vz::base64_encode(sealed),
                    &$vz::base64_encode(nonce),
                    &key,
                )
                .map_err(|_| Code::StateCorrupt)
            }

            /// `(curve25519, ed25519)` public identity keys of an account.
            pub fn identity_keys(account: &Account) -> ([u8; 32], [u8; 32]) {
                let keys = account.identity_keys();
                (keys.curve25519.to_bytes(), *keys.ed25519.as_bytes())
            }

            /// The published-key view: `Account::fallback_key()` lists unpublished keys only.
            pub fn unpublished_fallback_keys(account: &Account) -> usize {
                account.fallback_key().len()
            }

            pub fn load(pickle: &[u8]) -> Result<Session, Code> {
                let parsed: SessionPickle =
                    serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
                Ok(Session::from_pickle(parsed))
            }

            pub fn store(session: &Session) -> Result<Vec<u8>, Code> {
                serde_json::to_vec(&session.pickle()).map_err(|_| Code::StateCorrupt)
            }

            /// `sessionOutbound`: a throwaway account from the own identity (no fallback key)
            /// runs Olm's 3DH to the peer's identity and fallback key with a fresh base key.
            pub fn session_outbound(
                own: &DehydratedSecrets,
                peer_identity: &[u8; 32],
                peer_fallback: &[u8; 32],
            ) -> Result<(Vec<u8>, String), Code> {
                let account = account(own)?;
                let session = account
                    .create_outbound_session(
                        SessionConfig::version_1(),
                        Curve25519PublicKey::from_bytes(*peer_identity),
                        Curve25519PublicKey::from_bytes(*peer_fallback),
                    )
                    .map_err(creation_code)?;
                Ok((store(&session)?, session.session_id()))
            }

            pub fn encrypt(pickle: &[u8], plaintext: &[u8]) -> Result<Encrypted, Code> {
                let mut session = load(pickle)?;
                let message = session.encrypt(plaintext).map_err(encryption_code)?;
                let (kind, l1) = message.to_parts();
                Ok(Encrypted {
                    l1,
                    is_prekey: kind == 0,
                    pickle: store(&session)?,
                })
            }

            pub fn message(l1: &[u8], is_prekey: bool) -> Result<OlmMessage, Code> {
                OlmMessage::from_parts(if is_prekey { 0 } else { 1 }, l1)
                    .map_err(|_| Code::Undecryptable)
            }

            pub fn parse(l1: &[u8], is_prekey: bool) -> Result<L1Header, Code> {
                Ok(match message(l1, is_prekey)? {
                    OlmMessage::PreKey(m) => L1Header::PreKey {
                        identity_key: m.identity_key().to_bytes(),
                        base_key: m.base_key().to_bytes(),
                        one_time_key: m.one_time_key().to_bytes(),
                        session_id: m.session_id(),
                        ratchet_key: m.message().ratchet_key().to_bytes(),
                        chain_index: m.message().chain_index(),
                    },
                    OlmMessage::Normal(m) => L1Header::Normal {
                        ratchet_key: m.ratchet_key().to_bytes(),
                        chain_index: m.chain_index(),
                    },
                })
            }

            /// `sessionInbound` with the §22.8.2 pre-check: a throwaway account holding exactly
            /// the generation's fallback secret; the inner ratchet key must be contributory.
            pub fn session_inbound(
                generation: &DehydratedSecrets,
                expected_peer: &[u8; 32],
                l1: &[u8],
            ) -> Result<Inbound, Code> {
                if let L1Header::PreKey { ratchet_key, .. } = parse(l1, true)? {
                    if !contributory(&ratchet_key) {
                        return Err(Code::InvalidKey);
                    }
                }
                session_inbound_library(generation, expected_peer, l1)
            }

            /// The library call alone, without GHOST's pre-check.
            pub fn session_inbound_library(
                generation: &DehydratedSecrets,
                expected_peer: &[u8; 32],
                l1: &[u8],
            ) -> Result<Inbound, Code> {
                let OlmMessage::PreKey(prekey) = message(l1, true)? else {
                    return Err(Code::Undecryptable);
                };
                let mut account = account(generation)?;
                let created = account
                    .create_inbound_session(
                        SessionConfig::version_1(),
                        Curve25519PublicKey::from_bytes(*expected_peer),
                        &prekey,
                    )
                    .map_err(creation_code)?;
                Ok(Inbound {
                    pickle: store(&created.session)?,
                    session_id: created.session.session_id(),
                    plaintext: created.plaintext,
                })
            }

            /// Value semantics: the returned pickle exists only on success.
            pub fn decrypt(pickle: &[u8], l1: &[u8], is_prekey: bool) -> Result<Decrypted, Code> {
                let mut session = load(pickle)?;
                let parsed = message(l1, is_prekey)?;
                let plaintext = session.decrypt(&parsed).map_err(|e| decryption_code(&e))?;
                Ok(Decrypted {
                    plaintext,
                    pickle: store(&session)?,
                })
            }

            /// The misuse §7.9 point 2 forbids: decrypt on a live object and read its state back
            /// whatever the outcome.
            pub fn decrypt_keeping_object(
                pickle: &[u8],
                l1: &[u8],
                is_prekey: bool,
            ) -> Result<(Result<Vec<u8>, Code>, Vec<u8>), Code> {
                let mut session = load(pickle)?;
                let parsed = message(l1, is_prekey)?;
                let outcome = session.decrypt(&parsed).map_err(|e| decryption_code(&e));
                Ok((outcome, store(&session)?))
            }

            pub fn session_id_of(pickle: &[u8]) -> Result<String, Code> {
                Ok(load(pickle)?.session_id())
            }

            pub fn has_received_message(pickle: &[u8]) -> Result<bool, Code> {
                Ok(load(pickle)?.has_received_message())
            }

            /// Every `SessionCreationError` variant gets a code; the match has no wildcard, so a
            /// new variant at a bump fails the build (the compile-time half of DmResultCodesTest).
            pub fn creation_code(error: SessionCreationError) -> Code {
                match error {
                    SessionCreationError::MissingOneTimeKey(_) => Code::MissingKey,
                    SessionCreationError::MismatchedIdentityKey(_, _) => Code::IdentityMismatch,
                    SessionCreationError::MismatchedSessionConfig { .. } => Code::Undecryptable,
                    SessionCreationError::Decryption(inner) => decryption_code(&inner),
                    SessionCreationError::NonContributoryKey => Code::InvalidKey,
                }
            }

            /// Every `EncryptionError` variant is `INVALID_SESSION` (§22.8.2 rule 2).
            pub fn encryption_code(error: EncryptionError) -> Code {
                match error {
                    EncryptionError::NonContributoryKey => Code::InvalidSession,
                }
            }

            /// Every `DecryptionError` variant gets a code (no wildcard, as above).
            pub fn decryption_code(error: &DecryptionError) -> Code {
                match error {
                    DecryptionError::InvalidMAC(_)
                    | DecryptionError::InvalidMACLength(_, _)
                    | DecryptionError::InvalidPadding(_)
                    | DecryptionError::NonContributoryKey => Code::Undecryptable,
                    DecryptionError::MissingMessageKey(_) => Code::DuplicateOrLost,
                    DecryptionError::TooBigMessageGap(_, _) => Code::GapTooBig,
                }
            }
        }
    };
}

olm_version!(v11, vz11, "0.11.0");
olm_version!(v10, vz10, "0.10.0");
