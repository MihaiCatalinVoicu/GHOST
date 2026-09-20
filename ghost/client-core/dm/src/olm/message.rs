//! The L1 (Olm message) header GHOST reads before any session call, and the closed mapping of
//! every vodozemac error to a [`DmCode`] (design §2.6, §22.8.2, as corrected by S0′ V-2).
//!
//! GHOST never lets a library error type cross this crate's boundary, and every match below is
//! **exhaustive with no wildcard**, so a new variant at a bump fails the build instead of
//! collapsing into a generic code (§2.1's "exhaustive match on session-config errors"). That is
//! the compile-time half of `DmResultCodesTest`.
//!
//! The header itself never leaves an AEAD on the wire (T29): the seal of §6 carries L1 whole, and
//! `openOuter`/`openIntro` hand these fields to Kotlin **after** the seal opened, which is what
//! lets the typed facade's `L1.parse` be a view over a decoded result rather than a Kotlin parser
//! (ADR-19: no protocol logic in Kotlin).

use crate::result::{DmCode, DmResult};
use vodozemac::olm::{
    DecryptionError, EncryptionError, OlmMessage, PreKeyMessage, SessionCreationError,
};

/// Message type of a PreKey message in `OlmMessage::from_parts`.
pub const MESSAGE_TYPE_PRE_KEY: usize = 0;
/// Message type of a normal message in `OlmMessage::from_parts`.
pub const MESSAGE_TYPE_NORMAL: usize = 1;
/// Length of a raw session id (`SHA-256(identity || base || one-time key)`).
pub const SESSION_ID_BYTES: usize = 32;

/// The fields of an L1 message GHOST decides on before touching a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L1Header {
    /// A PreKey message: the first flight of a session.
    PreKey {
        /// The sender's Olm identity key, checked against the pinned one (§8.2 rule 3).
        identity_key: [u8; 32],
        /// The sender's base key, which binding v3 signs (§3.4).
        base_key: [u8; 32],
        /// The fallback key the sender used: it must be the named generation's (§3.4).
        one_time_key: [u8; 32],
        /// The raw session id, matched against the two stored slots (D2b, §7.6).
        session_id: [u8; SESSION_ID_BYTES],
        /// The inner ratchet key of the wrapped normal message.
        ratchet_key: [u8; 32],
        /// The inner chain index, used by the gap hold (§7.7 point 2).
        chain_index: u64,
    },
    /// A normal message of an established session.
    Normal {
        /// The receiver chain this message belongs to.
        ratchet_key: [u8; 32],
        /// The index inside that chain.
        chain_index: u64,
    },
}

impl L1Header {
    /// The chain index, whichever kind this is.
    pub const fn chain_index(&self) -> u64 {
        match self {
            L1Header::PreKey { chain_index, .. } | L1Header::Normal { chain_index, .. } => {
                *chain_index
            }
        }
    }

    /// The ratchet key, whichever kind this is.
    pub const fn ratchet_key(&self) -> [u8; 32] {
        match self {
            L1Header::PreKey { ratchet_key, .. } | L1Header::Normal { ratchet_key, .. } => {
                *ratchet_key
            }
        }
    }

    /// Whether this is a PreKey message (`isPreKey` of the typed facade).
    pub const fn is_pre_key(&self) -> bool {
        matches!(self, L1Header::PreKey { .. })
    }
}

/// Parses L1 bytes of the given kind. A blob that does not decode is [`DmCode::NonCanonical`]:
/// it opened under a GHOST seal, so its bytes are inside our own AEAD and malformed content there
/// is a format failure, not a decryption one.
pub fn parse(l1: &[u8], is_pre_key: bool) -> DmResult<L1Header> {
    Ok(match decode(l1, is_pre_key)? {
        OlmMessage::PreKey(message) => L1Header::PreKey {
            identity_key: message.identity_key().to_bytes(),
            base_key: message.base_key().to_bytes(),
            one_time_key: message.one_time_key().to_bytes(),
            session_id: session_id_bytes(&message.session_id())?,
            ratchet_key: message.message().ratchet_key().to_bytes(),
            chain_index: message.message().chain_index(),
        },
        OlmMessage::Normal(message) => L1Header::Normal {
            ratchet_key: message.ratchet_key().to_bytes(),
            chain_index: message.chain_index(),
        },
    })
}

/// Decodes L1 bytes into the library's message type.
pub fn decode(l1: &[u8], is_pre_key: bool) -> DmResult<OlmMessage> {
    let kind = if is_pre_key {
        MESSAGE_TYPE_PRE_KEY
    } else {
        MESSAGE_TYPE_NORMAL
    };
    OlmMessage::from_parts(kind, l1).map_err(|_| DmCode::NonCanonical)
}

/// Decodes L1 bytes that must be a PreKey message.
pub fn decode_pre_key(l1: &[u8]) -> DmResult<PreKeyMessage> {
    match decode(l1, true)? {
        OlmMessage::PreKey(message) => Ok(message),
        OlmMessage::Normal(_) => Err(DmCode::NonCanonical),
    }
}

/// The raw 32 bytes behind vodozemac's base64 session id. The schema stores those bytes
/// (`olm_session.session_id`, `length = 32`), so nothing base64 reaches a row.
pub fn session_id_bytes(session_id: &str) -> DmResult<[u8; SESSION_ID_BYTES]> {
    let decoded = vodozemac::base64_decode(session_id).map_err(|_| DmCode::StateCorrupt)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| DmCode::StateCorrupt)
}

/// Every `SessionCreationError` variant (§2.6 function 14; S0′ V-2 added the session-config row).
pub const fn creation_code(error: &SessionCreationError) -> DmCode {
    match error {
        SessionCreationError::MissingOneTimeKey(_) => DmCode::MissingKey,
        SessionCreationError::MismatchedIdentityKey(_, _) => DmCode::IdentityMismatch,
        // A PreKey message of another session version: not our peer's session, and not a forgery
        // we can name any better than "does not decrypt".
        SessionCreationError::MismatchedSessionConfig { .. } => DmCode::Undecryptable,
        SessionCreationError::Decryption(inner) => decryption_code(inner),
        SessionCreationError::NonContributoryKey => DmCode::InvalidKey,
    }
}

/// Every `EncryptionError` variant is `INVALID_SESSION` (§22.8.2 rule 2).
pub const fn encryption_code(error: &EncryptionError) -> DmCode {
    match error {
        EncryptionError::NonContributoryKey => DmCode::InvalidSession,
    }
}

/// Every `DecryptionError` variant (§2.6 function 13; S0′ V-2 added the non-contributory row).
pub const fn decryption_code(error: &DecryptionError) -> DmCode {
    match error {
        DecryptionError::InvalidMAC(_)
        | DecryptionError::InvalidMACLength(_, _)
        | DecryptionError::InvalidPadding(_)
        | DecryptionError::NonContributoryKey => DmCode::Undecryptable,
        DecryptionError::MissingMessageKey(_) => DmCode::DuplicateOrLost,
        DecryptionError::TooBigMessageGap(_, _) => DmCode::GapTooBig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_that_is_not_a_message_is_non_canonical() {
        for is_pre_key in [false, true] {
            assert_eq!(parse(&[], is_pre_key).err(), Some(DmCode::NonCanonical));
            assert_eq!(
                parse(&[0xff; 64], is_pre_key).err(),
                Some(DmCode::NonCanonical)
            );
        }
    }

    /// The **runtime half** of §22.8.2 rule 4 (S0′ forward note: "its runtime half checks the
    /// mapping table"): every variant of vodozemac's three error types is named here with the code
    /// §2.6 gives it. The compile-time half is the wildcard-free `match` of each function above,
    /// which a bump that adds a variant fails; this table pins what each variant maps to, which a
    /// wildcard-free match cannot.
    #[test]
    fn every_vodozemac_error_has_the_code_2_6_gives_it() {
        use aes::cipher::block_padding::Error as UnpadError;
        use hmac::digest::MacError;
        use vodozemac::olm::SessionConfig;
        use vodozemac::Curve25519PublicKey;

        let key = Curve25519PublicKey::from_bytes([7u8; 32]);

        assert_eq!(
            decryption_code(&DecryptionError::InvalidMAC(MacError)),
            DmCode::Undecryptable
        );
        assert_eq!(
            decryption_code(&DecryptionError::InvalidMACLength(8, 7)),
            DmCode::Undecryptable
        );
        assert_eq!(
            decryption_code(&DecryptionError::InvalidPadding(UnpadError)),
            DmCode::Undecryptable
        );
        assert_eq!(
            decryption_code(&DecryptionError::NonContributoryKey),
            DmCode::Undecryptable
        );
        assert_eq!(
            decryption_code(&DecryptionError::MissingMessageKey(3)),
            DmCode::DuplicateOrLost
        );
        assert_eq!(
            decryption_code(&DecryptionError::TooBigMessageGap(2_001, 2_000)),
            DmCode::GapTooBig
        );

        assert_eq!(
            encryption_code(&EncryptionError::NonContributoryKey),
            DmCode::InvalidSession
        );

        assert_eq!(
            creation_code(&SessionCreationError::MissingOneTimeKey(key)),
            DmCode::MissingKey
        );
        assert_eq!(
            creation_code(&SessionCreationError::MismatchedIdentityKey(key, key)),
            DmCode::IdentityMismatch
        );
        assert_eq!(
            creation_code(&SessionCreationError::MismatchedSessionConfig {
                expected: SessionConfig::version_1(),
                got: None,
            }),
            DmCode::Undecryptable
        );
        assert_eq!(
            creation_code(&SessionCreationError::Decryption(
                DecryptionError::MissingMessageKey(0)
            )),
            DmCode::DuplicateOrLost
        );
        assert_eq!(
            creation_code(&SessionCreationError::NonContributoryKey),
            DmCode::InvalidKey
        );
    }

    #[test]
    fn a_session_id_that_is_not_thirty_two_bytes_is_state_corrupt() {
        assert_eq!(session_id_bytes("").err(), Some(DmCode::StateCorrupt));
        assert_eq!(session_id_bytes("!!!!").err(), Some(DmCode::StateCorrupt));
        let short = vodozemac::base64_encode([0u8; 31]);
        assert_eq!(session_id_bytes(&short).err(), Some(DmCode::StateCorrupt));
        let exact = vodozemac::base64_encode([7u8; 32]);
        assert_eq!(session_id_bytes(&exact).expect("32 bytes"), [7u8; 32]);
    }
}
