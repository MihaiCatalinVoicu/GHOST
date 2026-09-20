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

use crate::pq;
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
///
/// Every key the message carries must be a **canonical** Curve25519 encoding
/// ([`pq::canonical_u_coordinate`]); anything else is [`DmCode::NonCanonical`] (review round 2,
/// R2-06). This is the one place every L1 passes — [`parse`], [`decode_pre_key`] and
/// `session::decrypt` all come through here — which is what makes the rule hold for the session
/// id, the pinned identity and the receiver chain a message names at once.
pub fn decode(l1: &[u8], is_pre_key: bool) -> DmResult<OlmMessage> {
    let kind = if is_pre_key {
        MESSAGE_TYPE_PRE_KEY
    } else {
        MESSAGE_TYPE_NORMAL
    };
    let message = OlmMessage::from_parts(kind, l1).map_err(|_| DmCode::NonCanonical)?;
    if !canonical_keys(&message) {
        return Err(DmCode::NonCanonical);
    }
    Ok(message)
}

/// Whether every Curve25519 key of a decoded message is a canonical encoding of its point.
///
/// Olm hashes the three PreKey fields into the session id and matches a receiver chain by the
/// ratchet key's **bytes**, while X25519 works on the point: without this, one key set would name
/// two sessions and one chain two chains (R2-06).
fn canonical_keys(message: &OlmMessage) -> bool {
    match message {
        OlmMessage::PreKey(pre_key) => {
            pq::canonical_u_coordinate(&pre_key.identity_key().to_bytes())
                && pq::canonical_u_coordinate(&pre_key.base_key().to_bytes())
                && pq::canonical_u_coordinate(&pre_key.one_time_key().to_bytes())
                && pq::canonical_u_coordinate(&pre_key.message().ratchet_key().to_bytes())
        }
        OlmMessage::Normal(normal) => pq::canonical_u_coordinate(&normal.ratchet_key().to_bytes()),
    }
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
///
/// **The whole `Decryption` branch is `UNDECRYPTABLE`** (review round 2, S4B2-01/R2-01), which is
/// the code §2.6 function 14's row names for a first flight that does not open. It is not
/// [`decryption_code`], because that function's codes belong to function 13: `create_inbound_session`
/// forwards the inner decryption of the first message, and `DecryptionError::TooBigMessageGap` —
/// which vodozemac reports **before** the MAC is checked
/// (`vz:src/olm/session/receiver_chain.rs:184-190`) — would otherwise hand the typed facade a
/// `GAP_TOO_BIG` its `sessionInbound` arm list does not carry. Any holder of the recipient's card
/// can author such a first flight with no key material beyond the published fallback key, and the
/// outcome would be an `IllegalStateException` per blob rather than the silent drop D10 and §7.4
/// require. A gap on an established session is still `GAP_TOO_BIG`: that path is function 13's.
pub const fn creation_code(error: &SessionCreationError) -> DmCode {
    match error {
        SessionCreationError::MissingOneTimeKey(_) => DmCode::MissingKey,
        SessionCreationError::MismatchedIdentityKey(_, _) => DmCode::IdentityMismatch,
        // A PreKey message of another session version: not our peer's session, and not a forgery
        // we can name any better than "does not decrypt".
        SessionCreationError::MismatchedSessionConfig { .. } => DmCode::Undecryptable,
        SessionCreationError::Decryption(_) => DmCode::Undecryptable,
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
        // Every inner decryption failure is one code at session creation (S4B2-01/R2-01): the two
        // that differ from `decryption_code` are named here, because a wildcard-free match cannot
        // pin what a branch maps to.
        assert_eq!(
            creation_code(&SessionCreationError::Decryption(
                DecryptionError::MissingMessageKey(0)
            )),
            DmCode::Undecryptable
        );
        assert_eq!(
            creation_code(&SessionCreationError::Decryption(
                DecryptionError::TooBigMessageGap(2_001, 2_000)
            )),
            DmCode::Undecryptable
        );
        assert_eq!(
            creation_code(&SessionCreationError::Decryption(
                DecryptionError::InvalidMAC(MacError)
            )),
            DmCode::Undecryptable
        );
        assert_eq!(
            creation_code(&SessionCreationError::NonContributoryKey),
            DmCode::InvalidKey
        );
    }

    /// §15.2 and R-C4 for the L1 parsers (review round 2, S4B2-04): `10^6` seeded inputs, free-form
    /// and mutated from a **real** PreKey and a real normal message, through both `is_pre_key`
    /// values. Never a panic, never an over-read, and every refusal a typed [`DmCode`].
    ///
    /// These bytes are attacker-supplied: a card holder's intro envelope carries L1 whole, so this
    /// is the parser §15.2's "every parser" means most literally. Both entry points are covered at
    /// once — [`parse`] calls [`decode`] and then reads every field out of the decoded message,
    /// which is where an over-read would live.
    #[test]
    fn the_l1_parsers_never_panic_on_seeded_inputs() {
        let templates = crate::olm::session::fixtures::settled().messages;
        let mut rng = crate::property::Seeded::new(0x4f_6c_6d_31_5f_4c_31_00);
        for _ in 0..crate::property::inputs() {
            let template = &templates[rng.below(templates.len())];
            let bytes = rng.mutate(template);
            // The kind is the caller's claim, not the blob's: both are tried on every input.
            for is_pre_key in [false, true] {
                match parse(&bytes, is_pre_key) {
                    Ok(header) => assert_eq!(header.is_pre_key(), is_pre_key),
                    Err(code) => assert!(
                        matches!(code, DmCode::NonCanonical | DmCode::StateCorrupt),
                        "{code:?}"
                    ),
                }
                if let Ok(message) = decode(&bytes, is_pre_key) {
                    assert_eq!(
                        matches!(message, OlmMessage::PreKey(_)),
                        is_pre_key,
                        "the decoded kind is the one that was asked for"
                    );
                }
            }
        }
        for _ in 0..crate::property::inputs() / 4 {
            let bytes = rng.random_input(256);
            for is_pre_key in [false, true] {
                if let Err(code) = parse(&bytes, is_pre_key) {
                    assert!(
                        matches!(code, DmCode::NonCanonical | DmCode::StateCorrupt),
                        "{code:?}"
                    );
                }
            }
        }
    }

    /// Review round 2 (R2-06): an L1 whose keys are **non-canonical encodings** of their points is
    /// refused, so one key set names one session id and one receiver chain.
    ///
    /// RFC 7748 masks the top bit of a u-coordinate and reduces mod `p`, so `k`, `k | 2^255` and
    /// `k + p` are the same point to X25519 — `curve25519-dalek`'s `MontgomeryPoint::ct_eq`
    /// compares field elements — while `to_bytes()` keeps the raw byte that
    /// `PreKeyMessage::session_id` hashes. Without this check a sender could hand its peer two
    /// `olm_session` rows for one key set, or a normal message that names a chain the peer holds
    /// under a different encoding.
    #[test]
    fn a_non_canonical_key_encoding_is_refused() {
        let settled = crate::olm::session::fixtures::settled();
        let first = &settled.messages[0];
        let normal = &settled.messages[1];

        let pre_key = match parse(first, true).expect("header") {
            L1Header::PreKey {
                identity_key,
                base_key,
                one_time_key,
                ratchet_key,
                ..
            } => vec![identity_key, base_key, one_time_key, ratchet_key],
            L1Header::Normal { .. } => panic!("the first flight is a PreKey message"),
        };
        for key in pre_key {
            for variant in non_canonical_variants(&key) {
                let blob = replace_key(first, &key, &variant);
                assert_eq!(
                    parse(&blob, true).err(),
                    Some(DmCode::NonCanonical),
                    "a PreKey message key must be canonical"
                );
                assert_eq!(decode(&blob, true).err(), Some(DmCode::NonCanonical));
            }
        }

        let ratchet_key = parse(normal, false).expect("header").ratchet_key();
        for variant in non_canonical_variants(&ratchet_key) {
            let blob = replace_key(normal, &ratchet_key, &variant);
            assert_eq!(parse(&blob, false).err(), Some(DmCode::NonCanonical));
        }

        // The genuine messages, whose keys are canonical, still parse.
        assert!(parse(first, true).is_ok());
        assert!(parse(normal, false).is_ok());
    }

    /// The two encodings of one point RFC 7748 accepts and this crate does not: the top bit set,
    /// and the value `k + p` when it still fits in 255 bits.
    fn non_canonical_variants(key: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut variants = Vec::new();
        let mut high = *key;
        high[31] |= 0x80;
        if high != *key {
            variants.push(high);
        }
        // `k + p`, kept only when it did not overflow 255 bits: `p = 2^255 - 19`.
        let mut sum = [0u8; 32];
        let mut carry = 0u16;
        let p = crate::pq::CURVE25519_P;
        for i in 0..32 {
            let value = u16::from(key[i]) + u16::from(p[i]) + carry;
            sum[i] = (value & 0xff) as u8;
            carry = value >> 8;
        }
        if carry == 0 && sum[31] & 0x80 == 0 {
            variants.push(sum);
        }
        assert!(
            !variants.is_empty(),
            "no non-canonical variant for this key"
        );
        variants
    }

    /// Replaces the 32 bytes of `key` inside an encoded message. The keys of an Olm message are
    /// protobuf `bytes` fields, so they appear verbatim.
    fn replace_key(l1: &[u8], key: &[u8; 32], replacement: &[u8; 32]) -> Vec<u8> {
        let at = l1
            .windows(32)
            .position(|window| window == key)
            .expect("the key is in the message");
        let mut out = l1.to_vec();
        out[at..at + 32].copy_from_slice(replacement);
        out
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
