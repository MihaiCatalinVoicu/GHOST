//! Contact card v2 (design §3.3): the only thing two people exchange to be able to message.
//!
//! ```text
//! card = version(1) = 0x02 || card_index(2, BE) || identity_pk(32, Ed25519) || card_secret(32)
//!        || signature(64, Ed25519 over "ghost/v1/contact-card" || all previous bytes)
//!      = 131 bytes
//! link = "ghost://contact/" || z-base-32(131 bytes)      (16 + 210 = 226 characters, QR 9-L)
//! ```
//!
//! The card carries no relay address, no expiry, no nonce, no one-time key and, since v2, no intro
//! key: the first-contact key lives in the weekly bundle, so nothing seed-derived opens an intro
//! inner layer (P-7). The `ghost1…` public identity string is derived from `identity_pk`, never
//! carried.
//!
//! It is a bearer secret for "may message me": whoever holds it can fetch the bundle, deposit into
//! the inbox, and recognise intro envelopes to the owner (L7-D3, L7-D8, L7-D16).

use crate::derive::CardSecret;
use crate::result::{DmCode, DmResult};
use crate::sign;
use crate::zbase32;
use sha2::{Digest, Sha256};

/// Length of a card.
pub const CARD_BYTES: usize = 131;
/// The only card version Phase 9 issues or accepts.
pub const CARD_VERSION: u8 = 0x02;
/// The only card index Phase 9 issues or accepts (cut-off rotation is deferred to Phase 13).
pub const CARD_INDEX_PHASE_9: u16 = 0;
/// Scheme and path of a card link; no other URL structure is accepted.
pub const LINK_PREFIX: &str = "ghost://contact/";
/// Length of a card link in characters.
pub const LINK_CHARS: usize = LINK_PREFIX.len() + 210;
/// Label of the card signature.
pub const CARD_SIGN_LABEL: &[u8] = b"ghost/v1/contact-card";

/// Prefix of a GHOST public identity string (FR-1.3).
pub const IDENTITY_PREFIX: &str = "ghost1";
/// The only identity-string version Phase 9 writes (FR-1.3).
pub const IDENTITY_VERSION: u8 = 0x01;
/// Length of the checksum inside an identity string.
pub const IDENTITY_CHECKSUM_BYTES: usize = 4;
/// `version(1) || SHA-256(identity_pk)(32) || checksum(4)`: what the z-base-32 part encodes.
pub const IDENTITY_PAYLOAD_BYTES: usize = 1 + 32 + IDENTITY_CHECKSUM_BYTES;
/// Length of a public identity string in characters: the prefix and 60 z-base-32 characters.
pub const IDENTITY_CHARS: usize = IDENTITY_PREFIX.len() + 60;

const OFFSET_INDEX: usize = 1;
const OFFSET_IDENTITY: usize = 3;
const OFFSET_SECRET: usize = 35;
const OFFSET_SIGNATURE: usize = 67;

/// A parsed, signature-checked contact card.
#[derive(Clone)]
pub struct Card {
    /// The card index; 0 in Phase 9.
    pub card_index: u16,
    /// The owner's Ed25519 identity key.
    pub identity_pk: [u8; 32],
    /// The bearer secret every card-level value derives from.
    pub card_secret: CardSecret,
    /// The signature, kept so the card can be re-encoded byte for byte.
    pub signature: [u8; 64],
}

impl core::fmt::Debug for Card {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The card secret never renders.
        f.debug_struct("Card")
            .field("card_index", &self.card_index)
            .finish_non_exhaustive()
    }
}

impl Card {
    /// The 131 bytes of this card.
    pub fn encode(&self) -> [u8; CARD_BYTES] {
        let mut out = [0u8; CARD_BYTES];
        out[0] = CARD_VERSION;
        out[OFFSET_INDEX..OFFSET_IDENTITY].copy_from_slice(&self.card_index.to_be_bytes());
        out[OFFSET_IDENTITY..OFFSET_SECRET].copy_from_slice(&self.identity_pk);
        out[OFFSET_SECRET..OFFSET_SIGNATURE].copy_from_slice(self.card_secret.as_bytes());
        out[OFFSET_SIGNATURE..].copy_from_slice(&self.signature);
        out
    }

    /// The link form of this card.
    pub fn link(&self) -> String {
        let mut link = String::with_capacity(LINK_CHARS);
        link.push_str(LINK_PREFIX);
        link.push_str(&zbase32::encode(&self.encode()));
        link
    }

    /// The owner's public identity string, derived and never carried (§3.3).
    pub fn ghost1(&self) -> String {
        ghost1(&self.identity_pk)
    }
}

/// The public identity string of an Ed25519 identity key (FR-1.3, design §3.3):
///
/// ```text
/// ghost1 = "ghost1" || z-base-32(version(1) = 0x01 || SHA-256(identity_pk)(32) || checksum(4))
/// checksum = SHA-256(version || SHA-256(identity_pk))[0..4]
/// ```
///
/// §3.3 writes this as `z32(SHA-256(identity_pk))`, which names the hash the string carries, not
/// the string: the encoding that `:identity`'s `GhostIdentity` (FR-1.3) parses is the one above,
/// and it is the one this function produces, so a value this crate calls `ghost1` is a value the
/// project's own parser accepts.
pub fn ghost1(identity_pk: &[u8; 32]) -> String {
    let hash: [u8; 32] = Sha256::digest(identity_pk).into();
    let mut payload = Vec::with_capacity(IDENTITY_PAYLOAD_BYTES);
    payload.push(IDENTITY_VERSION);
    payload.extend_from_slice(&hash);
    let checksum: [u8; 32] = Sha256::digest(&payload).into();
    payload.extend_from_slice(&checksum[..IDENTITY_CHECKSUM_BYTES]);
    let mut out = String::with_capacity(IDENTITY_CHARS);
    out.push_str(IDENTITY_PREFIX);
    out.push_str(&zbase32::encode(&payload));
    out
}

/// The bytes the card signature covers.
fn signed_bytes(card: &[u8; CARD_BYTES]) -> Vec<u8> {
    let mut message = CARD_SIGN_LABEL.to_vec();
    message.extend_from_slice(&card[..OFFSET_SIGNATURE]);
    message
}

/// Builds and signs the own card of `card_index` (§3.3). One card per (identity, index), identical
/// for every contact.
pub fn build(identity_seed: &[u8; 32], card_index: u16, card_secret: &CardSecret) -> Card {
    let identity_pk = sign::public_key(identity_seed);
    let mut unsigned = [0u8; CARD_BYTES];
    unsigned[0] = CARD_VERSION;
    unsigned[OFFSET_INDEX..OFFSET_IDENTITY].copy_from_slice(&card_index.to_be_bytes());
    unsigned[OFFSET_IDENTITY..OFFSET_SECRET].copy_from_slice(&identity_pk);
    unsigned[OFFSET_SECRET..OFFSET_SIGNATURE].copy_from_slice(card_secret.as_bytes());
    let signature = sign::sign(identity_seed, &signed_bytes(&unsigned));
    Card {
        card_index,
        identity_pk,
        card_secret: card_secret.clone(),
        signature,
    }
}

/// Parses a card, fail closed, in the order of §3.3: exact length, `version = 2`, `card_index = 0`,
/// then the signature under `identity_pk` (strict verification).
///
/// A version or index Phase 9 does not issue is [`DmCode::InvalidCard`] ("card version
/// unsupported", FR-7.7); so is every other refusal, so a parse failure tells a caller nothing
/// about which field was wrong.
pub fn parse(bytes: &[u8]) -> DmResult<Card> {
    if bytes.len() != CARD_BYTES {
        return Err(DmCode::InvalidCard);
    }
    let mut card = [0u8; CARD_BYTES];
    card.copy_from_slice(bytes);
    if card[0] != CARD_VERSION {
        return Err(DmCode::InvalidCard);
    }
    let card_index = u16::from_be_bytes([card[OFFSET_INDEX], card[OFFSET_INDEX + 1]]);
    if card_index != CARD_INDEX_PHASE_9 {
        return Err(DmCode::InvalidCard);
    }
    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&card[OFFSET_IDENTITY..OFFSET_SECRET]);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&card[OFFSET_SECRET..OFFSET_SIGNATURE]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&card[OFFSET_SIGNATURE..]);
    sign::verify_strict(&identity_pk, &signed_bytes(&card), &signature)
        .map_err(|_| DmCode::InvalidCard)?;
    Ok(Card {
        card_index,
        identity_pk,
        card_secret: CardSecret::from_bytes(secret),
        signature,
    })
}

/// Parses a card of another person: [`parse`] plus the `identity_pk ≠ own` check of §3.3.
pub fn parse_foreign(bytes: &[u8], own_identity_pk: &[u8; 32]) -> DmResult<Card> {
    let card = parse(bytes)?;
    if &card.identity_pk == own_identity_pk {
        return Err(DmCode::InvalidCard);
    }
    Ok(card)
}

/// Parses a card link: the scheme exactly, then an exact-length z-base-32 decode, then [`parse`].
pub fn parse_link(link: &str) -> DmResult<Card> {
    if link.len() != LINK_CHARS {
        return Err(DmCode::InvalidCard);
    }
    let payload = link.strip_prefix(LINK_PREFIX).ok_or(DmCode::InvalidCard)?;
    let bytes = zbase32::decode(payload, CARD_BYTES).map_err(|_| DmCode::InvalidCard)?;
    parse(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [11u8; 32];

    fn own_card() -> Card {
        build(&SEED, 0, &CardSecret::from_bytes([5u8; 32]))
    }

    #[test]
    fn a_card_is_one_hundred_and_thirty_one_bytes_and_its_link_two_hundred_and_twenty_six() {
        let card = own_card();
        assert_eq!(card.encode().len(), 131);
        assert_eq!(card.link().len(), 226);
        assert_eq!(LINK_CHARS, 226);
    }

    #[test]
    fn round_trip_through_bytes_and_link() {
        let card = own_card();
        let parsed = parse(&card.encode()).expect("parse");
        assert_eq!(parsed.encode(), card.encode());
        let from_link = parse_link(&card.link()).expect("link");
        assert_eq!(from_link.encode(), card.encode());
        assert_eq!(from_link.ghost1(), card.ghost1());
    }

    #[test]
    fn every_single_byte_mutation_is_refused() {
        let card = own_card().encode();
        for i in 0..CARD_BYTES {
            for bit in 0..8u32 {
                let mut bad = card;
                bad[i] ^= 1 << bit;
                if bad == card {
                    continue;
                }
                assert_eq!(
                    parse(&bad).err(),
                    Some(DmCode::InvalidCard),
                    "byte {i} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn every_wrong_length_is_refused() {
        let card = own_card().encode();
        for len in 0..CARD_BYTES + 8 {
            if len == CARD_BYTES {
                continue;
            }
            let mut bytes = card.to_vec();
            bytes.resize(len, 0);
            assert_eq!(
                parse(&bytes).err(),
                Some(DmCode::InvalidCard),
                "length {len}"
            );
        }
    }

    #[test]
    fn version_one_and_a_second_index_are_unsupported() {
        let mut v1 = own_card().encode();
        v1[0] = 0x01;
        assert_eq!(parse(&v1).err(), Some(DmCode::InvalidCard));
        let indexed = build(&SEED, 1, &CardSecret::from_bytes([5u8; 32]));
        assert_eq!(parse(&indexed.encode()).err(), Some(DmCode::InvalidCard));
    }

    #[test]
    fn own_card_is_refused_as_a_contact() {
        let card = own_card();
        assert_eq!(
            parse_foreign(&card.encode(), &card.identity_pk).err(),
            Some(DmCode::InvalidCard)
        );
        assert!(parse_foreign(&card.encode(), &[0u8; 32]).is_ok());
    }

    #[test]
    fn the_link_takes_no_other_url_structure() {
        let card = own_card();
        let payload = zbase32::encode(&card.encode());
        for bad in [
            format!("ghost://contact{payload}"),
            format!("ghost://contacts/{payload}"),
            format!("https://contact/{payload}"),
            format!("GHOST://CONTACT/{payload}"),
            format!("ghost://contact/{payload}?x=1"),
            format!("ghost://contact//{payload}"),
        ] {
            assert_eq!(parse_link(&bad).err(), Some(DmCode::InvalidCard), "{bad}");
        }
    }

    #[test]
    fn the_link_alphabet_is_strict() {
        let card = own_card();
        let mut link = card.link();
        link.replace_range(16..17, "l");
        assert_eq!(parse_link(&link).err(), Some(DmCode::InvalidCard));
    }

    /// The identity string this crate derives is the one `GhostIdentity.parse` accepts (FR-1.3):
    /// 66 characters, the `ghost1` prefix, version 1, the SHA-256 of the key and the 4-byte
    /// checksum. The rules are re-implemented here from FR-1.3 rather than called, because
    /// `:identity` is Kotlin and this crate takes no dependency on it.
    #[test]
    fn the_identity_string_is_the_one_the_project_parser_accepts() {
        let card = own_card();
        let text = card.ghost1();
        assert_eq!(text.len(), IDENTITY_CHARS);
        assert_eq!(IDENTITY_CHARS, 66);
        let payload = text
            .strip_prefix(IDENTITY_PREFIX)
            .expect("the ghost1 prefix");
        let bytes = zbase32::decode(payload, IDENTITY_PAYLOAD_BYTES).expect("z-base-32");
        assert_eq!(bytes[0], IDENTITY_VERSION);
        let expected: [u8; 32] = Sha256::digest(card.identity_pk).into();
        assert_eq!(&bytes[1..33], &expected);
        let checksum: [u8; 32] = Sha256::digest(&bytes[..33]).into();
        assert_eq!(&bytes[33..], &checksum[..IDENTITY_CHECKSUM_BYTES]);
        // Another key gives another string, and the string is not the bare hash.
        assert_ne!(ghost1(&[0u8; 32]), text);
        assert_ne!(zbase32::encode(&expected), text);
    }

    /// §15.2's seeded property run for the card parsers. The card is a fixed-length record whose
    /// cost is dominated by `verify_strict`, so the `10^6` run feeds length-varying inputs (the
    /// signature path is reached only by the rare exact-length one) and a shorter run feeds
    /// exact-length mutants. The exhaustive single-bit test above already covers every one-bit
    /// mutant of a valid card, which sampling cannot match.
    #[test]
    fn the_card_parsers_never_panic_on_seeded_inputs() {
        let mut rng = crate::property::Seeded::new(0x2545_f491_4f6c_dd1d);
        for _ in 0..crate::property::inputs() {
            let bytes = rng.random_input(CARD_BYTES + 16);
            match parse(&bytes) {
                Ok(card) => assert_eq!(card.encode().len(), CARD_BYTES),
                Err(code) => assert_eq!(code, DmCode::InvalidCard),
            }
            // The link parser sits on top of the z-base-32 decoder and the same record.
            let text: String = bytes.iter().map(|b| char::from(*b)).collect();
            match parse_link(&text) {
                Ok(card) => assert_eq!(card.encode().len(), CARD_BYTES),
                Err(code) => assert_eq!(code, DmCode::InvalidCard),
            }
        }
        let template = own_card().encode();
        for _ in 0..crate::property::signature_inputs() {
            let bytes = rng.mutate(&template);
            match parse(&bytes) {
                Ok(card) => assert_eq!(card.encode().as_slice(), bytes.as_slice()),
                Err(code) => assert_eq!(code, DmCode::InvalidCard),
            }
        }
    }

    #[test]
    fn one_card_per_identity_and_index() {
        let secret = CardSecret::from_bytes([5u8; 32]);
        assert_eq!(
            build(&SEED, 0, &secret).encode(),
            build(&SEED, 0, &secret).encode()
        );
    }
}
