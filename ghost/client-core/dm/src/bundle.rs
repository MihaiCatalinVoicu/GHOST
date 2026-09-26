//! Bundle v2 (design §5.3, §5.4): the one sealed 4 KiB blob a card holder fetches to start a
//! conversation.
//!
//! ```text
//! bundle_plain = ver(1) = 0x02 || card_index(2) || bundle_week(8) || bundle_rank(2) || gen_id(4)
//!              || OI(32) || F_g(32) || Q_g(1216) || identity_pk(32)
//!              || sig(64, Ed25519 over "ghost/v1/dm-bundle/v2" || all previous bytes)
//!              = 1 393 bytes
//! blob(4096)   = the §6.2 seal in bundle mode, under KB_i, in the namespace P_i
//! ```
//!
//! One signature binds everything a fetcher needs: the Olm identity (the bundle signature is the
//! identity binding), the fallback key (Olm's signed prekey, which its PCS needs) and the X-Wing
//! key. Distinct fixed lengths and positions keep X25519, X-Wing and Ed25519 encodings pairwise
//! distinct, which is the key-confusion lesson of the PQXDH analysis.
//!
//! There are **no one-time keys** (§5.6), **no registration id and no device id**: a per-install
//! registration id would let any card holder detect a reinstall or a restore by polling bundles.
//! `bundle_rank` replaces round 9's `issued_hour`, which gave card holders the hour of the owner's
//! first wake after `t_pub` and of a restore.

use crate::pq;
use crate::provenance::SealKey;
use crate::result::{DmCode, DmResult};
use crate::seal::{self, SALT_BYTES};
use crate::sign;

/// Length of a bundle plaintext.
pub const BUNDLE_PLAIN_BYTES: usize = 1393;
/// Length of a sealed bundle blob.
pub const BUNDLE_BLOB_BYTES: usize = 4096;
/// The only bundle version Phase 9 publishes or accepts.
pub const BUNDLE_VERSION: u8 = 0x02;
/// Label of the bundle signature.
pub const BUNDLE_SIGN_LABEL: &[u8] = b"ghost/v1/dm-bundle/v2";
/// Length of a wrapped bundle candidate: the plaintext plus a wrap envelope (§13.6).
pub const BUNDLE_ENV_BYTES: usize = BUNDLE_PLAIN_BYTES + crate::wrap::ENVELOPE_OVERHEAD;

const OFFSET_CARD_INDEX: usize = 1;
const OFFSET_WEEK: usize = 3;
const OFFSET_RANK: usize = 11;
const OFFSET_GEN_ID: usize = 13;
const OFFSET_OI: usize = 17;
const OFFSET_FALLBACK: usize = 49;
const OFFSET_XWING: usize = 81;
const OFFSET_IDENTITY: usize = 1297;
const OFFSET_SIGNATURE: usize = 1329;

/// A parsed, signature-checked bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The card index the bundle belongs to.
    pub card_index: u16,
    /// The ISO week the bundle is valid for; it is also valid in the next week.
    pub bundle_week: u64,
    /// The rank inside the week: 0 for the scheduled publication, higher for an activation or a
    /// restore, so no publication hour leaks (§5.3).
    pub bundle_rank: u16,
    /// The generation this bundle publishes.
    pub gen_id: u32,
    /// The Olm identity key.
    pub olm_identity: [u8; 32],
    /// The Olm fallback key `F_g`.
    pub fallback_key: [u8; 32],
    /// The X-Wing encapsulation key `Q_g`.
    pub xwing_public: Vec<u8>,
    /// The owner's Ed25519 identity key.
    pub identity_pk: [u8; 32],
    /// The bundle signature.
    pub signature: [u8; sign::SIGNATURE_BYTES],
}

fn signed_bytes(plain: &[u8]) -> Vec<u8> {
    let mut message = BUNDLE_SIGN_LABEL.to_vec();
    message.extend_from_slice(&plain[..OFFSET_SIGNATURE]);
    message
}

/// What a publication puts into a bundle (§5.4).
pub struct BundleFields<'a> {
    /// The card index; 0 in Phase 9.
    pub card_index: u16,
    /// The ISO week of the publication.
    pub bundle_week: u64,
    /// 0 for the weekly publication; `1 + max(rank)` for an activation or a restore.
    pub bundle_rank: u16,
    /// The random generation id, distinct from every retained one.
    pub gen_id: u32,
    /// The Olm identity key.
    pub olm_identity: &'a [u8; 32],
    /// The generation's Olm fallback key.
    pub fallback_key: &'a [u8; 32],
    /// The generation's X-Wing encapsulation key.
    pub xwing_public: &'a [u8],
}

/// Builds and signs a bundle plaintext.
pub fn build(identity_seed: &[u8; 32], fields: &BundleFields<'_>) -> DmResult<Vec<u8>> {
    if fields.xwing_public.len() != pq::PUBLIC_KEY_BYTES {
        return Err(DmCode::InvalidKey);
    }
    let identity_pk = sign::public_key(identity_seed);
    let mut plain = vec![0u8; BUNDLE_PLAIN_BYTES];
    plain[0] = BUNDLE_VERSION;
    plain[OFFSET_CARD_INDEX..OFFSET_WEEK].copy_from_slice(&fields.card_index.to_be_bytes());
    plain[OFFSET_WEEK..OFFSET_RANK].copy_from_slice(&fields.bundle_week.to_be_bytes());
    plain[OFFSET_RANK..OFFSET_GEN_ID].copy_from_slice(&fields.bundle_rank.to_be_bytes());
    plain[OFFSET_GEN_ID..OFFSET_OI].copy_from_slice(&fields.gen_id.to_be_bytes());
    plain[OFFSET_OI..OFFSET_FALLBACK].copy_from_slice(fields.olm_identity);
    plain[OFFSET_FALLBACK..OFFSET_XWING].copy_from_slice(fields.fallback_key);
    plain[OFFSET_XWING..OFFSET_IDENTITY].copy_from_slice(fields.xwing_public);
    plain[OFFSET_IDENTITY..OFFSET_SIGNATURE].copy_from_slice(&identity_pk);
    let signature = sign::sign(identity_seed, &signed_bytes(&plain));
    plain[OFFSET_SIGNATURE..].copy_from_slice(&signature);
    Ok(plain)
}

/// Parses a bundle plaintext and verifies its signature, strictly.
///
/// The X-Wing key is validated whole (§22.8.2 rule 3), so a contact that published a low-order
/// X25519 half or an out-of-range ML-KEM half is `INVALID_KEY` and its candidate is dropped rather
/// than failing later inside the time-triggered `EST-READY`.
///
/// **The Olm identity and the fallback key must be canonical encodings too** (phase review
/// CRY-P9-01). Their points are fine to X25519 whatever the top bit says, so `sessionOutbound`
/// used to build a session on `F | 2^255` — but vodozemac carries the bytes verbatim into every
/// PreKey message, and [`crate::olm::message`]'s `canonical_keys` refuses such a message on both
/// sides: `sealIntro` then answered `NON_CANONICAL` on every send to that contact, which the
/// engine treats as its own bug and throws on every time-triggered pass. The Olm identity is
/// pinned and compared byte for byte (§22.9 item 13), so its encoding is refused here as well.
/// Keys this crate builds are canonical, so only the bundle's owner can publish either form, and
/// it is the same `INVALID_KEY` the S13 review gave the X-Wing half: the candidate is dropped.
pub fn parse(plain: &[u8]) -> DmResult<Bundle> {
    if plain.len() != BUNDLE_PLAIN_BYTES {
        return Err(DmCode::NonCanonical);
    }
    if plain[0] != BUNDLE_VERSION {
        return Err(DmCode::NonCanonical);
    }
    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&plain[OFFSET_IDENTITY..OFFSET_SIGNATURE]);
    let mut signature = [0u8; sign::SIGNATURE_BYTES];
    signature.copy_from_slice(&plain[OFFSET_SIGNATURE..]);
    sign::verify_strict(&identity_pk, &signed_bytes(plain), &signature)?;
    pq::validate_public_key(&plain[OFFSET_XWING..OFFSET_IDENTITY])?;
    let mut olm_identity = [0u8; 32];
    olm_identity.copy_from_slice(&plain[OFFSET_OI..OFFSET_FALLBACK]);
    let mut fallback_key = [0u8; 32];
    fallback_key.copy_from_slice(&plain[OFFSET_FALLBACK..OFFSET_XWING]);
    if !pq::canonical_u_coordinate(&olm_identity) || !pq::canonical_u_coordinate(&fallback_key) {
        return Err(DmCode::InvalidKey);
    }
    let mut week = [0u8; 8];
    week.copy_from_slice(&plain[OFFSET_WEEK..OFFSET_RANK]);
    Ok(Bundle {
        card_index: u16::from_be_bytes([plain[OFFSET_CARD_INDEX], plain[OFFSET_CARD_INDEX + 1]]),
        bundle_week: u64::from_be_bytes(week),
        bundle_rank: u16::from_be_bytes([plain[OFFSET_RANK], plain[OFFSET_RANK + 1]]),
        gen_id: u32::from_be_bytes([
            plain[OFFSET_GEN_ID],
            plain[OFFSET_GEN_ID + 1],
            plain[OFFSET_GEN_ID + 2],
            plain[OFFSET_GEN_ID + 3],
        ]),
        olm_identity,
        fallback_key,
        xwing_public: plain[OFFSET_XWING..OFFSET_IDENTITY].to_vec(),
        identity_pk,
        signature,
    })
}

/// Seals a bundle plaintext into its 4 KiB blob under `KB_i`, in the namespace `P_i`, with a fresh
/// salt (R-S4).
pub fn seal(bundle_key: &SealKey, bundle_namespace: &[u8; 32], plain: &[u8]) -> DmResult<Vec<u8>> {
    seal_with(bundle_key, bundle_namespace, plain, &seal::random_salt())
}

/// Seals a bundle plaintext with a given salt: the vector and equivalence-fixture path.
pub fn seal_with(
    bundle_key: &SealKey,
    bundle_namespace: &[u8; 32],
    plain: &[u8],
    salt: &[u8; SALT_BYTES],
) -> DmResult<Vec<u8>> {
    if plain.len() != BUNDLE_PLAIN_BYTES {
        return Err(DmCode::NonCanonical);
    }
    seal::seal_bundle_with(bundle_key, bundle_namespace, plain, salt)
}

/// Opens a bundle blob and checks it against the card it is expected to belong to (§5.5).
///
/// The caller still checks validity (`now < start(bundle_week + 2)` and
/// `bundle_week ≤ week(now) + 1`) and the `(bundle_week, bundle_rank)` rollback rule against
/// `dm_contact.bundle_week_seen`: both need a clock, which this crate does not read.
pub fn open(
    bundle_key: &SealKey,
    bundle_namespace: &[u8; 32],
    blob: &[u8],
    expected_identity_pk: &[u8; 32],
    expected_card_index: u16,
) -> DmResult<Bundle> {
    let plain = seal::open_bundle(bundle_key, bundle_namespace, blob, BUNDLE_PLAIN_BYTES)?;
    let bundle = parse(&plain)?;
    if &bundle.identity_pk != expected_identity_pk || bundle.card_index != expected_card_index {
        return Err(DmCode::BadSignature);
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::KemSecret;
    use crate::provenance::{CardSource, KeyProvenance};

    const IDENTITY_SEED: [u8; 32] = [0xa1; 32];
    const NAMESPACE: [u8; 32] = [0xa2; 32];
    /// Canonical encodings: the top byte is below `0x7f` (CRY-P9-01).
    const OLM_IDENTITY: [u8; 32] = [0x25; 32];
    const FALLBACK_KEY: [u8; 32] = [0x26; 32];

    fn bundle_key() -> SealKey {
        SealKey::new([0xa3; 32], KeyProvenance::Card(CardSource::InPerson))
    }

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let xwing = pq::public_key(&KemSecret::from_bytes([0xa4; 32])).expect("keygen");
        let plain = build(
            &IDENTITY_SEED,
            &BundleFields {
                card_index: 0,
                bundle_week: 2_870,
                bundle_rank: 0,
                gen_id: 0x1234_5678,
                olm_identity: &OLM_IDENTITY,
                fallback_key: &FALLBACK_KEY,
                xwing_public: &xwing,
            },
        )
        .expect("build");
        (plain, xwing)
    }

    #[test]
    fn a_bundle_is_one_thousand_three_hundred_and_ninety_three_bytes() {
        let (plain, _) = fixture();
        assert_eq!(plain.len(), BUNDLE_PLAIN_BYTES);
        assert_eq!(
            OFFSET_SIGNATURE + sign::SIGNATURE_BYTES,
            BUNDLE_PLAIN_BYTES,
            "the layout fills the record exactly"
        );
        assert_eq!(BUNDLE_ENV_BYTES, 1421);
    }

    #[test]
    fn round_trip_through_the_seal() {
        let (plain, xwing) = fixture();
        let parsed = parse(&plain).expect("parse");
        assert_eq!(parsed.bundle_week, 2_870);
        assert_eq!(parsed.bundle_rank, 0);
        assert_eq!(parsed.gen_id, 0x1234_5678);
        assert_eq!(parsed.xwing_public, xwing);
        let blob = seal_with(&bundle_key(), &NAMESPACE, &plain, &[0xa7; SALT_BYTES]).expect("seal");
        assert_eq!(blob.len(), BUNDLE_BLOB_BYTES);
        let identity_pk = sign::public_key(&IDENTITY_SEED);
        assert_eq!(
            open(&bundle_key(), &NAMESPACE, &blob, &identity_pk, 0).expect("open"),
            parsed
        );
    }

    #[test]
    fn another_card_or_another_owner_is_refused() {
        let (plain, _) = fixture();
        let blob = seal_with(&bundle_key(), &NAMESPACE, &plain, &[0xa7; SALT_BYTES]).expect("seal");
        let identity_pk = sign::public_key(&IDENTITY_SEED);
        assert_eq!(
            open(&bundle_key(), &NAMESPACE, &blob, &[0u8; 32], 0).err(),
            Some(DmCode::BadSignature)
        );
        assert_eq!(
            open(&bundle_key(), &NAMESPACE, &blob, &identity_pk, 1).err(),
            Some(DmCode::BadSignature)
        );
        let other_namespace = [0xa8u8; 32];
        assert_eq!(
            open(&bundle_key(), &other_namespace, &blob, &identity_pk, 0).err(),
            Some(DmCode::NotOpen)
        );
    }

    #[test]
    fn one_signature_binds_every_field() {
        let (plain, _) = fixture();
        for i in 0..OFFSET_SIGNATURE {
            let mut bad = plain.clone();
            bad[i] ^= 1;
            assert!(parse(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn a_low_order_x_wing_half_is_refused_at_open() {
        let xwing = pq::public_key(&KemSecret::from_bytes([0xb1; 32])).expect("keygen");
        let mut bad_key = xwing.clone();
        bad_key[pq::ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(&[0u8; 32]);
        let plain = build(
            &IDENTITY_SEED,
            &BundleFields {
                card_index: 0,
                bundle_week: 2_870,
                bundle_rank: 0,
                gen_id: 1,
                olm_identity: &OLM_IDENTITY,
                fallback_key: &FALLBACK_KEY,
                xwing_public: &bad_key,
            },
        )
        .expect("build");
        assert_eq!(parse(&plain).err(), Some(DmCode::InvalidKey));
    }

    /// Phase review CRY-P9-01: a signed bundle whose Olm identity or fallback key has the top bit
    /// set (the same point to X25519, other bytes to every hash and pin) is `INVALID_KEY` at the
    /// parser, so `EST-READY` drops the candidate instead of building a session whose every
    /// PreKey message `sealIntro` refuses. So is `p` itself and anything above it.
    #[test]
    fn a_non_canonical_olm_identity_or_fallback_key_is_refused_at_parse() {
        let xwing = pq::public_key(&KemSecret::from_bytes([0xa4; 32])).expect("keygen");
        let build_with = |olm_identity: &[u8; 32], fallback_key: &[u8; 32]| {
            build(
                &IDENTITY_SEED,
                &BundleFields {
                    card_index: 0,
                    bundle_week: 2_870,
                    bundle_rank: 0,
                    gen_id: 7,
                    olm_identity,
                    fallback_key,
                    xwing_public: &xwing,
                },
            )
            .expect("build signs whatever it is given")
        };
        assert!(
            parse(&build_with(&OLM_IDENTITY, &FALLBACK_KEY)).is_ok(),
            "the control parses"
        );
        let mut high = FALLBACK_KEY;
        high[31] |= 0x80;
        assert!(
            pq::contributory(&high),
            "the variant is still a usable point to X25519"
        );
        assert_eq!(
            parse(&build_with(&OLM_IDENTITY, &high)).err(),
            Some(DmCode::InvalidKey),
            "fallback key | 2^255"
        );
        let mut high_oi = OLM_IDENTITY;
        high_oi[31] |= 0x80;
        assert_eq!(
            parse(&build_with(&high_oi, &FALLBACK_KEY)).err(),
            Some(DmCode::InvalidKey),
            "Olm identity | 2^255"
        );
        assert_eq!(
            parse(&build_with(&OLM_IDENTITY, &pq::CURVE25519_P)).err(),
            Some(DmCode::InvalidKey),
            "the fallback key p"
        );
    }

    #[test]
    fn a_wrong_x_wing_length_is_refused_at_build() {
        assert_eq!(
            build(
                &IDENTITY_SEED,
                &BundleFields {
                    card_index: 0,
                    bundle_week: 1,
                    bundle_rank: 0,
                    gen_id: 1,
                    olm_identity: &[0u8; 32],
                    fallback_key: &[0u8; 32],
                    xwing_public: &[0u8; 32],
                },
            )
            .err(),
            Some(DmCode::InvalidKey)
        );
    }

    /// §15.2's seeded property run for the bundle parser. As for the card, the `10^6` run feeds
    /// length-varying inputs (the signature and whole-key validation are reached only by the rare
    /// exact-length one) and a shorter run feeds exact-length mutants; the exhaustive single-byte
    /// test above covers every signed byte of a valid bundle.
    #[test]
    fn the_bundle_parser_never_panics_on_seeded_inputs() {
        let mut rng = crate::property::Seeded::new(0x369d_ea0f_31a5_3f85);
        for _ in 0..crate::property::inputs() {
            let bytes = rng.random_input(BUNDLE_PLAIN_BYTES / 8);
            match parse(&bytes) {
                Ok(bundle) => assert_eq!(bundle.xwing_public.len(), pq::PUBLIC_KEY_BYTES),
                Err(code) => assert!(
                    matches!(
                        code,
                        DmCode::NonCanonical | DmCode::BadSignature | DmCode::InvalidKey
                    ),
                    "{code:?}"
                ),
            }
        }
        let (template, _) = fixture();
        for _ in 0..crate::property::signature_inputs() {
            let bytes = rng.mutate(&template);
            match parse(&bytes) {
                Ok(bundle) => assert_eq!(bundle.identity_pk.len(), 32),
                Err(code) => assert!(
                    matches!(
                        code,
                        DmCode::NonCanonical | DmCode::BadSignature | DmCode::InvalidKey
                    ),
                    "{code:?}"
                ),
            }
        }
    }

    #[test]
    fn a_wrong_version_or_length_is_refused() {
        let (plain, _) = fixture();
        let mut bad = plain.clone();
        bad[0] = 0x01;
        assert_eq!(parse(&bad).err(), Some(DmCode::NonCanonical));
        assert_eq!(
            parse(&plain[..BUNDLE_PLAIN_BYTES - 1]).err(),
            Some(DmCode::NonCanonical)
        );
    }
}
