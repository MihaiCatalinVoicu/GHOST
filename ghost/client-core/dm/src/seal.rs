//! The DM envelope: sealed sender without a server (design §6, T9, T29).
//!
//! Every DM blob, in all four modes, is the same shape:
//!
//! ```text
//! blob(B)  = salt(16) || hint(16) || ChaCha20-Poly1305(k, nonce = 0^12, AD, P)   |P| = B - 48
//! R_sel    = HKDF-SHA256(ikm = K_sel, salt = ∅, info = "ghost/v1/dm-recognition", L = 32)
//! hint     = HMAC-SHA256(R_sel, "ghost/v1/dm-hint" || salt)[0..16]
//! k        = HKDF-SHA256(ikm = K_sel, salt = salt, info = "ghost/v1/dm-seal" || namespace(32), L = 32)
//! AD       = "ghost/v1/dm-seal" || 0x02 || namespace(32) || u32_be(B) || mode(1) || pair_ad(32)
//! pair_ad  = SHA-256("ghost/v1/dm-pair-ad" || OI_sender || OI_recipient)   (pair, provisional)
//!            0^32                                                          (intro, bundle)
//! P        = mode(1) || mode-specific body || zeros
//! ```
//!
//! R-S1: `|blob| = B` exactly and every length is inside P, so the bytes are uniform.
//! R-S2: a blob is accepted only if it opens **and** parses exactly — a known mode and kind byte,
//! every length within P, all padding zero — so padding carries no covert channel and the format
//! is not malleable.
//! R-S3: `k` and AD bind the namespace and the bucket, so a relay that copies a blob into another
//! namespace or truncates it produces something that does not open.
//! R-S4: `k` is fresh per salt, so nonce 0 never repeats under one key. The salt is drawn from the
//! OS CSPRNG inside every production entry point ([`seal_pair`], [`seal_provisional`],
//! [`seal_bundle`], [`seal_intro`]); the `*_with` variants that take a caller's salt exist only
//! for the vectors and the deterministic equivalence fixture, as §2.6's `sealSym`, `sealIntro` and
//! `bundleCreate` carry no salt input.
//! R-S5: the recipient computes the hints of its candidate recognition keys and opens with at most
//! one key. The candidate set and the matching live in Kotlin; [`recognition_key`] and [`hint`]
//! are the primitives it uses.
//! R-S6: a recognition key recognises but does not open, and follows the erasure schedule of its
//! opening key.
//! R-S7: the key class that matched fixes the mode the AEAD expects, and `pair_ad` binds both Olm
//! identities and the seal version.

use crate::derive::{KemSecret, ReplySeed, SECRET_BYTES};
use crate::provenance::{assert_seal, SealKey, SealRequirement};
use crate::result::{DmCode, DmResult};
use crate::{binding, card, pq, sign};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Length of the random salt of every blob.
pub const SALT_BYTES: usize = 16;
/// Length of the recognition hint of every blob.
pub const HINT_BYTES: usize = 16;
/// Length of the Poly1305 tag.
pub const TAG_BYTES: usize = 16;
/// `salt || hint`, the part of a blob that is not the AEAD.
pub const HEADER_BYTES: usize = SALT_BYTES + HINT_BYTES;
/// The seal version byte inside the associated data.
pub const SEAL_VERSION: u8 = 0x02;
/// The three DM buckets. DMs never use 1 KiB (R-B2).
pub const BUCKETS: [usize; 3] = [4096, 16384, 65536];
/// Worst-case envelope overhead over an L0, frozen from measurement in S0′ (V-3): the worst intro
/// overhead measured on vodozemac 0.11.0 and 0.10.0 is 1 606 B at 64 KiB and 1 604 B at 4 and
/// 16 KiB, so 1 664 leaves 58 B of margin at the tightest class.
pub const O_MAX: usize = 1664;
/// The fixed part of an L0 with a quote (§7.1): version, kind, `message_id`, `author_minute`,
/// `minute_index`, `timer_code`, `timer_version`, `flags`, `quote_ref`, `body_len`, `ext_len`.
pub const L0_FIXED_BYTES: usize = 52;
/// The TLV room R-B1 reserves before encryption, so a pending TLV never changes the bucket.
pub const EXT_RESERVE: usize = 160;
/// The API cap on a body; longer content waits for Phase 11 media (§6.6).
pub const MAX_BODY_BYTES: usize = 61440;

/// Label of the seal key and of the associated data.
pub const SEAL_LABEL: &[u8] = b"ghost/v1/dm-seal";
/// Label of the recognition hint.
pub const HINT_LABEL: &[u8] = b"ghost/v1/dm-hint";
/// Label of the recognition key.
pub const RECOGNITION_LABEL: &[u8] = b"ghost/v1/dm-recognition";
/// Label of the associated-data binding of both Olm identities.
pub const PAIR_AD_LABEL: &[u8] = b"ghost/v1/dm-pair-ad";
/// Label of the intro KEM transcript.
pub const INTRO_KEM_LABEL: &[u8] = b"ghost/v1/dm-intro-kem";
/// Label of the intro inner key.
pub const INTRO_INNER_LABEL: &[u8] = b"ghost/v1/dm-intro-inner";
/// Label of the intro inner associated data.
pub const INTRO_AD_LABEL: &[u8] = b"ghost/v1/dm-intro";

/// Body kind of an Olm normal message inside a pair or provisional envelope.
pub const KIND_OLM_NORMAL: u8 = 0x01;
/// Body kind of an Olm PreKey message inside an intro inner layer.
pub const KIND_OLM_PREKEY: u8 = 0x02;

/// The fixed part of an intro inner plaintext: kind, card, binding minute, binding signature,
/// reply seed and `l1_len` (§6.6).
pub const INTRO_INNER_FIXED_BYTES: usize =
    1 + card::CARD_BYTES + 4 + sign::SIGNATURE_BYTES + SECRET_BYTES + 4;
/// The fixed part of an intro envelope inside the outer AEAD: mode, `gen_id`, the X-Wing
/// ciphertext and the inner tag.
pub const INTRO_OUTER_FIXED_BYTES: usize = 1 + 4 + pq::CIPHERTEXT_BYTES + TAG_BYTES;
/// The fixed part of a pair or provisional body: kind and `l1_len`.
pub const SYMMETRIC_BODY_FIXED_BYTES: usize = 5;

/// The four seal modes (§6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SealMode {
    /// Answered conversations: a per-pair symmetric key ratcheted weekly from a root the
    /// recipient generated.
    Pair = 0x01,
    /// Every PreKey message: a card-keyed outer layer and an X-Wing-keyed inner layer.
    Intro = 0x02,
    /// The weekly bundle, sealed under the card.
    Bundle = 0x03,
    /// Normal messages of a session before a pair root exists.
    Provisional = 0x04,
}

impl SealMode {
    /// The mode byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The mode of a byte, or `None` for a byte no mode uses.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => SealMode::Pair,
            0x02 => SealMode::Intro,
            0x03 => SealMode::Bundle,
            0x04 => SealMode::Provisional,
            _ => return None,
        })
    }

    /// What T35 requires of the key class that seals this mode (§9.3).
    pub const fn requirement(self) -> SealRequirement {
        match self {
            SealMode::Intro | SealMode::Bundle => SealRequirement::Card,
            SealMode::Pair | SealMode::Provisional => SealRequirement::PostQuantum,
        }
    }
}

/// `R_sel = HKDF-SHA256(ikm = K_sel, salt = ∅, info = "ghost/v1/dm-recognition", L = 32)`.
pub fn recognition_key(seal_key: &SealKey) -> [u8; SECRET_BYTES] {
    let mut out = [0u8; SECRET_BYTES];
    Hkdf::<Sha256>::new(None, seal_key.as_bytes())
        .expand(RECOGNITION_LABEL, &mut out)
        .expect("HKDF-SHA256 with L = 32 is inside the 255 x 32 byte output limit");
    out
}

/// `hint = HMAC-SHA256(R_sel, "ghost/v1/dm-hint" || salt)[0..16]`.
pub fn hint(recognition_key: &[u8; SECRET_BYTES], salt: &[u8; SALT_BYTES]) -> [u8; HINT_BYTES] {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(recognition_key)
        .expect("HMAC-SHA256 takes a key of any length");
    mac.update(HINT_LABEL);
    mac.update(salt);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HINT_BYTES];
    out.copy_from_slice(&tag[..HINT_BYTES]);
    out
}

/// True when `blob`'s hint is the one `recognition_key` produces for its salt (R-S5). Kotlin
/// matches; this is the primitive and the test oracle.
pub fn hint_matches(blob: &[u8], recognition_key: &[u8; SECRET_BYTES]) -> bool {
    if blob.len() < HEADER_BYTES {
        return false;
    }
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&blob[..SALT_BYTES]);
    hint(recognition_key, &salt) == blob[SALT_BYTES..HEADER_BYTES]
}

/// `pair_ad = SHA-256("ghost/v1/dm-pair-ad" || OI_sender || OI_recipient)` (R-S7).
pub fn pair_ad(oi_sender: &[u8; 32], oi_recipient: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(PAIR_AD_LABEL)
        .chain_update(oi_sender)
        .chain_update(oi_recipient)
        .finalize()
        .into()
}

/// The associated data of a blob. It is not transmitted.
pub fn associated_data(
    namespace: &[u8; 32],
    bucket: usize,
    mode: SealMode,
    pair_ad: &[u8; 32],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(SEAL_LABEL.len() + 1 + 32 + 4 + 1 + 32);
    ad.extend_from_slice(SEAL_LABEL);
    ad.push(SEAL_VERSION);
    ad.extend_from_slice(namespace);
    ad.extend_from_slice(&(bucket as u32).to_be_bytes());
    ad.push(mode.as_u8());
    ad.extend_from_slice(pair_ad);
    ad
}

/// The body capacity of a bucket, `C(B) = B − O_MAX` (§6.6).
pub const fn capacity(bucket: usize) -> usize {
    bucket - O_MAX
}

/// The largest L0 body a bucket carries under R-B1: `C(B) − 52 − 160`, that is 2 220 B at 4 KiB,
/// 14 508 B at 16 KiB and 63 660 B at 64 KiB.
pub const fn max_body(bucket: usize) -> usize {
    capacity(bucket) - L0_FIXED_BYTES - EXT_RESERVE
}

/// R-B1: `B = min{ b ∈ {4, 16, 64} KiB : 52 + |body| + 160 ≤ b − O_MAX }`, computed **before**
/// encryption from the body length alone, so pending TLVs and quotes never change the bucket and
/// PreKey vs normal, intro vs provisional vs pair, and text vs control of equal length land in one
/// class (T29).
pub fn bucket_for_body(body_len: usize) -> DmResult<usize> {
    if body_len > MAX_BODY_BYTES {
        return Err(DmCode::Oversize);
    }
    let l_class = L0_FIXED_BYTES + body_len + EXT_RESERVE;
    BUCKETS
        .iter()
        .copied()
        .find(|bucket| l_class <= capacity(*bucket))
        .ok_or(DmCode::Oversize)
}

/// A fresh 16-byte salt.
pub fn random_salt() -> [u8; SALT_BYTES] {
    let mut salt = [0u8; SALT_BYTES];
    pq::fill_random(&mut salt);
    salt
}

/// The derived seal key `k`. It is wiped when it goes out of scope, as every transient secret of
/// this crate is: §2.4 point 1 puts the seal in Rust precisely so that seal and KEM secrets can be
/// zeroised, which the JVM heap cannot do.
fn seal_key_of(
    seal_key: &SealKey,
    namespace: &[u8; 32],
    salt: &[u8; SALT_BYTES],
) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(SEAL_LABEL.len() + 32);
    info.extend_from_slice(SEAL_LABEL);
    info.extend_from_slice(namespace);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), seal_key.as_bytes())
        .expand(&info, out.as_mut())
        .expect("HKDF-SHA256 with L = 32 is inside the 255 x 32 byte output limit");
    out
}

fn aead(key: &[u8; 32]) -> DmResult<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| DmCode::NotOpen)
}

fn zero_nonce() -> Nonce {
    Nonce::from([0u8; 12])
}

/// Seals `body` in `mode`: `P = mode(1) || body || zeros` inside one bucket.
fn seal_body(
    key: &SealKey,
    namespace: &[u8; 32],
    bucket: usize,
    mode: SealMode,
    pair_ad: &[u8; 32],
    body: &[u8],
    salt: &[u8; SALT_BYTES],
) -> DmResult<Vec<u8>> {
    assert_seal(mode.requirement(), key);
    if !BUCKETS.contains(&bucket) {
        return Err(DmCode::NoFit);
    }
    let plaintext_len = bucket - HEADER_BYTES - TAG_BYTES;
    if body.len() + 1 > plaintext_len {
        return Err(DmCode::NoFit);
    }
    // The plaintext holds the inner layer or the Olm message: it is wiped after encryption.
    let mut plaintext = Zeroizing::new(vec![0u8; plaintext_len]);
    plaintext[0] = mode.as_u8();
    plaintext[1..1 + body.len()].copy_from_slice(body);
    let derived = seal_key_of(key, namespace, salt);
    let ad = associated_data(namespace, bucket, mode, pair_ad);
    let ciphertext = aead(&derived)?
        .encrypt(
            &zero_nonce(),
            Payload {
                msg: &plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| DmCode::NoFit)?;
    let recognition = recognition_key(key);
    let mut blob = Vec::with_capacity(bucket);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(&hint(&recognition, salt));
    blob.extend_from_slice(&ciphertext);
    if blob.len() != bucket {
        return Err(DmCode::NoFit);
    }
    Ok(blob)
}

/// Opens a blob in `mode` and returns `body || zeros` (P without its mode byte), in a buffer that
/// is wiped when the caller drops it.
fn open_body(
    key: &SealKey,
    namespace: &[u8; 32],
    mode: SealMode,
    pair_ad: &[u8; 32],
    blob: &[u8],
) -> DmResult<Zeroizing<Vec<u8>>> {
    if !BUCKETS.contains(&blob.len()) {
        return Err(DmCode::NotOpen);
    }
    let bucket = blob.len();
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&blob[..SALT_BYTES]);
    let derived = seal_key_of(key, namespace, &salt);
    let ad = associated_data(namespace, bucket, mode, pair_ad);
    let plaintext = Zeroizing::new(
        aead(&derived)?
            .decrypt(
                &zero_nonce(),
                Payload {
                    msg: &blob[HEADER_BYTES..],
                    aad: &ad,
                },
            )
            .map_err(|_| DmCode::NotOpen)?,
    );
    // R-S2: the mode byte the key class expects, and nothing else.
    if plaintext.first() != Some(&mode.as_u8()) {
        return Err(DmCode::NonCanonical);
    }
    Ok(Zeroizing::new(plaintext[1..].to_vec()))
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

/// `kind(1) || l1_len(4, BE) || L1` for pair and provisional bodies (§6.3, §6.7).
fn symmetric_body(l1: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(SYMMETRIC_BODY_FIXED_BYTES + l1.len());
    body.push(KIND_OLM_NORMAL);
    body.extend_from_slice(&(l1.len() as u32).to_be_bytes());
    body.extend_from_slice(l1);
    body
}

/// Parses `kind(1) || l1_len(4, BE) || L1 || zeros` (R-S2). A PreKey kind in a pair or provisional
/// envelope is refused: `drop(non_canonical)` of §6.5 step 5.
fn parse_symmetric_body(body: &[u8]) -> DmResult<Vec<u8>> {
    if body.len() < SYMMETRIC_BODY_FIXED_BYTES {
        return Err(DmCode::NonCanonical);
    }
    if body[0] != KIND_OLM_NORMAL {
        return Err(DmCode::NonCanonical);
    }
    let l1_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    let end = SYMMETRIC_BODY_FIXED_BYTES
        .checked_add(l1_len)
        .ok_or(DmCode::NonCanonical)?;
    if end > body.len() {
        return Err(DmCode::NonCanonical);
    }
    if !all_zero(&body[end..]) {
        return Err(DmCode::NonCanonical);
    }
    Ok(body[SYMMETRIC_BODY_FIXED_BYTES..end].to_vec())
}

/// Pair mode (§6.3): an Olm normal message under the week key of `week(author_minute)`, with a
/// fresh salt. R-S4 ("`k` is fresh per salt, so nonce 0 never repeats under one key") rests on the
/// salt being fresh, so the production entry point draws it here and never takes it from a caller;
/// [`seal_pair_with`] is the vector and equivalence-fixture path, as `seal_intro_with` is for the
/// KEM randomness.
pub fn seal_pair(
    week_key: &SealKey,
    namespace: &[u8; 32],
    bucket: usize,
    oi_sender: &[u8; 32],
    oi_recipient: &[u8; 32],
    l1: &[u8],
) -> DmResult<Vec<u8>> {
    seal_pair_with(
        week_key,
        namespace,
        bucket,
        oi_sender,
        oi_recipient,
        l1,
        &random_salt(),
    )
}

/// Pair mode with a given salt: the vector and equivalence-fixture path (§15.9 item 7).
pub fn seal_pair_with(
    week_key: &SealKey,
    namespace: &[u8; 32],
    bucket: usize,
    oi_sender: &[u8; 32],
    oi_recipient: &[u8; 32],
    l1: &[u8],
    salt: &[u8; SALT_BYTES],
) -> DmResult<Vec<u8>> {
    seal_body(
        week_key,
        namespace,
        bucket,
        SealMode::Pair,
        &pair_ad(oi_sender, oi_recipient),
        &symmetric_body(l1),
        salt,
    )
}

/// Provisional mode (§6.7): an Olm normal message under `K_prov(dir)` before a pair root exists,
/// with a fresh salt (R-S4).
pub fn seal_provisional(
    provisional_key: &SealKey,
    namespace: &[u8; 32],
    bucket: usize,
    oi_sender: &[u8; 32],
    oi_recipient: &[u8; 32],
    l1: &[u8],
) -> DmResult<Vec<u8>> {
    seal_provisional_with(
        provisional_key,
        namespace,
        bucket,
        oi_sender,
        oi_recipient,
        l1,
        &random_salt(),
    )
}

/// Provisional mode with a given salt: the vector and equivalence-fixture path (§15.9 item 7).
pub fn seal_provisional_with(
    provisional_key: &SealKey,
    namespace: &[u8; 32],
    bucket: usize,
    oi_sender: &[u8; 32],
    oi_recipient: &[u8; 32],
    l1: &[u8],
    salt: &[u8; SALT_BYTES],
) -> DmResult<Vec<u8>> {
    seal_body(
        provisional_key,
        namespace,
        bucket,
        SealMode::Provisional,
        &pair_ad(oi_sender, oi_recipient),
        &symmetric_body(l1),
        salt,
    )
}

/// Opens a pair or provisional envelope and returns its L1.
pub fn open_symmetric(
    key: &SealKey,
    namespace: &[u8; 32],
    mode: SealMode,
    oi_sender: &[u8; 32],
    oi_recipient: &[u8; 32],
    blob: &[u8],
) -> DmResult<Vec<u8>> {
    if !matches!(mode, SealMode::Pair | SealMode::Provisional) {
        return Err(DmCode::NonCanonical);
    }
    let body = open_body(
        key,
        namespace,
        mode,
        &pair_ad(oi_sender, oi_recipient),
        blob,
    )?;
    parse_symmetric_body(&body)
}

/// Bundle mode (§5.3): the 1 393-byte bundle plaintext in one 4 KiB blob under `KB_i`, with a
/// fresh salt (R-S4).
pub fn seal_bundle(
    bundle_key: &SealKey,
    namespace: &[u8; 32],
    bundle_plain: &[u8],
) -> DmResult<Vec<u8>> {
    seal_bundle_with(bundle_key, namespace, bundle_plain, &random_salt())
}

/// Bundle mode with a given salt: the vector and equivalence-fixture path (§15.9 item 7).
pub fn seal_bundle_with(
    bundle_key: &SealKey,
    namespace: &[u8; 32],
    bundle_plain: &[u8],
    salt: &[u8; SALT_BYTES],
) -> DmResult<Vec<u8>> {
    seal_body(
        bundle_key,
        namespace,
        BUCKETS[0],
        SealMode::Bundle,
        &[0u8; 32],
        bundle_plain,
        salt,
    )
}

/// Opens a bundle blob and returns its plaintext, padding checked (R-S2).
pub fn open_bundle(
    bundle_key: &SealKey,
    namespace: &[u8; 32],
    blob: &[u8],
    plain_len: usize,
) -> DmResult<Vec<u8>> {
    if blob.len() != BUCKETS[0] {
        return Err(DmCode::NotOpen);
    }
    let body = open_body(bundle_key, namespace, SealMode::Bundle, &[0u8; 32], blob)?;
    if body.len() < plain_len || !all_zero(&body[plain_len..]) {
        return Err(DmCode::NonCanonical);
    }
    Ok(body[..plain_len].to_vec())
}

/// Everything both sides of an intro envelope must agree on before the inner layer opens (§6.4).
pub struct IntroContext<'a> {
    /// The recipient's inbox namespace, which the outer layer is also bound to.
    pub namespace: &'a [u8; 32],
    /// The bucket, so the transcript names the blob length the AD already binds.
    pub bucket: usize,
    /// The recipient's bundle generation this envelope is addressed to.
    pub gen_id: u32,
    /// `Q_g`: that generation's 1 216-byte X-Wing encapsulation key.
    pub gen_public: &'a [u8],
    /// The recipient's Olm identity.
    pub recipient_oi: &'a [u8; 32],
    /// The recipient's Ed25519 identity key.
    pub recipient_identity_pk: &'a [u8; 32],
}

/// What the sender puts inside the inner layer, and signs binding v3 over (§3.4, §6.4).
pub struct IntroSender<'a> {
    /// The sender's Ed25519 identity seed, which signs binding v3.
    pub identity_seed: &'a [u8; 32],
    /// The sender's own card v2, which rides inside so one scan suffices (§12.2).
    pub card: &'a [u8; card::CARD_BYTES],
    /// The sender's Olm identity `OI_A`.
    pub oi: &'a [u8; 32],
    /// The base key of the Olm PreKey message inside this envelope.
    pub base_key: &'a [u8; 32],
    /// `floor_minute(now)` at sealing, not the compose minute (§21.4 point 1).
    pub binding_minute: u32,
    /// The session's `reply_seed`, which keys provisional replies (§6.7).
    pub reply_seed: &'a ReplySeed,
}

/// The outer layer of an intro envelope, as it comes out of the card-keyed AEAD (§6.5 step 3).
#[derive(Clone, Debug)]
pub struct IntroOuter {
    /// The bundle generation the sender addressed.
    pub gen_id: u32,
    /// The X-Wing ciphertext.
    pub ciphertext: Vec<u8>,
    /// The still-sealed inner layer.
    pub inner: Vec<u8>,
    /// The bucket the blob came in.
    pub bucket: usize,
}

/// The inner layer of an intro envelope, once the KEM has opened it (§6.4).
pub struct IntroPlain {
    /// The sender's card v2. [`open_intro_inner`] parsed it to reach the `identity_pk` that binding
    /// v3 verifies under; the bytes are returned as they arrived, and Kotlin's R5 parses them again
    /// for the card, freshness and request-path checks (§6.5 step 4).
    pub sender_card: [u8; card::CARD_BYTES],
    /// The sealing minute binding v3 covers.
    pub binding_minute: u32,
    /// The binding v3 signature, already verified against the transcript.
    pub binding_sig: [u8; sign::SIGNATURE_BYTES],
    /// The session's `reply_seed`.
    pub reply_seed: ReplySeed,
    /// The Olm PreKey message.
    pub l1: Vec<u8>,
}

impl core::fmt::Debug for IntroPlain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntroPlain")
            .field("binding_minute", &self.binding_minute)
            .field("l1_len", &self.l1.len())
            .finish_non_exhaustive()
    }
}

/// The fields of the Olm PreKey message inside an intro envelope that binding v3 is checked
/// against (§3.4, §6.5 step 4). The S4b facade parses them from the PreKey header.
pub struct PreKeyFields<'a> {
    /// `PreKey.identity_key`, which must equal `binding.OI_A`.
    pub identity_key: &'a [u8; 32],
    /// `PreKey.base_key`, which must equal `binding.base_key`.
    pub base_key: &'a [u8; 32],
    /// `PreKey.one_time_key`, which must be the generation's fallback key `F_{gen_id}`.
    pub fallback_key: &'a [u8; 32],
}

/// `T_in`, the transcript that hashes every public key and the ciphertext (§6.4), as the PQXDH
/// analysis recommends.
pub fn intro_transcript(context: &IntroContext<'_>, ciphertext: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(INTRO_KEM_LABEL)
        .chain_update(context.namespace)
        .chain_update((context.bucket as u32).to_be_bytes())
        .chain_update(context.gen_id.to_be_bytes())
        .chain_update(context.gen_public)
        .chain_update(ciphertext)
        .chain_update(context.recipient_oi)
        .chain_update(context.recipient_identity_pk)
        .finalize()
        .into()
}

/// `k_in`, wiped when it goes out of scope (§2.4 point 1). PQ1's spy counts every derivation (test
/// builds only): an open derives exactly one.
fn intro_inner_key(shared: &KemSecret, transcript: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    #[cfg(any(test, feature = "pq-spy"))]
    pq::spy::inner_key_derived();
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(transcript), shared.as_bytes())
        .expand(INTRO_INNER_LABEL, out.as_mut())
        .expect("HKDF-SHA256 with L = 32 is inside the 255 x 32 byte output limit");
    out
}

fn intro_inner_ad(transcript: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(INTRO_AD_LABEL.len() + 1 + 32);
    ad.extend_from_slice(INTRO_AD_LABEL);
    ad.push(SEAL_VERSION);
    ad.extend_from_slice(transcript);
    ad
}

/// Intro mode (§6.4): a card-keyed outer layer and an X-Wing-keyed inner layer.
///
/// Every intro envelope has its own encapsulation, so every PreKey message of an unacknowledged
/// session is sealed independently and no 16-byte window repeats across a world (JD10, NI-DM7).
/// The `kem_randomness` argument is what makes the deterministic equivalence fixture possible;
/// production callers pass fresh CSPRNG bytes through [`seal_intro`].
#[allow(clippy::too_many_arguments)]
pub fn seal_intro_with(
    outer_key: &SealKey,
    context: &IntroContext<'_>,
    sender: &IntroSender<'_>,
    l1: &[u8],
    salt: &[u8; SALT_BYTES],
    kem_randomness: &[u8; pq::ENCAPS_RANDOMNESS_BYTES],
) -> DmResult<Vec<u8>> {
    if !BUCKETS.contains(&context.bucket) {
        return Err(DmCode::NoFit);
    }
    let sender_card = card::parse(sender.card)?;
    let (ciphertext, shared) = pq::encapsulate_with(context.gen_public, kem_randomness)?;
    let transcript = intro_transcript(context, &ciphertext);
    let inner_key = intro_inner_key(&shared, &transcript);
    seal_intro_layers(
        outer_key,
        context,
        sender,
        sender_card.card_index,
        l1,
        salt,
        &ciphertext,
        &transcript,
        &inner_key,
    )
}

/// Everything of [`seal_intro_with`] after the KEM: binding v3, the inner layer under `inner_key`
/// and the card-keyed outer layer. Split out so the `gate`-variant client of PQ5 (the test-only
/// module `gate` below) builds its envelope through **the same code** and differs from an honest
/// one only in where `inner_key` came from.
#[allow(clippy::too_many_arguments)]
fn seal_intro_layers(
    outer_key: &SealKey,
    context: &IntroContext<'_>,
    sender: &IntroSender<'_>,
    sender_card_index: u16,
    l1: &[u8],
    salt: &[u8; SALT_BYTES],
    ciphertext: &[u8],
    transcript: &[u8; 32],
    inner_key: &[u8; 32],
) -> DmResult<Vec<u8>> {
    let signature = sign_intro_binding(
        sender.identity_seed,
        &binding::BindingV3 {
            oi_a: sender.oi,
            card_index_a: sender_card_index,
            recipient_namespace: context.namespace,
            binding_minute: sender.binding_minute,
            gen_id_b: context.gen_id,
            xwing_ct: ciphertext,
            base_key_a: sender.base_key,
            oi_b: context.recipient_oi,
        },
    );

    let inner_len = context.bucket - INTRO_OUTER_FIXED_BYTES - HEADER_BYTES - TAG_BYTES;
    if l1.len() + INTRO_INNER_FIXED_BYTES > inner_len {
        return Err(DmCode::NoFit);
    }
    // The inner plaintext carries the sender's card (its `card_secret`) and the session's
    // `reply_seed`: it is wiped as soon as the layer is sealed.
    let mut inner_plain = Zeroizing::new(vec![0u8; inner_len]);
    inner_plain[0] = KIND_OLM_PREKEY;
    let mut at = 1;
    inner_plain[at..at + card::CARD_BYTES].copy_from_slice(sender.card);
    at += card::CARD_BYTES;
    inner_plain[at..at + 4].copy_from_slice(&sender.binding_minute.to_be_bytes());
    at += 4;
    inner_plain[at..at + sign::SIGNATURE_BYTES].copy_from_slice(&signature);
    at += sign::SIGNATURE_BYTES;
    inner_plain[at..at + SECRET_BYTES].copy_from_slice(sender.reply_seed.as_bytes());
    at += SECRET_BYTES;
    inner_plain[at..at + 4].copy_from_slice(&(l1.len() as u32).to_be_bytes());
    at += 4;
    inner_plain[at..at + l1.len()].copy_from_slice(l1);

    let inner_ad = intro_inner_ad(transcript);
    let inner = aead(inner_key)?
        .encrypt(
            &zero_nonce(),
            Payload {
                msg: &inner_plain,
                aad: &inner_ad,
            },
        )
        .map_err(|_| DmCode::NoFit)?;

    let mut body = Vec::with_capacity(4 + ciphertext.len() + inner.len());
    body.extend_from_slice(&context.gen_id.to_be_bytes());
    body.extend_from_slice(ciphertext);
    body.extend_from_slice(&inner);
    seal_body(
        outer_key,
        context.namespace,
        context.bucket,
        SealMode::Intro,
        &[0u8; 32],
        &body,
        salt,
    )
}

/// Binding v3's signature for an intro (§3.4): in a shipped build, over the envelope's own values.
#[cfg(not(feature = "test-vectors"))]
fn sign_intro_binding(
    identity_seed: &[u8; 32],
    binding: &binding::BindingV3<'_>,
) -> [u8; sign::SIGNATURE_BYTES] {
    binding::sign(identity_seed, binding)
}

/// Binding v3's signature for an intro (§3.4), in a test build through KC5b's perturb hook, which
/// is off unless a JVM world set it on this context (`binding::hooks`, §22.37).
#[cfg(feature = "test-vectors")]
fn sign_intro_binding(
    identity_seed: &[u8; 32],
    binding: &binding::BindingV3<'_>,
) -> [u8; sign::SIGNATURE_BYTES] {
    binding::hooks::sign_intro(identity_seed, binding)
}

/// Intro mode with a fresh salt (R-S4) and CSPRNG encapsulation randomness.
pub fn seal_intro(
    outer_key: &SealKey,
    context: &IntroContext<'_>,
    sender: &IntroSender<'_>,
    l1: &[u8],
) -> DmResult<Vec<u8>> {
    let mut randomness = Zeroizing::new([0u8; pq::ENCAPS_RANDOMNESS_BYTES]);
    pq::fill_random(randomness.as_mut());
    seal_intro_with(outer_key, context, sender, l1, &random_salt(), &randomness)
}

/// Opens the card-keyed outer layer of an intro envelope (§6.5 step 3). It reads `gen_id` and the
/// ciphertext, which is all a card holder can read (L7-D3).
pub fn open_intro_outer(
    outer_key: &SealKey,
    namespace: &[u8; 32],
    blob: &[u8],
) -> DmResult<IntroOuter> {
    let bucket = blob.len();
    let body = open_body(outer_key, namespace, SealMode::Intro, &[0u8; 32], blob)?;
    if body.len() < 4 + pq::CIPHERTEXT_BYTES + TAG_BYTES {
        return Err(DmCode::NonCanonical);
    }
    let gen_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let ciphertext = body[4..4 + pq::CIPHERTEXT_BYTES].to_vec();
    let inner = body[4 + pq::CIPHERTEXT_BYTES..].to_vec();
    Ok(IntroOuter {
        gen_id,
        ciphertext,
        inner,
        bucket,
    })
}

/// Parses `kind(1) || card(131) || binding_minute(4) || binding_sig(64) || reply_seed(32)
/// || l1_len(4, BE) || L1 || zeros` (§6.4), with no cryptography: the pure parser the seeded
/// property run of R-C4 exercises directly, without paying for a decapsulation per input.
pub(crate) fn parse_intro_inner(plain: &[u8]) -> DmResult<IntroPlain> {
    if plain.len() < INTRO_INNER_FIXED_BYTES || plain[0] != KIND_OLM_PREKEY {
        return Err(DmCode::NonCanonical);
    }
    let mut at = 1;
    let mut sender_card = [0u8; card::CARD_BYTES];
    sender_card.copy_from_slice(&plain[at..at + card::CARD_BYTES]);
    at += card::CARD_BYTES;
    let binding_minute =
        u32::from_be_bytes([plain[at], plain[at + 1], plain[at + 2], plain[at + 3]]);
    at += 4;
    let mut binding_sig = [0u8; sign::SIGNATURE_BYTES];
    binding_sig.copy_from_slice(&plain[at..at + sign::SIGNATURE_BYTES]);
    at += sign::SIGNATURE_BYTES;
    let mut reply_seed = Zeroizing::new([0u8; SECRET_BYTES]);
    reply_seed.copy_from_slice(&plain[at..at + SECRET_BYTES]);
    at += SECRET_BYTES;
    let l1_len =
        u32::from_be_bytes([plain[at], plain[at + 1], plain[at + 2], plain[at + 3]]) as usize;
    at += 4;
    let end = at.checked_add(l1_len).ok_or(DmCode::NonCanonical)?;
    if end > plain.len() || !all_zero(&plain[end..]) {
        return Err(DmCode::NonCanonical);
    }
    Ok(IntroPlain {
        sender_card,
        binding_minute,
        binding_sig,
        reply_seed: ReplySeed::from_bytes(*reply_seed),
        l1: plain[at..end].to_vec(),
    })
}

/// Opens the X-Wing-keyed inner layer, verifies binding v3 and enforces all three equalities of
/// §6.5 step 4 — `binding.OI_A = PreKey.identity_key` and `binding.base_key = PreKey.base_key`
/// through the transcript the signature covers, and `PreKey.one_time_key = F_{gen_id}` against the
/// `generation_fallback_key` argument, so the S4b facade cannot forget the third. Every
/// decapsulation error is `NOT_OPEN`, never a crash (§22.8.2 rule 4).
pub fn open_intro_inner(
    gen_seed: &KemSecret,
    context: &IntroContext<'_>,
    outer: &IntroOuter,
    prekey: &PreKeyFields<'_>,
    generation_fallback_key: &[u8; 32],
) -> DmResult<IntroPlain> {
    let opened = open_intro_layer(gen_seed, context, outer)?;
    verify_intro_binding(&opened, context, outer, prekey, generation_fallback_key)?;
    Ok(opened)
}

/// Opens the inner layer and, in the same decapsulation, checks §6.5 step 4 against the PreKey
/// header the layer itself carries.
///
/// This is the shape the JNI surface uses (§2.6 function 12), because the three equalities of
/// §6.5 step 4 are checked against the **message inside this envelope** and nothing else: taking
/// the header from a caller would make a mismatched pair a caller's mistake rather than an
/// impossibility, and decapsulating twice to read it first would double the KEM cost of every
/// first flight.
pub fn open_intro_checked(
    gen_seed: &KemSecret,
    context: &IntroContext<'_>,
    outer: &IntroOuter,
    generation_fallback_key: &[u8; 32],
) -> DmResult<(IntroPlain, crate::olm::message::L1Header)> {
    let opened = open_intro_layer(gen_seed, context, outer)?;
    let header = crate::olm::message::parse(&opened.l1, true)?;
    let crate::olm::message::L1Header::PreKey {
        identity_key,
        base_key,
        one_time_key,
        ..
    } = header
    else {
        // An intro envelope carries a PreKey message by construction (§6.4); a normal message
        // inside one is `drop(non_canonical)` of §6.5 step 5's mirror image.
        return Err(DmCode::NonCanonical);
    };
    verify_intro_binding(
        &opened,
        context,
        outer,
        &PreKeyFields {
            identity_key: &identity_key,
            base_key: &base_key,
            fallback_key: &one_time_key,
        },
        generation_fallback_key,
    )?;
    Ok((opened, header))
}

/// The decapsulation and the AEAD open of the inner layer, without any signature check: both
/// public entry points add their own, and neither returns before they have.
pub(crate) fn open_intro_layer(
    gen_seed: &KemSecret,
    context: &IntroContext<'_>,
    outer: &IntroOuter,
) -> DmResult<IntroPlain> {
    if context.gen_id != outer.gen_id || context.bucket != outer.bucket {
        return Err(DmCode::NotOpen);
    }
    let shared = pq::decapsulate(gen_seed, &outer.ciphertext)?;
    let transcript = intro_transcript(context, &outer.ciphertext);
    let inner_ad = intro_inner_ad(&transcript);
    let plain = Zeroizing::new(
        aead(&intro_inner_key(&shared, &transcript))?
            .decrypt(
                &zero_nonce(),
                Payload {
                    msg: &outer.inner,
                    aad: &inner_ad,
                },
            )
            .map_err(|_| DmCode::NotOpen)?,
    );
    parse_intro_inner(&plain)
}

/// Binding v3 and the generation's fallback key (§6.5 step 4), against an already-opened layer.
fn verify_intro_binding(
    opened: &IntroPlain,
    context: &IntroContext<'_>,
    outer: &IntroOuter,
    prekey: &PreKeyFields<'_>,
    generation_fallback_key: &[u8; 32],
) -> DmResult<()> {
    // The card is parsed for the `identity_pk` binding v3 verifies under. A card that does not
    // parse is `drop(non_canonical)` (§6.5 step 4, §2.6 function 12): `INVALID_CARD` belongs to
    // `cardParse`, which is a different call.
    let sender = card::parse(&opened.sender_card).map_err(|_| DmCode::NonCanonical)?;
    // The binding names the sender's Olm identity and base key; §6.5 step 4 requires the PreKey
    // header to carry the same, and the one-time key to be this generation's fallback key.
    binding::verify(
        &sender.identity_pk,
        &binding::BindingV3 {
            oi_a: prekey.identity_key,
            card_index_a: sender.card_index,
            recipient_namespace: context.namespace,
            binding_minute: opened.binding_minute,
            gen_id_b: context.gen_id,
            xwing_ct: &outer.ciphertext,
            base_key_a: prekey.base_key,
            oi_b: context.recipient_oi,
        },
        &opened.binding_sig,
    )?;
    check_generation_fallback_key(prekey, generation_fallback_key)
}

/// The generation's fallback key check of §6.5 step 4: `PreKey.one_time_key = F_{gen_id}`.
/// [`open_intro_inner`] runs it; it stays public because the S4b facade parses the PreKey header
/// and may reach the same check from its own path.
pub fn check_generation_fallback_key(
    prekey: &PreKeyFields<'_>,
    generation_fallback_key: &[u8; 32],
) -> DmResult<()> {
    if prekey.fallback_key != generation_fallback_key {
        return Err(DmCode::NonCanonical);
    }
    Ok(())
}

/// The `gate`-variant client of PQ5 (design §15.5 PQ5, RG-5; §15.7 PM-32; §22.20): an intro
/// sealer whose inner layer is keyed **without the X-Wing KEM**, which an honest recipient must
/// refuse. Test builds only.
///
/// The envelope is the one [`seal_intro_with`] builds — the same binding v3, inner plaintext,
/// bucket and card-keyed outer layer, through `seal_intro_layers` — and differs only in where
/// `k_in` came from, so a refusal can only be the recipient's KEM dependence and never a malformed
/// envelope. The [`InnerKey::Kem`] control **is** [`seal_intro_with`] and must open, which is what
/// keeps the refusals from being vacuous.
///
/// **What it can and cannot refuse.** It is a list of attacker keys, not a proof: a recipient that
/// falls back to one of these keys is caught, and one that falls back to a key nobody put on the
/// list — derived from the recipient's own identity key, say — is not, unless it **tries** it after
/// the KEM key failed, which PQ1's one-inner-key-per-open count refuses whatever the key
/// (`pq::spy::assert_intro_open`). A recipient that picks a non-KEM key by a condition, without
/// trying the KEM key first, is caught only when the condition is one a variant here triggers:
/// [`InnerKey::LowOrderShare`] is the decapsulation error.
#[cfg(test)]
pub(crate) mod gate {
    use super::*;

    /// Where the gate-variant client takes the intro inner key from.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum InnerKey {
        /// Control: the production sealer, [`seal_intro_with`].
        Kem,
        /// No encapsulation at all: 1 120 fixed bytes where the ciphertext goes, and `k_in` from an
        /// all-zero secret, which anybody who reads the transcript computes.
        NoEncapsulation,
        /// A real encapsulation whose secret is dropped: `k_in` from an all-zero secret.
        SecretDropped,
        /// A real encapsulation, `k_in` from the card-derived outer key: the inner layer is then
        /// no stronger than the classical outer one.
        CardKey,
        /// A real encapsulation, `k_in` from `SHA-256(ct)`: a public value.
        CiphertextHash,
        /// A real encapsulation's ML-KEM half with a **low-order X25519 share** in place of its
        /// own, which the recipient's decapsulation refuses (§22.8.2 rule 5), and `k_in` from an
        /// all-zero secret: what a recipient that takes a failed decapsulation for a zero secret
        /// would open. Every other variant carries a ciphertext that decapsulates, so without this
        /// one the recipient's error path is never reached.
        LowOrderShare,
    }

    impl InnerKey {
        /// Every variant that seals the inner layer without the KEM secret.
        pub(crate) const WITHOUT_KEM: [InnerKey; 5] = [
            InnerKey::NoEncapsulation,
            InnerKey::SecretDropped,
            InnerKey::CardKey,
            InnerKey::CiphertextHash,
            InnerKey::LowOrderShare,
        ];
    }

    /// `k_in` exactly as both sides derive it — counted by PQ1's spy like every derivation — for
    /// the tests of the assertion's inner-key count.
    pub(crate) fn inner_key(secret: &KemSecret, transcript: &[u8; 32]) -> [u8; 32] {
        *intro_inner_key(secret, transcript)
    }

    /// [`seal_intro_with`] with the inner key taken from `variant`.
    pub(crate) fn seal_intro(
        variant: InnerKey,
        outer_key: &SealKey,
        context: &IntroContext<'_>,
        sender: &IntroSender<'_>,
        l1: &[u8],
        salt: &[u8; SALT_BYTES],
        kem_randomness: &[u8; pq::ENCAPS_RANDOMNESS_BYTES],
    ) -> DmResult<Vec<u8>> {
        if variant == InnerKey::Kem {
            return seal_intro_with(outer_key, context, sender, l1, salt, kem_randomness);
        }
        if !BUCKETS.contains(&context.bucket) {
            return Err(DmCode::NoFit);
        }
        let sender_card = card::parse(sender.card)?;
        let zero = KemSecret::from_bytes([0u8; 32]);
        let (ciphertext, secret) = if variant == InnerKey::NoEncapsulation {
            (vec![0x5a; pq::CIPHERTEXT_BYTES], zero)
        } else {
            let (mut ciphertext, _) = pq::encapsulate_with(context.gen_public, kem_randomness)?;
            let secret = match variant {
                InnerKey::CardKey => KemSecret::from_bytes(*outer_key.as_bytes()),
                InnerKey::CiphertextHash => {
                    KemSecret::from_bytes(Sha256::digest(&ciphertext).into())
                }
                InnerKey::LowOrderShare => {
                    let point = pq::low_order_points()[0];
                    ciphertext[pq::ML_KEM_CIPHERTEXT_BYTES..].copy_from_slice(&point);
                    zero
                }
                // `Kem` returned above.
                InnerKey::SecretDropped | InnerKey::NoEncapsulation | InnerKey::Kem => zero,
            };
            (ciphertext, secret)
        };
        let transcript = intro_transcript(context, &ciphertext);
        let inner_key = intro_inner_key(&secret, &transcript);
        seal_intro_layers(
            outer_key,
            context,
            sender,
            sender_card.card_index,
            l1,
            salt,
            &ciphertext,
            &transcript,
            &inner_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::CardSecret;
    use crate::provenance::{CardSource, KeyProvenance};

    const NAMESPACE: [u8; 32] = [0x11; 32];
    const OI_SENDER: [u8; 32] = [0x21; 32];
    const OI_RECIPIENT: [u8; 32] = [0x22; 32];
    const IDENTITY_SEED: [u8; 32] = [0x31; 32];

    fn pq_key(byte: u8) -> SealKey {
        SealKey::new([byte; 32], KeyProvenance::Kem.transported_under())
    }

    fn card_key(byte: u8) -> SealKey {
        SealKey::new([byte; 32], KeyProvenance::Card(CardSource::InPerson))
    }

    #[test]
    fn buckets_follow_the_body_length_only() {
        assert_eq!(bucket_for_body(0), Ok(4096));
        assert_eq!(bucket_for_body(max_body(4096)), Ok(4096));
        assert_eq!(bucket_for_body(max_body(4096) + 1), Ok(16384));
        assert_eq!(bucket_for_body(max_body(16384)), Ok(16384));
        assert_eq!(bucket_for_body(max_body(16384) + 1), Ok(65536));
        assert_eq!(bucket_for_body(MAX_BODY_BYTES), Ok(65536));
        assert_eq!(bucket_for_body(MAX_BODY_BYTES + 1), Err(DmCode::Oversize));
    }

    #[test]
    fn the_frozen_capacities_of_the_design() {
        assert_eq!(O_MAX, 1664);
        assert_eq!(max_body(4096), 2220);
        assert_eq!(max_body(16384), 14508);
        assert_eq!(max_body(65536), 63660);
        assert_eq!(capacity(4096), 2432);
        assert_eq!(capacity(16384), 14720);
        assert_eq!(capacity(65536), 63872);
    }

    #[test]
    fn the_intro_fixed_part_is_one_thousand_three_hundred_and_seventy_six_bytes() {
        // §6.6: gen_id 4, xwing_ct 1 120, inner tag 16, kind 1, card 131, minute 4, binding 64,
        // reply seed 32, l1_len 4.
        assert_eq!(INTRO_OUTER_FIXED_BYTES - 1 + INTRO_INNER_FIXED_BYTES, 1376);
    }

    #[test]
    fn pair_and_provisional_round_trip_in_every_bucket() {
        let key = pq_key(0x41);
        for bucket in BUCKETS {
            let l1 = vec![7u8; 64];
            let blob = seal_pair_with(
                &key,
                &NAMESPACE,
                bucket,
                &OI_SENDER,
                &OI_RECIPIENT,
                &l1,
                &[0x55; SALT_BYTES],
            )
            .expect("seal");
            assert_eq!(blob.len(), bucket);
            let opened = open_symmetric(
                &key,
                &NAMESPACE,
                SealMode::Pair,
                &OI_SENDER,
                &OI_RECIPIENT,
                &blob,
            )
            .expect("open");
            assert_eq!(opened, l1);
            let provisional = seal_provisional_with(
                &key,
                &NAMESPACE,
                bucket,
                &OI_SENDER,
                &OI_RECIPIENT,
                &l1,
                &[0x55; SALT_BYTES],
            )
            .expect("seal");
            // The same bytes under another mode do not open: the AD binds the mode (R-S7).
            assert_eq!(
                open_symmetric(
                    &key,
                    &NAMESPACE,
                    SealMode::Pair,
                    &OI_SENDER,
                    &OI_RECIPIENT,
                    &provisional
                )
                .err(),
                Some(DmCode::NotOpen)
            );
        }
    }

    #[test]
    fn the_associated_data_binds_namespace_bucket_mode_and_identities() {
        let key = pq_key(0x42);
        let blob = seal_pair_with(
            &key,
            &NAMESPACE,
            4096,
            &OI_SENDER,
            &OI_RECIPIENT,
            b"l1",
            &[1u8; SALT_BYTES],
        )
        .expect("seal");
        let other_namespace = [0x12u8; 32];
        assert_eq!(
            open_symmetric(
                &key,
                &other_namespace,
                SealMode::Pair,
                &OI_SENDER,
                &OI_RECIPIENT,
                &blob
            )
            .err(),
            Some(DmCode::NotOpen)
        );
        assert_eq!(
            open_symmetric(
                &key,
                &NAMESPACE,
                SealMode::Pair,
                &OI_RECIPIENT,
                &OI_SENDER,
                &blob
            )
            .err(),
            Some(DmCode::NotOpen)
        );
        // A truncated or extended blob is not a bucket any more.
        assert_eq!(
            open_symmetric(
                &key,
                &NAMESPACE,
                SealMode::Pair,
                &OI_SENDER,
                &OI_RECIPIENT,
                &blob[..4095]
            )
            .err(),
            Some(DmCode::NotOpen)
        );
    }

    #[test]
    fn the_hint_recognises_without_opening() {
        let key = pq_key(0x43);
        let salt = [0x77u8; SALT_BYTES];
        let blob = seal_pair_with(
            &key,
            &NAMESPACE,
            4096,
            &OI_SENDER,
            &OI_RECIPIENT,
            b"l1",
            &salt,
        )
        .expect("seal");
        let recognition = recognition_key(&key);
        assert!(hint_matches(&blob, &recognition));
        assert!(!hint_matches(&blob, &recognition_key(&pq_key(0x44))));
        // A recognition key is not an opening key.
        assert_ne!(&recognition, key.as_bytes());
    }

    #[test]
    fn a_fresh_salt_gives_fresh_bytes() {
        let key = pq_key(0x45);
        let first = seal_pair_with(
            &key,
            &NAMESPACE,
            4096,
            &OI_SENDER,
            &OI_RECIPIENT,
            b"l1",
            &[1u8; SALT_BYTES],
        )
        .expect("seal");
        let second = seal_pair_with(
            &key,
            &NAMESPACE,
            4096,
            &OI_SENDER,
            &OI_RECIPIENT,
            b"l1",
            &[2u8; SALT_BYTES],
        )
        .expect("seal");
        assert_ne!(first[HEADER_BYTES..], second[HEADER_BYTES..]);
    }

    /// R-S4: `k` is fresh per salt, so nonce 0 never repeats under one key. The salt is drawn
    /// inside Rust by every production entry point — §2.6's `sealIntro`, `sealSym` and
    /// `bundleCreate` carry no salt input — and only the `*_with` variants the vectors and the
    /// equivalence fixture use take one from a caller.
    #[test]
    fn the_production_entry_points_draw_their_own_salt() {
        let key = pq_key(0x47);
        let mut salts = Vec::new();
        for _ in 0..16 {
            let pair = seal_pair(&key, &NAMESPACE, 4096, &OI_SENDER, &OI_RECIPIENT, b"l1")
                .expect("seal pair");
            let provisional =
                seal_provisional(&key, &NAMESPACE, 4096, &OI_SENDER, &OI_RECIPIENT, b"l1")
                    .expect("seal provisional");
            salts.push(pair[..SALT_BYTES].to_vec());
            salts.push(provisional[..SALT_BYTES].to_vec());
        }
        let bundle_key = card_key(0x48);
        for _ in 0..16 {
            let blob = seal_bundle(&bundle_key, &NAMESPACE, &[0x5a; 1393]).expect("seal bundle");
            salts.push(blob[..SALT_BYTES].to_vec());
        }
        let count = salts.len();
        salts.sort_unstable();
        salts.dedup();
        assert_eq!(salts.len(), count, "a salt repeated");
        assert!(!salts.contains(&vec![0u8; SALT_BYTES]));
    }

    #[test]
    fn non_zero_padding_is_refused() {
        let key = pq_key(0x46);
        let l1 = vec![3u8; 16];
        // Build the plaintext by hand with one padding byte set.
        let bucket = 4096;
        let plaintext_len = bucket - HEADER_BYTES - TAG_BYTES;
        let mut plaintext = vec![0u8; plaintext_len];
        plaintext[0] = SealMode::Pair.as_u8();
        plaintext[1] = KIND_OLM_NORMAL;
        plaintext[2..6].copy_from_slice(&(l1.len() as u32).to_be_bytes());
        plaintext[6..6 + l1.len()].copy_from_slice(&l1);
        plaintext[plaintext_len - 1] = 1;
        let salt = [9u8; SALT_BYTES];
        let derived = seal_key_of(&key, &NAMESPACE, &salt);
        let ad = associated_data(
            &NAMESPACE,
            bucket,
            SealMode::Pair,
            &pair_ad(&OI_SENDER, &OI_RECIPIENT),
        );
        let ciphertext = aead(&derived)
            .expect("aead")
            .encrypt(
                &zero_nonce(),
                Payload {
                    msg: &plaintext,
                    aad: &ad,
                },
            )
            .expect("encrypt");
        let mut blob = Vec::with_capacity(bucket);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&hint(&recognition_key(&key), &salt));
        blob.extend_from_slice(&ciphertext);
        assert_eq!(
            open_symmetric(
                &key,
                &NAMESPACE,
                SealMode::Pair,
                &OI_SENDER,
                &OI_RECIPIENT,
                &blob
            )
            .err(),
            Some(DmCode::NonCanonical)
        );
    }

    struct IntroFixture {
        outer_key: SealKey,
        gen_seed: KemSecret,
        gen_public: Vec<u8>,
        card: [u8; card::CARD_BYTES],
        reply_seed: ReplySeed,
    }

    fn intro_fixture() -> IntroFixture {
        let gen_seed = KemSecret::from_bytes([0x61; 32]);
        let gen_public = pq::public_key(&gen_seed).expect("keygen");
        let card = crate::card::build(&IDENTITY_SEED, 0, &CardSecret::from_bytes([0x62; 32]));
        IntroFixture {
            outer_key: card_key(0x63),
            gen_seed,
            gen_public,
            card: card.encode(),
            reply_seed: ReplySeed::from_bytes([0x64; 32]),
        }
    }

    fn intro_context<'a>(fixture: &'a IntroFixture, bucket: usize) -> IntroContext<'a> {
        IntroContext {
            namespace: &NAMESPACE,
            bucket,
            gen_id: 0xdead_beef,
            gen_public: &fixture.gen_public,
            recipient_oi: &OI_RECIPIENT,
            recipient_identity_pk: &[0x65; 32],
        }
    }

    #[test]
    fn an_intro_envelope_round_trips_and_binds_its_prekey_fields() {
        let fixture = intro_fixture();
        let base_key = [0x71u8; 32];
        let fallback = [0x72u8; 32];
        let l1 = vec![8u8; 100];
        for bucket in BUCKETS {
            let context = intro_context(&fixture, bucket);
            let sender = IntroSender {
                identity_seed: &IDENTITY_SEED,
                card: &fixture.card,
                oi: &OI_SENDER,
                base_key: &base_key,
                binding_minute: 29_000_000,
                reply_seed: &fixture.reply_seed,
            };
            let blob = seal_intro(&fixture.outer_key, &context, &sender, &l1).expect("seal");
            assert_eq!(blob.len(), bucket);
            let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
            assert_eq!(outer.gen_id, 0xdead_beef);
            assert_eq!(outer.ciphertext.len(), pq::CIPHERTEXT_BYTES);
            let prekey = PreKeyFields {
                identity_key: &OI_SENDER,
                base_key: &base_key,
                fallback_key: &fallback,
            };
            let plain = open_intro_inner(&fixture.gen_seed, &context, &outer, &prekey, &fallback)
                .expect("inner");
            assert_eq!(plain.l1, l1);
            assert_eq!(plain.sender_card, fixture.card);
            assert_eq!(plain.binding_minute, 29_000_000);
            assert_eq!(plain.reply_seed.as_bytes(), fixture.reply_seed.as_bytes());
            assert_eq!(check_generation_fallback_key(&prekey, &fallback), Ok(()));
            assert_eq!(
                check_generation_fallback_key(&prekey, &[0u8; 32]).err(),
                Some(DmCode::NonCanonical)
            );
        }
    }

    /// §6.5 step 4's third equality, `PreKey.one_time_key = F_{gen_id}`, is enforced by the opener
    /// itself: a PreKey header naming a fallback key that is not the generation's is refused even
    /// when the envelope opens and the binding verifies.
    #[test]
    fn the_opener_enforces_the_generations_fallback_key() {
        let fixture = intro_fixture();
        let base_key = [0x71u8; 32];
        let fallback = [0x72u8; 32];
        let context = intro_context(&fixture, 4096);
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &OI_SENDER,
            base_key: &base_key,
            binding_minute: 29_000_000,
            reply_seed: &fixture.reply_seed,
        };
        let blob = seal_intro(&fixture.outer_key, &context, &sender, b"l1").expect("seal");
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        let prekey = PreKeyFields {
            identity_key: &OI_SENDER,
            base_key: &base_key,
            fallback_key: &fallback,
        };
        assert!(open_intro_inner(&fixture.gen_seed, &context, &outer, &prekey, &fallback).is_ok());
        for wrong in [[0u8; 32], [0x73u8; 32]] {
            assert_eq!(
                open_intro_inner(&fixture.gen_seed, &context, &outer, &prekey, &wrong).err(),
                Some(DmCode::NonCanonical),
                "a fallback key that is not the generation's must not open"
            );
        }
    }

    /// An inner card that does not parse is `drop(non_canonical)` (§6.5 step 4): `INVALID_CARD`
    /// belongs to `cardParse`, and §2.6 function 12 does not list it for `openIntro`.
    #[test]
    fn an_unparsable_inner_card_is_non_canonical_not_invalid_card() {
        let fixture = intro_fixture();
        let context = intro_context(&fixture, 4096);
        let blob = {
            // Build an inner layer by hand so the card bytes can be corrupted after sealing.
            let (ciphertext, shared) =
                pq::encapsulate_with(&fixture.gen_public, &[0x11; pq::ENCAPS_RANDOMNESS_BYTES])
                    .expect("encaps");
            let transcript = intro_transcript(&context, &ciphertext);
            let inner_len = context.bucket - INTRO_OUTER_FIXED_BYTES - HEADER_BYTES - TAG_BYTES;
            let mut inner_plain = vec![0u8; inner_len];
            inner_plain[0] = KIND_OLM_PREKEY;
            let mut bad_card = fixture.card;
            bad_card[0] = 0x01; // a card version Phase 9 never issued
            inner_plain[1..1 + card::CARD_BYTES].copy_from_slice(&bad_card);
            let inner = aead(&intro_inner_key(&shared, &transcript))
                .expect("aead")
                .encrypt(
                    &zero_nonce(),
                    Payload {
                        msg: &inner_plain,
                        aad: &intro_inner_ad(&transcript),
                    },
                )
                .expect("encrypt");
            let mut body = Vec::new();
            body.extend_from_slice(&context.gen_id.to_be_bytes());
            body.extend_from_slice(&ciphertext);
            body.extend_from_slice(&inner);
            seal_body(
                &fixture.outer_key,
                &NAMESPACE,
                context.bucket,
                SealMode::Intro,
                &[0u8; 32],
                &body,
                &[0x55; SALT_BYTES],
            )
            .expect("seal")
        };
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        assert_eq!(
            open_intro_inner(
                &fixture.gen_seed,
                &context,
                &outer,
                &PreKeyFields {
                    identity_key: &OI_SENDER,
                    base_key: &[0x71; 32],
                    fallback_key: &[0x72; 32],
                },
                &[0x72; 32],
            )
            .err(),
            Some(DmCode::NonCanonical)
        );
    }

    #[test]
    fn a_binding_cannot_be_moved_to_another_envelope() {
        let fixture = intro_fixture();
        let base_key = [0x71u8; 32];
        let context = intro_context(&fixture, 4096);
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &OI_SENDER,
            base_key: &base_key,
            binding_minute: 29_000_000,
            reply_seed: &fixture.reply_seed,
        };
        let blob = seal_intro(&fixture.outer_key, &context, &sender, b"l1").expect("seal");
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        // Another base key, another Olm identity, another recipient namespace, another generation.
        let other = [0u8; 32];
        for prekey in [
            PreKeyFields {
                identity_key: &OI_SENDER,
                base_key: &other,
                fallback_key: &other,
            },
            PreKeyFields {
                identity_key: &other,
                base_key: &base_key,
                fallback_key: &other,
            },
        ] {
            assert_eq!(
                open_intro_inner(&fixture.gen_seed, &context, &outer, &prekey, &other).err(),
                Some(DmCode::BadSignature)
            );
        }
        let other_namespace = [0x13u8; 32];
        let moved = IntroContext {
            namespace: &other_namespace,
            ..intro_context(&fixture, 4096)
        };
        assert_eq!(
            open_intro_inner(
                &fixture.gen_seed,
                &moved,
                &outer,
                &PreKeyFields {
                    identity_key: &OI_SENDER,
                    base_key: &base_key,
                    fallback_key: &other,
                },
                &other,
            )
            .err(),
            Some(DmCode::NotOpen),
            "the transcript covers the namespace, so the inner layer does not even open"
        );
    }

    #[test]
    fn a_card_holder_reads_the_generation_and_the_ciphertext_and_no_more() {
        let fixture = intro_fixture();
        let base_key = [0x71u8; 32];
        let context = intro_context(&fixture, 4096);
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &OI_SENDER,
            base_key: &base_key,
            binding_minute: 1,
            reply_seed: &fixture.reply_seed,
        };
        let blob = seal_intro(&fixture.outer_key, &context, &sender, b"secret l1").expect("seal");
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        // Without the generation secret the inner layer stays closed.
        let wrong_seed = KemSecret::from_bytes([0u8; 32]);
        assert_eq!(
            open_intro_inner(
                &wrong_seed,
                &context,
                &outer,
                &PreKeyFields {
                    identity_key: &OI_SENDER,
                    base_key: &base_key,
                    fallback_key: &[0u8; 32],
                },
                &[0u8; 32],
            )
            .err(),
            Some(DmCode::NotOpen)
        );
        assert!(!outer.inner.windows(9).any(|w| w == b"secret l1"));
    }

    /// §22.8.2 rule 5 (d), through the opener a peek reaches: a sender that replaces `ct_X` with a
    /// low-order point makes libcrux error, and that error must be `NOT_OPEN` with no state change
    /// and no panic.
    #[test]
    fn a_low_order_ciphertext_half_is_not_open_through_the_intro_opener() {
        let fixture = intro_fixture();
        let base_key = [0x71u8; 32];
        let fallback = [0x72u8; 32];
        let context = intro_context(&fixture, 4096);
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &OI_SENDER,
            base_key: &base_key,
            binding_minute: 29_000_000,
            reply_seed: &fixture.reply_seed,
        };
        let blob = seal_intro(&fixture.outer_key, &context, &sender, b"l1").expect("seal");
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        let prekey = PreKeyFields {
            identity_key: &OI_SENDER,
            base_key: &base_key,
            fallback_key: &fallback,
        };
        for point in pq::low_order_points() {
            let mut poisoned = IntroOuter {
                gen_id: outer.gen_id,
                ciphertext: outer.ciphertext.clone(),
                inner: outer.inner.clone(),
                bucket: outer.bucket,
            };
            poisoned.ciphertext[pq::ML_KEM_CIPHERTEXT_BYTES..].copy_from_slice(&point);
            assert_eq!(
                open_intro_inner(&fixture.gen_seed, &context, &poisoned, &prekey, &fallback).err(),
                Some(DmCode::NotOpen)
            );
        }
    }

    #[test]
    fn every_encapsulation_is_fresh() {
        let fixture = intro_fixture();
        let base_key = [0x71u8; 32];
        let context = intro_context(&fixture, 4096);
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &OI_SENDER,
            base_key: &base_key,
            binding_minute: 1,
            reply_seed: &fixture.reply_seed,
        };
        let first = seal_intro(&fixture.outer_key, &context, &sender, b"l1").expect("a");
        let second = seal_intro(&fixture.outer_key, &context, &sender, b"l1").expect("b");
        assert_ne!(first, second);
        // The production entry point draws its own salt, so no two blobs share one (R-S4).
        assert_ne!(first[..SALT_BYTES], second[..SALT_BYTES]);
        let a = open_intro_outer(&fixture.outer_key, &NAMESPACE, &first).expect("a");
        let b = open_intro_outer(&fixture.outer_key, &NAMESPACE, &second).expect("b");
        assert_ne!(a.ciphertext, b.ciphertext);
        // JD10: no 16-byte window of one inner layer appears in the other.
        assert!(!a
            .inner
            .windows(16)
            .any(|w| b.inner.windows(16).any(|o| o == w)));
    }

    #[test]
    #[should_panic(expected = "T35")]
    fn pm_32_an_intro_inner_layer_without_the_kem_trips_t35() {
        // A pair envelope keyed from a card-derived secret: the PM-32/PM-33 shape.
        let bad = SealKey::new([1u8; 32], KeyProvenance::Card(CardSource::Link));
        let _ = seal_pair_with(
            &bad,
            &NAMESPACE,
            4096,
            &OI_SENDER,
            &OI_RECIPIENT,
            b"l1",
            &[0u8; SALT_BYTES],
        );
    }

    #[test]
    #[should_panic(expected = "T35")]
    fn a_kem_key_may_not_seal_a_bundle() {
        let _ = seal_bundle_with(&pq_key(1), &NAMESPACE, &[0u8; 1393], &[0u8; SALT_BYTES]);
    }

    /// §15.2 asks for a seeded property run over every parser. The two parsers behind the AEADs —
    /// the pair/provisional body and the intro inner layer — are exercised directly, so `10^6`
    /// inputs per run are reachable: each runs on the plaintext an opener has already decrypted,
    /// and neither may panic or over-read on any byte string.
    #[test]
    fn the_symmetric_body_parser_never_panics_on_seeded_inputs() {
        let mut rng = crate::property::Seeded::new(0x1234_5678_9abc_def0);
        let template = {
            let mut body = symmetric_body(&[7u8; 64]);
            body.resize(4096 - HEADER_BYTES - TAG_BYTES - 1, 0);
            body
        };
        for _ in 0..crate::property::inputs() {
            let bytes = if rng.below(4) == 0 {
                rng.random_input(64)
            } else {
                rng.mutate(&template)
            };
            match parse_symmetric_body(&bytes) {
                Ok(l1) => assert!(l1.len() + SYMMETRIC_BODY_FIXED_BYTES <= bytes.len()),
                Err(code) => assert_eq!(code, DmCode::NonCanonical),
            }
        }
    }

    #[test]
    fn the_intro_inner_parser_never_panics_on_seeded_inputs() {
        let mut rng = crate::property::Seeded::new(0x0fed_cba9_8765_4321);
        let fixture = intro_fixture();
        let template = {
            let inner_len = 4096 - INTRO_OUTER_FIXED_BYTES - HEADER_BYTES - TAG_BYTES;
            let mut plain = vec![0u8; inner_len];
            plain[0] = KIND_OLM_PREKEY;
            plain[1..1 + card::CARD_BYTES].copy_from_slice(&fixture.card);
            let at = 1 + card::CARD_BYTES + 4 + sign::SIGNATURE_BYTES + SECRET_BYTES;
            plain[at..at + 4].copy_from_slice(&64u32.to_be_bytes());
            plain
        };
        for _ in 0..crate::property::inputs() {
            let bytes = if rng.below(4) == 0 {
                rng.random_input(INTRO_INNER_FIXED_BYTES + 32)
            } else {
                rng.mutate(&template)
            };
            match parse_intro_inner(&bytes) {
                Ok(plain) => {
                    assert!(plain.l1.len() + INTRO_INNER_FIXED_BYTES <= bytes.len());
                }
                Err(code) => assert_eq!(code, DmCode::NonCanonical),
            }
        }
    }

    #[test]
    fn a_bundle_round_trips_in_four_kilobytes() {
        let key = card_key(0x51);
        let plain = vec![0x5au8; 1393];
        let blob = seal_bundle_with(&key, &NAMESPACE, &plain, &[3u8; SALT_BYTES]).expect("seal");
        assert_eq!(blob.len(), 4096);
        assert_eq!(
            open_bundle(&key, &NAMESPACE, &blob, 1393).expect("open"),
            plain
        );
        assert_eq!(
            open_bundle(&key, &NAMESPACE, &blob[..2048], 1393).err(),
            Some(DmCode::NotOpen)
        );
    }

    /// [`open_intro_checked`] on a **real** first flight: the PreKey header it checks binding v3
    /// against is read from the message inside the envelope, not from an argument, so §6.5 step
    /// 4's three equalities hold by construction. A caller that supplies the header can get them
    /// wrong; this entry point cannot.
    ///
    /// It is the shape §2.6 function 12 uses, and it decapsulates **once**: the transcript covers
    /// the ciphertext and both recipient identities, so reading the header first would mean either
    /// a second decapsulation or shuttling opaque parts through Kotlin.
    #[test]
    fn open_intro_checked_reads_its_prekey_header_from_the_envelope() {
        use crate::derive::{self, MessagingBranch, OlmSecret};
        use crate::olm::message::L1Header;
        use crate::olm::session;

        let sender_branch = MessagingBranch::from_bytes([0x81; 32]);
        let recipient_branch = MessagingBranch::from_bytes([0x82; 32]);
        let sender_identity = derive::derive_olm_identity(&sender_branch);
        let sender_signing = derive::derive_olm_account_signing(&sender_branch);
        let sender_oi = derive::olm_identity_public(&sender_identity);
        let recipient_oi =
            derive::olm_identity_public(&derive::derive_olm_identity(&recipient_branch));
        let fallback_secret = [0x83u8; 32];
        let fallback_public = derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret));

        let outbound = session::session_outbound(
            &sender_identity,
            &sender_signing,
            &recipient_oi,
            &fallback_public,
            700,
        )
        .expect("outbound");
        let first = session::encrypt(&outbound.state, b"first flight", 700).expect("encrypt");
        assert!(first.is_pre_key);

        let fixture = intro_fixture();
        let context = IntroContext {
            namespace: &NAMESPACE,
            bucket: BUCKETS[0],
            gen_id: 0xdead_beef,
            gen_public: &fixture.gen_public,
            recipient_oi: &recipient_oi,
            recipient_identity_pk: &[0x65; 32],
        };
        let L1Header::PreKey { base_key, .. } = session::header(&first.l1, true).expect("header")
        else {
            panic!("a first flight is a PreKey message");
        };
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &sender_oi,
            base_key: &base_key,
            binding_minute: 29_000_000,
            reply_seed: &fixture.reply_seed,
        };
        let blob = seal_intro(&fixture.outer_key, &context, &sender, &first.l1).expect("seal");
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        let (plain, header) =
            open_intro_checked(&fixture.gen_seed, &context, &outer, &fallback_public)
                .expect("checked open");
        assert_eq!(plain.l1, first.l1);
        assert_eq!(
            header.ratchet_key(),
            session::header(&first.l1, true).unwrap().ratchet_key()
        );
        assert!(header.is_pre_key());

        // The generation's fallback key is still checked, and the whole open fails without it.
        assert_eq!(
            open_intro_checked(&fixture.gen_seed, &context, &outer, &[0u8; 32]).err(),
            Some(DmCode::NonCanonical)
        );
    }

    /// An intro envelope whose inner layer carries a **normal** Olm message is refused: §6.4 says
    /// the inner kind byte is `0x02` (PreKey) and the message under it is a first flight, so a
    /// normal message there is `drop(non_canonical)` — never a header read as if it were one.
    #[test]
    fn open_intro_checked_refuses_a_normal_message_inside_an_intro_envelope() {
        use crate::derive::{self, MessagingBranch, OlmSecret};
        use crate::olm::session;

        let branch = MessagingBranch::from_bytes([0x91; 32]);
        let peer = MessagingBranch::from_bytes([0x92; 32]);
        let identity = derive::derive_olm_identity(&branch);
        let signing = derive::derive_olm_account_signing(&branch);
        let peer_identity = derive::derive_olm_identity(&peer);
        let peer_signing = derive::derive_olm_account_signing(&peer);
        let fallback_secret = [0x93u8; 32];
        let fallback_public = derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret));
        let outbound = session::session_outbound(
            &identity,
            &signing,
            &derive::olm_identity_public(&peer_identity),
            &fallback_public,
            700,
        )
        .expect("outbound");
        let first = session::encrypt(&outbound.state, b"hello", 700).expect("encrypt");
        let inbound = session::session_inbound(
            &peer_identity,
            &peer_signing,
            fallback_secret,
            &derive::olm_identity_public(&identity),
            &first.l1,
            700,
        )
        .expect("inbound");
        // The reply is a **normal** message.
        let reply = session::encrypt(&inbound.state, b"hi", 700).expect("reply");
        assert!(!reply.is_pre_key);

        let fixture = intro_fixture();
        let context = intro_context(&fixture, BUCKETS[0]);
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &fixture.card,
            oi: &OI_SENDER,
            base_key: &[0x71; 32],
            binding_minute: 29_000_000,
            reply_seed: &fixture.reply_seed,
        };
        let blob = seal_intro(&fixture.outer_key, &context, &sender, &reply.l1).expect("seal");
        let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
        assert_eq!(
            open_intro_checked(&fixture.gen_seed, &context, &outer, &[0x72; 32]).err(),
            Some(DmCode::NonCanonical)
        );
    }
}
