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
//! R-S4: `k` is fresh per salt, so nonce 0 never repeats under one key.
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

fn seal_key_of(seal_key: &SealKey, namespace: &[u8; 32], salt: &[u8; SALT_BYTES]) -> [u8; 32] {
    let mut info = Vec::with_capacity(SEAL_LABEL.len() + 32);
    info.extend_from_slice(SEAL_LABEL);
    info.extend_from_slice(namespace);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), seal_key.as_bytes())
        .expand(&info, &mut out)
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
    let mut plaintext = vec![0u8; plaintext_len];
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

/// Opens a blob in `mode` and returns `body || zeros` (P without its mode byte).
fn open_body(
    key: &SealKey,
    namespace: &[u8; 32],
    mode: SealMode,
    pair_ad: &[u8; 32],
    blob: &[u8],
) -> DmResult<Vec<u8>> {
    if !BUCKETS.contains(&blob.len()) {
        return Err(DmCode::NotOpen);
    }
    let bucket = blob.len();
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&blob[..SALT_BYTES]);
    let derived = seal_key_of(key, namespace, &salt);
    let ad = associated_data(namespace, bucket, mode, pair_ad);
    let plaintext = aead(&derived)?
        .decrypt(
            &zero_nonce(),
            Payload {
                msg: &blob[HEADER_BYTES..],
                aad: &ad,
            },
        )
        .map_err(|_| DmCode::NotOpen)?;
    // R-S2: the mode byte the key class expects, and nothing else.
    if plaintext.first() != Some(&mode.as_u8()) {
        return Err(DmCode::NonCanonical);
    }
    Ok(plaintext[1..].to_vec())
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

/// Pair mode (§6.3): an Olm normal message under the week key of `week(author_minute)`.
pub fn seal_pair(
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

/// Provisional mode (§6.7): an Olm normal message under `K_prov(dir)` before a pair root exists.
pub fn seal_provisional(
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

/// Bundle mode (§5.3): the 1 393-byte bundle plaintext in one 4 KiB blob under `KB_i`.
pub fn seal_bundle(
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
    /// The sender's card v2, unparsed: Kotlin's R5 parses and checks it.
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

fn intro_inner_key(shared: &KemSecret, transcript: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(transcript), shared.as_bytes())
        .expand(INTRO_INNER_LABEL, &mut out)
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
    let signature = binding::sign(
        sender.identity_seed,
        &binding::BindingV3 {
            oi_a: sender.oi,
            card_index_a: sender_card.card_index,
            recipient_namespace: context.namespace,
            binding_minute: sender.binding_minute,
            gen_id_b: context.gen_id,
            xwing_ct: &ciphertext,
            base_key_a: sender.base_key,
            oi_b: context.recipient_oi,
        },
    );

    let inner_len = context.bucket - INTRO_OUTER_FIXED_BYTES - HEADER_BYTES - TAG_BYTES;
    if l1.len() + INTRO_INNER_FIXED_BYTES > inner_len {
        return Err(DmCode::NoFit);
    }
    let mut inner_plain = vec![0u8; inner_len];
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

    let inner_ad = intro_inner_ad(&transcript);
    let inner = aead(&intro_inner_key(&shared, &transcript))?
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
    body.extend_from_slice(&ciphertext);
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

/// Intro mode with CSPRNG encapsulation randomness.
pub fn seal_intro(
    outer_key: &SealKey,
    context: &IntroContext<'_>,
    sender: &IntroSender<'_>,
    l1: &[u8],
    salt: &[u8; SALT_BYTES],
) -> DmResult<Vec<u8>> {
    let mut randomness = [0u8; pq::ENCAPS_RANDOMNESS_BYTES];
    pq::fill_random(&mut randomness);
    seal_intro_with(outer_key, context, sender, l1, salt, &randomness)
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

/// Opens the X-Wing-keyed inner layer, verifies binding v3 and enforces the three equalities of
/// §6.5 step 4. Every decapsulation error is `NOT_OPEN`, never a crash (§22.8.2 rule 4).
pub fn open_intro_inner(
    gen_seed: &KemSecret,
    context: &IntroContext<'_>,
    outer: &IntroOuter,
    prekey: &PreKeyFields<'_>,
) -> DmResult<IntroPlain> {
    if context.gen_id != outer.gen_id || context.bucket != outer.bucket {
        return Err(DmCode::NotOpen);
    }
    let shared = pq::decapsulate(gen_seed, &outer.ciphertext)?;
    let transcript = intro_transcript(context, &outer.ciphertext);
    let inner_ad = intro_inner_ad(&transcript);
    let plain = aead(&intro_inner_key(&shared, &transcript))?
        .decrypt(
            &zero_nonce(),
            Payload {
                msg: &outer.inner,
                aad: &inner_ad,
            },
        )
        .map_err(|_| DmCode::NotOpen)?;
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
    let mut reply_seed = [0u8; SECRET_BYTES];
    reply_seed.copy_from_slice(&plain[at..at + SECRET_BYTES]);
    at += SECRET_BYTES;
    let l1_len =
        u32::from_be_bytes([plain[at], plain[at + 1], plain[at + 2], plain[at + 3]]) as usize;
    at += 4;
    let end = at.checked_add(l1_len).ok_or(DmCode::NonCanonical)?;
    if end > plain.len() || !all_zero(&plain[end..]) {
        return Err(DmCode::NonCanonical);
    }
    let l1 = plain[at..end].to_vec();

    let sender = card::parse(&sender_card)?;
    // The binding names the sender's Olm identity and base key; §6.5 step 4 requires the PreKey
    // header to carry the same, and the one-time key to be this generation's fallback key.
    binding::verify(
        &sender.identity_pk,
        &binding::BindingV3 {
            oi_a: prekey.identity_key,
            card_index_a: sender.card_index,
            recipient_namespace: context.namespace,
            binding_minute,
            gen_id_b: context.gen_id,
            xwing_ct: &outer.ciphertext,
            base_key_a: prekey.base_key,
            oi_b: context.recipient_oi,
        },
        &binding_sig,
    )?;

    Ok(IntroPlain {
        sender_card,
        binding_minute,
        binding_sig,
        reply_seed: ReplySeed::from_bytes(reply_seed),
        l1,
    })
}

/// The generation's fallback key check of §6.5 step 4, kept next to the opener so the S4b facade
/// cannot forget it: `PreKey.one_time_key = F_{gen_id}`.
pub fn check_generation_fallback_key(
    prekey: &PreKeyFields<'_>,
    generation_fallback_key: &[u8; 32],
) -> DmResult<()> {
    if prekey.fallback_key != generation_fallback_key {
        return Err(DmCode::NonCanonical);
    }
    Ok(())
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
            let blob = seal_pair(
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
            let provisional = seal_provisional(
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
        let blob = seal_pair(
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
        let blob = seal_pair(
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
        let first = seal_pair(
            &key,
            &NAMESPACE,
            4096,
            &OI_SENDER,
            &OI_RECIPIENT,
            b"l1",
            &[1u8; SALT_BYTES],
        )
        .expect("seal");
        let second = seal_pair(
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
            let blob = seal_intro(
                &fixture.outer_key,
                &context,
                &sender,
                &l1,
                &[0x55; SALT_BYTES],
            )
            .expect("seal");
            assert_eq!(blob.len(), bucket);
            let outer = open_intro_outer(&fixture.outer_key, &NAMESPACE, &blob).expect("outer");
            assert_eq!(outer.gen_id, 0xdead_beef);
            assert_eq!(outer.ciphertext.len(), pq::CIPHERTEXT_BYTES);
            let prekey = PreKeyFields {
                identity_key: &OI_SENDER,
                base_key: &base_key,
                fallback_key: &fallback,
            };
            let plain =
                open_intro_inner(&fixture.gen_seed, &context, &outer, &prekey).expect("inner");
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
        let blob = seal_intro(
            &fixture.outer_key,
            &context,
            &sender,
            b"l1",
            &[0x55; SALT_BYTES],
        )
        .expect("seal");
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
                open_intro_inner(&fixture.gen_seed, &context, &outer, &prekey).err(),
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
                }
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
        let blob = seal_intro(
            &fixture.outer_key,
            &context,
            &sender,
            b"secret l1",
            &[0x55; SALT_BYTES],
        )
        .expect("seal");
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
                }
            )
            .err(),
            Some(DmCode::NotOpen)
        );
        assert!(!outer.inner.windows(9).any(|w| w == b"secret l1"));
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
        let first = seal_intro(
            &fixture.outer_key,
            &context,
            &sender,
            b"l1",
            &[1; SALT_BYTES],
        )
        .expect("a");
        let second = seal_intro(
            &fixture.outer_key,
            &context,
            &sender,
            b"l1",
            &[1; SALT_BYTES],
        )
        .expect("b");
        assert_ne!(first, second);
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
        let _ = seal_pair(
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
        let _ = seal_bundle(&pq_key(1), &NAMESPACE, &[0u8; 1393], &[0u8; SALT_BYTES]);
    }

    #[test]
    fn a_bundle_round_trips_in_four_kilobytes() {
        let key = card_key(0x51);
        let plain = vec![0x5au8; 1393];
        let blob = seal_bundle(&key, &NAMESPACE, &plain, &[3u8; SALT_BYTES]).expect("seal");
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
}
