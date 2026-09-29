//! The outer seal (design §5.6), the size classes and buckets (§5.7) and the TTL table (§5.8).
//!
//! ```text
//! blob(B) = salt(16) || hint(16) || ChaCha20-Poly1305(k, nonce = 0^12, AD, P)       |P| = B − 48,  B ∈ {4096, 16384, 65536}
//! hint    = HMAC-SHA256(R, "ghost/v1/ch-hint" || mode(1) || salt)[0..16]
//! k       = HKDF-SHA256(ikm = K, salt = salt, info = "ghost/v1/ch-seal" || ns(32), L = 32)
//! AD      = "ghost/v1/ch-seal" || 0x01 || ns(32) || u32_be(B) || mode(1)                 (not transmitted)
//! P       = mode(1) || body_len(u24_be) || order(16) || body || zeros                    capacity C(B) = B − 68
//! order   = epoch(u64_be) || sender_leaf(u32_be) || seq(u32_be)                          (mode 0x11; zeros otherwise)
//! ```
//!
//! CS-S1 … CS-S7: one size per bucket, canonical padding and lengths, the namespace and bucket
//! bound by `k` and `AD`, a fresh key per salt (the zero nonce never repeats under one key), one
//! attempt per hint, and `order` checked against the MLS header and the author's `ChannelOrder`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn};
use sha2::Sha256;

use crate::derive::{
    derive_epoch_recognition, derive_epoch_seal_key, derive_join_recognition, derive_join_seal_key,
    EpochExport, JoinKey, RecognitionKey, SealKey, LABEL_SEAL,
};
use crate::ext::ChannelOrder;
use crate::result::{Code, MlsError, MlsResult};

/// The three blob sizes (§5.6).
pub const BUCKETS: [usize; 3] = [4096, 16_384, 65_536];
/// `salt(16) ‖ hint(16) ‖ tag(16)` outside P, `mode(1) ‖ body_len(3) ‖ order(16)` inside.
pub const OVERHEAD: usize = 68;
pub const HINT_LABEL: &[u8] = b"ghost/v1/ch-hint";

pub const MODE_EPOCH: u8 = 0x11;
pub const MODE_JOIN: u8 = 0x12;
pub const MODE_WELCOME: u8 = 0x13;

/// `C(B) = B − 68`.
pub const fn capacity(bucket: usize) -> usize {
    bucket - OVERHEAD
}

/// The class floor (§5.3, §5.7): 4 KiB small (≤ 32 members), 16 KiB large (≤ 100).
pub fn floor(size_class: u8) -> Option<usize> {
    match size_class {
        0 => Some(4096),
        1 => Some(16_384),
        _ => None,
    }
}

/// `bucket(len) = min{ B : B ≥ floor(class) ∧ C(B) ≥ len }`, or `NO_FIT` above `C(65536)`.
pub fn bucket(len: usize, size_class: u8) -> MlsResult<usize> {
    let f = floor(size_class).ok_or(MlsError::new(Code::InvalidPolicy))?;
    BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= f && capacity(b) >= len)
        .ok_or(MlsError::new(Code::NoFit))
}

/// The seal's `order` (§5.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Order {
    pub epoch: u64,
    pub sender_leaf: u32,
    pub seq: u32,
}

impl Order {
    pub fn encode(&self) -> [u8; 16] {
        let mut o = [0u8; 16];
        o[..8].copy_from_slice(&self.epoch.to_be_bytes());
        o[8..12].copy_from_slice(&self.sender_leaf.to_be_bytes());
        o[12..].copy_from_slice(&self.seq.to_be_bytes());
        o
    }

    pub fn decode(b: &[u8; 16]) -> Self {
        let mut e = [0u8; 8];
        e.copy_from_slice(&b[..8]);
        let mut l = [0u8; 4];
        l.copy_from_slice(&b[8..12]);
        let mut s = [0u8; 4];
        s.copy_from_slice(&b[12..]);
        Self {
            epoch: u64::from_be_bytes(e),
            sender_leaf: u32::from_be_bytes(l),
            seq: u32::from_be_bytes(s),
        }
    }
}

/// The key a blob is sealed under: `K_ep(e)` for mode 0x11, `JK_g` for modes 0x12 and 0x13.
pub enum SealKeyInput<'a> {
    Epoch(&'a EpochExport),
    Join(&'a JoinKey),
}

impl SealKeyInput<'_> {
    fn recognition(&self) -> RecognitionKey {
        match self {
            SealKeyInput::Epoch(k) => derive_epoch_recognition(k),
            SealKeyInput::Join(k) => derive_join_recognition(k),
        }
    }

    fn key(&self, salt: &[u8; 16], ns: &[u8; 32]) -> SealKey {
        match self {
            SealKeyInput::Epoch(k) => derive_epoch_seal_key(k, salt, ns),
            SealKeyInput::Join(k) => derive_join_seal_key(k, salt, ns),
        }
    }

    fn allows(&self, mode: u8) -> bool {
        matches!(
            (self, mode),
            (SealKeyInput::Epoch(_), MODE_EPOCH)
                | (SealKeyInput::Join(_), MODE_JOIN)
                | (SealKeyInput::Join(_), MODE_WELCOME)
        )
    }
}

/// `hint = HMAC-SHA256(R, "ghost/v1/ch-hint" ‖ mode ‖ salt)[0..16]` (what Kotlin also computes
/// with the recognition keys it holds, CS-S5, CS-S6).
pub fn hint(r: &RecognitionKey, mode: u8, salt: &[u8; 16]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(r.as_bytes())
        .expect("HMAC takes any key length");
    mac.update(HINT_LABEL);
    mac.update(&[mode]);
    mac.update(salt);
    let full = mac.finalize().into_bytes();
    let mut h = [0u8; 16];
    h.copy_from_slice(&full[..16]);
    h
}

fn ad(ns: &[u8; 32], bucket: usize, mode: u8) -> Vec<u8> {
    let mut a = Vec::with_capacity(LABEL_SEAL.len() + 38);
    a.extend_from_slice(LABEL_SEAL);
    a.push(0x01);
    a.extend_from_slice(ns);
    a.extend_from_slice(&(bucket as u32).to_be_bytes());
    a.push(mode);
    a
}

/// `seal` (§10.2 fn 11). `salt` comes from the provider's CSPRNG (the seeded stream in host
/// builds). `NO_FIT` when the body exceeds `C(bucket)`; `INVALID_POLICY` for a bucket that is not
/// one of the three, a mode the key class does not seal, or a non-zero order outside mode 0x11.
pub fn seal(
    key: &SealKeyInput<'_>,
    ns: &[u8; 32],
    bucket: usize,
    mode: u8,
    order: &Order,
    body: &[u8],
    salt: [u8; 16],
) -> MlsResult<Vec<u8>> {
    if !BUCKETS.contains(&bucket) || !key.allows(mode) {
        return Err(MlsError::new(Code::InvalidPolicy));
    }
    if mode != MODE_EPOCH && *order != Order::default() {
        return Err(MlsError::new(Code::InvalidPolicy));
    }
    if body.len() > capacity(bucket) {
        return Err(MlsError::new(Code::NoFit));
    }
    let mut p = Vec::with_capacity(bucket - 48);
    p.push(mode);
    p.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    p.extend_from_slice(&order.encode());
    p.extend_from_slice(body);
    p.resize(bucket - 48, 0);
    let k = key.key(&salt, ns);
    let ct = ChaCha20Poly1305::new(k.as_bytes().into())
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &p,
                aad: &ad(ns, bucket, mode),
            },
        )
        .map_err(|_| MlsError::new(Code::Internal))?;
    let mut blob = Vec::with_capacity(bucket);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&hint(&key.recognition(), mode, &salt));
    blob.extend_from_slice(&ct);
    debug_assert_eq!(blob.len(), bucket);
    Ok(blob)
}

/// What `open` returns (§10.2 fn 12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub order: Order,
    pub body: Vec<u8>,
    /// Mode 0x11: the PrivateMessage header's epoch and content type, and for an application
    /// message the author's `ChannelOrder` from its MLS AAD (checked against `order`, CS-S7).
    pub header: Option<EpochHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochContent {
    Application,
    Commit,
    Proposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochHeader {
    pub epoch: u64,
    pub content: EpochContent,
    pub channel_order: Option<ChannelOrder>,
}

/// `open` (§10.2 fn 12): `NOT_OPEN` when the hint does not match or the AEAD refuses (a match whose
/// AEAD fails is a forgery, CS-S5); `NON_CANONICAL` for a wrong mode byte, a length outside P,
/// non-zero padding, or an `order` that differs from the MLS header's epoch or from the author's
/// `ChannelOrder` (CS-S7; a commit's `sender_leaf` and `seq` are zero).
pub fn open(key: &SealKeyInput<'_>, ns: &[u8; 32], mode: u8, blob: &[u8]) -> MlsResult<Opened> {
    let bucket = blob.len();
    if !BUCKETS.contains(&bucket) || !key.allows(mode) {
        return Err(MlsError::new(Code::NotOpen));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blob[..16]);
    let want = hint(&key.recognition(), mode, &salt);
    // A constant-time comparison is not needed for a public hint, but costs nothing.
    if want
        .iter()
        .zip(&blob[16..32])
        .fold(0u8, |a, (x, y)| a | (x ^ y))
        != 0
    {
        return Err(MlsError::new(Code::NotOpen));
    }
    let k = key.key(&salt, ns);
    let p = ChaCha20Poly1305::new(k.as_bytes().into())
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &blob[32..],
                aad: &ad(ns, bucket, mode),
            },
        )
        .map_err(|_| MlsError::new(Code::NotOpen))?;
    open_plain(bucket, mode, &p)
}

/// The layout checks of `open` on the decrypted P (split out so the property tests reach them
/// without an AEAD in front, design §12.2). `p` is `B − 48` bytes after the AEAD; any other
/// length is `NON_CANONICAL`.
pub(crate) fn open_plain(bucket: usize, mode: u8, p: &[u8]) -> MlsResult<Opened> {
    let nc = MlsError::new(Code::NonCanonical);
    if !BUCKETS.contains(&bucket) || p.len() + 48 != bucket || p[0] != mode {
        return Err(nc);
    }
    let len = u32::from_be_bytes([0, p[1], p[2], p[3]]) as usize;
    if len > capacity(bucket) {
        return Err(nc);
    }
    let mut ob = [0u8; 16];
    ob.copy_from_slice(&p[4..20]);
    let order = Order::decode(&ob);
    let body = p[20..20 + len].to_vec();
    if p[20 + len..].iter().any(|&b| b != 0) {
        return Err(nc);
    }
    let header = if mode == MODE_EPOCH {
        Some(check_epoch_body(&order, &body)?)
    } else {
        if order != Order::default() {
            return Err(nc);
        }
        None
    };
    Ok(Opened {
        order,
        body,
        header,
    })
}

/// CS-S7 for mode 0x11: the body is an `MlsMessage` carrying a PrivateMessage whose header epoch
/// equals `order.epoch`; an application message's MLS AAD is a `ChannelOrder` equal to
/// `(order.sender_leaf, order.seq)`; a commit or proposal has `sender_leaf = seq = 0`.
pub fn check_epoch_body(order: &Order, body: &[u8]) -> MlsResult<EpochHeader> {
    let nc = MlsError::new(Code::NonCanonical);
    let m = MlsMessageIn::tls_deserialize_exact(body).map_err(|_| nc)?;
    let pm = match m.extract() {
        MlsMessageBodyIn::PrivateMessage(pm) => pm,
        _ => return Err(nc),
    };
    let epoch = pm.epoch().as_u64();
    if epoch != order.epoch {
        return Err(nc);
    }
    let (content, channel_order) = match pm.content_type() {
        ContentType::Application => {
            let co = ChannelOrder::decode(pm.aad()).ok_or(nc)?;
            if co.sender_leaf != order.sender_leaf || co.seq != order.seq {
                return Err(nc);
            }
            (EpochContent::Application, Some(co))
        }
        ContentType::Commit => {
            if order.sender_leaf != 0 || order.seq != 0 {
                return Err(nc);
            }
            (EpochContent::Commit, None)
        }
        ContentType::Proposal => {
            if order.sender_leaf != 0 || order.seq != 0 {
                return Err(nc);
            }
            (EpochContent::Proposal, None)
        }
    };
    Ok(EpochHeader {
        epoch,
        content,
        channel_order,
    })
}

/// §5.8: the TTL of a post (mode 0x11 application message) under a channel timer code, in seconds.
pub fn post_ttl(timer_code: u8) -> Option<u32> {
    Some(match timer_code {
        0 => 2_592_000,
        1 | 2 => 3_600,
        3 => 86_400,
        4 => 604_800,
        5 => 2_592_000,
        _ => return None,
    })
}

/// §5.8: the TTL of a handshake blob (commits, JOIN, WELCOME, `INVITE_ISSUED`, `LEAVE`; X-7).
pub fn handshake_ttl(timer_code: u8) -> Option<u32> {
    Some(match timer_code {
        0 | 5 => 2_592_000,
        1..=4 => 604_800,
        _ => return None,
    })
}

/// §5.8: an op's deadline after its author minute, in seconds (`author + min(bucket, 7 d)`, ADR-32
/// point 3); a handshake op's deadline is always 7 days.
pub fn op_deadline(timer_code: u8, handshake: bool) -> Option<u32> {
    if timer_code > 5 {
        return None;
    }
    if handshake {
        return Some(604_800);
    }
    Some(match timer_code {
        1 | 2 => 3_600,
        3 => 86_400,
        _ => 604_800,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_and_classes() {
        assert_eq!(capacity(4096), 4028);
        assert_eq!(capacity(16_384), 16_316);
        assert_eq!(capacity(65_536), 65_468);
        assert_eq!(bucket(0, 0), Ok(4096));
        assert_eq!(bucket(4028, 0), Ok(4096));
        assert_eq!(bucket(4029, 0), Ok(16_384));
        assert_eq!(bucket(10, 1), Ok(16_384));
        assert_eq!(bucket(65_468, 1), Ok(65_536));
        assert_eq!(bucket(65_469, 0), Err(MlsError::new(Code::NoFit)));
        assert_eq!(bucket(1, 2), Err(MlsError::new(Code::InvalidPolicy)));
    }

    #[test]
    fn seal_open_join_modes() {
        let jk = JoinKey::from_bytes([4; 32]);
        let ns = [5u8; 32];
        let key = SealKeyInput::Join(&jk);
        for bucket_size in BUCKETS {
            for mode in [MODE_JOIN, MODE_WELCOME] {
                let blob = seal(
                    &key,
                    &ns,
                    bucket_size,
                    mode,
                    &Order::default(),
                    b"body",
                    [6; 16],
                )
                .unwrap();
                assert_eq!(blob.len(), bucket_size);
                let o = open(&key, &ns, mode, &blob).unwrap();
                assert_eq!(o.body, b"body");
                assert_eq!(o.header, None);
                // Another namespace, another mode, a truncation, a flipped bit: refused (CS-S3).
                assert_eq!(
                    open(&key, &[6; 32], mode, &blob),
                    Err(MlsError::new(Code::NotOpen))
                );
                let other = if mode == MODE_JOIN {
                    MODE_WELCOME
                } else {
                    MODE_JOIN
                };
                assert_eq!(
                    open(&key, &ns, other, &blob),
                    Err(MlsError::new(Code::NotOpen))
                );
                assert!(open(&key, &ns, mode, &blob[..bucket_size - 1]).is_err());
                let mut flip = blob.clone();
                flip[100] ^= 1;
                assert_eq!(
                    open(&key, &ns, mode, &flip),
                    Err(MlsError::new(Code::NotOpen))
                );
            }
        }
        // The key classes seal only their modes; a join blob cannot carry an order.
        assert!(seal(&key, &ns, 4096, MODE_EPOCH, &Order::default(), b"", [0; 16]).is_err());
        let o = Order {
            epoch: 1,
            ..Order::default()
        };
        assert!(seal(&key, &ns, 4096, MODE_JOIN, &o, b"", [0; 16]).is_err());
        assert_eq!(
            seal(
                &key,
                &ns,
                4096,
                MODE_JOIN,
                &Order::default(),
                &[0; 4029],
                [0; 16]
            ),
            Err(MlsError::new(Code::NoFit))
        );
    }

    #[test]
    fn ttl_table() {
        let posts: Vec<u32> = (0..=5).map(|c| post_ttl(c).unwrap()).collect();
        assert_eq!(posts, [2_592_000, 3_600, 3_600, 86_400, 604_800, 2_592_000]);
        let hs: Vec<u32> = (0..=5).map(|c| handshake_ttl(c).unwrap()).collect();
        assert_eq!(
            hs,
            [2_592_000, 604_800, 604_800, 604_800, 604_800, 2_592_000]
        );
        let dl: Vec<u32> = (0..=5).map(|c| op_deadline(c, false).unwrap()).collect();
        assert_eq!(dl, [604_800, 3_600, 3_600, 86_400, 604_800, 604_800]);
        assert_eq!(op_deadline(1, true), Some(604_800));
        assert_eq!(post_ttl(6), None);
    }
}
