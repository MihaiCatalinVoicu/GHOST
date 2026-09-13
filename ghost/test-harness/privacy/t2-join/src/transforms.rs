//! J3 (Phase 8 design §13.4): transforms of the values of one side searched in the other side.
//!
//! The transform set F applied to a source value v (every field of 8–64 bytes, and SHA-256 of every
//! 256-byte value):
//! - identity; SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b-256;
//! - for every label L (every GHOST derivation label and the Phase 8 labels): HMAC-SHA256(L, v),
//!   HMAC-SHA256(v, L), HKDF-SHA256(ikm = v, salt = L), HKDF-SHA256(ikm = v, info = L),
//!   SHA-256(L ‖ v), SHA-256(v ‖ L);
//! - counters (issuer → relay direction, on the issuer fields of 8–64 bytes): SHA-256(v ‖ c) and
//!   SHA-256(c ‖ v) for c in 0..=255 as u8, u32 BE, u32 LE and u64 BE; the counter suffixes of
//!   labels, HKDF-SHA256(ikm = v, info = L ‖ u8(c)) for every label L and every position c of a pack
//!   or trial layout (0..64); and, beyond the design's family (a heuristic extension, §19.24 point
//!   3), HKDF-SHA256(ikm = v, info = w ‖ u8(c)) for a few generic info words w;
//! - byte reversal; hex, base32, z-base-32 and base64 text.
//!
//! Every image is probed with its first and last 8 bytes against a Bloom filter of every 8-byte
//! window of every value of the target side, whatever its length (blob data, addresses, database
//! rows and journal segments included), so an image found whole, or truncated to 8 or 16 bytes (a
//! prefix or a suffix), or embedded in a larger target value, is a candidate; candidates are
//! verified exactly. HKDF outputs are 32 bytes: the 16-byte output of the same HKDF is their prefix.

use std::collections::{HashMap, HashSet};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::numbers::{structural_window, window, Bloom};
use crate::values::{Hit, Public, Values, ISSUER};

type HmacSha256 = Hmac<Sha256>;

/// Every GHOST derivation label (`DerivationLabels.ALL` of `:identity`) and every Phase 8 label.
pub const LABELS: &[&str] = &[
    "ghost/v1/identity",
    "ghost/v1/messaging",
    "ghost/v1/wallet",
    "ghost/v1/backup-wrap",
    "ghost/v1/channel-pseudonym",
    "ghost/v1/invite-signing",
    "ghost/v1/referral-secret",
    "ghost/v1/invite-drop-namespace",
    "ghost/v1/invite-drop-key",
    "ghost/v1/attempt",
    "ghost/v1/blind-batch",
    "ghost/v1/blindsign",
    "ghost/v1/cap-serial",
    "ghost/v1/claim-payout",
    "ghost/v1/drop-seal",
    "ghost/v1/entitlement-schedule",
    "ghost/v1/issuer-claim",
    "ghost/v1/key-seal",
    "ghost/v1/layout",
    "ghost/v1/ledger-address",
    "ghost/v1/ledger-claim",
    "ghost/v1/nullifier",
    "ghost/v1/nullifier-store-key",
    "ghost/v1/payout-batch",
    "ghost/v1/payout-order",
    "ghost/v1/perm-proof",
    "ghost/v1/redeem-binding",
    "ghost/v1/redemption-context",
    "ghost/v1/referral-commitment",
    "ghost/v1/refresh-credit",
    "ghost/v1/request-invoice",
    "ghost/v1/trial",
    "",
];

/// The generic info words of the counter HKDF family (a heuristic extension of the design's J3
/// family, which names HKDF keyed or salted with the GHOST labels and counter suffixes of labels).
pub const INFO_WORDS: &[&str] = &["nonce", "salt", "seed", "key", "id", "r", "n", ""];

/// The label counters of `hkdf(info=label||u8)`: every position of a pack (N = 63) or a trial.
pub const LABEL_COUNTERS: u8 = 64;

// -------------------------------------------------------------------------------------------------
// BLAKE2b (RFC 7693), unkeyed.
// -------------------------------------------------------------------------------------------------

const B2_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const B2_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn b2_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().expect("8"));
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&B2_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    let g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    };
    for s in &B2_SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b with an `out_len`-byte digest (1..=64), no key.
pub fn blake2b(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = B2_IV;
    h[0] ^= 0x0101_0000 ^ out_len as u64;
    let mut t: u128 = 0;
    let mut chunks = data.chunks(128).peekable();
    if data.is_empty() {
        b2_compress(&mut h, &[0u8; 128], 0, true);
    }
    while let Some(c) = chunks.next() {
        let mut block = [0u8; 128];
        block[..c.len()].copy_from_slice(c);
        t += c.len() as u128;
        b2_compress(&mut h, &block, t, chunks.peek().is_none());
    }
    let mut out = Vec::with_capacity(64);
    for w in h {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.truncate(out_len);
    out
}

// -------------------------------------------------------------------------------------------------
// Text encodings.
// -------------------------------------------------------------------------------------------------

fn base32(v: &[u8], alphabet: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in v {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(alphabet[((acc >> (bits - 5)) & 31) as usize]);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(alphabet[((acc << (5 - bits)) & 31) as usize]);
    }
    out
}

fn base64(v: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4 / 3 + 4);
    for c in v.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize]);
            } else if pad {
                out.push(b'=');
            }
        }
    }
    out
}

const B32_UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The text encodings of `v` J3 searches (ASCII images).
pub fn encodings(v: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("hex", hex::encode(v).into_bytes()),
        ("HEX", hex::encode_upper(v).into_bytes()),
        ("base32", base32(v, B32_UPPER)),
        ("base32-lower", base32(v, B32_LOWER)),
        ("z-base-32", base32(v, ZBASE32)),
        ("base64", base64(v, B64_STD, true)),
        ("base64url", base64(v, B64_URL, false)),
    ]
}

// -------------------------------------------------------------------------------------------------
// The transform engine.
// -------------------------------------------------------------------------------------------------

/// Precomputed keyed HMAC states.
pub struct Keys {
    labels: Vec<(String, HmacSha256)>,
}

impl Keys {
    pub fn new() -> Self {
        Self {
            labels: LABELS
                .iter()
                .map(|l| {
                    (
                        l.to_string(),
                        <HmacSha256 as KeyInit>::new_from_slice(l.as_bytes()).expect("any key"),
                    )
                })
                .collect(),
        }
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

fn hmac(key: &HmacSha256, parts: &[&[u8]]) -> [u8; 32] {
    let mut m = key.clone();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Calls `probe(image, transform)` for every image of `v` under F (counters when `counters`).
pub fn images(v: &[u8], keys: &Keys, counters: bool, probe: &mut dyn FnMut(&[u8], &str)) {
    probe(v, "identity");
    probe(&sha256(&[v]), "sha256");
    probe(Sha384::digest(v).as_slice(), "sha384");
    probe(Sha512::digest(v).as_slice(), "sha512");
    probe(
        <sha3::Sha3_256 as sha3::Digest>::digest(v).as_slice(),
        "sha3-256",
    );
    probe(&blake2b(v, 32), "blake2b-256");
    let rev: Vec<u8> = v.iter().rev().copied().collect();
    probe(&rev, "reverse");
    for (name, e) in encodings(v) {
        probe(&e, name);
    }
    // HKDF-Extract with no salt (the zero key) and with v as the HMAC key.
    let zero = <HmacSha256 as KeyInit>::new_from_slice(&[]).expect("any key");
    let prk0 = hmac(&zero, &[v]);
    let prk0_key = <HmacSha256 as KeyInit>::new_from_slice(&prk0).expect("any key");
    let v_key = <HmacSha256 as KeyInit>::new_from_slice(v).expect("any key");
    for (label, lkey) in &keys.labels {
        let l = label.as_bytes();
        // HMAC(L, v); it is also HKDF-Extract(salt = L, ikm = v).
        let keyed = hmac(lkey, &[v]);
        probe(&keyed, "hmac(label, v)");
        let prk_l = <HmacSha256 as KeyInit>::new_from_slice(&keyed).expect("any key");
        probe(&hmac(&prk_l, &[&[1u8]]), "hkdf(salt=label)");
        probe(&hmac(&v_key, &[l]), "hmac(v, label)");
        probe(&hmac(&prk0_key, &[l, &[1u8]]), "hkdf(info=label)");
        probe(&sha256(&[l, v]), "sha256(label||v)");
        probe(&sha256(&[v, l]), "sha256(v||label)");
    }
    if counters {
        for c in 0u32..=255 {
            let encs: [&[u8]; 4] = [
                &[c as u8],
                &c.to_be_bytes(),
                &c.to_le_bytes(),
                &u64::from(c).to_be_bytes(),
            ];
            for e in encs {
                probe(&sha256(&[v, e]), "sha256(v||ctr)");
                probe(&sha256(&[e, v]), "sha256(ctr||v)");
            }
            for w in INFO_WORDS {
                probe(
                    &hmac(&prk0_key, &[w.as_bytes(), &[c as u8], &[1u8]]),
                    "hkdf(info=word||u8)",
                );
            }
        }
        for (label, _) in &keys.labels {
            for c in 0..LABEL_COUNTERS {
                probe(
                    &hmac(&prk0_key, &[label.as_bytes(), &[c], &[1u8]]),
                    "hkdf(info=label||u8)",
                );
            }
        }
    }
}

/// One direction of J3: the sources' images probed against every 8-byte window of the targets.
fn direction(
    values: &Values,
    public: &Public,
    from_issuer: bool,
    counters_on_small: bool,
) -> Vec<Hit> {
    let on_source = |sides: u8| {
        if from_issuer {
            sides & ISSUER != 0
        } else {
            sides & !ISSUER != 0
        }
    };
    // Targets: every value of the other side of at least 8 bytes, whatever its length (a derivation
    // placed in a blob header, a ciphertext prefix, an address or a database row is found too), and
    // every one of their windows.
    let targets: Vec<&[u8]> = values
        .map
        .iter()
        .filter(|(v, p)| !on_source(p.sides) && p.sides != 0 && v.len() >= 8)
        .map(|(v, _)| &v[..])
        .collect();
    let count: usize = targets.iter().map(|v| v.len() - 7).sum();
    // 16 bits per window (7 probes: about 7·10⁻⁴ false positives per probe); a very large target
    // side gets 12, which keeps the filter under 1 GiB and the candidates few.
    let bits = if count > 150_000_000 { 12 } else { 16 };
    let mut bloom = Bloom::with_capacity(count, bits);
    for v in &targets {
        for i in 0..v.len() - 7 {
            bloom.insert(window(v, i));
        }
    }
    // Sources: fields of 8–64 bytes (counters on the issuer side) and SHA-256 of 256-byte values.
    let sources: Vec<(Vec<u8>, bool, u16)> = values
        .map
        .iter()
        .filter(|(_, p)| on_source(p.sides))
        .filter_map(|(v, p)| {
            let field = if from_issuer {
                p.issuer_field
            } else {
                p.relay_field
            };
            if (8..=64).contains(&v.len()) {
                Some((v.to_vec(), counters_on_small, field))
            } else if v.len() == 256 {
                Some((sha256(&[v]).to_vec(), false, field))
            } else {
                None
            }
        })
        .collect();
    let keys = Keys::new();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    let chunk = sources.len().div_ceil(threads).max(1);
    let candidates: Vec<(u64, u16, &'static str)> = std::thread::scope(|s| {
        let handles: Vec<_> = sources
            .chunks(chunk)
            .map(|part| {
                let bloom = &bloom;
                let keys = &keys;
                s.spawn(move || {
                    let mut out = Vec::new();
                    for (v, counters, field) in part {
                        images(v, keys, *counters, &mut |img, t| {
                            if img.len() < 8 {
                                return;
                            }
                            for w in [window(img, 0), window(img, img.len() - 8)] {
                                if bloom.contains(w) && !structural_window(w) {
                                    out.push((w, *field, transform_name(t)));
                                }
                            }
                        });
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("J3 worker"))
            .collect()
    });
    // Exact verification against the target windows.
    let wanted: HashMap<u64, (u16, &'static str)> =
        candidates.iter().map(|&(w, f, t)| (w, (f, t))).collect();
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    for (v, p) in &values.map {
        if on_source(p.sides) || p.sides == 0 || v.len() < 8 {
            continue;
        }
        for i in 0..v.len() - 7 {
            let w = window(v, i);
            if let Some(&(f, t)) = wanted.get(&w) {
                if !public.window(w) && seen.insert(w) {
                    let target_field = if from_issuer {
                        p.relay_field
                    } else {
                        p.issuer_field
                    };
                    let (a, b) = if from_issuer {
                        (f, target_field)
                    } else {
                        (target_field, f)
                    };
                    hits.push(Hit {
                        check: "J3",
                        value: w.to_le_bytes().to_vec(),
                        a: format!("{} [{t}]", values.fields.name(a)),
                        b: values.fields.name(b).to_string(),
                    });
                }
            }
        }
    }
    hits
}

/// Transform names as static strings (the probe callback's names are already static).
fn transform_name(t: &str) -> &'static str {
    const NAMES: &[&str] = &[
        "identity",
        "sha256",
        "sha384",
        "sha512",
        "sha3-256",
        "blake2b-256",
        "reverse",
        "hex",
        "HEX",
        "base32",
        "base32-lower",
        "z-base-32",
        "base64",
        "base64url",
        "hmac(label, v)",
        "hkdf(salt=label)",
        "hmac(v, label)",
        "hkdf(info=label)",
        "sha256(label||v)",
        "sha256(v||label)",
        "sha256(v||ctr)",
        "sha256(ctr||v)",
        "hkdf(info=word||u8)",
        "hkdf(info=label||u8)",
    ];
    NAMES.iter().find(|n| **n == t).copied().unwrap_or("?")
}

/// J3 in both directions: issuer values transformed and searched in the relay views (with the
/// counter family on the issuer fields of 8–64 bytes), and relay values transformed and searched
/// in the issuer view.
pub fn j3(values: &Values, public: &Public) -> Vec<Hit> {
    let mut hits = direction(values, public, true, true);
    hits.extend(direction(values, public, false, false));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_matches_rfc_7693() {
        assert_eq!(
            hex::encode(blake2b(b"abc", 64)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex::encode(blake2b(b"", 32)),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        // Multi-block input: the last block flag is on the final block only.
        assert_ne!(blake2b(&[7u8; 128], 32), blake2b(&[7u8; 129], 32));
    }

    #[test]
    fn text_encodings_match_rfc_4648() {
        let e: HashMap<_, _> = encodings(b"foobar").into_iter().collect();
        assert_eq!(e["base32"], b"MZXW6YTBOI");
        assert_eq!(e["base64"], b"Zm9vYmFy");
        let e: HashMap<_, _> = encodings(b"fo").into_iter().collect();
        assert_eq!(e["base64"], b"Zm8=");
        assert_eq!(e["base64url"], b"Zm8");
        assert_eq!(e["hex"], b"666f");
    }

    #[test]
    fn hkdf_images_equal_the_rfc_5869_construction() {
        // HKDF-SHA256(ikm = v, info = L, 32) = HMAC(HMAC(0, v), L || 0x01).
        let v = [9u8; 16];
        let mut found = Vec::new();
        images(&v, &Keys::new(), false, &mut |img, t| {
            if t == "hkdf(info=label)" {
                found.push(img.to_vec());
            }
        });
        let zero = <HmacSha256 as KeyInit>::new_from_slice(&[]).unwrap();
        let prk = hmac(&zero, &[&v]);
        let k = <HmacSha256 as KeyInit>::new_from_slice(&prk).unwrap();
        let expected = hmac(&k, &[b"ghost/v1/nullifier", &[1]]);
        assert!(found.iter().any(|f| f[..] == expected[..]));
    }
}
