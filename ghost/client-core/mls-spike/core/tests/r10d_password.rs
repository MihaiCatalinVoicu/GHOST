//! Round 10d, the channel password (design §19.28): Argon2id (RFC 9106) through RustCrypto's
//! `argon2` 0.6.0 — the RFC's own Argon2id test vector, the cost of candidate parameter profiles on
//! this host — and the password-sealed invite `ChannelInviteV2`: one size for open and password
//! invites, a wrong password refused by the AEAD, nothing readable from a link without the
//! password.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test r10d_password -- --nocapture --test-threads=1`

use std::time::Instant;

use argon2::{Algorithm, Argon2, AssociatedData, Params, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 9106 §5.3 (Argon2id test vector): P = 32 × 0x01, S = 16 × 0x02, K = 8 × 0x03,
/// X = 12 × 0x04, m = 32 KiB, t = 3, p = 4, T = 32.
#[test]
fn r10d_rfc9106_argon2id_vector() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[4u8; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let secret = [3u8; 8];
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
        .unwrap();
    let expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
    println!("R10d PW RFC 9106 §5.3 Argon2id tag {}", hex::encode(out));
    assert_eq!(hex::encode(out), expected);
}

fn argon2id(m_kib: u32, t: u32, p: u32, pw: &[u8], salt: &[u8]) -> [u8; 32] {
    let a = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m_kib, t, p, Some(32)).unwrap(),
    );
    let mut out = [0u8; 32];
    a.hash_password_into(pw, salt, &mut out).unwrap();
    out
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// The candidate profiles, timed on this host (medians of 7; single-threaded: `argon2` without its
/// `parallel` feature computes the p lanes one after the other).
#[test]
fn r10d_argon2id_profiles_on_this_host() {
    let profiles: [(&str, u32, u32, u32); 6] = [
        (
            "RFC 9106 second recommended: m=64 MiB t=3 p=4",
            65_536,
            3,
            4,
        ),
        ("m=64 MiB t=3 p=1", 65_536, 3, 1),
        ("m=64 MiB t=1 p=4", 65_536, 1, 4),
        ("m=32 MiB t=3 p=4", 32_768, 3, 4),
        ("m=19 MiB t=2 p=1 (argon2 crate default)", 19_456, 2, 1),
        ("m=256 MiB t=1 p=4", 262_144, 1, 4),
    ];
    let pw = "abandon ability able about above absent".as_bytes();
    let salt = [9u8; 16];
    for (name, m, t, p) in profiles {
        let _ = argon2id(m, t, p, pw, &salt); // warm-up (page faults of the first allocation)
        let mut v = Vec::new();
        for _ in 0..7 {
            let s = Instant::now();
            let k = argon2id(m, t, p, pw, &salt);
            v.push(s.elapsed().as_secs_f64() * 1e3);
            assert_ne!(k, [0u8; 32]);
        }
        println!(
            "R10d PW Argon2id {name}: median {:.1} ms (min {:.1}, max {:.1}); memory {} MiB",
            median(v.clone()),
            v.iter().cloned().fold(f64::INFINITY, f64::min),
            v.iter().cloned().fold(0.0, f64::max),
            m / 1024
        );
    }
}

// ---- ChannelInviteV2 (design §19.28 R-PW formats) ------------------------------------------------

const INNER_LEN: usize = 303;
const LINK_LEN: usize = 1 + 16 + INNER_LEN + 16;

/// The password key: Argon2id with the profile the design fixes for invite version 2
/// (m = 64 MiB, t = 3, p = 4, T = 32), then HKDF to the link key.
fn link_key_password(password_nfkd: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let ikm = argon2id(65_536, 3, 4, password_nfkd, salt);
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(b"ghost/v1/ch/invite-pw", &mut k)
        .unwrap();
    k
}

fn link_key_open(salt: &[u8; 16]) -> [u8; 32] {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, salt)
        .expand(b"ghost/v1/ch/invite-open", &mut k)
        .unwrap();
    k
}

fn aad(salt: &[u8; 16]) -> Vec<u8> {
    let mut a = b"ghost/v1/ch/invite".to_vec();
    a.push(2);
    a.extend_from_slice(salt);
    a
}

fn seal(inner: &[u8; INNER_LEN], salt: [u8; 16], key: [u8; 32]) -> Vec<u8> {
    let ct = ChaCha20Poly1305::new(&key.into())
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: inner,
                aad: &aad(&salt),
            },
        )
        .unwrap();
    let mut link = vec![2u8];
    link.extend_from_slice(&salt);
    link.extend_from_slice(&ct);
    link
}

fn open(link: &[u8], key: [u8; 32]) -> Option<Vec<u8>> {
    if link.len() != LINK_LEN || link[0] != 2 {
        return None;
    }
    let salt: [u8; 16] = link[1..17].try_into().unwrap();
    ChaCha20Poly1305::new(&key.into())
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &link[17..],
                aad: &aad(&salt),
            },
        )
        .ok()
}

fn salt_of(link: &[u8]) -> [u8; 16] {
    link[1..17].try_into().unwrap()
}

/// RFC 4648 base32, lowercase, unpadded (the `ghost://` link alphabet of ADR-05).
fn base32_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

#[test]
fn r10d_password_sealed_invite() {
    // A stand-in inner invite: every field of §5.9's body, fixed-size, name padded to 48 bytes.
    let mut inner = [0u8; INNER_LEN];
    for (i, b) in inner.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let pw = "cabin frost ladder margin orbit velvet".as_bytes(); // six BIP-39 words, NFKD = itself
    let salt_p = [0x11u8; 16];
    let salt_o = [0x22u8; 16];
    let t = Instant::now();
    let kp = link_key_password(pw, &salt_p);
    let kdf_ms = t.elapsed().as_secs_f64() * 1e3;
    let with_pw = seal(&inner, salt_p, kp);
    let open_link = seal(&inner, salt_o, link_key_open(&salt_o));
    println!(
        "R10d PW ChannelInviteV2: password invite {} B, open invite {} B, link {} characters after the 16-character prefix; one Argon2id at the v2 profile {:.1} ms here",
        with_pw.len(),
        open_link.len(),
        base32_len(with_pw.len()),
        kdf_ms
    );
    assert_eq!(with_pw.len(), LINK_LEN);
    assert_eq!(open_link.len(), LINK_LEN);

    // The joiner's client tries the open key first; a password invite does not open with it.
    assert_eq!(
        open(&open_link, link_key_open(&salt_of(&open_link))).as_deref(),
        Some(&inner[..])
    );
    assert!(open(&with_pw, link_key_open(&salt_of(&with_pw))).is_none());
    // The right password opens it; a wrong one (one word changed) does not.
    assert_eq!(
        open(&with_pw, link_key_password(pw, &salt_of(&with_pw))).as_deref(),
        Some(&inner[..])
    );
    let wrong = "cabin frost ladder margin orbit velvet.".as_bytes();
    assert!(open(&with_pw, link_key_password(wrong, &salt_of(&with_pw))).is_none());
    // A flipped ciphertext bit is refused (integrity).
    let mut tampered = with_pw.clone();
    tampered[40] ^= 1;
    assert!(open(&tampered, link_key_password(pw, &salt_of(&tampered))).is_none());

    // The leaked-link view: without the password the only fields a holder can read are the version
    // byte and the salt; the ciphertext is the inner invite under a key it cannot derive.
    let visible: Vec<u8> = with_pw[..17].to_vec();
    assert_eq!(visible[0], 2);
    for w in inner.windows(8) {
        assert!(
            !with_pw.windows(8).any(|x| x == w),
            "no 8-byte run of the inner invite appears in the link"
        );
    }
    println!("R10d PW leaked link without the password: 17 readable bytes (version, salt); the inner invite does not appear; the open key, a wrong password and a tampered link are all refused");
}
