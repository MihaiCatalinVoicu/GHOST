//! Round 10d, the channel password (design §19.28, as corrected by round 10e, §19.29): Argon2id
//! (RFC 9106) through RustCrypto's `argon2` 0.6.0 — the RFC's own Argon2id test vector, the cost of
//! candidate parameter profiles on this host — and the password-sealed invite `ChannelInviteV2`
//! exactly as §19.28.3 specifies it (`support/invite_v2.rs`): one size for open and password
//! invites and for every name, a wrong password, a tampered body and a tampered header refused by
//! the AEAD, what a leaked link shows (the version, whether a password is needed, a random salt),
//! and that an open link opens from its public salt alone.
//!
//! Round 10e: the first version of this probe measured a simplified format (a 17-byte header, the
//! t = 3 profile, HKDF without a salt, labels of its own, an AD without `kdf_code`), not the one the
//! design specified (review finding P12); it now builds the specified construction.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test r10d_password -- --nocapture --test-threads=1`

#[path = "support/invite_v2.rs"]
mod invite_v2;

use std::time::Instant;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use invite_v2::*;

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

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// The candidate profiles, timed on this host (medians of 7; single-threaded: `argon2` without its
/// `parallel` feature computes the p lanes one after the other, so p = 1 and p = 4 do the same work
/// — m blocks per pass — and take the same time here; round 10e, privacy finding 3).
#[test]
fn r10d_argon2id_profiles_on_this_host() {
    let profiles: [(&str, u32, u32, u32); 7] = [
        (
            "RFC 9106 second recommended: m=64 MiB t=3 p=4",
            65_536,
            3,
            4,
        ),
        ("m=64 MiB t=3 p=1", 65_536, 3, 1),
        ("m=64 MiB t=1 p=4 (kdf_code 1)", 65_536, 1, 4),
        ("m=64 MiB t=1 p=1", 65_536, 1, 1),
        ("m=32 MiB t=3 p=4", 32_768, 3, 4),
        ("m=19 MiB t=2 p=1 (an OWASP pair)", 19_456, 2, 1),
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

#[test]
fn r10d_password_sealed_invite() {
    let pw = "cabin frost ladder margin orbit velvet".as_bytes(); // six BIP-39 words, NFKD = itself
    let (short, long) = (v1_fields(0), v1_fields(48));
    let t = Instant::now();
    let with_pw = build(&short, 1, Some(pw), [0x11; 16]);
    let kdf_ms = t.elapsed().as_secs_f64() * 1e3;
    let with_pw_named = build(&long, 1, Some(pw), [0x33; 16]);
    let open_link = build(&short, 0, None, [0x22; 16]);
    let open_named = build(&long, 0, None, [0x44; 16]);
    let chars = 16 + base32_len(LINK_LEN);
    let v1_chars = 16 + base32_len(254);
    println!(
        "R10d PW ChannelInviteV2 (§19.28.3): password {} B / {} B (name 0 / 48 bytes), open {} B / {} B; link {chars} characters ({} after the 16-character prefix), QR byte mode level M version {} (V1's 254 B: {v1_chars} characters, version {}); one Argon2id at kdf_code 1 {kdf_ms:.1} ms here",
        with_pw.len(),
        with_pw_named.len(),
        open_link.len(),
        open_named.len(),
        base32_len(LINK_LEN),
        qr_version_m(chars),
        qr_version_m(v1_chars),
    );
    for l in [&with_pw, &with_pw_named, &open_link, &open_named] {
        assert_eq!(l.len(), LINK_LEN); // one size whatever the kdf_code and the name
    }
    assert_eq!(LINK_LEN, 335);
    assert_eq!((chars, qr_version_m(chars)), (552, 18));
    assert_eq!((v1_chars, qr_version_m(v1_chars)), (423, 16));

    // Opening: the right password; an open link without one; the refusals.
    assert_eq!(open(&with_pw, Some(pw)), Opened::Fields(short.clone()));
    assert_eq!(open(&with_pw_named, Some(pw)), Opened::Fields(long.clone()));
    assert_eq!(open(&open_link, None), Opened::Fields(short.clone()));
    assert_eq!(open(&open_named, Some(pw)), Opened::Fields(long)); // typed, but not needed
    assert_eq!(open(&with_pw, None), Opened::PasswordRequired);
    let wrong = "cabin frost ladder margin orbit velvet.".as_bytes();
    assert_eq!(open(&with_pw, Some(wrong)), Opened::WrongPasswordOrTampered);
    let mut tampered = with_pw.clone();
    tampered[40] ^= 1;
    assert_eq!(open(&tampered, Some(pw)), Opened::WrongPasswordOrTampered);
    // The header is in the AD: turning a password link into an "open" one is refused.
    let mut downgraded = with_pw.clone();
    downgraded[1] = 0;
    assert_eq!(open(&downgraded, None), Opened::WrongPasswordOrTampered);
    // A password link has no key without a password (no "zero" or absent-password key).
    assert!(seal_key(1, None, &[0x11; 16]).is_none());

    // What a leaked link shows without the password: the version, whether a password is needed
    // (kdf_code) and a random salt; an open link opens from its public salt alone, so the two kinds
    // are always distinguishable to a link holder; no pw_version travels in the link.
    assert_eq!((with_pw[0], with_pw[1], open_link[1]), (2, 1, 0));
    for w in short.windows(8) {
        assert!(
            !with_pw.windows(8).any(|x| x == w),
            "no 8-byte run of the inner invite appears in a password link"
        );
    }
    println!("R10d PW leaked link without the password: {HEADER_LEN} readable bytes (version, kdf_code, salt): a holder learns open vs password, and an open link opens from its salt; the inner invite does not appear in a password link; a wrong password, a flipped body bit and a flipped kdf_code are refused");
}
