//! `ChannelInviteV2` exactly as design §19.28.3 specifies it (as corrected by round 10e, §19.29),
//! shared by the `r10d_password` and `r10e_password` probes (`#[path]` module; not a test target).
//!
//! ```text
//! header = version(1) = 0x02 || kdf_code(1) || salt(16)                          18 bytes, in clear
//! inner  = the V1 fields of §5.9 from `suite` to `name` (253 + name_len bytes), zero-padded to 301
//! AD     = "ghost/v1/ch/invite-v2" || header                                      (not transmitted)
//! k      = HKDF-SHA256(ikm, salt = salt, info = "ghost/v1/ch/invite-seal" || kdf_code, L = 32)
//! ikm    = Argon2id(NFKD(password), salt, profile(kdf_code), T = 32)  for kdf_code >= 1
//!        = salt                                                        for kdf_code = 0 (open)
//! link   = header || ChaCha20-Poly1305(k, 0^12, AD, inner)                        335 bytes
//! ```
#![allow(dead_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// The V1 fields from `suite` to `name` are 253 + name_len bytes, at most 301 (§5.9).
pub const INNER_LEN: usize = 301;
/// version(1) ‖ kdf_code(1) ‖ salt(16).
pub const HEADER_LEN: usize = 18;
pub const LINK_LEN: usize = HEADER_LEN + INNER_LEN + 16;
/// The AD label is the link's own: round 10d reused `"ghost/v1/ch/invite"`, the domain string of
/// `sponsor_sig` (§5.5).
pub const AD_LABEL: &[u8] = b"ghost/v1/ch/invite-v2";
pub const SEAL_INFO: &[u8] = b"ghost/v1/ch/invite-seal";

pub fn argon2id(m_kib: u32, t: u32, p: u32, pw: &[u8], salt: &[u8]) -> [u8; 32] {
    let a = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m_kib, t, p, Some(32)).unwrap(),
    );
    let mut out = [0u8; 32];
    a.hash_password_into(pw, salt, &mut out).unwrap();
    out
}

/// `profile(kdf_code)` = `(m KiB, t, p)`; code 0 is the open invite (no KDF).
pub fn profile(kdf_code: u8) -> Option<(u32, u32, u32)> {
    match kdf_code {
        1 => Some((65_536, 1, 4)),
        _ => None,
    }
}

/// The seal key. `ikm = Argon2id(password, salt, profile)` for a password invite, `ikm = salt` for
/// an open one (the declared exemption from §5.2 rule (1): the open seal is a format, not a
/// secret). A password for an open link, or none for a password link, gives no key.
pub fn seal_key(kdf_code: u8, password: Option<&[u8]>, salt: &[u8; 16]) -> Option<[u8; 32]> {
    let ikm: Vec<u8> = match (kdf_code, password) {
        (0, None) => salt.to_vec(),
        (c, Some(pw)) if c >= 1 => {
            let (m, t, p) = profile(c)?;
            argon2id(m, t, p, pw, salt).to_vec()
        }
        _ => return None,
    };
    let mut info = SEAL_INFO.to_vec();
    info.push(kdf_code);
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), &ikm)
        .expand(&info, &mut k)
        .unwrap();
    Some(k)
}

pub fn ad(header: &[u8]) -> Vec<u8> {
    let mut a = AD_LABEL.to_vec();
    a.extend_from_slice(header);
    a
}

/// A stand-in V1 body (§5.9) from `suite` on, with a name of `name_len` bytes.
pub fn v1_fields(name_len: usize) -> Vec<u8> {
    let mut b = vec![0x00, 0x03, 0, 3]; // suite 0x0003, size_class, handshake_ttl_code
    for i in 0..248 {
        b.push((i as u8).wrapping_mul(31).wrapping_add(7)); // channel_id … expiry_day
    }
    b.push(name_len as u8);
    b.extend(std::iter::repeat_n(b'n', name_len));
    assert_eq!(b.len(), 253 + name_len);
    b
}

pub fn build(fields: &[u8], kdf_code: u8, password: Option<&[u8]>, salt: [u8; 16]) -> Vec<u8> {
    let mut inner = fields.to_vec();
    inner.resize(INNER_LEN, 0);
    let mut header = vec![2u8, kdf_code];
    header.extend_from_slice(&salt);
    let k = seal_key(kdf_code, password, &salt).expect("key");
    let ct = ChaCha20Poly1305::new(&k.into())
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &inner,
                aad: &ad(&header),
            },
        )
        .unwrap();
    let mut link = header;
    link.extend_from_slice(&ct);
    link
}

#[derive(Debug, PartialEq)]
pub enum Opened {
    Fields(Vec<u8>),
    PasswordRequired,
    WrongPasswordOrTampered,
    NonCanonical,
}

pub fn open(link: &[u8], password: Option<&[u8]>) -> Opened {
    if link.len() != LINK_LEN || link[0] != 2 {
        return Opened::NonCanonical;
    }
    let kdf_code = link[1];
    if kdf_code != 0 && profile(kdf_code).is_none() {
        return Opened::NonCanonical;
    }
    if kdf_code >= 1 && password.is_none() {
        return Opened::PasswordRequired;
    }
    let salt: [u8; 16] = link[2..HEADER_LEN].try_into().unwrap();
    // An open link is opened with the open key whatever the user typed.
    let pw = if kdf_code == 0 { None } else { password };
    let Some(k) = seal_key(kdf_code, pw, &salt) else {
        return Opened::NonCanonical;
    };
    match ChaCha20Poly1305::new(&k.into()).decrypt(
        &Nonce::from([0u8; 12]),
        Payload {
            msg: &link[HEADER_LEN..],
            aad: &ad(&link[..HEADER_LEN]),
        },
    ) {
        Ok(inner) => {
            let name_len = inner[252] as usize;
            if name_len > 48 || inner[253 + name_len..].iter().any(|&b| b != 0) {
                return Opened::NonCanonical;
            }
            Opened::Fields(inner[..253 + name_len].to_vec())
        }
        Err(_) => Opened::WrongPasswordOrTampered,
    }
}

/// RFC 4648 base32, lowercase, unpadded (the `ghost://` link alphabet of ADR-05).
pub fn base32_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

/// The smallest QR version that holds `chars` bytes in byte mode at error-correction level M
/// (ISO/IEC 18004 capacities, versions 14 … 20).
pub fn qr_version_m(chars: usize) -> usize {
    [
        (14, 362),
        (15, 412),
        (16, 450),
        (17, 504),
        (18, 560),
        (19, 624),
        (20, 666),
    ]
    .iter()
    .find(|&&(_, cap)| chars <= cap)
    .map(|&(v, _)| v)
    .unwrap()
}
