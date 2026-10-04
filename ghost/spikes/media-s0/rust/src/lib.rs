//! Phase 11 S0 evidence tooling (design `docs/design/faza11-media.md`). Not product code.
//!
//! * [`format`]: a reference implementation of the media object of design §3 and §4 — written
//!   from the design text alone, so that every constant, offset and rule is exercised once before
//!   `ghost-client-media` is built in S1.
//! * [`jpeg`]: the JPEG marker walker and the §8.2 canonicaliser (V-M6).
//! * [`profile`]: the canonical fMP4 profile as corrected after the S0 review, as a checker.
//! * [`mp4`]: an ISO-BMFF box walker for the Media3 outputs pulled from the emulators (V-M2,
//!   V-M3, V-M12, V-M17, V-M22, V-M24), including the GHOST `mfra` builder of §8.3.

pub mod format;
pub mod jpeg;
pub mod mp4;
pub mod profile;
pub mod vectors;

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Parses lower- or upper-case hex; `None` on an odd length or a non-hex digit.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let b = t.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
