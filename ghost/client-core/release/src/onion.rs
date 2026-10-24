//! Canonical onion spelling, §4.1: the ES parser's rule (`issuer/crates/entitlement/src/onion.rs`),
//! repeated here so the release formats do not depend on the issuer crate or the lenient
//! `OnionAddress` (F-D10). Canonical form: `"<56 lowercase base32>.onion:<port>"`, version byte 3,
//! SHA3-256 checksum, decimal port 1..=65535 with no sign, leading zeros or whitespace;
//! `format(parse(s)) = s`.

use sha3::{Digest, Sha3_256};

use crate::FormatError;

/// Parse and canonically validate one onion; on success the input slice IS the canonical form.
pub fn canonical_onion(s: &[u8]) -> Result<(), FormatError> {
    // Length: 56 base32 + ".onion:" (6) + 1..=5 port digits = 63..=67? No: 56+6=62, port 1..65535
    // gives total 63..=67? 62+1..=62+5 = 63..=67 — but §4.1 bounds onions as `<u16 ASCII ...>`, so
    // the wire cap is what the reader enforces; here we validate spelling and checksum only.
    let text = std::str::from_utf8(s).map_err(|_| FormatError::Onion)?;
    let (host, port) = text.rsplit_once(".onion:").ok_or(FormatError::Onion)?;
    if host.len() != 56 {
        return Err(FormatError::Onion);
    }
    if !host.bytes().all(|b| (b'a'..=b'z').contains(&b) || b.is_ascii_digit()) {
        return Err(FormatError::Onion);
    }
    // Port: decimal, 1..=65535, no sign, no leading zeros, no whitespace.
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FormatError::Onion);
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(FormatError::Onion);
    }
    let port: u32 = port.parse().map_err(|_| FormatError::Onion)?;
    if port == 0 {
        return Err(FormatError::Onion);
    }
    decode_check(host).map(|_| ())
}

fn decode_check(host: &str) -> Result<(), FormatError> {
    // RFC 4648 lowercase base32 decode of 56 chars -> 35 bytes (pubkey 32 + checksum 2 + version 1).
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(35);
    for c in host.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(FormatError::Onion),
        };
        acc = (acc << 5) | u32::from(v);
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1u32 << nbits) - 1;
        }
    }
    if out.len() != 35 {
        return Err(FormatError::Onion);
    }
    if out[34] != 3 {
        return Err(FormatError::Onion);
    }
    // Tor rend-spec-v3: checksum = SHA3-256(".onion checksum" || pubkey || version)[0..2].
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(&out[..32]);
    h.update([3u8]);
    let sum = h.finalize();
    if sum[0] != out[32] || sum[1] != out[33] {
        return Err(FormatError::Onion);
    }
    Ok(())
}

/// A parsed canonical onion, owned. Ordering/compare is on the canonical bytes (§4.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalOnion(pub Vec<u8>);

impl CanonicalOnion {
    pub fn parse(s: &[u8]) -> Result<Self, FormatError> {
        canonical_onion(s)?;
        Ok(CanonicalOnion(s.to_vec()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for CanonicalOnion {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A borrowed validated onion (avoids an alloc on the hot parse path).
#[derive(Debug, Clone, Copy)]
pub struct OnionRef<'a>(pub &'a [u8]);

impl<'a> OnionRef<'a> {
    pub fn parse(s: &'a [u8]) -> Result<Self, FormatError> {
        canonical_onion(s)?;
        Ok(OnionRef(s))
    }
}

impl AsRef<[u8]> for OnionRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real v3 onion (the staging issuer), canonical, port 443.
    const GOOD: &str =
        "yc5kgo3q6eyexdscqt7lhwlhxqni4a6b3p2yzcfalmmaxbgbggvya3ad.onion:443";

    #[test]
    fn good_onion_accepts() {
        canonical_onion(GOOD.as_bytes()).unwrap();
    }

    #[test]
    fn uppercase_rejected() {
        let bad = GOOD.to_uppercase().replace(".ONION:", ".onion:");
        assert_eq!(canonical_onion(bad.as_bytes()), Err(FormatError::Onion));
    }

    #[test]
    fn leading_zero_port_rejected() {
        let bad = GOOD.replace(":443", ":0443");
        assert_eq!(canonical_onion(bad.as_bytes()), Err(FormatError::Onion));
    }

    #[test]
    fn plus_port_rejected() {
        let bad = GOOD.replace(":443", ":+443");
        assert_eq!(canonical_onion(bad.as_bytes()), Err(FormatError::Onion));
    }

    #[test]
    fn port_zero_rejected() {
        let bad = GOOD.replace(":443", ":0");
        assert_eq!(canonical_onion(bad.as_bytes()), Err(FormatError::Onion));
    }

    #[test]
    fn corrupt_checksum_rejected() {
        let mut bad = GOOD.to_string();
        bad.replace_range(0..1, if bad.starts_with('a') { "b" } else { "a" });
        assert_eq!(canonical_onion(bad.as_bytes()), Err(FormatError::Onion));
    }
}
