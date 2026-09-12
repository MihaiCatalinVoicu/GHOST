//! v3 onion addresses as the Entitlement Schedule stores them (`"<56>.onion:<port>"`, design §3.1
//! rule 4): only the canonical form is accepted (lowercase RFC 4648 base32, version byte 3,
//! SHA3-256 checksum, decimal port 1..65535 without leading zeros). The client's transport keeps its
//! own parser (`client-core/net/src/onion.rs`); this one exists so the ES parser does not depend on
//! the client library.

use sha3::{Digest, Sha3_256};

use crate::FormatError;

const V3_LABEL_LEN: usize = 56;
const V3_VERSION: u8 = 0x03;
const CHECKSUM_DOMAIN: &[u8] = b".onion checksum";
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A validated v3 onion service address with port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Onion {
    pub pubkey: [u8; 32],
    pub port: u16,
}

impl Onion {
    /// Parses the canonical `"<56 base32>.onion:<port>"`.
    pub fn parse(text: &str) -> Result<Self, FormatError> {
        let (host, port) = text.rsplit_once(':').ok_or(FormatError::Onion)?;
        if port.is_empty() || port.len() > 5 {
            return Err(FormatError::Onion);
        }
        if !port.bytes().all(|b| b.is_ascii_digit()) || port.starts_with('0') {
            return Err(FormatError::Onion);
        }
        let port: u16 = port.parse().map_err(|_| FormatError::Onion)?;
        let pubkey = parse_hostname(host)?;
        Ok(Self { pubkey, port })
    }

    /// The canonical text form.
    pub fn format(&self) -> String {
        format!("{}:{}", hostname(&self.pubkey), self.port)
    }
}

/// Parses a canonical host name `"<56 base32>.onion"` (no port: what Tor writes to
/// `HiddenServiceDir/hostname`, without the newline) and returns the service key. A relay reads
/// its own onion this way (design §10.5, §19.10 point 3).
pub fn parse_hostname(host: &str) -> Result<[u8; 32], FormatError> {
    let label = host.strip_suffix(".onion").ok_or(FormatError::Onion)?;
    if label.len() != V3_LABEL_LEN {
        return Err(FormatError::Onion);
    }
    let raw = base32_decode(label).ok_or(FormatError::Onion)?;
    let pubkey: [u8; 32] = raw[..32].try_into().map_err(|_| FormatError::Onion)?;
    if raw[34] != V3_VERSION || raw[32..34] != checksum(&pubkey) {
        return Err(FormatError::Onion);
    }
    Ok(pubkey)
}

/// The host name `"<56 base32>.onion"` of a v3 service key (rend-spec-v3 §6 [ONIONADDRESS]):
/// `base32(pubkey || checksum || 0x03)`, `checksum = SHA3-256(".onion checksum" || pubkey ||
/// 0x03)[..2]`. It is what Tor writes to `HiddenServiceDir/hostname` (without the newline).
pub fn hostname(pubkey: &[u8; 32]) -> String {
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pubkey);
    raw[32..34].copy_from_slice(&checksum(pubkey));
    raw[34] = V3_VERSION;
    format!("{}.onion", base32_encode(&raw))
}

fn checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(CHECKSUM_DOMAIN);
    h.update(pubkey);
    h.update([V3_VERSION]);
    let d = h.finalize();
    [d[0], d[1]]
}

fn base32_encode(raw: &[u8; 35]) -> String {
    let mut out = String::with_capacity(V3_LABEL_LEN);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in raw {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    out
}

/// 56 lowercase base32 characters -> 35 bytes (280 bits exactly, so no padding bits exist).
fn base32_decode(label: &str) -> Option<[u8; 35]> {
    let mut out = [0u8; 35];
    let (mut acc, mut bits, mut pos) = (0u32, 0u32, 0usize);
    for c in label.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(pos)? = (acc >> bits) as u8;
            pos += 1;
        }
    }
    (pos == 35).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../../../protocol/test-vectors/onion_addresses.txt");

    #[test]
    fn canonical_valid_vectors_parse_and_round_trip() {
        let mut seen = 0;
        for line in VECTORS.lines() {
            let Some(addr) = line.strip_prefix("valid|") else {
                continue;
            };
            // The ES stores the canonical form only: no case folding, no surrounding whitespace.
            if addr != addr.trim()
                || addr.contains('\\')
                || addr.bytes().any(|b| b.is_ascii_uppercase())
            {
                assert!(Onion::parse(addr).is_err(), "{addr}");
                continue;
            }
            let onion = Onion::parse(addr).unwrap_or_else(|e| panic!("{addr}: {e:?}"));
            assert_eq!(onion.format(), addr);
            seen += 1;
        }
        assert!(seen >= 2);
    }

    #[test]
    fn invalid_vectors_are_refused() {
        for line in VECTORS.lines() {
            let Some(rest) = line.strip_prefix("invalid|") else {
                continue;
            };
            let addr = rest.rsplit_once('|').map_or(rest, |(a, _)| a);
            assert!(Onion::parse(addr).is_err(), "{addr}");
        }
    }

    #[test]
    fn non_canonical_ports_are_refused() {
        let host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        assert!(Onion::parse(&format!("{host}:443")).is_ok());
        for port in ["0443", "+443", "0", "65536", "", "44 3"] {
            assert!(Onion::parse(&format!("{host}:{port}")).is_err(), "{port}");
        }
    }

    #[test]
    fn host_names_parse_without_a_port_and_only_in_canonical_form() {
        let key = [7u8; 32];
        let host = hostname(&key);
        assert_eq!(parse_hostname(&host), Ok(key));
        let with_port = format!("{host}:443");
        let upper = host.to_ascii_uppercase().replace(".ONION", ".onion");
        let mut bad_checksum = host.clone().into_bytes();
        bad_checksum[53] = if bad_checksum[53] == b'a' { b'b' } else { b'a' };
        let bad_checksum = String::from_utf8(bad_checksum).unwrap();
        for bad in [
            with_port.as_str(),
            upper.as_str(),
            &host[1..],
            &format!("a{host}"),
            host.trim_end_matches(".onion"),
            &format!("{host}\n"),
            &format!(" {host}"),
            bad_checksum.as_str(),
            "",
        ] {
            assert!(parse_hostname(bad).is_err(), "{bad:?}");
        }
        // The port parser and the host parser agree on the key.
        assert_eq!(Onion::parse(&with_port).unwrap().pubkey, key);
    }

    #[test]
    fn format_parses_back() {
        let onion = Onion {
            pubkey: [7; 32],
            port: 9001,
        };
        assert_eq!(Onion::parse(&onion.format()).unwrap(), onion);
    }
}
