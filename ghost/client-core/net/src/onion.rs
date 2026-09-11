//! v3 onion address type. Parsing is strict: ASCII only, RFC 4648 base32, 56 characters,
//! `.onion`, v3 version byte and SHA3-256 checksum. It is the only destination type the transport
//! accepts (fail-closed, T6). Test vectors are shared with the Kotlin mirror
//! (`protocol/test-vectors/onion_addresses.txt`).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress {
    host: String, // "<56 base32 chars>.onion", lowercase
    port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OnionParseError {
    NotOnion,
    BadLength,
    BadAlphabet,
    BadPort,
    UrlStructure,
    /// Well-formed length and alphabet, but the v3 version byte or SHA3 checksum is wrong.
    BadChecksum,
}

impl fmt::Display for OnionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OnionParseError::NotOnion => "address is not a .onion host",
            OnionParseError::BadLength => "onion address has wrong length (v3 requires 56 chars)",
            OnionParseError::BadAlphabet => "onion address contains non-base32 characters",
            OnionParseError::BadPort => "port is missing or invalid",
            OnionParseError::UrlStructure => "address must be host:port without scheme or path",
            OnionParseError::BadChecksum => "onion address has a wrong v3 version or checksum",
        };
        f.write_str(s)
    }
}

impl std::error::Error for OnionParseError {}

const V3_LEN: usize = 56;
const SUFFIX: &str = ".onion";

impl OnionAddress {
    /// Parses `"<56 base32>.onion:<port>"`. Anything else, including IPs, DNS names and URLs, fails.
    pub fn parse(text: &str) -> Result<Self, OnionParseError> {
        // Only ASCII space and tab are trimmed, exactly like the Kotlin mirror (str::trim would
        // also strip Unicode whitespace such as U+0085 and disagree with it).
        let t = text.trim_matches(|c| c == ' ' || c == '\t');
        if !t.is_ascii() || t.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(OnionParseError::BadAlphabet);
        }
        if t.contains("://")
            || t.contains('/')
            || t.contains('?')
            || t.contains('#')
            || t.contains('@')
        {
            return Err(OnionParseError::UrlStructure);
        }
        let (host, port) = t.rsplit_once(':').ok_or(OnionParseError::BadPort)?;
        let port: u16 = port.parse().map_err(|_| OnionParseError::BadPort)?;
        if port == 0 {
            return Err(OnionParseError::BadPort);
        }
        let host = host.to_ascii_lowercase();
        let label = host.strip_suffix(SUFFIX).ok_or(OnionParseError::NotOnion)?;
        if label.len() != V3_LEN {
            return Err(OnionParseError::BadLength);
        }
        if !label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        {
            return Err(OnionParseError::BadAlphabet);
        }
        // Version byte (3) and SHA3-256 checksum, via the same parser Arti uses: a mistyped
        // address fails here as not-onion instead of later as an unreachable-relay error.
        host.parse::<tor_hscrypto::pk::HsId>()
            .map_err(|_| OnionParseError::BadChecksum)?;
        Ok(OnionAddress { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors shared with the Kotlin mirror so the two validators cannot drift apart.
    const VECTORS: &str = include_str!("../../../protocol/test-vectors/onion_addresses.txt");

    /// Inputs may carry \\uXXXX escapes (control and whitespace characters).
    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("\\u") {
            out.push_str(&rest[..i]);
            let code = u32::from_str_radix(&rest[i + 2..i + 6], 16).expect("4 hex digits");
            out.push(char::from_u32(code).expect("valid char"));
            rest = &rest[i + 6..];
        }
        out.push_str(rest);
        out
    }

    fn vectors() -> impl Iterator<Item = (bool, String, &'static str)> {
        VECTORS
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut parts = l.splitn(3, '|');
                let kind = parts.next().unwrap();
                let input = unescape(parts.next().unwrap());
                let why = parts.next().unwrap_or("");
                (kind == "valid", input, why)
            })
    }

    #[test]
    fn shared_vectors() {
        let mut valid = 0;
        let mut invalid = 0;
        for (ok, input, why) in vectors() {
            let parsed = OnionAddress::parse(&input);
            if ok {
                valid += 1;
                let a = parsed.unwrap_or_else(|e| panic!("{input} must be accepted: {e}"));
                assert!(a.host().ends_with(".onion"));
                assert_eq!(a.host(), a.host().to_ascii_lowercase());
            } else {
                invalid += 1;
                assert!(parsed.is_err(), "{input} must be rejected ({why})");
            }
        }
        assert!(valid >= 3 && invalid >= 15, "vector file incomplete");
    }

    #[test]
    fn checksum_errors_are_reported_as_such() {
        // Public key changed, checksum and version kept: only the SHA3 checksum can catch it.
        let bad = "eeckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443";
        assert_eq!(OnionAddress::parse(bad), Err(OnionParseError::BadChecksum));
        // Checksum kept, version byte 0x23 instead of 3.
        let bad_version = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczbd.onion:443";
        assert_eq!(
            OnionAddress::parse(bad_version),
            Err(OnionParseError::BadChecksum)
        );
    }
}
