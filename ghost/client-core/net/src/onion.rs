//! v3 onion address type. Parsing is strict (RFC 4648 base32 lowercase, 56 characters, `.onion`),
//! and the type is the only thing the transport will connect to (fail-closed, T6).

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
}

impl fmt::Display for OnionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OnionParseError::NotOnion => "address is not a .onion host",
            OnionParseError::BadLength => "onion address has wrong length (v3 requires 56 chars)",
            OnionParseError::BadAlphabet => "onion address contains non-base32 characters",
            OnionParseError::BadPort => "port is missing or invalid",
            OnionParseError::UrlStructure => "address must be host:port without scheme or path",
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
        let t = text.trim();
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

    const GOOD: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:443";

    #[test]
    fn accepts_v3_and_normalizes_case() {
        let a = OnionAddress::parse(GOOD).unwrap();
        assert_eq!(a.port(), 443);
        assert!(a.host().ends_with(".onion"));
        assert_eq!(OnionAddress::parse(&GOOD.to_uppercase()).unwrap(), a);
    }

    #[test]
    fn rejects_everything_that_is_not_an_onion_host() {
        for bad in [
            "relay.example.com:443",
            "203.0.113.5:443",
            "[2001:db8::1]:443",
            "https://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:443",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:0",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:443/path",
            "facebookcorewwwi.onion:443", // v2 length
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscry1.onion:443", // '1' not base32
            "user@pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:443",
        ] {
            assert!(OnionAddress::parse(bad).is_err(), "{bad} must be rejected");
        }
    }
}
