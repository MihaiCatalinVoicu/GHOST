//! RFC 2617 HTTP Digest authentication, `qop=auth`, MD5 (Phase 8 design §7.1, §14.3; RM §2.2,
//! §8; ADR-26): the scheme of `--rpc-login` on `monero-wallet-rpc` and `monerod`. Their epee HTTP
//! server answers a request without valid credentials with `401` and two challenges,
//! `algorithm=MD5` and `algorithm=MD5-sess`, both `qop="auth"`, realm `monero-rpc`; this client
//! answers the MD5 one and never falls back to another scheme.
//!
//! The server keeps the nonce and a request counter **per connection**: every 401 carries a fresh
//! nonce and resets the counter, every request carrying credentials raises it and its `nc` must
//! equal it, and a nonce the connection does not hold is answered `stale=true`. The rail keeps a
//! challenge with the connection it arrived on and counts `nc` from 1 there ([`super::monero`]).
//!
//! ```text
//! HA1      = MD5(username ":" realm ":" password)
//! HA2      = MD5(method ":" uri)
//! response = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" "auth" ":" HA2)      (lowercase hex)
//! ```

use md5::{Digest, Md5};

use super::hex_encode;

/// The only `qop` value this client answers.
const QOP_AUTH: &str = "auth";

/// A login that is not one line `user:password` a digest header can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialsError;

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("login is not one line of the form user:password")
    }
}

impl std::error::Error for CredentialsError {}

/// The login of one RPC server, in the `--rpc-login` / `RPC_LOGIN` form `user:password`. `Debug`
/// never shows the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// A non-empty user name a quoted string carries as it is (printable ASCII without `"` and
    /// `\`) and a password without control characters.
    pub fn new(username: &str, password: &str) -> Result<Self, CredentialsError> {
        if username.is_empty() || !quotable(username) || password.chars().any(char::is_control) {
            return Err(CredentialsError);
        }
        Ok(Self {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// A login file: `user:password` on one line, one trailing line break allowed; the password is
    /// everything after the first `:`.
    pub fn parse_login(text: &str) -> Result<Self, CredentialsError> {
        let line = match text.strip_suffix('\n') {
            Some(l) => l.strip_suffix('\r').unwrap_or(l),
            None => text,
        };
        let (username, password) = line.split_once(':').ok_or(CredentialsError)?;
        Self::new(username, password)
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"redacted")
            .finish()
    }
}

/// A digest challenge this client answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    /// The server refused a nonce it does not hold (on this connection), not the credentials.
    pub stale: bool,
}

/// The first of `values` (each one `WWW-Authenticate` header value) that is a Digest challenge
/// with the MD5 algorithm (named or implied) and a `qop` list containing `auth`, and whose realm,
/// nonce and opaque value a quoted string carries as they are. A challenge with a parameter that
/// does not parse, or with one parameter given twice, is skipped.
pub fn select_challenge<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<Challenge> {
    values.into_iter().find_map(parse_challenge)
}

fn parse_challenge(value: &str) -> Option<Challenge> {
    let value = value.trim_start();
    let (scheme, params) = value.split_at(value.find([' ', '\t'])?);
    if !scheme.eq_ignore_ascii_case("Digest") {
        return None;
    }
    let params = parse_params(params)?;
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if get("algorithm").is_some_and(|a| !a.eq_ignore_ascii_case("MD5")) {
        return None;
    }
    if !get("qop")?
        .split(',')
        .any(|q| q.trim().eq_ignore_ascii_case(QOP_AUTH))
    {
        return None;
    }
    let realm = get("realm")?;
    let nonce = get("nonce")?;
    let opaque = get("opaque");
    if nonce.is_empty()
        || !quotable(realm)
        || !quotable(nonce)
        || opaque.is_some_and(|o| !quotable(o))
    {
        return None;
    }
    Some(Challenge {
        realm: realm.to_string(),
        nonce: nonce.to_string(),
        opaque: opaque.map(str::to_string),
        stale: get("stale").is_some_and(|s| s.eq_ignore_ascii_case("true")),
    })
}

/// `name=token` and `name="quoted string"` pairs separated by commas (RFC 2617 §1.2, RFC 2616
/// §2.2); names are compared in lowercase.
fn parse_params(s: &str) -> Option<Vec<(String, String)>> {
    let bytes = s.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    loop {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        if i == bytes.len() {
            return Some(out);
        }
        let start = i;
        while i < bytes.len() && is_token(bytes[i]) {
            i += 1;
        }
        if i == start || bytes.get(i) != Some(&b'=') {
            return None;
        }
        let name = s[start..i].to_ascii_lowercase();
        i += 1;
        let value = if bytes.get(i) == Some(&b'"') {
            i += 1;
            let mut v = Vec::new();
            loop {
                match *bytes.get(i)? {
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b'\\' => {
                        v.push(*bytes.get(i + 1)?);
                        i += 2;
                    }
                    c => {
                        v.push(c);
                        i += 1;
                    }
                }
            }
            String::from_utf8(v).ok()?
        } else {
            let start = i;
            while i < bytes.len() && is_token(bytes[i]) {
                i += 1;
            }
            if i == start {
                return None;
            }
            s[start..i].to_string()
        };
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        if (i < bytes.len() && bytes[i] != b',') || out.iter().any(|(k, _)| *k == name) {
            return None;
        }
        out.push((name, value));
    }
}

/// RFC 2616 token characters.
fn is_token(b: u8) -> bool {
    b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b)
}

/// Printable ASCII without `"` and `\`: carried inside a quoted string as it is.
fn quotable(s: &str) -> bool {
    s.bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

/// The `Authorization` value answering `challenge` for one request: `nc` counts the requests
/// carrying this challenge on its connection from 1, `cnonce` is fresh client randomness (hex).
/// `uri` and `cnonce` are the caller's own quotable values.
pub fn authorization(
    credentials: &Credentials,
    challenge: &Challenge,
    method: &str,
    uri: &str,
    nc: u32,
    cnonce: &str,
) -> String {
    let ha1 = md5_hex(&[
        &credentials.username,
        ":",
        &challenge.realm,
        ":",
        &credentials.password,
    ]);
    let ha2 = md5_hex(&[method, ":", uri]);
    let nc = format!("{nc:08x}");
    let response = md5_hex(&[
        &ha1,
        ":",
        &challenge.nonce,
        ":",
        &nc,
        ":",
        cnonce,
        ":",
        QOP_AUTH,
        ":",
        &ha2,
    ]);
    let opaque = challenge
        .opaque
        .as_ref()
        .map(|o| format!(", opaque=\"{o}\""))
        .unwrap_or_default();
    format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", algorithm=MD5, \
         response=\"{response}\", qop={QOP_AUTH}, nc={nc}, cnonce=\"{cnonce}\"{opaque}",
        credentials.username, challenge.realm, challenge.nonce
    )
}

fn md5_hex(parts: &[&str]) -> String {
    let mut h = Md5::new();
    for p in parts {
        h.update(p.as_bytes());
    }
    hex_encode(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two challenges of a `monerod` v0.18.5.1 401 (recorded from a regtest daemon with
    /// `--rpc-login`).
    const EPEE_MD5: &str = "Digest qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"zJzP8R8JlXUFtsjK7/o5NQ==\",stale=false";
    const EPEE_MD5_SESS: &str = "Digest qop=\"auth\",algorithm=MD5-sess,realm=\"monero-rpc\",nonce=\"zJzP8R8JlXUFtsjK7/o5NQ==\",stale=false";

    #[test]
    fn rfc_2617_example() {
        // RFC 2617 §3.5.
        let challenge = select_challenge([
            "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        ])
        .unwrap();
        let creds = Credentials::new("Mufasa", "Circle Of Life").unwrap();
        let header = authorization(&creds, &challenge, "GET", "/dir/index.html", 1, "0a4f113b");
        assert!(
            header.contains("response=\"6629fae49393a05397450978507c4ef1\""),
            "{header}"
        );
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    }

    #[test]
    fn the_md5_challenge_of_epee_is_chosen() {
        let c = select_challenge([EPEE_MD5_SESS, EPEE_MD5]).unwrap();
        assert_eq!(c.realm, "monero-rpc");
        assert_eq!(c.nonce, "zJzP8R8JlXUFtsjK7/o5NQ==");
        assert!(!c.stale);
        assert!(select_challenge([EPEE_MD5_SESS]).is_none());
        let stale = EPEE_MD5.replace("stale=false", "stale=true");
        assert!(select_challenge([stale.as_str()]).unwrap().stale);
    }

    #[test]
    fn challenges_the_client_cannot_answer_are_skipped() {
        for bad in [
            "Basic realm=\"monero-rpc\"",
            "Digest realm=\"r\", nonce=\"n\"",
            "Digest qop=\"auth-int\", realm=\"r\", nonce=\"n\"",
            "Digest qop=\"auth\", algorithm=SHA-256, realm=\"r\", nonce=\"n\"",
            "Digest qop=\"auth\", realm=\"r\", nonce=\"\"",
            "Digest qop=\"auth\", realm=\"r\", nonce=\"a\\\"b\"",
            "Digest qop=\"auth\", realm=\"r\", realm=\"s\", nonce=\"n\"",
            "Digest qop=\"auth\", realm=\"r\" nonce=\"n\"",
            "Digest qop=\"auth\", realm=\"r\", nonce=\"n",
            "Digest",
        ] {
            assert!(select_challenge([bad]).is_none(), "{bad}");
        }
    }

    #[test]
    fn login_files() {
        let c = Credentials::parse_login("ci:pass:with:colons\n").unwrap();
        assert_eq!(c.username(), "ci");
        assert_eq!(c.password, "pass:with:colons");
        assert_eq!(Credentials::parse_login("ci:x\r\n").unwrap().password, "x");
        for bad in ["", "ci", ":x", "ci:x\nsecond:y", "c\"i:x", "ci:x\n\n"] {
            assert!(Credentials::parse_login(bad).is_err(), "{bad:?}");
        }
        assert!(!format!("{c:?}").contains("colons"));
    }
}
