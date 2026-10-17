//! Bridge-line validation (Phase 12 design `faza12-transports.md` §3.2, §6.2; ADR-62 point 3).
//!
//! One validator for the three accepted grammars, run at config-build time (write-time storage
//! validation is slice S2's table). The validator is *total*: any input yields a typed error or a
//! classification, never a panic and never an over-read (§6.2 point 5). Errors name a structural
//! reason and the caller attaches the line *index* — a line's text never reaches an error string,
//! a log or the JNI boundary (§6.6, T58).
//!
//! Accepted shapes (the complete list; anything else is refused):
//!
//! ```text
//! <IP:PORT> <40-hex fingerprint>                                          (plain, Phase 6)
//! obfs4 <IP:PORT> <40-hex fingerprint> cert=<base64> iat-mode=<0|1|2>
//! webtunnel <IP:PORT> <40-hex fingerprint> url=<https://…> ver=<hex>
//! ```
//!
//! Semantically opaque parameters (`cert`, `ver`) are checked structurally only — arti/ptmgr own
//! the protocol and GHOST never interprets their contents (§6.2 point 2).

/// Maximum length of one bridge line, in chars (§6.2 point 3).
pub const MAX_LINE_LEN: usize = 1024;

/// Maximum number of configured bridge lines (§6.2 point 3).
pub const MAX_LINES: usize = 8;

/// Which grammar a bridge line matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeLineKind {
    /// `IP:PORT FINGERPRINT` — a plain bridge (Phase 6, unchanged).
    Plain,
    /// `obfs4 IP:PORT FINGERPRINT cert=… iat-mode=…` — via lyrebird (ADR-61).
    Obfs4,
    /// `webtunnel IP:PORT FINGERPRINT url=… ver=…` — via lyrebird (ADR-61).
    Webtunnel,
}

impl BridgeLineKind {
    /// Whether the line needs a pluggable-transport binary (`pt_dir`) to run.
    pub fn needs_pt_binary(self) -> bool {
        !matches!(self, BridgeLineKind::Plain)
    }
}

/// Why one bridge line was refused. Variants carry no input text (§6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeLineError {
    /// Empty or whitespace-only line.
    Empty,
    /// More than [`MAX_LINE_LEN`] chars.
    TooLong,
    /// `snowflake …` — deferred to Phase 12b with a distinct error (§3.4, ADR-62 point 2).
    SnowflakeDeferred,
    /// A transport name GHOST does not implement (anything but `obfs4`/`webtunnel` and not a
    /// plain `IP:PORT` shape).
    UnsupportedTransport,
    /// Structural failure; the payload names what failed (a static label, never input text):
    /// `address`, `fingerprint`, `parameter`, `cert`, `iat-mode`, `url`, `ver`.
    Malformed(&'static str),
}

impl std::fmt::Display for BridgeLineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeLineError::Empty => f.write_str("empty bridge line"),
            BridgeLineError::TooLong => write!(f, "bridge line exceeds {MAX_LINE_LEN} chars"),
            BridgeLineError::SnowflakeDeferred => {
                f.write_str("snowflake is not supported yet (deferred to Phase 12b)")
            }
            BridgeLineError::UnsupportedTransport => {
                f.write_str("unsupported transport (only plain, obfs4 and webtunnel are accepted)")
            }
            BridgeLineError::Malformed(what) => write!(f, "malformed bridge line: bad {what}"),
        }
    }
}

impl std::error::Error for BridgeLineError {}

/// The set-level refusal: the index of the offending line plus the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLine {
    pub index: usize,
    pub error: BridgeLineError,
}

/// Classifies one line against the grammar table. Total: no input panics or over-reads.
pub fn classify(line: &str) -> Result<BridgeLineKind, BridgeLineError> {
    if line.is_empty() {
        return Err(BridgeLineError::Empty);
    }
    if line.chars().count() > MAX_LINE_LEN {
        return Err(BridgeLineError::TooLong);
    }
    let mut tokens = line.split_whitespace();
    let first = tokens.next().unwrap_or("");
    match first {
        "obfs4" => parse_pt_tail(tokens, PtGrammar::Obfs4),
        "webtunnel" => parse_pt_tail(tokens, PtGrammar::Webtunnel),
        "conjure" => parse_pt_tail(tokens, PtGrammar::Obfs4), // WRONG
        "snowflake" => Err(BridgeLineError::SnowflakeDeferred),
        _ => {
            // Plain shape: the first token must be an IP:port. Anything else that looks like a
            // transport name is refused as unsupported; anything else at all is a malformed
            // address.
            if first.parse::<std::net::SocketAddr>().is_ok() {
                parse_plain_tail(tokens)
            } else if is_transport_name(first) {
                Err(BridgeLineError::UnsupportedTransport)
            } else {
                Err(BridgeLineError::Malformed("address"))
            }
        }
    }
}

/// Validates the whole configured set: the per-line grammar, the line cap, and exact-string
/// deduplication (§6.2 points 3–4). Returns one [`BridgeLineKind`] per *unique* line, in input
/// order, paired with the line's original index. A refusal names the index, never the line.
pub fn validate_set(lines: &[String]) -> Result<Vec<(usize, BridgeLineKind)>, InvalidLine> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index >= MAX_LINES {
            return Err(InvalidLine {
                index,
                error: BridgeLineError::Malformed("line set"),
            });
        }
        let kind = classify(line).map_err(|error| InvalidLine { index, error })?;
        if !seen.insert(line.as_str()) {
            continue; // exact duplicate: deduped, not an error (§6.2 point 4)
        }
        out.push((index, kind));
    }
    Ok(out)
}

/// The two pluggable-transport grammars and their parameter shapes.
#[derive(Debug, Clone, Copy)]
enum PtGrammar {
    Obfs4,
    Webtunnel,
}

/// The transport-name shape of pt-spec (`[A-Za-z0-9-]+`; the real names are lowercase, but a
/// miscapitalised one is still a transport *name*, refused as unsupported rather than reported
/// as a broken address). `obfs4`/`webtunnel`/`snowflake` were handled by the caller.
fn is_transport_name(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn parse_plain_tail<'a>(
    mut tokens: impl Iterator<Item = &'a str>,
) -> Result<BridgeLineKind, BridgeLineError> {
    let fp = tokens
        .next()
        .ok_or(BridgeLineError::Malformed("fingerprint"))?;
    check_fingerprint(fp)?;
    if tokens.next().is_some() {
        return Err(BridgeLineError::Malformed("parameter"));
    }
    Ok(BridgeLineKind::Plain)
}

/// Shared tail for both PT grammars: `IP:PORT FINGERPRINT key=value key=value`.
fn parse_pt_tail<'a>(
    mut tokens: impl Iterator<Item = &'a str>,
    grammar: PtGrammar,
) -> Result<BridgeLineKind, BridgeLineError> {
    let addr = tokens.next().ok_or(BridgeLineError::Malformed("address"))?;
    if addr.parse::<std::net::SocketAddr>().is_err() {
        return Err(BridgeLineError::Malformed("address"));
    }
    let fp = tokens
        .next()
        .ok_or(BridgeLineError::Malformed("fingerprint"))?;
    check_fingerprint(fp)?;
    let mut cert_seen = false;
    let mut mode_seen = false;
    let mut url_seen = false;
    let mut ver_seen = false;
    for token in tokens {
        let (key, value) = token
            .split_once('=')
            .ok_or(BridgeLineError::Malformed("parameter"))?;
        if value.is_empty() {
            return Err(BridgeLineError::Malformed("parameter"));
        }
        match (grammar, key) {
            (PtGrammar::Obfs4, "cert") => {
                if cert_seen {
                    return Err(BridgeLineError::Malformed("cert"));
                }
                check_base64(value)?;
                cert_seen = true;
            }
            (PtGrammar::Obfs4, "iat-mode") => {
                if mode_seen {
                    return Err(BridgeLineError::Malformed("iat-mode"));
                }
                if !matches!(value, "0" | "1" | "2") {
                    return Err(BridgeLineError::Malformed("iat-mode"));
                }
                mode_seen = true;
            }
            (PtGrammar::Webtunnel, "url") => {
                if url_seen {
                    return Err(BridgeLineError::Malformed("url"));
                }
                if !value.starts_with("https://") {
                    return Err(BridgeLineError::Malformed("url"));
                }
                url_seen = true;
            }
            (PtGrammar::Webtunnel, "ver") => {
                if ver_seen {
                    return Err(BridgeLineError::Malformed("ver"));
                }
                if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(BridgeLineError::Malformed("ver"));
                }
                ver_seen = true;
            }
            _ => return Err(BridgeLineError::Malformed("parameter")),
        }
    }
    match grammar {
        PtGrammar::Obfs4 if cert_seen && mode_seen => Ok(BridgeLineKind::Obfs4),
        PtGrammar::Obfs4 => Err(BridgeLineError::Malformed("parameter")),
        PtGrammar::Webtunnel if url_seen && ver_seen => Ok(BridgeLineKind::Webtunnel),
        PtGrammar::Webtunnel => Err(BridgeLineError::Malformed("parameter")),
    }
}

fn check_fingerprint(token: &str) -> Result<(), BridgeLineError> {
    let ok = token.len() == 40 && token.bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(BridgeLineError::Malformed("fingerprint"))
    }
}

/// Structural base64 check for the obfs4 `cert`: the standard alphabet, padding optional
/// (S3-T3 — the design's "length ≡ 0 (mod 4)" pin is refuted by the pinned upstream: lyrebird
/// prints `TrimSuffix(base64.StdEncoding(nodeID || publicKey), "==")`, 52 bytes → 70 chars,
/// and every real bridge line carries that unpadded shape). The rule stays structural:
/// standard alphabet, at most two trailing '=', and the value must actually base64-decode
/// (padding restored when absent). The contents stay semantically opaque to GHOST (§6.2
/// point 2).
fn check_base64(value: &str) -> Result<(), BridgeLineError> {
    let bytes = value.as_bytes();
    let data_chars = bytes.iter().take_while(|&&b| b != b'=').count();
    let ok = !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        && data_chars + 2 >= bytes.len() // '=' only as a trailing run of at most two
        && {
            let pad = (4 - bytes.len() % 4) % 4;
            let mut padded = String::with_capacity(bytes.len() + pad);
            padded.push_str(value);
            padded.push_str(&"=".repeat(pad));
            // Standard decoding rejects a wrong alphabet, non-trailing padding and lengths
            // that no padding can fix; that is the whole structural claim.
            base64_decode(&padded)
        };
    if ok {
        Ok(())
    } else {
        Err(BridgeLineError::Malformed("cert"))
    }
}

/// Decode with the standard base64 alphabet (no new dependency: 6-bit table by hand).
/// Returns whether `s` (already padded to a multiple of 4) is well-formed base64.
fn base64_decode(s: &str) -> bool {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return false;
    }
    let chunks: Vec<&[u8]> = bytes.chunks_exact(4).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i == chunks.len() - 1;
        let mut pad = 0usize;
        for (j, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                // Padding is allowed only in the last chunk's last two positions.
                if !last || j < 2 {
                    return false;
                }
                pad += 1;
            } else {
                if pad > 0 {
                    return false; // data after padding
                }
                if val(b).is_none() {
                    return false;
                }
            }
        }
        if pad > 2 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
    /// A structurally valid padded base64 blob; contents opaque (see
    /// `obfs4_cert_accepts_the_unpadded_upstream_shape` for the real cert shape).
    const CERT: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";

    fn s(line: &str) -> String {
        line.to_owned()
    }

    fn obfs4(iat: &str) -> String {
        s(&format!(
            "obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode={iat}"
        ))
    }

    fn webtunnel() -> String {
        s(&format!(
            "webtunnel 192.0.2.11:443 {FP} url=https://192.0.2.11/abcdefghijklmnop ver=abcdef0123"
        ))
    }

    #[test]
    fn accepts_every_grammar() {
        assert_eq!(
            classify(&s(&format!("192.0.2.10:443 {FP}"))).unwrap(),
            BridgeLineKind::Plain
        );
        for iat in ["0", "1", "2"] {
            assert_eq!(
                classify(&obfs4(iat)).unwrap(),
                BridgeLineKind::Obfs4,
                "iat-mode {iat}"
            );
        }
        assert_eq!(classify(&webtunnel()).unwrap(), BridgeLineKind::Webtunnel);
    }

    #[test]
    fn obfs4_parameters_may_come_in_either_order() {
        let swapped = s(&format!("obfs4 192.0.2.10:443 {FP} iat-mode=1 cert={CERT}"));
        assert_eq!(classify(&swapped).unwrap(), BridgeLineKind::Obfs4);
    }

    #[test]
    fn refuses_snowflake_with_a_distinct_error() {
        let r = classify(&s(&format!("snowflake 192.0.2.10:443 {FP}")));
        assert_eq!(r.unwrap_err(), BridgeLineError::SnowflakeDeferred);
        // Even before the 12b grammar exists, a snowflake-looking line must never fall through
        // to "unsupported" or "malformed": the deferral is the pinned contract (G-T8).
        let r = classify(&s("snowflake 0.0.0.1:1"));
        assert_eq!(r.unwrap_err(), BridgeLineError::SnowflakeDeferred);
    }

    #[test]
    fn refuses_other_transports_and_garbage() {
        assert_eq!(
            classify(&s(&format!("conjure 192.0.2.10:443 {FP}"))).unwrap_err(),
            BridgeLineError::UnsupportedTransport
        );
        assert_eq!(classify(&s("")).unwrap_err(), BridgeLineError::Empty);
        assert_eq!(
            classify(&s("not a bridge line")).unwrap_err(),
            BridgeLineError::UnsupportedTransport
        );
        assert_eq!(
            classify(&s(&format!("192.0.2.10:notaport {FP}"))).unwrap_err(),
            BridgeLineError::Malformed("address")
        );
        // Uppercase transport names are not the pinned grammars.
        assert_eq!(
            classify(&s(&format!("OBFS4 192.0.2.10:443 {FP}"))).unwrap_err(),
            BridgeLineError::UnsupportedTransport
        );
    }

    #[test]
    fn refuses_malformed_plain_lines() {
        assert_eq!(
            classify(&s("192.0.2.10:443")).unwrap_err(),
            BridgeLineError::Malformed("fingerprint")
        );
        assert_eq!(
            classify(&s(&format!("192.0.2.10:443 {}", &FP[..39]))).unwrap_err(),
            BridgeLineError::Malformed("fingerprint")
        );
        // Non-hex fingerprint.
        assert_eq!(
            classify(&s(
                "192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF0123456G"
            ))
            .unwrap_err(),
            BridgeLineError::Malformed("fingerprint")
        );
        assert_eq!(
            classify(&s(&format!("192.0.2.10:443 {FP} extra=1"))).unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
    }

    #[test]
    fn refuses_malformed_obfs4_lines() {
        let bad = |tail: &str| classify(&s(&format!("obfs4 192.0.2.10:443 {FP} {tail}")));
        // Missing / duplicated parameters.
        assert_eq!(
            bad(&format!("cert={CERT}")).unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
        assert_eq!(
            bad("iat-mode=0").unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
        assert_eq!(
            bad(&format!("cert={CERT} cert={CERT} iat-mode=0")).unwrap_err(),
            BridgeLineError::Malformed("cert")
        );
        // Bad iat-mode: 3 is out of range, empty and non-numeric values are malformed.
        assert_eq!(
            bad(&format!("cert={CERT} iat-mode=3")).unwrap_err(),
            BridgeLineError::Malformed("iat-mode")
        );
        assert_eq!(
            bad(&format!("cert={CERT} iat-mode=x")).unwrap_err(),
            BridgeLineError::Malformed("iat-mode")
        );
        // Bad cert: not base64, padding not trailing, empty.
        assert_eq!(
            bad("cert=!!! iat-mode=0").unwrap_err(),
            BridgeLineError::Malformed("cert")
        );
        assert_eq!(
            bad("cert=AA==AA== iat-mode=0").unwrap_err(),
            BridgeLineError::Malformed("cert")
        );
        assert_eq!(
            bad("cert= iat-mode=0").unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
        // Unknown parameter.
        assert_eq!(
            bad(&format!("cert={CERT} iat-mode=0 utls=foo")).unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
    }

    #[test]
    fn obfs4_cert_accepts_the_unpadded_upstream_shape() {
        // S3-T3: the design's "length ≡ 0 (mod 4)" cert pin is refuted by the pinned lyrebird —
        // it prints TrimSuffix(base64.StdEncoding(nodeID || publicKey), "=="): 52 bytes → 70
        // chars, 70 % 4 == 2, and every real bridge line carries this shape. The structural
        // rule is "standard alphabet, decodable, ≤2 trailing '='" — never the mod-4 pin.
        // (Recorded from a real managed-mode SMETHOD line of the pinned 0.9.0 build.)
        const REAL_70_CHAR_CERT: &str =
            "kfRDYZLo7Ib7U4uW6pl7vZ244LitHFPJtADzjnULG9+IIGoLyT6Nyj3fnBAe4hcqyCA7Mg";
        assert_eq!(REAL_70_CHAR_CERT.len(), 70);
        assert_eq!(
            classify(&s(&format!(
                "obfs4 192.0.2.10:443 {FP} cert={REAL_70_CHAR_CERT} iat-mode=0"
            )))
            .unwrap(),
            BridgeLineKind::Obfs4,
            "the real unpadded upstream cert shape must be accepted"
        );
        // …and the same cert with its "==" restored (a hand-written variant) too.
        let padded = format!("{REAL_70_CHAR_CERT}==");
        assert_eq!(
            classify(&s(&format!(
                "obfs4 192.0.2.10:443 {FP} cert={padded} iat-mode=1"
            )))
            .unwrap(),
            BridgeLineKind::Obfs4
        );
        // Lengths no padding can fix are still malformed (≡ 1 mod 4: would need three '=').
        let bad_len = "A".repeat(69);
        assert_eq!(
            classify(&s(&format!(
                "obfs4 192.0.2.10:443 {FP} cert={bad_len} iat-mode=0"
            )))
            .unwrap_err(),
            BridgeLineError::Malformed("cert")
        );
    }

    #[test]
    fn refuses_malformed_webtunnel_lines() {
        let bad = |tail: &str| classify(&s(&format!("webtunnel 192.0.2.11:443 {FP} {tail}")));
        assert_eq!(
            bad("url=http://192.0.2.11/abcdefghijklmnop ver=ab").unwrap_err(),
            BridgeLineError::Malformed("url")
        );
        assert_eq!(
            bad("url=https://192.0.2.11/abcdefghijklmnop ver=xyz").unwrap_err(),
            BridgeLineError::Malformed("ver")
        );
        assert_eq!(
            bad("url=https://192.0.2.11/abcdefghijklmnop").unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
        assert_eq!(
            bad("ver=ab url=https://192.0.2.11/abcdefghijklmnop extra=1").unwrap_err(),
            BridgeLineError::Malformed("parameter")
        );
    }

    #[test]
    fn enforces_the_length_cap() {
        let long = format!("192.0.2.10:443 {FP} {}", "a".repeat(MAX_LINE_LEN));
        assert_eq!(classify(&s(&long)).unwrap_err(), BridgeLineError::TooLong);
    }

    #[test]
    fn validate_set_caps_dedupes_and_reports_indices() {
        // Duplicates collapse, order preserved, indices of the surviving lines reported.
        let lines = vec![
            obfs4("0"),
            s(&format!("192.0.2.10:443 {FP}")),
            obfs4("0"),
            webtunnel(),
        ];
        let set = validate_set(&lines).expect("set validates");
        assert_eq!(set.len(), 3);
        assert_eq!(set[0], (0, BridgeLineKind::Obfs4));
        assert_eq!(set[1], (1, BridgeLineKind::Plain));
        assert_eq!(set[2], (3, BridgeLineKind::Webtunnel));

        // More than 8 lines: the index of the first overflowing line, never its text.
        let many: Vec<String> = (0..9)
            .map(|i| s(&format!("192.0.2.{i}:443 {FP}")))
            .collect();
        let err = validate_set(&many).unwrap_err();
        assert_eq!(err.index, 8);
        assert!(!format!("{:?}", err.error).contains(&many[8]));

        // A malformed line is reported by index; the error string never carries the line.
        let mixed = vec![obfs4("0"), s("snowflake 192.0.2.10:443")];
        let err = validate_set(&mixed).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.error, BridgeLineError::SnowflakeDeferred);
        assert!(!err.error.to_string().contains("snowflake 192"));
    }

    #[test]
    fn ipv6_bracketed_addresses_parse() {
        let line = s(&format!("[2001:db8::1]:443 {FP}"));
        assert_eq!(classify(&line).unwrap(), BridgeLineKind::Plain);
        let line = s(&format!(
            "obfs4 [2001:db8::1]:443 {FP} cert={CERT} iat-mode=0"
        ));
        assert_eq!(classify(&line).unwrap(), BridgeLineKind::Obfs4);
    }

    /// PT-U7's native half (§8.2 PT-3): the `nativeValidateBridgeLines` status contract. A
    /// validated line never begins with `bridge_line_` (so Kotlin can distinguish the error
    /// prefix unambiguously), and a refusal names the index, never the line text.
    #[test]
    fn pt3_status_contract() {
        // The prefix itself must not be classifiable as a valid line in any grammar.
        assert!(classify(&s("bridge_line_invalid:3")).is_err());
        assert!(classify(&s("bridge_line_unsupported_transport:1")).is_err());

        let valid = vec![obfs4("0"), s(&format!("192.0.2.10:443 {FP}")), webtunnel()];
        for (index, _) in validate_set(&valid).expect("valid set") {
            assert!(!valid[index].starts_with("bridge_line_"));
        }

        // Snowflake maps to the unsupported-transport category with its own index; the generic
        // malformed line to bridge_line_invalid — both without line text in the reason.
        let mixed = vec![webtunnel(), s("snowflake 192.0.2.10:443")];
        let err = validate_set(&mixed).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.error, BridgeLineError::SnowflakeDeferred);
    }

    /// PT-U5 (§6.2 point 5): the validator is total — seeded random inputs of every shape never
    /// panic and never over-read. Deterministic seed: the assertion set is the *absence* of a
    /// panic; the design pins 10⁶ inputs per CI run.
    #[test]
    fn validator_is_total_over_seeded_random_inputs() {
        // A tiny splitmix64 so the test needs no dependencies and stays deterministic.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let alphabet: &[u8] = b" \t\n=abcz019AZ:/.-cert=iat-modeurlverobfs4webtunnelsnowflakexy";
        for _ in 0..1_000_000 {
            let len = (next() % 128) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(alphabet[(next() as usize) % alphabet.len()]);
            }
            let text = String::from_utf8_lossy(&bytes).into_owned();
            // Must not panic; result is discarded (both outcomes are valid).
            let _ = classify(&text);
            let line: String = text.chars().take(MAX_LINE_LEN).collect();
            let _ = classify(&line);
        }
    }
}
