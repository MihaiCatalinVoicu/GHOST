//! z-base-32 (Zooko's human-oriented base-32), the encoding of the public identity string and of
//! contact card links (FR-1.3, design §3.3).
//!
//! The rules match `android/identity/src/main/kotlin/org/ghost/identity/ZBase32.kt` byte for byte:
//! no padding, ASCII-only case folding on input, a strict alphabet, an exact output length, and
//! trailing bits beyond the last whole byte that must be zero, so one byte string has exactly one
//! spelling.

use crate::result::{DmCode, DmResult};

const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// The number of characters `len` bytes encode to.
pub const fn encoded_len(len: usize) -> usize {
    (len * 8).div_ceil(5)
}

/// Encodes bytes, no padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(data.len()));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn value_of(c: u8) -> Option<u32> {
    let lower = if c.is_ascii_uppercase() { c + 32 } else { c };
    ALPHABET.iter().position(|a| *a == lower).map(|v| v as u32)
}

/// Decodes to exactly `expected_len` bytes. A foreign character, a wrong length or a non-canonical
/// trailing group is [`DmCode::NonCanonical`].
pub fn decode(text: &str, expected_len: usize) -> DmResult<Vec<u8>> {
    if text.len() != encoded_len(expected_len) || !text.is_ascii() {
        return Err(DmCode::NonCanonical);
    }
    let mut out = Vec::with_capacity(expected_len);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in text.as_bytes() {
        // Only ASCII letters fold. Unicode lowercasing would map U+212A KELVIN SIGN to 'k' and
        // accept a second spelling of the same payload.
        let value = value_of(*c).ok_or(DmCode::NonCanonical)?;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out.len() < expected_len {
                out.push(((buffer >> bits) & 0xff) as u8);
            }
        }
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(DmCode::NonCanonical);
    }
    if out.len() != expected_len {
        return Err(DmCode::NonCanonical);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_length_up_to_a_card() {
        for len in 0..=131usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let text = encode(&bytes);
            assert_eq!(text.len(), encoded_len(len));
            assert_eq!(decode(&text, len).expect("decode"), bytes);
        }
    }

    #[test]
    fn a_card_is_two_hundred_and_ten_characters() {
        assert_eq!(encoded_len(131), 210);
    }

    #[test]
    fn upper_case_folds_but_foreign_characters_do_not() {
        let bytes = [1u8, 2, 3, 4, 5];
        let text = encode(&bytes);
        assert_eq!(decode(&text.to_uppercase(), 5).expect("folds"), bytes);
        let mut bad = text.clone();
        bad.replace_range(0..1, "l");
        assert_eq!(decode(&bad, 5), Err(DmCode::NonCanonical));
        assert_eq!(decode("\u{212a}bcdefgh", 5), Err(DmCode::NonCanonical));
    }

    #[test]
    fn non_canonical_trailing_bits_are_refused() {
        // 5 bytes = 40 bits = 8 characters exactly, so use 4 bytes (32 bits, 7 characters, 3
        // trailing bits) and set one of them.
        let bytes = [0u8; 4];
        let text = encode(&bytes);
        assert_eq!(text.len(), 7);
        let mut bad = text.into_bytes();
        bad[6] = ALPHABET[1];
        let bad = String::from_utf8(bad).expect("ascii");
        assert_eq!(decode(&bad, 4), Err(DmCode::NonCanonical));
    }

    #[test]
    fn wrong_length_is_refused() {
        let text = encode(&[0u8; 8]);
        assert_eq!(decode(&text, 7), Err(DmCode::NonCanonical));
        assert_eq!(decode(&text, 9), Err(DmCode::NonCanonical));
    }

    /// §15.2 asks for a seeded property run over every parser. The decoder never panics, never
    /// over-reads and never returns anything but `NON_CANONICAL`; what it accepts re-encodes to
    /// the same characters, which is the "one spelling per byte string" rule.
    #[test]
    fn the_decoder_never_panics_on_seeded_inputs() {
        let mut rng = crate::property::Seeded::new(0x5851_f42d_4c95_7f2d);
        let card = encode(&[0x5a; 131]);
        for _ in 0..crate::property::inputs() {
            // A mutated card link payload, in the alphabet and out of it.
            let mut bytes = card.clone().into_bytes();
            for _ in 0..rng.below(4) + 1 {
                let at = rng.below(bytes.len());
                bytes[at] = match rng.below(4) {
                    0 => rng.byte(),
                    _ => ALPHABET[rng.below(ALPHABET.len())],
                };
            }
            if rng.below(8) == 0 {
                bytes.truncate(rng.below(bytes.len()));
            }
            if let Ok(text) = core::str::from_utf8(&bytes) {
                match decode(text, 131) {
                    Ok(decoded) => assert_eq!(encode(&decoded), text.to_ascii_lowercase()),
                    Err(code) => assert_eq!(code, DmCode::NonCanonical),
                }
            }
            // And a free-form input at a free-form expected length.
            let mut raw = vec![0u8; rng.below(48)];
            rng.fill(&mut raw);
            let text: String = raw.iter().map(|b| char::from(*b)).collect();
            let expected = rng.below(40);
            match decode(&text, expected) {
                Ok(decoded) => assert_eq!(decoded.len(), expected),
                Err(code) => assert_eq!(code, DmCode::NonCanonical),
            }
        }
    }
}
