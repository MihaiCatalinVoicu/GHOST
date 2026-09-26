//! `dm-fuzz` target `card` (Phase 9 design §16.2 `dm-fuzz`, §3.3, §22.35): contact card v2 bytes,
//! card links and z-base-32, raw and re-signed. A card is self-signed, so raw bytes reach the
//! length, version and index checks and strict Ed25519 verification under a key the input names;
//! the re-signed mode signs what the input chooses, as `card::build` does, so the parser's
//! success path runs too.
#![no_main]

use ghost_client_dm::derive::CardSecret;
use ghost_client_dm::{card, zbase32};
use ghost_client_dm_fuzz::array;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            if let Ok(parsed) = card::parse(rest) {
                assert_eq!(
                    &parsed.encode()[..],
                    rest,
                    "a card that parses re-encodes to its bytes"
                );
                assert!(card::parse_foreign(rest, &parsed.identity_pk).is_err());
                let again = card::parse_link(&parsed.link()).expect("a parsed card's link parses");
                assert_eq!(again.encode(), parsed.encode());
            }
        }
        1 => {
            // Any UTF-8 as a link, then as z-base-32 of every length a byte can name: one byte
            // string has one spelling up to ASCII case (zbase32.rs).
            let Ok(text) = core::str::from_utf8(tail(rest)) else {
                return;
            };
            if let Ok(parsed) = card::parse_link(text) {
                assert_eq!(
                    parsed.link(),
                    text.to_ascii_lowercase(),
                    "a link that parses is canonical"
                );
            }
            let expected_len = usize::from(rest.first().copied().unwrap_or(0));
            if let Ok(bytes) = zbase32::decode(text, expected_len) {
                assert_eq!(bytes.len(), expected_len);
                assert_eq!(
                    zbase32::encode(&bytes),
                    text.to_ascii_lowercase(),
                    "z-base-32 is canonical"
                );
            }
        }
        _ => {
            let seed = array::<32>(rest, 0);
            let index = u16::from_be_bytes(array::<2>(rest, 32));
            let secret = array::<32>(rest, 34);
            let built = card::build(&seed, index, &CardSecret::from_bytes(secret)).encode();
            match card::parse(&built) {
                Ok(parsed) => {
                    assert_eq!(parsed.card_index, index);
                    assert_eq!(parsed.card_secret.as_bytes(), &secret);
                    assert_eq!(parsed.encode(), built);
                }
                // Phase 9 issues card index 0 only (§3.3): every other index is refused.
                Err(_) => assert_ne!(
                    index, 0,
                    "a card index 0 that `card::build` signed must parse"
                ),
            }
        }
    }
});

fn tail(rest: &[u8]) -> &[u8] {
    rest.get(1..).unwrap_or(&[])
}
