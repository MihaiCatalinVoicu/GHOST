//! `dm-fuzz` target `l0` (Phase 9 design §16.2 `dm-fuzz`, §7.1, R-C4, §22.35): `DmContent` v1
//! decoding, fail closed. Content is attacker-chosen inside a pair envelope its sender holds the key
//! of, so the bytes go to `codec::decode` directly. A record that decodes and re-encodes must be
//! its own bytes: one content, one encoding (a record `encode` refuses — the sender cap of
//! §21.11 point 3 — is not compared).
#![no_main]

use ghost_client_dm::{codec, seal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = codec::decode(data) {
        if let Ok(encoded) = content.encode() {
            assert_eq!(
                encoded, data,
                "an L0 that decodes and re-encodes is its own bytes"
            );
        }
        let _ = content.bucket();
        let _ = seal::bucket_for_body(content.body.len());
    }
});
