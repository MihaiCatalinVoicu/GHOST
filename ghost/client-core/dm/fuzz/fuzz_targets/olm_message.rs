//! `dm-fuzz` target `olm_message` (Phase 9 design §16.2 `dm-fuzz`, §2.2, §6.5, §22.35): Olm message
//! parsing — vodozemac's decoding of normal and PreKey messages and GHOST's canonical-key checks
//! (`olm::message`) on raw bytes, and the same L1 inside a pair or provisional envelope an attacker
//! contact holds the key of, so `open_symmetric` decrypts it and runs its framing (kind, length,
//! zero padding) before the parse.
#![no_main]

use ghost_client_dm::olm::message;
use ghost_client_dm::seal::{self, SealMode};
use ghost_client_dm_fuzz::{bucket, fixture, tail};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 | 1 => {
            let is_pre_key = mode % 4 == 1;
            let parsed = message::parse(rest, is_pre_key);
            assert_eq!(parsed.is_ok(), message::decode(rest, is_pre_key).is_ok());
            if let Ok(header) = parsed {
                assert_eq!(header.is_pre_key(), is_pre_key);
                assert_eq!(message::decode_pre_key(rest).is_ok(), is_pre_key);
            }
        }
        _ => {
            let f = fixture();
            let mode_used = if mode % 4 == 2 {
                SealMode::Pair
            } else {
                SealMode::Provisional
            };
            let first = rest.first().copied().unwrap_or(mode_used.as_u8());
            let Some(blob) = f.seal_envelope(
                &f.pair_seal_key(),
                bucket(mode >> 2),
                mode_used,
                first,
                &seal::pair_ad(&f.oi_sender, &f.oi_recipient),
                tail(rest, 1),
            ) else {
                return;
            };
            let opened = seal::open_symmetric(
                &f.pair_seal_key(),
                &f.namespace,
                mode_used,
                &f.oi_sender,
                &f.oi_recipient,
                &blob,
            );
            if let Ok(l1) = opened {
                let _ = message::parse(&l1, false);
                let _ = message::parse(&l1, true);
            }
        }
    }
});
