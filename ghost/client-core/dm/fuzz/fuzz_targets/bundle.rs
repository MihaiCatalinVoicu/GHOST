//! `dm-fuzz` target `bundle` (Phase 9 design §16.2 `dm-fuzz`, §5, §22.35): the bundle plaintext
//! and its envelope. A bundle is self-signed, so raw bytes stop at strict Ed25519 verification; the
//! re-signed mode signs the fields the input chooses (`bundle::build`) and reaches the rest of the
//! parser, the ML-KEM-768 encapsulation-key check on 1 216 attacker bytes among it; the sealed mode
//! puts attacker bytes inside a valid bundle envelope, so `bundle::open` decrypts them and runs its
//! framing and the parser; the raw-blob mode feeds the envelope header and bucket checks.
#![no_main]

use ghost_client_dm::bundle::{self, BundleFields};
use ghost_client_dm::seal::{self, SealMode, BUCKETS};
use ghost_client_dm::{pq, sign};
use ghost_client_dm_fuzz::{array, fixture, tail};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let f = fixture();
    match mode % 4 {
        0 => {
            if let Ok(parsed) = bundle::parse(rest) {
                assert_eq!(parsed.xwing_public.len(), pq::PUBLIC_KEY_BYTES);
                assert!(pq::validate_public_key(&parsed.xwing_public).is_ok());
            }
        }
        1 => {
            let seed = array::<32>(rest, 0);
            let card_index = u16::from_be_bytes(array::<2>(rest, 32));
            let bundle_week = u64::from_be_bytes(array::<8>(rest, 34));
            let bundle_rank = u16::from_be_bytes(array::<2>(rest, 42));
            let gen_id = u32::from_be_bytes(array::<4>(rest, 44));
            let olm_identity = array::<32>(rest, 48);
            let fallback_key = array::<32>(rest, 80);
            let xwing_public = array::<{ pq::PUBLIC_KEY_BYTES }>(rest, 112);
            let fields = BundleFields {
                card_index,
                bundle_week,
                bundle_rank,
                gen_id,
                olm_identity: &olm_identity,
                fallback_key: &fallback_key,
                xwing_public: &xwing_public,
            };
            let plain = bundle::build(&seed, &fields).expect("a 1 216-byte X-Wing key builds");
            match bundle::parse(&plain) {
                Ok(parsed) => {
                    assert_eq!(parsed.card_index, card_index);
                    assert_eq!(parsed.bundle_week, bundle_week);
                    assert_eq!(parsed.bundle_rank, bundle_rank);
                    assert_eq!(parsed.gen_id, gen_id);
                    assert_eq!(parsed.olm_identity, olm_identity);
                    assert_eq!(parsed.fallback_key, fallback_key);
                    assert_eq!(&parsed.xwing_public[..], &xwing_public[..]);
                    assert_eq!(parsed.identity_pk, sign::public_key(&seed));
                }
                // Signed by its own key, a built bundle is refused for exactly three reasons: its X-Wing
                // key, or the Olm identity or the fallback key not being a canonical X25519 encoding
                // (the phase review's CRY-P9-01: a non-canonical key made every sealIntro to the
                // contact answer NON_CANONICAL). The property stated only the first of them, so every
                // nightly run since that fix failed on a one-bit input.
                Err(_) => assert!(
                    pq::validate_public_key(&xwing_public).is_err()
                        || !pq::canonical_u_coordinate(&olm_identity)
                        || !pq::canonical_u_coordinate(&fallback_key)
                ),
            }
        }
        2 => {
            // A bundle envelope around attacker bytes: the first byte is the plaintext's mode byte
            // (R-S2), the rest the body `open_bundle` frames and `bundle::parse` reads.
            let first = rest.first().copied().unwrap_or(SealMode::Bundle.as_u8());
            let Some(blob) = f.seal_envelope(
                &f.card_seal_key(),
                BUCKETS[0],
                SealMode::Bundle,
                first,
                &[0u8; 32],
                tail(rest, 1),
            ) else {
                return;
            };
            let _ = bundle::open(&f.card_seal_key(), &f.namespace, &blob, &f.recipient_pk, 0);
        }
        _ => {
            let _ = bundle::open(&f.card_seal_key(), &f.namespace, rest, &f.recipient_pk, 0);
            let _ = seal::hint_matches(rest, &seal::recognition_key(&f.card_seal_key()));
        }
    }
});
