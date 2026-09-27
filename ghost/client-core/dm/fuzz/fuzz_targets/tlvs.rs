//! `dm-fuzz` target `tlvs` (Phase 9 design §16.2 `dm-fuzz`, §7.1 TLV registry, §22.35): the TLV
//! values the receive path decodes — `SEAL_ROOT`, `SEAL_ROOT_PQ` (and the decapsulation of its
//! attacker ciphertext, `pqroot::open`), `PQ_KEY` (the ML-KEM-768 key check on attacker bytes) and
//! the revocation certificate, raw and re-signed — and the TLV list of a control L0 (ascending
//! types, registry lengths, the critical bit, the receiving cap). A value that decodes re-encodes
//! to its own bytes.
#![no_main]

use ghost_client_dm::codec::{self, PqKey, SealRoot, SealRootPq};
use ghost_client_dm::pqroot::{self, PqRootParties};
use ghost_client_dm::{revocation, sign};
use ghost_client_dm_fuzz::{array, fixture, tail};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let f = fixture();
    match mode % 6 {
        0 => {
            if let Ok(root) = SealRoot::decode(rest) {
                assert_eq!(root.encode(), rest);
            }
        }
        1 => {
            if let Ok(root) = SealRootPq::decode(rest) {
                assert_eq!(
                    root.encode().expect("a decoded SEAL_ROOT_PQ re-encodes"),
                    rest
                );
                let parties = PqRootParties {
                    oi_offerer: &f.oi_sender,
                    oi_target: &f.oi_recipient,
                };
                let _ = pqroot::open(&root, f.gen_id, &f.gen_seed, parties);
            }
        }
        2 => {
            if let Ok(key) = PqKey::decode(rest) {
                assert_eq!(key.encode().expect("a decoded PQ_KEY re-encodes"), rest);
            }
        }
        3 => {
            let _ = revocation::verify(rest, None);
            let _ = revocation::verify(rest, Some(&f.recipient_pk));
        }
        4 => {
            let seed = array::<32>(rest, 0);
            let minute = u32::from_be_bytes(array::<4>(rest, 32));
            let reason = array::<1>(rest, 36)[0];
            if let Ok(certificate) = revocation::issue(&seed, minute, reason) {
                revocation::verify(&certificate, Some(&sign::public_key(&seed)))
                    .expect("a certificate `issue` signed verifies");
            }
        }
        _ => {
            // A control L0 around attacker TLV bytes: version, kind 4, message id, minute and
            // index, no timer, no quote, an empty body, then `ext_len || ext`.
            let ext = tail(rest, 0);
            let Ok(ext_len) = u16::try_from(ext.len()) else {
                return;
            };
            let mut l0 = vec![codec::CONTENT_VERSION, 0x04];
            l0.extend_from_slice(&[0x61; 16]);
            l0.extend_from_slice(&1000u32.to_be_bytes());
            l0.extend_from_slice(&0u16.to_be_bytes());
            l0.push(0);
            l0.extend_from_slice(&0u32.to_be_bytes());
            l0.push(0);
            l0.extend_from_slice(&0u32.to_be_bytes());
            l0.extend_from_slice(&ext_len.to_be_bytes());
            l0.extend_from_slice(ext);
            if let Ok(content) = codec::decode(&l0) {
                if let Ok(encoded) = content.encode() {
                    assert_eq!(
                        encoded, l0,
                        "a control L0 that decodes and re-encodes is its own bytes"
                    );
                }
            }
        }
    }
});
