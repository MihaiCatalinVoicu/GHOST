//! V-10: FailedDecryptLeavesStateTest (design §7.9 point 2, RX-1, mutant MC-29).
//!
//! A responder session whose sending ratchet is still inactive receives a message under an
//! unknown ratchet key that fails authentication. vodozemac activates the inactive ratchet in
//! place before the decryption fails (`double_ratchet.rs:168-191`). Value semantics keep the
//! stored pickle byte-identical and the next valid message decrypts; keeping the live object
//! (the MC-29 misuse) stores the activation.

use ghost_dm_spike::codes::Code;
use ghost_dm_spike::msc3814::DehydratedSecrets;
use ghost_dm_spike::olm::{random_bytes, x25519_public};
use serde_json::Value;

fn ratchet_type(pickle: &[u8]) -> String {
    let v: Value = serde_json::from_slice(pickle).expect("json");
    v.pointer("/sending_ratchet/type")
        .and_then(Value::as_str)
        .expect("type")
        .to_owned()
}

/// A normal Olm message (version 3) under a random, contributory ratchet key with a wrong MAC.
fn forged_normal(chain_index: u8) -> Vec<u8> {
    let mut out = vec![3u8, 0x0A, 0x20];
    out.extend_from_slice(&x25519_public(&random_bytes()));
    out.extend_from_slice(&[0x10, chain_index, 0x22, 16]);
    out.extend_from_slice(&random_bytes::<16>());
    out.extend_from_slice(&random_bytes::<8>());
    out
}

macro_rules! v10_checks {
    ($module:ident, $olm:path) => {
        mod $module {
            use super::*;
            use $olm as olm;

            struct Setup {
                sender: Vec<u8>,
                responder: Vec<u8>,
            }

            fn setup() -> Setup {
                let a = DehydratedSecrets {
                    curve25519: random_bytes(),
                    ed25519_seed: random_bytes(),
                    fallback: None,
                };
                let f: [u8; 32] = random_bytes();
                let b = DehydratedSecrets {
                    curve25519: random_bytes(),
                    ed25519_seed: random_bytes(),
                    fallback: Some(f),
                };
                let (a0, _) =
                    olm::session_outbound(&a, &x25519_public(&b.curve25519), &x25519_public(&f))
                        .expect("outbound");
                let first = olm::encrypt(&a0, b"one").expect("encrypt");
                let inbound = olm::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1)
                    .expect("inbound");
                Setup {
                    sender: first.pickle,
                    responder: inbound.pickle,
                }
            }

            #[test]
            fn failed_decrypt_leaves_stored_state() {
                let s = setup();
                assert_eq!(ratchet_type(&s.responder), "inactive");
                let forged = forged_normal(0);

                // The misuse: the live object after the failure carries an activated ratchet.
                let (outcome, after) =
                    olm::decrypt_keeping_object(&s.responder, &forged, false).expect("loads");
                assert_eq!(outcome.err(), Some(Code::Undecryptable));
                assert_eq!(
                    ratchet_type(&after),
                    "active",
                    "{}: in-place activation not reproduced",
                    olm::VERSION
                );
                assert_ne!(after, s.responder);

                // Value semantics: nothing is returned on failure; the stored bytes stay as they were.
                let stored = s.responder.clone();
                assert_eq!(
                    olm::decrypt(&stored, &forged, false).err(),
                    Some(Code::Undecryptable)
                );
                assert_eq!(stored, s.responder);

                // The next valid message decrypts on the unchanged state.
                let second = olm::encrypt(&s.sender, b"two").expect("encrypt");
                let done = olm::decrypt(&stored, &second.l1, second.is_prekey).expect("decrypts");
                assert_eq!(done.plaintext, b"two");
            }

            /// An active sending ratchet is not changed by a failed decrypt (the activation only
            /// happens for inactive ratchets), and a low-order ratchet key fails before any change.
            #[test]
            fn active_ratchet_and_low_order_key_do_not_mutate() {
                let s = setup();
                let reply = olm::encrypt(&s.responder, b"reply").expect("encrypt");
                assert_eq!(ratchet_type(&reply.pickle), "active");
                let (outcome, after) =
                    olm::decrypt_keeping_object(&reply.pickle, &forged_normal(3), false)
                        .expect("loads");
                assert_eq!(outcome.err(), Some(Code::Undecryptable));
                assert_eq!(after, reply.pickle);

                let mut low_order = forged_normal(0);
                low_order[3..35].copy_from_slice(&[0u8; 32]);
                let (outcome, after) =
                    olm::decrypt_keeping_object(&s.responder, &low_order, false).expect("loads");
                assert_eq!(outcome.err(), Some(Code::Undecryptable));
                assert_eq!(after, s.responder);
            }

            /// Persisting the activated object does not break Olm interop (the peer still
            /// decrypts the responder's reply); the defect is local state drift, which breaks the
            /// byte-identity GHOST's crash enumeration and worlds rely on.
            #[test]
            fn persisted_activation_is_state_drift_not_interop_loss() {
                let s = setup();
                let (_, drifted) =
                    olm::decrypt_keeping_object(&s.responder, &forged_normal(0), false)
                        .expect("loads");
                let reply = olm::encrypt(&drifted, b"reply").expect("encrypt");
                let done =
                    olm::decrypt(&s.sender, &reply.l1, reply.is_prekey).expect("peer decrypts");
                assert_eq!(done.plaintext, b"reply");
            }
        }
    };
}

v10_checks!(vodozemac_0_11_0, ghost_dm_spike::olm::v11);
v10_checks!(vodozemac_0_10_0, ghost_dm_spike::olm::v10);
