//! V-15: the skipped-key age bound (design §7.7 point 4, Q67, RG-6, R-41, MC-30).
//!
//! No public API of either pin drops message keys; the pinned-schema edit of the JSON pickle
//! does, and both pins share the edited layout, so golden pickles and an UpgradeTest drill can
//! cover it.

use ghost_dm_spike::codes::Code;
use ghost_dm_spike::msc3814::DehydratedSecrets;
use ghost_dm_spike::olm::{random_bytes, x25519_public};
use ghost_dm_spike::prune::{self, SkippedKey};
use std::collections::HashMap;

/// First-seen day of every skipped key, maintained beside the pickle (GHOST state).
type Days = HashMap<SkippedKey, u32>;

const FRESH_PLUS_2SIGMA_DAYS: u32 = 45 + 6;

macro_rules! v15_checks {
    ($module:ident, $olm:path) => {
        mod $module {
            use super::*;
            use $olm as olm;

            /// A sender chain of `n` messages and the recipient's session after the first.
            fn chain(n: usize) -> (Vec<u8>, Vec<(Vec<u8>, bool)>) {
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
                let (mut a_state, _) =
                    olm::session_outbound(&a, &x25519_public(&b.curve25519), &x25519_public(&f))
                        .expect("outbound");
                let first = olm::encrypt(&a_state, b"m0").expect("encrypt");
                a_state = first.pickle;
                let b_state = olm::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1)
                    .expect("inbound")
                    .pickle;
                let mut out = Vec::new();
                for i in 1..n {
                    let m = olm::encrypt(&a_state, format!("m{i}").as_bytes()).expect("encrypt");
                    a_state = m.pickle;
                    out.push((m.l1, m.is_prekey));
                }
                (b_state, out)
            }

            fn decrypt_tracking(
                state: &[u8],
                msg: &(Vec<u8>, bool),
                today: u32,
                days: &mut Days,
            ) -> Result<Vec<u8>, Code> {
                let done = olm::decrypt(state, &msg.0, msg.1)?;
                for key in prune::added_keys(state, &done.pickle)? {
                    days.insert(key, today);
                }
                Ok(done.pickle)
            }

            #[test]
            fn prune_by_first_seen_day() {
                let (mut state, msgs) = chain(12);
                let mut days = Days::new();
                // Day 100: message index 5 arrives first (keys 1..4 skipped).
                state = decrypt_tracking(&state, &msgs[4], 100, &mut days).expect("m5");
                // Day 130: index 10 arrives (keys 6..9 skipped).
                state = decrypt_tracking(&state, &msgs[9], 130, &mut days).expect("m10");
                assert_eq!(prune::skipped_keys(&state).expect("keys").len(), 8);
                assert_eq!(days.values().filter(|&&d| d == 100).count(), 4);

                // Sweep on day 152: keys first seen on day 100 are older than FRESH + 2σ.
                let today = 152;
                let (pruned, removed) = prune::prune(&state, |k| {
                    days.get(k)
                        .is_some_and(|d| today >= d + FRESH_PLUS_2SIGMA_DAYS)
                })
                .expect("prune");
                assert_eq!(removed, 4);
                // A pruned key's message is gone; a kept one decrypts; the chain continues.
                assert_eq!(
                    olm::decrypt(&pruned, &msgs[1].0, msgs[1].1).err(),
                    Some(Code::DuplicateOrLost)
                );
                let kept = olm::decrypt(&pruned, &msgs[6].0, msgs[6].1).expect("m7 kept");
                assert_eq!(kept.plaintext, b"m7");
                let next = olm::decrypt(&kept.pickle, &msgs[10].0, msgs[10].1).expect("m11");
                assert_eq!(next.plaintext, b"m11");
                // Without pruning the old key still opens its message (the exception Q67 removes).
                assert_eq!(
                    olm::decrypt(&state, &msgs[1].0, msgs[1].1)
                        .expect("m2")
                        .plaintext,
                    b"m2"
                );
            }

            /// Pruning keeps FIFO order: after the edit, the next 40 skipped keys still evict the
            /// oldest remaining entries first.
            #[test]
            fn prune_keeps_fifo_order() {
                let (mut state, msgs) = chain(60);
                state = olm::decrypt(&state, &msgs[20].0, msgs[20].1)
                    .expect("m21")
                    .pickle; // skips 1..20
                let (edited, removed) = prune::prune(&state, |k| k.index % 2 == 1).expect("prune");
                assert_eq!(removed, 10);
                let before: Vec<u64> = prune::skipped_keys(&edited)
                    .expect("keys")
                    .iter()
                    .map(|k| k.index)
                    .collect();
                let mid = olm::decrypt(&edited, &msgs[48].0, msgs[48].1)
                    .expect("m49")
                    .pickle; // skips 22..48
                let kept: Vec<u64> = prune::skipped_keys(&mid)
                    .expect("keys")
                    .iter()
                    .map(|k| k.index)
                    .collect();
                // 10 kept even keys + 27 new keys = 37 <= 40: nothing evicted, order preserved.
                assert_eq!(kept.len(), 37);
                assert_eq!(&kept[..before.len()], before.as_slice());
                // 9 more skipped keys (50..58) overflow the 40-key store: the 6 oldest go first.
                let late = olm::decrypt(&mid, &msgs[58].0, msgs[58].1)
                    .expect("m59")
                    .pickle;
                let last: Vec<u64> = prune::skipped_keys(&late)
                    .expect("keys")
                    .iter()
                    .map(|k| k.index)
                    .collect();
                let mut expected: Vec<u64> = (14..=20).step_by(2).collect();
                expected.extend(22..=48);
                expected.extend(50..=58);
                assert_eq!(last, expected);
            }
        }
    };
}

v15_checks!(vodozemac_0_11_0, ghost_dm_spike::olm::v11);
v15_checks!(vodozemac_0_10_0, ghost_dm_spike::olm::v10);

/// UpgradeTest drill: a pickle pruned under 0.10.0 loads and continues under 0.11.0.
#[test]
fn pruned_pickle_upgrades() {
    use ghost_dm_spike::olm::{v10, v11};
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
    let (mut a_state, _) =
        v10::session_outbound(&a, &x25519_public(&b.curve25519), &x25519_public(&f))
            .expect("outbound");
    let first = v10::encrypt(&a_state, b"0").expect("encrypt");
    a_state = first.pickle;
    let mut b_state = v10::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1)
        .expect("inbound")
        .pickle;
    let mut msgs = Vec::new();
    for i in 1..8 {
        let m = v10::encrypt(&a_state, format!("{i}").as_bytes()).expect("encrypt");
        a_state = m.pickle.clone();
        msgs.push(m);
    }
    b_state = v10::decrypt(&b_state, &msgs[5].l1, msgs[5].is_prekey)
        .expect("6")
        .pickle;
    let (pruned, removed) = prune::prune(&b_state, |k| k.index <= 2).expect("prune");
    assert_eq!(removed, 2);
    assert_eq!(
        v11::decrypt(&pruned, &msgs[0].l1, msgs[0].is_prekey).err(),
        Some(Code::DuplicateOrLost)
    );
    assert_eq!(
        v11::decrypt(&pruned, &msgs[3].l1, msgs[3].is_prekey)
            .expect("4 under 0.11.0")
            .plaintext,
        b"4"
    );
    // The sender continues under 0.11.0 too.
    let m = v11::encrypt(&a_state, b"8").expect("encrypt under 0.11.0");
    assert_eq!(
        v11::decrypt(&pruned, &m.l1, m.is_prekey)
            .expect("8")
            .plaintext,
        b"8"
    );
}
