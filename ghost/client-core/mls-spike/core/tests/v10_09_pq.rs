//! V10-9 (evidence for Q2 only): OpenMLS's post-quantum suites with the libcrux provider —
//! 0x004D (OpenMLS's X-Wing code point), 0x004F and 0x004E (the WG draft's provisional TBD1 and
//! TBD2) — whether the provider accepts them, whether a group works end to end, and GHOST-shaped
//! sizes at 20 and 32 members against the class floors. Build with `--features pq`.
//!
//! Run: `cargo test --release -p ghost-mls-spike --features pq --test v10_09_pq -- --nocapture --test-threads=1`

use std::sync::atomic::Ordering;

use ghost_mls_spike::ext::{AdmitEvidence, CommitAad};
use ghost_mls_spike::harness::*;
use ghost_mls_spike::seal;
use openmls::prelude::*;
use openmls_traits::crypto::OpenMlsCrypto;

fn probe_suite(code: u16) -> Vec<(usize, usize, bool)> {
    let s = Ciphersuite::try_from(code).expect("suite known with the pq feature");
    let crypto = openmls_libcrux_crypto::CryptoProvider::new().unwrap();
    let listed = crypto.supported_ciphersuites().contains(&s);
    let supports = crypto.supports(s);
    // All three code points name the same HPKE KEM in openmls_traits 0.6.0 (types.rs:788-794),
    // and the provider's `supports()` checks the AEAD, signature and hash, never the KEM
    // (crypto.rs:64-86): "supported" and "works" below are one implementation with itself.
    println!(
        "V10-9 suite 0x{code:04x} {s:?}: HPKE KEM {:?}; listed by the provider {listed}, supports() -> {supports:?}",
        s.hpke_kem_algorithm()
    );
    assert_eq!(s.hpke_kem_algorithm(), HpkeKemType::XWingKemDraft6);
    let mut results = Vec::new();
    if supports.is_err() {
        return results;
    }
    SUITE_OVERRIDE.store(code, Ordering::Relaxed);
    let day = host_day();
    for n in [20usize, 32] {
        let r = std::panic::catch_unwind(|| {
            let mut w = World::build(n, n - 1, day);
            let ch = w.channel;
            let e = w.members[0].epoch(ch);
            let mut j = Device::new(900, day);
            let kp_bytes = j.key_package(ch, 1, day, 0).unwrap();
            let kp = w.members[0].parse_key_package(&kp_bytes).unwrap();
            let r = kp
                .hash_ref(&w.members[0].crypto)
                .unwrap()
                .as_slice()
                .to_vec();
            let far = w.members[n - 1].leaf_index(ch);
            let base = CommitSpec {
                aad: CommitAad {
                    commit_minute: day * 1440,
                    ..Default::default()
                },
                refresh_epoch: Some(e),
                force_path: true,
                no_exported_group_info: true,
                ..Default::default()
            };
            let mut sizes = Vec::new();
            for (tag, spec) in [
                ("PCS self-update", base.clone()),
                (
                    "Remove 1",
                    CommitSpec {
                        removes: vec![LeafNodeIndex::new(far)],
                        ..base.clone()
                    },
                ),
                (
                    "Add 1 + evidence",
                    CommitSpec {
                        adds: vec![kp.clone()],
                        aad: CommitAad {
                            commit_minute: day * 1440,
                            admits: vec![AdmitEvidence::filler(r.clone())],
                            ..Default::default()
                        },
                        ..base.clone()
                    },
                ),
            ] {
                let saved = w.members[0].rows.clone();
                let out = w.members[0].commit(ch, &spec).unwrap();
                w.members[0].rows = saved;
                let valid = w.members[1].validate(ch, &out.commit).map(|_| ());
                sizes.push(format!(
                    "{tag} {} B (bucket small {} / large {}){} valid {:?}",
                    out.commit.len(),
                    seal::bucket(out.commit.len(), 0).map_or("NO_FIT".into(), |b| b.to_string()),
                    seal::bucket(out.commit.len(), 1).map_or("NO_FIT".into(), |b| b.to_string()),
                    out.welcome
                        .as_ref()
                        .map_or(String::new(), |x| format!(", Welcome {} B", x.len())),
                    valid.is_ok()
                ));
            }
            // End to end: a post and its decryption after merging a self-update.
            w.self_update(n - 1).unwrap();
            let m = w.members[1].encrypt(ch, 1, b"pq post").unwrap();
            let got = w.members[0].receive(ch, &m).unwrap().plaintext;
            (
                kp_bytes.len(),
                sizes,
                got == b"pq post" && w.authenticators_agree(),
            )
        });
        match r {
            Ok((kp, sizes, e2e)) => {
                println!(
                    "V10-9 0x{code:04x} n={n}: KeyPackage {kp} B; {}; end to end {e2e}",
                    sizes.join("; ")
                );
                results.push((n, kp, e2e));
            }
            Err(_) => println!("V10-9 0x{code:04x} n={n}: PANICKED (see output above)"),
        }
    }
    SUITE_OVERRIDE.store(0, Ordering::Relaxed);
    results
}

#[test]
fn v10_09_pq_suites_with_libcrux() {
    for code in [0x004Du16, 0x004F, 0x004E] {
        let r = probe_suite(code);
        // Both member counts ran end to end, with the 2 765-byte X-Wing KeyPackage.
        assert_eq!(r.len(), 2, "0x{code:04x}");
        for (n, kp, e2e) in r {
            assert!(e2e, "0x{code:04x} n={n}");
            assert_eq!(kp, 2765, "0x{code:04x}");
        }
    }
}
