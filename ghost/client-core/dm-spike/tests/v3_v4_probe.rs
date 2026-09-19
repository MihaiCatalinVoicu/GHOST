//! V-3 and V-4: the measurement probe (design RG-8, §6.6, §7.9 point 4).
//!
//! Run with `cargo test --release --test v3_v4_probe -- --nocapture`; the tests assert the
//! bounds and print the measured values the evidence records.

use ghost_dm_spike::pickle_bound;
use ghost_dm_spike::sizes::{self, fixed};
use ghost_dm_spike::xwing;

/// The provisional O_MAX of §6.6; the probe checks every measured output fits under it.
const O_MAX_PROVISIONAL: usize = 1664;
const SESSION_STATE_MAX: usize = 65_536;

/// Chain indices at every protobuf varint length (1 … 10 bytes) and the largest usable index.
const INDICES: [u64; 12] = [
    0,
    127,
    128,
    1 << 14,
    1 << 21,
    1 << 28,
    1 << 35,
    1 << 42,
    1 << 49,
    1 << 56,
    1 << 63,
    u64::MAX - 1,
];

fn lengths() -> Vec<usize> {
    let mut out: Vec<usize> = (0..=64).collect();
    for bucket in fixed::BUCKETS {
        let capacity = bucket - O_MAX_PROVISIONAL;
        out.extend(capacity - 64..=capacity);
    }
    out
}

macro_rules! probe {
    ($module:ident, $sizes:path, $bound:path, $label:literal) => {
        mod $module {
            use super::*;
            use $bound as bound;
            use $sizes as measure;

            #[test]
            fn v3_olm_overheads() {
                let pair = measure::pair().expect("session pair");
                let mut max_prekey = [0usize; 3];
                let mut max_normal = [0usize; 3];
                let mut max_prekey_small_index = [0usize; 3];
                let mut max_normal_small_index = [0usize; 3];
                let mut rows = 0;
                for len in lengths() {
                    let class = fixed::BUCKETS.iter().position(|b| len <= b - O_MAX_PROVISIONAL).expect("class");
                    for index in INDICES {
                        let o = measure::overhead(&pair, len, index).expect("measure");
                        max_prekey[class] = max_prekey[class].max(o.prekey);
                        max_normal[class] = max_normal[class].max(o.normal);
                        if index < (1 << 28) {
                            max_prekey_small_index[class] = max_prekey_small_index[class].max(o.prekey);
                            max_normal_small_index[class] = max_normal_small_index[class].max(o.normal);
                        }
                        rows += 1;
                    }
                }
                let ct = xwing::CIPHERTEXT_LEN;
                let intro_total = fixed::L2_OUTER + fixed::intro(ct) + max_prekey.iter().max().copied().unwrap_or(0);
                let symmetric_total = fixed::L2_OUTER + fixed::SYMMETRIC_BODY + max_normal.iter().max().copied().unwrap_or(0);
                println!("V3 {} measured outputs: {}", $label, rows);
                for (i, bucket) in fixed::BUCKETS.iter().enumerate() {
                    println!(
                        "V3 {} bucket {:>5}: prekey max {} (index < 2^28: {}), normal max {} (index < 2^28: {})",
                        $label, bucket, max_prekey[i], max_prekey_small_index[i], max_normal[i], max_normal_small_index[i]
                    );
                }
                println!("V3 {} intro fixed part {} (xwing ct {}), L2 outer {}", $label, fixed::intro(ct), ct, fixed::L2_OUTER);
                println!("V3 {} worst intro PreKey total {}, worst pair/provisional total {}", $label, intro_total, symmetric_total);
                assert!(intro_total <= O_MAX_PROVISIONAL);
                assert!(symmetric_total <= O_MAX_PROVISIONAL);
                // Every body length of each class fits after sealing (golden sizes at the class edge).
                for (i, bucket) in fixed::BUCKETS.iter().enumerate() {
                    let body_capacity = bucket - O_MAX_PROVISIONAL - fixed::L0_FIXED - fixed::EXT_RESERVE;
                    let l0 = fixed::L0_FIXED + body_capacity + fixed::EXT_RESERVE;
                    assert!(fixed::L2_OUTER + fixed::intro(ct) + l0 + max_prekey[i] <= *bucket);
                    assert!(fixed::L2_OUTER + fixed::SYMMETRIC_BODY + l0 + max_normal[i] <= *bucket);
                    println!("V3 {} bucket {:>5}: body capacity {} (L0 {}), slack intro {}, slack pair {}",
                        $label, bucket, body_capacity, l0,
                        bucket - (fixed::L2_OUTER + fixed::intro(ct) + l0 + max_prekey[i]),
                        bucket - (fixed::L2_OUTER + fixed::SYMMETRIC_BODY + l0 + max_normal[i]));
                }
            }

            #[test]
            fn v4_worst_case_pickle() {
                let driven = bound::drive().expect("drive");
                let shape = pickle_bound::shape(&driven).expect("shape");
                println!("V4 {} driven shape {:?}, driven JSON {} B", $label, shape, driven.len());
                assert_eq!(shape.receiver_chains, 5);
                assert_eq!(shape.skipped_keys_per_chain, [40; 5]);
                assert!(shape.sending_active && shape.parent_key_present);
                let widened = pickle_bound::widened(&driven).expect("widen");
                assert!(bound::loads_unchanged(&widened).expect("loads"), "widened pickle does not round-trip");
                let analytic = pickle_bound::analytic_bound(true);
                println!(
                    "V4 {} widened JSON {} B (analytic {} B), SESSION_STATE_MAX {} B, margin {} B ({:.1} %)",
                    $label,
                    widened.len(),
                    analytic,
                    SESSION_STATE_MAX,
                    SESSION_STATE_MAX - widened.len(),
                    100.0 * (SESSION_STATE_MAX - widened.len()) as f64 / SESSION_STATE_MAX as f64
                );
                assert_eq!(widened.len(), analytic);
                assert!(widened.len() < SESSION_STATE_MAX);
            }
        }
    };
}

probe!(
    vodozemac_0_11_0,
    ghost_dm_spike::sizes::v11,
    ghost_dm_spike::pickle_bound::v11,
    "0.11.0"
);
probe!(
    vodozemac_0_10_0,
    ghost_dm_spike::sizes::v10,
    ghost_dm_spike::pickle_bound::v10,
    "0.10.0"
);

/// The pickle of 0.10.0 loads in 0.11.0 (the UpgradeTest direction) with the same bytes.
#[test]
fn v4_pickle_layout_is_shared() {
    let driven = ghost_dm_spike::pickle_bound::v10::drive().expect("drive");
    let upgraded = ghost_dm_spike::olm::v11::load(&driven).expect("0.11.0 loads a 0.10.0 pickle");
    assert_eq!(
        ghost_dm_spike::olm::v11::store(&upgraded).expect("store"),
        driven
    );
    let _ = sizes::set_sending_index;
}
