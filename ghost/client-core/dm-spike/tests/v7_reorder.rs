//! V-7: reorder loss with Olm's 40-skipped-keys window in seeded worlds (design §7.7, Q54).
//!
//! `cargo test --release --test v7_reorder -- --nocapture` prints one line per configuration:
//! worlds, messages, lost (real vodozemac), lost predicted by the rule model, worlds with a loss,
//! blobs held, the largest display delay.

use ghost_dm_spike::codes::Code;
use ghost_dm_spike::olm::v11 as olm;
use ghost_dm_spike::reorder::{self, Mode, Policy, Recipient, Withholding, World};

const WORLDS: u64 = 200;
const MESSAGES: usize = 60;

#[test]
fn rule_model_matches_known_orders() {
    // In order: nothing lost.
    assert!(reorder::predict_losses(&(0..60).collect::<Vec<_>>())
        .iter()
        .all(|l| !l));
    // Index 41 first: key 0 is 41 behind and never stored; keys 1..40 are.
    let lost = reorder::predict_losses(&[41, 0, 1, 40]);
    assert_eq!(lost, vec![false, true, false, false]);
    // 45 keys skipped in two steps: the 5 oldest are evicted (FIFO) although no single jump > 40.
    let lost = reorder::predict_losses(&[20, 46, 0, 5, 19, 21]);
    assert_eq!(lost, vec![false, false, true, false, false, false]);
}

/// The measured hold is time-bounded, not once per blob: while the gap persists, the same blob is
/// left `fetched` again on every consumer pass until `first_seen + HOLD_MAX`. `held_blobs` counts
/// each blob once, `hold_events` counts every pass that held one, so a rule applied "at most once
/// per blob per process" would make the two equal. This pins the rule the zero-loss rows were
/// measured under (design §7.7 point 2).
#[test]
fn hold_is_re_applied_on_every_pass() {
    let burst = reorder::burst(MESSAGES).expect("burst");
    let world = |policy, fresh_process_per_pass, seed| World {
        messages: MESSAGES,
        mode: Mode::High,
        withholding: Withholding::OneLate,
        recipient: Recipient::Offline,
        policy,
        fresh_process_per_pass,
        seed,
    };
    let mut multi_pass_worlds = 0;
    for seed in 1..=20 {
        let r = reorder::run(&world(Policy::PeekHoldSession, false, seed), &burst).expect("world");
        assert!(
            r.hold_events >= r.held_blobs,
            "a held blob is counted once, so events cannot be fewer ({r:?})"
        );
        multi_pass_worlds += usize::from(r.hold_events > r.held_blobs);
        // A fresh process per pass reads the expected index from the stored session, so the hold
        // survives the restart and still spans passes.
        let fresh = reorder::run(&world(Policy::PeekHoldSession, true, seed), &burst).expect("f");
        assert_eq!(fresh.lost, 0, "session hold loses nothing across restarts");
    }
    assert_eq!(
        multi_pass_worlds, 20,
        "every world held at least one blob on more than one pass"
    );
    // The policies without a hold never hold.
    for policy in [Policy::ClaimOrder, Policy::Peek] {
        let r = reorder::run(&world(policy, false, 1), &burst).expect("world");
        assert_eq!((r.held_blobs, r.hold_events), (0, 0));
    }
}

/// `chainPosition` reads vodozemac's serde pickle layout, which is not part of its public API
/// (design §2.1/ADR-35 "public API only"; the deviation is recorded in the evidence document).
/// A renamed field must therefore be loud: returning "new chain" would silently disable the hold
/// and bring V-7's offline-burst loss back with no result code.
#[test]
fn chain_position_refuses_a_drifted_layout() {
    let burst = reorder::burst(3).expect("burst");
    let after = olm::decrypt(&burst.recipient_pickle, &burst.l1[0], false)
        .expect("first message")
        .pickle;
    assert_eq!(
        reorder::chain_next_index(&after, &burst.ratchet_key).expect("position"),
        1,
        "one message decrypted on the chain"
    );
    // An unknown but well-formed chain key is a new chain, not a drift.
    assert_eq!(
        reorder::chain_next_index(&after, &[7u8; 32]).expect("new chain"),
        0
    );
    // A bump that renames the field (serde derives the name from the private struct member) must
    // fail with STATE_CORRUPT, not report every chain as new.
    let mut value: serde_json::Value = serde_json::from_slice(&after).expect("json");
    for chain in value
        .pointer_mut("/receiving_chains/inner")
        .and_then(serde_json::Value::as_array_mut)
        .expect("chains")
    {
        let key = chain.get("ratchet_key").expect("ratchet_key").clone();
        let object = chain.as_object_mut().expect("chain object");
        object.remove("ratchet_key");
        object.insert("ratchet_key_v2".to_owned(), key);
    }
    let drifted = serde_json::to_vec(&value).expect("re-encode");
    assert_eq!(
        reorder::chain_next_index(&drifted, &burst.ratchet_key).err(),
        Some(Code::StateCorrupt),
        "a renamed ratchet_key field must not read as a new chain"
    );
    // The burst's own chain does not exist before its first message: index 0.
    assert_eq!(
        reorder::chain_next_index(&burst.recipient_pickle, &burst.ratchet_key).expect("new chain"),
        0
    );
}

#[test]
fn reorder_loss_worlds() {
    let burst = reorder::burst(MESSAGES).expect("burst");
    let mut any_mismatch = false;
    for mode in [Mode::Standard, Mode::High] {
        for recipient in [Recipient::Online, Recipient::Offline] {
            for withholding in [
                Withholding::None,
                Withholding::OneNever,
                Withholding::OneLate,
            ] {
                for (policy, fresh_process_per_pass) in [
                    (Policy::ClaimOrder, false),
                    (Policy::Peek, false),
                    (Policy::PeekHold, false),
                    (Policy::PeekHold, true),
                    (Policy::PeekHoldSession, false),
                    (Policy::PeekHoldSession, true),
                ] {
                    let mut lost = 0;
                    let mut predicted = 0;
                    let mut worlds_with_loss = 0;
                    let mut held = 0;
                    let mut hold_events = 0;
                    let mut max_delay = 0;
                    let mut max_local = 0;
                    let mut displayed = 0;
                    for seed in 1..=WORLDS {
                        let world = World {
                            messages: MESSAGES,
                            mode,
                            withholding,
                            recipient,
                            policy,
                            fresh_process_per_pass,
                            seed,
                        };
                        let r = reorder::run(&world, &burst).expect("world");
                        assert_eq!(
                            r.displayed + r.lost,
                            MESSAGES,
                            "every message consumed ({world:?})"
                        );
                        lost += r.lost;
                        predicted += r.predicted_lost;
                        displayed += r.displayed;
                        worlds_with_loss += usize::from(r.lost > 0);
                        held += r.held_blobs;
                        hold_events += r.hold_events;
                        max_delay = max_delay.max(r.max_display_delay_ms);
                        max_local = max_local.max(r.max_local_delay_ms);
                        any_mismatch |= r.lost != r.predicted_lost;
                    }
                    println!(
                        "V7 {:?} {:?} {:?} {:?}{}: worlds {} messages {} displayed {} lost {} (model {}) worlds-with-loss {} held {} hold-passes {} max-delay-from-store {:.1} min max-delay-from-fetch {:.1} min",
                        mode,
                        recipient,
                        withholding,
                        policy,
                        if fresh_process_per_pass { " fresh-process" } else { "" },
                        WORLDS,
                        WORLDS as usize * MESSAGES,
                        displayed,
                        lost,
                        predicted,
                        worlds_with_loss,
                        held,
                        hold_events,
                        max_delay as f64 / 60_000.0,
                        max_local as f64 / 60_000.0
                    );
                }
            }
        }
    }
    assert!(!any_mismatch, "the rule model and vodozemac disagree");
}
