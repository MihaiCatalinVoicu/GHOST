//! V-7: reorder loss with Olm's 40-skipped-keys window in seeded worlds (design §7.7, Q54).
//!
//! `cargo test --release --test v7_reorder -- --nocapture` prints one line per configuration:
//! worlds, messages, lost (real vodozemac), lost predicted by the rule model, worlds with a loss,
//! blobs held, the largest display delay.

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
                        max_delay = max_delay.max(r.max_display_delay_ms);
                        max_local = max_local.max(r.max_local_delay_ms);
                        any_mismatch |= r.lost != r.predicted_lost;
                    }
                    println!(
                        "V7 {:?} {:?} {:?} {:?}{}: worlds {} messages {} displayed {} lost {} (model {}) worlds-with-loss {} held {} max-delay-from-store {:.1} min max-delay-from-fetch {:.1} min",
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
                        max_delay as f64 / 60_000.0,
                        max_local as f64 / 60_000.0
                    );
                }
            }
        }
    }
    assert!(!any_mismatch, "the rule model and vodozemac disagree");
}
