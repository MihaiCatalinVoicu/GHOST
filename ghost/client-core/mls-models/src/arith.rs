//! The quantitative halves of EM-3's abstractions, checked exhaustively in minutes and days (the
//! method of EM-2's `the_provisional_schedule_has_no_gap`): the search orders events (a settle
//! window elapsing, a store-hour anchor passing, a day passing) and these checks prove that the
//! orderings it assumes or excludes follow from the design's constants.
//!
//! Each check returns how many cases it enumerated and its smallest margin: the bound minus the
//! value, minus one more for a strict bound, so a check holds exactly when its margin is at least
//! zero (the caller asserts it).

/// A check's outcome: cases enumerated and the smallest margin (in the check's unit).
#[derive(Clone, Copy, Debug)]
pub struct Arith {
    pub name: &'static str,
    pub cases: u64,
    pub margin: i64,
}

/// CO-4's settle window (§6.4: 20 minutes after the anchor).
pub const WINDOW_MIN: i64 = 20;
/// The foreground listing interval (ADR-20: 30 s), rounded up to whole minutes.
pub const LIST_MIN: i64 = 1;
/// The largest send delay of an honest store (Phase 7 HIGH mode: U[0, 10 min]).
pub const SEND_DELAY_MAX: i64 = 10;
/// The pass of a committer that found no candidate: at most U[0, 5 min] after its catch-up listing
/// (CO-8), or at once for a user action seen within one listing interval.
pub const PASS_AFTER_LIST_MAX: i64 = 5;
/// The handshake TTLs of §5.8 (seconds): 7 d and 30 d, whole hours both.
pub const HANDSHAKE_TTLS: [i64; 2] = [604_800, 2_592_000];

fn ceil_hour(minute: i64) -> i64 {
    (minute + 59).div_euclid(60) * 60
}

/// The store hour a member computes from a fetched copy (CO-4): `relayExpiryHour − handshake TTL`,
/// where the relay rounds the expiry up to the hour (F7:485).
pub fn store_hour(store_minute: i64, ttl_seconds: i64) -> i64 {
    let ttl = ttl_seconds / 60;
    ceil_hour(store_minute + ttl) - ttl
}

/// The relay's rounding: for every store minute of a week and both handshake TTLs, the store hour
/// is in `[store, store + 60)` — CO-4's "the store happened no later" — so `store_hour + 60 + 20`
/// is at least 80 minutes after the store. Margin: the smaller of `h − s` and `s + 59 − h`.
pub fn store_hour_bounds() -> Arith {
    let mut cases = 0;
    let mut margin = i64::MAX;
    for &ttl in &HANDSHAKE_TTLS {
        for s in 0..7 * 24 * 60 {
            let h = store_hour(s, ttl);
            margin = margin.min((h - s).min(s + 59 - h));
            cases += 1;
        }
    }
    Arith {
        name: "store hour in [store, store + 60 min) (F7:485)",
        cases,
        margin,
    }
}

/// T1 and T2 (the search's timing assumptions): a blind pass — one whose committer held no
/// candidate for the epoch because it last listed before the first candidate's store `s` — happens
/// before `s + 5` (CO-8: at most 5 minutes after its listing) and is stored before `s + 20`, the
/// earliest any member's window for that epoch can end (every sighting is at or after `s`). Every
/// `s` of one hour of phases, every listing up to 30 minutes before it, every pass up to 5 minutes
/// after that listing, every send delay up to 10 minutes; strict bound.
pub fn blind_pass_is_prompt() -> Arith {
    let mut cases = 0;
    let mut margin = i64::MAX;
    for s in 0..60 {
        for last_list in (s - 30)..=(s + LIST_MIN - 1) {
            // A blind pass: its last listing did not see the candidate (it listed before `s`), or
            // it saw nothing because the candidate arrived after the listing it acted on.
            for pass in last_list..=(last_list + PASS_AFTER_LIST_MAX) {
                if last_list >= s {
                    continue;
                }
                for delay in 0..=SEND_DELAY_MAX {
                    let stored = pass + delay;
                    let earliest_window_end = s + WINDOW_MIN;
                    margin = margin.min(earliest_window_end - stored - 1);
                    cases += 1;
                }
            }
        }
    }
    Arith {
        name: "a blind concurrent pass is stored before any settle window ends (T1)",
        cases,
        margin,
    }
}

/// T1's second half: a prompt store precedes every sibling's store-hour anchor (at least 80
/// minutes after the sibling's store, `store_hour_bounds`), so the search lets no anchor pass
/// while a prompt sibling is unstored. Strict bound.
pub fn prompt_store_precedes_anchors() -> Arith {
    let mut cases = 0;
    let mut margin = i64::MAX;
    for &ttl in &HANDSHAKE_TTLS {
        for s in 0..60 {
            let anchor_end = store_hour(s, ttl) + 60 + WINDOW_MIN;
            // The latest prompt store of a sibling (`blind_pass_is_prompt`): s + 16.
            let prompt = s + LIST_MIN + PASS_AFTER_LIST_MAX + SEND_DELAY_MAX;
            margin = margin.min(anchor_end - prompt - 1);
            cases += 1;
        }
    }
    Arith {
        name: "a prompt store precedes every sibling's store-hour anchor (T1)",
        cases,
        margin,
    }
}

/// §12.3 "catch-up latency" (§19.1 rule 3): a member that returns at least 140 minutes after the
/// last store of N ≤ 30 missed epochs finds every candidate's store-hour anchor past, so it settles
/// all N in its first listing pass with no wall-clock wait. Enumerated for every N ≤ 30, epoch
/// spacings of 21 to 25 minutes (a settle window and a listing pass at least), the hour phase of
/// the last store and both TTLs. The margin is in minutes before the return.
pub fn catch_up_without_waiting() -> Arith {
    let mut cases = 0;
    let mut margin = i64::MAX;
    for &ttl in &HANDSHAKE_TTLS {
        for n in 1..=30i64 {
            for spacing in 21..=25 {
                for phase in 0..60 {
                    let last = 10_000 + phase;
                    let ret = last + 140;
                    for i in 0..n {
                        let s = last - (n - 1 - i) * spacing;
                        let anchor_end = store_hour(s, ttl) + 60 + WINDOW_MIN;
                        margin = margin.min(ret - anchor_end);
                        cases += 1;
                    }
                }
            }
        }
    }
    Arith {
        name: "a return 140 min after the last store settles N <= 30 epochs at once",
        cases,
        margin,
    }
}

/// CO-14 (§19.5): with the owner's weekly PCS commit and every other member's 28-day self-update,
/// at least `4 + (n − 2)` epochs pass in 28 days, so an honest member's 28-day self-update always
/// meets `refresh_epoch ≤ e − min(8, n)` (n = 2 … 100 members, of which up to 8 committers).
pub fn co14_keeps_honest_members_inside() -> Arith {
    let mut cases = 0;
    let mut margin = i64::MAX;
    for n in 2..=100i64 {
        let k = n.min(8);
        // Epochs a member sees between two of its own self-updates: the owner's four weekly PCS
        // commits and the self-updates of the other n − 2 members (the owner not counted twice).
        let epochs = 4 + (n - 2);
        margin = margin.min(epochs - k);
        cases += 1;
    }
    Arith {
        name: "honest 28-day self-updates satisfy CO-14 for 2..=100 members",
        cases,
        margin,
    }
}

/// CO-11, CO-12 and the drain (§6.5, §19.15): a member that receives the channel's commits never
/// reaches the 9-day clocks (a committer commits at least every 7 days, every day in short-timer
/// channels, Q36); a silent orphan raises `stale_suspected` on day 9, inside the 14-day drain, so
/// its resync still reaches committers that list its namespace. Margins in days.
pub fn day_bounds() -> Arith {
    let pcs_days = [7i64, 1];
    let mut margin = i64::MAX;
    let mut cases = 0;
    for p in pcs_days {
        // Strict: the counter, reset by every committer commit, never reaches 9.
        margin = margin.min(9 - p - 1);
        cases += 1;
    }
    // The drain: 7-day store window + 2σ (σ = 3 d) = 13, rounded up to 14; stale at day 9.
    let drain = 14i64;
    assert!(drain >= 7 + 2 * 3);
    margin = margin.min(drain - 9 - 1);
    cases += 1;
    Arith {
        name: "9-day flags exceed the PCS cadence; stale_suspected comes inside the drain",
        cases,
        margin,
    }
}

/// CO-8's work-age rule: the owner's scheduled passes are at most 24 h apart while it runs (a daily
/// background pass, CO-8), so a moderator of rank r (r × 48 h) commits fresh work only after the
/// owner left it at least one whole day. Margin in hours.
pub fn work_age_margin() -> Arith {
    let mut margin = i64::MAX;
    let mut cases = 0;
    for r in 1..=7i64 {
        margin = margin.min(r * 48 - 24 - 1);
        cases += 1;
    }
    Arith {
        name: "a moderator never races an active owner on fresh work",
        cases,
        margin,
    }
}

/// Every quantitative check.
pub fn all() -> Vec<Arith> {
    vec![
        store_hour_bounds(),
        blind_pass_is_prompt(),
        prompt_store_precedes_anchors(),
        catch_up_without_waiting(),
        co14_keeps_honest_members_inside(),
        day_bounds(),
        work_age_margin(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_holds() {
        for a in all() {
            assert!(a.margin >= 0, "{}: margin {}", a.name, a.margin);
            assert!(a.cases > 0, "{}: no case", a.name);
        }
    }

    #[test]
    fn the_store_hour_rounds_up() {
        assert_eq!(store_hour(0, 604_800), 0);
        assert_eq!(store_hour(1, 604_800), 60);
        assert_eq!(store_hour(59, 604_800), 60);
        assert_eq!(store_hour(60, 604_800), 60);
    }
}
