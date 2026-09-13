//! The Rust reference client policy of T2 (Phase 8 design §13.4 "reference policy", §12.3–§12.5,
//! §19.4, §19.8, §19.11, §19.14): a line-for-line mirror of the pure decisions of the Kotlin
//! `:entitlement` engine (`Slots`, `RedeemPlanner`, `ClockEstimate`, `RetryPolicy`,
//! `QuietRunWork.pick`, `Pricing.coveringSet`). Both replay
//! `protocol/test-vectors/entitlement_policy.txt` (`t2_policy_vectors.rs` here,
//! `PolicyVectorsTest.kt` there), so the reference cannot drift from the engine on anything the file
//! pins; the T2 world schedules its clients with these functions only.
//!
//! Times are unix seconds (`i64`, as the Kotlin `Long`); every rounding and truncation is the
//! Kotlin one (`Math.floorDiv`, `Double.toLong()` truncating toward zero).

use std::collections::BTreeMap;

use ring::hkdf;

pub const MINUTE: i64 = 60;
pub const HOUR: i64 = 3_600;
pub const DAY: i64 = 86_400;
pub const WEEK: i64 = 604_800;
pub const WEEK_ORIGIN: i64 = 345_600;

pub fn week(t: i64) -> i64 {
    (t - WEEK_ORIGIN).div_euclid(WEEK)
}

pub fn week_start(week: i64) -> i64 {
    WEEK_ORIGIN + WEEK * week
}

pub fn credit_epoch(week: i64) -> i64 {
    week.div_euclid(13)
}

pub fn floor_minute(t: i64) -> i64 {
    t.div_euclid(MINUTE) * MINUTE
}

pub fn ceil_minute(t: i64) -> i64 {
    -(-t).div_euclid(MINUTE) * MINUTE
}

// ---------------------------------------------------------------------------------------------
// Activation slots (§12.3, `Slots.kt`).
// ---------------------------------------------------------------------------------------------

const SLOT_DELAY: i64 = 4 * HOUR;
const SPREAD: i64 = 6 * HOUR;
const MAX_EXTRA_DAYS: i64 = 16;

/// A pack's tokens: `floor_minute(first UTC-day boundary ≥ t_f + 4 h + U[0, 6 h))`, plus
/// Geometric(1/2) whole days in HIGH mode (the geometric draws first, then the offset's).
pub fn pack_eligible_minute(finalized: i64, uniform: &mut dyn FnMut() -> f64, high: bool) -> i64 {
    let shifted = finalized + SLOT_DELAY;
    let boundary = -(-shifted).div_euclid(DAY) * DAY;
    let mut extra = 0;
    if high {
        while extra < MAX_EXTRA_DAYS && uniform() < 0.5 {
            extra += 1;
        }
    }
    let offset = (SPREAD - 1).min((uniform() * SPREAD as f64) as i64);
    floor_minute(boundary + offset + extra * DAY)
}

/// A trial's tokens: at once in STANDARD mode, by the pack rule in HIGH mode.
pub fn trial_eligible_minute(finalized: i64, uniform: &mut dyn FnMut() -> f64, high: bool) -> i64 {
    if high {
        pack_eligible_minute(finalized, uniform, high)
    } else {
        floor_minute(finalized)
    }
}

// ---------------------------------------------------------------------------------------------
// Redemption planning (§12.4, `RedeemPlanner.kt`).
// ---------------------------------------------------------------------------------------------

const EXPIRING_LEAD: i64 = 23 * HOUR;
const EXPIRING_SPAN: i64 = 22 * HOUR;
const READ_SPAN: i64 = 6 * HOUR;

/// A relay or slot onion: service key and port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Onion {
    pub key: [u8; 32],
    pub port: u16,
}

/// One row of the ES slot table as the client summary holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotRow {
    pub slot: u8,
    pub from: i64,
    /// Exclusive; 0 = open-ended.
    pub until: i64,
    pub onion: Onion,
}

impl SlotRow {
    fn valid_in(&self, week: i64) -> bool {
        self.from <= week && (self.until == 0 || week < self.until)
    }
}

/// Within ±1 h of a week boundary (R9: no redeem there).
pub fn near_boundary(t: i64) -> bool {
    let p = week(t);
    t - week_start(p) < HOUR || week_start(p + 1) - t < HOUR
}

/// The ES slots `relay` serves in `week`: those listed under its exact onion and port, otherwise
/// the single slot listed under its service key; a key holding several slots in the week with an
/// unlisted port serves none.
pub fn slots_for(slots: &[SlotRow], relay: Onion, week: i64) -> Vec<u8> {
    let valid: Vec<&SlotRow> = slots.iter().filter(|s| s.valid_in(week)).collect();
    let mut exact: Vec<u8> = valid
        .iter()
        .filter(|s| s.onion == relay)
        .map(|s| s.slot)
        .collect();
    exact.sort_unstable();
    exact.dedup();
    if !exact.is_empty() {
        return exact;
    }
    let mut by_key: Vec<u8> = Vec::new();
    for s in valid.iter().filter(|s| s.onion.key == relay.key) {
        if !by_key.contains(&s.slot) {
            by_key.push(s.slot);
        }
    }
    if by_key.len() == 1 {
        by_key
    } else {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeedKind {
    Write,
    Read,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeedReason {
    Missing,
    Expiring,
    Exhausted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Redeem { week: i64, slots: Vec<u8>, due: i64 },
    Deferred,
    NoSlot,
    Skip,
}

/// One need's plan. `now_est` is the relay-facing estimate, `relay_week` the relay's week,
/// `first_seen` the first sighting of the need in this process, `write_expiry` the expiry of the
/// pair's usable write capability, `prf` the need's PRF draw in [0, 1).
#[allow(clippy::too_many_arguments)]
pub fn plan(
    kind: NeedKind,
    reason: NeedReason,
    relay: Onion,
    slots: &[SlotRow],
    now_est: i64,
    relay_week: i64,
    trusted: bool,
    first_seen: i64,
    write_expiry: Option<i64>,
    prf: f64,
) -> Decision {
    if !trusted || near_boundary(now_est) {
        return Decision::Deferred;
    }
    let p = relay_week;
    let next_start = week_start(p + 1);
    let (target, due) = if reason == NeedReason::Expiring && now_est >= next_start - EXPIRING_LEAD {
        (
            p + 1,
            next_start - EXPIRING_LEAD + (prf * EXPIRING_SPAN as f64) as i64,
        )
    } else if kind == NeedKind::Read && reason == NeedReason::Missing {
        (p, first_seen + (prf * READ_SPAN as f64) as i64)
    } else {
        (p, now_est)
    };
    if write_expiry.is_some_and(|e| e >= week_start(target + 1)) {
        return Decision::Skip;
    }
    let s = slots_for(slots, relay, target);
    if s.is_empty() {
        return Decision::NoSlot;
    }
    Decision::Redeem {
        week: target,
        slots: s,
        due,
    }
}

// ---------------------------------------------------------------------------------------------
// The relay-facing clock (§12.5, §19.4, `ClockEstimate.kt`).
// ---------------------------------------------------------------------------------------------

const MIN_RELAYS: usize = 2;
const MAX_SKEW: i64 = 24 * HOUR;
const MAX_SKEW_MINUTES: i64 = MAX_SKEW / MINUTE;
/// A move of `wall − monotonic` this large is a device clock change (`ClockEstimate.CLOCK_JUMP_MILLIS`).
pub const CLOCK_JUMP_MILLIS: i64 = 120_000;

/// The relay-facing clock (`ClockEstimate.kt`, §12.5, §19.24 point 1): the median of the relays'
/// offsets, each relay's own offset for the decisions about it once it answered, adopted periods,
/// and a device clock change forgetting it all.
#[derive(Debug, Clone, Default)]
pub struct ClockEstimate {
    offset_minutes: BTreeMap<u64, i64>,
    adopted: BTreeMap<u64, i64>,
    basis_millis: Option<i64>,
}

impl ClockEstimate {
    /// Forgets the estimate when `wall − monotonic` moved by [`CLOCK_JUMP_MILLIS`] or more since the
    /// last observation (the device clock was set).
    pub fn observe(&mut self, wall: i64, monotonic_millis: i64) {
        let basis = wall * 1000 - monotonic_millis;
        if self
            .basis_millis
            .is_some_and(|last| (basis - last).abs() >= CLOCK_JUMP_MILLIS)
        {
            self.offset_minutes.clear();
            self.adopted.clear();
        }
        self.basis_millis = Some(basis);
    }

    /// The time of `relay`'s decisions: its own clock once it answered, else [`Self::now`].
    pub fn relay_now(&self, relay: u64, wall: i64) -> i64 {
        match self.offset_minutes.get(&relay) {
            Some(&own) => wall + own * MINUTE,
            None => self.now(wall),
        }
    }

    /// Whether `relay` answered in this process (since the last device clock change).
    pub fn answered(&self, relay: u64) -> bool {
        self.offset_minutes.contains_key(&relay)
    }

    pub fn record(
        &mut self,
        relay: u64,
        relay_minute: i64,
        relay_period: i64,
        local_seconds: i64,
        wrong_period: bool,
    ) {
        let local = local_seconds.div_euclid(MINUTE);
        let offset = if relay_minute >= local + MAX_SKEW_MINUTES {
            MAX_SKEW_MINUTES
        } else if relay_minute <= local - MAX_SKEW_MINUTES {
            -MAX_SKEW_MINUTES
        } else {
            relay_minute - local
        };
        self.offset_minutes.insert(relay, offset);
        if wrong_period {
            self.adopted.insert(relay, relay_period);
        } else {
            self.adopted.remove(&relay);
        }
    }

    pub fn now(&self, wall: i64) -> i64 {
        if self.offset_minutes.len() < MIN_RELAYS {
            return wall;
        }
        let mut sorted: Vec<i64> = self.offset_minutes.values().copied().collect();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        let median = if sorted.len() % 2 == 1 {
            sorted[mid]
        } else {
            (sorted[mid - 1] + sorted[mid]).div_euclid(2)
        };
        wall + median * MINUTE
    }

    /// The week of `relay`'s decisions: its adopted period while that is within a day of `wall`
    /// (never behind the relay's own clock), else the week of [`Self::relay_now`].
    pub fn week(&self, relay: u64, wall: i64) -> i64 {
        let own = week(self.relay_now(relay, wall));
        match self.adopted.get(&relay) {
            Some(&a) if (week(wall - MAX_SKEW)..=week(wall + MAX_SKEW)).contains(&a) => a.max(own),
            _ => own,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The redeem lane's reservations (§11.6, R8, `RedeemLane.reserveStep`, `wrongPeriodRetryAfter`).
// ---------------------------------------------------------------------------------------------

const EARLY_RETRY_LEAD: i64 = 23 * HOUR;

/// What tx1 does with a plan (`RedeemLane.ReserveStep`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveStep {
    Retry,
    Wait,
    Drop,
    Covered,
    Fresh,
}

/// A week's tokens are refused from `start(week + 1) + 1 h` (design §3.4).
pub fn window_over(week: i64, relay_now: i64) -> bool {
    relay_now >= week_start(week + 1) + HOUR
}

/// tx1 for a plan of `week` at `relay_now` (the plan's relay's clock): the pair's pending
/// reservation of that week (`held`, with its `retry_after`) is retried identically unless its week
/// is over (dropped); otherwise a fresh token, unless the week is over or the pair's write
/// capability reaches past it.
pub fn reserve_step(
    held: bool,
    retry_after: Option<i64>,
    week: i64,
    relay_now: i64,
    write_expiry: Option<i64>,
) -> ReserveStep {
    if held && window_over(week, relay_now) {
        ReserveStep::Drop
    } else if held {
        if retry_after.is_some_and(|a| relay_now < a) {
            ReserveStep::Wait
        } else {
            ReserveStep::Retry
        }
    } else if window_over(week, relay_now) {
        ReserveStep::Wait
    } else if write_expiry.is_some_and(|e| e >= week_start(week + 1)) {
        ReserveStep::Covered
    } else {
        ReserveStep::Fresh
    }
}

/// A `WRONG_PERIOD` answer: a token of a week after the relay's period is kept and retried from
/// `start(week) − 23 h` (returned); one of the relay's period or before is deleted (`None`).
pub fn wrong_period_retry_after(token_week: i64, relay_period: i64) -> Option<i64> {
    (token_week > relay_period).then(|| week_start(token_week) - EARLY_RETRY_LEAD)
}

// ---------------------------------------------------------------------------------------------
// Attempt caps and pre-drawn due times (§19.11, `RetryPolicy.kt`).
// ---------------------------------------------------------------------------------------------

pub const BLIND_SIGN_ATTEMPTS: usize = 5;
pub const CALL_ATTEMPTS: usize = 2;

const WINDOWS: [(i64, i64); BLIND_SIGN_ATTEMPTS] = [
    (3 * HOUR, 5 * HOUR),
    (44 * HOUR, 52 * HOUR),
    (100 * HOUR, 112 * HOUR),
    (7 * DAY, 8 * DAY),
    (20 * DAY, 22 * DAY),
];
const ATTEMPT_LABEL: &[u8] = b"ghost/v1/attempt";
const RETRY_MIN: i64 = 20 * HOUR;
const RETRY_SPAN: i64 = 8 * HOUR;

struct Len8;

impl hkdf::KeyType for Len8 {
    fn len(&self) -> usize {
        8
    }
}

/// The due minute of `BlindSign` attempt `k` (0-based) of the invoice received at `receipt`:
/// `u` = the top 53 bits of HKDF-SHA256(ikm = seed, salt = none, info = "ghost/v1/attempt" ‖ u8(k), 8).
pub fn blind_sign_due_minute(seed: &[u8; 32], receipt: i64, k: usize) -> i64 {
    let (lo, hi) = WINDOWS[k];
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(seed);
    let mut okm = [0u8; 8];
    prk.expand(&[ATTEMPT_LABEL, &[k as u8]], Len8)
        .and_then(|o| o.fill(&mut okm))
        .expect("HKDF of 8 bytes");
    let u = (u64::from_be_bytes(okm) >> 11) as f64 * (1.0 / (1u64 << 53) as f64);
    ceil_minute(receipt + lo + (u * (hi - lo) as f64) as i64)
}

/// The due time written ahead with attempt `attempt` of a capped call sent at `now`: at the first
/// send the one retry at `ceil_minute(now + 20 h + u × 8 h)`, afterwards `current` unchanged.
pub fn next_due_after_send(attempt: usize, current: Option<i64>, now: i64, u: f64) -> Option<i64> {
    if attempt == 0 {
        Some(ceil_minute(
            now + RETRY_MIN + (u * RETRY_SPAN as f64) as i64,
        ))
    } else {
        current
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Transient,
    Unauthorized,
    Rejected,
    Malformed,
}

pub fn classify(category: &str) -> Failure {
    match category {
        "unauthorized" => Failure::Unauthorized,
        "rejected" | "invalid_argument" | "not_onion" => Failure::Rejected,
        "malformed_response" => Failure::Malformed,
        _ => Failure::Transient,
    }
}

// ---------------------------------------------------------------------------------------------
// Quiet-run work (§11.6, §12.2, J9, `QuietRunWork.pick`).
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkKind {
    Request,
    Sign,
    Refresh,
    Revocation,
    Claim,
    Renewal,
}

/// The one item a quiet run serves: the most overdue of the items due at `now`, ties in list
/// order. Returns its index.
pub fn pick(items: &[(WorkKind, i64)], now: i64) -> Option<usize> {
    let mut best: Option<(usize, i64)> = None;
    for (i, &(_, due)) in items.iter().enumerate() {
        if due <= now && best.is_none_or(|(_, b)| due < b) {
            best = Some((i, due));
        }
    }
    best.map(|(i, _)| i)
}

// ---------------------------------------------------------------------------------------------
// Credits paying for a pack (§4.6, §19.8, `Pricing.coveringSet`).
// ---------------------------------------------------------------------------------------------

pub const MAX_DISCOUNT_CREDITS: usize = 20;
const CREDIT_EPOCHS_ACCEPTED: i64 = 4;

pub fn accepted(credit_epoch_of_key: i64, now_week: i64) -> bool {
    let now = credit_epoch(now_week);
    (now - CREDIT_EPOCHS_ACCEPTED..=now).contains(&credit_epoch_of_key)
}

/// The positions (into `credits`, the credit epochs of the candidates) of the smallest set of at
/// least `floor` and at most 20 accepted credits covering `price(price_epoch(base))`, highest value
/// first, the older epoch first among equal values, then in list order; `None` when none covers.
pub fn covering_set(
    prices: &BTreeMap<i64, i64>,
    credits: &[i64],
    base: i64,
    now_week: i64,
    floor: usize,
) -> Option<Vec<usize>> {
    let target = *prices.get(&credit_epoch(base))?;
    let value = |epoch: i64| prices.get(&epoch).map(|p| p / 10);
    let mut usable: Vec<usize> = (0..credits.len())
        .filter(|&i| accepted(credits[i], now_week) && value(credits[i]).is_some())
        .collect();
    // Stable, as Kotlin's sortedWith.
    usable.sort_by(|&a, &b| {
        value(credits[b])
            .cmp(&value(credits[a]))
            .then(credits[a].cmp(&credits[b]))
    });
    let mut chosen = Vec::new();
    let mut sum = 0i64;
    for i in usable {
        if chosen.len() >= floor && sum >= target {
            break;
        }
        chosen.push(i);
        sum += value(credits[i]).expect("usable");
    }
    (sum >= target && chosen.len() >= floor && chosen.len() <= MAX_DISCOUNT_CREDITS)
        .then_some(chosen)
}
