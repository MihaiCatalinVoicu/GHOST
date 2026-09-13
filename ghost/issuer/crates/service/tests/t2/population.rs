//! The scripted population of a T2 world (Phase 8 design §13.4 "World", §19.16): who exists, when
//! each client joins, how it is onboarded and how its user behaves, drawn from the `user` seed.
//!
//! Gate (`N = 2 000`, 84 days): about 600 first packs of invitees, 1 300 renewals and 100 resumes;
//! 700 trials (100 of them never buy), 20 genesis identities, 40 Sybil invitees of the attacker,
//! and 150 future credit spenders run through a 40-week warm-up (100 credits-paid packs and 30
//! payout claims in the window). Existing subscribers buy their first pack in the four weeks
//! before the window. The PR variant (`N = 300`, 21 days) scales every count; the achieved counts
//! are reported by the world.

use ghost_t2_join::model::ClientKind;

use super::policy::{DAY, HOUR, WEEK};
use super::rng::Rng;

/// The first access week of the warm-up (the T2 ES covers weeks 2957..3021).
pub const FIRST_WEEK: i64 = 2958;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scale {
    pub packs: u64,
    pub window_days: u64,
    pub warmup_weeks: u64,
}

pub const GATE: Scale = Scale {
    packs: 2_000,
    window_days: 84,
    warmup_weeks: 40,
};

pub const PR: Scale = Scale {
    packs: 300,
    window_days: 21,
    warmup_weeks: 40,
};

/// A small world for the mutant and twin-world checks that need no statistical power.
pub const SMALL: Scale = Scale {
    packs: 120,
    window_days: 21,
    warmup_weeks: 40,
};

#[derive(Debug, Clone, Copy)]
pub struct Timeline {
    /// Warm-up start.
    pub t0: u64,
    /// Scored window [tw, te).
    pub tw: u64,
    pub te: u64,
}

impl Timeline {
    pub fn of(scale: Scale) -> Self {
        let t0 = super::policy::week_start(FIRST_WEEK) as u64;
        let tw = t0 + scale.warmup_weeks * WEEK as u64;
        Timeline {
            t0,
            tw,
            te: tw + scale.window_days * DAY as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spend {
    None,
    /// Renews once with credits in the window (auto-renewal with credits).
    CreditsPack,
    /// Claims a payout of its credits once in the window.
    Claim,
}

#[derive(Debug, Clone)]
pub struct ClientSpec {
    pub kind: ClientKind,
    /// When the app is installed (onboarding happens at the first foreground after it).
    pub join: u64,
    /// Offset of local time from UTC (seconds): the user's day.
    pub tz: i64,
    pub high: bool,
    /// Device clock offset and the time the user corrects it.
    pub skew: Option<(i64, u64)>,
    /// Invitees: the delay of the first pack after onboarding (None: trial only).
    pub first_pack_delay: Option<u64>,
    /// Lets its coverage lapse once in the window and resumes after this many seconds.
    pub resume_gap: Option<u64>,
    pub spend: Spend,
    /// Buys one extra pack in the window when `ENTITLEMENT_NEEDED` surfaces (about 5 % of N,
    /// design §13.4 "Other activity", §19.13).
    pub need_buyer: bool,
    /// Background job cadence while the user is awake: probability that a 15-minute slot runs.
    pub run_probability: f64,
    /// Foreground sessions per day.
    pub foregrounds: f64,
}

pub struct Counts {
    pub existing: u64,
    pub spenders: u64,
    pub credits_packs: u64,
    pub claims: u64,
    pub invitees: u64,
    pub trial_only: u64,
    pub sybils: u64,
    pub genesis: u64,
    pub resumes: u64,
}

fn round(x: f64) -> u64 {
    x.round().max(0.0) as u64
}

/// The renewal cadence of the world (`World::user_actions`): a pack covers its week and the four
/// after it and is renewed with one week left, so a subscriber renews every three weeks.
pub const RENEWAL_DAYS: f64 = 21.0;

/// The share of N that are extra packs triggered by `ENTITLEMENT_NEEDED` (design §13.4, §19.13).
pub const NEED_SHARE: f64 = 0.05;

pub fn counts(scale: Scale) -> Counts {
    let n = scale.packs as f64;
    let d = scale.window_days as f64;
    let invitee_first = round(0.30 * n);
    let trial_only = round(0.05 * n).max(2);
    let credits_packs = round(0.05 * n).max(5);
    let claims = round(0.015 * n).max(3);
    let spenders = credits_packs + claims + round(0.01 * n).max(2);
    let per = d / RENEWAL_DAYS;
    // Renewals expected from spenders and invitees; existing subscribers make up the rest of
    // 0.65 N. Spenders renew at the common cadence in the window (their credits come from the
    // warm-up), a credits-paid pack replacing one renewal.
    let spender_ren = (spenders as f64 * per - credits_packs as f64).max(0.0);
    let span = (d - 10.0).max(1.0);
    let mut invitee_ren = 0.0;
    for k in 1..8 {
        // An invitee joins in [tw, te − 10 d), buys its first pack 2–9 days later and renews every
        // three weeks: the share of invitees whose k-th renewal falls in the window.
        invitee_ren += ((span - (5.5 + RENEWAL_DAYS * k as f64)) / span).max(0.0);
    }
    invitee_ren *= invitee_first as f64;
    let existing = round((0.65 * n - spender_ren - invitee_ren) / per.max(0.25)).max(10);
    Counts {
        existing,
        spenders,
        credits_packs,
        claims,
        invitees: invitee_first + trial_only,
        trial_only,
        sybils: round(0.02 * n).max(4),
        genesis: round(0.01 * n).max(3),
        resumes: round(0.05 * n).max(5),
    }
}

fn user_traits(r: &mut Rng) -> (i64, bool, Option<(i64, u64)>, f64, f64) {
    let tz = (r.range(0, 17) as i64 - 6) * HOUR;
    let high = r.chance(0.1);
    let skew = r
        .chance(0.1)
        .then(|| ((r.uniform() * 6.0 - 3.0) * DAY as f64) as i64);
    let run_probability = 0.08 + 0.14 * r.uniform();
    let foregrounds = 0.8 + 1.6 * r.uniform();
    (tz, high, skew.map(|s| (s, 0)), run_probability, foregrounds)
}

/// The population of a world: spenders first, then existing subscribers, invitees, Sybil
/// invitees and genesis identities.
pub fn population(scale: Scale, user_seed: u64) -> Vec<ClientSpec> {
    let tl = Timeline::of(scale);
    let c = counts(scale);
    let mut r = Rng::new(user_seed, &[b"population"]);
    let mut out = Vec::new();
    let push = |r: &mut Rng, kind: ClientKind, join: u64, spend: Spend| {
        let (tz, high, skew, run_probability, foregrounds) = user_traits(r);
        let skew = skew.map(|(s, _)| (s, join + r.range(DAY as u64, 20 * DAY as u64)));
        ClientSpec {
            kind,
            join,
            tz,
            high,
            skew,
            first_pack_delay: None,
            resume_gap: None,
            spend,
            need_buyer: false,
            run_probability,
            foregrounds,
        }
    };
    let week = WEEK as u64;
    let day = DAY as u64;
    for i in 0..c.spenders {
        let spend = if i < c.credits_packs {
            Spend::CreditsPack
        } else if i < c.credits_packs + c.claims {
            Spend::Claim
        } else {
            Spend::None
        };
        let join = tl.t0 + r.range(HOUR as u64, 4 * week);
        let s = push(&mut r, ClientKind::Spender, join, spend);
        out.push(s);
    }
    for _ in 0..c.existing {
        let join = tl.tw - r.range(3 * day, 28 * day);
        let s = push(&mut r, ClientKind::Existing, join, Spend::None);
        out.push(s);
    }
    // Resumes: existing subscribers that let one coverage lapse.
    let existing_start = c.spenders as usize;
    let mut idx: Vec<usize> = (existing_start..existing_start + c.existing as usize).collect();
    for i in (1..idx.len()).rev() {
        let j = r.below(i as u64 + 1) as usize;
        idx.swap(i, j);
    }
    for &i in idx.iter().take(c.resumes as usize) {
        out[i].resume_gap = Some(r.range(7 * day, 21 * day));
    }
    let latest_invitee = tl.te.saturating_sub(10 * day).max(tl.tw + day);
    for i in 0..c.invitees {
        let join = r.range(tl.tw, latest_invitee);
        let mut s = push(&mut r, ClientKind::Invitee, join, Spend::None);
        if i >= c.trial_only {
            s.first_pack_delay = Some(r.range(2 * day, 9 * day));
        }
        out.push(s);
    }
    // Sybil invitees join from seven weeks before the window, so their pre-drawn drop times
    // (3–8 weeks after the trial) fall in the window and their inviters must refresh the credits.
    let latest_sybil = (tl.tw + scale.window_days * day / 3).max(tl.tw + day);
    for _ in 0..c.sybils {
        let join = r.range(tl.tw - 49 * day, latest_sybil);
        let mut s = push(&mut r, ClientKind::Sybil, join, Spend::None);
        s.first_pack_delay = Some(r.range(day, 3 * day));
        out.push(s);
    }
    let latest_genesis = tl.te.saturating_sub(7 * day).max(tl.tw + day);
    for _ in 0..c.genesis {
        let join = r.range(tl.tw, latest_genesis);
        let s = push(&mut r, ClientKind::Genesis, join, Spend::None);
        out.push(s);
    }
    // The need buyers: 5 % of N among the clients that pay for packs in the window (existing
    // subscribers, invitees that buy, genesis identities), each buying once when its need surfaces.
    let mut buyers: Vec<usize> = (0..out.len())
        .filter(|&i| match out[i].kind {
            ClientKind::Existing | ClientKind::Genesis => true,
            ClientKind::Invitee => out[i].first_pack_delay.is_some(),
            _ => false,
        })
        .collect();
    for i in (1..buyers.len()).rev() {
        let j = r.below(i as u64 + 1) as usize;
        buyers.swap(i, j);
    }
    for &i in buyers
        .iter()
        .take(round(NEED_SHARE * scale.packs as f64) as usize)
    {
        out[i].need_buyer = true;
    }
    out
}
